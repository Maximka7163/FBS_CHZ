from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from wbcz_web.models import AuditEventRecord, ParticipantRecord, SessionRecord, User
from wbcz_web.services.authorization import AuthorizationError, AuthorizationService, Permission
from wbcz_web.services.audit_history import (
    ActorContext,
    ActorKind,
    AuditOutcome,
    AuditService,
    AuditTenantScope,
    AuthorizationDecision,
    SubjectRef,
    SubjectType,
    TraceContext,
)

from .dependencies import AuthenticatedIdentity, get_db, require_permission


audit_router = APIRouter(prefix="/api")


def _scope(db: Session, identity: AuthenticatedIdentity):
    user = db.get(User, identity.user_id)
    session = db.get(SessionRecord, identity.session_id)
    if user is None or session is None:
        raise HTTPException(401, "Session is invalid")
    try:
        scope = AuthorizationService(db).resolve_session_scope(user, session, require_participant=False)
        AuthorizationService.require(scope, Permission.AUDIT_READ)
        return scope
    except AuthorizationError as exc:
        raise HTTPException(403, "Permission denied") from exc


def _event_view(row: AuditEventRecord) -> dict[str, Any]:
    return {
        "event_id": row.event_id,
        "sequence": row.sequence,
        "category": row.category,
        "event_type": row.event_type,
        "action": row.action,
        "outcome": row.outcome,
        "authorization_decision": row.authorization_decision,
        "organisation_id": row.organisation_id,
        "participant_id": row.participant_id,
        "actor": {
            "kind": row.actor_kind,
            "user_id": row.actor_user_id,
            "membership_id": row.actor_membership_id,
            "role": row.actor_role_snapshot,
            "permissions": row.permission_snapshot_json,
        },
        "subject": {"type": row.subject_type, "id": row.subject_id},
        "secondary_subject": (
            {"type": row.secondary_subject_type, "id": row.secondary_subject_id}
            if row.secondary_subject_type else None
        ),
        "trace": {
            "request_id": row.request_id,
            "correlation_id": row.correlation_id,
            "causation_id": row.causation_id,
            "operation_id": row.operation_id,
            "agent_job_id": row.agent_job_id,
        },
        "before_sha256": row.before_sha256,
        "after_sha256": row.after_sha256,
        "evidence_hashes": list(row.evidence_hashes_json or []),
        "metadata": dict(row.metadata_sanitized_json or {}),
        "previous_event_hash": row.previous_event_hash,
        "event_hash": row.event_hash,
        "audit_format_version": row.audit_format_version,
        "occurred_at": row.occurred_at.isoformat(),
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


def _query_audit(
    db: Session,
    *,
    scope,
    chain_id: str,
    filters: dict[str, Any],
    limit: int,
    returned_count: int,
    query_kind: str,
) -> None:
    trace_data = db.info.get("audit_trace")
    request_id = trace_data.get("request_id") if isinstance(trace_data, dict) else None
    correlation_id = trace_data.get("correlation_id") if isinstance(trace_data, dict) else request_id
    service = AuditService(
        db,
        pseudonym_key=db.info.get("audit_pseudonym_key"),
        pseudonym_key_id=db.info.get("audit_pseudonym_key_id"),
    )
    service.append(
        event_type="AUDIT_QUERY_EXECUTED",
        actor=ActorContext(ActorKind.USER, user_id=scope.user_id),
        tenant=AuditTenantScope(scope.organisation_id, None),
        subject=SubjectRef(SubjectType.AUDIT_CHAIN, chain_id),
        outcome=AuditOutcome.SUCCESS,
        authorization_decision=AuthorizationDecision.ALLOW,
        trace=TraceContext(
            request_id=request_id,
            correlation_id=correlation_id,
            event_key=(f"audit-query:{request_id}:{query_kind}"[:256] if request_id else None),
        ),
        metadata={
            "filter_summary": filters,
            "limit": limit,
            "returned_count": returned_count,
            "query_kind": query_kind,
        },
    )
    # Audit-of-audit must be durable before browser data is released.
    db.commit()


@audit_router.get("/audit/events")
def list_audit_events(
    from_time: datetime | None = Query(default=None, alias="from"),
    to_time: datetime | None = Query(default=None, alias="to"),
    category: str | None = None,
    event_type: str | None = None,
    action: str | None = None,
    actor_kind: str | None = None,
    actor_user_id: int | None = Query(default=None, ge=1),
    subject_type: str | None = None,
    subject_id: str | None = Query(default=None, min_length=1, max_length=256),
    participant_id: str | None = Query(default=None, min_length=1, max_length=36),
    outcome: str | None = None,
    correlation_id: str | None = Query(default=None, min_length=1, max_length=128),
    before_sequence: int | None = Query(default=None, ge=1),
    limit: int = Query(default=100, ge=1, le=200),
    identity: AuthenticatedIdentity = Depends(require_permission(Permission.AUDIT_READ, participant_required=False)),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    scope = _scope(db, identity)
    service = AuditService(
        db,
        pseudonym_key=db.info.get("audit_pseudonym_key"),
        pseudonym_key_id=db.info.get("audit_pseudonym_key_id"),
    )
    chain = service.chain_for_organisation(scope.organisation_id)

    if participant_id is not None:
        participant = db.scalar(select(ParticipantRecord).where(
            ParticipantRecord.id == participant_id,
            ParticipantRecord.organisation_id == scope.organisation_id,
        ))
        if participant is None:
            raise HTTPException(404, "Audit scope not found")

    stmt = select(AuditEventRecord).where(AuditEventRecord.chain_id == chain.chain_id)
    filters: dict[str, Any] = {}
    if from_time is not None:
        stmt = stmt.where(AuditEventRecord.occurred_at >= from_time)
        filters["from"] = from_time.isoformat()
    if to_time is not None:
        stmt = stmt.where(AuditEventRecord.occurred_at <= to_time)
        filters["to"] = to_time.isoformat()
    for name, value, column in (
        ("category", category, AuditEventRecord.category),
        ("event_type", event_type, AuditEventRecord.event_type),
        ("action", action, AuditEventRecord.action),
        ("actor_kind", actor_kind, AuditEventRecord.actor_kind),
        ("subject_type", subject_type, AuditEventRecord.subject_type),
        ("subject_id", subject_id, AuditEventRecord.subject_id),
        ("participant_id", participant_id, AuditEventRecord.participant_id),
        ("outcome", outcome, AuditEventRecord.outcome),
        ("correlation_id", correlation_id, AuditEventRecord.correlation_id),
    ):
        if value is not None:
            stmt = stmt.where(column == value)
            filters[name] = value
    if actor_user_id is not None:
        stmt = stmt.where(AuditEventRecord.actor_user_id == actor_user_id)
        filters["actor_user_id"] = actor_user_id
    if before_sequence is not None:
        stmt = stmt.where(AuditEventRecord.sequence < before_sequence)
        filters["before_sequence"] = before_sequence

    rows = list(db.scalars(stmt.order_by(AuditEventRecord.sequence.desc()).limit(limit)))
    payload = [_event_view(row) for row in rows]
    _query_audit(
        db,
        scope=scope,
        chain_id=chain.chain_id,
        filters=filters,
        limit=limit,
        returned_count=len(payload),
        query_kind="LIST",
    )
    return {
        "events": payload,
        "next_before_sequence": rows[-1].sequence if len(rows) == limit else None,
        "limit": limit,
    }


@audit_router.get("/audit/events/{event_id}")
def get_audit_event(
    event_id: str,
    identity: AuthenticatedIdentity = Depends(require_permission(Permission.AUDIT_READ, participant_required=False)),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    scope = _scope(db, identity)
    service = AuditService(
        db,
        pseudonym_key=db.info.get("audit_pseudonym_key"),
        pseudonym_key_id=db.info.get("audit_pseudonym_key_id"),
    )
    chain = service.chain_for_organisation(scope.organisation_id)
    row = db.scalar(select(AuditEventRecord).where(
        AuditEventRecord.event_id == event_id,
        AuditEventRecord.chain_id == chain.chain_id,
    ))
    if row is None:
        raise HTTPException(404, "Audit event not found")
    payload = _event_view(row)
    _query_audit(
        db,
        scope=scope,
        chain_id=chain.chain_id,
        filters={"event_id": event_id},
        limit=1,
        returned_count=1,
        query_kind="DETAIL",
    )
    return payload
