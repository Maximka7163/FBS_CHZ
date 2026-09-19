from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from wbcz_web.api.dependencies import AuthenticatedIdentity, get_db, require_csrf, require_permission
from wbcz_web.models import ManualReviewCaseRecord
from wbcz_web.services.authorization import Permission
from wbcz_web.services.production_hardening import ManualReviewService
from wbcz_web.services.tenant import active_tenant


manual_review_router = APIRouter(prefix="/api/manual-review", tags=["manual-review"])
read_review = require_permission(Permission.AUDIT_READ)
manage_review = require_permission(Permission.INTEGRATIONS_MANAGE)


class ResolveReviewRequest(BaseModel):
    resolution_code: str = Field(min_length=1, max_length=80)
    resolution_note: str | None = Field(default=None, max_length=500)


def _dto(row: ManualReviewCaseRecord) -> dict:
    return {
        "id": row.id,
        "domain": row.domain,
        "reason_code": row.reason_code,
        "subject_type": row.subject_type,
        "subject_id": row.subject_id,
        "operation_id": row.operation_id,
        "severity": row.severity,
        "status": row.status,
        "first_seen_at": row.first_seen_at.isoformat(),
        "last_seen_at": row.last_seen_at.isoformat(),
        "occurrence_count": row.occurrence_count,
        "attempt_count": row.attempt_count,
        "evidence_hashes": list(row.evidence_hashes_json or ()),
        "metadata": dict(row.metadata_sanitized_json or {}),
        "assigned_to_user_id": row.assigned_to_user_id,
        "resolved_at": row.resolved_at.isoformat() if row.resolved_at else None,
        "resolution_code": row.resolution_code,
        "correlation_id": row.correlation_id,
    }


@manual_review_router.get("")
def list_manual_review(
    _: AuthenticatedIdentity = Depends(read_review),
    db: Session = Depends(get_db),
    status: str | None = Query(default=None, max_length=16),
    domain: str | None = Query(default=None, max_length=48),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0, le=100000),
) -> dict:
    scope = active_tenant(db)
    stmt = select(ManualReviewCaseRecord).where(
        ManualReviewCaseRecord.organisation_id == scope.organisation_id,
        ManualReviewCaseRecord.participant_id == scope.participant_id,
    )
    if status:
        stmt = stmt.where(ManualReviewCaseRecord.status == status)
    if domain:
        stmt = stmt.where(ManualReviewCaseRecord.domain == domain)
    rows = list(db.scalars(
        stmt.order_by(ManualReviewCaseRecord.last_seen_at.desc(), ManualReviewCaseRecord.id)
        .offset(offset).limit(limit)
    ))
    return {"items": [_dto(row) for row in rows], "limit": limit, "offset": offset}


@manual_review_router.post("/{case_id}/resolve")
def resolve_manual_review(
    case_id: str,
    payload: ResolveReviewRequest,
    request: Request,
    _: None = Depends(require_csrf),
    identity: AuthenticatedIdentity = Depends(manage_review),
    db: Session = Depends(get_db),
) -> dict:
    try:
        row = ManualReviewService(db).resolve(
            case_id,
            user_id=identity.user_id,
            resolution_code=payload.resolution_code,
            resolution_note=payload.resolution_note,
        )
    except KeyError as exc:
        raise HTTPException(
            status_code=404,
            detail={"code": "MANUAL_REVIEW_NOT_FOUND", "message": "Manual review case not found", "correlation_id": request.state.correlation_id},
        ) from exc
    return _dto(row)
