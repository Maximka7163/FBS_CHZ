from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
from uuid import uuid4

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from wbcz.windows_agent import AgentAuthError
from wbcz_web.models import (
    AgentBindingEncryptionKeyRecord, AgentBindingRecord, ParticipantRecord,
    PrintExecutionRecord, PrintPayloadDeliveryReservationRecord,
)
from wbcz_web.services.audit_history import (
    ActorContext, ActorKind, AuditOutcome, AuditService, AuditTenantScope,
    AuthorizationDecision, SubjectRef, SubjectType, TraceContext,
)
from wbcz_web.services.integration_secrets import provision_agent_credential
from wbcz_web.services.integration_status import agent_runtime_status
from wbcz_web.services.tenant import active_tenant, bind_tenant_scope


def _now() -> datetime:
    return datetime.now(timezone.utc)


def credential_hash(raw: str) -> str:
    if not isinstance(raw, str) or len(raw) < 43:
        raise AgentAuthError("invalid agent credentials")
    return hashlib.sha256(("m14-agent-credential:v1:" + raw).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class AgentPrincipal:
    binding_id: str | None
    organisation_id: str | None
    participant_id: str | None
    participant_inn: str
    legacy: bool = False


class AgentBindingService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def _audit(
        self,
        event_type: str,
        row: AgentBindingRecord,
        *,
        user_id: int | None,
        metadata: dict,
        actor_kind: ActorKind = ActorKind.USER,
    ) -> None:
        actor = (
            ActorContext(actor_kind, user_id=user_id)
            if actor_kind is ActorKind.USER
            else ActorContext(actor_kind, machine_principal=f"agent-binding:{row.id}")
        )
        trace = self.db.info.get("audit_trace") if isinstance(self.db.info.get("audit_trace"), dict) else {}
        AuditService(
            self.db,
            pseudonym_key=self.db.info.get("audit_pseudonym_key"),
            pseudonym_key_id=self.db.info.get("audit_pseudonym_key_id"),
        ).append(
            event_type=event_type,
            actor=actor,
            tenant=AuditTenantScope(row.organisation_id, row.participant_id),
            subject=SubjectRef(SubjectType.INTEGRATION_CONNECTION, row.id),
            outcome=AuditOutcome.SUCCESS,
            authorization_decision=(
                AuthorizationDecision.ALLOW
                if actor_kind is ActorKind.USER
                else AuthorizationDecision.NOT_APPLICABLE
            ),
            trace=TraceContext(
                request_id=trace.get("request_id"),
                correlation_id=trace.get("correlation_id"),
                causation_id=trace.get("causation_id"),
                operation_id=row.id,
                event_key=(
                    f"m14-agent-binding:{row.id}:{event_type}:{row.credential_version}:"
                    f"{metadata.get('key_version', '')}"
                )[:256],
            ),
            metadata=metadata,
        )

    def _scope_row(self, binding_id: str, *, lock: bool = False) -> AgentBindingRecord:
        scope = active_tenant(self.db)
        stmt = select(AgentBindingRecord).where(
            AgentBindingRecord.id == binding_id,
            AgentBindingRecord.organisation_id == scope.organisation_id,
            AgentBindingRecord.participant_id == scope.participant_id,
        )
        if lock:
            stmt = stmt.with_for_update()
        row = self.db.scalar(stmt)
        if row is None:
            raise KeyError("agent binding not found")
        return row

    def create(
        self,
        *,
        installation_id: str | None,
        display_name: str,
        protocol_version: str = "m14-v1",
        agent_version: str | None = None,
        activate: bool = True,
        primary: bool = True,
        user_id: int | None = None,
    ) -> tuple[AgentBindingRecord, str]:
        scope = active_tenant(self.db)
        raw = provision_agent_credential()
        existing_primary = self.db.scalar(
            select(AgentBindingRecord).where(
                AgentBindingRecord.organisation_id == scope.organisation_id,
                AgentBindingRecord.participant_id == scope.participant_id,
                AgentBindingRecord.state == "ACTIVE",
                AgentBindingRecord.is_primary.is_(True),
            ).with_for_update()
        )
        if activate and primary and existing_primary is not None:
            raise ValueError("participant already has an active primary agent binding")
        row = AgentBindingRecord(
            organisation_id=scope.organisation_id,
            participant_id=scope.participant_id,
            installation_id=(installation_id or str(uuid4())),
            display_name=display_name.strip()[:200] or "Windows Agent",
            protocol_version=protocol_version.strip()[:32] or "m14-v1",
            agent_version=(agent_version or "").strip()[:64] or None,
            credential_hash=credential_hash(raw),
            credential_version=1,
            state="ACTIVE" if activate else "PENDING",
            is_primary=bool(primary and activate),
            capabilities_sanitized={},
        )
        self.db.add(row)
        self.db.flush()
        self._audit(
            "AGENT_BINDING_CREATED", row, user_id=user_id,
            metadata={
                "binding_id": row.id,
                "installation_id": row.installation_id,
                "protocol_version": row.protocol_version,
                "credential_version": row.credential_version,
                "is_primary": row.is_primary,
            },
        )
        return row, raw

    def rotate_credential(self, binding_id: str, *, user_id: int | None = None) -> tuple[AgentBindingRecord, str]:
        row = self._scope_row(binding_id, lock=True)
        if row.state not in {"PENDING", "ACTIVE"}:
            raise ValueError("disabled or archived binding cannot rotate credential")
        raw = provision_agent_credential()
        row.credential_hash = credential_hash(raw)
        row.credential_version += 1
        row.updated_at = _now()
        self.db.flush()
        self._audit(
            "AGENT_BINDING_CHANGED", row, user_id=user_id,
            metadata={
                "binding_id": row.id,
                "changed_fields": ["credential_version"],
                "credential_version": row.credential_version,
                "is_primary": row.is_primary,
                "state": row.state,
            },
        )
        return row, raw

    def disable(self, binding_id: str, *, user_id: int | None = None) -> AgentBindingRecord:
        row = self._scope_row(binding_id, lock=True)
        if row.state == "ARCHIVED":
            raise ValueError("archived binding cannot be disabled")
        now = _now()
        keys = list(self.db.scalars(
            select(AgentBindingEncryptionKeyRecord)
            .where(
                AgentBindingEncryptionKeyRecord.agent_binding_id == row.id,
                AgentBindingEncryptionKeyRecord.state.in_(("ACTIVE", "RETIRING")),
            )
            .with_for_update()
        ))
        key_ids = [key.id for key in keys]
        if key_ids:
            reservations = list(self.db.scalars(
                select(PrintPayloadDeliveryReservationRecord)
                .where(
                    PrintPayloadDeliveryReservationRecord.agent_encryption_key_id.in_(key_ids),
                    PrintPayloadDeliveryReservationRecord.state.in_(("AVAILABLE", "ISSUED")),
                )
                .with_for_update()
            ))
            for reservation in reservations:
                reservation.state = "REVOKED"
                reservation.revoked_at = now
                reservation.safe_error_code = "AGENT_BINDING_DISABLED"
                execution = self.db.get(PrintExecutionRecord, reservation.print_execution_id)
                if execution is not None and execution.state in {
                    "REQUESTED", "AUTHORIZED", "PAYLOAD_AVAILABLE", "PAYLOAD_ISSUED", "PAYLOAD_DELIVERED"
                }:
                    execution.state = "BLOCKED"
                    execution.safe_error_code = "AGENT_BINDING_DISABLED"
                    execution.terminal_at = now
        executions = list(self.db.scalars(
            select(PrintExecutionRecord)
            .where(
                PrintExecutionRecord.agent_binding_id == row.id,
                PrintExecutionRecord.state.in_((
                    "REQUESTED","AUTHORIZED","PAYLOAD_AVAILABLE","PAYLOAD_ISSUED",
                    "PAYLOAD_DELIVERED","RENDERED_VERIFIED","SPOOL_SUBMITTING","SPOOL_JOB_CREATED",
                )),
            )
            .with_for_update()
        ))
        for execution in executions:
            if execution.state in {"SPOOL_SUBMITTING", "SPOOL_JOB_CREATED"}:
                execution.state = "UNKNOWN_AFTER_SPOOL"
                execution.safe_error_code = "AGENT_BINDING_DISABLED_AFTER_SPOOL_BOUNDARY"
            else:
                execution.state = "BLOCKED"
                execution.safe_error_code = "AGENT_BINDING_DISABLED"
            execution.terminal_at = now

        for key in keys:
            key.state = "REVOKED"
            key.revoked_at = now
            self._audit(
                "PRINT_AGENT_KEY_REVOKED",
                row,
                user_id=user_id,
                metadata={
                    "binding_id": row.id,
                    "key_fingerprint": key.public_key_fingerprint,
                    "key_version": key.key_version,
                    "error_code": "AGENT_BINDING_DISABLED",
                },
            )
        row.state = "DISABLED"
        row.is_primary = False
        row.updated_at = now
        self.db.flush()
        self._audit(
            "AGENT_BINDING_DISABLED", row, user_id=user_id,
            metadata={"binding_id": row.id, "state": row.state},
        )
        return row

    def authenticate(self, raw: str, *, mark_poll: bool = False) -> AgentPrincipal:
        digest = credential_hash(raw)
        row = self.db.scalar(
            select(AgentBindingRecord).where(
                AgentBindingRecord.credential_hash == digest,
                AgentBindingRecord.state == "ACTIVE",
                AgentBindingRecord.protocol_compatibility_state == "COMPATIBLE",
            ).with_for_update()
        )
        if row is None or not hmac.compare_digest(row.credential_hash, digest):
            raise AgentAuthError("invalid agent credentials")
        participant = self.db.scalar(select(ParticipantRecord).where(
            ParticipantRecord.id == row.participant_id,
            ParticipantRecord.organisation_id == row.organisation_id,
            ParticipantRecord.is_active.is_(True),
            ParticipantRecord.verification_state == "VERIFIED",
        ))
        if participant is None:
            raise AgentAuthError("invalid agent credentials")
        now = _now()
        row.last_seen_at = now
        if mark_poll:
            row.last_poll_at = now
        row.updated_at = now
        self.db.flush()
        bind_tenant_scope(
            self.db,
            organisation_id=row.organisation_id,
            participant_id=row.participant_id,
            user_id=None,
            role=None,
        )
        return AgentPrincipal(row.id, row.organisation_id, row.participant_id, participant.inn, False)

    def active_binding_count(self) -> int:
        return int(self.db.scalar(
            select(func.count()).select_from(AgentBindingRecord).where(AgentBindingRecord.state == "ACTIVE")
        ) or 0)

    def primary_for_active_scope(self) -> AgentBindingRecord | None:
        scope = active_tenant(self.db)
        return self.db.scalar(select(AgentBindingRecord).where(
            AgentBindingRecord.organisation_id == scope.organisation_id,
            AgentBindingRecord.participant_id == scope.participant_id,
            AgentBindingRecord.state == "ACTIVE",
            AgentBindingRecord.is_primary.is_(True),
        ))

    def status(self, row: AgentBindingRecord, *, online_seconds: int = 120, stale_seconds: int = 600) -> dict:
        return {
            "id": row.id,
            "display_name": row.display_name,
            "installation_id": row.installation_id,
            "protocol_version": row.protocol_version,
            "agent_version": row.agent_version,
            "protocol_compatibility_state": row.protocol_compatibility_state,
            "supported_job_types": list(row.supported_job_types_json or ()),
            "supported_capabilities": list(row.supported_capabilities_json or ()),
            "state": row.state,
            "is_primary": row.is_primary,
            "runtime_status": agent_runtime_status(
                state=row.state,
                last_seen_at=row.last_seen_at,
                online_seconds=online_seconds,
                stale_seconds=stale_seconds,
                last_error_code=row.last_error_code,
            ),
            "last_seen_at": row.last_seen_at.isoformat() if row.last_seen_at else None,
            "last_poll_at": row.last_poll_at.isoformat() if row.last_poll_at else None,
            "last_true_api_auth_at": row.last_true_api_auth_at.isoformat() if row.last_true_api_auth_at else None,
            "credential_version": row.credential_version,
            "capabilities": dict(row.capabilities_sanitized or {}),
            "last_error_code": row.last_error_code,
        }
