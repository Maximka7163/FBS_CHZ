from __future__ import annotations

import base64
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import hashlib
from typing import Any, Mapping

from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from wbcz.models import Decision, canonical_json
from wbcz.windows_agent import AgentJob, AgentJobState, AgentJobType, AgentReplayConflict, AgentResult
from wbcz.write_pipeline import (
    ALLOWED_DOCUMENT_TYPES,
    ALLOWED_PRODUCT_GROUP,
    CreateCategory,
    CreateResult,
    DuplicateSubmitBlocked,
    ExactDocument,
    InvalidWriteOperation,
    OperationRecord,
    PollClassification,
    ReplayConflict,
    SigningRequest,
    SigningResponse,
    WriteState,
    classify_poll_status,
)
from wbcz_web.models import AgentBindingRecord, AgentJobRecord, BootstrapRecord, WriteAuditRecord, WriteOperationRecord
from wbcz_web.services.tenant import active_tenant, optional_tenant
from wbcz_web.services.audit_history import (
    ActorContext,ActorKind,AuditOutcome,AuditService,AuditTenantScope,
    AuthorizationDecision,SubjectRef,SubjectType,TraceContext,
)


_WRITE_MAPPING = {
    Decision.READY_TO_WITHDRAW: ("LK_RECEIPT", "DISTANCE"),
    Decision.READY_TO_RETURN: ("LP_RETURN", "REMOTE_SALE_RETURN"),
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _normalized_b64(value: str, *, label: str) -> str:
    if not value or "\r" in value or "\n" in value:
        raise InvalidWriteOperation(f"{label} must be non-empty Base64 without CR/LF")
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise InvalidWriteOperation(f"{label} is invalid Base64") from exc
    if not raw:
        raise InvalidWriteOperation(f"{label} decodes to empty bytes")
    return base64.b64encode(raw).decode("ascii")


class SqlAlchemyWriteOperationStore:
    """PostgreSQL-backed production equivalent of the isolated SQLite write store."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def _row(self, operation_id: str, *, lock: bool = False) -> WriteOperationRecord:
        stmt = select(WriteOperationRecord).where(WriteOperationRecord.operation_id == operation_id)
        scope = optional_tenant(self.db)
        if scope is not None:
            stmt = stmt.where(
                WriteOperationRecord.organisation_id == scope.organisation_id,
                WriteOperationRecord.participant_id == scope.participant_id,
            )
        elif self.db.get(BootstrapRecord, 1) is not None:
            raise KeyError(f"operation not found: {operation_id}")
        if lock:
            stmt = stmt.with_for_update()
        row = self.db.scalar(stmt)
        if row is None:
            raise KeyError(f"operation not found: {operation_id}")
        return row

    @staticmethod
    def _record(row: WriteOperationRecord) -> OperationRecord:
        return OperationRecord(
            operation_id=row.operation_id,
            business_fingerprint=row.business_fingerprint,
            event_id=row.event_id,
            decision=Decision(row.decision),
            document_type=row.document_type,
            operation_reason=row.operation_reason,
            pg=row.pg,
            expected_inn=row.expected_inn,
            document_sha256=row.document_sha256,
            product_document_base64=row.product_document_base64,
            prepared_at=row.prepared_at.isoformat(),
            state=WriteState(row.state),
            signature_base64=row.signature_base64,
            document_id=row.document_id,
        )

    def _audit(
        self,
        operation_id: str,
        action: str,
        *,
        from_state: WriteState | None = None,
        to_state: WriteState | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        self.db.add(
            WriteAuditRecord(
                operation_id=operation_id,
                action=action,
                from_state=from_state.value if from_state else None,
                to_state=to_state.value if to_state else None,
                details_json=dict(details or {}),
            )
        )

    def _immutable_write(
        self,
        row: WriteOperationRecord,
        event_type: str,
        *,
        actor_kind: ActorKind,
        machine_principal: str | None = None,
        outcome: AuditOutcome,
        metadata: Mapping[str, Any],
        evidence_hashes: tuple[str, ...] = (),
        event_key_suffix: str,
    ) -> None:
        scope=optional_tenant(self.db)
        if scope is None:
            return
        actor=(
            ActorContext(ActorKind.USER,user_id=scope.user_id)
            if actor_kind is ActorKind.USER and scope.user_id is not None
            else ActorContext(actor_kind,machine_principal=machine_principal)
        )
        trace_data=self.db.info.get("audit_trace")
        correlation_id=trace_data.get("correlation_id") if isinstance(trace_data,dict) else None
        causation_id=trace_data.get("request_id") if isinstance(trace_data,dict) else None
        AuditService(
            self.db,
            pseudonym_key=self.db.info.get("audit_pseudonym_key"),
            pseudonym_key_id=self.db.info.get("audit_pseudonym_key_id"),
        ).append(
            event_type=event_type,
            actor=actor,
            tenant=AuditTenantScope(scope.organisation_id,scope.participant_id),
            subject=SubjectRef(SubjectType.WRITE_OPERATION,row.operation_id),
            outcome=outcome,
            authorization_decision=AuthorizationDecision.ALLOW if actor.kind is ActorKind.USER else AuthorizationDecision.NOT_APPLICABLE,
            trace=TraceContext(
                correlation_id=correlation_id,causation_id=causation_id,
                operation_id=row.operation_id,
                event_key=f"write:{row.operation_id}:{event_key_suffix}"[:256],
            ),
            metadata=dict(metadata),
            evidence_hashes=evidence_hashes,
        )

    def get(self, operation_id: str) -> OperationRecord:
        return self._record(self._row(operation_id))

    def _transition(
        self,
        operation_id: str,
        *,
        expected: set[WriteState],
        target: WriteState,
        action: str,
        details: Mapping[str, Any] | None = None,
    ) -> OperationRecord:
        row = self._row(operation_id, lock=True)
        current = WriteState(row.state)
        if current not in expected:
            raise InvalidWriteOperation(f"{action} not allowed from state {current.value}")
        row.state = target.value
        row.updated_at = _now()
        self._audit(operation_id, action, from_state=current, to_state=target, details=details)
        self.db.flush()
        return self._record(row)

    def prepare(
        self,
        *,
        event_id: str,
        decision: Decision,
        document_type: str,
        operation_reason: str,
        pg: str,
        expected_inn: str,
        document: ExactDocument,
    ) -> OperationRecord:
        if decision not in _WRITE_MAPPING:
            raise InvalidWriteOperation("control decision is not approved for write")
        expected_type, expected_reason = _WRITE_MAPPING[decision]
        if document_type != expected_type or operation_reason != expected_reason:
            raise InvalidWriteOperation("decision/document mapping mismatch")
        if document_type not in ALLOWED_DOCUMENT_TYPES or pg != ALLOWED_PRODUCT_GROUP:
            raise InvalidWriteOperation("operation is outside P0 write whitelist")
        if not expected_inn:
            raise InvalidWriteOperation("expected_inn is required")
        try:
            decoded = base64.b64decode(document.product_document_base64, validate=True)
        except Exception as exc:
            raise InvalidWriteOperation("product_document is invalid Base64") from exc
        if decoded != document.bytes_for_signature:
            raise InvalidWriteOperation("bytes_for_signature != Base64Decode(product_document)")
        if hashlib.sha256(decoded).hexdigest() != document.sha256:
            raise InvalidWriteOperation("document hash mismatch")
        source = {
            "event_id": event_id,
            "decision": decision.value,
            "document_type": document_type,
            "operation_reason": operation_reason,
            "pg": pg,
        }
        scope = optional_tenant(self.db)
        if scope is None and self.db.get(BootstrapRecord, 1) is not None:
            raise PermissionError("post-bootstrap write operations require tenant scope")
        if scope is not None and expected_inn != scope.participant_inn:
            raise InvalidWriteOperation("expected_inn must match active participant")
        namespace = (
            "wb-fbs-write:m12:" + scope.organisation_id + ":" + scope.participant_id + ":"
            if scope is not None else "wb-fbs-write:legacy:"
        )
        fingerprint = hashlib.sha256((namespace + canonical_json(source)).encode("utf-8")).hexdigest()
        existing_stmt = select(WriteOperationRecord).where(
            WriteOperationRecord.business_fingerprint == fingerprint,
        )
        if scope is not None:
            existing_stmt = existing_stmt.where(
                WriteOperationRecord.organisation_id == scope.organisation_id,
                WriteOperationRecord.participant_id == scope.participant_id,
            )
        existing = self.db.scalar(existing_stmt.with_for_update())
        if existing is not None:
            record = self._record(existing)
            if not (
                record.document_sha256 == document.sha256
                and record.product_document_base64 == document.product_document_base64
                and record.expected_inn == expected_inn
            ):
                raise ReplayConflict("same business operation has different immutable document data")
            self._audit(record.operation_id, "PREPARE_REPLAY_IDEMPOTENT", details={"document_sha256": document.sha256})
            self.db.flush()
            return record
        operation_id = "op_" + fingerprint[:32]
        now = _now()
        row = WriteOperationRecord(
            operation_id=operation_id,
            organisation_id=scope.organisation_id if scope is not None else None,
            participant_id=scope.participant_id if scope is not None else None,
            business_fingerprint=fingerprint,
            event_id=event_id,
            decision=decision.value,
            document_type=document_type,
            operation_reason=operation_reason,
            pg=pg,
            expected_inn=expected_inn,
            document_sha256=document.sha256,
            product_document_base64=document.product_document_base64,
            prepared_at=now,
            state=WriteState.AWAITING_SIGNATURE.value,
            updated_at=now,
        )
        self.db.add(row)
        self.db.flush()
        self._immutable_write(
            row,
            "TURNOVER_INTENT_CREATED",
            actor_kind=ActorKind.USER if scope is not None and scope.user_id is not None else ActorKind.WORKER,
            machine_principal=None if scope is not None and scope.user_id is not None else "write-worker",
            outcome=AuditOutcome.PENDING,
            metadata={
                "operation_kind":operation_reason,
                "document_type":document_type,
                "document_sha256":document.sha256,
                "idempotency_fingerprint":fingerprint,
            },
            evidence_hashes=(document.sha256,),
            event_key_suffix="intent",
        )
        self._audit(operation_id, "OPERATION_PREPARED", to_state=WriteState.PREPARED, details={"document_type": document_type, "pg": pg, "document_sha256": document.sha256})
        self._audit(operation_id, "SIGNING_REQUEST_PENDING", from_state=WriteState.PREPARED, to_state=WriteState.AWAITING_SIGNATURE)
        self.db.flush()
        return self._record(row)

    def signing_request(self, operation_id: str) -> SigningRequest:
        op = self.get(operation_id)
        if op.state is not WriteState.AWAITING_SIGNATURE:
            raise InvalidWriteOperation(f"signing request unavailable from state {op.state.value}")
        if op.document_type not in ALLOWED_DOCUMENT_TYPES or op.pg != ALLOWED_PRODUCT_GROUP:
            raise InvalidWriteOperation("operation is outside signing whitelist")
        return SigningRequest(op.operation_id, op.document_type, op.pg, op.expected_inn, op.document_sha256, op.product_document_base64)

    def accept_signature(self, response: SigningResponse, *, own_inn: str) -> OperationRecord:
        row = self._row(response.operation_id, lock=True)
        op = self._record(row)
        if op.document_sha256 != response.document_sha256:
            raise InvalidWriteOperation("document_sha256 mismatch")
        if op.document_type not in ALLOWED_DOCUMENT_TYPES or op.pg != ALLOWED_PRODUCT_GROUP:
            raise InvalidWriteOperation("operation is outside write whitelist")
        if op.expected_inn != own_inn:
            raise InvalidWriteOperation("expected_inn mismatch")
        if response.certificate_inn and response.certificate_inn != op.expected_inn:
            raise InvalidWriteOperation("certificate INN mismatch")
        signature = _normalized_b64(response.signature_base64, label="signature")
        if op.state is not WriteState.AWAITING_SIGNATURE:
            if row.signature_base64 == signature and op.state in {
                WriteState.SIGNED, WriteState.SUBMITTING, WriteState.SUBMITTED,
                WriteState.PROCESSING, WriteState.RECONCILIATION_REQUIRED,
                WriteState.SUCCEEDED, WriteState.FAILED, WriteState.MANUAL_REVIEW,
            }:
                self._audit(op.operation_id, "SIGNATURE_REPLAY_IDEMPOTENT", details={"document_sha256": op.document_sha256})
                self.db.flush()
                return op
            raise InvalidWriteOperation(f"signature not accepted from state {op.state.value}")
        row.signature_base64 = signature
        row.certificate_thumbprint = response.certificate_thumbprint
        row.certificate_subject = response.certificate_subject
        row.certificate_inn = response.certificate_inn
        row.certificate_valid_from = response.certificate_valid_from
        row.certificate_valid_to = response.certificate_valid_to
        row.state = WriteState.SIGNED.value
        row.updated_at = _now()
        self._audit(op.operation_id, "SIGNATURE_ACCEPTED", from_state=WriteState.AWAITING_SIGNATURE, to_state=WriteState.SIGNED, details={"document_sha256": op.document_sha256, "certificate_thumbprint": response.certificate_thumbprint, "certificate_inn": response.certificate_inn})
        self.db.flush()
        return self._record(row)

    def reserve_submit(self, operation_id: str) -> OperationRecord:
        op = self.get(operation_id)
        if op.state is not WriteState.SIGNED:
            if op.state in {WriteState.SUBMITTING, WriteState.SUBMITTED, WriteState.PROCESSING, WriteState.RECONCILIATION_REQUIRED, WriteState.SUCCEEDED}:
                raise DuplicateSubmitBlocked("second True API create is prohibited")
            raise InvalidWriteOperation(f"submit not allowed from state {op.state.value}")
        if not op.signature_base64:
            raise InvalidWriteOperation("signature missing")
        return self._transition(operation_id, expected={WriteState.SIGNED}, target=WriteState.SUBMITTING, action="SUBMIT_RESERVED")

    def complete_submit(self, operation_id: str, result: CreateResult) -> OperationRecord:
        row = self._row(operation_id, lock=True)
        current = WriteState(row.state)
        if current is not WriteState.SUBMITTING:
            raise InvalidWriteOperation(f"submit result not allowed from state {current.value}")
        if result.category is CreateCategory.SUCCESS_WITH_ID:
            if not result.document_id:
                raise InvalidWriteOperation("success parser returned no document id")
            target = WriteState.SUBMITTED
        elif result.category in {CreateCategory.SERVER_ERROR, CreateCategory.SUCCESS_CONTRACT_UNCONFIRMED}:
            target = WriteState.MANUAL_REVIEW
        else:
            target = WriteState.FAILED
        row.state = target.value
        row.document_id = result.document_id if target is WriteState.SUBMITTED else None
        row.submit_http_status = result.http_status
        row.submit_category = result.category.value
        row.submit_body_sha256 = result.body_sha256
        row.updated_at = _now()
        self._audit(operation_id, "SUBMIT_RESULT", from_state=current, to_state=target, details={"http_status": result.http_status, "category": result.category.value, "body_sha256": result.body_sha256, "content_type": result.content_type, "document_id_present": result.document_id is not None})
        remote_outcome=(
            AuditOutcome.SUCCESS if target is WriteState.SUBMITTED
            else AuditOutcome.AMBIGUOUS if target is WriteState.MANUAL_REVIEW
            else AuditOutcome.FAILED
        )
        self._immutable_write(
            row,
            "TURNOVER_REMOTE_RESULT",
            actor_kind=ActorKind.WINDOWS_AGENT,
            machine_principal=self._machine_principal(),
            outcome=remote_outcome,
            metadata={
                "operation_kind":row.operation_reason,
                "document_type":row.document_type,
                "document_sha256":row.document_sha256,
                "remote_document_id":row.document_id,
                "http_status":row.submit_http_status,
                "remote_status":row.submit_category,
                "body_sha256":row.submit_body_sha256,
                "ambiguity":target is WriteState.MANUAL_REVIEW,
                "document_id_present":row.document_id is not None,
            },
            evidence_hashes=tuple(x for x in (row.document_sha256,row.submit_body_sha256) if x),
            event_key_suffix=f"remote-result:{row.submit_body_sha256 or row.submit_category or 'none'}",
        )
        self.db.flush()
        return self._record(row)

    def mark_manual_review(self, operation_id: str, *, reason: str) -> OperationRecord:
        return self._transition(
            operation_id,
            expected={WriteState.AWAITING_SIGNATURE, WriteState.SIGNED, WriteState.SUBMITTING, WriteState.SUBMITTED, WriteState.PROCESSING, WriteState.RECONCILIATION_REQUIRED},
            target=WriteState.MANUAL_REVIEW,
            action="MANUAL_REVIEW_REQUIRED",
            details={"reason": reason[:500]},
        )

    def mark_error(self, operation_id: str, *, error_type: str) -> OperationRecord:
        return self._transition(operation_id, expected={WriteState.AWAITING_SIGNATURE, WriteState.SIGNED}, target=WriteState.ERROR, action="PIPELINE_ERROR", details={"error_type": error_type[:200]})

    def audit_note(self, operation_id: str, action: str, details: Mapping[str, Any]) -> None:
        self._row(operation_id)
        self._audit(operation_id, action, details=details)
        self.db.flush()

    def apply_poll_status(
        self,
        operation_id: str,
        *,
        status: str | None,
        http_status: int | None = None,
        body_sha256: str | None = None,
    ) -> tuple[OperationRecord, PollClassification]:
        classification = classify_poll_status(status)
        op = self.get(operation_id)
        if op.state not in {WriteState.SUBMITTED, WriteState.PROCESSING}:
            raise InvalidWriteOperation(f"polling not allowed from state {op.state.value}")
        details = {"remote_status": status, "http_status": http_status, "body_sha256": body_sha256, "classification": classification.value}
        if classification is PollClassification.INTERMEDIATE:
            if op.state is WriteState.SUBMITTED:
                op = self._transition(operation_id, expected={WriteState.SUBMITTED}, target=WriteState.PROCESSING, action="POLL_INTERMEDIATE", details=details)
            else:
                self._audit(operation_id, "POLL_INTERMEDIATE", details=details)
                self.db.flush()
                op = self.get(operation_id)
            return op, classification
        target = (
            WriteState.RECONCILIATION_REQUIRED
            if classification is PollClassification.TERMINAL_SUCCESS
            else WriteState.FAILED
            if classification is PollClassification.TERMINAL_FAILURE
            else WriteState.MANUAL_REVIEW
        )
        op = self._transition(operation_id, expected={WriteState.SUBMITTED, WriteState.PROCESSING}, target=target, action="POLL_TERMINAL", details=details)
        return op, classification

    def reconciliation_result(self, operation_id: str, *, confirmed: bool, details: Mapping[str, Any] | None = None) -> OperationRecord:
        result=self._transition(
            operation_id,
            expected={WriteState.RECONCILIATION_REQUIRED},
            target=WriteState.SUCCEEDED if confirmed else WriteState.MANUAL_REVIEW,
            action="RECONCILIATION_RESULT",
            details={"confirmed": confirmed, **dict(details or {})},
        )
        row=self._row(operation_id)
        evidence_payload={"confirmed":confirmed,"details":dict(details or {})}
        evidence_hash=hashlib.sha256(canonical_json(evidence_payload).encode("utf-8")).hexdigest()
        self._immutable_write(
            row,
            "TURNOVER_RECONCILED",
            actor_kind=ActorKind.WORKER,
            machine_principal="reconciliation-worker",
            outcome=AuditOutcome.SUCCESS if confirmed else AuditOutcome.CONFLICT,
            metadata={
                "operation_kind":row.operation_reason,
                "document_type":row.document_type,
                "document_sha256":row.document_sha256,
                "reconciliation_state":"RECONCILED" if confirmed else "MANUAL_REVIEW",
                "postcondition_evidence_sha256":evidence_hash,
                "manual_review_reason":None if confirmed else "postcondition_not_confirmed",
            },
            evidence_hashes=(row.document_sha256,evidence_hash),
            event_key_suffix=f"reconciled:{evidence_hash}",
        )
        self.db.flush()
        return result

    def audit_entries(self, operation_id: str) -> list[dict[str, Any]]:
        rows = list(self.db.scalars(select(WriteAuditRecord).where(WriteAuditRecord.operation_id == operation_id).order_by(WriteAuditRecord.id)))
        return [
            {
                "id": row.id,
                "operation_id": row.operation_id,
                "action": row.action,
                "from_state": row.from_state,
                "to_state": row.to_state,
                "details_json": row.details_json,
                "created_at": row.created_at.isoformat(),
            }
            for row in rows
        ]


@dataclass(frozen=True, slots=True)
class AgentJobMetadata:
    job: AgentJob
    agent_binding_id: str | None
    purpose: str
    event_id: str | None
    control_run_id: str | None
    poll_attempt: int
    available_at: datetime
    state: AgentJobState


class SqlAlchemyAgentJobStore:
    """PostgreSQL durable outbox with lease expiry and result replay protection."""

    def __init__(
        self,
        db: Session,
        *,
        lease_seconds: int = 90,
        agent_binding_id: str | None = None,
        organisation_id: str | None = None,
        participant_id: str | None = None,
        legacy_unbound: bool = False,
    ) -> None:
        if lease_seconds < 15:
            raise ValueError("agent job lease must be at least 15 seconds")
        if agent_binding_id and (not organisation_id or not participant_id):
            raise ValueError("bound agent store requires exact tenant scope")
        if agent_binding_id and legacy_unbound:
            raise ValueError("bound and legacy agent modes are mutually exclusive")
        self.db = db
        self.lease_seconds = lease_seconds
        self.agent_binding_id = agent_binding_id
        self.organisation_id = organisation_id
        self.participant_id = participant_id
        self.legacy_unbound = bool(legacy_unbound)

    def _machine_principal(self) -> str:
        return f"agent-binding:{self.agent_binding_id}" if self.agent_binding_id else "legacy-windows-agent"

    def _lease_scope(self, stmt):
        if self.agent_binding_id:
            return stmt.where(
                AgentJobRecord.agent_binding_id == self.agent_binding_id,
                AgentJobRecord.organisation_id == self.organisation_id,
                AgentJobRecord.participant_id == self.participant_id,
            )
        if self.legacy_unbound:
            return stmt.where(AgentJobRecord.agent_binding_id.is_(None))
        raise PermissionError("agent leasing requires an authenticated binding or explicit legacy mode")

    @staticmethod
    def _payload(job: AgentJob) -> dict[str, Any]:
        value = asdict(job)
        value["job_type"] = job.job_type.value
        value["cises"] = list(job.cises)
        return value

    @classmethod
    def _digest(cls, job: AgentJob) -> tuple[dict[str, Any], str]:
        payload = cls._payload(job)
        return payload, hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()

    @staticmethod
    def _job(row: AgentJobRecord) -> AgentJob:
        data = dict(row.payload_json)
        data["job_type"] = AgentJobType(data["job_type"])
        data["cises"] = tuple(data.get("cises") or ())
        return AgentJob(**data)

    def metadata(self, job_id: str, *, lock: bool = False) -> AgentJobMetadata:
        stmt = select(AgentJobRecord).where(AgentJobRecord.job_id == job_id)
        if lock:
            stmt = stmt.with_for_update()
        row = self.db.scalar(stmt)
        if row is None:
            raise KeyError(job_id)
        return AgentJobMetadata(
            job=self._job(row),
            agent_binding_id=row.agent_binding_id,
            purpose=row.purpose,
            event_id=row.event_id,
            control_run_id=row.control_run_id,
            poll_attempt=row.poll_attempt,
            available_at=row.available_at,
            state=AgentJobState(row.state),
        )

    def enqueue(
        self,
        job: AgentJob,
        *,
        purpose: str | None = None,
        event_id: str | None = None,
        control_run_id: str | None = None,
        poll_attempt: int = 0,
        available_at: datetime | None = None,
    ) -> AgentJob:
        job.validate()
        payload, digest = self._digest(job)
        purpose = purpose or (
            "WRITE" if job.job_type in {AgentJobType.LK_RECEIPT, AgentJobType.LP_RETURN}
            else "POLL" if job.job_type is AgentJobType.POLL_DOCUMENT
            else "CIS_CHECK"
        )
        scope = optional_tenant(self.db)
        if scope is None and self.db.get(BootstrapRecord, 1) is not None:
            raise PermissionError("post-bootstrap agent jobs require tenant scope")
        binding_id: str | None = None
        if scope is not None:
            primary = self.db.scalar(select(AgentBindingRecord).where(
                AgentBindingRecord.organisation_id == scope.organisation_id,
                AgentBindingRecord.participant_id == scope.participant_id,
                AgentBindingRecord.state == "ACTIVE",
                AgentBindingRecord.is_primary.is_(True),
            ))
            if primary is not None:
                binding_id = primary.id
            else:
                has_binding = self.db.scalar(select(AgentBindingRecord.id).where(
                    AgentBindingRecord.organisation_id == scope.organisation_id,
                    AgentBindingRecord.participant_id == scope.participant_id,
                ).limit(1))
                if has_binding is not None:
                    raise PermissionError("participant has no active primary agent binding")

        existing_stmt = select(AgentJobRecord).where(AgentJobRecord.job_id == job.job_id)
        if scope is not None:
            existing_stmt = existing_stmt.where(
                AgentJobRecord.organisation_id == scope.organisation_id,
                AgentJobRecord.participant_id == scope.participant_id,
            )
        existing = self.db.scalar(existing_stmt.with_for_update())
        if existing is not None:
            if existing.payload_sha256 != digest:
                raise AgentReplayConflict("same job_id has different payload")
            if existing.purpose != purpose or existing.event_id != event_id or existing.control_run_id != control_run_id or existing.poll_attempt != poll_attempt:
                raise AgentReplayConflict("same job_id has incompatible orchestration metadata")
            return self._job(existing)
        if job.job_type in {AgentJobType.LK_RECEIPT, AgentJobType.LP_RETURN}:
            prior_write = self.db.scalar(
                select(AgentJobRecord)
                .where(
                    AgentJobRecord.operation_id == job.operation_id,
                    AgentJobRecord.job_type.in_([AgentJobType.LK_RECEIPT.value, AgentJobType.LP_RETURN.value]),
                )
                .with_for_update()
            )
            if prior_write is not None:
                if prior_write.payload_sha256 != digest:
                    raise AgentReplayConflict("same write operation has different payload")
                return self._job(prior_write)
        trace_data=self.db.info.get("audit_trace")
        correlation_id=trace_data.get("correlation_id") if isinstance(trace_data,dict) else None
        causation_id=trace_data.get("request_id") if isinstance(trace_data,dict) else None
        row = AgentJobRecord(
            job_id=job.job_id,
            organisation_id=scope.organisation_id if scope else None,
            participant_id=scope.participant_id if scope else None,
            correlation_id=correlation_id,
            causation_id=causation_id,
            agent_binding_id=binding_id,
            job_type=job.job_type.value,
            operation_id=job.operation_id,
            purpose=purpose,
            event_id=event_id,
            control_run_id=control_run_id,
            poll_attempt=poll_attempt,
            payload_sha256=digest,
            payload_json=payload,
            state=AgentJobState.PENDING.value,
            available_at=(available_at or _now()).astimezone(timezone.utc),
            delivery_count=0,
        )
        self.db.add(row)
        self.db.flush()
        if row.organisation_id is not None or row.participant_id is not None:
            if not row.organisation_id or not row.participant_id:
                raise PermissionError("tenant-owned agent job has incomplete tenant scope")
            audit=AuditService(
                self.db,
                pseudonym_key=self.db.info.get("audit_pseudonym_key"),
                pseudonym_key_id=self.db.info.get("audit_pseudonym_key_id"),
            )
            tenant=AuditTenantScope(row.organisation_id,row.participant_id)
            actor=ActorContext(ActorKind.USER,user_id=scope.user_id) if scope is not None and scope.user_id is not None else ActorContext(ActorKind.SYSTEM)
            audit.append(
                event_type="AGENT_JOB_CREATED",
                actor=actor,
                tenant=tenant,
                subject=SubjectRef(SubjectType.AGENT_JOB,row.job_id),
                outcome=AuditOutcome.PENDING,
                authorization_decision=AuthorizationDecision.ALLOW if actor.kind is ActorKind.USER else AuthorizationDecision.NOT_APPLICABLE,
                trace=TraceContext(
                    correlation_id=row.correlation_id,causation_id=row.causation_id,
                    operation_id=row.operation_id,agent_job_id=row.job_id,
                    event_key=f"agent:{row.job_id}:created",
                ),
                metadata={
                    "job_type":row.job_type,"purpose":row.purpose,
                    "delivery_count":row.delivery_count,"payload_sha256":row.payload_sha256,
                },
            )
        self.db.flush()
        return job

    def fetch_one(self) -> AgentJob | None:
        now = _now()
        stmt = self._lease_scope(
            select(AgentJobRecord)
            .where(
                AgentJobRecord.state != AgentJobState.COMPLETED.value,
                AgentJobRecord.available_at <= now,
                or_(
                    AgentJobRecord.state == AgentJobState.PENDING.value,
                    and_(
                        AgentJobRecord.state == AgentJobState.LEASED.value,
                        AgentJobRecord.lease_expires_at.is_not(None),
                        AgentJobRecord.lease_expires_at <= now,
                    ),
                ),
            )
            .order_by(AgentJobRecord.available_at, AgentJobRecord.created_at, AgentJobRecord.job_id)
            .with_for_update(skip_locked=True)
            .limit(1)
        )
        row = self.db.scalar(stmt)
        if row is None:
            return None
        row.state = AgentJobState.LEASED.value
        row.leased_at = now
        row.lease_expires_at = now + timedelta(seconds=self.lease_seconds)
        row.delivery_count += 1
        row.updated_at = now
        self.db.flush()
        if row.organisation_id is not None or row.participant_id is not None:
            if not row.organisation_id or not row.participant_id:
                raise PermissionError("tenant-owned agent job has incomplete tenant scope")
            audit=AuditService(
                self.db,
                pseudonym_key=self.db.info.get("audit_pseudonym_key"),
                pseudonym_key_id=self.db.info.get("audit_pseudonym_key_id"),
            )
            audit.append(
                event_type="AGENT_JOB_CLAIMED",
                actor=ActorContext(ActorKind.WINDOWS_AGENT,machine_principal=self._machine_principal()),
                tenant=AuditTenantScope(row.organisation_id,row.participant_id),
                subject=SubjectRef(SubjectType.AGENT_JOB,row.job_id),
                outcome=AuditOutcome.PENDING,
                trace=TraceContext(
                    correlation_id=row.correlation_id,causation_id=row.causation_id,
                    operation_id=row.operation_id,agent_job_id=row.job_id,
                    event_key=f"agent:{row.job_id}:claimed:{row.delivery_count}",
                ),
                metadata={
                    "job_type":row.job_type,"purpose":row.purpose,
                    "delivery_count":row.delivery_count,"payload_sha256":row.payload_sha256,
                },
            )
        self.db.flush()
        return self._job(row)

    def complete(self, result: AgentResult) -> None:
        stmt = select(AgentJobRecord).where(AgentJobRecord.job_id == result.job_id)
        stmt = self._lease_scope(stmt).with_for_update()
        row = self.db.scalar(stmt)
        if row is None:
            raise KeyError("unknown agent job")
        if row.operation_id != result.operation_id:
            raise AgentReplayConflict("result operation_id mismatch")

        payload = result.safe_dict()
        digest = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()

        audit = None
        tenant = None
        if row.organisation_id is not None or row.participant_id is not None:
            if not row.organisation_id or not row.participant_id:
                raise PermissionError("tenant-owned agent job has incomplete tenant scope")
            audit = AuditService(
                self.db,
                pseudonym_key=self.db.info.get("audit_pseudonym_key"),
                pseudonym_key_id=self.db.info.get("audit_pseudonym_key_id"),
            )
            tenant = AuditTenantScope(row.organisation_id, row.participant_id)

        if row.state == AgentJobState.COMPLETED.value:
            if row.result_sha256 != digest:
                raise AgentReplayConflict("incompatible duplicate agent result")
            if audit is not None and tenant is not None:
                audit.append(
                    event_type="AGENT_REPLAY_CONVERGED",
                    actor=ActorContext(
                        ActorKind.WINDOWS_AGENT,
                        machine_principal=self._machine_principal(),
                    ),
                    tenant=tenant,
                    subject=SubjectRef(SubjectType.AGENT_JOB, row.job_id),
                    outcome=AuditOutcome.SUCCESS,
                    trace=TraceContext(
                        correlation_id=row.correlation_id,
                        causation_id=row.causation_id,
                        operation_id=row.operation_id,
                        agent_job_id=row.job_id,
                        event_key=f"agent:{row.job_id}:replay:{digest}",
                    ),
                    metadata={
                        "job_type": row.job_type,
                        "purpose": row.purpose,
                        "result_sha256": digest,
                    },
                )
            self.db.flush()
            return

        row.state = AgentJobState.COMPLETED.value
        row.result_sha256 = digest
        row.result_json = payload
        row.lease_expires_at = None
        row.updated_at = _now()
        self.db.flush()

        if audit is not None and tenant is not None:
            result_outcome = str(result.outcome or "")
            ambiguous = (
                "AMBIGUOUS" in result_outcome.upper()
                or "AMBIGUOUS" in str(result.error_code or "").upper()
            )
            failed = bool(result.error_code) or "FAIL" in result_outcome.upper()
            event_type = (
                "AGENT_RESULT_AMBIGUOUS"
                if ambiguous
                else "AGENT_JOB_FAILED"
                if failed
                else "AGENT_JOB_COMPLETED"
            )
            audit.append(
                event_type=event_type,
                actor=ActorContext(
                    ActorKind.WINDOWS_AGENT,
                    machine_principal=self._machine_principal(),
                ),
                tenant=tenant,
                subject=SubjectRef(SubjectType.AGENT_JOB, row.job_id),
                outcome=(
                    AuditOutcome.AMBIGUOUS
                    if ambiguous
                    else AuditOutcome.FAILED
                    if failed
                    else AuditOutcome.SUCCESS
                ),
                trace=TraceContext(
                    correlation_id=row.correlation_id,
                    causation_id=row.causation_id,
                    operation_id=row.operation_id,
                    agent_job_id=row.job_id,
                    event_key=f"agent:{row.job_id}:result:{digest}",
                ),
                metadata={
                    "job_type": row.job_type,
                    "purpose": row.purpose,
                    "delivery_count": row.delivery_count,
                    "result_sha256": digest,
                    "result_outcome": result_outcome,
                    "error_code": (
                        str(result.error_code)[:80]
                        if result.error_code
                        else None
                    ),
                },
            )
            if (
                row.job_type
                in {AgentJobType.LK_RECEIPT.value, AgentJobType.LP_RETURN.value}
                and result.document_id
            ):
                audit.append(
                    event_type="AGENT_DOCUMENT_SUBMITTED",
                    actor=ActorContext(
                        ActorKind.WINDOWS_AGENT,
                        machine_principal=self._machine_principal(),
                    ),
                    tenant=tenant,
                    subject=SubjectRef(SubjectType.AGENT_JOB, row.job_id),
                    secondary_subject=SubjectRef(
                        SubjectType.WRITE_OPERATION,
                        row.operation_id,
                    ),
                    outcome=AuditOutcome.SUCCESS,
                    trace=TraceContext(
                        correlation_id=row.correlation_id,
                        causation_id=row.job_id,
                        operation_id=row.operation_id,
                        agent_job_id=row.job_id,
                        event_key=(
                            f"agent:{row.job_id}:document-submitted:{digest}"
                        ),
                    ),
                    metadata={
                        "job_type": row.job_type,
                        "purpose": row.purpose,
                        "remote_document_id": str(result.document_id)[:512],
                        "http_status": result.http_status,
                        "body_sha256": result.body_sha256,
                    },
                )
        self.db.flush()

    def state(self, job_id: str) -> AgentJobState:
        row = self.db.get(AgentJobRecord, job_id)
        if row is None:
            raise KeyError(job_id)
        return AgentJobState(row.state)

    def next_poll_attempt(self, operation_id: str) -> int:
        value = self.db.scalar(
            select(func.coalesce(func.max(AgentJobRecord.poll_attempt), 0)).where(
                AgentJobRecord.operation_id == operation_id,
                AgentJobRecord.job_type == AgentJobType.POLL_DOCUMENT.value,
            )
        )
        return int(value or 0) + 1
