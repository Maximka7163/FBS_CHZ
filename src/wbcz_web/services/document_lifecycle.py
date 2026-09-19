from __future__ import annotations

from datetime import timezone
import hashlib
from typing import Any
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from wbcz.document_lifecycle import (
    DOCUMENT_STATUS_REGISTRY,
    DOCUMENT_TYPE_REGISTRY,
    M4_READ_JOB_TYPES,
    M4_SOURCE_VERSION,
    DocumentFormat,
    DocumentListFormat,
    local_idempotency_key,
    validate_m4_job_payload,
)
from wbcz.models import canonical_json
from wbcz.windows_agent import AgentJob, AgentJobState, AgentJobType, AgentReplayConflict, P0_PG
from wbcz_web.config import WebConfig
from wbcz_web.models import AgentJobRecord, AuditLog, DocumentLifecycleLedgerRecord, WriteOperationRecord
from wbcz_web.repositories import SqlAlchemyAgentJobStore
from wbcz_web.services.tenant import active_tenant, scoped_agent_job, tenant_operation_id


DOCUMENT_LIFECYCLE_PURPOSE = "DOCUMENT_LIFECYCLE"


class DocumentLifecycleUnavailable(RuntimeError):
    pass


class DocumentLifecycleService:
    """M4 typed document lifecycle/read queue; True API network stays Windows-side."""

    def __init__(self, db: Session, config: WebConfig) -> None:
        if not config.agent_enabled:
            raise DocumentLifecycleUnavailable("Windows agent is disabled")
        self.db = db
        self.config = config
        self.jobs = SqlAlchemyAgentJobStore(db, lease_seconds=config.agent_job_lease_seconds)

    @staticmethod
    def _request_body(job_type: AgentJobType, payload: dict[str, Any]) -> bytes:
        return canonical_json({"job_type": job_type.value, "read_payload": payload}).encode("utf-8")

    @classmethod
    def _request_hash(cls, job_type: AgentJobType, payload: dict[str, Any]) -> str:
        return hashlib.sha256(cls._request_body(job_type, payload)).hexdigest()

    def _ledger_row(self, operation_id: str, *, lock: bool = False) -> DocumentLifecycleLedgerRecord | None:
        scope = active_tenant(self.db)
        stmt = select(DocumentLifecycleLedgerRecord).where(
            DocumentLifecycleLedgerRecord.operation_id == operation_id,
            DocumentLifecycleLedgerRecord.organisation_id == scope.organisation_id,
            DocumentLifecycleLedgerRecord.participant_id == scope.participant_id,
        )
        if lock:
            stmt = stmt.with_for_update()
        return self.db.scalar(stmt)

    def _audit(self, *, user_id: int | None, operation_id: str, action: str, metadata: dict[str, Any]) -> None:
        scope = active_tenant(self.db)
        self.db.add(
            AuditLog(
                action=action,
                organisation_id=scope.organisation_id,
                participant_id=scope.participant_id,
                user_id=user_id,
                entity_type="document_lifecycle",
                entity_id=operation_id,
                metadata_json=metadata,
            )
        )

    def _replay_response(
        self,
        ledger: DocumentLifecycleLedgerRecord,
        *,
        user_id: int | None,
        expected_job_type: AgentJobType,
        request_hash: str,
        idem_key: str,
    ) -> dict[str, Any]:
        if ledger.job_type != expected_job_type.value or ledger.request_sha256 != request_hash:
            raise AgentReplayConflict("duplicate operation_id has different request body")
        self._audit(
            user_id=user_id,
            operation_id=ledger.operation_id,
            action="DOCUMENT_LIFECYCLE_IDEMPOTENT_REPLAY",
            metadata={
                "request_id": ledger.request_id,
                "job_type": ledger.job_type,
                "request_sha256": request_hash,
                "idempotency_key": idem_key,
            },
        )
        self.db.flush()
        return {
            "request_id": ledger.request_id,
            "operation_id": ledger.operation_id,
            "status": "deduplicated",
            "job_type": ledger.job_type,
            "source": "windows-agent-true-api",
            "request_sha256": request_hash,
            "idempotency_key": idem_key,
        }

    def queue(
        self,
        job_type: AgentJobType,
        payload: dict[str, Any],
        *,
        operation_id: str | None = None,
        user_id: int | None = None,
    ) -> dict[str, Any]:
        if job_type.value not in M4_READ_JOB_TYPES:
            raise ValueError("unsupported document lifecycle job type")
        canonical = validate_m4_job_payload(job_type.value, payload)
        external_operation_id = operation_id or f"m4read:{uuid4().hex}"
        operation_id = tenant_operation_id(self.db, "m4-document", external_operation_id, prefix="m4_")
        if not operation_id or len(operation_id) > 128:
            raise ValueError("operation_id must be 1..128 characters")

        body = self._request_body(job_type, canonical)
        request_hash = hashlib.sha256(body).hexdigest()
        idem_key = local_idempotency_key(operation_id, body)
        existing = self._ledger_row(operation_id, lock=True)
        if existing is not None:
            return self._replay_response(
                existing,
                user_id=user_id,
                expected_job_type=job_type,
                request_hash=request_hash,
                idem_key=idem_key,
            )

        request_id = f"job_m4_{uuid4().hex}"
        scope = active_tenant(self.db)
        ledger = DocumentLifecycleLedgerRecord(
            operation_id=operation_id,
            organisation_id=scope.organisation_id,
            participant_id=scope.participant_id,
            request_id=request_id,
            job_type=job_type.value,
            request_sha256=request_hash,
            idempotency_key=idem_key,
            request_json=canonical,
        )
        self.db.add(ledger)
        try:
            self.db.flush()
        except IntegrityError as exc:
            # A concurrent request may have won the primary-key race. Roll only
            # this nested unit and compare the persisted immutable request.
            self.db.rollback()
            concurrent = self._ledger_row(operation_id, lock=True)
            if concurrent is None:
                raise
            return self._replay_response(
                concurrent,
                user_id=user_id,
                expected_job_type=job_type,
                request_hash=request_hash,
                idem_key=idem_key,
            )

        job = AgentJob(
            job_id=request_id,
            job_type=job_type,
            operation_id=operation_id,
            pg=P0_PG,
            expected_inn=scope.participant_inn,
            read_payload=canonical,
        )
        self.jobs.enqueue(job, purpose=DOCUMENT_LIFECYCLE_PURPOSE)
        self._audit(
            user_id=user_id,
            operation_id=operation_id,
            action="DOCUMENT_LIFECYCLE_QUEUED",
            metadata={
                "request_id": request_id,
                "job_type": job_type.value,
                "request_sha256": request_hash,
                "idempotency_key": idem_key,
            },
        )
        self.db.flush()
        return {
            "request_id": request_id,
            "operation_id": operation_id,
            "status": "pending",
            "job_type": job_type.value,
            "source": "windows-agent-true-api",
            "request_sha256": request_hash,
            "idempotency_key": idem_key,
        }

    def queue_cises(
        self,
        *,
        document_id: str | None = None,
        write_operation_id: str | None = None,
        operation_id: str | None = None,
        user_id: int | None = None,
    ) -> dict[str, Any]:
        if bool(document_id) == bool(write_operation_id):
            raise ValueError("provide exactly one of document_id or write_operation_id")
        if write_operation_id:
            scope = active_tenant(self.db)
            row = self.db.scalar(select(WriteOperationRecord).where(
                WriteOperationRecord.operation_id == write_operation_id,
                WriteOperationRecord.organisation_id == scope.organisation_id,
                WriteOperationRecord.participant_id == scope.participant_id,
            ))
            if row is None:
                raise KeyError(write_operation_id)
            if not row.document_id:
                raise ValueError("write operation has no confirmed remote document_id")
            document_id = row.document_id
        assert document_id is not None
        return self.queue(
            AgentJobType.DOCUMENT_CISES,
            {"document_id": document_id, "product_group": P0_PG},
            operation_id=operation_id,
            user_id=user_id,
        )

    def status(self, request_id: str) -> dict[str, Any]:
        row = scoped_agent_job(self.db, request_id)
        if row is None or row.purpose != DOCUMENT_LIFECYCLE_PURPOSE:
            raise KeyError(request_id)
        scope = active_tenant(self.db)
        ledger = self.db.scalar(select(DocumentLifecycleLedgerRecord).where(
            DocumentLifecycleLedgerRecord.request_id == request_id,
            DocumentLifecycleLedgerRecord.organisation_id == scope.organisation_id,
            DocumentLifecycleLedgerRecord.participant_id == scope.participant_id,
        ))
        if ledger is None:
            raise KeyError(request_id)
        state = AgentJobState(row.state)
        result = dict(row.result_json) if isinstance(row.result_json, dict) else None
        if state is AgentJobState.PENDING:
            public_state = "pending"
        elif state is AgentJobState.LEASED:
            public_state = "running"
        elif result and result.get("outcome") == "READ_COMPLETED":
            public_state = "completed"
        else:
            public_state = "failed"
        return {
            "request_id": row.job_id,
            "operation_id": ledger.operation_id,
            "job_type": row.job_type,
            "status": public_state,
            "source": "windows-agent-true-api",
            "request": dict(ledger.request_json or {}),
            "request_sha256": ledger.request_sha256,
            "idempotency_key": ledger.idempotency_key,
            "result": result.get("read_result") if result else None,
            "transport": (
                {
                    "http_status": result.get("http_status"),
                    "content_type": result.get("content_type"),
                    "safe_error_code": result.get("error_code"),
                    "safe_error_message": result.get("error_message"),
                    "body_sha256": result.get("body_sha256"),
                }
                if result else None
            ),
            "fetched_at": (
                row.updated_at.astimezone(timezone.utc).isoformat()
                if state is AgentJobState.COMPLETED and row.updated_at is not None
                else None
            ),
        }

    def ledger(self, operation_id: str) -> dict[str, Any]:
        ledger = self._ledger_row(operation_id)
        if ledger is None:
            raise KeyError(operation_id)
        row = self.db.get(AgentJobRecord, ledger.request_id)
        audits = list(
            self.db.scalars(
                select(AuditLog)
                .where(
                    AuditLog.entity_type == "document_lifecycle",
                    AuditLog.entity_id == operation_id,
                )
                .order_by(AuditLog.id)
            )
        )
        return {
            "operation_id": operation_id,
            "request_id": ledger.request_id,
            "job_type": ledger.job_type,
            "request_sha256": ledger.request_sha256,
            "idempotency_key": ledger.idempotency_key,
            "request": dict(ledger.request_json or {}),
            "state": row.state if row else "LEDGER_ONLY",
            "result": dict(row.result_json) if row and isinstance(row.result_json, dict) else None,
            "created_at": ledger.created_at.astimezone(timezone.utc).isoformat() if ledger.created_at else None,
            "updated_at": ledger.updated_at.astimezone(timezone.utc).isoformat() if ledger.updated_at else None,
            "audit": [
                {
                    "id": item.id,
                    "action": item.action,
                    "metadata": dict(item.metadata_json or {}),
                    "occurred_at": item.occurred_at.astimezone(timezone.utc).isoformat() if item.occurred_at else None,
                }
                for item in audits
            ],
        }

    @staticmethod
    def registries() -> dict[str, Any]:
        return {
            "source_version": M4_SOURCE_VERSION,
            "document_formats": [item.value for item in DocumentFormat],
            "document_list_formats": [item.value for item in DocumentListFormat],
            "document_types": [
                {
                    "type_code": item.type_code,
                    "formats": [fmt.value for fmt in item.formats],
                    "create_supported": item.create_supported,
                    "view_supported": item.view_supported,
                }
                for item in DOCUMENT_TYPE_REGISTRY.values()
            ],
            "document_statuses": [
                {"raw": item.raw, "display": item.display, "scope": item.scope.value}
                for item in DOCUMENT_STATUS_REGISTRY.values()
            ],
            "notes": {
                "unknown_statuses": "preserved raw and never treated as success",
                "CANCELLED_CANCELED": "both raw spellings are preserved",
                "processing_error_codes": "commonErrors.errorCode is raw, not an enum",
            },
        }
