from __future__ import annotations

from datetime import timezone
import hashlib
from typing import Any
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from wbcz.document_lifecycle import (
    DOCUMENT_STATUS_REGISTRY,
    DOCUMENT_TYPE_REGISTRY,
    M4_READ_JOB_TYPES,
    M4_SOURCE_VERSION,
    DocumentFormat,
    DocumentListFormat,
    LocalDocumentCategory,
    local_idempotency_key,
    validate_m4_job_payload,
)
from wbcz.models import canonical_json
from wbcz.windows_agent import AgentJob, AgentJobState, AgentJobType, AgentReplayConflict, P0_PG
from wbcz_web.config import WebConfig
from wbcz_web.models import AgentJobRecord, AuditLog, WriteOperationRecord
from wbcz_web.repositories import SqlAlchemyAgentJobStore


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

    def _existing_for_operation(self, operation_id: str) -> AgentJobRecord | None:
        return self.db.scalar(
            select(AgentJobRecord)
            .where(
                AgentJobRecord.purpose == DOCUMENT_LIFECYCLE_PURPOSE,
                AgentJobRecord.operation_id == operation_id,
            )
            .order_by(AgentJobRecord.created_at)
            .with_for_update()
            .limit(1)
        )

    def _audit(self, *, user_id: int | None, operation_id: str, action: str, metadata: dict[str, Any]) -> None:
        self.db.add(
            AuditLog(
                action=action,
                user_id=user_id,
                entity_type="document_lifecycle",
                entity_id=operation_id,
                metadata_json=metadata,
            )
        )

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
        operation_id = operation_id or f"m4read:{uuid4().hex}"
        if not operation_id or len(operation_id) > 128:
            raise ValueError("operation_id must be 1..128 characters")
        body = self._request_body(job_type, canonical)
        request_hash = hashlib.sha256(body).hexdigest()
        idem_key = local_idempotency_key(operation_id, body)

        existing = self._existing_for_operation(operation_id)
        if existing is not None:
            existing_payload = dict(existing.payload_json.get("read_payload") or {})
            existing_job_type = AgentJobType(existing.job_type)
            existing_hash = self._request_hash(existing_job_type, existing_payload)
            if existing_job_type is not job_type or existing_hash != request_hash:
                raise AgentReplayConflict("duplicate operation_id has different request body")
            self._audit(
                user_id=user_id,
                operation_id=operation_id,
                action="DOCUMENT_LIFECYCLE_IDEMPOTENT_REPLAY",
                metadata={
                    "request_id": existing.job_id,
                    "job_type": job_type.value,
                    "request_sha256": request_hash,
                    "idempotency_key": idem_key,
                },
            )
            self.db.flush()
            return {
                "request_id": existing.job_id,
                "operation_id": operation_id,
                "status": "deduplicated",
                "job_type": job_type.value,
                "source": "windows-agent-true-api",
                "request_sha256": request_hash,
                "idempotency_key": idem_key,
            }

        request_uuid = uuid4().hex
        job = AgentJob(
            job_id=f"job_m4_{request_uuid}",
            job_type=job_type,
            operation_id=operation_id,
            pg=P0_PG,
            expected_inn=self.config.own_inn,
            read_payload=canonical,
        )
        self.jobs.enqueue(job, purpose=DOCUMENT_LIFECYCLE_PURPOSE)
        self._audit(
            user_id=user_id,
            operation_id=operation_id,
            action="DOCUMENT_LIFECYCLE_QUEUED",
            metadata={
                "request_id": job.job_id,
                "job_type": job_type.value,
                "request_sha256": request_hash,
                "idempotency_key": idem_key,
            },
        )
        self.db.flush()
        return {
            "request_id": job.job_id,
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
            row = self.db.get(WriteOperationRecord, write_operation_id)
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
        row = self.db.get(AgentJobRecord, request_id)
        if row is None or row.purpose != DOCUMENT_LIFECYCLE_PURPOSE:
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
        read_payload = dict(row.payload_json.get("read_payload") or {})
        job_type = AgentJobType(row.job_type)
        request_hash = self._request_hash(job_type, read_payload)
        idem_key = local_idempotency_key(row.operation_id, self._request_body(job_type, read_payload))
        return {
            "request_id": row.job_id,
            "operation_id": row.operation_id,
            "job_type": row.job_type,
            "status": public_state,
            "source": "windows-agent-true-api",
            "request": read_payload,
            "request_sha256": request_hash,
            "idempotency_key": idem_key,
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
        row = self._existing_for_operation(operation_id)
        if row is None:
            raise KeyError(operation_id)
        read_payload = dict(row.payload_json.get("read_payload") or {})
        job_type = AgentJobType(row.job_type)
        body = self._request_body(job_type, read_payload)
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
            "request_id": row.job_id,
            "job_type": row.job_type,
            "request_sha256": hashlib.sha256(body).hexdigest(),
            "idempotency_key": local_idempotency_key(operation_id, body),
            "request": read_payload,
            "state": row.state,
            "result": dict(row.result_json) if isinstance(row.result_json, dict) else None,
            "created_at": row.created_at.astimezone(timezone.utc).isoformat() if row.created_at else None,
            "updated_at": row.updated_at.astimezone(timezone.utc).isoformat() if row.updated_at else None,
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
            "local_document_categories": [item.value for item in LocalDocumentCategory],
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
                {
                    "raw": item.raw,
                    "display": item.display,
                    "scope": item.scope.value,
                }
                for item in DOCUMENT_STATUS_REGISTRY.values()
            ],
            "notes": {
                "unknown_statuses": "preserved raw and never treated as success",
                "CANCELLED_CANCELED": "both raw spellings are preserved",
                "processing_error_codes": "commonErrors.errorCode is raw, not an enum",
            },
        }
