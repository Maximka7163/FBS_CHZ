from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from typing import Any, Mapping, Sequence
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from wbcz.models import canonical_json
from wbcz.turnover import (
    EAEU_DIRECT_SUBFLOW_DEFER_REASON,
    EAEU_DIRECT_SUBFLOW_IMPLEMENTED,
    KNOWN_FAIL_CLOSED_DOCUMENT_TYPES,
    M5_SOURCE_VERSION,
    TURNOVER_OPERATION_REGISTRY,
    CisSnapshot,
    OperationReconciliationService,
    PreparedTurnoverDocument,
    ReconciliationState,
    TurnoverOperationKind,
)
from wbcz.windows_agent import AgentJob, AgentJobType, AgentReplayConflict, P0_PG
from wbcz_web.config import WebConfig
from wbcz_web.models import AuditLog, TurnoverOperationLedgerRecord
from wbcz_web.repositories import SqlAlchemyAgentJobStore


TURNOVER_PURPOSE = "TURNOVER_M5"


class TurnoverServiceUnavailable(RuntimeError):
    pass


class TurnoverApplicationService:
    """Typed M5 queue/ledger. True API network and signing stay Windows-side."""

    def __init__(self, db: Session, config: WebConfig) -> None:
        if not config.agent_enabled:
            raise TurnoverServiceUnavailable("Windows agent is disabled")
        self.db = db
        self.config = config
        self.jobs = SqlAlchemyAgentJobStore(db, lease_seconds=config.agent_job_lease_seconds)
        self.reconciler = OperationReconciliationService()

    @staticmethod
    def registry() -> dict[str, Any]:
        return {
            "source_version": M5_SOURCE_VERSION,
            "pg": P0_PG,
            "operations": [
                {
                    "operation_kind": definition.operation_kind.value,
                    "document_type": definition.document_type,
                    "formats": list(definition.formats),
                    "pg": list(definition.pg),
                    "supported_reasons": list(definition.supported_reasons),
                    "precondition_class": definition.precondition_class,
                    "postcondition_class": definition.postcondition_class,
                    "cancellation_relation": definition.cancellation_relation,
                    "capability": definition.capability,
                }
                for definition in TURNOVER_OPERATION_REGISTRY.values()
            ],
            "known_fail_closed_document_types": dict(KNOWN_FAIL_CLOSED_DOCUMENT_TYPES),
            "eaeu_direct_subflow_implemented": EAEU_DIRECT_SUBFLOW_IMPLEMENTED,
            "eaeu_direct_subflow_defer_reason": EAEU_DIRECT_SUBFLOW_DEFER_REASON,
        }

    @staticmethod
    def preview(prepared: PreparedTurnoverDocument) -> dict[str, Any]:
        exact = prepared.exact_document
        return {
            "operation_kind": prepared.operation_kind.value,
            "document_type": prepared.document_type,
            "document_format": prepared.document_format,
            "pg": prepared.pg,
            "document_sha256": exact.sha256,
            "product_document_base64": exact.product_document_base64,
            "raw_business_reason": prepared.raw_business_reason,
            "expected_postcondition": prepared.expected_postcondition,
        }

    def _ledger(self, operation_id: str, *, lock: bool = False) -> TurnoverOperationLedgerRecord | None:
        stmt = select(TurnoverOperationLedgerRecord).where(
            TurnoverOperationLedgerRecord.operation_id == operation_id
        )
        if lock:
            stmt = stmt.with_for_update()
        return self.db.scalar(stmt)

    def _audit(self, operation_id: str, action: str, metadata: Mapping[str, Any]) -> None:
        self.db.add(
            AuditLog(
                action=action,
                entity_type="turnover_operation",
                entity_id=operation_id,
                metadata_json=dict(metadata),
            )
        )

    def queue_prevalidated(
        self,
        prepared: PreparedTurnoverDocument,
        *,
        operation_id: str,
        precondition_snapshot: Mapping[str, Any],
        cancellation_reference: str | None = None,
    ) -> dict[str, Any]:
        """Queue only after OperationPreconditionService has validated fresh M1/M2 evidence."""
        if not operation_id or len(operation_id) > 128:
            raise ValueError("operation_id must be 1..128 characters")
        if prepared.pg != P0_PG:
            raise ValueError("M5 turnover is scoped to pg=lp")
        definition = TURNOVER_OPERATION_REGISTRY[prepared.operation_kind]
        if prepared.document_type != definition.document_type:
            raise ValueError("operation/document type registry mismatch")
        if prepared.document_format != "MANUAL":
            raise ValueError("M5 JSON turnover operations use MANUAL")
        if not precondition_snapshot.get("verified_fresh"):
            raise ValueError("fresh precondition verification is required")

        request = {
            "operation_kind": prepared.operation_kind.value,
            "document_type": prepared.document_type,
            "pg": prepared.pg,
            "document_sha256": prepared.exact_document.sha256,
            "raw_business_reason": prepared.raw_business_reason,
            "expected_postcondition": prepared.expected_postcondition,
            "cancellation_reference": cancellation_reference,
        }
        request_bytes = canonical_json(request).encode("utf-8")
        request_sha = hashlib.sha256(request_bytes).hexdigest()
        idempotency_key = f"{operation_id}:{prepared.exact_document.sha256}"

        existing = self._ledger(operation_id, lock=True)
        if existing is not None:
            if (
                existing.document_sha256 != prepared.exact_document.sha256
                or existing.operation_kind != prepared.operation_kind.value
                or existing.document_type != prepared.document_type
            ):
                raise AgentReplayConflict("same operation_id has different immutable turnover payload")
            self._audit(
                operation_id,
                "TURNOVER_IDEMPOTENT_REPLAY",
                {"request_id": existing.request_id, "document_sha256": existing.document_sha256},
            )
            self.db.flush()
            return {
                "request_id": existing.request_id,
                "operation_id": operation_id,
                "status": "deduplicated",
                "document_sha256": existing.document_sha256,
                "idempotency_key": existing.idempotency_key,
            }

        request_id = f"job_m5_{uuid4().hex}"
        ledger = TurnoverOperationLedgerRecord(
            operation_id=operation_id,
            request_id=request_id,
            operation_kind=prepared.operation_kind.value,
            document_type=prepared.document_type,
            document_sha256=prepared.exact_document.sha256,
            request_sha256=request_sha,
            idempotency_key=idempotency_key,
            raw_business_reason=prepared.raw_business_reason,
            precondition_snapshot=dict(precondition_snapshot),
            expected_postcondition={"class": prepared.expected_postcondition},
            reconciliation_state=ReconciliationState.PENDING.value,
            cancellation_reference=cancellation_reference,
        )
        self.db.add(ledger)
        self.db.flush()

        job = AgentJob(
            job_id=request_id,
            job_type=AgentJobType(prepared.document_type),
            operation_id=operation_id,
            pg=P0_PG,
            expected_inn=self.config.own_inn,
            document_type=prepared.document_type,
            document_sha256=prepared.exact_document.sha256,
            product_document_base64=prepared.exact_document.product_document_base64,
        )
        self.jobs.enqueue(job, purpose=TURNOVER_PURPOSE)
        self._audit(
            operation_id,
            "TURNOVER_QUEUED",
            {
                "request_id": request_id,
                "operation_kind": prepared.operation_kind.value,
                "document_type": prepared.document_type,
                "document_sha256": prepared.exact_document.sha256,
            },
        )
        self.db.flush()
        return {
            "request_id": request_id,
            "operation_id": operation_id,
            "status": "pending",
            "document_sha256": prepared.exact_document.sha256,
            "idempotency_key": idempotency_key,
        }

    def record_remote_document(self, operation_id: str, document_id: str) -> None:
        ledger = self._ledger(operation_id, lock=True)
        if ledger is None:
            raise KeyError(operation_id)
        if not document_id or len(document_id) > 512:
            raise ValueError("unsafe document_id")
        if ledger.remote_document_id and ledger.remote_document_id != document_id:
            raise AgentReplayConflict("remote document id changed for operation")
        ledger.remote_document_id = document_id
        self._audit(operation_id, "TURNOVER_REMOTE_DOCUMENT_CONFIRMED", {"document_id": document_id})
        self.db.flush()

    def reconcile(
        self,
        operation_id: str,
        *,
        document_status_raw: str | None,
        cis_snapshots: Sequence[CisSnapshot],
        expected_restore: Mapping[str, tuple[str | None, str | None]] | None = None,
    ) -> dict[str, Any]:
        ledger = self._ledger(operation_id, lock=True)
        if ledger is None:
            raise KeyError(operation_id)
        result = self.reconciler.reconcile(
            operation_kind=ledger.operation_kind,
            document_status_raw=document_status_raw,
            snapshots=cis_snapshots,
            expected_restore=expected_restore,
        )
        ledger.reconciliation_state = result.state.value
        ledger.reconciliation_json = {
            "document_status_raw": result.document_status_raw,
            "reason": result.reason,
            "observed": list(result.observed),
            "recorded_at": datetime.now(timezone.utc).isoformat(),
        }
        self._audit(
            operation_id,
            "TURNOVER_RECONCILIATION",
            {"state": result.state.value, "reason": result.reason},
        )
        self.db.flush()
        return {
            "operation_id": operation_id,
            "reconciliation_state": result.state.value,
            "reason": result.reason,
            "observed": list(result.observed),
        }

    def status(self, operation_id: str) -> dict[str, Any]:
        ledger = self._ledger(operation_id)
        if ledger is None:
            raise KeyError(operation_id)
        return {
            "operation_id": operation_id,
            "request_id": ledger.request_id,
            "operation_kind": ledger.operation_kind,
            "document_type": ledger.document_type,
            "document_sha256": ledger.document_sha256,
            "remote_document_id": ledger.remote_document_id,
            "raw_business_reason": ledger.raw_business_reason,
            "expected_postcondition": dict(ledger.expected_postcondition or {}),
            "reconciliation_state": ledger.reconciliation_state,
            "reconciliation": dict(ledger.reconciliation_json or {}),
            "cancellation_reference": ledger.cancellation_reference,
        }
