from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from typing import Any, Mapping, Sequence
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from wbcz.aggregation import (
    AggregationOperationKind,
    AggregationReconciliationResult,
    AggregationReconciliationState,
    M6_OPERATION_REGISTRY,
    M6_PG,
    PreparedAggregationDocument,
    operation_evidence_hash,
)
from wbcz.models import canonical_json
from wbcz.windows_agent import AgentJob, AgentJobType, AgentReplayConflict
from wbcz_web.config import WebConfig
from wbcz_web.models import AggregationOperationLedgerRecord, AuditLog
from wbcz_web.services.tenant import active_tenant, tenant_operation_id
from wbcz_web.repositories import SqlAlchemyAgentJobStore
from wbcz_web.services.audit_history import (
    ActorContext,ActorKind,AuditOutcome,AuditService,AuditTenantScope,
    AuthorizationDecision,SubjectRef,SubjectType,TraceContext,
)

AGGREGATION_PURPOSE = "AGGREGATION_M6"


class AggregationServiceUnavailable(RuntimeError):
    pass


class AggregationApplicationService:
    """Typed M6 queue/evidence ledger; CRPT remains the canonical relation graph."""

    def __init__(self, db: Session, config: WebConfig) -> None:
        if not config.agent_enabled:
            raise AggregationServiceUnavailable("Windows agent is disabled")
        self.db = db
        self.config = config
        self.jobs = SqlAlchemyAgentJobStore(db, lease_seconds=config.agent_job_lease_seconds)

    @staticmethod
    def registry() -> dict[str, Any]:
        return {
            "source_version": "true-api-v726.0",
            "pg": M6_PG,
            "operations": [
                {
                    "operation_kind": item.operation_kind.value,
                    "document_type": item.document_type,
                    "executable": item.executable,
                    "capability": item.capability,
                }
                for item in M6_OPERATION_REGISTRY.values()
            ],
            "generic_write": False,
            "generic_cancel": False,
            "move_child": False,
            "local_graph_canonical": False,
        }

    def _ledger(self, operation_id: str, *, lock: bool = False) -> AggregationOperationLedgerRecord | None:
        scope = active_tenant(self.db)
        stmt = select(AggregationOperationLedgerRecord).where(
            AggregationOperationLedgerRecord.operation_id == operation_id,
            AggregationOperationLedgerRecord.organisation_id == scope.organisation_id,
            AggregationOperationLedgerRecord.participant_id == scope.participant_id,
        )
        if lock:
            stmt = stmt.with_for_update()
        return self.db.scalar(stmt)

    def _audit(self, operation_id: str, action: str, metadata: Mapping[str, Any]) -> None:
        scope = active_tenant(self.db)
        self.db.add(AuditLog(action=action, organisation_id=scope.organisation_id, participant_id=scope.participant_id, entity_type="aggregation_operation", entity_id=operation_id, metadata_json=dict(metadata)))

    def _immutable(
        self,
        event_type: str,
        operation_id: str,
        *,
        actor_kind: ActorKind,
        machine_principal: str | None,
        outcome: AuditOutcome,
        metadata: Mapping[str, Any],
        evidence_hashes: tuple[str, ...] = (),
        event_key_suffix: str,
    ) -> None:
        scope=active_tenant(self.db)
        actor=(
            ActorContext(ActorKind.USER,user_id=scope.user_id)
            if actor_kind is ActorKind.USER and scope.user_id is not None
            else ActorContext(actor_kind,machine_principal=machine_principal)
        )
        trace_data=self.db.info.get("audit_trace")
        AuditService(
            self.db,
            pseudonym_key=self.db.info.get("audit_pseudonym_key"),
            pseudonym_key_id=self.db.info.get("audit_pseudonym_key_id"),
        ).append(
            event_type=event_type,
            actor=actor,
            tenant=AuditTenantScope(scope.organisation_id,scope.participant_id),
            subject=SubjectRef(SubjectType.AGGREGATION_OPERATION,operation_id),
            outcome=outcome,
            authorization_decision=AuthorizationDecision.ALLOW if actor.kind is ActorKind.USER else AuthorizationDecision.NOT_APPLICABLE,
            trace=TraceContext(
                request_id=trace_data.get("request_id") if isinstance(trace_data,dict) else None,
                correlation_id=trace_data.get("correlation_id") if isinstance(trace_data,dict) else None,
                causation_id=trace_data.get("causation_id") if isinstance(trace_data,dict) else None,
                operation_id=operation_id,
                event_key=f"aggregation:{operation_id}:{event_key_suffix}"[:256],
            ),
            metadata=dict(metadata),
            evidence_hashes=evidence_hashes,
        )

    @staticmethod
    def _relation_delta(kind: AggregationOperationKind) -> str:
        if kind in {AggregationOperationKind.FORM_TRANSPORT_PACKAGE, AggregationOperationKind.FORM_MULTIPRODUCT_TRANSPORT_PACKAGE, AggregationOperationKind.FORM_SET, AggregationOperationKind.FORM_SET_GENERIC_COMPATIBILITY, AggregationOperationKind.FORM_ATK}:
            return "FORM"
        if kind in {AggregationOperationKind.TRANSFORM_PACKAGE_ADD, AggregationOperationKind.TRANSFORM_ATK_ADD}:
            return "ADD"
        if kind in {AggregationOperationKind.TRANSFORM_PACKAGE_REMOVE, AggregationOperationKind.TRANSFORM_ATK_REMOVE}:
            return "REMOVE"
        if kind in {AggregationOperationKind.DISAGGREGATE_PACKAGE, AggregationOperationKind.DISAGGREGATE_ATK}:
            return "DISAGGREGATE"
        raise ValueError("operation is not a write mutation")

    def queue_prevalidated(
        self,
        prepared: PreparedAggregationDocument,
        *,
        operation_id: str,
        precondition_snapshot: Mapping[str, Any],
        parent_cis: str | None,
        child_cises: Sequence[str],
        expected_relation_delta: Mapping[str, Any],
    ) -> dict[str, Any]:
        if not operation_id or len(operation_id) > 128:
            raise ValueError("operation_id must be 1..128 characters")
        operation_id = tenant_operation_id(self.db, "m6-aggregation", operation_id, prefix="m6_")
        if prepared.pg != M6_PG or prepared.document_format != "MANUAL":
            raise ValueError("M6 supports JSON MANUAL with pg=lp")
        definition = M6_OPERATION_REGISTRY[prepared.operation_kind]
        if not definition.executable or prepared.document_type != definition.document_type:
            raise ValueError("operation/document registry mismatch")
        if not precondition_snapshot.get("verified_fresh"):
            raise ValueError("fresh M1/M2 precondition snapshot is required")
        children = tuple(sorted(set(child_cises)))
        if not children:
            raise ValueError("child_cises must be non-empty")
        child_set_hash = hashlib.sha256("\n".join(children).encode("utf-8")).hexdigest()
        request = {
            "operation_kind": prepared.operation_kind.value,
            "document_type": prepared.document_type,
            "document_sha256": prepared.exact_document.sha256,
            "parent_cis": parent_cis,
            "child_set_hash": child_set_hash,
            "expected_relation_delta": dict(expected_relation_delta),
        }
        request_sha = hashlib.sha256(canonical_json(request).encode("utf-8")).hexdigest()
        idempotency_key = f"{operation_id}:{request_sha}"
        existing = self._ledger(operation_id, lock=True)
        if existing is not None:
            if existing.request_sha256 != request_sha or existing.document_sha256 != prepared.exact_document.sha256:
                raise AgentReplayConflict("same operation_id has different immutable aggregation payload")
            self._audit(operation_id, "AGGREGATION_IDEMPOTENT_REPLAY", {"request_id": existing.request_id})
            self.db.flush()
            return {"request_id": existing.request_id, "operation_id": operation_id, "status": "deduplicated", "idempotency_key": existing.idempotency_key}

        request_id = f"job_m6_{uuid4().hex}"
        scope = active_tenant(self.db)
        row = AggregationOperationLedgerRecord(
            operation_id=operation_id,
            organisation_id=scope.organisation_id,
            participant_id=scope.participant_id,
            request_id=request_id,
            operation_kind=prepared.operation_kind.value,
            document_type=prepared.document_type,
            document_sha256=prepared.exact_document.sha256,
            request_sha256=request_sha,
            idempotency_key=idempotency_key,
            parent_cis=parent_cis,
            discovered_parent_cis=None,
            child_set_hash=child_set_hash,
            relation_delta=self._relation_delta(prepared.operation_kind),
            precondition_snapshot=dict(precondition_snapshot),
            expected_relation_delta=dict(expected_relation_delta),
            reconciliation_state=AggregationReconciliationState.RECONCILIATION_PENDING.value,
            reconciliation_json={},
            raw_history_evidence=[],
        )
        self.db.add(row)
        self.db.flush()
        scope=active_tenant(self.db)
        precondition_hash=hashlib.sha256(canonical_json(dict(precondition_snapshot)).encode("utf-8")).hexdigest()
        self._immutable(
            "AGGREGATION_INTENT_CREATED",
            operation_id,
            actor_kind=ActorKind.USER if scope.user_id is not None else ActorKind.WORKER,
            machine_principal=None if scope.user_id is not None else "aggregation-worker",
            outcome=AuditOutcome.PENDING,
            metadata={
                "request_id":request_id,"operation_kind":prepared.operation_kind.value,
                "document_type":prepared.document_type,"document_sha256":prepared.exact_document.sha256,
                "request_sha256":request_sha,"idempotency_fingerprint":idempotency_key,
                "precondition_evidence_sha256":precondition_hash,"child_set_hash":child_set_hash,
                "relation_delta":row.relation_delta,
            },
            evidence_hashes=(prepared.exact_document.sha256,request_sha,precondition_hash,child_set_hash),
            event_key_suffix="intent",
        )
        self.jobs.enqueue(
            AgentJob(
                job_id=request_id,
                job_type=AgentJobType(prepared.document_type),
                operation_id=operation_id,
                pg=M6_PG,
                expected_inn=scope.participant_inn,
                document_type=prepared.document_type,
                document_sha256=prepared.exact_document.sha256,
                product_document_base64=prepared.exact_document.product_document_base64,
            ),
            purpose=AGGREGATION_PURPOSE,
        )
        self._audit(operation_id, "AGGREGATION_QUEUED", {"request_id": request_id, "operation_kind": prepared.operation_kind.value, "document_type": prepared.document_type, "document_sha256": prepared.exact_document.sha256})
        self.db.flush()
        return {"request_id": request_id, "operation_id": operation_id, "status": "pending", "idempotency_key": idempotency_key}

    def record_remote_document(self, operation_id: str, document_id: str) -> None:
        row = self._ledger(operation_id, lock=True)
        if row is None:
            raise KeyError(operation_id)
        if row.remote_document_id and row.remote_document_id != document_id:
            raise AgentReplayConflict("remote document id changed")
        row.remote_document_id = document_id
        self._audit(operation_id, "AGGREGATION_REMOTE_DOCUMENT_CONFIRMED", {"document_id": document_id})
        self._immutable(
            "AGGREGATION_REMOTE_RESULT",
            operation_id,
            actor_kind=ActorKind.WORKER,
            machine_principal="aggregation-result-worker",
            outcome=AuditOutcome.SUCCESS,
            metadata={
                "operation_kind":row.operation_kind,"document_type":row.document_type,
                "document_sha256":row.document_sha256,"request_sha256":row.request_sha256,
                "remote_document_id":document_id,"child_set_hash":row.child_set_hash,
                "relation_delta":row.relation_delta,
            },
            evidence_hashes=(row.document_sha256,row.request_sha256,row.child_set_hash),
            event_key_suffix=f"remote-result:{hashlib.sha256(document_id.encode()).hexdigest()}",
        )
        self.db.flush()

    def record_reconciliation(self, operation_id: str, result: AggregationReconciliationResult, *, history_evidence: Sequence[Mapping[str, Any]] = ()) -> dict[str, Any]:
        row = self._ledger(operation_id, lock=True)
        if row is None:
            raise KeyError(operation_id)
        row.reconciliation_state = result.state.value
        row.discovered_parent_cis = result.discovered_parent_cis
        row.reconciliation_json = {"reason": result.reason, "recorded_at": datetime.now(timezone.utc).isoformat()}
        row.raw_history_evidence = [dict(x) for x in history_evidence]
        self._audit(operation_id, "AGGREGATION_RECONCILIATION", {"state": result.state.value, "reason": result.reason, "discovered_parent_cis": result.discovered_parent_cis})
        reconciliation_hash=hashlib.sha256(canonical_json({
            "state":result.state.value,"reason":result.reason,"child_set_hash":row.child_set_hash,
        }).encode("utf-8")).hexdigest()
        self._immutable(
            "AGGREGATION_RECONCILED",
            operation_id,
            actor_kind=ActorKind.WORKER,
            machine_principal="aggregation-reconciliation-worker",
            outcome=AuditOutcome.SUCCESS if result.state.value=="RECONCILED" else AuditOutcome.CONFLICT,
            metadata={
                "operation_kind":row.operation_kind,"document_type":row.document_type,
                "document_sha256":row.document_sha256,"reconciliation_state":result.state.value,
                "postcondition_evidence_sha256":reconciliation_hash,
                "manual_review_reason":None if result.state.value=="RECONCILED" else result.reason,
                "child_set_hash":row.child_set_hash,"relation_delta":row.relation_delta,
            },
            evidence_hashes=(row.document_sha256,row.child_set_hash,reconciliation_hash),
            event_key_suffix=f"reconciled:{reconciliation_hash}",
        )
        self.db.flush()
        return self.status(operation_id)

    def status(self, operation_id: str) -> dict[str, Any]:
        row = self._ledger(operation_id)
        if row is None:
            raise KeyError(operation_id)
        return {
            "operation_id": row.operation_id,
            "request_id": row.request_id,
            "operation_kind": row.operation_kind,
            "document_type": row.document_type,
            "remote_document_id": row.remote_document_id,
            "parent_cis": row.parent_cis,
            "discovered_parent_cis": row.discovered_parent_cis,
            "relation_delta": row.relation_delta,
            "reconciliation_state": row.reconciliation_state,
            "reconciliation": dict(row.reconciliation_json or {}),
            "local_graph_canonical": False,
        }
