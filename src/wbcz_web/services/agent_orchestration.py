from __future__ import annotations

from collections import Counter
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
from typing import Protocol

from sqlalchemy.orm import Session

from wbcz.control_engine import decide
from wbcz.models import Decision, Event, KiState, Outcome, canonical_json
from wbcz.windows_agent import (
    AgentJob,
    AgentJobState,
    AgentJobType,
    AgentResult,
    AgentReplayConflict,
    MachineTokenVerifier,
    P0_PG,
    VpsAgentBroker,
)
from wbcz.write_pipeline import ExactDocument, InvalidWriteOperation, WriteState
from wbcz_web.config import WebConfig
from wbcz_web.models import AgentJobRecord, CheckRecord, ControlRun
from wbcz_web.repositories import ImportRepository, SqlAlchemyAgentJobStore, SqlAlchemyWriteOperationStore
from wbcz_web.services.imports import record_to_event
from wbcz.m11_reports import FilesystemReportArtifactStore
from wbcz_web.services.reports import (
    EnvironmentArtifactKeyProvider,
    REPORT_AGENT_PURPOSE,
    ReportArtifactIngressService,
    TrueApiReportOrchestrator,
)


CONTROL_CIS = "CONTROL_CIS"
WRITE = "WRITE"
POLL = "POLL"
RECONCILIATION_CIS = "RECONCILIATION_CIS"


class ExactDocumentAssembler(Protocol):
    """Produces official exact bytes only after the document contract is confirmed."""

    def build_exact(self, event: Event, decision: Decision) -> ExactDocument:
        ...


class ProductionDocumentContractUnconfirmed(InvalidWriteOperation):
    pass


class UnavailableExactDocumentAssembler:
    def build_exact(self, event: Event, decision: Decision) -> ExactDocument:
        raise ProductionDocumentContractUnconfirmed(
            "production document body contract is not confirmed; write job not created"
        )


def _stable_job_id(purpose: str, operation_id: str, seed: str) -> str:
    digest = hashlib.sha256(
        f"p0-agent:v2:{purpose}:{operation_id}:{seed}".encode("utf-8")
    ).hexdigest()
    return "job_" + digest[:32]


def _select_event_ids(imports: ImportRepository, import_id: str, event_ids: list[str] | None) -> list[str]:
    if imports.get(import_id) is None:
        raise KeyError("Импорт не найден")
    allowed = imports.import_event_ids(import_id)
    allowed_set = set(allowed)
    if event_ids is None:
        return allowed
    requested = list(dict.fromkeys(event_ids))
    if not requested:
        raise ValueError("Не выбран ни один КИЗ")
    if any(event_id not in allowed_set for event_id in requested):
        raise ValueError("КИЗ не относится к выбранному импорту")
    wanted = set(requested)
    return [event_id for event_id in allowed if event_id in wanted]


class AgentControlService:
    """WB/control entry boundary: queue CIS checks, never decide on Windows."""

    def __init__(self, db: Session, config: WebConfig) -> None:
        if not config.agent_enabled:
            raise InvalidWriteOperation("Windows agent is disabled")
        self.db = db
        self.config = config
        self.imports = ImportRepository(db)
        self.jobs = SqlAlchemyAgentJobStore(db, lease_seconds=config.agent_job_lease_seconds)

    def run(self, import_id: str, user_id: int, mode: str, event_ids: list[str] | None = None) -> dict:
        selected = _select_event_ids(self.imports, import_id, event_ids)
        run = ControlRun(
            import_id=import_id,
            user_id=user_id,
            mode=getattr(mode, "value", str(mode)),
            provider="windows-agent-true-api",
        )
        self.db.add(run)
        self.db.flush()
        queued = 0
        for event_id in selected:
            row = self.imports.event(event_id)
            if row is None:
                raise KeyError(event_id)
            event = record_to_event(row)
            seed = hashlib.sha256(event.kiz.encode("utf-8")).hexdigest()
            operation_id = f"cis:{run.id}:{event_id}"
            job = AgentJob(
                job_id=_stable_job_id(CONTROL_CIS, operation_id, seed),
                job_type=AgentJobType.CIS_CHECK,
                operation_id=operation_id,
                pg=P0_PG,
                expected_inn=self.config.own_inn,
                cises=(event.kiz,),
            )
            self.jobs.enqueue(
                job,
                purpose=CONTROL_CIS,
                event_id=event_id,
                control_run_id=run.id,
            )
            queued += 1
        self.db.flush()
        return {
            "run_id": run.id,
            "provider": "windows-agent",
            "mode": getattr(mode, "value", str(mode)),
            "checked": 0,
            "pending": queued,
            "counts": {"PENDING": queued} if queued else {},
            "reasons": {},
            "production_submission_available": False,
        }


class AgentOrchestrationBroker:
    """VPS control plane. Contains no True API network client or signer."""

    def __init__(
        self,
        db: Session,
        config: WebConfig,
        *,
        document_assembler: ExactDocumentAssembler | None = None,
    ) -> None:
        if not config.agent_enabled or not config.agent_machine_token:
            raise InvalidWriteOperation("Windows agent server boundary is disabled")
        self.db = db
        self.config = config
        self.imports = ImportRepository(db)
        self.write_store = SqlAlchemyWriteOperationStore(db)
        self.job_store = SqlAlchemyAgentJobStore(db, lease_seconds=config.agent_job_lease_seconds)
        self.machine_auth = MachineTokenVerifier(config.agent_machine_token)
        self.core = VpsAgentBroker(
            write_store=self.write_store,
            job_store=self.job_store,
            machine_auth=self.machine_auth,
            own_inn=config.own_inn,
        )
        self.document_assembler = document_assembler or UnavailableExactDocumentAssembler()

    def check_auth(self, machine_token: str) -> None:
        self.machine_auth.verify(machine_token)

    def fetch_one(self, machine_token: str) -> AgentJob | None:
        return self.core.fetch_one(machine_token)

    def _report_artifact_ingress(self) -> ReportArtifactIngressService:
        if not self.config.report_artifact_root or not self.config.report_temp_root:
            raise InvalidWriteOperation("M11 report artifact storage is not configured")
        store = FilesystemReportArtifactStore(
            Path(self.config.report_artifact_root),
            key_provider=EnvironmentArtifactKeyProvider(),
            key_version=self.config.report_artifact_key_version,
        )
        return ReportArtifactIngressService(
            self.db,
            artifact_store=store,
            temp_root=Path(self.config.report_temp_root),
            remote_download_byte_ceiling=self.config.report_remote_download_byte_ceiling,
            temp_storage_ceiling_bytes=self.config.report_temp_storage_ceiling_bytes,
            min_free_disk_bytes=self.config.report_min_free_disk_bytes,
        )

    def upload_report_artifact(
        self,
        machine_token: str,
        *,
        artifact_upload_id: str,
        report_job_id: str,
        remote_result_id: str,
        remote_result_part_id: str | None,
        chunks,
        observed_mime: str | None,
    ):
        self.machine_auth.verify(machine_token)
        artifact = self._report_artifact_ingress().ingest_stream(
            artifact_upload_id=artifact_upload_id,
            report_job_id=report_job_id,
            remote_result_id=remote_result_id,
            remote_result_part_id=remote_result_part_id,
            chunks=chunks,
            observed_mime=observed_mime,
        )
        self.db.flush()
        return artifact

    def submit_result(self, machine_token: str, result: AgentResult) -> None:
        self.machine_auth.verify(machine_token)
        metadata = self.job_store.metadata(result.job_id, lock=True)
        if metadata.job.operation_id != result.operation_id:
            raise AgentReplayConflict("result operation_id mismatch")

        # A completed identical result is a pure replay. Return before core state
        # application and before any application-level follow-up, so duplicate
        # HTTP delivery cannot add another CheckRecord or schedule work twice.
        if metadata.state is AgentJobState.COMPLETED:
            row = self.db.get(AgentJobRecord, result.job_id)
            digest = hashlib.sha256(
                canonical_json(result.safe_dict()).encode("utf-8")
            ).hexdigest()
            if row is None or row.result_sha256 != digest:
                raise AgentReplayConflict("incompatible duplicate agent result")
            return

        if metadata.purpose == REPORT_AGENT_PURPOSE:
            # M11 report jobs never touch P0 write/document state. Complete the
            # durable agent delivery first, then advance only report control state.
            self.job_store.complete(result)
            TrueApiReportOrchestrator(
                self.db,
                participant_inn=self.config.own_inn,
                agent_lease_seconds=self.config.agent_job_lease_seconds,
                reports_enabled=self.config.true_api_reports_enabled,
            ).handle_agent_result(metadata, result)
            self.db.flush()
            return

        # Core applies write/poll state transitions before the application-level
        # follow-up is scheduled. CIS checks are intentionally decision-free in
        # the Windows process, so core only marks those jobs completed.
        self.core.submit_result(machine_token, result)
        if metadata.purpose == CONTROL_CIS:
            self._apply_control_cis(metadata.event_id, metadata.control_run_id, result)
        elif metadata.purpose == WRITE:
            self._after_write(result)
        elif metadata.purpose == POLL:
            self._after_poll(metadata.poll_attempt, result)
        elif metadata.purpose == RECONCILIATION_CIS:
            self._apply_reconciliation(metadata.event_id, result)
        elif metadata.purpose == "CIS_INVENTORY":
            # M1 read results are already sanitized/typed on Windows and durably
            # stored by the job store. No P0 control/write state is touched.
            pass
        elif metadata.purpose == "REFERENCE_PRODUCTS":
            # M2 is read-only; typed/sanitized results are already durable.
            pass
        elif metadata.purpose == "DOCUMENT_LIFECYCLE":
            # M4 is read-only; result/ledger persistence has no business mutation.
            pass
        else:
            raise AgentReplayConflict("unknown agent job purpose")
        self.db.flush()

    def _single_state(self, event: Event, result: AgentResult) -> KiState:
        if result.outcome != "CIS_CHECKED" or len(result.cises) != 1:
            raise AgentReplayConflict("CIS_CHECK result is incomplete")
        item = result.cises[0]
        if item.get("cis") != event.kiz:
            raise AgentReplayConflict("CIS_CHECK returned mismatched KI")
        return KiState(
            status=str(item.get("status") or "UNKNOWN:missing"),
            statusEx=item.get("statusEx"),
            withdrawReason=item.get("withdrawReason"),
            ownerInn=item.get("ownerInn"),
            productGroup=item.get("productGroup"),
        )

    def _apply_control_cis(self, event_id: str | None, run_id: str | None, result: AgentResult) -> None:
        if not event_id or not run_id:
            raise AgentReplayConflict("control CIS job misses orchestration metadata")
        row = self.imports.event(event_id)
        if row is None:
            raise KeyError(event_id)
        event = record_to_event(row)
        snapshot: KiState | None = None
        try:
            snapshot = self._single_state(event, result)
            outcome = decide(event, snapshot, self.config.own_inn)
        except Exception as exc:
            outcome = Outcome(Decision.ERROR, "STATE_LOOKUP_OR_NORMALIZATION_FAILED", type(exc).__name__)
        if self.imports.history_order_ambiguous(event.kiz):
            snapshot = None
            outcome = Outcome(Decision.MANUAL_REVIEW, "HISTORY_ORDER_AMBIGUOUS")
        self.db.add(
            CheckRecord(
                run_id=run_id,
                event_id=event_id,
                source="windows-agent-true-api",
                snapshot=asdict(snapshot) if snapshot else None,
                decision=outcome.decision.value,
                reason=outcome.reason,
                error=outcome.error,
            )
        )
        self.db.flush()
        if outcome.decision in {Decision.READY_TO_WITHDRAW, Decision.READY_TO_RETURN}:
            try:
                document = self.document_assembler.build_exact(event, outcome.decision)
            except ProductionDocumentContractUnconfirmed:
                # READY is preserved as the control decision, but fail closed:
                # no write operation/job exists until official exact bytes are available.
                return
            self.prepare_approved_write(event_id, document, decision=outcome.decision)

    def prepare_approved_write(
        self,
        event_id: str,
        document: ExactDocument,
        *,
        decision: Decision | None = None,
    ) -> AgentJob:
        row = self.imports.event(event_id)
        if row is None:
            raise KeyError(event_id)
        check = self.imports.latest_check(event_id)
        approved = decision or (Decision(check.decision) if check else None)
        if approved not in {Decision.READY_TO_WITHDRAW, Decision.READY_TO_RETURN}:
            raise InvalidWriteOperation("only READY control decisions can create a write job")
        expected = Decision(check.decision) if check else None
        if expected is not approved:
            raise InvalidWriteOperation("write decision must match latest stored control decision")
        document_type, operation_reason = (
            ("LK_RECEIPT", "DISTANCE")
            if approved is Decision.READY_TO_WITHDRAW
            else ("LP_RETURN", "REMOTE_SALE_RETURN")
        )
        op = self.write_store.prepare(
            event_id=event_id,
            decision=approved,
            document_type=document_type,
            operation_reason=operation_reason,
            pg=P0_PG,
            expected_inn=self.config.own_inn,
            document=document,
        )
        req = self.write_store.signing_request(op.operation_id)
        job_type = AgentJobType(req.document_type)
        job = AgentJob(
            job_id=_stable_job_id(WRITE, op.operation_id, req.document_sha256),
            job_type=job_type,
            operation_id=op.operation_id,
            pg=req.pg,
            expected_inn=req.expected_inn,
            document_type=req.document_type,
            document_sha256=req.document_sha256,
            product_document_base64=req.product_document_base64,
        )
        self.job_store.enqueue(job, purpose=WRITE, event_id=event_id)
        return job

    def _after_write(self, result: AgentResult) -> None:
        op = self.write_store.get(result.operation_id)
        if op.state is WriteState.SUBMITTED and op.document_id:
            self._schedule_poll(op.operation_id, op.document_id, attempt=1)

    def _poll_delay(self, attempt: int) -> int:
        exponent = max(0, attempt - 1)
        return min(
            self.config.agent_poll_max_seconds,
            self.config.agent_poll_initial_seconds * (2 ** min(exponent, 20)),
        )

    def _schedule_poll(self, operation_id: str, document_id: str, *, attempt: int) -> AgentJob:
        if attempt > self.config.agent_poll_max_attempts:
            self.write_store.mark_manual_review(operation_id, reason="POLL_ATTEMPT_LIMIT")
            raise InvalidWriteOperation("poll attempt limit reached")
        seed = f"{document_id}:{attempt}"
        job = AgentJob(
            job_id=_stable_job_id(POLL, operation_id, seed),
            job_type=AgentJobType.POLL_DOCUMENT,
            operation_id=operation_id,
            pg=P0_PG,
            expected_inn=self.config.own_inn,
            document_id=document_id,
        )
        available = datetime.now(timezone.utc) + timedelta(seconds=self._poll_delay(attempt))
        self.job_store.enqueue(
            job,
            purpose=POLL,
            event_id=self.write_store.get(operation_id).event_id,
            poll_attempt=attempt,
            available_at=available,
        )
        return job

    def _after_poll(self, attempt: int, result: AgentResult) -> None:
        op = self.write_store.get(result.operation_id)
        if op.state is WriteState.PROCESSING:
            if attempt >= self.config.agent_poll_max_attempts:
                self.write_store.mark_manual_review(result.operation_id, reason="POLL_ATTEMPT_LIMIT")
                return
            if not op.document_id:
                self.write_store.mark_manual_review(result.operation_id, reason="POLL_DOCUMENT_ID_MISSING")
                return
            self._schedule_poll(op.operation_id, op.document_id, attempt=attempt + 1)
            return
        if op.state is WriteState.RECONCILIATION_REQUIRED:
            row = self.imports.event(op.event_id)
            if row is None:
                self.write_store.reconciliation_result(op.operation_id, confirmed=False, details={"reason": "EVENT_NOT_FOUND"})
                return
            event = record_to_event(row)
            seed = hashlib.sha256(f"{op.operation_id}:{event.kiz}:reconcile".encode("utf-8")).hexdigest()
            job = AgentJob(
                job_id=_stable_job_id(RECONCILIATION_CIS, op.operation_id, seed),
                job_type=AgentJobType.CIS_CHECK,
                operation_id=op.operation_id,
                pg=P0_PG,
                expected_inn=self.config.own_inn,
                cises=(event.kiz,),
            )
            self.job_store.enqueue(job, purpose=RECONCILIATION_CIS, event_id=op.event_id)

    def _apply_reconciliation(self, event_id: str | None, result: AgentResult) -> None:
        op = self.write_store.get(result.operation_id)
        if op.state is not WriteState.RECONCILIATION_REQUIRED:
            return
        if not event_id or event_id != op.event_id:
            self.write_store.reconciliation_result(op.operation_id, confirmed=False, details={"reason": "EVENT_MISMATCH"})
            return
        row = self.imports.event(event_id)
        if row is None:
            self.write_store.reconciliation_result(op.operation_id, confirmed=False, details={"reason": "EVENT_NOT_FOUND"})
            return
        event = record_to_event(row)
        try:
            state = self._single_state(event, result)
            outcome = decide(event, state, self.config.own_inn)
            expected_reason = (
                "SALE_ALREADY_WITHDRAWN_DISTANCE"
                if op.document_type == "LK_RECEIPT"
                else "RETURN_ALREADY_IN_CIRCULATION"
            )
            confirmed = outcome.decision is Decision.ALREADY_DONE and outcome.reason == expected_reason
            details = {
                "decision": outcome.decision.value,
                "reason": outcome.reason,
                "status": state.status,
                "withdrawReason": state.withdrawReason,
            }
        except Exception as exc:
            confirmed = False
            details = {"reason": "RECONCILIATION_STATE_INVALID", "error_type": type(exc).__name__}
        self.write_store.reconciliation_result(op.operation_id, confirmed=confirmed, details=details)
