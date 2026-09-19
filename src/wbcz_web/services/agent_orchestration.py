from __future__ import annotations

from collections import Counter
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
from typing import Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session

from wbcz.control_engine import decide
from wbcz.models import Decision, Event, KiState, Outcome, canonical_json
from wbcz.windows_agent import (
    AgentAuthError,
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
from wbcz_web.models import AgentBindingRecord, AgentJobRecord, BootstrapRecord, CheckRecord, ControlRun, ParticipantRecord, ReportJobRecord
from wbcz_web.repositories import ImportRepository, SqlAlchemyAgentJobStore, SqlAlchemyWriteOperationStore
from wbcz_web.services.imports import record_to_event
from wbcz_web.services.agent_bindings import AgentBindingService, AgentPrincipal
from wbcz_web.services.integration_secrets import ReadOnlySecretProvider
from wbcz_web.services.production_secrets import build_artifact_key_provider
from wbcz_web.services.audit_history import (
    ActorContext,ActorKind,AuditOutcome,AuditService,AuditTenantScope,
    AuthorizationDecision,SubjectRef,SubjectType,TraceContext,
)
from wbcz.m11_reports import FilesystemReportArtifactStore
from wbcz_web.services.tenant import active_tenant, bind_tenant_scope, optional_tenant
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

def _tenant_or_legacy_inn(db: Session, config: WebConfig) -> str:
    scope = optional_tenant(db)
    if scope is not None:
        return scope.participant_inn
    if db.get(BootstrapRecord, 1) is not None:
        raise PermissionError("active tenant scope required")
    return config.own_inn


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
        self.scope = optional_tenant(db)
        if self.scope is None and db.get(BootstrapRecord, 1) is not None:
            raise PermissionError("active tenant scope required")

    def run(self, import_id: str, user_id: int, mode: str, event_ids: list[str] | None = None) -> dict:
        selected = _select_event_ids(self.imports, import_id, event_ids)
        run = ControlRun(
            organisation_id=self.scope.organisation_id if self.scope else None,
            participant_id=self.scope.participant_id if self.scope else None,
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
                expected_inn=self.scope.participant_inn if self.scope else self.config.own_inn,
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
        if not config.agent_enabled:
            raise InvalidWriteOperation("Windows agent server boundary is disabled")
        self.db = db
        self.config = config
        self.imports = ImportRepository(db)
        self.write_store = SqlAlchemyWriteOperationStore(db)
        # Backend orchestration must be able to enqueue tenant-routed jobs before
        # any Windows agent authenticates. Agent fetch/complete replaces this
        # producer store with an authenticated binding-scoped store.
        self.job_store: SqlAlchemyAgentJobStore = SqlAlchemyAgentJobStore(
            db, lease_seconds=config.agent_job_lease_seconds
        )
        self.machine_auth: MachineTokenVerifier | None = None
        self.core: VpsAgentBroker | None = None
        self.principal: AgentPrincipal | None = None
        self.document_assembler = document_assembler or UnavailableExactDocumentAssembler()

    def _authorize_agent(self, machine_token: str, *, mark_poll: bool = False) -> AgentPrincipal:
        bindings = AgentBindingService(self.db)
        try:
            principal = bindings.authenticate(machine_token, mark_poll=mark_poll)
        except AgentAuthError:
            if bindings.active_binding_count() > 0:
                # Once any M14 binding is active, the global credential can no
                # longer authenticate or drain NULL historical jobs.
                raise
            if (
                not getattr(self.config, "agent_legacy_bootstrap_enabled", True)
                or not self.config.agent_machine_token
            ):
                raise
            MachineTokenVerifier(self.config.agent_machine_token).verify(machine_token)
            participants = list(self.db.scalars(
                select(ParticipantRecord)
                .where(
                    ParticipantRecord.is_active.is_(True),
                    ParticipantRecord.verification_state == "VERIFIED",
                )
                .order_by(ParticipantRecord.id)
                .limit(2)
            ))
            if len(participants) > 1:
                raise AgentAuthError("legacy agent is disabled outside single-tenant mode")
            if participants:
                participant = participants[0]
                bind_tenant_scope(
                    self.db,
                    organisation_id=participant.organisation_id,
                    participant_id=participant.id,
                    user_id=None,
                    role=None,
                )
                principal = AgentPrincipal(
                    None, participant.organisation_id, participant.id, participant.inn, True
                )
            elif self.db.get(BootstrapRecord, 1) is not None:
                raise AgentAuthError("legacy agent has no verified participant")
            else:
                principal = AgentPrincipal(None, None, None, self.config.own_inn, True)

        self.principal = principal
        self.machine_auth = MachineTokenVerifier(machine_token)
        self.job_store = SqlAlchemyAgentJobStore(
            self.db,
            lease_seconds=self.config.agent_job_lease_seconds,
            agent_binding_id=principal.binding_id,
            organisation_id=principal.organisation_id,
            participant_id=principal.participant_id,
            legacy_unbound=principal.legacy,
        )
        self.core = VpsAgentBroker(
            write_store=self.write_store,
            job_store=self.job_store,
            machine_auth=self.machine_auth,
            own_inn=principal.participant_inn,
        )
        return principal

    def check_auth(self, machine_token: str) -> None:
        self._authorize_agent(machine_token)

    def fetch_one(self, machine_token: str) -> AgentJob | None:
        self._authorize_agent(machine_token, mark_poll=True)
        assert self.core is not None
        return self.core.fetch_one(machine_token)

    def _report_artifact_ingress(self) -> ReportArtifactIngressService:
        if not self.config.report_artifact_root or not self.config.report_temp_root:
            raise InvalidWriteOperation("M11 report artifact storage is not configured")
        store = FilesystemReportArtifactStore(
            Path(self.config.report_artifact_root),
            key_provider=build_artifact_key_provider(self.config),
            key_version=self.config.report_artifact_key_version,
            min_free_disk_bytes=self.config.report_min_free_disk_bytes,
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
        principal = self._authorize_agent(machine_token)
        artifact = self._report_artifact_ingress().ingest_stream(
            artifact_upload_id=artifact_upload_id,
            report_job_id=report_job_id,
            remote_result_id=remote_result_id,
            remote_result_part_id=remote_result_part_id,
            chunks=chunks,
            observed_mime=observed_mime,
        )
        job=self.db.get(ReportJobRecord,report_job_id)
        if job is None or not job.organisation_id or not job.participant_id:
            raise AgentReplayConflict("report artifact has no tenant-owned report job")
        if (
            principal.binding_id is not None
            and (job.organisation_id != principal.organisation_id or job.participant_id != principal.participant_id)
        ):
            raise AgentReplayConflict("agent cannot upload an artifact for another tenant")
        AuditService(
            self.db,
            pseudonym_key=self.db.info.get("audit_pseudonym_key"),
            pseudonym_key_id=self.db.info.get("audit_pseudonym_key_id"),
        ).append(
            event_type="AGENT_ARTIFACT_UPLOADED",
            actor=ActorContext(
                ActorKind.WINDOWS_AGENT,
                machine_principal=(
                    f"agent-binding:{principal.binding_id}" if principal.binding_id
                    else "legacy-windows-agent"
                ),
            ),
            tenant=AuditTenantScope(job.organisation_id,job.participant_id),
            subject=SubjectRef(SubjectType.REPORT_ARTIFACT,artifact.artifact_id),
            outcome=AuditOutcome.SUCCESS,
            authorization_decision=AuthorizationDecision.NOT_APPLICABLE,
            trace=TraceContext(
                correlation_id=job.correlation_id,
                causation_id=job.causation_id,
                operation_id=job.id,
                event_key=f"agent-artifact:{artifact_upload_id}:{artifact.artifact_id}"[:256],
            ),
            metadata={
                "report_job_id":job.id,"artifact_id":artifact.artifact_id,
                "artifact_sha256":artifact.sha256,"byte_size":artifact.byte_size,
                "remote_result_part_id":remote_result_part_id,
            },
            evidence_hashes=(artifact.sha256,),
        )
        self.db.flush()
        return artifact

    def submit_result(self, machine_token: str, result: AgentResult) -> None:
        principal = self._authorize_agent(machine_token)
        assert self.job_store is not None and self.machine_auth is not None and self.core is not None
        metadata = self.job_store.metadata(result.job_id, lock=True)
        job_row = self.db.get(AgentJobRecord, result.job_id)
        if job_row is None:
            raise AgentReplayConflict("unknown agent job")
        if job_row.organisation_id and job_row.participant_id:
            bind_tenant_scope(
                self.db,
                organisation_id=job_row.organisation_id,
                participant_id=job_row.participant_id,
            )
            self.db.info["audit_trace"]={
                "request_id":job_row.job_id,
                "correlation_id":job_row.correlation_id or job_row.job_id,
                "causation_id":job_row.job_id,
            }
        elif self.db.get(BootstrapRecord, 1) is not None:
            raise AgentReplayConflict("post-bootstrap agent job has no tenant ownership")
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

        if metadata.purpose == "INTEGRATION_HEALTH":
            if principal.binding_id is None:
                raise AgentReplayConflict("M14 health jobs require a participant-bound agent")
            binding = self.db.get(AgentBindingRecord, principal.binding_id)
            if (
                binding is None
                or binding.organisation_id != principal.organisation_id
                or binding.participant_id != principal.participant_id
                or binding.state != "ACTIVE"
            ):
                raise AgentReplayConflict("agent binding is inactive or tenant-mismatched")
            from wbcz_web.services.integration_settings import IntegrationSettingsService
            IntegrationSettingsService(
                self.db,
                self.config,
                secret_provider=ReadOnlySecretProvider(),
            ).apply_agent_health_result(binding, result)
            self.job_store.complete(result)
            self.db.flush()
            return

        if metadata.purpose == REPORT_AGENT_PURPOSE:
            # M11 report jobs never touch P0 write/document state. Complete the
            # durable agent delivery first, then advance only report control state.
            self.job_store.complete(result)
            TrueApiReportOrchestrator(
                self.db,
                participant_inn=_tenant_or_legacy_inn(self.db, self.config),
                agent_lease_seconds=self.config.agent_job_lease_seconds,
                reports_enabled=self.config.true_api_reports_enabled,
            ).handle_agent_result(metadata, result)
            self.db.flush()
            return

        # Core applies write/poll state transitions before the application-level
        # follow-up is scheduled. Construct the P0 core with the already verified
        # active participant INN; frozen P0 code remains unchanged.
        tenant_core = VpsAgentBroker(
            write_store=self.write_store,
            job_store=self.job_store,
            machine_auth=self.machine_auth,
            own_inn=principal.participant_inn,
        )
        tenant_core.submit_result(machine_token, result)
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
            outcome = decide(event, snapshot, _tenant_or_legacy_inn(self.db, self.config))
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
            expected_inn=_tenant_or_legacy_inn(self.db, self.config),
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
            expected_inn=_tenant_or_legacy_inn(self.db, self.config),
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
                expected_inn=_tenant_or_legacy_inn(self.db, self.config),
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
            outcome = decide(event, state, op.expected_inn)
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
