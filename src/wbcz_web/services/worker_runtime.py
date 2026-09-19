from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import errno
import os
from pathlib import Path
import random
import signal
import socket
import time
from uuid import uuid4

from sqlalchemy import and_, select
from sqlalchemy.exc import DBAPIError, OperationalError
from sqlalchemy.orm import Session

from wbcz.m11_reports import ArtifactLimitExceeded, FilesystemReportArtifactStore, ReportSecurityError
from wbcz_web.models import (
    AggregationOperationLedgerRecord, ReportJobRecord, TurnoverOperationLedgerRecord,
    WorkerHeartbeatRecord, WriteOperationRecord,
)
from wbcz_web.repositories.reports import ClaimedReportJob, SqlReportRepository
from wbcz_web.services.production_hardening import (
    ManualReviewService, RetryClassification, classify_failure, retry_decision,
)
from wbcz_web.services.production_secrets import build_artifact_key_provider
from wbcz_web.services.reports import SynchronousReportExecutor
from wbcz_web.services.runtime_health import audit_key_material
from wbcz_web.services.tenant import bind_tenant_scope


SCHEDULER_DOMAIN_POLICY = {
    "M4": "POLL_NONTERMINAL_TYPED_READ_ONLY",
    "M5": "READ_RECONCILE_NO_BLIND_REPOST",
    "M6": "READ_RECONCILE_NO_BLIND_REPOST",
    "M7": "READ_ONLY_FOUNDATION_NO_XML_WRITE",
    "M8": "FOUNDATION_ONLY_NO_SUZ_ORDER",
    "M9": "WB_READ_RECONCILIATION_ONLY",
    "M10": "NO_REMOTE_SCHEDULE",
    "M11": "REMOTE_REPORT_POLL_BOUNDED_MAX_AGE",
    "M14": "LOW_FREQUENCY_TYPED_HEALTH_ONLY",
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


class WorkerHeartbeatService:
    def __init__(self, db: Session, *, worker_id: str, instance_id: str, build_sha: str) -> None:
        self.db = db
        self.worker_id = worker_id
        self.instance_id = instance_id
        self.build_sha = build_sha

    def beat(self, *, state: str = "RUNNING", scheduler: bool = False) -> WorkerHeartbeatRecord:
        now = _now()
        row = self.db.get(WorkerHeartbeatRecord, self.worker_id)
        if row is None:
            row = WorkerHeartbeatRecord(
                worker_id=self.worker_id,
                role="worker",
                instance_id=self.instance_id,
                state=state,
                build_sha=self.build_sha,
                started_at=now,
                heartbeat_at=now,
                scheduler_heartbeat_at=now if scheduler else None,
                metadata_json={"pid": os.getpid()},
            )
            self.db.add(row)
        else:
            row.state = state
            row.heartbeat_at = now
            row.build_sha = self.build_sha
            if scheduler:
                row.scheduler_heartbeat_at = now
        self.db.flush()
        return row


class ProductionScheduler:
    """Authoritative-state scanner. It never emits a blind business mutation."""

    def __init__(self, db: Session, *, config, worker_id: str) -> None:
        self.db = db
        self.config = config
        self.worker_id = worker_id

    def _review_for_row(
        self,
        *,
        organisation_id: str | None,
        participant_id: str | None,
        domain: str,
        reason: str,
        subject_type: str,
        subject_id: str,
        operation_id: str | None,
        severity: str = "HIGH",
    ) -> None:
        if not organisation_id or not participant_id:
            return
        bind_tenant_scope(
            self.db, organisation_id=organisation_id, participant_id=participant_id,
            user_id=None, role=None,
        )
        ManualReviewService(self.db).open_or_converge(
            domain=domain,
            reason_code=reason,
            subject_type=subject_type,
            subject_id=subject_id,
            operation_id=operation_id,
            severity=severity,
            metadata={"scheduler_policy": SCHEDULER_DOMAIN_POLICY.get(domain, "TYPED_REVIEW")},
        )

    def tick(self) -> dict[str, int]:
        opened = 0
        # Existing P0 remote ambiguity/reconciliation remains evidence-first:
        # scheduler creates/converges a review case, never calls create again.
        writes = list(self.db.scalars(select(WriteOperationRecord).where(
            WriteOperationRecord.state.in_(("MANUAL_REVIEW", "RECONCILIATION_REQUIRED"))
        ).limit(200)))
        for row in writes:
            self._review_for_row(
                organisation_id=row.organisation_id, participant_id=row.participant_id,
                domain="P0", reason="REMOTE_OPERATION_REQUIRES_RECONCILIATION",
                subject_type="WRITE_OPERATION", subject_id=row.operation_id,
                operation_id=row.operation_id,
            )
            opened += 1

        for model, domain in (
            (TurnoverOperationLedgerRecord, "M5"),
            (AggregationOperationLedgerRecord, "M6"),
        ):
            rows = list(self.db.scalars(select(model).where(
                model.reconciliation_state.in_(("RECONCILIATION_PENDING", "MANUAL_REVIEW"))
            ).limit(200)))
            for row in rows:
                self._review_for_row(
                    organisation_id=row.organisation_id, participant_id=row.participant_id,
                    domain=domain, reason="RECONCILIATION_REQUIRED",
                    subject_type="DOMAIN_OPERATION", subject_id=row.operation_id,
                    operation_id=row.operation_id,
                    severity="WARNING" if row.reconciliation_state == "RECONCILIATION_PENDING" else "HIGH",
                )
                opened += 1

        remote_max_age = _now() - timedelta(seconds=self.config.scheduler_max_age_seconds)
        reports = list(self.db.scalars(select(ReportJobRecord).where(
            ReportJobRecord.origin == "TRUE_API_REMOTE",
            ReportJobRecord.state.in_(("REQUESTED", "QUEUED", "GENERATING")),
            ReportJobRecord.requested_at <= remote_max_age,
        ).limit(200)))
        for row in reports:
            self._review_for_row(
                organisation_id=row.organisation_id, participant_id=row.participant_id,
                domain="M11", reason="REMOTE_REPORT_MAX_AGE",
                subject_type="REPORT_JOB", subject_id=row.id,
                operation_id=row.id, severity="HIGH",
            )
            opened += 1

        ambiguous_reports = list(self.db.scalars(select(ReportJobRecord).where(
            ReportJobRecord.remote_create_ambiguous.is_(True),
            ReportJobRecord.state.notin_(("READY", "EXPIRED", "CANCELLED")),
        ).limit(200)))
        for row in ambiguous_reports:
            self._review_for_row(
                organisation_id=row.organisation_id, participant_id=row.participant_id,
                domain="M11", reason="AMBIGUOUS_AFTER_SEND",
                subject_type="REPORT_JOB", subject_id=row.id,
                operation_id=row.id, severity="HIGH",
            )
            opened += 1
        self.db.info.pop("tenant_scope", None)
        return {"manual_review_observations": opened}


def classify_worker_exception(exc: BaseException) -> RetryClassification:
    if isinstance(exc, (OperationalError, DBAPIError)):
        return RetryClassification.DATABASE_TRANSIENT
    if isinstance(exc, OSError):
        if getattr(exc, "errno", None) in {errno.ENOSPC, errno.EIO, errno.ESTALE}:
            return RetryClassification.STORAGE_TRANSIENT
    if isinstance(exc, ArtifactLimitExceeded):
        return RetryClassification.DETERMINISTIC_FAILURE
    if isinstance(exc, (ValueError, PermissionError, ReportSecurityError)):
        return RetryClassification.VALIDATION_FAILURE
    return classify_failure(error_code=type(exc).__name__)


@dataclass(slots=True)
class ProductionWorkerRuntime:
    session_factory: object
    config: object
    worker_id: str
    instance_id: str
    draining: bool = False

    @classmethod
    def build(cls, session_factory, config):
        instance = os.getenv("WBCZ_WORKER_INSTANCE_ID", "").strip() or (socket.gethostname() + "-" + uuid4().hex[:12])
        worker_id = "worker:" + instance
        return cls(session_factory, config, worker_id, instance)

    def _prime_session(self, db: Session) -> None:
        key, key_id = audit_key_material(self.config)
        if key:
            db.info["audit_pseudonym_key"] = key
            db.info["audit_pseudonym_key_id"] = key_id

    def _artifact_store(self) -> FilesystemReportArtifactStore:
        if not self.config.report_artifact_root:
            raise RuntimeError("artifact root is not configured")
        return FilesystemReportArtifactStore(
            Path(self.config.report_artifact_root),
            key_provider=build_artifact_key_provider(self.config),
            key_version=self.config.report_artifact_key_version,
        )

    def heartbeat(self, *, state: str = "RUNNING", scheduler: bool = False) -> None:
        with self.session_factory() as db:
            self._prime_session(db)
            WorkerHeartbeatService(
                db, worker_id=self.worker_id, instance_id=self.instance_id, build_sha=self.config.build_sha
            ).beat(state=state, scheduler=scheduler)
            db.commit()

    def scheduler_tick(self) -> None:
        with self.session_factory() as db:
            self._prime_session(db)
            WorkerHeartbeatService(
                db, worker_id=self.worker_id, instance_id=self.instance_id, build_sha=self.config.build_sha
            ).beat(state="DRAINING" if self.draining else "RUNNING", scheduler=True)
            ProductionScheduler(db, config=self.config, worker_id=self.worker_id).tick()
            db.commit()

    def _claim(self) -> ClaimedReportJob | None:
        with self.session_factory() as db:
            self._prime_session(db)
            claimed = SqlReportRepository(db).claim_next(
                worker_id=self.worker_id,
                lease_seconds=self.config.worker_lease_seconds,
                max_attempts=3,
            )
            db.commit()  # claim commits before any filesystem/external work
            return claimed

    def _execute(self, claimed: ClaimedReportJob) -> None:
        db = self.session_factory()
        try:
            self._prime_session(db)
            executor = SynchronousReportExecutor(
                db,
                artifact_store=self._artifact_store(),
                temp_root=Path(self.config.report_temp_root),
                participant_inn=claimed.participant_inn,
                max_rows=self.config.report_max_local_rows,
                max_artifact_bytes=self.config.report_max_artifact_bytes,
                db_fetch_batch_size=self.config.report_db_fetch_batch_size,
                snapshot_timeout_seconds=self.config.report_snapshot_timeout_seconds,
                worker_timeout_seconds=self.config.report_worker_timeout_seconds,
                temp_storage_ceiling_bytes=self.config.report_temp_storage_ceiling_bytes,
                min_free_disk_bytes=self.config.report_min_free_disk_bytes,
            )
            executor.execute_claimed(claimed, terminal_on_error=False)
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def _handle_failure(self, claimed: ClaimedReportJob, exc: BaseException) -> None:
        classification = classify_worker_exception(exc)
        with self.session_factory() as db:
            self._prime_session(db)
            row = db.get(ReportJobRecord, claimed.job_id)
            if row is None:
                return
            decision = retry_decision(
                classification,
                semantic_retry_count=row.semantic_retry_count,
                now=_now(),
                operation_deadline=row.requested_at + timedelta(seconds=self.config.scheduler_max_age_seconds),
            )
            repo = SqlReportRepository(db)
            if decision.retry:
                repo.schedule_retry(
                    row.id,
                    classification=classification.value,
                    available_at=_now() + timedelta(seconds=decision.delay_seconds),
                    consumes_semantic_attempt=decision.consumes_semantic_attempt,
                    error_code=classification.value,
                )
            else:
                repo.fail(row.id, code=classification.value, message_redacted="worker terminal failure")
                row = db.get(ReportJobRecord, claimed.job_id)
                if row and row.organisation_id and row.participant_id:
                    bind_tenant_scope(
                        db, organisation_id=row.organisation_id, participant_id=row.participant_id,
                        user_id=None, role=None,
                    )
                    ManualReviewService(db).open_or_converge(
                        domain="M11",
                        reason_code=decision.terminal_reason or classification.value,
                        subject_type="REPORT_JOB",
                        subject_id=row.id,
                        operation_id=row.id,
                        severity="HIGH",
                        metadata={"retry_classification": classification.value},
                    )
            db.commit()

    def run_once(self) -> bool:
        self.heartbeat(state="DRAINING" if self.draining else "RUNNING")
        if self.draining:
            return False
        claimed = self._claim()
        if claimed is None:
            return False
        try:
            self._execute(claimed)
        except BaseException as exc:
            self._handle_failure(claimed, exc)
        return True

    def cleanup_ephemeral(self, *, older_than_seconds: int = 3600) -> int:
        removed = 0
        now = time.time()
        for root_value in (self.config.report_temp_root, self.config.report_artifact_root):
            if not root_value:
                continue
            root = Path(root_value)
            if not root.is_dir():
                continue
            for path in root.glob("*.tmp"):
                try:
                    if now - path.stat().st_mtime >= older_than_seconds:
                        path.unlink()
                        removed += 1
                except OSError:
                    continue
        return removed

    def run_forever(self) -> None:
        stop = False

        def request_stop(*_: object) -> None:
            nonlocal stop
            stop = True
            self.draining = True

        for name in ("SIGINT", "SIGTERM"):
            sig = getattr(signal, name, None)
            if sig is not None:
                signal.signal(sig, request_stop)

        self.heartbeat()
        next_scheduler = 0.0
        while not stop:
            now_mono = time.monotonic()
            if now_mono >= next_scheduler:
                self.scheduler_tick()
                self.cleanup_ephemeral()
                next_scheduler = now_mono + self.config.scheduler_interval_seconds
            worked = self.run_once()
            if not worked and not stop:
                # Sleep happens only outside DB claim/domain transactions.
                time.sleep(random.uniform(0.25, 1.0))
        self.heartbeat(state="STOPPED")
