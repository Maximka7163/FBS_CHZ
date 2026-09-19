from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
import hashlib
import uuid
from typing import Any, Mapping

from sqlalchemy import and_, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from wbcz.m11_reports import (
    ArtifactIntegrityConflict,
    ReportArtifactUploadBinding,
    ReportJobState,
    ReportSecurityError,
    UploadBindingStore,
    sanitize_report_evidence,
)
from wbcz_web.models import BootstrapRecord
from wbcz_web.services.audit_history import (
    ActorContext,ActorKind,AuditOutcome,AuditService,AuditTenantScope,
    AuthorizationDecision,SubjectRef,SubjectType,TraceContext,
)
from wbcz_web.models.reports import (
    ReportArtifactRecord,
    ReportArtifactUploadRecord,
    ReportJobEventRecord,
    ReportJobRecord,
    ReportSnapshotRecord,
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True, slots=True)
class ClaimedReportJob:
    job_id: str
    participant_inn: str
    report_type: str
    report_schema_version: str
    output_format: str
    sensitivity_class: str
    filters_sanitized: Mapping[str, Any]
    request_fingerprint_sha256: str
    attempt_count: int
    lease_owner: str
    lease_expires_at: datetime


class SqlReportRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def _immutable(
        self,
        row: ReportJobRecord,
        event_type: str,
        *,
        actor_kind: ActorKind,
        actor_user_id: int | None = None,
        machine_principal: str | None = None,
        subject_type: SubjectType = SubjectType.REPORT_JOB,
        subject_id: str | None = None,
        outcome: AuditOutcome = AuditOutcome.SUCCESS,
        authorization_decision: AuthorizationDecision = AuthorizationDecision.NOT_APPLICABLE,
        metadata: Mapping[str, Any] | None = None,
        evidence_hashes: tuple[str, ...] = (),
        event_key_suffix: str,
    ) -> None:
        if not row.organisation_id or not row.participant_id:
            return
        AuditService(
            self.db,
            pseudonym_key=self.db.info.get("audit_pseudonym_key"),
            pseudonym_key_id=self.db.info.get("audit_pseudonym_key_id"),
        ).append(
            event_type=event_type,
            actor=ActorContext(actor_kind, user_id=actor_user_id, machine_principal=machine_principal),
            tenant=AuditTenantScope(row.organisation_id, row.participant_id),
            subject=SubjectRef(subject_type, subject_id or row.id),
            outcome=outcome,
            authorization_decision=authorization_decision,
            trace=TraceContext(
                correlation_id=row.correlation_id,
                causation_id=row.causation_id,
                operation_id=row.id,
                event_key=f"report:{row.id}:{event_key_suffix}"[:256],
            ),
            metadata=dict(metadata or {}),
            evidence_hashes=evidence_hashes,
        )

    def event(
        self,
        job_id: str,
        event_type: str,
        *,
        from_state: str | None = None,
        to_state: str | None = None,
        details: Mapping[str, Any] | None = None,
        artifact_id: str | None = None,
        remote_task_id: str | None = None,
        remote_result_id: str | None = None,
        evidence_sha256: str | None = None,
        actor_user_id: str | None = None,
    ) -> None:
        safe = sanitize_report_evidence(dict(details or {}))
        self.db.add(
            ReportJobEventRecord(
                report_job_id=job_id,
                event_type=event_type,
                from_state=from_state,
                to_state=to_state,
                details_redacted=safe if isinstance(safe, dict) else {"value": safe},
                artifact_id=artifact_id,
                remote_task_id=remote_task_id,
                remote_result_id=remote_result_id,
                evidence_sha256=evidence_sha256,
                actor_user_id=actor_user_id,
            )
        )

    def create_job(
        self,
        *,
        origin: str,
        participant_inn: str,
        report_type: str,
        report_schema_version: str,
        output_format: str,
        sensitivity_class: str,
        filters_sanitized: Mapping[str, Any],
        sensitive_filter_ref: str | None,
        request_fingerprint_sha256: str,
        requested_by_user_id: str | None,
        requested_at: datetime | None = None,
    ) -> ReportJobRecord:
        now = requested_at or _now()
        job_id = "rpt_" + uuid.uuid4().hex
        scope = self.db.info.get("tenant_scope")
        organisation_id = participant_id = None
        if isinstance(scope, dict) and scope.get("organisation_id") and scope.get("participant_id"):
            if participant_inn != scope.get("participant_inn"):
                raise ReportSecurityError("report participant must match active tenant scope")
            organisation_id = str(scope["organisation_id"])
            participant_id = str(scope["participant_id"])
        elif self.db.get(BootstrapRecord, 1) is not None:
            raise ReportSecurityError("post-bootstrap report jobs require tenant scope")
        trace_data=self.db.info.get("audit_trace")
        correlation_id=trace_data.get("correlation_id") if isinstance(trace_data,dict) else None
        causation_id=trace_data.get("request_id") if isinstance(trace_data,dict) else None
        row = ReportJobRecord(
            id=job_id,
            organisation_id=organisation_id,
            participant_id=participant_id,
            correlation_id=correlation_id,
            causation_id=causation_id,
            origin=origin,
            participant_inn=participant_inn,
            report_type=report_type,
            report_schema_version=report_schema_version,
            output_format=output_format,
            sensitivity_class=sensitivity_class,
            filters_sanitized_json=dict(sanitize_report_evidence(dict(filters_sanitized))),
            sensitive_filter_ref=sensitive_filter_ref,
            request_fingerprint_sha256=request_fingerprint_sha256,
            state=ReportJobState.REQUESTED.value,
            remote_metadata_sanitized={},
            remote_create_ambiguous=False,
            requested_by_user_id=requested_by_user_id,
            requested_at=now,
            attempt_count=0,
        )
        self.db.add(row)
        self.db.flush()
        self.event(job_id, "requested", to_state=ReportJobState.REQUESTED.value, actor_user_id=requested_by_user_id)
        self.db.flush()
        actor_user_id=int(requested_by_user_id) if requested_by_user_id and str(requested_by_user_id).isdigit() else None
        self._immutable(
            row,
            "REPORT_REQUESTED",
            actor_kind=ActorKind.USER if actor_user_id is not None else ActorKind.WORKER,
            actor_user_id=actor_user_id,
            machine_principal=None if actor_user_id is not None else "report-request-worker",
            outcome=AuditOutcome.PENDING,
            authorization_decision=AuthorizationDecision.ALLOW if actor_user_id is not None else AuthorizationDecision.NOT_APPLICABLE,
            metadata={
                "report_job_id":row.id,"report_type":row.report_type,"format":row.output_format,
                "sensitivity_class":row.sensitivity_class,"schema_version":row.report_schema_version,
                "request_fingerprint_sha256":row.request_fingerprint_sha256,"origin":row.origin,
            },
            event_key_suffix="requested",
        )
        self.db.flush()
        return row

    def queue(self, job_id: str) -> ReportJobRecord:
        row = self.db.scalar(select(ReportJobRecord).where(ReportJobRecord.id == job_id).with_for_update())
        if row is None:
            raise KeyError(job_id)
        current = ReportJobState(row.state)
        if current is not ReportJobState.REQUESTED:
            if current in {ReportJobState.QUEUED, ReportJobState.GENERATING, ReportJobState.READY}:
                return row
            raise ReportSecurityError(f"report job cannot queue from {current.value}")
        row.state = ReportJobState.QUEUED.value
        self.event(job_id, "queued", from_state=current.value, to_state=row.state)
        self.db.flush()
        return row

    def _has_ready_output(self, job_id: str) -> bool:
        return self.db.scalar(
            select(ReportArtifactRecord.artifact_id).where(
                ReportArtifactRecord.report_job_id == job_id,
                ReportArtifactRecord.artifact_role == "OUTPUT",
                ReportArtifactRecord.state == "READY",
                ReportArtifactRecord.deleted_at.is_(None),
            ).limit(1)
        ) is not None

    def claim_next(
        self,
        *,
        worker_id: str,
        lease_seconds: int = 120,
        max_attempts: int = 3,
        now: datetime | None = None,
    ) -> ClaimedReportJob | None:
        if not worker_id or lease_seconds <= 0 or max_attempts <= 0:
            raise ValueError("invalid worker lease configuration")
        now = now or _now()
        stmt = (
            select(ReportJobRecord)
            .where(
                or_(
                    ReportJobRecord.state == ReportJobState.QUEUED.value,
                    and_(
                        ReportJobRecord.state == ReportJobState.GENERATING.value,
                        ReportJobRecord.lease_expires_at.is_not(None),
                        ReportJobRecord.lease_expires_at <= now,
                    ),
                )
            )
            .order_by(ReportJobRecord.requested_at, ReportJobRecord.id)
            .with_for_update(skip_locked=True)
            .limit(1)
        )
        row = self.db.scalar(stmt)
        if row is None:
            return None
        previous = row.state
        if self._has_ready_output(row.id):
            row.state = ReportJobState.READY.value
            row.lease_owner = None
            row.lease_expires_at = None
            self.event(row.id, "lease_recovered", from_state=previous, to_state=row.state, details={"reason": "ready_output_exists"})
            self.db.flush()
            return None
        if row.attempt_count >= max_attempts:
            row.state = ReportJobState.FAILED.value
            row.error_code = "ATTEMPT_LIMIT"
            row.error_message_redacted = "bounded report attempt limit reached"
            row.lease_owner = None
            row.lease_expires_at = None
            self.event(row.id, "generation_failed", from_state=previous, to_state=row.state, details={"reason": "attempt_limit"})
            self._immutable(
                row,"REPORT_GENERATION_FAILED",actor_kind=ActorKind.WORKER,
                machine_principal=worker_id,outcome=AuditOutcome.FAILED,
                metadata={"report_job_id":row.id,"error_code":"ATTEMPT_LIMIT","attempt_count":row.attempt_count},
                event_key_suffix=f"generation-failed-attempt-limit:{row.attempt_count}",
            )
            self.db.flush()
            return None
        reclaimed = previous == ReportJobState.GENERATING.value
        row.state = ReportJobState.GENERATING.value
        row.lease_owner = worker_id
        row.claimed_at = row.claimed_at or now
        row.heartbeat_at = now
        row.lease_expires_at = now + timedelta(seconds=lease_seconds)
        row.attempt_count += 1
        row.started_at = row.started_at or now
        self.event(
            row.id,
            "lease_recovered" if reclaimed else "claimed",
            from_state=previous,
            to_state=row.state,
            details={"attempt_count": row.attempt_count},
        )
        self.event(row.id, "generation_started", from_state=row.state, to_state=row.state)
        self._immutable(
            row,"REPORT_GENERATION_STARTED",actor_kind=ActorKind.WORKER,
            machine_principal=worker_id,outcome=AuditOutcome.PENDING,
            metadata={
                "report_job_id":row.id,"attempt_count":row.attempt_count,
                "lease_recovered":reclaimed,
            },
            event_key_suffix=f"generation-started:{row.attempt_count}",
        )
        self.db.flush()
        return ClaimedReportJob(
            row.id,
            row.participant_inn,
            row.report_type,
            row.report_schema_version,
            row.output_format,
            row.sensitivity_class,
            dict(row.filters_sanitized_json or {}),
            row.request_fingerprint_sha256,
            row.attempt_count,
            worker_id,
            row.lease_expires_at,
        )

    def heartbeat(
        self,
        job_id: str,
        *,
        worker_id: str,
        lease_seconds: int,
        now: datetime | None = None,
    ) -> None:
        now = now or _now()
        row = self.db.scalar(select(ReportJobRecord).where(ReportJobRecord.id == job_id).with_for_update())
        if row is None:
            raise KeyError(job_id)
        if row.state != ReportJobState.GENERATING.value or row.lease_owner != worker_id:
            raise ReportSecurityError("report lease ownership mismatch")
        row.heartbeat_at = now
        row.lease_expires_at = now + timedelta(seconds=lease_seconds)
        self.db.flush()

    def record_snapshot(self, job_id: str, descriptor: Any) -> ReportSnapshotRecord:
        payload = descriptor.canonical_payload()
        snapshot_id = "snap_" + uuid.uuid4().hex
        row = ReportSnapshotRecord(
            id=snapshot_id,
            report_job_id=job_id,
            strategy=payload["strategy"],
            snapshot_at=descriptor.snapshot_at,
            source_domains=list(payload["source_domains"]),
            source_tables=list(payload["source_tables"]),
            high_water_metadata=dict(payload["high_water_metadata"]),
            source_filter_sanitized=dict(sanitize_report_evidence(payload["source_filter_sanitized"])),
            descriptor_sha256=descriptor.descriptor_sha256,
            schema_version=payload["schema_version"],
            internal_snapshot_artifact_id=payload["internal_snapshot_artifact_id"],
            row_count=payload["row_count"],
        )
        self.db.add(row)
        self.db.flush()
        job = self.db.get(ReportJobRecord, job_id)
        if job is None:
            raise KeyError(job_id)
        job.snapshot_id = snapshot_id
        self.db.flush()
        return row

    def finalize_artifact(
        self,
        *,
        job_id: str,
        artifact_id: str,
        artifact_role: str,
        publication_key: str,
        storage_backend: str,
        storage_key: str,
        format: str,
        mime: str | None,
        safe_filename: str,
        byte_size: int,
        sha256: str,
        sensitivity_class: str,
        encryption_metadata: Mapping[str, Any],
        encryption_version: str | None,
        remote_result_id: str | None = None,
        remote_result_part_id: str | None = None,
        remote_file_delete_date_raw: str | None = None,
        remote_file_delete_at: datetime | None = None,
    ) -> ReportArtifactRecord:
        existing = self.db.scalar(
            select(ReportArtifactRecord).where(ReportArtifactRecord.publication_key == publication_key).with_for_update()
        )
        if existing is not None:
            same = (
                existing.report_job_id == job_id
                and existing.sha256 == sha256
                and existing.byte_size == byte_size
                and existing.storage_key == storage_key
                and existing.state == "READY"
            )
            if same:
                return existing
            raise ArtifactIntegrityConflict("publication key already finalized with different artifact")

        row = ReportArtifactRecord(
            artifact_id=artifact_id,
            report_job_id=job_id,
            artifact_role=artifact_role,
            publication_key=publication_key,
            state="READY",
            storage_backend=storage_backend,
            storage_key=storage_key,
            format=format,
            mime=mime,
            safe_filename=safe_filename,
            byte_size=byte_size,
            sha256=sha256,
            sensitivity_class=sensitivity_class,
            encryption_metadata=dict(sanitize_report_evidence(dict(encryption_metadata))),
            encryption_version=encryption_version,
            remote_result_id=remote_result_id,
            remote_result_part_id=remote_result_part_id,
            remote_file_delete_date_raw=remote_file_delete_date_raw,
            remote_file_delete_at=remote_file_delete_at,
            expires_at=None,
        )
        self.db.add(row)
        try:
            self.db.flush()
        except IntegrityError as exc:
            raise ArtifactIntegrityConflict("artifact publication conflict") from exc
        self.event(
            job_id,
            "artifact_stored",
            artifact_id=artifact_id,
            remote_result_id=remote_result_id,
            evidence_sha256=sha256,
            details={"role": artifact_role, "format": format, "byte_size": byte_size},
        )
        job=self.db.get(ReportJobRecord,job_id)
        if job is None:raise KeyError(job_id)
        self._immutable(
            job,"REPORT_ARTIFACT_FINALIZED",actor_kind=ActorKind.WORKER,
            machine_principal="report-artifact-worker",
            subject_type=SubjectType.REPORT_ARTIFACT,subject_id=artifact_id,
            outcome=AuditOutcome.SUCCESS,
            metadata={
                "report_job_id":job.id,"artifact_id":artifact_id,"artifact_role":artifact_role,
                "format":format,"sensitivity_class":sensitivity_class,"byte_size":byte_size,
                "artifact_sha256":sha256,"remote_result_part_id":remote_result_part_id,
            },
            evidence_hashes=(sha256,),
            event_key_suffix=f"artifact-finalized:{artifact_id}",
        )
        return row

    def mark_ready(self, job_id: str, *, worker_id: str | None = None) -> ReportJobRecord:
        row = self.db.scalar(select(ReportJobRecord).where(ReportJobRecord.id == job_id).with_for_update())
        if row is None:
            raise KeyError(job_id)
        if worker_id is not None and row.lease_owner not in (None, worker_id):
            raise ReportSecurityError("report lease ownership mismatch")
        if not self._has_ready_output(job_id) and row.origin == "LOCAL":
            raise ReportSecurityError("local report cannot become READY without finalized OUTPUT artifact")
        previous = row.state
        row.state = ReportJobState.READY.value
        row.completed_at = _now()
        row.lease_owner = None
        row.lease_expires_at = None
        row.heartbeat_at = None
        self.event(job_id, "ready", from_state=previous, to_state=row.state)
        self._immutable(
            row,"REPORT_GENERATION_COMPLETED",actor_kind=ActorKind.WORKER,
            machine_principal=worker_id or "report-worker",outcome=AuditOutcome.SUCCESS,
            metadata={"report_job_id":row.id,"state":row.state,"attempt_count":row.attempt_count},
            event_key_suffix="generation-completed",
        )
        self.db.flush()
        return row

    def fail(self, job_id: str, *, code: str, message_redacted: str) -> ReportJobRecord:
        row = self.db.scalar(select(ReportJobRecord).where(ReportJobRecord.id == job_id).with_for_update())
        if row is None:
            raise KeyError(job_id)
        previous = row.state
        row.state = ReportJobState.FAILED.value
        row.error_code = code[:80]
        row.error_message_redacted = message_redacted[:1000]
        row.completed_at = _now()
        row.lease_owner = None
        row.lease_expires_at = None
        row.heartbeat_at = None
        self.event(job_id, "generation_failed", from_state=previous, to_state=row.state, details={"error_code": code})
        self._immutable(
            row,"REPORT_GENERATION_FAILED",actor_kind=ActorKind.WORKER,
            machine_principal="report-worker",outcome=AuditOutcome.FAILED,
            metadata={
                "report_job_id":row.id,"error_code":row.error_code,
                "redacted_message":row.error_message_redacted[:512] if row.error_message_redacted else None,
            },
            event_key_suffix=f"generation-failed:{row.attempt_count}:{row.error_code}",
        )
        self.db.flush()
        return row

    def set_remote_create_ambiguous(self, job_id: str) -> None:
        row = self.db.scalar(select(ReportJobRecord).where(ReportJobRecord.id == job_id).with_for_update())
        if row is None:
            raise KeyError(job_id)
        row.remote_create_ambiguous = True
        row.error_code = "REMOTE_CREATE_AMBIGUOUS"
        row.error_message_redacted = "remote create outcome is ambiguous; blind retry prohibited"
        self.event(job_id, "remote_create_ambiguous", details={"blind_retry": False})
        self.db.flush()

    def set_remote_task(self, job_id: str, *, task_id: str, raw_status: str | None, metadata: Mapping[str, Any]) -> None:
        row = self.db.scalar(select(ReportJobRecord).where(ReportJobRecord.id == job_id).with_for_update())
        if row is None:
            raise KeyError(job_id)
        if row.remote_task_id is not None and row.remote_task_id != task_id:
            raise ArtifactIntegrityConflict("remote task identity conflict")
        row.remote_task_id = task_id
        row.raw_remote_status = raw_status
        row.remote_metadata_sanitized = dict(sanitize_report_evidence(dict(metadata)))
        self.event(job_id, "remote_task_created", remote_task_id=task_id, details={"raw_status": raw_status})
        self.db.flush()


class SqlUploadBindingStore(UploadBindingStore):
    def __init__(self, db: Session) -> None:
        self.db = db

    @staticmethod
    def _binding(row: ReportArtifactUploadRecord) -> ReportArtifactUploadBinding:
        return ReportArtifactUploadBinding(
            row.artifact_upload_id,
            row.report_job_id,
            row.remote_result_id,
            row.remote_result_part_id,
            row.product_group_code,
            row.expected_archive_size,
            row.state,
            row.finalized_artifact_id,
            row.observed_byte_size,
            row.observed_sha256,
        )

    def get(self, upload_id: str) -> ReportArtifactUploadBinding | None:
        row = self.db.get(ReportArtifactUploadRecord, upload_id)
        return self._binding(row) if row else None

    def put(self, binding: ReportArtifactUploadBinding) -> None:
        if self.db.get(ReportArtifactUploadRecord, binding.artifact_upload_id) is not None:
            raise ArtifactIntegrityConflict("duplicate artifact upload id")
        self.db.add(
            ReportArtifactUploadRecord(
                artifact_upload_id=binding.artifact_upload_id,
                report_job_id=binding.report_job_id,
                remote_result_id=binding.remote_result_id,
                remote_result_part_id=binding.remote_result_part_id,
                product_group_code=binding.product_group_code,
                expected_archive_size=binding.expected_archive_size,
                state=binding.state,
                finalized_artifact_id=binding.finalized_artifact_id,
                observed_byte_size=binding.observed_byte_size,
                observed_sha256=binding.observed_sha256,
            )
        )
        self.db.flush()

    def update(self, binding: ReportArtifactUploadBinding) -> None:
        row = self.db.scalar(
            select(ReportArtifactUploadRecord)
            .where(ReportArtifactUploadRecord.artifact_upload_id == binding.artifact_upload_id)
            .with_for_update()
        )
        if row is None:
            raise KeyError(binding.artifact_upload_id)
        if row.report_job_id != binding.report_job_id or row.remote_result_id != binding.remote_result_id or row.remote_result_part_id != binding.remote_result_part_id:
            raise ReportSecurityError("artifact upload immutable binding mismatch")
        row.state = binding.state
        row.finalized_artifact_id = binding.finalized_artifact_id
        row.observed_byte_size = binding.observed_byte_size
        row.observed_sha256 = binding.observed_sha256
        self.db.flush()
