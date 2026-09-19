from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, Boolean, CheckConstraint, DateTime, ForeignKey, Integer, JSON, LargeBinary, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


_REPORT_STATES = ("REQUESTED", "QUEUED", "GENERATING", "READY", "FAILED", "EXPIRED", "CANCELLED")
_ARTIFACT_STATES = ("PENDING", "READY", "FAILED", "INTEGRITY_CONFLICT", "DELETED")
_UPLOAD_STATES = ("PREPARED", "RECEIVING", "COMPLETED", "CONFLICT", "FAILED")


class ReportJobRecord(Base):
    __tablename__ = "report_jobs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    organisation_id: Mapped[str | None] = mapped_column(ForeignKey("organisations.id", ondelete="RESTRICT"), nullable=True, index=True)
    participant_id: Mapped[str | None] = mapped_column(ForeignKey("participants.id", ondelete="RESTRICT"), nullable=True, index=True)\n    correlation_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)\n    causation_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    origin: Mapped[str] = mapped_column(String(24), nullable=False, index=True)
    participant_inn: Mapped[str] = mapped_column(String(12), nullable=False, index=True)
    report_type: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    report_schema_version: Mapped[str] = mapped_column(String(32), nullable=False)
    output_format: Mapped[str] = mapped_column(String(16), nullable=False)
    sensitivity_class: Mapped[str] = mapped_column(String(32), nullable=False)
    filters_sanitized_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    sensitive_filter_ref: Mapped[str | None] = mapped_column(Text, nullable=True)
    request_fingerprint_sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    state: Mapped[str] = mapped_column(String(24), nullable=False, index=True)
    snapshot_id: Mapped[str | None] = mapped_column(String(64), ForeignKey("report_snapshots.id", ondelete="SET NULL"), nullable=True, index=True)
    remote_task_id: Mapped[str | None] = mapped_column(String(256), nullable=True, index=True)
    raw_remote_status: Mapped[str | None] = mapped_column(Text, nullable=True)
    remote_metadata_sanitized: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    remote_create_ambiguous: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    requested_by_user_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    lease_owner: Mapped[str | None] = mapped_column(String(128), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_code: Mapped[str | None] = mapped_column(String(80), nullable=True)
    error_message_redacted: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        CheckConstraint("origin IN ('LOCAL','TRUE_API_REMOTE')", name="ck_report_jobs_origin"),
        CheckConstraint(
            "state IN (" + ",".join(f"'{value}'" for value in _REPORT_STATES) + ")",
            name="ck_report_jobs_state",
        ),
    )


class ReportSnapshotRecord(Base):
    __tablename__ = "report_snapshots"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    report_job_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    strategy: Mapped[str] = mapped_column(String(48), nullable=False)
    snapshot_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source_domains: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    source_tables: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    high_water_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    source_filter_sanitized: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    descriptor_sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    schema_version: Mapped[str] = mapped_column(String(32), nullable=False)
    internal_snapshot_artifact_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    row_count: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class ReportArtifactRecord(Base):
    __tablename__ = "report_artifacts"

    artifact_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    report_job_id: Mapped[str] = mapped_column(String(64), ForeignKey("report_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    artifact_role: Mapped[str] = mapped_column(String(40), nullable=False)
    publication_key: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    state: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    storage_backend: Mapped[str] = mapped_column(String(40), nullable=False)
    storage_key: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    format: Mapped[str] = mapped_column(String(16), nullable=False)
    mime: Mapped[str | None] = mapped_column(String(160), nullable=True)
    safe_filename: Mapped[str] = mapped_column(Text, nullable=False)
    byte_size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    sensitivity_class: Mapped[str] = mapped_column(String(32), nullable=False)
    encryption_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    encryption_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    remote_result_id: Mapped[str | None] = mapped_column(String(256), nullable=True, index=True)
    remote_result_part_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    remote_file_delete_date_raw: Mapped[str | None] = mapped_column(Text, nullable=True)
    remote_file_delete_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        CheckConstraint("artifact_role IN ('OUTPUT','REMOTE_TRUE_API_ARCHIVE','SNAPSHOT_INTERNAL','MANIFEST')", name="ck_report_artifacts_role"),
        CheckConstraint(
            "state IN (" + ",".join(f"'{value}'" for value in _ARTIFACT_STATES) + ")",
            name="ck_report_artifacts_state",
        ),
    )


class ReportJobEventRecord(Base):
    __tablename__ = "report_job_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    report_job_id: Mapped[str] = mapped_column(String(64), ForeignKey("report_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    from_state: Mapped[str | None] = mapped_column(String(24), nullable=True)
    to_state: Mapped[str | None] = mapped_column(String(24), nullable=True)
    details_redacted: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    artifact_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    remote_task_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    remote_result_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    evidence_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    actor_user_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class ReportArtifactUploadRecord(Base):
    __tablename__ = "report_artifact_uploads"

    artifact_upload_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    report_job_id: Mapped[str] = mapped_column(String(64), ForeignKey("report_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    remote_result_id: Mapped[str] = mapped_column(String(256), nullable=False)
    remote_result_part_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    product_group_code: Mapped[str | None] = mapped_column(String(32), nullable=True)
    expected_archive_size: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    state: Mapped[str] = mapped_column(String(24), nullable=False, index=True)
    finalized_artifact_id: Mapped[str | None] = mapped_column(String(64), ForeignKey("report_artifacts.artifact_id", ondelete="SET NULL"), nullable=True)
    observed_byte_size: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    observed_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    observed_mime: Mapped[str | None] = mapped_column(String(160), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        CheckConstraint(
            "state IN (" + ",".join(f"'{value}'" for value in _UPLOAD_STATES) + ")",
            name="ck_report_artifact_uploads_state",
        ),
    )
