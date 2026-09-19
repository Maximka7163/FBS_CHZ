from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger, CheckConstraint, DateTime, Float, ForeignKey, ForeignKeyConstraint,
    Index, Integer, JSON, String, Text, UniqueConstraint, func, text,
)
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base, uuid_text


class ManualReviewCaseRecord(Base):
    __tablename__ = "manual_review_cases"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_text)
    organisation_id: Mapped[str] = mapped_column(ForeignKey("organisations.id", ondelete="RESTRICT"), nullable=False, index=True)
    participant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    active_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    domain: Mapped[str] = mapped_column(String(48), nullable=False, index=True)
    reason_code: Mapped[str] = mapped_column(String(96), nullable=False, index=True)
    subject_type: Mapped[str] = mapped_column(String(48), nullable=False)
    subject_id: Mapped[str] = mapped_column(String(160), nullable=False)
    operation_id: Mapped[str | None] = mapped_column(String(160), nullable=True, index=True)
    source_job_id: Mapped[str | None] = mapped_column(String(160), nullable=True, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="WARNING", index=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="OPEN", index=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    occurrence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    evidence_hashes_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    metadata_sanitized_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    assigned_to_user_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    resolved_by_user_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolution_code: Mapped[str | None] = mapped_column(String(80), nullable=True)
    resolution_note: Mapped[str | None] = mapped_column(String(500), nullable=True)
    correlation_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        ForeignKeyConstraint(
            ["participant_id", "organisation_id"],
            ["participants.id", "participants.organisation_id"],
            name="fk_manual_review_participant_organisation",
            ondelete="RESTRICT",
        ),
        CheckConstraint("severity IN ('INFO','WARNING','HIGH','CRITICAL')", name="ck_manual_review_severity"),
        CheckConstraint("status IN ('OPEN','ACKNOWLEDGED','RESOLVED')", name="ck_manual_review_status"),
        CheckConstraint("occurrence_count >= 1", name="ck_manual_review_occurrence_count"),
        CheckConstraint("attempt_count >= 0", name="ck_manual_review_attempt_count"),
        Index(
            "uq_manual_review_active_fingerprint",
            "organisation_id", "participant_id", "active_fingerprint",
            unique=True,
            postgresql_where=text("status IN ('OPEN','ACKNOWLEDGED')"),
        ),
    )


class WorkerHeartbeatRecord(Base):
    __tablename__ = "worker_heartbeats"

    worker_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    role: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    instance_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="RUNNING", index=True)
    build_sha: Mapped[str] = mapped_column(String(64), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    heartbeat_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    scheduler_heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        CheckConstraint("state IN ('RUNNING','DRAINING','STOPPED')", name="ck_worker_heartbeat_state"),
    )


class RemoteRateLimitStateRecord(Base):
    __tablename__ = "remote_rate_limit_state"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    provider: Mapped[str] = mapped_column(String(24), nullable=False)
    connection_id: Mapped[str] = mapped_column(String(160), nullable=False)
    credential_version: Mapped[str] = mapped_column(String(128), nullable=False)
    environment: Mapped[str] = mapped_column(String(24), nullable=False)
    rate_family: Mapped[str] = mapped_column(String(64), nullable=False)
    token_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    tokens: Mapped[float] = mapped_column(Float, nullable=False)
    capacity: Mapped[float] = mapped_column(Float, nullable=False)
    refill_per_second: Mapped[float] = mapped_column(Float, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "provider", "connection_id", "credential_version", "environment", "rate_family",
            name="uq_remote_rate_scope",
        ),
        CheckConstraint("capacity > 0", name="ck_remote_rate_capacity"),
        CheckConstraint("refill_per_second > 0", name="ck_remote_rate_refill"),
    )


class AgentEnrollmentTokenRecord(Base):
    __tablename__ = "agent_enrollment_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_text)
    organisation_id: Mapped[str] = mapped_column(ForeignKey("organisations.id", ondelete="RESTRICT"), nullable=False, index=True)
    participant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)
    requested_protocol_version: Mapped[str] = mapped_column(String(32), nullable=False)
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="PENDING", index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    binding_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    created_by_user_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    correlation_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        ForeignKeyConstraint(
            ["participant_id", "organisation_id"],
            ["participants.id", "participants.organisation_id"],
            name="fk_agent_enrollment_participant_organisation",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["binding_id", "organisation_id", "participant_id"],
            ["agent_bindings.id", "agent_bindings.organisation_id", "agent_bindings.participant_id"],
            name="fk_agent_enrollment_binding_tenant",
            ondelete="RESTRICT",
        ),
        CheckConstraint("state IN ('PENDING','USED','EXPIRED','REVOKED')", name="ck_agent_enrollment_state"),
    )
