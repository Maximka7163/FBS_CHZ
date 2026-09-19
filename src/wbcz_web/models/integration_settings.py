from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger, Boolean, CheckConstraint, DateTime, ForeignKey, ForeignKeyConstraint,
    Index, Integer, JSON, String, Text, UniqueConstraint, func, text,
)
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base, uuid_text


class AgentBindingRecord(Base):
    __tablename__ = "agent_bindings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_text)
    organisation_id: Mapped[str] = mapped_column(
        ForeignKey("organisations.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    participant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    installation_id: Mapped[str] = mapped_column(String(36), nullable=False)
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)
    protocol_version: Mapped[str] = mapped_column(String(32), nullable=False, default="m14-v1")
    agent_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    credential_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    credential_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="PENDING", index=True)
    is_primary: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_poll_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_true_api_auth_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    capabilities_sanitized: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    last_error_code: Mapped[str | None] = mapped_column(String(80), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        ForeignKeyConstraint(
            ["participant_id", "organisation_id"],
            ["participants.id", "participants.organisation_id"],
            name="fk_agent_bindings_participant_organisation",
            ondelete="RESTRICT",
        ),
        CheckConstraint("state IN ('PENDING','ACTIVE','DISABLED','ARCHIVED')", name="ck_agent_bindings_state"),
        CheckConstraint("credential_version >= 1", name="ck_agent_bindings_credential_version"),
        UniqueConstraint("organisation_id", "participant_id", "installation_id", name="uq_agent_bindings_participant_installation"),
        UniqueConstraint("id", "organisation_id", "participant_id", name="uq_agent_bindings_id_tenant"),
        Index(
            "uq_agent_bindings_active_primary",
            "organisation_id", "participant_id",
            unique=True,
            postgresql_where=text("state='ACTIVE' AND is_primary"),
        ),
    )


class AgentCertificateObservationRecord(Base):
    __tablename__ = "agent_certificate_observations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_text)
    agent_binding_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    organisation_id: Mapped[str] = mapped_column(
        ForeignKey("organisations.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    participant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    thumbprint: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    subject: Mapped[str | None] = mapped_column(Text, nullable=True)
    issuer: Mapped[str | None] = mapped_column(Text, nullable=True)
    certificate_inn: Mapped[str | None] = mapped_column(String(12), nullable=True)
    valid_from: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    valid_to: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    algorithm: Mapped[str | None] = mapped_column(String(128), nullable=True)
    has_private_key: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    crypto_provider: Mapped[str | None] = mapped_column(String(160), nullable=True)
    compatibility: Mapped[str] = mapped_column(String(32), nullable=False, default="UNKNOWN")
    key_usage_summary: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    serial: Mapped[str | None] = mapped_column(String(160), nullable=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    readiness_state: Mapped[str] = mapped_column(String(32), nullable=False)
    match_state: Mapped[str] = mapped_column(String(32), nullable=False)
    expiry_state: Mapped[str] = mapped_column(String(32), nullable=False)
    reason_code: Mapped[str | None] = mapped_column(String(80), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        ForeignKeyConstraint(
            ["participant_id", "organisation_id"],
            ["participants.id", "participants.organisation_id"],
            name="fk_agent_cert_obs_participant_organisation",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["agent_binding_id", "organisation_id", "participant_id"],
            ["agent_bindings.id", "agent_bindings.organisation_id", "agent_bindings.participant_id"],
            name="fk_agent_cert_obs_binding_tenant",
            ondelete="RESTRICT",
        ),
        UniqueConstraint("id", "organisation_id", "participant_id", name="uq_agent_cert_obs_id_tenant"),
        CheckConstraint(
            "readiness_state IN ('READY','NOT_READY','UNKNOWN')",
            name="ck_agent_cert_obs_readiness",
        ),
        CheckConstraint(
            "match_state IN ('MATCH','MISMATCH','UNKNOWN')",
            name="ck_agent_cert_obs_match",
        ),
        CheckConstraint(
            "expiry_state IN ('EXPIRED','EXPIRING_CRITICAL','EXPIRING_SOON','VALID','UNKNOWN')",
            name="ck_agent_cert_obs_expiry",
        ),
    )


class TrueApiConnectionRecord(Base):
    __tablename__ = "true_api_connections"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_text)
    organisation_id: Mapped[str] = mapped_column(
        ForeignKey("organisations.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    participant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    environment: Mapped[str] = mapped_column(String(24), nullable=False, default="PRODUCTION")
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="ENABLED", index=True)
    primary_agent_binding_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    desired_capabilities_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    observed_capabilities_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    desired_certificate_ref: Mapped[str | None] = mapped_column(String(160), nullable=True)
    certificate_selection_state: Mapped[str] = mapped_column(String(32), nullable=False, default="NONE")
    observed_certificate_observation_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    last_auth_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_check_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error_code: Mapped[str | None] = mapped_column(String(80), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        ForeignKeyConstraint(
            ["participant_id", "organisation_id"],
            ["participants.id", "participants.organisation_id"],
            name="fk_true_api_connections_participant_organisation",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["primary_agent_binding_id", "organisation_id", "participant_id"],
            ["agent_bindings.id", "agent_bindings.organisation_id", "agent_bindings.participant_id"],
            name="fk_true_api_primary_binding_tenant",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["observed_certificate_observation_id", "organisation_id", "participant_id"],
            ["agent_certificate_observations.id", "agent_certificate_observations.organisation_id", "agent_certificate_observations.participant_id"],
            name="fk_true_api_observed_cert_tenant",
            ondelete="RESTRICT",
        ),
        CheckConstraint("state IN ('ENABLED','DISABLED','ARCHIVED')", name="ck_true_api_connections_state"),
        CheckConstraint(
            "certificate_selection_state IN ('NONE','PENDING_LOCAL_APPLY','READY','MISMATCH')",
            name="ck_true_api_certificate_selection_state",
        ),
        Index(
            "uq_true_api_connection_participant_live",
            "organisation_id", "participant_id",
            unique=True,
            postgresql_where=text("state <> 'ARCHIVED'"),
        ),
    )


class IntegrationHealthCheckRecord(Base):
    __tablename__ = "integration_health_checks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_text)
    organisation_id: Mapped[str] = mapped_column(
        ForeignKey("organisations.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    participant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    integration_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    connection_type: Mapped[str] = mapped_column(String(32), nullable=False)
    connection_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    agent_binding_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    check_kind: Mapped[str] = mapped_column(String(48), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    overall_status: Mapped[str] = mapped_column(String(32), nullable=False)
    component_statuses_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    capabilities_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    remote_identity_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    certificate_snapshot_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    error_code: Mapped[str | None] = mapped_column(String(80), nullable=True)
    redacted_message: Mapped[str | None] = mapped_column(String(500), nullable=True)
    evidence_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    requested_by_user_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    correlation_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    reused_from_check_id: Mapped[str | None] = mapped_column(
        ForeignKey("integration_health_checks.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        ForeignKeyConstraint(
            ["participant_id", "organisation_id"],
            ["participants.id", "participants.organisation_id"],
            name="fk_integration_health_participant_organisation",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["agent_binding_id", "organisation_id", "participant_id"],
            ["agent_bindings.id", "agent_bindings.organisation_id", "agent_bindings.participant_id"],
            name="fk_integration_health_binding_tenant",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "overall_status IN ('CHECKING','READY','DEGRADED','ERROR','BLOCKED','NOT_TESTED')",
            name="ck_integration_health_overall_status",
        ),
        CheckConstraint("latency_ms IS NULL OR latency_ms >= 0", name="ck_integration_health_latency"),
    )
