from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger, CheckConstraint, DateTime, ForeignKey, ForeignKeyConstraint, Index, JSON, String,
    UniqueConstraint, func, text,
)
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base, uuid_text


AUDIT_FORMAT_VERSION = "SELLARI_AUDIT_V1"
CHECKPOINT_FORMAT_VERSION = "SELLARI_AUDIT_CHECKPOINT_V1"
ZERO_HASH = "0" * 64

AUDIT_CATEGORIES = (
    "SECURITY", "AUTHORIZATION", "TENANT_ADMIN", "INTEGRATION", "IMPORT",
    "CONTROL", "CIS_READ", "REFERENCE_READ", "DOCUMENT", "TURNOVER",
    "AGGREGATION", "EDO", "SUZ", "WB", "OZON", "REPORT", "AGENT", "PRINTING", "SYSTEM",
)
ACTOR_KINDS = ("USER", "SYSTEM", "WORKER", "WINDOWS_AGENT", "CLI_ADMIN", "BOOTSTRAP", "REMOTE_SYSTEM")
AUDIT_OUTCOMES = ("SUCCESS", "DENIED", "FAILED", "PENDING", "CONFLICT", "CANCELLED", "AMBIGUOUS")
AUTHORIZATION_DECISIONS = ("ALLOW", "DENY", "NOT_APPLICABLE")
SUBJECT_TYPES = (
    "USER", "SESSION", "MEMBERSHIP", "INVITATION", "ORGANISATION", "PARTICIPANT",
    "IMPORT", "EVENT", "CONTROL_RUN", "AGENT_JOB", "WRITE_OPERATION",
    "DOCUMENT_OPERATION", "TURNOVER_OPERATION", "AGGREGATION_OPERATION", "EDO_OBJECT",
    "SUZ_CONNECTION", "SUZ_ORDER", "WB_CONNECTION", "WB_OBJECT", "OZON_CONNECTION",
    "OZON_OBJECT", "REPORT_JOB", "REPORT_ARTIFACT", "INTEGRATION_CONNECTION",
    "MARKING_IDENTIFIER", "PRINT_TEMPLATE", "PRINT_JOB", "PRINT_EVENT", "AUDIT_CHAIN", "AUDIT_CHECKPOINT",
)


def _quoted(values: tuple[str, ...]) -> str:
    return ",".join("'" + value + "'" for value in values)


class AuditChainHeadRecord(Base):
    __tablename__ = "audit_chain_heads"

    chain_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_text)
    scope_kind: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    organisation_id: Mapped[str | None] = mapped_column(
        ForeignKey("organisations.id", ondelete="RESTRICT"), nullable=True, index=True
    )
    head_sequence: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    head_hash: Mapped[str] = mapped_column(String(64), nullable=False, default=ZERO_HASH)
    audit_format_version: Mapped[str] = mapped_column(String(32), nullable=False, default=AUDIT_FORMAT_VERSION)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        CheckConstraint("scope_kind IN ('SYSTEM','ORGANISATION')", name="ck_audit_chain_scope_kind"),
        CheckConstraint(
            "(scope_kind='SYSTEM' AND organisation_id IS NULL) OR "
            "(scope_kind='ORGANISATION' AND organisation_id IS NOT NULL)",
            name="ck_audit_chain_scope_binding",
        ),
        CheckConstraint("head_sequence >= 0", name="ck_audit_chain_head_sequence"),
        CheckConstraint("length(head_hash) = 64", name="ck_audit_chain_head_hash"),
        Index(
            "uq_audit_chain_system",
            "scope_kind",
            unique=True,
            postgresql_where=text("scope_kind = 'SYSTEM'"),
        ),
        Index(
            "uq_audit_chain_organisation",
            "organisation_id",
            unique=True,
            postgresql_where=text("scope_kind = 'ORGANISATION'"),
        ),
    )


class AuditEventRecord(Base):
    __tablename__ = "audit_events"

    event_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_text)
    chain_id: Mapped[str] = mapped_column(
        ForeignKey("audit_chain_heads.chain_id", ondelete="RESTRICT"), nullable=False, index=True
    )
    sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    organisation_id: Mapped[str | None] = mapped_column(
        ForeignKey("organisations.id", ondelete="RESTRICT"), nullable=True, index=True
    )
    participant_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)

    category: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(96), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(96), nullable=False, index=True)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    authorization_decision: Mapped[str] = mapped_column(String(24), nullable=False)

    actor_kind: Mapped[str] = mapped_column(String(24), nullable=False, index=True)
    actor_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), nullable=True, index=True
    )
    actor_membership_id: Mapped[str | None] = mapped_column(
        ForeignKey("organisation_memberships.id", ondelete="RESTRICT"), nullable=True
    )
    actor_role_snapshot: Mapped[str | None] = mapped_column(String(16), nullable=True)
    permission_snapshot_json: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)

    subject_type: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    subject_id: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    secondary_subject_type: Mapped[str | None] = mapped_column(String(40), nullable=True)
    secondary_subject_id: Mapped[str | None] = mapped_column(String(256), nullable=True)

    request_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    correlation_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    causation_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    operation_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    agent_job_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    event_key: Mapped[str | None] = mapped_column(String(256), nullable=True)

    before_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    after_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    evidence_hashes_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    metadata_sanitized_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    previous_event_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    audit_format_version: Mapped[str] = mapped_column(String(32), nullable=False, default=AUDIT_FORMAT_VERSION)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        UniqueConstraint("chain_id", "sequence", name="uq_audit_events_chain_sequence"),
        UniqueConstraint("chain_id", "event_key", name="uq_audit_events_chain_event_key"),
        ForeignKeyConstraint(
            ["participant_id", "organisation_id"],
            ["participants.id", "participants.organisation_id"],
            name="fk_audit_events_participant_organisation",
            ondelete="RESTRICT",
        ),
        CheckConstraint(f"category IN ({_quoted(AUDIT_CATEGORIES)})", name="ck_audit_event_category"),
        CheckConstraint(f"actor_kind IN ({_quoted(ACTOR_KINDS)})", name="ck_audit_event_actor_kind"),
        CheckConstraint(f"outcome IN ({_quoted(AUDIT_OUTCOMES)})", name="ck_audit_event_outcome"),
        CheckConstraint(
            f"authorization_decision IN ({_quoted(AUTHORIZATION_DECISIONS)})",
            name="ck_audit_event_authorization_decision",
        ),
        CheckConstraint(f"subject_type IN ({_quoted(SUBJECT_TYPES)})", name="ck_audit_event_subject_type"),
        CheckConstraint(
            "secondary_subject_type IS NULL OR secondary_subject_type IN (" + _quoted(SUBJECT_TYPES) + ")",
            name="ck_audit_event_secondary_subject_type",
        ),
        CheckConstraint("sequence >= 1", name="ck_audit_event_sequence"),
        CheckConstraint("length(previous_event_hash) = 64", name="ck_audit_event_previous_hash"),
        CheckConstraint("length(event_hash) = 64", name="ck_audit_event_hash"),
        CheckConstraint(
            "(participant_id IS NULL) OR (organisation_id IS NOT NULL)",
            name="ck_audit_event_participant_requires_org",
        ),
        Index("ix_audit_events_chain_sequence_desc", "chain_id", text("sequence DESC")),
        Index("ix_audit_events_org_occurred", "organisation_id", "occurred_at"),
        Index("ix_audit_events_org_category", "organisation_id", "category"),
        Index("ix_audit_events_org_actor", "organisation_id", "actor_user_id"),
        Index("ix_audit_events_org_subject", "organisation_id", "subject_type", "subject_id"),
        Index("ix_audit_events_org_participant", "organisation_id", "participant_id"),
        Index("ix_audit_events_org_correlation", "organisation_id", "correlation_id"),
    )


class AuditCheckpointRecord(Base):
    __tablename__ = "audit_checkpoints"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_text)
    chain_id: Mapped[str] = mapped_column(
        ForeignKey("audit_chain_heads.chain_id", ondelete="RESTRICT"), nullable=False, index=True
    )
    through_sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    head_event_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    previous_checkpoint_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    checkpoint_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    checkpoint_format_version: Mapped[str] = mapped_column(
        String(40), nullable=False, default=CHECKPOINT_FORMAT_VERSION
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        UniqueConstraint("chain_id", "through_sequence", name="uq_audit_checkpoint_chain_sequence"),
        CheckConstraint("through_sequence >= 1", name="ck_audit_checkpoint_sequence"),
        CheckConstraint("length(head_event_hash) = 64", name="ck_audit_checkpoint_head_hash"),
        CheckConstraint("length(previous_checkpoint_hash) = 64", name="ck_audit_checkpoint_previous_hash"),
        CheckConstraint("length(checkpoint_hash) = 64", name="ck_audit_checkpoint_hash"),
    )
