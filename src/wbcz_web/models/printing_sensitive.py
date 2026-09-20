from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    BigInteger, CheckConstraint, DateTime, ForeignKey, ForeignKeyConstraint,
    Index, Integer, LargeBinary, String, UniqueConstraint, func, text,
)
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base, uuid_text


class AgentBindingEncryptionKeyRecord(Base):
    __tablename__ = "agent_binding_encryption_keys"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_text)
    organisation_id: Mapped[str] = mapped_column(ForeignKey("organisations.id", ondelete="RESTRICT"), nullable=False, index=True)
    participant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    agent_binding_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    algorithm: Mapped[str] = mapped_column(String(64), nullable=False)
    public_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    public_key_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    key_version: Mapped[int] = mapped_column(Integer, nullable=False)
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="ACTIVE", index=True)
    registered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    retiring_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        ForeignKeyConstraint(
            ["participant_id", "organisation_id"],
            ["participants.id", "participants.organisation_id"],
            name="fk_print_agent_key_participant_organisation",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["agent_binding_id", "organisation_id", "participant_id"],
            ["agent_bindings.id", "agent_bindings.organisation_id", "agent_bindings.participant_id"],
            name="fk_print_agent_key_binding_tenant",
            ondelete="RESTRICT",
        ),
        UniqueConstraint("agent_binding_id", "key_version", name="uq_print_agent_key_binding_version"),
        UniqueConstraint("id", "organisation_id", "participant_id", name="uq_print_agent_key_id_tenant"),
        CheckConstraint("algorithm = 'HPKE_DHKEM_X25519_HKDF_SHA256_AES128GCM'", name="ck_print_agent_key_algorithm"),
        CheckConstraint("octet_length(public_key) = 32", name="ck_print_agent_key_public_length"),
        CheckConstraint("key_version >= 1", name="ck_print_agent_key_version_positive"),
        CheckConstraint("state IN ('ACTIVE','RETIRING','REVOKED')", name="ck_print_agent_key_state"),
        Index(
            "uq_print_agent_key_active_binding",
            "agent_binding_id",
            unique=True,
            postgresql_where=text("state='ACTIVE'"),
        ),
    )


class PrintEncryptionKeyIntentRecord(Base):
    __tablename__ = "print_encryption_key_intents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_text)
    organisation_id: Mapped[str] = mapped_column(ForeignKey("organisations.id", ondelete="RESTRICT"), nullable=False, index=True)
    participant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    agent_binding_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    purpose: Mapped[str] = mapped_column(String(24), nullable=False)
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="PENDING", index=True)
    expected_active_key_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by_user_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    correlation_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        ForeignKeyConstraint(
            ["participant_id", "organisation_id"],
            ["participants.id", "participants.organisation_id"],
            name="fk_print_key_intent_participant_organisation",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["agent_binding_id", "organisation_id", "participant_id"],
            ["agent_bindings.id", "agent_bindings.organisation_id", "agent_bindings.participant_id"],
            name="fk_print_key_intent_binding_tenant",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["expected_active_key_id", "organisation_id", "participant_id"],
            ["agent_binding_encryption_keys.id", "agent_binding_encryption_keys.organisation_id", "agent_binding_encryption_keys.participant_id"],
            name="fk_print_key_intent_expected_key_tenant",
            ondelete="RESTRICT",
        ),
        CheckConstraint("purpose IN ('FIRST_REGISTRATION','ROTATE','REPLACE_LOST')", name="ck_print_key_intent_purpose"),
        CheckConstraint("state IN ('PENDING','USED','EXPIRED','REVOKED')", name="ck_print_key_intent_state"),
    )


class PrintExecutionRecord(Base):
    __tablename__ = "print_executions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_text)
    organisation_id: Mapped[str] = mapped_column(ForeignKey("organisations.id", ondelete="RESTRICT"), nullable=False, index=True)
    participant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    print_job_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    print_job_item_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    stored_full_km_item_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    template_version_id: Mapped[str] = mapped_column(ForeignKey("print_template_versions.id", ondelete="RESTRICT"), nullable=False, index=True)
    agent_binding_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    attempt_number: Mapped[int] = mapped_column(Integer, nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="REQUESTED", index=True)
    payload_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    layout_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    agent_version: Mapped[str] = mapped_column(String(64), nullable=False)
    print_protocol_version: Mapped[str] = mapped_column(String(32), nullable=False)
    renderer_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    authorized_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    payload_delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    terminal_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    safe_error_code: Mapped[str | None] = mapped_column(String(96), nullable=True)
    correlation_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        ForeignKeyConstraint(
            ["participant_id", "organisation_id"],
            ["participants.id", "participants.organisation_id"],
            name="fk_print_execution_participant_organisation",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["print_job_id", "organisation_id", "participant_id"],
            ["print_jobs.id", "print_jobs.organisation_id", "print_jobs.participant_id"],
            name="fk_print_execution_job_tenant",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["print_job_item_id", "organisation_id", "participant_id"],
            ["print_job_items.id", "print_job_items.organisation_id", "print_job_items.participant_id"],
            name="fk_print_execution_item_tenant",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["stored_full_km_item_id", "organisation_id", "participant_id"],
            ["stored_full_km_items.id", "stored_full_km_items.organisation_id", "stored_full_km_items.participant_id"],
            name="fk_print_execution_stored_tenant",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["agent_binding_id", "organisation_id", "participant_id"],
            ["agent_bindings.id", "agent_bindings.organisation_id", "agent_bindings.participant_id"],
            name="fk_print_execution_binding_tenant",
            ondelete="RESTRICT",
        ),
        UniqueConstraint("print_job_item_id", "attempt_number", name="uq_print_execution_item_attempt"),
        UniqueConstraint("id", "organisation_id", "participant_id", name="uq_print_execution_id_tenant"),
        CheckConstraint("attempt_number >= 1", name="ck_print_execution_attempt_positive"),
        CheckConstraint(
            "state IN ('REQUESTED','AUTHORIZED','PAYLOAD_AVAILABLE','PAYLOAD_ISSUED','PAYLOAD_DELIVERED','FAILED_PRE_SPOOL','BLOCKED','CANCELLED_PRE_SPOOL')",
            name="ck_print_execution_state",
        ),
        Index(
            "uq_print_execution_item_nonterminal",
            "print_job_item_id",
            unique=True,
            postgresql_where=text("state IN ('REQUESTED','AUTHORIZED','PAYLOAD_AVAILABLE','PAYLOAD_ISSUED','PAYLOAD_DELIVERED')"),
        ),
    )


class PrintPayloadDeliveryReservationRecord(Base):
    __tablename__ = "print_payload_delivery_reservations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_text)
    organisation_id: Mapped[str] = mapped_column(ForeignKey("organisations.id", ondelete="RESTRICT"), nullable=False, index=True)
    participant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    print_execution_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    print_job_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    print_job_item_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    stored_full_km_item_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    agent_binding_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    agent_encryption_key_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    payload_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="AVAILABLE", index=True)
    issue_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_issue_count: Mapped[int] = mapped_column(Integer, nullable=False)
    authorized_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    first_issued_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_issued_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_context_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    safe_error_code: Mapped[str | None] = mapped_column(String(96), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        ForeignKeyConstraint(
            ["participant_id", "organisation_id"],
            ["participants.id", "participants.organisation_id"],
            name="fk_print_reservation_participant_organisation",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["print_execution_id", "organisation_id", "participant_id"],
            ["print_executions.id", "print_executions.organisation_id", "print_executions.participant_id"],
            name="fk_print_reservation_execution_tenant",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["print_job_id", "organisation_id", "participant_id"],
            ["print_jobs.id", "print_jobs.organisation_id", "print_jobs.participant_id"],
            name="fk_print_reservation_job_tenant",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["print_job_item_id", "organisation_id", "participant_id"],
            ["print_job_items.id", "print_job_items.organisation_id", "print_job_items.participant_id"],
            name="fk_print_reservation_item_tenant",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["stored_full_km_item_id", "organisation_id", "participant_id"],
            ["stored_full_km_items.id", "stored_full_km_items.organisation_id", "stored_full_km_items.participant_id"],
            name="fk_print_reservation_stored_tenant",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["agent_binding_id", "organisation_id", "participant_id"],
            ["agent_bindings.id", "agent_bindings.organisation_id", "agent_bindings.participant_id"],
            name="fk_print_reservation_binding_tenant",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["agent_encryption_key_id", "organisation_id", "participant_id"],
            ["agent_binding_encryption_keys.id", "agent_binding_encryption_keys.organisation_id", "agent_binding_encryption_keys.participant_id"],
            name="fk_print_reservation_key_tenant",
            ondelete="RESTRICT",
        ),
        CheckConstraint("state IN ('AVAILABLE','ISSUED','ACKNOWLEDGED','EXPIRED','REVOKED','BLOCKED')", name="ck_print_reservation_state"),
        CheckConstraint("issue_count >= 0 AND issue_count <= max_issue_count", name="ck_print_reservation_issue_count"),
        CheckConstraint("max_issue_count >= 1 AND max_issue_count <= 10", name="ck_print_reservation_max_issue_count"),
        CheckConstraint("expires_at > authorized_at", name="ck_print_reservation_expiry"),
        Index(
            "uq_print_reservation_execution_active",
            "print_execution_id",
            unique=True,
            postgresql_where=text("state IN ('AVAILABLE','ISSUED')"),
        ),
    )
