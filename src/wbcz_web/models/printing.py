from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger, CheckConstraint, DateTime, ForeignKey, ForeignKeyConstraint,
    Integer, JSON, Numeric, String, Text, UniqueConstraint, func,
)
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


class StoredFullKmItemRecord(Base):
    __tablename__ = "stored_full_km_items"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    organisation_id: Mapped[str] = mapped_column(ForeignKey("organisations.id", ondelete="RESTRICT"), nullable=False, index=True)
    participant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    suz_order_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("suz_orders.id", ondelete="RESTRICT"), nullable=False, index=True)
    suz_order_item_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("suz_order_items.id", ondelete="RESTRICT"), nullable=True)
    suz_code_block_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("suz_code_blocks.id", ondelete="RESTRICT"), nullable=False, index=True)
    vault_entry_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("suz_km_vault.id", ondelete="RESTRICT"), nullable=False, index=True)
    gtin: Mapped[str] = mapped_column(Text, nullable=False)
    cis_hmac: Mapped[str] = mapped_column(String(64), nullable=False)
    vault_item_ordinal: Mapped[int] = mapped_column(Integer, nullable=False)
    vault_item_offset: Mapped[int] = mapped_column(Integer, nullable=False)
    vault_item_length: Mapped[int] = mapped_column(Integer, nullable=False)
    full_km_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    provenance_state: Mapped[str] = mapped_column(String(16), nullable=False)
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        ForeignKeyConstraint(
            ["participant_id", "organisation_id"],
            ["participants.id", "participants.organisation_id"],
            name="fk_stored_full_km_participant_organisation",
            ondelete="RESTRICT",
        ),
        UniqueConstraint(
            "organisation_id", "participant_id", "cis_hmac",
            name="uq_stored_full_km_tenant_cis_hmac",
        ),
        UniqueConstraint(
            "vault_entry_id", "vault_item_ordinal",
            name="uq_stored_full_km_vault_ordinal",
        ),
        CheckConstraint("vault_item_ordinal >= 0", name="ck_stored_full_km_ordinal"),
        CheckConstraint("vault_item_offset >= 0", name="ck_stored_full_km_offset"),
        CheckConstraint("vault_item_length > 0", name="ck_stored_full_km_length"),
        CheckConstraint("provenance_state IN ('PROVEN','CONFLICT','UNKNOWN')", name="ck_stored_full_km_provenance"),
        CheckConstraint(
            "source IN ('INITIAL_SUZ_FETCH','REPEAT_SUZ_FETCH','MIGRATED_TRUSTED_SOURCE')",
            name="ck_stored_full_km_source",
        ),
    )


class PrintTemplateRecord(Base):
    __tablename__ = "print_templates"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    organisation_id: Mapped[str] = mapped_column(ForeignKey("organisations.id", ondelete="RESTRICT"), nullable=False, index=True)
    participant_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="ACTIVE")
    current_version_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("print_template_versions.id", ondelete="RESTRICT", use_alter=True, name="fk_print_template_current_version"),
        nullable=True,
    )
    created_by_user_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        ForeignKeyConstraint(
            ["participant_id", "organisation_id"],
            ["participants.id", "participants.organisation_id"],
            name="fk_print_template_participant_organisation",
            ondelete="RESTRICT",
        ),
        UniqueConstraint("organisation_id", "participant_id", "name", name="uq_print_template_tenant_name"),
        CheckConstraint("state IN ('ACTIVE','ARCHIVED')", name="ck_print_template_state"),
    )


class PrintTemplateVersionRecord(Base):
    __tablename__ = "print_template_versions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    template_id: Mapped[str] = mapped_column(ForeignKey("print_templates.id", ondelete="RESTRICT"), nullable=False, index=True)
    organisation_id: Mapped[str] = mapped_column(ForeignKey("organisations.id", ondelete="RESTRICT"), nullable=False, index=True)
    participant_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    version_number: Mapped[int] = mapped_column(Integer, nullable=False)
    schema_version: Mapped[str] = mapped_column(String(24), nullable=False)
    label_width_mm: Mapped[float] = mapped_column(Numeric(7, 3), nullable=False)
    label_height_mm: Mapped[float] = mapped_column(Numeric(7, 3), nullable=False)
    layout_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    layout_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    created_by_user_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        ForeignKeyConstraint(
            ["participant_id", "organisation_id"],
            ["participants.id", "participants.organisation_id"],
            name="fk_print_template_version_participant_organisation",
            ondelete="RESTRICT",
        ),
        UniqueConstraint("template_id", "version_number", name="uq_print_template_version_number"),
        UniqueConstraint("id", "organisation_id", "participant_id", name="uq_print_template_version_tenant"),
        CheckConstraint("version_number >= 1", name="ck_print_template_version_number"),
        CheckConstraint("label_width_mm >= 10 AND label_width_mm <= 300", name="ck_print_template_width"),
        CheckConstraint("label_height_mm >= 10 AND label_height_mm <= 300", name="ck_print_template_height"),
    )


class PrintJobRecord(Base):
    __tablename__ = "print_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    organisation_id: Mapped[str] = mapped_column(ForeignKey("organisations.id", ondelete="RESTRICT"), nullable=False, index=True)
    participant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    template_version_id: Mapped[str] = mapped_column(ForeignKey("print_template_versions.id", ondelete="RESTRICT"), nullable=False, index=True)
    mode: Mapped[str] = mapped_column(String(40), nullable=False)
    requested_by_user_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    state: Mapped[str] = mapped_column(String(24), nullable=False, default="PENDING")
    item_count: Mapped[int] = mapped_column(Integer, nullable=False)
    output_kind: Mapped[str] = mapped_column(String(24), nullable=False, default="WINDOWS_AGENT")
    printer_profile_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    printer_profile_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    metadata_sanitized_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    correlation_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    original_print_event_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("print_events.id", ondelete="RESTRICT", use_alter=True, name="fk_print_job_original_event"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        ForeignKeyConstraint(
            ["participant_id", "organisation_id"],
            ["participants.id", "participants.organisation_id"],
            name="fk_print_job_participant_organisation",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "mode IN ('INITIAL_PRINT','REPRINT_ORIGINAL_TEMPLATE','PRINT_USING_CURRENT_TEMPLATE')",
            name="ck_print_job_mode",
        ),
        CheckConstraint(
            "state IN ('PENDING','READY_FOR_AGENT','COMPLETED','FAILED','BLOCKED')",
            name="ck_print_job_state",
        ),
        CheckConstraint("item_count > 0 AND item_count <= 1000", name="ck_print_job_item_count"),
        CheckConstraint("output_kind IN ('WINDOWS_AGENT','SYNTHETIC_PREVIEW')", name="ck_print_job_output_kind"),
    )


class PrintJobItemRecord(Base):
    __tablename__ = "print_job_items"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    print_job_id: Mapped[str] = mapped_column(ForeignKey("print_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    organisation_id: Mapped[str] = mapped_column(ForeignKey("organisations.id", ondelete="RESTRICT"), nullable=False, index=True)
    participant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    stored_full_km_item_id: Mapped[str] = mapped_column(ForeignKey("stored_full_km_items.id", ondelete="RESTRICT"), nullable=False, index=True)
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False)
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[str] = mapped_column(String(24), nullable=False, default="PENDING")
    error_code: Mapped[str | None] = mapped_column(String(96), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        ForeignKeyConstraint(
            ["participant_id", "organisation_id"],
            ["participants.id", "participants.organisation_id"],
            name="fk_print_job_item_participant_organisation",
            ondelete="RESTRICT",
        ),
        UniqueConstraint("print_job_id", "ordinal", name="uq_print_job_item_ordinal"),
        UniqueConstraint("print_job_id", "stored_full_km_item_id", name="uq_print_job_stored_km"),
        CheckConstraint("ordinal >= 0", name="ck_print_job_item_ordinal"),
        CheckConstraint("state IN ('PENDING','RENDERED','COMPLETED','FAILED','BLOCKED')", name="ck_print_job_item_state"),
    )


class PrintEventRecord(Base):
    __tablename__ = "print_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    organisation_id: Mapped[str] = mapped_column(ForeignKey("organisations.id", ondelete="RESTRICT"), nullable=False, index=True)
    participant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    print_job_id: Mapped[str] = mapped_column(ForeignKey("print_jobs.id", ondelete="RESTRICT"), nullable=False, index=True)
    print_job_item_id: Mapped[str | None] = mapped_column(ForeignKey("print_job_items.id", ondelete="RESTRICT"), nullable=True)
    stored_full_km_item_id: Mapped[str | None] = mapped_column(ForeignKey("stored_full_km_items.id", ondelete="RESTRICT"), nullable=True)
    template_version_id: Mapped[str] = mapped_column(ForeignKey("print_template_versions.id", ondelete="RESTRICT"), nullable=False)
    payload_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    actor_kind: Mapped[str] = mapped_column(String(24), nullable=False)
    actor_user_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    printer_profile_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    event_type: Mapped[str] = mapped_column(String(40), nullable=False)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False)
    error_code: Mapped[str | None] = mapped_column(String(96), nullable=True)
    original_print_event_id: Mapped[str | None] = mapped_column(ForeignKey("print_events.id", ondelete="RESTRICT"), nullable=True)
    evidence_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    metadata_sanitized_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        ForeignKeyConstraint(
            ["participant_id", "organisation_id"],
            ["participants.id", "participants.organisation_id"],
            name="fk_print_event_participant_organisation",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "event_type IN ('PRINT_JOB_REQUESTED','PRINT_JOB_COMPLETED','PRINT_JOB_FAILED','REPRINT_REQUESTED','REPRINT_COMPLETED','REPRINT_FAILED')",
            name="ck_print_event_type",
        ),
        CheckConstraint("outcome IN ('PENDING','SUCCESS','FAILED','BLOCKED')", name="ck_print_event_outcome"),
    )
