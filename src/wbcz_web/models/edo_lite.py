from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, CheckConstraint, DateTime, Integer, JSON, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


class EdoLiteLedgerRecord(Base):
    __tablename__ = "edo_lite_ledger"

    operation_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    direction: Mapped[str] = mapped_column(String(16), nullable=False)
    edo_document_id: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    edo_group_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    edo_event_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    parent_document_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    annulment_event_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    official_type_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    document_family: Mapped[str | None] = mapped_column(String(64), nullable=True)
    function: Mapped[str | None] = mapped_column(String(64), nullable=True)
    fns_order: Mapped[str | None] = mapped_column(String(128), nullable=True)
    schema_identity: Mapped[str | None] = mapped_column(String(128), nullable=True)
    counterparty_inn: Mapped[str | None] = mapped_column(String(12), nullable=True)
    counterparty_edo_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    document_number: Mapped[str | None] = mapped_column(Text, nullable=True)
    document_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    id_file: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    filename: Mapped[str | None] = mapped_column(Text, nullable=True)
    exact_xml_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    signature_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    raw_edo_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    raw_edo_status_label: Mapped[str | None] = mapped_column(Text, nullable=True)
    normalized_local_state: Mapped[str] = mapped_column(String(64), nullable=False)
    gis_source_doc_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    gis_result_doc_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    gis_processing_state: Mapped[str | None] = mapped_column(String(32), nullable=True)
    correction_relation: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    annulment_relation: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    last_error_http: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_error_raw: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_reconciled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    evidence_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        CheckConstraint("direction IN ('INCOMING','OUTGOING','UNKNOWN')", name="ck_edo_lite_direction"),
    )


class EdoLiteSchemaRegistryRecord(Base):
    __tablename__ = "edo_lite_schema_registry"

    schema_identity: Mapped[str] = mapped_column(String(128), primary_key=True)
    family: Mapped[str] = mapped_column(String(64), nullable=False)
    official_type_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    title_role: Mapped[str | None] = mapped_column(String(32), nullable=True)
    function: Mapped[str | None] = mapped_column(String(64), nullable=True)
    official_order: Mapped[str | None] = mapped_column(String(128), nullable=True)
    artifact_filename: Mapped[str | None] = mapped_column(Text, nullable=True)
    artifact_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    xsd_filename: Mapped[str | None] = mapped_column(Text, nullable=True)
    xsd_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    root: Mapped[str | None] = mapped_column(Text, nullable=True)
    target_namespace: Mapped[str | None] = mapped_column(Text, nullable=True)
    encoding: Mapped[str | None] = mapped_column(String(32), nullable=True)
    filename_grammar: Mapped[str | None] = mapped_column(Text, nullable=True)
    parent_link_rule: Mapped[str | None] = mapped_column(Text, nullable=True)
    marking_capability: Mapped[str | None] = mapped_column(Text, nullable=True)
    enabled_for_lp: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    disabled_reason: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        CheckConstraint("enabled_for_lp = false", name="ck_m7_schema_registry_foundation_disabled"),
    )


class EdoLiteAnnualQuotaRecord(Base):
    __tablename__ = "edo_lite_annual_quota"

    year: Mapped[int] = mapped_column(Integer, primary_key=True)
    local_observed_outgoing_count: Mapped[int] = mapped_column(Integer, nullable=False)
    last_updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    source_evidence: Mapped[str] = mapped_column(Text, nullable=False)
    authoritative_remote_remaining: Mapped[int | None] = mapped_column(Integer, nullable=True)

    __table_args__ = (
        CheckConstraint("local_observed_outgoing_count >= 0", name="ck_edo_lite_quota_nonnegative"),
        CheckConstraint("authoritative_remote_remaining IS NULL", name="ck_edo_lite_no_fake_remote_remaining"),
    )
