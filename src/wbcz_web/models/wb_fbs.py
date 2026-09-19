from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Integer, JSON, LargeBinary, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


class WbConnectionRecord(Base):
    __tablename__ = "wb_connections"

    organisation_id: Mapped[str | None] = mapped_column(ForeignKey("organisations.id", ondelete="RESTRICT"), nullable=True, index=True)
    participant_id: Mapped[str | None] = mapped_column(ForeignKey("participants.id", ondelete="RESTRICT"), nullable=True, index=True)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    environment: Mapped[str] = mapped_column(String(24), nullable=False)
    participant_inn: Mapped[str] = mapped_column(String(12), nullable=False, index=True)
    wb_sid: Mapped[str | None] = mapped_column(Text, nullable=True)
    wb_tin: Mapped[str | None] = mapped_column(String(12), nullable=True)
    token_type: Mapped[str] = mapped_column(String(32), nullable=False)
    token_categories: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    token_scopes: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    token_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    secret_ref: Mapped[str] = mapped_column(Text, nullable=False)
    rate_profile: Mapped[str | None] = mapped_column(String(64), nullable=True)
    connection_state: Mapped[str] = mapped_column(String(32), nullable=False)
    last_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())


class WbOrderRecord(Base):
    __tablename__ = "wb_orders"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    connection_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("wb_connections.id", ondelete="CASCADE"), nullable=False, index=True)
    assembly_order_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    order_uid: Mapped[str | None] = mapped_column(Text, nullable=True)
    rid: Mapped[str | None] = mapped_column(Text, nullable=True)
    srid: Mapped[str | None] = mapped_column(Text, nullable=True)
    nm_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    chrt_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    article: Mapped[str | None] = mapped_column(Text, nullable=True)
    barcode: Mapped[str | None] = mapped_column(Text, nullable=True)
    skus: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    warehouse_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    office_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    supply_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    sticker_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    fulfillment_model: Mapped[str] = mapped_column(String(16), nullable=False, default="FBS")
    raw_supplier_status: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_wb_status: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at_raw: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_at_raw: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at_parsed: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    price_evidence: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    currency_evidence: Mapped[str | None] = mapped_column(String(8), nullable=True)
    is_b2b: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    source: Mapped[str] = mapped_column(String(16), nullable=False)
    source_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    raw_evidence_ref: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_evidence_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        UniqueConstraint("connection_id", "assembly_order_id", name="uq_wb_order_connection_assembly"),
    )


class WbMarkingBindingRecord(Base):
    __tablename__ = "wb_marking_bindings"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    order_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("wb_orders.id", ondelete="CASCADE"), nullable=False, index=True)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    auth_tag: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    key_version: Mapped[str] = mapped_column(String(64), nullable=False)
    vault_format: Mapped[str] = mapped_column(String(64), nullable=False)
    aad_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    fingerprint_sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    masked_value: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String(16), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    validation_state: Mapped[str] = mapped_column(String(32), nullable=False)
    conflict_state: Mapped[str] = mapped_column(String(32), nullable=False)
    source_evidence_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class WbEventRecord(Base):
    __tablename__ = "wb_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    connection_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("wb_connections.id", ondelete="CASCADE"), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(16), nullable=False)
    source_family: Mapped[str] = mapped_column(String(40), nullable=False)
    source_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    assembly_order_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    rid: Mapped[str | None] = mapped_column(Text, nullable=True)
    srid: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_status: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_cancel_type: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_evidence_sanitized: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    raw_evidence_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        UniqueConstraint("connection_id", "source", "source_fingerprint", name="uq_wb_event_evidence"),
    )


class WbReturnRecord(Base):
    __tablename__ = "wb_returns"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    connection_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("wb_connections.id", ondelete="CASCADE"), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(16), nullable=False)
    source_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    order_id_raw: Mapped[str | None] = mapped_column(Text, nullable=True)
    srid: Mapped[str | None] = mapped_column(Text, nullable=True)
    nm_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    barcode: Mapped[str | None] = mapped_column(Text, nullable=True)
    sticker_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    shk_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    ready_to_return_dt_raw: Mapped[str | None] = mapped_column(Text, nullable=True)
    ready_to_return_dt_parsed: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_dt_raw: Mapped[str | None] = mapped_column(Text, nullable=True)
    completed_dt_parsed: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    timestamp_semantics: Mapped[str] = mapped_column(String(32), nullable=False)
    raw_return_status: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_return_type: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_evidence_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_state: Mapped[str] = mapped_column(String(32), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class WbSyncCursorRecord(Base):
    __tablename__ = "wb_sync_cursors"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    connection_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("wb_connections.id", ondelete="CASCADE"), nullable=False, index=True)
    feed: Mapped[str] = mapped_column(String(40), nullable=False)
    window_start_raw: Mapped[str | None] = mapped_column(Text, nullable=True)
    window_end_raw: Mapped[str | None] = mapped_column(Text, nullable=True)
    next_cursor: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    snapshot_time: Mapped[str | None] = mapped_column(Text, nullable=True)
    offset: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    last_change_date: Mapped[str | None] = mapped_column(Text, nullable=True)
    year: Mapped[int | None] = mapped_column(Integer, nullable=True)
    month: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cycle_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    generation: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        UniqueConstraint("connection_id", "feed", name="uq_wb_sync_cursor_connection_feed"),
    )


class WbReconciliationRecord(Base):
    __tablename__ = "wb_reconciliation"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    connection_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("wb_connections.id", ondelete="CASCADE"), nullable=False, index=True)
    order_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("wb_orders.id", ondelete="CASCADE"), nullable=True, index=True)
    state: Mapped[str] = mapped_column(String(48), nullable=False)
    decision: Mapped[str] = mapped_column(String(48), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_redacted: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class WbPaidEvidenceRecord(Base):
    __tablename__ = "wb_paid_evidence"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    connection_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("wb_connections.id", ondelete="CASCADE"), nullable=False, index=True)
    order_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("wb_orders.id", ondelete="CASCADE"), nullable=True, index=True)
    source: Mapped[str] = mapped_column(String(40), nullable=False)
    raw_amount: Mapped[str] = mapped_column(Text, nullable=False)
    currency: Mapped[str | None] = mapped_column(String(8), nullable=True)
    scale: Mapped[int | None] = mapped_column(Integer, nullable=True)
    contract_status: Mapped[str] = mapped_column(String(40), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
