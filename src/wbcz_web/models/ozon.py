from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, DateTime, ForeignKey, Integer, JSON, LargeBinary, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


class OzonConnectionRecord(Base):
    __tablename__ = "ozon_connections"

    organisation_id: Mapped[str | None] = mapped_column(ForeignKey("organisations.id", ondelete="RESTRICT"), nullable=True, index=True)
    participant_id: Mapped[str | None] = mapped_column(ForeignKey("participants.id", ondelete="RESTRICT"), nullable=True, index=True)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    participant_inn: Mapped[str] = mapped_column(String(12), nullable=False, index=True)
    client_id: Mapped[str] = mapped_column(Text, nullable=False)
    api_key_secret_ref: Mapped[str] = mapped_column(Text, nullable=False)
    api_key_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    roles_metadata: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    capability_metadata: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    connection_state: Mapped[str] = mapped_column(String(32), nullable=False)
    last_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())


class OzonPostingRecord(Base):
    __tablename__ = "ozon_postings"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    connection_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("ozon_connections.id", ondelete="CASCADE"), nullable=False, index=True)
    posting_number: Mapped[str] = mapped_column(Text, nullable=False)
    order_id_opaque: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_status: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_substatus: Mapped[str | None] = mapped_column(Text, nullable=True)
    integration_type_flow_raw: Mapped[str | None] = mapped_column(Text, nullable=True)
    sorting_center_raw: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_capability: Mapped[str] = mapped_column(String(48), nullable=False)
    source_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    raw_sanitized_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    raw_created_at: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_updated_at: Mapped[str | None] = mapped_column(Text, nullable=True)
    local_reconciliation_state: Mapped[str] = mapped_column(String(48), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        UniqueConstraint("connection_id", "posting_number", name="uq_ozon_posting_connection_number"),
    )


class OzonItemRecord(Base):
    __tablename__ = "ozon_items"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    posting_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("ozon_postings.id", ondelete="CASCADE"), nullable=False, index=True)
    item_ref_opaque: Mapped[str | None] = mapped_column(Text, nullable=True)
    product_id_opaque: Mapped[str | None] = mapped_column(Text, nullable=True)
    offer_id_opaque: Mapped[str | None] = mapped_column(Text, nullable=True)
    sku_opaque: Mapped[str | None] = mapped_column(Text, nullable=True)
    barcode_opaque: Mapped[str | None] = mapped_column(Text, nullable=True)
    warehouse_id_opaque: Mapped[str | None] = mapped_column(Text, nullable=True)
    delivery_method_id_opaque: Mapped[str | None] = mapped_column(Text, nullable=True)
    exemplar_id_opaque: Mapped[str | None] = mapped_column(Text, nullable=True)
    quantity_raw: Mapped[str | None] = mapped_column(Text, nullable=True)
    relation_metadata_sanitized: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    source_capability: Mapped[str] = mapped_column(String(48), nullable=False)
    source_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class OzonMarkingBindingRecord(Base):
    __tablename__ = "ozon_marking_bindings"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    connection_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("ozon_connections.id", ondelete="CASCADE"), nullable=False, index=True)
    posting_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("ozon_postings.id", ondelete="CASCADE"), nullable=True, index=True)
    item_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("ozon_items.id", ondelete="CASCADE"), nullable=True, index=True)
    exemplar_id_opaque: Mapped[str | None] = mapped_column(Text, nullable=True)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    auth_tag: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    key_version: Mapped[str] = mapped_column(String(64), nullable=False)
    vault_format: Mapped[str] = mapped_column(String(64), nullable=False)
    aad_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    plaintext_sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    ciphertext_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    masked_value: Mapped[str] = mapped_column(Text, nullable=False)
    source_capability: Mapped[str] = mapped_column(String(48), nullable=False)
    source_evidence_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class OzonEventRecord(Base):
    __tablename__ = "ozon_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    connection_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("ozon_connections.id", ondelete="CASCADE"), nullable=False, index=True)
    posting_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("ozon_postings.id", ondelete="CASCADE"), nullable=True, index=True)
    source_capability: Mapped[str] = mapped_column(String(48), nullable=False)
    source_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_type: Mapped[str] = mapped_column(String(48), nullable=False)
    conflict_state: Mapped[str] = mapped_column(String(32), nullable=False)
    remote_identities_sanitized: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    raw_evidence_sanitized: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    raw_sanitized_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        UniqueConstraint("connection_id", "source_capability", "source_fingerprint", name="uq_ozon_event_evidence"),
    )


class OzonReturnRecord(Base):
    __tablename__ = "ozon_returns"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    connection_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("ozon_connections.id", ondelete="CASCADE"), nullable=False, index=True)
    posting_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("ozon_postings.id", ondelete="CASCADE"), nullable=True, index=True)
    return_id_opaque: Mapped[str | None] = mapped_column(Text, nullable=True)
    report_id_opaque: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_status: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_type: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_capability: Mapped[str] = mapped_column(String(48), nullable=False)
    source_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    raw_evidence_sanitized: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    raw_sanitized_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_state: Mapped[str] = mapped_column(String(32), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class OzonSyncCursorRecord(Base):
    __tablename__ = "ozon_sync_cursors"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    connection_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("ozon_connections.id", ondelete="CASCADE"), nullable=False, index=True)
    feed: Mapped[str] = mapped_column(String(48), nullable=False)
    capability: Mapped[str | None] = mapped_column(String(48), nullable=True)
    cycle_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    cursor_opaque: Mapped[str | None] = mapped_column(Text, nullable=True)
    offset_opaque: Mapped[str | None] = mapped_column(Text, nullable=True)
    window_start_raw: Mapped[str | None] = mapped_column(Text, nullable=True)
    window_end_raw: Mapped[str | None] = mapped_column(Text, nullable=True)
    snapshot_opaque: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error_redacted: Mapped[str | None] = mapped_column(Text, nullable=True)
    generation: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        UniqueConstraint("connection_id", "feed", name="uq_ozon_sync_cursor_connection_feed"),
    )


class OzonReconciliationRecord(Base):
    __tablename__ = "ozon_reconciliation"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    connection_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("ozon_connections.id", ondelete="CASCADE"), nullable=False, index=True)
    posting_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("ozon_postings.id", ondelete="CASCADE"), nullable=True, index=True)
    state: Mapped[str] = mapped_column(String(48), nullable=False)
    decision: Mapped[str] = mapped_column(String(48), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_redacted: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class OzonPaidEvidenceRecord(Base):
    __tablename__ = "ozon_paid_evidence"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    connection_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("ozon_connections.id", ondelete="CASCADE"), nullable=False, index=True)
    posting_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("ozon_postings.id", ondelete="CASCADE"), nullable=True, index=True)
    source: Mapped[str] = mapped_column(String(48), nullable=False)
    raw_amount: Mapped[str] = mapped_column(Text, nullable=False)
    currency: Mapped[str | None] = mapped_column(String(8), nullable=True)
    scale: Mapped[int | None] = mapped_column(Integer, nullable=True)
    semantics: Mapped[str] = mapped_column(String(64), nullable=False)
    confidence_state: Mapped[str] = mapped_column(String(32), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
