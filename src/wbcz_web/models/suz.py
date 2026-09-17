from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, CheckConstraint, DateTime, ForeignKey, Integer, JSON, LargeBinary, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


class SuzConnectionRecord(Base):
    __tablename__ = "suz_connections"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    participant_inn: Mapped[str] = mapped_column(String(12), nullable=False, index=True)
    oms_id: Mapped[str] = mapped_column(Text, nullable=False)
    oms_connection: Mapped[str] = mapped_column(Text, nullable=False, unique=True, index=True)
    environment: Mapped[str] = mapped_column(String(32), nullable=False)
    installation_name: Mapped[str] = mapped_column(Text, nullable=False)
    token_issued_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    token_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_auth_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    token_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    connection_state: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        CheckConstraint(
            "connection_state IN ('NOT_ACQUIRED','ACTIVE','EXPIRED','SUPERSEDED','INVALIDATED')",
            name="ck_suz_connection_state",
        ),
    )


class SuzKmVaultRecord(Base):
    __tablename__ = "suz_km_vault"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    order_operation_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    gtin: Mapped[str] = mapped_column(Text, nullable=False)
    remote_block_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    auth_tag: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    key_version: Mapped[str] = mapped_column(String(64), nullable=False)
    vault_format_version: Mapped[str] = mapped_column(String(64), nullable=False)
    aad_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    plaintext_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    ciphertext_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    code_count: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        CheckConstraint("code_count >= 0", name="ck_suz_km_vault_code_count_nonnegative"),
    )


class SuzOrderRecord(Base):
    __tablename__ = "suz_orders"

    operation_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    connection_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("suz_connections.id", ondelete="RESTRICT"), nullable=False, index=True)
    remote_order_id: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    request_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    raw_release_method: Mapped[str] = mapped_column(Text, nullable=False)
    raw_order_status: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_buffer_status: Mapped[str | None] = mapped_column(Text, nullable=True)
    requested_count: Mapped[int] = mapped_column(Integer, nullable=False)
    generated_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    fetched_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    reconciliation_state: Mapped[str] = mapped_column(String(64), nullable=False)
    submission_state: Mapped[str] = mapped_column(String(64), nullable=False)
    last_error_code: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_error_message_redacted: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        CheckConstraint("requested_count > 0", name="ck_suz_order_requested_count_positive"),
        CheckConstraint("generated_count IS NULL OR generated_count >= 0", name="ck_suz_order_generated_count_nonnegative"),
        CheckConstraint("fetched_count IS NULL OR fetched_count >= 0", name="ck_suz_order_fetched_count_nonnegative"),
        CheckConstraint(
            "submission_state IN ('NOT_SUBMITTED','SUBMISSION_UNKNOWN','REMOTE_LOOKUP_REQUIRED','REMOTE_CONFIRMED','CONFLICT','MANUAL_REVIEW')",
            name="ck_suz_order_submission_state",
        ),
    )


class SuzOrderItemRecord(Base):
    __tablename__ = "suz_order_items"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    order_operation_id: Mapped[str] = mapped_column(String(128), ForeignKey("suz_orders.operation_id", ondelete="CASCADE"), nullable=False, index=True)
    gtin: Mapped[str] = mapped_column(Text, nullable=False)
    quantity: Mapped[int] = mapped_column(Integer, nullable=False)
    serial_mode: Mapped[str] = mapped_column(String(32), nullable=False)
    serial_count: Mapped[int] = mapped_column(Integer, nullable=False)
    serials_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    raw_template_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_cis_type: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_create_method_type: Mapped[str | None] = mapped_column(Text, nullable=True)
    service_provider_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    producer: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        UniqueConstraint("order_operation_id", "gtin", name="uq_suz_order_item_gtin"),
        CheckConstraint("quantity > 0", name="ck_suz_order_item_quantity_positive"),
        CheckConstraint("serial_count >= 0", name="ck_suz_order_item_serial_count_nonnegative"),
        CheckConstraint("serial_mode IN ('OPERATOR','SELF_MADE')", name="ck_suz_order_item_serial_mode"),
    )


class SuzCodeBlockRecord(Base):
    __tablename__ = "suz_code_blocks"

    local_block_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    order_operation_id: Mapped[str] = mapped_column(String(128), ForeignKey("suz_orders.operation_id", ondelete="CASCADE"), nullable=False, index=True)
    gtin: Mapped[str] = mapped_column(Text, nullable=False)
    remote_block_id: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    remote_package_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    code_count: Mapped[int] = mapped_column(Integer, nullable=False)
    exact_payload_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    vault_entry_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("suz_km_vault.id", ondelete="RESTRICT"), nullable=False, unique=True)
    fetch_state: Mapped[str] = mapped_column(String(64), nullable=False)
    recovery_state: Mapped[str] = mapped_column(String(64), nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    committed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        CheckConstraint("code_count >= 0", name="ck_suz_code_block_count_nonnegative"),
    )


class SuzReconciliationEventRecord(Base):
    __tablename__ = "suz_reconciliation_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    order_operation_id: Mapped[str] = mapped_column(String(128), ForeignKey("suz_orders.operation_id", ondelete="CASCADE"), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    from_state: Mapped[str | None] = mapped_column(String(64), nullable=True)
    to_state: Mapped[str | None] = mapped_column(String(64), nullable=True)
    raw_order_status: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_buffer_status: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_code: Mapped[str | None] = mapped_column(Text, nullable=True)
    details_redacted: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    evidence_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
