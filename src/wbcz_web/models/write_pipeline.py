from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Integer, JSON, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


class WriteOperationRecord(Base):
    __tablename__ = "write_operations"

    operation_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    business_fingerprint: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    source_event_id: Mapped[str] = mapped_column(ForeignKey("events.event_id"), nullable=False, index=True)
    source_decision: Mapped[str] = mapped_column(String(32), nullable=False)
    document_type: Mapped[str] = mapped_column(String(32), nullable=False)
    operation_reason: Mapped[str] = mapped_column(String(64), nullable=False)
    pg: Mapped[str] = mapped_column(String(16), nullable=False)
    expected_inn: Mapped[str] = mapped_column(String(12), nullable=False)
    document_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    product_document_base64: Mapped[str] = mapped_column(Text, nullable=False)
    prepared_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False, index=True)

    signature_base64: Mapped[str | None] = mapped_column(Text, nullable=True)
    signature_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    certificate_thumbprint: Mapped[str | None] = mapped_column(String(128), nullable=True)
    certificate_subject: Mapped[str | None] = mapped_column(Text, nullable=True)
    certificate_inn: Mapped[str | None] = mapped_column(String(12), nullable=True)
    certificate_valid_from: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    certificate_valid_to: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    signed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    submit_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    submitted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    doc_id: Mapped[str | None] = mapped_column(String(256), unique=True, nullable=True)
    last_http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_response_meta: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    last_poll_status: Mapped[str | None] = mapped_column(String(64), nullable=True)
    terminal_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reconciliation_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class SigningRequestDbRecord(Base):
    __tablename__ = "signing_requests"

    request_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    operation_id: Mapped[str] = mapped_column(
        ForeignKey("write_operations.operation_id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
    )
    status: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    fulfilled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class WriteOperationAuditRecord(Base):
    __tablename__ = "write_operation_audit"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    operation_id: Mapped[str] = mapped_column(
        ForeignKey("write_operations.operation_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    action: Mapped[str] = mapped_column(String(96), nullable=False, index=True)
    from_state: Mapped[str | None] = mapped_column(String(32), nullable=True)
    to_state: Mapped[str] = mapped_column(String(32), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), index=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
