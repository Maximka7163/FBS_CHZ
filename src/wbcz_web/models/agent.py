from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, CheckConstraint, DateTime, ForeignKey, Integer, JSON, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


_WRITE_STATES = (
    "PREPARED", "AWAITING_SIGNATURE", "SIGNED", "SUBMITTING", "SUBMITTED",
    "PROCESSING", "RECONCILIATION_REQUIRED", "SUCCEEDED", "FAILED",
    "MANUAL_REVIEW", "ERROR",
)


class WriteOperationRecord(Base):
    __tablename__ = "write_operations"

    operation_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    organisation_id: Mapped[str | None] = mapped_column(ForeignKey("organisations.id", ondelete="RESTRICT"), nullable=True, index=True)
    participant_id: Mapped[str | None] = mapped_column(ForeignKey("participants.id", ondelete="RESTRICT"), nullable=True, index=True)
    business_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    event_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    decision: Mapped[str] = mapped_column(String(32), nullable=False)
    document_type: Mapped[str] = mapped_column(String(32), nullable=False)
    operation_reason: Mapped[str] = mapped_column(String(64), nullable=False)
    pg: Mapped[str] = mapped_column(String(16), nullable=False)
    expected_inn: Mapped[str] = mapped_column(String(12), nullable=False)
    document_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    product_document_base64: Mapped[str] = mapped_column(Text, nullable=False)
    prepared_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    state: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    signature_base64: Mapped[str | None] = mapped_column(Text, nullable=True)
    certificate_thumbprint: Mapped[str | None] = mapped_column(String(160), nullable=True)
    certificate_subject: Mapped[str | None] = mapped_column(Text, nullable=True)
    certificate_inn: Mapped[str | None] = mapped_column(String(12), nullable=True)
    certificate_valid_from: Mapped[str | None] = mapped_column(String(64), nullable=True)
    certificate_valid_to: Mapped[str | None] = mapped_column(String(64), nullable=True)
    document_id: Mapped[str | None] = mapped_column(String(512), nullable=True)
    submit_http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    submit_category: Mapped[str | None] = mapped_column(String(64), nullable=True)
    submit_body_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        CheckConstraint("decision IN ('READY_TO_WITHDRAW','READY_TO_RETURN')", name="ck_write_operations_decision"),
        CheckConstraint("document_type IN ('LK_RECEIPT','LP_RETURN')", name="ck_write_operations_document_type"),
        CheckConstraint("operation_reason IN ('DISTANCE','REMOTE_SALE_RETURN')", name="ck_write_operations_reason"),
        CheckConstraint("pg = 'lp'", name="ck_write_operations_pg"),
        UniqueConstraint("organisation_id", "participant_id", "business_fingerprint", name="uq_write_operations_tenant_business_fingerprint"),
        UniqueConstraint("organisation_id", "participant_id", "document_id", name="uq_write_operations_tenant_document_id"),
        CheckConstraint(
            "state IN (" + ",".join(f"'{value}'" for value in _WRITE_STATES) + ")",
            name="ck_write_operations_state",
        ),
    )


class WriteAuditRecord(Base):
    __tablename__ = "write_audit"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    operation_id: Mapped[str] = mapped_column(String(64), ForeignKey("write_operations.operation_id", ondelete="CASCADE"), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(96), nullable=False, index=True)
    from_state: Mapped[str | None] = mapped_column(String(32), nullable=True)
    to_state: Mapped[str | None] = mapped_column(String(32), nullable=True)
    details_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class AgentJobRecord(Base):
    __tablename__ = "agent_jobs"

    job_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    organisation_id: Mapped[str | None] = mapped_column(ForeignKey("organisations.id", ondelete="RESTRICT"), nullable=True, index=True)
    participant_id: Mapped[str | None] = mapped_column(ForeignKey("participants.id", ondelete="RESTRICT"), nullable=True, index=True)
    correlation_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    causation_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    agent_binding_id: Mapped[str | None] = mapped_column(
        ForeignKey("agent_bindings.id", ondelete="RESTRICT"), nullable=True, index=True
    )
    job_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    operation_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    purpose: Mapped[str] = mapped_column(String(48), nullable=False, index=True)
    event_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    control_run_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    poll_attempt: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    payload_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    payload_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    state: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    available_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), index=True)
    leased_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    delivery_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    result_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    result_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        CheckConstraint("job_type IN ('CIS_CHECK','LK_RECEIPT','LP_RETURN','POLL_DOCUMENT','CIS_INFO','CIS_SEARCH','CIS_HISTORY','CIS_AGGREGATED_LIST','CIS_AGGREGATION_HISTORY','PRODUCT_INFO','CIS_TO_PRODUCT','PARTICIPANTS','MODS_LIST','TN_VED_SEARCH','PRODUCT_GTIN_LIST','RD_LIST','DOCUMENT_LIST','DOCUMENT_INFO','DOCUMENT_CISES','LP_INTRODUCE_GOODS','LK_INDI_COMMISSIONING','LP_GOODS_IMPORT','CROSSBORDER','LP_INTRODUCE_OST','LK_CONTRACT_COMMISSIONING','LP_FTS_INTRODUCE','LK_REMARK','WRITE_OFF','LK_RECEIPT_CANCEL','AGGREGATION_DOCUMENT','SETS_AGGREGATION','REAGGREGATION_DOCUMENT','DISAGGREGATION_DOCUMENT','ATK_AGGREGATION','ATK_TRANSFORMATION','ATK_DISAGGREGATION','EDO_PARTICIPANT','EDO_OUTGOING_LIST','EDO_INCOMING_LIST','EDO_OUTGOING_CONTENT','EDO_INCOMING_CONTENT','EDO_OUTGOING_PRINT','EDO_INCOMING_PRINT','EDO_OUTGOING_LEGAL_ZIP','EDO_INCOMING_LEGAL_ZIP','EDO_OUTGOING_UNSIGNED_EVENTS','EDO_INCOMING_UNSIGNED_EVENTS','EDO_EVENT_CONTENT','EDO_OUTGOING_RECEIPT','EDO_INCOMING_RECEIPT','EDO_OUTGOING_MCHD','EDO_INCOMING_MCHD','EDO_GIS_PROCESSING','REPORT_CREATE','REPORT_TASK_GET','REPORT_TASK_LIST','REPORT_RESULTS','REPORT_DOWNLOAD','REPORT_QUOTA_TYPE','REPORT_QUOTA_ID','INTEGRATION_HEALTH')", name="ck_agent_jobs_type"),
        CheckConstraint("state IN ('PENDING','LEASED','COMPLETED')", name="ck_agent_jobs_state"),
        UniqueConstraint("job_id", "payload_sha256", name="uq_agent_jobs_payload"),
    )


class DocumentLifecycleLedgerRecord(Base):
    __tablename__ = "document_lifecycle_ledger"

    operation_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    organisation_id: Mapped[str | None] = mapped_column(ForeignKey("organisations.id", ondelete="RESTRICT"), nullable=True, index=True)
    participant_id: Mapped[str | None] = mapped_column(ForeignKey("participants.id", ondelete="RESTRICT"), nullable=True, index=True)
    request_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    job_type: Mapped[str] = mapped_column(String(32), nullable=False)
    request_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(256), nullable=False)
    request_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())
    __table_args__ = (
        UniqueConstraint("organisation_id", "participant_id", "request_id", name="uq_document_lifecycle_ledger_tenant_request_id"),
    )


class TurnoverOperationLedgerRecord(Base):
    __tablename__ = "turnover_operation_ledger"

    operation_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    organisation_id: Mapped[str | None] = mapped_column(ForeignKey("organisations.id", ondelete="RESTRICT"), nullable=True, index=True)
    participant_id: Mapped[str | None] = mapped_column(ForeignKey("participants.id", ondelete="RESTRICT"), nullable=True, index=True)
    request_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    operation_kind: Mapped[str] = mapped_column(String(64), nullable=False)
    document_type: Mapped[str] = mapped_column(String(64), nullable=False)
    document_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    request_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(256), nullable=False)
    raw_business_reason: Mapped[str | None] = mapped_column(String(128), nullable=True)
    precondition_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    expected_postcondition: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    reconciliation_state: Mapped[str] = mapped_column(String(32), nullable=False)
    reconciliation_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    cancellation_reference: Mapped[str | None] = mapped_column(String(512), nullable=True)
    remote_document_id: Mapped[str | None] = mapped_column(String(512), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        CheckConstraint(
            "reconciliation_state IN ('RECONCILIATION_PENDING','RECONCILED','MANUAL_REVIEW')",
            name="ck_turnover_reconciliation_state",
        ),
        UniqueConstraint("organisation_id", "participant_id", "request_id", name="uq_turnover_operation_ledger_tenant_request_id"),
    )


class AggregationOperationLedgerRecord(Base):
    __tablename__ = "aggregation_operation_ledger"

    operation_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    organisation_id: Mapped[str | None] = mapped_column(ForeignKey("organisations.id", ondelete="RESTRICT"), nullable=True, index=True)
    participant_id: Mapped[str | None] = mapped_column(ForeignKey("participants.id", ondelete="RESTRICT"), nullable=True, index=True)
    request_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    operation_kind: Mapped[str] = mapped_column(String(64), nullable=False)
    document_type: Mapped[str] = mapped_column(String(64), nullable=False)
    document_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    request_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(256), nullable=False)
    parent_cis: Mapped[str | None] = mapped_column(String(128), nullable=True)
    discovered_parent_cis: Mapped[str | None] = mapped_column(String(128), nullable=True)
    child_set_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    relation_delta: Mapped[str] = mapped_column(String(32), nullable=False)
    precondition_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    expected_relation_delta: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    reconciliation_state: Mapped[str] = mapped_column(String(32), nullable=False)
    reconciliation_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    raw_history_evidence: Mapped[list[Any]] = mapped_column(JSON, nullable=False, default=list)
    remote_document_id: Mapped[str | None] = mapped_column(String(512), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        UniqueConstraint("organisation_id", "participant_id", "request_id", name="uq_aggregation_operation_ledger_tenant_request_id"),
        CheckConstraint("relation_delta IN ('FORM','ADD','REMOVE','DISAGGREGATE')", name="ck_aggregation_relation_delta"),
        CheckConstraint(
            "reconciliation_state IN ('RECONCILIATION_PENDING','RECONCILED','MANUAL_REVIEW')",
            name="ck_aggregation_reconciliation_state",
        ),
    )
