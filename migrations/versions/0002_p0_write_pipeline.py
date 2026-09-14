from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0002_p0_write_pipeline"
down_revision = "0001_web_v05"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "write_operations",
        sa.Column("operation_id", sa.String(length=36), primary_key=True),
        sa.Column("business_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("source_event_id", sa.String(length=64), sa.ForeignKey("events.event_id"), nullable=False),
        sa.Column("source_decision", sa.String(length=32), nullable=False),
        sa.Column("document_type", sa.String(length=32), nullable=False),
        sa.Column("operation_reason", sa.String(length=64), nullable=False),
        sa.Column("pg", sa.String(length=16), nullable=False),
        sa.Column("expected_inn", sa.String(length=12), nullable=False),
        sa.Column("document_sha256", sa.String(length=64), nullable=False),
        sa.Column("product_document_base64", sa.Text(), nullable=False),
        sa.Column("prepared_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("signature_base64", sa.Text(), nullable=True),
        sa.Column("signature_sha256", sa.String(length=64), nullable=True),
        sa.Column("certificate_thumbprint", sa.String(length=128), nullable=True),
        sa.Column("certificate_subject", sa.Text(), nullable=True),
        sa.Column("certificate_inn", sa.String(length=12), nullable=True),
        sa.Column("certificate_valid_from", sa.DateTime(timezone=True), nullable=True),
        sa.Column("certificate_valid_to", sa.DateTime(timezone=True), nullable=True),
        sa.Column("signed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("submit_started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("submitted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("doc_id", sa.String(length=256), nullable=True),
        sa.Column("last_http_status", sa.Integer(), nullable=True),
        sa.Column("last_response_meta", sa.JSON(), nullable=False),
        sa.Column("last_poll_status", sa.String(length=64), nullable=True),
        sa.Column("terminal_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reconciliation_required", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.UniqueConstraint("business_fingerprint", name="uq_write_operations_business_fingerprint"),
        sa.UniqueConstraint("doc_id", name="uq_write_operations_doc_id"),
    )
    op.create_index("ix_write_operations_source_event_id", "write_operations", ["source_event_id"])
    op.create_index("ix_write_operations_state", "write_operations", ["state"])

    op.create_table(
        "signing_requests",
        sa.Column("request_id", sa.String(length=36), primary_key=True),
        sa.Column(
            "operation_id",
            sa.String(length=36),
            sa.ForeignKey("write_operations.operation_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("fulfilled_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("operation_id", name="uq_signing_requests_operation_id"),
    )
    op.create_index("ix_signing_requests_status", "signing_requests", ["status"])

    op.create_table(
        "write_operation_audit",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column(
            "operation_id",
            sa.String(length=36),
            sa.ForeignKey("write_operations.operation_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("action", sa.String(length=96), nullable=False),
        sa.Column("from_state", sa.String(length=32), nullable=True),
        sa.Column("to_state", sa.String(length=32), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
    )
    op.create_index("ix_write_operation_audit_operation_id", "write_operation_audit", ["operation_id"])
    op.create_index("ix_write_operation_audit_action", "write_operation_audit", ["action"])
    op.create_index("ix_write_operation_audit_occurred_at", "write_operation_audit", ["occurred_at"])


def downgrade() -> None:
    op.drop_table("write_operation_audit")
    op.drop_table("signing_requests")
    op.drop_table("write_operations")
