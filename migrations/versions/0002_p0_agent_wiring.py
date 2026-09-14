from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0002_p0_agent_wiring"
down_revision = "0001_web_v05"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "write_operations",
        sa.Column("operation_id", sa.String(64), primary_key=True),
        sa.Column("business_fingerprint", sa.String(64), nullable=False),
        sa.Column("event_id", sa.String(64), nullable=False),
        sa.Column("decision", sa.String(32), nullable=False),
        sa.Column("document_type", sa.String(32), nullable=False),
        sa.Column("operation_reason", sa.String(64), nullable=False),
        sa.Column("pg", sa.String(16), nullable=False),
        sa.Column("expected_inn", sa.String(12), nullable=False),
        sa.Column("document_sha256", sa.String(64), nullable=False),
        sa.Column("product_document_base64", sa.Text(), nullable=False),
        sa.Column("prepared_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("signature_base64", sa.Text(), nullable=True),
        sa.Column("certificate_thumbprint", sa.String(160), nullable=True),
        sa.Column("certificate_subject", sa.Text(), nullable=True),
        sa.Column("certificate_inn", sa.String(12), nullable=True),
        sa.Column("certificate_valid_from", sa.String(64), nullable=True),
        sa.Column("certificate_valid_to", sa.String(64), nullable=True),
        sa.Column("document_id", sa.String(512), nullable=True),
        sa.Column("submit_http_status", sa.Integer(), nullable=True),
        sa.Column("submit_category", sa.String(64), nullable=True),
        sa.Column("submit_body_sha256", sa.String(64), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("decision IN ('READY_TO_WITHDRAW','READY_TO_RETURN')", name="ck_write_operations_decision"),
        sa.CheckConstraint("document_type IN ('LK_RECEIPT','LP_RETURN')", name="ck_write_operations_document_type"),
        sa.CheckConstraint("operation_reason IN ('DISTANCE','REMOTE_SALE_RETURN')", name="ck_write_operations_reason"),
        sa.CheckConstraint("pg = 'lp'", name="ck_write_operations_pg"),
        sa.CheckConstraint("state IN ('PREPARED','AWAITING_SIGNATURE','SIGNED','SUBMITTING','SUBMITTED','PROCESSING','RECONCILIATION_REQUIRED','SUCCEEDED','FAILED','MANUAL_REVIEW','ERROR')", name="ck_write_operations_state"),
        sa.UniqueConstraint("business_fingerprint", name="uq_write_operations_business_fingerprint"),
        sa.UniqueConstraint("document_id", name="uq_write_operations_document_id"),
    )
    op.create_index("ix_write_operations_business_fingerprint", "write_operations", ["business_fingerprint"], unique=True)
    op.create_index("ix_write_operations_event_id", "write_operations", ["event_id"])
    op.create_index("ix_write_operations_state", "write_operations", ["state"])

    op.create_table(
        "write_audit",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("operation_id", sa.String(64), nullable=False),
        sa.Column("action", sa.String(96), nullable=False),
        sa.Column("from_state", sa.String(32), nullable=True),
        sa.Column("to_state", sa.String(32), nullable=True),
        sa.Column("details_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["operation_id"], ["write_operations.operation_id"], ondelete="RESTRICT"),
    )
    op.create_index("ix_write_audit_operation_id", "write_audit", ["operation_id"])
    op.create_index("ix_write_audit_action", "write_audit", ["action"])
    op.execute("""
    CREATE OR REPLACE FUNCTION wbcz_write_audit_append_only() RETURNS trigger AS $$
    BEGIN
      RAISE EXCEPTION 'write_audit is append-only';
    END;
    $$ LANGUAGE plpgsql;
    """)
    op.execute("""
    CREATE TRIGGER trg_write_audit_append_only
    BEFORE UPDATE OR DELETE ON write_audit
    FOR EACH ROW EXECUTE FUNCTION wbcz_write_audit_append_only();
    """)

    op.create_table(
        "agent_jobs",
        sa.Column("job_id", sa.String(128), primary_key=True),
        sa.Column("job_type", sa.String(32), nullable=False),
        sa.Column("operation_id", sa.String(128), nullable=False),
        sa.Column("purpose", sa.String(48), nullable=False),
        sa.Column("event_id", sa.String(64), nullable=True),
        sa.Column("control_run_id", sa.String(36), nullable=True),
        sa.Column("poll_attempt", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("payload_sha256", sa.String(64), nullable=False),
        sa.Column("payload_json", sa.JSON(), nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("leased_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("delivery_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("result_sha256", sa.String(64), nullable=True),
        sa.Column("result_json", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("job_type IN ('CIS_CHECK','LK_RECEIPT','LP_RETURN','POLL_DOCUMENT')", name="ck_agent_jobs_type"),
        sa.CheckConstraint("state IN ('PENDING','LEASED','COMPLETED')", name="ck_agent_jobs_state"),
        sa.UniqueConstraint("job_id", "payload_sha256", name="uq_agent_jobs_payload"),
    )
    for name, cols in (
        ("ix_agent_jobs_job_type", ["job_type"]),
        ("ix_agent_jobs_operation_id", ["operation_id"]),
        ("ix_agent_jobs_purpose", ["purpose"]),
        ("ix_agent_jobs_event_id", ["event_id"]),
        ("ix_agent_jobs_control_run_id", ["control_run_id"]),
        ("ix_agent_jobs_state", ["state"]),
        ("ix_agent_jobs_available_at", ["available_at"]),
        ("ix_agent_jobs_lease_expires_at", ["lease_expires_at"]),
    ):
        op.create_index(name, "agent_jobs", cols)


def downgrade() -> None:
    op.drop_table("agent_jobs")
    op.execute("DROP TRIGGER IF EXISTS trg_write_audit_append_only ON write_audit")
    op.execute("DROP FUNCTION IF EXISTS wbcz_write_audit_append_only()")
    op.drop_table("write_audit")
    op.drop_table("write_operations")
