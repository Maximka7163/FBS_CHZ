from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0012_m11_reports"
down_revision = "0011_m10_ozon"
branch_labels = None
depends_on = None


_OLD_AGENT_TYPES = (
    "CIS_CHECK","LK_RECEIPT","LP_RETURN","POLL_DOCUMENT",
    "CIS_INFO","CIS_SEARCH","CIS_HISTORY","CIS_AGGREGATED_LIST","CIS_AGGREGATION_HISTORY","PRODUCT_INFO","CIS_TO_PRODUCT",
    "PARTICIPANTS","MODS_LIST","TN_VED_SEARCH","PRODUCT_GTIN_LIST","RD_LIST",
    "DOCUMENT_LIST","DOCUMENT_INFO","DOCUMENT_CISES",
    "LP_INTRODUCE_GOODS","LK_INDI_COMMISSIONING","LP_GOODS_IMPORT","CROSSBORDER","LP_INTRODUCE_OST",
    "LK_CONTRACT_COMMISSIONING","LP_FTS_INTRODUCE","LK_REMARK","WRITE_OFF","LK_RECEIPT_CANCEL",
    "AGGREGATION_DOCUMENT","SETS_AGGREGATION","REAGGREGATION_DOCUMENT","DISAGGREGATION_DOCUMENT",
    "ATK_AGGREGATION","ATK_TRANSFORMATION","ATK_DISAGGREGATION",
    "EDO_PARTICIPANT","EDO_OUTGOING_LIST","EDO_INCOMING_LIST","EDO_OUTGOING_CONTENT","EDO_INCOMING_CONTENT",
    "EDO_OUTGOING_PRINT","EDO_INCOMING_PRINT","EDO_OUTGOING_LEGAL_ZIP","EDO_INCOMING_LEGAL_ZIP",
    "EDO_OUTGOING_UNSIGNED_EVENTS","EDO_INCOMING_UNSIGNED_EVENTS","EDO_EVENT_CONTENT",
    "EDO_OUTGOING_RECEIPT","EDO_INCOMING_RECEIPT","EDO_OUTGOING_MCHD","EDO_INCOMING_MCHD","EDO_GIS_PROCESSING",
)
_M11_AGENT_TYPES = (
    "REPORT_CREATE","REPORT_TASK_GET","REPORT_TASK_LIST","REPORT_RESULTS",
    "REPORT_DOWNLOAD","REPORT_QUOTA_TYPE","REPORT_QUOTA_ID",
)


def _job_type_check(values: tuple[str, ...]) -> str:
    return "job_type IN (" + ",".join("'" + value + "'" for value in values) + ")"


def upgrade() -> None:
    op.create_table(
        "report_snapshots",
        sa.Column("id", sa.String(length=64), primary_key=True, nullable=False),
        sa.Column("report_job_id", sa.String(length=64), nullable=False),
        sa.Column("strategy", sa.String(length=48), nullable=False),
        sa.Column("snapshot_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_domains", sa.JSON(), nullable=False, server_default=sa.text("'[]'::json")),
        sa.Column("source_tables", sa.JSON(), nullable=False, server_default=sa.text("'[]'::json")),
        sa.Column("high_water_metadata", sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")),
        sa.Column("source_filter_sanitized", sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")),
        sa.Column("descriptor_sha256", sa.String(length=64), nullable=False),
        sa.Column("schema_version", sa.String(length=32), nullable=False),
        sa.Column("internal_snapshot_artifact_id", sa.String(length=64), nullable=True),
        sa.Column("row_count", sa.BigInteger(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_report_snapshots_report_job_id", "report_snapshots", ["report_job_id"])
    op.create_index("ix_report_snapshots_descriptor_sha256", "report_snapshots", ["descriptor_sha256"])

    op.create_table(
        "report_jobs",
        sa.Column("id", sa.String(length=64), primary_key=True, nullable=False),
        sa.Column("origin", sa.String(length=24), nullable=False),
        sa.Column("participant_inn", sa.String(length=12), nullable=False),
        sa.Column("report_type", sa.String(length=80), nullable=False),
        sa.Column("report_schema_version", sa.String(length=32), nullable=False),
        sa.Column("output_format", sa.String(length=16), nullable=False),
        sa.Column("sensitivity_class", sa.String(length=32), nullable=False),
        sa.Column("filters_sanitized_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")),
        sa.Column("sensitive_filter_ref", sa.Text(), nullable=True),
        sa.Column("request_fingerprint_sha256", sa.String(length=64), nullable=False),
        sa.Column("state", sa.String(length=24), nullable=False),
        sa.Column("snapshot_id", sa.String(length=64), sa.ForeignKey("report_snapshots.id", ondelete="SET NULL"), nullable=True),
        sa.Column("remote_task_id", sa.String(length=256), nullable=True),
        sa.Column("raw_remote_status", sa.Text(), nullable=True),
        sa.Column("remote_metadata_sanitized", sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")),
        sa.Column("remote_create_ambiguous", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("requested_by_user_id", sa.Text(), nullable=True),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("lease_owner", sa.String(length=128), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error_code", sa.String(length=80), nullable=True),
        sa.Column("error_message_redacted", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("origin IN ('LOCAL','TRUE_API_REMOTE')", name="ck_report_jobs_origin"),
        sa.CheckConstraint("state IN ('REQUESTED','QUEUED','GENERATING','READY','FAILED','EXPIRED','CANCELLED')", name="ck_report_jobs_state"),
    )
    for name, cols in (
        ("ix_report_jobs_origin", ["origin"]),
        ("ix_report_jobs_participant_inn", ["participant_inn"]),
        ("ix_report_jobs_report_type", ["report_type"]),
        ("ix_report_jobs_request_fingerprint_sha256", ["request_fingerprint_sha256"]),
        ("ix_report_jobs_state", ["state"]),
        ("ix_report_jobs_snapshot_id", ["snapshot_id"]),
        ("ix_report_jobs_remote_task_id", ["remote_task_id"]),
        ("ix_report_jobs_lease_expires_at", ["lease_expires_at"]),
    ):
        op.create_index(name, "report_jobs", cols)

    op.create_table(
        "report_artifacts",
        sa.Column("artifact_id", sa.String(length=64), primary_key=True, nullable=False),
        sa.Column("report_job_id", sa.String(length=64), sa.ForeignKey("report_jobs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("artifact_role", sa.String(length=40), nullable=False),
        sa.Column("publication_key", sa.String(length=128), nullable=False, unique=True),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("storage_backend", sa.String(length=40), nullable=False),
        sa.Column("storage_key", sa.Text(), nullable=False, unique=True),
        sa.Column("format", sa.String(length=16), nullable=False),
        sa.Column("mime", sa.String(length=160), nullable=True),
        sa.Column("safe_filename", sa.Text(), nullable=False),
        sa.Column("byte_size", sa.BigInteger(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("sensitivity_class", sa.String(length=32), nullable=False),
        sa.Column("encryption_metadata", sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")),
        sa.Column("encryption_version", sa.String(length=64), nullable=True),
        sa.Column("remote_result_id", sa.String(length=256), nullable=True),
        sa.Column("remote_result_part_id", sa.String(length=256), nullable=True),
        sa.Column("remote_file_delete_date_raw", sa.Text(), nullable=True),
        sa.Column("remote_file_delete_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("artifact_role IN ('OUTPUT','REMOTE_TRUE_API_ARCHIVE','SNAPSHOT_INTERNAL','MANIFEST')", name="ck_report_artifacts_role"),
        sa.CheckConstraint("state IN ('PENDING','READY','FAILED','INTEGRITY_CONFLICT','DELETED')", name="ck_report_artifacts_state"),
    )
    op.create_index("ix_report_artifacts_report_job_id", "report_artifacts", ["report_job_id"])
    op.create_index("ix_report_artifacts_state", "report_artifacts", ["state"])
    op.create_index("ix_report_artifacts_remote_result_id", "report_artifacts", ["remote_result_id"])

    op.create_table(
        "report_job_events",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True, nullable=False),
        sa.Column("report_job_id", sa.String(length=64), sa.ForeignKey("report_jobs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("from_state", sa.String(length=24), nullable=True),
        sa.Column("to_state", sa.String(length=24), nullable=True),
        sa.Column("details_redacted", sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")),
        sa.Column("artifact_id", sa.String(length=64), nullable=True),
        sa.Column("remote_task_id", sa.String(length=256), nullable=True),
        sa.Column("remote_result_id", sa.String(length=256), nullable=True),
        sa.Column("evidence_sha256", sa.String(length=64), nullable=True),
        sa.Column("actor_user_id", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_report_job_events_report_job_id", "report_job_events", ["report_job_id"])
    op.create_index("ix_report_job_events_event_type", "report_job_events", ["event_type"])

    op.create_table(
        "report_artifact_uploads",
        sa.Column("artifact_upload_id", sa.String(length=96), primary_key=True, nullable=False),
        sa.Column("report_job_id", sa.String(length=64), sa.ForeignKey("report_jobs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("remote_result_id", sa.String(length=256), nullable=False),
        sa.Column("remote_result_part_id", sa.String(length=256), nullable=True),
        sa.Column("product_group_code", sa.String(length=32), nullable=True),
        sa.Column("expected_archive_size", sa.BigInteger(), nullable=True),
        sa.Column("state", sa.String(length=24), nullable=False),
        sa.Column("finalized_artifact_id", sa.String(length=64), sa.ForeignKey("report_artifacts.artifact_id", ondelete="SET NULL"), nullable=True),
        sa.Column("observed_byte_size", sa.BigInteger(), nullable=True),
        sa.Column("observed_sha256", sa.String(length=64), nullable=True),
        sa.Column("observed_mime", sa.String(length=160), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("state IN ('PREPARED','RECEIVING','COMPLETED','CONFLICT','FAILED')", name="ck_report_artifact_uploads_state"),
    )
    op.create_index("ix_report_artifact_uploads_report_job_id", "report_artifact_uploads", ["report_job_id"])
    op.create_index("ix_report_artifact_uploads_state", "report_artifact_uploads", ["state"])

    op.drop_constraint("ck_agent_jobs_type", "agent_jobs", type_="check")
    op.create_check_constraint("ck_agent_jobs_type", "agent_jobs", _job_type_check(_OLD_AGENT_TYPES + _M11_AGENT_TYPES))


def downgrade() -> None:
    op.drop_constraint("ck_agent_jobs_type", "agent_jobs", type_="check")
    op.create_check_constraint("ck_agent_jobs_type", "agent_jobs", _job_type_check(_OLD_AGENT_TYPES))
    op.drop_index("ix_report_artifact_uploads_state", table_name="report_artifact_uploads")
    op.drop_index("ix_report_artifact_uploads_report_job_id", table_name="report_artifact_uploads")
    op.drop_table("report_artifact_uploads")
    op.drop_index("ix_report_job_events_event_type", table_name="report_job_events")
    op.drop_index("ix_report_job_events_report_job_id", table_name="report_job_events")
    op.drop_table("report_job_events")
    op.drop_index("ix_report_artifacts_remote_result_id", table_name="report_artifacts")
    op.drop_index("ix_report_artifacts_state", table_name="report_artifacts")
    op.drop_index("ix_report_artifacts_report_job_id", table_name="report_artifacts")
    op.drop_table("report_artifacts")
    for name in (
        "ix_report_jobs_lease_expires_at","ix_report_jobs_remote_task_id","ix_report_jobs_snapshot_id",
        "ix_report_jobs_state","ix_report_jobs_request_fingerprint_sha256","ix_report_jobs_report_type",
        "ix_report_jobs_participant_inn","ix_report_jobs_origin",
    ):
        op.drop_index(name, table_name="report_jobs")
    op.drop_table("report_jobs")
    op.drop_index("ix_report_snapshots_descriptor_sha256", table_name="report_snapshots")
    op.drop_index("ix_report_snapshots_report_job_id", table_name="report_snapshots")
    op.drop_table("report_snapshots")
