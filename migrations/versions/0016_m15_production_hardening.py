"""M15 production hardening operational state.

Revision ID: 0016_m15_production_hardening
Revises: 0015_m14_integration_settings

Additive schema-only migration. No environment secrets, certificates, PINs,
remote calls, business mutations, or guessed external contracts are involved.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0016_m15_production_hardening"
down_revision = "0015_m14_integration_settings"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "manual_review_cases",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organisation_id", sa.String(36), sa.ForeignKey("organisations.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("participant_id", sa.String(36), nullable=False),
        sa.Column("active_fingerprint", sa.String(64), nullable=False),
        sa.Column("domain", sa.String(48), nullable=False),
        sa.Column("reason_code", sa.String(96), nullable=False),
        sa.Column("subject_type", sa.String(48), nullable=False),
        sa.Column("subject_id", sa.String(160), nullable=False),
        sa.Column("operation_id", sa.String(160), nullable=True),
        sa.Column("source_job_id", sa.String(160), nullable=True),
        sa.Column("severity", sa.String(16), nullable=False, server_default="WARNING"),
        sa.Column("status", sa.String(16), nullable=False, server_default="OPEN"),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("occurrence_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("evidence_hashes_json", sa.JSON(), nullable=False, server_default=sa.text("'[]'::json")),
        sa.Column("metadata_sanitized_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")),
        sa.Column("assigned_to_user_id", sa.BigInteger(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("resolved_by_user_id", sa.BigInteger(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolution_code", sa.String(80), nullable=True),
        sa.Column("resolution_note", sa.String(500), nullable=True),
        sa.Column("correlation_id", sa.String(128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(
            ["participant_id","organisation_id"],
            ["participants.id","participants.organisation_id"],
            name="fk_manual_review_participant_organisation",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint("severity IN ('INFO','WARNING','HIGH','CRITICAL')", name="ck_manual_review_severity"),
        sa.CheckConstraint("status IN ('OPEN','ACKNOWLEDGED','RESOLVED')", name="ck_manual_review_status"),
        sa.CheckConstraint("occurrence_count >= 1", name="ck_manual_review_occurrence_count"),
        sa.CheckConstraint("attempt_count >= 0", name="ck_manual_review_attempt_count"),
    )
    for name, cols in (
        ("ix_manual_review_organisation", ["organisation_id"]),
        ("ix_manual_review_participant", ["participant_id"]),
        ("ix_manual_review_fingerprint", ["active_fingerprint"]),
        ("ix_manual_review_domain", ["domain"]),
        ("ix_manual_review_reason", ["reason_code"]),
        ("ix_manual_review_operation", ["operation_id"]),
        ("ix_manual_review_source_job", ["source_job_id"]),
        ("ix_manual_review_severity", ["severity"]),
        ("ix_manual_review_status", ["status"]),
        ("ix_manual_review_correlation", ["correlation_id"]),
    ):
        op.create_index(name, "manual_review_cases", cols)
    op.create_index(
        "uq_manual_review_active_fingerprint",
        "manual_review_cases",
        ["organisation_id","participant_id","active_fingerprint"],
        unique=True,
        postgresql_where=sa.text("status IN ('OPEN','ACKNOWLEDGED')"),
    )

    op.create_table(
        "worker_heartbeats",
        sa.Column("worker_id", sa.String(128), primary_key=True),
        sa.Column("role", sa.String(32), nullable=False),
        sa.Column("instance_id", sa.String(128), nullable=False),
        sa.Column("state", sa.String(16), nullable=False, server_default="RUNNING"),
        sa.Column("build_sha", sa.String(64), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("scheduler_heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("state IN ('RUNNING','DRAINING','STOPPED')", name="ck_worker_heartbeat_state"),
    )
    op.create_index("ix_worker_heartbeats_role", "worker_heartbeats", ["role"])
    op.create_index("ix_worker_heartbeats_instance", "worker_heartbeats", ["instance_id"])
    op.create_index("ix_worker_heartbeats_state", "worker_heartbeats", ["state"])
    op.create_index("ix_worker_heartbeats_heartbeat", "worker_heartbeats", ["heartbeat_at"])

    op.create_table(
        "remote_rate_limit_state",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("provider", sa.String(24), nullable=False),
        sa.Column("connection_id", sa.String(160), nullable=False),
        sa.Column("credential_version", sa.String(128), nullable=False),
        sa.Column("environment", sa.String(24), nullable=False),
        sa.Column("rate_family", sa.String(64), nullable=False),
        sa.Column("token_type", sa.String(32), nullable=True),
        sa.Column("tokens", sa.Float(), nullable=False),
        sa.Column("capacity", sa.Float(), nullable=False),
        sa.Column("refill_per_second", sa.Float(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "provider","connection_id","credential_version","environment","rate_family",
            name="uq_remote_rate_scope",
        ),
        sa.CheckConstraint("capacity > 0", name="ck_remote_rate_capacity"),
        sa.CheckConstraint("refill_per_second > 0", name="ck_remote_rate_refill"),
    )

    op.create_table(
        "agent_enrollment_tokens",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organisation_id", sa.String(36), sa.ForeignKey("organisations.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("participant_id", sa.String(36), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("display_name", sa.String(200), nullable=False),
        sa.Column("requested_protocol_version", sa.String(32), nullable=False),
        sa.Column("state", sa.String(16), nullable=False, server_default="PENDING"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("binding_id", sa.String(36), nullable=True),
        sa.Column("created_by_user_id", sa.BigInteger(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("correlation_id", sa.String(128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(
            ["participant_id","organisation_id"],
            ["participants.id","participants.organisation_id"],
            name="fk_agent_enrollment_participant_organisation",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["binding_id","organisation_id","participant_id"],
            ["agent_bindings.id","agent_bindings.organisation_id","agent_bindings.participant_id"],
            name="fk_agent_enrollment_binding_tenant",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("token_hash", name="uq_agent_enrollment_token_hash"),
        sa.CheckConstraint("state IN ('PENDING','USED','EXPIRED','REVOKED')", name="ck_agent_enrollment_state"),
    )
    for name, cols in (
        ("ix_agent_enrollment_organisation", ["organisation_id"]),
        ("ix_agent_enrollment_participant", ["participant_id"]),
        ("ix_agent_enrollment_state", ["state"]),
        ("ix_agent_enrollment_expires", ["expires_at"]),
        ("ix_agent_enrollment_binding", ["binding_id"]),
        ("ix_agent_enrollment_correlation", ["correlation_id"]),
    ):
        op.create_index(name, "agent_enrollment_tokens", cols)

    for table in ("agent_jobs", "report_jobs"):
        op.add_column(table, sa.Column("semantic_retry_count", sa.Integer(), nullable=False, server_default="0"))
        op.add_column(table, sa.Column("retry_classification", sa.String(48), nullable=True))
        op.add_column(table, sa.Column("terminal_reason", sa.String(160), nullable=True))
        op.add_column(table, sa.Column("priority", sa.Integer(), nullable=False, server_default="100"))
        op.create_check_constraint(f"ck_{table}_semantic_retry_nonnegative", table, "semantic_retry_count >= 0")
        op.create_check_constraint(f"ck_{table}_priority_range", table, "priority >= 0 AND priority <= 1000")

    op.add_column("agent_jobs", sa.Column("last_error_code", sa.String(80), nullable=True))
    op.add_column("report_jobs", sa.Column("delivery_count", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("report_jobs", sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=True))
    op.create_check_constraint("ck_report_jobs_delivery_nonnegative", "report_jobs", "delivery_count >= 0")
    op.create_index("ix_report_jobs_next_attempt_at", "report_jobs", ["next_attempt_at"])

    op.add_column("agent_bindings", sa.Column("protocol_compatibility_state", sa.String(32), nullable=False, server_default="COMPATIBLE"))
    op.add_column("agent_bindings", sa.Column("supported_job_types_json", sa.JSON(), nullable=False, server_default=sa.text("'[]'::json")))
    op.add_column("agent_bindings", sa.Column("supported_capabilities_json", sa.JSON(), nullable=False, server_default=sa.text("'[]'::json")))
    op.add_column("agent_bindings", sa.Column("enrolled_at", sa.DateTime(timezone=True), nullable=True))
    op.create_check_constraint(
        "ck_agent_bindings_protocol_compatibility",
        "agent_bindings",
        "protocol_compatibility_state IN ('COMPATIBLE','UPGRADE_REQUIRED','UNSUPPORTED')",
    )


def downgrade() -> None:
    op.drop_constraint("ck_agent_bindings_protocol_compatibility", "agent_bindings", type_="check")
    for name in ("enrolled_at","supported_capabilities_json","supported_job_types_json","protocol_compatibility_state"):
        op.drop_column("agent_bindings", name)

    op.drop_index("ix_report_jobs_next_attempt_at", table_name="report_jobs")
    op.drop_constraint("ck_report_jobs_delivery_nonnegative", "report_jobs", type_="check")
    op.drop_column("report_jobs", "next_attempt_at")
    op.drop_column("report_jobs", "delivery_count")
    op.drop_column("agent_jobs", "last_error_code")

    for table in ("report_jobs", "agent_jobs"):
        op.drop_constraint(f"ck_{table}_priority_range", table, type_="check")
        op.drop_constraint(f"ck_{table}_semantic_retry_nonnegative", table, type_="check")
        for name in ("priority","terminal_reason","retry_classification","semantic_retry_count"):
            op.drop_column(table, name)

    for name in (
        "ix_agent_enrollment_correlation","ix_agent_enrollment_binding","ix_agent_enrollment_expires",
        "ix_agent_enrollment_state","ix_agent_enrollment_participant","ix_agent_enrollment_organisation",
    ):
        op.drop_index(name, table_name="agent_enrollment_tokens")
    op.drop_table("agent_enrollment_tokens")
    op.drop_table("remote_rate_limit_state")
    for name in (
        "ix_worker_heartbeats_heartbeat","ix_worker_heartbeats_state",
        "ix_worker_heartbeats_instance","ix_worker_heartbeats_role",
    ):
        op.drop_index(name, table_name="worker_heartbeats")
    op.drop_table("worker_heartbeats")
    op.drop_index("uq_manual_review_active_fingerprint", table_name="manual_review_cases")
    for name in (
        "ix_manual_review_correlation","ix_manual_review_status","ix_manual_review_severity",
        "ix_manual_review_source_job","ix_manual_review_operation","ix_manual_review_reason",
        "ix_manual_review_domain","ix_manual_review_fingerprint",
        "ix_manual_review_participant","ix_manual_review_organisation",
    ):
        op.drop_index(name, table_name="manual_review_cases")
    op.drop_table("manual_review_cases")
