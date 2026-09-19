"""M14 fail-closed multi-tenant integration settings.

Revision ID: 0015_m14_integration_settings
Revises: 0014_m13_audit_history

Schema-only migration. It deliberately does not inspect environment credentials,
Windows certificate configuration, or plaintext runtime secrets.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0015_m14_integration_settings"
down_revision = "0014_m13_audit_history"
branch_labels = None
depends_on = None


AGENT_JOB_TYPES = (
    "CIS_CHECK","LK_RECEIPT","LP_RETURN","POLL_DOCUMENT","CIS_INFO","CIS_SEARCH",
    "CIS_HISTORY","CIS_AGGREGATED_LIST","CIS_AGGREGATION_HISTORY","PRODUCT_INFO",
    "CIS_TO_PRODUCT","PARTICIPANTS","MODS_LIST","TN_VED_SEARCH","PRODUCT_GTIN_LIST",
    "RD_LIST","DOCUMENT_LIST","DOCUMENT_INFO","DOCUMENT_CISES","LP_INTRODUCE_GOODS",
    "LK_INDI_COMMISSIONING","LP_GOODS_IMPORT","CROSSBORDER","LP_INTRODUCE_OST",
    "LK_CONTRACT_COMMISSIONING","LP_FTS_INTRODUCE","LK_REMARK","WRITE_OFF",
    "LK_RECEIPT_CANCEL","AGGREGATION_DOCUMENT","SETS_AGGREGATION",
    "REAGGREGATION_DOCUMENT","DISAGGREGATION_DOCUMENT","ATK_AGGREGATION",
    "ATK_TRANSFORMATION","ATK_DISAGGREGATION","EDO_PARTICIPANT","EDO_OUTGOING_LIST",
    "EDO_INCOMING_LIST","EDO_OUTGOING_CONTENT","EDO_INCOMING_CONTENT",
    "EDO_OUTGOING_PRINT","EDO_INCOMING_PRINT","EDO_OUTGOING_LEGAL_ZIP",
    "EDO_INCOMING_LEGAL_ZIP","EDO_OUTGOING_UNSIGNED_EVENTS",
    "EDO_INCOMING_UNSIGNED_EVENTS","EDO_EVENT_CONTENT","EDO_OUTGOING_RECEIPT",
    "EDO_INCOMING_RECEIPT","EDO_OUTGOING_MCHD","EDO_INCOMING_MCHD",
    "EDO_GIS_PROCESSING","REPORT_CREATE","REPORT_TASK_GET","REPORT_TASK_LIST",
    "REPORT_RESULTS","REPORT_DOWNLOAD","REPORT_QUOTA_TYPE","REPORT_QUOTA_ID",
    "INTEGRATION_HEALTH",
)


def _quoted(values: tuple[str, ...]) -> str:
    return ",".join("'" + value + "'" for value in values)


def _connection_columns(table: str, *, secret: bool) -> None:
    op.add_column(table, sa.Column("display_name", sa.String(200), nullable=True))
    op.add_column(table, sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.true()))
    op.add_column(table, sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True))
    if secret:
        op.add_column(table, sa.Column("active_secret_ref", sa.Text(), nullable=True))
        op.add_column(table, sa.Column("active_secret_version", sa.String(128), nullable=True))
        op.add_column(table, sa.Column("pending_secret_ref", sa.Text(), nullable=True))
        op.add_column(table, sa.Column("pending_secret_version", sa.String(128), nullable=True))
        op.add_column(table, sa.Column("secret_rotation_state", sa.String(32), nullable=False, server_default="NONE"))
        op.add_column(table, sa.Column("secret_configured_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column(table, sa.Column("last_check_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column(table, sa.Column("last_error_code", sa.String(80), nullable=True))
    op.add_column(table, sa.Column("health_metadata_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")))


def upgrade() -> None:
    op.create_table(
        "agent_bindings",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organisation_id", sa.String(36), sa.ForeignKey("organisations.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("participant_id", sa.String(36), nullable=False),
        sa.Column("installation_id", sa.String(36), nullable=False),
        sa.Column("display_name", sa.String(200), nullable=False),
        sa.Column("protocol_version", sa.String(32), nullable=False, server_default="m14-v1"),
        sa.Column("agent_version", sa.String(64), nullable=True),
        sa.Column("credential_hash", sa.String(64), nullable=False),
        sa.Column("credential_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("state", sa.String(16), nullable=False, server_default="PENDING"),
        sa.Column("is_primary", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_poll_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_true_api_auth_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("capabilities_sanitized", sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")),
        sa.Column("last_error_code", sa.String(80), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["participant_id","organisation_id"],
            ["participants.id","participants.organisation_id"],
            name="fk_agent_bindings_participant_organisation",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("credential_hash", name="uq_agent_bindings_credential_hash"),
        sa.UniqueConstraint("participant_id","installation_id", name="uq_agent_bindings_participant_installation"),
        sa.CheckConstraint("state IN ('PENDING','ACTIVE','DISABLED','ARCHIVED')", name="ck_agent_bindings_state"),
        sa.CheckConstraint("credential_version >= 1", name="ck_agent_bindings_credential_version"),
    )
    op.create_index("ix_agent_bindings_organisation_id", "agent_bindings", ["organisation_id"])
    op.create_index("ix_agent_bindings_participant_id", "agent_bindings", ["participant_id"])
    op.create_index("ix_agent_bindings_state", "agent_bindings", ["state"])
    op.create_index(
        "uq_agent_bindings_active_primary", "agent_bindings",
        ["organisation_id","participant_id"], unique=True,
        postgresql_where=sa.text("state='ACTIVE' AND is_primary"),
    )

    op.create_table(
        "agent_certificate_observations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("agent_binding_id", sa.String(36), sa.ForeignKey("agent_bindings.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("organisation_id", sa.String(36), sa.ForeignKey("organisations.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("participant_id", sa.String(36), nullable=False),
        sa.Column("thumbprint", sa.String(160), nullable=False),
        sa.Column("subject", sa.Text(), nullable=True),
        sa.Column("issuer", sa.Text(), nullable=True),
        sa.Column("certificate_inn", sa.String(12), nullable=True),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=True),
        sa.Column("valid_to", sa.DateTime(timezone=True), nullable=True),
        sa.Column("algorithm", sa.String(128), nullable=True),
        sa.Column("has_private_key", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("crypto_provider", sa.String(160), nullable=True),
        sa.Column("compatibility", sa.String(32), nullable=False, server_default="UNKNOWN"),
        sa.Column("key_usage_summary", sa.JSON(), nullable=False, server_default=sa.text("'[]'::json")),
        sa.Column("serial", sa.String(160), nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("readiness_state", sa.String(32), nullable=False),
        sa.Column("match_state", sa.String(32), nullable=False),
        sa.Column("expiry_state", sa.String(32), nullable=False),
        sa.Column("reason_code", sa.String(80), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(
            ["participant_id","organisation_id"],
            ["participants.id","participants.organisation_id"],
            name="fk_agent_cert_obs_participant_organisation",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint("readiness_state IN ('READY','NOT_READY','UNKNOWN')", name="ck_agent_cert_obs_readiness"),
        sa.CheckConstraint("match_state IN ('MATCH','MISMATCH','UNKNOWN')", name="ck_agent_cert_obs_match"),
        sa.CheckConstraint("expiry_state IN ('EXPIRED','EXPIRING_CRITICAL','EXPIRING_SOON','VALID','UNKNOWN')", name="ck_agent_cert_obs_expiry"),
    )
    op.create_index("ix_agent_cert_obs_binding", "agent_certificate_observations", ["agent_binding_id"])
    op.create_index("ix_agent_cert_obs_participant", "agent_certificate_observations", ["participant_id"])
    op.create_index("ix_agent_cert_obs_thumbprint", "agent_certificate_observations", ["thumbprint"])

    op.create_table(
        "true_api_connections",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organisation_id", sa.String(36), sa.ForeignKey("organisations.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("participant_id", sa.String(36), nullable=False),
        sa.Column("environment", sa.String(24), nullable=False, server_default="PRODUCTION"),
        sa.Column("state", sa.String(16), nullable=False, server_default="ENABLED"),
        sa.Column("primary_agent_binding_id", sa.String(36), sa.ForeignKey("agent_bindings.id", ondelete="RESTRICT"), nullable=True),
        sa.Column("desired_capabilities_json", sa.JSON(), nullable=False, server_default=sa.text("'[]'::json")),
        sa.Column("observed_capabilities_json", sa.JSON(), nullable=False, server_default=sa.text("'[]'::json")),
        sa.Column("desired_certificate_ref", sa.String(160), nullable=True),
        sa.Column("certificate_selection_state", sa.String(32), nullable=False, server_default="NONE"),
        sa.Column("observed_certificate_observation_id", sa.String(36), sa.ForeignKey("agent_certificate_observations.id", ondelete="SET NULL"), nullable=True),
        sa.Column("last_auth_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_check_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error_code", sa.String(80), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["participant_id","organisation_id"],
            ["participants.id","participants.organisation_id"],
            name="fk_true_api_connections_participant_organisation",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint("state IN ('ENABLED','DISABLED','ARCHIVED')", name="ck_true_api_connections_state"),
        sa.CheckConstraint("certificate_selection_state IN ('NONE','PENDING_LOCAL_APPLY','READY','MISMATCH')", name="ck_true_api_certificate_selection_state"),
    )
    op.create_index("ix_true_api_connections_organisation", "true_api_connections", ["organisation_id"])
    op.create_index("ix_true_api_connections_participant", "true_api_connections", ["participant_id"])
    op.create_index(
        "uq_true_api_connection_participant_live", "true_api_connections",
        ["organisation_id","participant_id"], unique=True,
        postgresql_where=sa.text("state <> 'ARCHIVED'"),
    )

    op.create_table(
        "integration_health_checks",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organisation_id", sa.String(36), sa.ForeignKey("organisations.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("participant_id", sa.String(36), nullable=False),
        sa.Column("integration_type", sa.String(32), nullable=False),
        sa.Column("connection_type", sa.String(32), nullable=False),
        sa.Column("connection_id", sa.String(64), nullable=True),
        sa.Column("agent_binding_id", sa.String(36), sa.ForeignKey("agent_bindings.id", ondelete="RESTRICT"), nullable=True),
        sa.Column("check_kind", sa.String(48), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("overall_status", sa.String(32), nullable=False),
        sa.Column("component_statuses_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")),
        sa.Column("capabilities_json", sa.JSON(), nullable=False, server_default=sa.text("'[]'::json")),
        sa.Column("latency_ms", sa.Integer(), nullable=True),
        sa.Column("remote_identity_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")),
        sa.Column("certificate_snapshot_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")),
        sa.Column("error_code", sa.String(80), nullable=True),
        sa.Column("redacted_message", sa.String(500), nullable=True),
        sa.Column("evidence_sha256", sa.String(64), nullable=True),
        sa.Column("requested_by_user_id", sa.BigInteger(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("correlation_id", sa.String(128), nullable=True),
        sa.Column("reused_from_check_id", sa.String(36), sa.ForeignKey("integration_health_checks.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(
            ["participant_id","organisation_id"],
            ["participants.id","participants.organisation_id"],
            name="fk_integration_health_participant_organisation",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint("overall_status IN ('CHECKING','READY','DEGRADED','ERROR','BLOCKED','NOT_TESTED')", name="ck_integration_health_overall_status"),
        sa.CheckConstraint("latency_ms IS NULL OR latency_ms >= 0", name="ck_integration_health_latency"),
    )
    for name, cols in (
        ("ix_integration_health_organisation", ["organisation_id"]),
        ("ix_integration_health_participant", ["participant_id"]),
        ("ix_integration_health_integration_type", ["integration_type"]),
        ("ix_integration_health_connection_id", ["connection_id"]),
        ("ix_integration_health_agent_binding", ["agent_binding_id"]),
        ("ix_integration_health_completed", ["completed_at"]),
        ("ix_integration_health_requested_by", ["requested_by_user_id"]),
        ("ix_integration_health_correlation", ["correlation_id"]),
    ):
        op.create_index(name, "integration_health_checks", cols)

    op.add_column("agent_jobs", sa.Column("agent_binding_id", sa.String(36), nullable=True))
    op.create_foreign_key(
        "fk_agent_jobs_agent_binding", "agent_jobs", "agent_bindings",
        ["agent_binding_id"], ["id"], ondelete="RESTRICT",
    )
    op.create_index("ix_agent_jobs_agent_binding_id", "agent_jobs", ["agent_binding_id"])
    op.drop_constraint("ck_agent_jobs_type", "agent_jobs", type_="check")
    op.create_check_constraint(
        "ck_agent_jobs_type", "agent_jobs",
        "job_type IN (" + _quoted(AGENT_JOB_TYPES) + ")",
    )

    _connection_columns("wb_connections", secret=True)
    _connection_columns("ozon_connections", secret=True)
    _connection_columns("suz_connections", secret=False)

    op.add_column("ozon_connections", sa.Column("environment", sa.String(24), nullable=False, server_default="PRODUCTION"))
    op.add_column("ozon_connections", sa.Column("local_validation_state", sa.String(32), nullable=False, server_default="NOT_VALIDATED"))
    op.add_column("ozon_connections", sa.Column("wire_readiness", sa.String(32), nullable=False, server_default="BLOCKED"))
    op.add_column("ozon_connections", sa.Column("blocker_code", sa.String(96), nullable=False, server_default="M10_EXECUTABLE_READ_CAPABILITIES_NONE"))
    op.create_index(
        "uq_ozon_active_participant_environment_client",
        "ozon_connections", ["participant_id","environment","client_id"],
        unique=True, postgresql_where=sa.text("archived_at IS NULL"),
    )

    op.add_column("suz_connections", sa.Column("local_config_state", sa.String(32), nullable=False, server_default="CONFIGURED"))
    op.add_column("suz_connections", sa.Column("wire_readiness", sa.String(32), nullable=False, server_default="BLOCKED"))
    op.add_column("suz_connections", sa.Column("blocker_code", sa.String(96), nullable=False, server_default="OFFICIAL_SUZ_PROGRAMMER_MANUAL_NOT_PINNED"))


def downgrade() -> None:
    op.drop_column("suz_connections", "blocker_code")
    op.drop_column("suz_connections", "wire_readiness")
    op.drop_column("suz_connections", "local_config_state")
    op.drop_index("uq_ozon_active_participant_environment_client", table_name="ozon_connections")
    op.drop_column("ozon_connections", "blocker_code")
    op.drop_column("ozon_connections", "wire_readiness")
    op.drop_column("ozon_connections", "local_validation_state")
    op.drop_column("ozon_connections", "environment")

    for table, secret in (("suz_connections", False), ("ozon_connections", True), ("wb_connections", True)):
        for name in ("health_metadata_json","last_error_code","last_check_at"):
            op.drop_column(table, name)
        if secret:
            for name in ("secret_configured_at","secret_rotation_state","pending_secret_version","pending_secret_ref","active_secret_version","active_secret_ref"):
                op.drop_column(table, name)
        op.drop_column(table, "archived_at")
        op.drop_column(table, "is_enabled")
        op.drop_column(table, "display_name")

    op.drop_constraint("ck_agent_jobs_type", "agent_jobs", type_="check")
    # Downgrade cannot safely re-introduce a historical type list if M14 health
    # rows remain. Delete only M14 control-plane jobs; business jobs are untouched.
    op.execute("DELETE FROM agent_jobs WHERE job_type='INTEGRATION_HEALTH'")
    op.create_check_constraint(
        "ck_agent_jobs_type", "agent_jobs",
        "job_type IN (" + _quoted(tuple(x for x in AGENT_JOB_TYPES if x != "INTEGRATION_HEALTH")) + ")",
    )
    op.drop_index("ix_agent_jobs_agent_binding_id", table_name="agent_jobs")
    op.drop_constraint("fk_agent_jobs_agent_binding", "agent_jobs", type_="foreignkey")
    op.drop_column("agent_jobs", "agent_binding_id")

    for name in (
        "ix_integration_health_correlation","ix_integration_health_requested_by",
        "ix_integration_health_completed","ix_integration_health_agent_binding",
        "ix_integration_health_connection_id","ix_integration_health_integration_type",
        "ix_integration_health_participant","ix_integration_health_organisation",
    ):
        op.drop_index(name, table_name="integration_health_checks")
    op.drop_table("integration_health_checks")
    op.drop_index("uq_true_api_connection_participant_live", table_name="true_api_connections")
    op.drop_index("ix_true_api_connections_participant", table_name="true_api_connections")
    op.drop_index("ix_true_api_connections_organisation", table_name="true_api_connections")
    op.drop_table("true_api_connections")
    op.drop_index("ix_agent_cert_obs_thumbprint", table_name="agent_certificate_observations")
    op.drop_index("ix_agent_cert_obs_participant", table_name="agent_certificate_observations")
    op.drop_index("ix_agent_cert_obs_binding", table_name="agent_certificate_observations")
    op.drop_table("agent_certificate_observations")
    op.drop_index("uq_agent_bindings_active_primary", table_name="agent_bindings")
    op.drop_index("ix_agent_bindings_state", table_name="agent_bindings")
    op.drop_index("ix_agent_bindings_participant_id", table_name="agent_bindings")
    op.drop_index("ix_agent_bindings_organisation_id", table_name="agent_bindings")
    op.drop_table("agent_bindings")
