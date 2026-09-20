"""Printer discovery and allowlisted profile foundation.

Revision ID: 0019_printing_printer_profiles
Revises: 0018_printing_sensitive_delivery

Phase B only. Stores sanitized typed printer observations/profile evidence.
No exact queue/server/share/port path, raw DEVMODE, arbitrary printer commands,
FULL KM, GDI/spool submission state, or physical-print completion state.
"""

from alembic import op
import sqlalchemy as sa


revision = "0019_printing_printer_profiles"
down_revision = "0018_printing_sensitive_delivery"
branch_labels = None
depends_on = None


_OLD_AGENT_TYPES = (
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
_NEW_AGENT_TYPES = _OLD_AGENT_TYPES + ("PRINTER_DISCOVERY",)


def _in(values: tuple[str, ...]) -> str:
    return ",".join(repr(value) for value in values)


def upgrade() -> None:
    op.drop_constraint("ck_agent_jobs_type", "agent_jobs", type_="check")
    op.create_check_constraint(
        "ck_agent_jobs_type", "agent_jobs", "job_type IN (" + _in(_NEW_AGENT_TYPES) + ")"
    )

    op.create_table(
        "printer_discovery_runs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organisation_id", sa.String(36), sa.ForeignKey("organisations.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("participant_id", sa.String(36), nullable=False),
        sa.Column("agent_binding_id", sa.String(36), nullable=False),
        sa.Column("agent_job_id", sa.String(128), sa.ForeignKey("agent_jobs.job_id", ondelete="SET NULL"), nullable=True, unique=True),
        sa.Column("state", sa.String(16), nullable=False, server_default="PENDING"),
        sa.Column("requested_by_user_id", sa.BigInteger(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("printer_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("safe_error_code", sa.String(80), nullable=True),
        sa.Column("correlation_id", sa.String(128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(
            ["participant_id","organisation_id"],
            ["participants.id","participants.organisation_id"],
            name="fk_printer_discovery_run_participant_organisation",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["agent_binding_id","organisation_id","participant_id"],
            ["agent_bindings.id","agent_bindings.organisation_id","agent_bindings.participant_id"],
            name="fk_printer_discovery_run_binding_tenant",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("id","organisation_id","participant_id",name="uq_printer_discovery_run_id_tenant"),
        sa.CheckConstraint("state IN ('PENDING','RUNNING','COMPLETED','FAILED')",name="ck_printer_discovery_run_state"),
        sa.CheckConstraint("printer_count >= 0",name="ck_printer_discovery_run_count"),
    )
    for name, columns in (
        ("ix_printer_discovery_run_organisation",["organisation_id"]),
        ("ix_printer_discovery_run_participant",["participant_id"]),
        ("ix_printer_discovery_run_binding",["agent_binding_id"]),
        ("ix_printer_discovery_run_state",["state"]),
        ("ix_printer_discovery_run_correlation",["correlation_id"]),
    ):
        op.create_index(name, "printer_discovery_runs", columns)

    op.create_table(
        "printer_discovery_observations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organisation_id", sa.String(36), sa.ForeignKey("organisations.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("participant_id", sa.String(36), nullable=False),
        sa.Column("agent_binding_id", sa.String(36), nullable=False),
        sa.Column("discovery_run_id", sa.String(36), nullable=False),
        sa.Column("agent_printer_id", sa.String(160), nullable=False),
        sa.Column("local_printer_fingerprint", sa.String(64), nullable=False),
        sa.Column("display_name_sanitized", sa.String(160), nullable=False),
        sa.Column("driver_name_sanitized", sa.String(160), nullable=True),
        sa.Column("dpi_x", sa.Integer(), nullable=False),
        sa.Column("dpi_y", sa.Integer(), nullable=False),
        sa.Column("media_width_mm", sa.Numeric(10,4), nullable=False),
        sa.Column("media_height_mm", sa.Numeric(10,4), nullable=False),
        sa.Column("orientation", sa.String(16), nullable=False),
        sa.Column("physical_width_px", sa.Integer(), nullable=False),
        sa.Column("physical_height_px", sa.Integer(), nullable=False),
        sa.Column("printable_width_px", sa.Integer(), nullable=False),
        sa.Column("printable_height_px", sa.Integer(), nullable=False),
        sa.Column("offset_x_px", sa.Integer(), nullable=False),
        sa.Column("offset_y_px", sa.Integer(), nullable=False),
        sa.Column("capability_hash", sa.String(64), nullable=False),
        sa.Column("availability_state", sa.String(16), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("safe_error_code", sa.String(80), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(
            ["participant_id","organisation_id"],
            ["participants.id","participants.organisation_id"],
            name="fk_printer_observation_participant_organisation",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["agent_binding_id","organisation_id","participant_id"],
            ["agent_bindings.id","agent_bindings.organisation_id","agent_bindings.participant_id"],
            name="fk_printer_observation_binding_tenant",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["discovery_run_id","organisation_id","participant_id"],
            ["printer_discovery_runs.id","printer_discovery_runs.organisation_id","printer_discovery_runs.participant_id"],
            name="fk_printer_observation_run_tenant",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("discovery_run_id","agent_printer_id",name="uq_printer_observation_run_agent_printer"),
        sa.UniqueConstraint("id","organisation_id","participant_id",name="uq_printer_observation_id_tenant"),
        sa.CheckConstraint("orientation IN ('PORTRAIT','LANDSCAPE')",name="ck_printer_observation_orientation"),
        sa.CheckConstraint("availability_state IN ('AVAILABLE','UNAVAILABLE','ERROR')",name="ck_printer_observation_availability"),
        sa.CheckConstraint(
            "dpi_x >= 0 AND dpi_y >= 0 AND physical_width_px >= 0 AND physical_height_px >= 0 "
            "AND printable_width_px >= 0 AND printable_height_px >= 0 "
            "AND offset_x_px >= 0 AND offset_y_px >= 0",
            name="ck_printer_observation_geometry_nonnegative",
        ),
    )
    for name, columns in (
        ("ix_printer_observation_organisation",["organisation_id"]),
        ("ix_printer_observation_participant",["participant_id"]),
        ("ix_printer_observation_binding",["agent_binding_id"]),
        ("ix_printer_observation_run",["discovery_run_id"]),
        ("ix_printer_observation_agent_printer",["agent_printer_id"]),
    ):
        op.create_index(name, "printer_discovery_observations", columns)

    op.create_table(
        "printer_profiles",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organisation_id", sa.String(36), sa.ForeignKey("organisations.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("participant_id", sa.String(36), nullable=False),
        sa.Column("agent_binding_id", sa.String(36), nullable=False),
        sa.Column("agent_printer_id", sa.String(160), nullable=False),
        sa.Column("local_printer_fingerprint", sa.String(64), nullable=False),
        sa.Column("display_name_sanitized", sa.String(160), nullable=False),
        sa.Column("driver_name_sanitized", sa.String(160), nullable=True),
        sa.Column("dpi_x", sa.Integer(), nullable=False),
        sa.Column("dpi_y", sa.Integer(), nullable=False),
        sa.Column("media_width_mm", sa.Numeric(10,4), nullable=False),
        sa.Column("media_height_mm", sa.Numeric(10,4), nullable=False),
        sa.Column("orientation", sa.String(16), nullable=False),
        sa.Column("physical_width_px", sa.Integer(), nullable=False),
        sa.Column("physical_height_px", sa.Integer(), nullable=False),
        sa.Column("printable_width_px", sa.Integer(), nullable=False),
        sa.Column("printable_height_px", sa.Integer(), nullable=False),
        sa.Column("offset_x_px", sa.Integer(), nullable=False),
        sa.Column("offset_y_px", sa.Integer(), nullable=False),
        sa.Column("capability_hash", sa.String(64), nullable=False),
        sa.Column("capability_revision", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("state", sa.String(16), nullable=False, server_default="ACTIVE"),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("created_by_user_id", sa.BigInteger(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.ForeignKeyConstraint(
            ["participant_id","organisation_id"],
            ["participants.id","participants.organisation_id"],
            name="fk_printer_profile_participant_organisation",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["agent_binding_id","organisation_id","participant_id"],
            ["agent_bindings.id","agent_bindings.organisation_id","agent_bindings.participant_id"],
            name="fk_printer_profile_binding_tenant",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("agent_binding_id","agent_printer_id",name="uq_printer_profile_binding_agent_printer"),
        sa.UniqueConstraint("id","organisation_id","participant_id",name="uq_printer_profile_id_tenant"),
        sa.CheckConstraint("state IN ('ACTIVE','STALE','MISSING','INCOMPATIBLE','DISABLED')",name="ck_printer_profile_state"),
        sa.CheckConstraint("orientation IN ('PORTRAIT','LANDSCAPE')",name="ck_printer_profile_orientation"),
        sa.CheckConstraint("capability_revision >= 1",name="ck_printer_profile_revision"),
        sa.CheckConstraint(
            "dpi_x >= 0 AND dpi_y >= 0 AND physical_width_px >= 0 AND physical_height_px >= 0 "
            "AND printable_width_px >= 0 AND printable_height_px >= 0 "
            "AND offset_x_px >= 0 AND offset_y_px >= 0",
            name="ck_printer_profile_geometry_nonnegative",
        ),
    )
    for name, columns in (
        ("ix_printer_profile_organisation",["organisation_id"]),
        ("ix_printer_profile_participant",["participant_id"]),
        ("ix_printer_profile_binding",["agent_binding_id"]),
        ("ix_printer_profile_state",["state"]),
    ):
        op.create_index(name, "printer_profiles", columns)


def downgrade() -> None:
    for name in (
        "ix_printer_profile_state","ix_printer_profile_binding",
        "ix_printer_profile_participant","ix_printer_profile_organisation",
    ):
        op.drop_index(name, table_name="printer_profiles")
    op.drop_table("printer_profiles")

    for name in (
        "ix_printer_observation_agent_printer","ix_printer_observation_run",
        "ix_printer_observation_binding","ix_printer_observation_participant",
        "ix_printer_observation_organisation",
    ):
        op.drop_index(name, table_name="printer_discovery_observations")
    op.drop_table("printer_discovery_observations")

    for name in (
        "ix_printer_discovery_run_correlation","ix_printer_discovery_run_state",
        "ix_printer_discovery_run_binding","ix_printer_discovery_run_participant",
        "ix_printer_discovery_run_organisation",
    ):
        op.drop_index(name, table_name="printer_discovery_runs")
    op.drop_table("printer_discovery_runs")

    op.drop_constraint("ck_agent_jobs_type", "agent_jobs", type_="check")
    op.create_check_constraint(
        "ck_agent_jobs_type", "agent_jobs", "job_type IN (" + _in(_OLD_AGENT_TYPES) + ")"
    )
