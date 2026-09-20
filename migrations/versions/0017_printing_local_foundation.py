"""Local printing/DataMatrix foundation.

Revision ID: 0017_printing_local_foundation
Revises: 0016_m15_production_hardening

Local-only additive schema. It stores no plaintext FULL KM and adds no
production SUZ/True API/printer wire capability.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0017_printing_local_foundation"
down_revision = "0016_m15_production_hardening"
branch_labels = None
depends_on = None


def _tenant_fk(name: str, table: str) -> None:
    op.create_foreign_key(
        name, table, "participants",
        ["participant_id", "organisation_id"],
        ["id", "organisation_id"],
        ondelete="RESTRICT",
    )


def upgrade() -> None:
    op.create_table(
        "stored_full_km_items",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organisation_id", sa.String(36), sa.ForeignKey("organisations.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("participant_id", sa.String(36), nullable=False),
        sa.Column("suz_order_id", sa.BigInteger(), sa.ForeignKey("suz_orders.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("suz_order_item_id", sa.BigInteger(), sa.ForeignKey("suz_order_items.id", ondelete="RESTRICT"), nullable=True),
        sa.Column("suz_code_block_id", sa.BigInteger(), sa.ForeignKey("suz_code_blocks.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("vault_entry_id", sa.BigInteger(), sa.ForeignKey("suz_km_vault.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("gtin", sa.Text(), nullable=False),
        sa.Column("cis_hmac", sa.String(64), nullable=False),
        sa.Column("vault_item_ordinal", sa.Integer(), nullable=False),
        sa.Column("vault_item_offset", sa.Integer(), nullable=False),
        sa.Column("vault_item_length", sa.Integer(), nullable=False),
        sa.Column("full_km_sha256", sa.String(64), nullable=False),
        sa.Column("provenance_state", sa.String(16), nullable=False),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("organisation_id", "participant_id", "cis_hmac", name="uq_stored_full_km_tenant_cis_hmac"),
        sa.UniqueConstraint("vault_entry_id", "vault_item_ordinal", name="uq_stored_full_km_vault_ordinal"),
        sa.CheckConstraint("vault_item_ordinal >= 0", name="ck_stored_full_km_ordinal"),
        sa.CheckConstraint("vault_item_offset >= 0", name="ck_stored_full_km_offset"),
        sa.CheckConstraint("vault_item_length > 0", name="ck_stored_full_km_length"),
        sa.CheckConstraint("provenance_state IN ('PROVEN','CONFLICT','UNKNOWN')", name="ck_stored_full_km_provenance"),
        sa.CheckConstraint(
            "source IN ('INITIAL_SUZ_FETCH','REPEAT_SUZ_FETCH','MIGRATED_TRUSTED_SOURCE')",
            name="ck_stored_full_km_source",
        ),
        sa.ForeignKeyConstraint(
            ["participant_id", "organisation_id"], ["participants.id", "participants.organisation_id"],
            name="fk_stored_full_km_participant_organisation", ondelete="RESTRICT",
        ),
    )
    for name, cols in (
        ("ix_stored_full_km_organisation", ["organisation_id"]),
        ("ix_stored_full_km_participant", ["participant_id"]),
        ("ix_stored_full_km_order", ["suz_order_id"]),
        ("ix_stored_full_km_block", ["suz_code_block_id"]),
        ("ix_stored_full_km_vault", ["vault_entry_id"]),
        ("ix_stored_full_km_gtin", ["gtin"]),
        ("ix_stored_full_km_cis_hmac", ["cis_hmac"]),
    ):
        op.create_index(name, "stored_full_km_items", cols)

    op.create_table(
        "print_templates",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organisation_id", sa.String(36), sa.ForeignKey("organisations.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("participant_id", sa.String(36), nullable=True),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("state", sa.String(16), nullable=False, server_default="ACTIVE"),
        sa.Column("current_version_id", sa.String(36), nullable=True),
        sa.Column("created_by_user_id", sa.BigInteger(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["participant_id", "organisation_id"], ["participants.id", "participants.organisation_id"],
            name="fk_print_template_participant_organisation", ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("organisation_id", "participant_id", "name", name="uq_print_template_tenant_name"),
        sa.CheckConstraint("state IN ('ACTIVE','ARCHIVED')", name="ck_print_template_state"),
    )
    op.create_index("ix_print_template_organisation", "print_templates", ["organisation_id"])
    op.create_index("ix_print_template_participant", "print_templates", ["participant_id"])

    op.create_table(
        "print_template_versions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("template_id", sa.String(36), sa.ForeignKey("print_templates.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("organisation_id", sa.String(36), sa.ForeignKey("organisations.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("participant_id", sa.String(36), nullable=True),
        sa.Column("version_number", sa.Integer(), nullable=False),
        sa.Column("schema_version", sa.String(24), nullable=False),
        sa.Column("label_width_mm", sa.Numeric(7,3), nullable=False),
        sa.Column("label_height_mm", sa.Numeric(7,3), nullable=False),
        sa.Column("layout_json", sa.JSON(), nullable=False),
        sa.Column("layout_sha256", sa.String(64), nullable=False),
        sa.Column("created_by_user_id", sa.BigInteger(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(
            ["participant_id", "organisation_id"], ["participants.id", "participants.organisation_id"],
            name="fk_print_template_version_participant_organisation", ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("template_id", "version_number", name="uq_print_template_version_number"),
        sa.UniqueConstraint("id", "organisation_id", "participant_id", name="uq_print_template_version_tenant"),
        sa.CheckConstraint("version_number >= 1", name="ck_print_template_version_number"),
        sa.CheckConstraint("label_width_mm >= 10 AND label_width_mm <= 300", name="ck_print_template_width"),
        sa.CheckConstraint("label_height_mm >= 10 AND label_height_mm <= 300", name="ck_print_template_height"),
    )
    op.create_index("ix_print_template_version_template", "print_template_versions", ["template_id"])
    op.create_index("ix_print_template_version_organisation", "print_template_versions", ["organisation_id"])
    op.create_index("ix_print_template_version_participant", "print_template_versions", ["participant_id"])
    op.create_foreign_key(
        "fk_print_template_current_version", "print_templates", "print_template_versions",
        ["current_version_id"], ["id"], ondelete="RESTRICT",
    )

    op.create_table(
        "print_jobs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organisation_id", sa.String(36), sa.ForeignKey("organisations.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("participant_id", sa.String(36), nullable=False),
        sa.Column("template_version_id", sa.String(36), sa.ForeignKey("print_template_versions.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("mode", sa.String(40), nullable=False),
        sa.Column("requested_by_user_id", sa.BigInteger(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("state", sa.String(24), nullable=False, server_default="PENDING"),
        sa.Column("item_count", sa.Integer(), nullable=False),
        sa.Column("output_kind", sa.String(24), nullable=False, server_default="WINDOWS_AGENT"),
        sa.Column("printer_profile_id", sa.String(128), nullable=True),
        sa.Column("printer_profile_fingerprint", sa.String(64), nullable=True),
        sa.Column("metadata_sanitized_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")),
        sa.Column("correlation_id", sa.String(128), nullable=True),
        sa.Column("original_print_event_id", sa.String(36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(
            ["participant_id", "organisation_id"], ["participants.id", "participants.organisation_id"],
            name="fk_print_job_participant_organisation", ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "mode IN ('INITIAL_PRINT','REPRINT_ORIGINAL_TEMPLATE','PRINT_USING_CURRENT_TEMPLATE')",
            name="ck_print_job_mode",
        ),
        sa.CheckConstraint(
            "state IN ('PENDING','READY_FOR_AGENT','COMPLETED','FAILED','BLOCKED')",
            name="ck_print_job_state",
        ),
        sa.CheckConstraint("item_count > 0 AND item_count <= 1000", name="ck_print_job_item_count"),
        sa.CheckConstraint("output_kind IN ('WINDOWS_AGENT','SYNTHETIC_PREVIEW')", name="ck_print_job_output_kind"),
    )
    for name, cols in (
        ("ix_print_job_organisation", ["organisation_id"]),
        ("ix_print_job_participant", ["participant_id"]),
        ("ix_print_job_template_version", ["template_version_id"]),
        ("ix_print_job_state", ["state"]),
        ("ix_print_job_requested_at", ["requested_at"]),
    ):
        op.create_index(name, "print_jobs", cols)

    op.create_table(
        "print_job_items",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("print_job_id", sa.String(36), sa.ForeignKey("print_jobs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("organisation_id", sa.String(36), sa.ForeignKey("organisations.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("participant_id", sa.String(36), nullable=False),
        sa.Column("stored_full_km_item_id", sa.String(36), sa.ForeignKey("stored_full_km_items.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("ordinal", sa.Integer(), nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.Column("state", sa.String(24), nullable=False, server_default="PENDING"),
        sa.Column("error_code", sa.String(96), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(
            ["participant_id", "organisation_id"], ["participants.id", "participants.organisation_id"],
            name="fk_print_job_item_participant_organisation", ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("print_job_id", "ordinal", name="uq_print_job_item_ordinal"),
        sa.UniqueConstraint("print_job_id", "stored_full_km_item_id", name="uq_print_job_stored_km"),
        sa.CheckConstraint("ordinal >= 0", name="ck_print_job_item_ordinal"),
        sa.CheckConstraint("state IN ('PENDING','RENDERED','COMPLETED','FAILED','BLOCKED')", name="ck_print_job_item_state"),
    )
    for name, cols in (
        ("ix_print_job_item_job", ["print_job_id"]),
        ("ix_print_job_item_organisation", ["organisation_id"]),
        ("ix_print_job_item_participant", ["participant_id"]),
        ("ix_print_job_item_stored", ["stored_full_km_item_id"]),
    ):
        op.create_index(name, "print_job_items", cols)

    op.create_table(
        "print_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organisation_id", sa.String(36), sa.ForeignKey("organisations.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("participant_id", sa.String(36), nullable=False),
        sa.Column("print_job_id", sa.String(36), sa.ForeignKey("print_jobs.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("print_job_item_id", sa.String(36), sa.ForeignKey("print_job_items.id", ondelete="RESTRICT"), nullable=True),
        sa.Column("stored_full_km_item_id", sa.String(36), sa.ForeignKey("stored_full_km_items.id", ondelete="RESTRICT"), nullable=True),
        sa.Column("template_version_id", sa.String(36), sa.ForeignKey("print_template_versions.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=True),
        sa.Column("actor_kind", sa.String(24), nullable=False),
        sa.Column("actor_user_id", sa.BigInteger(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("printer_profile_fingerprint", sa.String(64), nullable=True),
        sa.Column("event_type", sa.String(40), nullable=False),
        sa.Column("outcome", sa.String(16), nullable=False),
        sa.Column("error_code", sa.String(96), nullable=True),
        sa.Column("original_print_event_id", sa.String(36), sa.ForeignKey("print_events.id", ondelete="RESTRICT"), nullable=True),
        sa.Column("evidence_sha256", sa.String(64), nullable=True),
        sa.Column("metadata_sanitized_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(
            ["participant_id", "organisation_id"], ["participants.id", "participants.organisation_id"],
            name="fk_print_event_participant_organisation", ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "event_type IN ('PRINT_JOB_REQUESTED','PRINT_JOB_COMPLETED','PRINT_JOB_FAILED','REPRINT_REQUESTED','REPRINT_COMPLETED','REPRINT_FAILED')",
            name="ck_print_event_type",
        ),
        sa.CheckConstraint("outcome IN ('PENDING','SUCCESS','FAILED','BLOCKED')", name="ck_print_event_outcome"),
    )
    for name, cols in (
        ("ix_print_event_organisation", ["organisation_id"]),
        ("ix_print_event_participant", ["participant_id"]),
        ("ix_print_event_job", ["print_job_id"]),
        ("ix_print_event_created_at", ["created_at"]),
    ):
        op.create_index(name, "print_events", cols)

    op.create_foreign_key(
        "fk_print_job_original_event", "print_jobs", "print_events",
        ["original_print_event_id"], ["id"], ondelete="RESTRICT",
    )

    # M13 append-only audit registry extension for printing events.
    op.drop_constraint("ck_audit_event_category", "audit_events", type_="check")
    op.drop_constraint("ck_audit_event_subject_type", "audit_events", type_="check")
    op.drop_constraint("ck_audit_event_secondary_subject_type", "audit_events", type_="check")
    op.create_check_constraint("ck_audit_event_category", "audit_events", "category IN ('SECURITY','AUTHORIZATION','TENANT_ADMIN','INTEGRATION','IMPORT','CONTROL','CIS_READ','REFERENCE_READ','DOCUMENT','TURNOVER','AGGREGATION','EDO','SUZ','WB','OZON','REPORT','AGENT','PRINTING','SYSTEM')")
    op.create_check_constraint("ck_audit_event_subject_type", "audit_events", "subject_type IN ('USER','SESSION','MEMBERSHIP','INVITATION','ORGANISATION','PARTICIPANT','IMPORT','EVENT','CONTROL_RUN','AGENT_JOB','WRITE_OPERATION','DOCUMENT_OPERATION','TURNOVER_OPERATION','AGGREGATION_OPERATION','EDO_OBJECT','SUZ_CONNECTION','SUZ_ORDER','WB_CONNECTION','WB_OBJECT','OZON_CONNECTION','OZON_OBJECT','REPORT_JOB','REPORT_ARTIFACT','INTEGRATION_CONNECTION','MARKING_IDENTIFIER','PRINT_TEMPLATE','PRINT_JOB','PRINT_EVENT','AUDIT_CHAIN','AUDIT_CHECKPOINT')")
    op.create_check_constraint(
        "ck_audit_event_secondary_subject_type", "audit_events",
        "secondary_subject_type IS NULL OR secondary_subject_type IN ('USER','SESSION','MEMBERSHIP','INVITATION','ORGANISATION','PARTICIPANT','IMPORT','EVENT','CONTROL_RUN','AGENT_JOB','WRITE_OPERATION','DOCUMENT_OPERATION','TURNOVER_OPERATION','AGGREGATION_OPERATION','EDO_OBJECT','SUZ_CONNECTION','SUZ_ORDER','WB_CONNECTION','WB_OBJECT','OZON_CONNECTION','OZON_OBJECT','REPORT_JOB','REPORT_ARTIFACT','INTEGRATION_CONNECTION','MARKING_IDENTIFIER','PRINT_TEMPLATE','PRINT_JOB','PRINT_EVENT','AUDIT_CHAIN','AUDIT_CHECKPOINT')",
    )

    op.execute("""
    CREATE FUNCTION wbcz_printing_immutable_guard() RETURNS trigger AS $guard$
    BEGIN
      RAISE EXCEPTION 'printing immutable history cannot be updated or deleted';
    END;
    $guard$ LANGUAGE plpgsql
    """)
    op.execute("""
    CREATE TRIGGER trg_print_template_versions_immutable
    BEFORE UPDATE OR DELETE ON print_template_versions
    FOR EACH ROW EXECUTE FUNCTION wbcz_printing_immutable_guard()
    """)
    op.execute("""
    CREATE TRIGGER trg_print_events_append_only
    BEFORE UPDATE OR DELETE ON print_events
    FOR EACH ROW EXECUTE FUNCTION wbcz_printing_immutable_guard()
    """)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS trg_print_events_append_only ON print_events")
    op.execute("DROP TRIGGER IF EXISTS trg_print_template_versions_immutable ON print_template_versions")
    op.execute("DROP FUNCTION IF EXISTS wbcz_printing_immutable_guard()")
    op.drop_constraint("ck_audit_event_category", "audit_events", type_="check")
    op.drop_constraint("ck_audit_event_subject_type", "audit_events", type_="check")
    op.drop_constraint("ck_audit_event_secondary_subject_type", "audit_events", type_="check")
    op.create_check_constraint("ck_audit_event_category", "audit_events", "category IN ('SECURITY','AUTHORIZATION','TENANT_ADMIN','INTEGRATION','IMPORT','CONTROL','CIS_READ','REFERENCE_READ','DOCUMENT','TURNOVER','AGGREGATION','EDO','SUZ','WB','OZON','REPORT','AGENT','SYSTEM')")
    op.create_check_constraint("ck_audit_event_subject_type", "audit_events", "subject_type IN ('USER','SESSION','MEMBERSHIP','INVITATION','ORGANISATION','PARTICIPANT','IMPORT','EVENT','CONTROL_RUN','AGENT_JOB','WRITE_OPERATION','DOCUMENT_OPERATION','TURNOVER_OPERATION','AGGREGATION_OPERATION','EDO_OBJECT','SUZ_CONNECTION','SUZ_ORDER','WB_CONNECTION','WB_OBJECT','OZON_CONNECTION','OZON_OBJECT','REPORT_JOB','REPORT_ARTIFACT','INTEGRATION_CONNECTION','MARKING_IDENTIFIER','AUDIT_CHAIN','AUDIT_CHECKPOINT')")
    op.create_check_constraint(
        "ck_audit_event_secondary_subject_type", "audit_events",
        "secondary_subject_type IS NULL OR secondary_subject_type IN ('USER','SESSION','MEMBERSHIP','INVITATION','ORGANISATION','PARTICIPANT','IMPORT','EVENT','CONTROL_RUN','AGENT_JOB','WRITE_OPERATION','DOCUMENT_OPERATION','TURNOVER_OPERATION','AGGREGATION_OPERATION','EDO_OBJECT','SUZ_CONNECTION','SUZ_ORDER','WB_CONNECTION','WB_OBJECT','OZON_CONNECTION','OZON_OBJECT','REPORT_JOB','REPORT_ARTIFACT','INTEGRATION_CONNECTION','MARKING_IDENTIFIER','AUDIT_CHAIN','AUDIT_CHECKPOINT')",
    )
    op.drop_constraint("fk_print_job_original_event", "print_jobs", type_="foreignkey")
    for name in ("ix_print_event_created_at","ix_print_event_job","ix_print_event_participant","ix_print_event_organisation"):
        op.drop_index(name, table_name="print_events")
    op.drop_table("print_events")
    for name in ("ix_print_job_item_stored","ix_print_job_item_participant","ix_print_job_item_organisation","ix_print_job_item_job"):
        op.drop_index(name, table_name="print_job_items")
    op.drop_table("print_job_items")
    for name in ("ix_print_job_requested_at","ix_print_job_state","ix_print_job_template_version","ix_print_job_participant","ix_print_job_organisation"):
        op.drop_index(name, table_name="print_jobs")
    op.drop_table("print_jobs")
    op.drop_constraint("fk_print_template_current_version", "print_templates", type_="foreignkey")
    for name in ("ix_print_template_version_participant","ix_print_template_version_organisation","ix_print_template_version_template"):
        op.drop_index(name, table_name="print_template_versions")
    op.drop_table("print_template_versions")
    for name in ("ix_print_template_participant","ix_print_template_organisation"):
        op.drop_index(name, table_name="print_templates")
    op.drop_table("print_templates")
    for name in (
        "ix_stored_full_km_cis_hmac","ix_stored_full_km_gtin","ix_stored_full_km_vault",
        "ix_stored_full_km_block","ix_stored_full_km_order","ix_stored_full_km_participant",
        "ix_stored_full_km_organisation",
    ):
        op.drop_index(name, table_name="stored_full_km_items")
    op.drop_table("stored_full_km_items")
