from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0008_m7_edo_lite_foundation"
down_revision = "0007_m6_aggregation"
branch_labels = None
depends_on = None

_PREVIOUS_TYPES = (
    "CIS_CHECK","LK_RECEIPT","LP_RETURN","POLL_DOCUMENT","CIS_INFO","CIS_SEARCH",
    "CIS_HISTORY","CIS_AGGREGATED_LIST","CIS_AGGREGATION_HISTORY","PRODUCT_INFO",
    "CIS_TO_PRODUCT","PARTICIPANTS","MODS_LIST","TN_VED_SEARCH","PRODUCT_GTIN_LIST",
    "RD_LIST","DOCUMENT_LIST","DOCUMENT_INFO","DOCUMENT_CISES",
    "LP_INTRODUCE_GOODS","LK_INDI_COMMISSIONING","LP_GOODS_IMPORT","CROSSBORDER",
    "LP_INTRODUCE_OST","LK_CONTRACT_COMMISSIONING","LP_FTS_INTRODUCE","LK_REMARK",
    "WRITE_OFF","LK_RECEIPT_CANCEL",
    "AGGREGATION_DOCUMENT","SETS_AGGREGATION","REAGGREGATION_DOCUMENT",
    "DISAGGREGATION_DOCUMENT","ATK_AGGREGATION","ATK_TRANSFORMATION","ATK_DISAGGREGATION",
)
_M7_READ_TYPES = (
    "EDO_PARTICIPANT","EDO_OUTGOING_LIST","EDO_INCOMING_LIST",
    "EDO_OUTGOING_CONTENT","EDO_INCOMING_CONTENT",
    "EDO_OUTGOING_PRINT","EDO_INCOMING_PRINT",
    "EDO_OUTGOING_LEGAL_ZIP","EDO_INCOMING_LEGAL_ZIP",
    "EDO_OUTGOING_UNSIGNED_EVENTS","EDO_INCOMING_UNSIGNED_EVENTS",
    "EDO_EVENT_CONTENT","EDO_OUTGOING_RECEIPT","EDO_INCOMING_RECEIPT",
    "EDO_OUTGOING_MCHD","EDO_INCOMING_MCHD","EDO_GIS_PROCESSING",
)


def _check(values: tuple[str, ...]) -> str:
    return "job_type IN (" + ",".join(repr(value) for value in values) + ")"


def upgrade() -> None:
    op.drop_constraint("ck_agent_jobs_type", "agent_jobs", type_="check")
    op.create_check_constraint("ck_agent_jobs_type", "agent_jobs", _check(_PREVIOUS_TYPES + _M7_READ_TYPES))

    op.create_table(
        "edo_lite_ledger",
        sa.Column("operation_id", sa.String(length=128), primary_key=True, nullable=False),
        sa.Column("direction", sa.String(length=16), nullable=False),
        sa.Column("edo_document_id", sa.Text(), nullable=True),
        sa.Column("edo_group_id", sa.Text(), nullable=True),
        sa.Column("edo_event_id", sa.Text(), nullable=True),
        sa.Column("parent_document_id", sa.Text(), nullable=True),
        sa.Column("annulment_event_id", sa.Text(), nullable=True),
        sa.Column("official_type_code", sa.String(length=64), nullable=True),
        sa.Column("document_family", sa.String(length=64), nullable=True),
        sa.Column("function", sa.String(length=64), nullable=True),
        sa.Column("fns_order", sa.String(length=128), nullable=True),
        sa.Column("schema_identity", sa.String(length=128), nullable=True),
        sa.Column("counterparty_inn", sa.String(length=12), nullable=True),
        sa.Column("counterparty_edo_id", sa.Text(), nullable=True),
        sa.Column("document_number", sa.Text(), nullable=True),
        sa.Column("document_date", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id_file", sa.Text(), nullable=True),
        sa.Column("filename", sa.Text(), nullable=True),
        sa.Column("exact_xml_sha256", sa.String(length=64), nullable=True),
        sa.Column("signature_sha256", sa.String(length=64), nullable=True),
        sa.Column("raw_edo_status", sa.Integer(), nullable=True),
        sa.Column("raw_edo_status_label", sa.Text(), nullable=True),
        sa.Column("normalized_local_state", sa.String(length=64), nullable=False),
        sa.Column("gis_source_doc_id", sa.Text(), nullable=True),
        sa.Column("gis_result_doc_id", sa.Text(), nullable=True),
        sa.Column("gis_processing_state", sa.String(length=32), nullable=True),
        sa.Column("correction_relation", sa.JSON(), nullable=True),
        sa.Column("annulment_relation", sa.JSON(), nullable=True),
        sa.Column("last_error_http", sa.Integer(), nullable=True),
        sa.Column("last_error_raw", sa.Text(), nullable=True),
        sa.Column("last_reconciled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("evidence_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("direction IN ('INCOMING','OUTGOING','UNKNOWN')", name="ck_edo_lite_direction"),
    )
    op.create_index("ix_edo_lite_ledger_document_id", "edo_lite_ledger", ["edo_document_id"], unique=False)
    op.create_index("ix_edo_lite_ledger_id_file", "edo_lite_ledger", ["id_file"], unique=False)

    op.create_table(
        "edo_lite_schema_registry",
        sa.Column("schema_identity", sa.String(length=128), primary_key=True, nullable=False),
        sa.Column("family", sa.String(length=64), nullable=False),
        sa.Column("official_type_code", sa.String(length=64), nullable=True),
        sa.Column("title_role", sa.String(length=32), nullable=True),
        sa.Column("function", sa.String(length=64), nullable=True),
        sa.Column("official_order", sa.String(length=128), nullable=True),
        sa.Column("artifact_filename", sa.Text(), nullable=True),
        sa.Column("artifact_sha256", sa.String(length=64), nullable=True),
        sa.Column("xsd_filename", sa.Text(), nullable=True),
        sa.Column("xsd_sha256", sa.String(length=64), nullable=True),
        sa.Column("root", sa.Text(), nullable=True),
        sa.Column("target_namespace", sa.Text(), nullable=True),
        sa.Column("encoding", sa.String(length=32), nullable=True),
        sa.Column("filename_grammar", sa.Text(), nullable=True),
        sa.Column("parent_link_rule", sa.Text(), nullable=True),
        sa.Column("marking_capability", sa.Text(), nullable=True),
        sa.Column("enabled_for_lp", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("disabled_reason", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("enabled_for_lp = false", name="ck_m7_schema_registry_foundation_disabled"),
    )

    op.create_table(
        "edo_lite_annual_quota",
        sa.Column("year", sa.Integer(), primary_key=True, nullable=False),
        sa.Column("local_observed_outgoing_count", sa.Integer(), nullable=False),
        sa.Column("last_updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("source_evidence", sa.Text(), nullable=False),
        sa.Column("authoritative_remote_remaining", sa.Integer(), nullable=True),
        sa.CheckConstraint("local_observed_outgoing_count >= 0", name="ck_edo_lite_quota_nonnegative"),
        sa.CheckConstraint("authoritative_remote_remaining IS NULL", name="ck_edo_lite_no_fake_remote_remaining"),
    )


def downgrade() -> None:
    op.drop_table("edo_lite_annual_quota")
    op.drop_table("edo_lite_schema_registry")
    op.drop_index("ix_edo_lite_ledger_id_file", table_name="edo_lite_ledger")
    op.drop_index("ix_edo_lite_ledger_document_id", table_name="edo_lite_ledger")
    op.drop_table("edo_lite_ledger")
    op.drop_constraint("ck_agent_jobs_type", "agent_jobs", type_="check")
    op.create_check_constraint("ck_agent_jobs_type", "agent_jobs", _check(_PREVIOUS_TYPES))
