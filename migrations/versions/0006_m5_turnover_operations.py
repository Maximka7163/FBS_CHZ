from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0006_m5_turnover"
down_revision = "0005_m4_documents"
branch_labels = None
depends_on = None

_M4_TYPES = (
    "CIS_CHECK","LK_RECEIPT","LP_RETURN","POLL_DOCUMENT","CIS_INFO","CIS_SEARCH",
    "CIS_HISTORY","CIS_AGGREGATED_LIST","CIS_AGGREGATION_HISTORY","PRODUCT_INFO",
    "CIS_TO_PRODUCT","PARTICIPANTS","MODS_LIST","TN_VED_SEARCH","PRODUCT_GTIN_LIST",
    "RD_LIST","DOCUMENT_LIST","DOCUMENT_INFO","DOCUMENT_CISES",
)
_M5_ADDED_TYPES = (
    "LP_INTRODUCE_GOODS","LK_INDI_COMMISSIONING","LP_GOODS_IMPORT","CROSSBORDER",
    "LP_INTRODUCE_OST","LK_CONTRACT_COMMISSIONING","LP_FTS_INTRODUCE","LK_REMARK",
    "WRITE_OFF","LK_RECEIPT_CANCEL",
)


def _check(values: tuple[str, ...]) -> str:
    return "job_type IN (" + ",".join(repr(value) for value in values) + ")"


def upgrade() -> None:
    op.drop_constraint("ck_agent_jobs_type", "agent_jobs", type_="check")
    op.create_check_constraint("ck_agent_jobs_type", "agent_jobs", _check(_M4_TYPES + _M5_ADDED_TYPES))
    op.create_table(
        "turnover_operation_ledger",
        sa.Column("operation_id", sa.String(length=128), primary_key=True, nullable=False),
        sa.Column("request_id", sa.String(length=128), nullable=False, unique=True),
        sa.Column("operation_kind", sa.String(length=64), nullable=False),
        sa.Column("document_type", sa.String(length=64), nullable=False),
        sa.Column("document_sha256", sa.String(length=64), nullable=False),
        sa.Column("request_sha256", sa.String(length=64), nullable=False),
        sa.Column("idempotency_key", sa.String(length=256), nullable=False),
        sa.Column("raw_business_reason", sa.String(length=128), nullable=True),
        sa.Column("precondition_snapshot", sa.JSON(), nullable=False),
        sa.Column("expected_postcondition", sa.JSON(), nullable=False),
        sa.Column("reconciliation_state", sa.String(length=32), nullable=False),
        sa.Column("reconciliation_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")),
        sa.Column("cancellation_reference", sa.String(length=512), nullable=True),
        sa.Column("remote_document_id", sa.String(length=512), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("reconciliation_state IN ('RECONCILIATION_PENDING','RECONCILED','MANUAL_REVIEW')", name="ck_turnover_reconciliation_state"),
    )
    op.create_index("ix_turnover_operation_ledger_request_id", "turnover_operation_ledger", ["request_id"], unique=True)
    op.create_index("ix_turnover_operation_ledger_document_id", "turnover_operation_ledger", ["remote_document_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_turnover_operation_ledger_document_id", table_name="turnover_operation_ledger")
    op.drop_index("ix_turnover_operation_ledger_request_id", table_name="turnover_operation_ledger")
    op.drop_table("turnover_operation_ledger")
    op.drop_constraint("ck_agent_jobs_type", "agent_jobs", type_="check")
    op.create_check_constraint("ck_agent_jobs_type", "agent_jobs", _check(_M4_TYPES))
