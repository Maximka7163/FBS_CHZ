from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0005_m4_document_lifecycle_read_jobs"
down_revision = "0004_m2_reference_products"
branch_labels = None
depends_on = None


_OLD = "job_type IN ('CIS_CHECK','LK_RECEIPT','LP_RETURN','POLL_DOCUMENT','CIS_INFO','CIS_SEARCH','CIS_HISTORY','CIS_AGGREGATED_LIST','CIS_AGGREGATION_HISTORY','PRODUCT_INFO','CIS_TO_PRODUCT','PARTICIPANTS','MODS_LIST','TN_VED_SEARCH','PRODUCT_GTIN_LIST','RD_LIST')"
_NEW = "job_type IN ('CIS_CHECK','LK_RECEIPT','LP_RETURN','POLL_DOCUMENT','CIS_INFO','CIS_SEARCH','CIS_HISTORY','CIS_AGGREGATED_LIST','CIS_AGGREGATION_HISTORY','PRODUCT_INFO','CIS_TO_PRODUCT','PARTICIPANTS','MODS_LIST','TN_VED_SEARCH','PRODUCT_GTIN_LIST','RD_LIST','DOCUMENT_LIST','DOCUMENT_INFO','DOCUMENT_CISES')"


def upgrade() -> None:
    op.drop_constraint("ck_agent_jobs_type", "agent_jobs", type_="check")
    op.create_check_constraint("ck_agent_jobs_type", "agent_jobs", _NEW)
    op.create_table(
        "document_lifecycle_ledger",
        sa.Column("operation_id", sa.String(length=128), primary_key=True, nullable=False),
        sa.Column("request_id", sa.String(length=128), nullable=False, unique=True),
        sa.Column("job_type", sa.String(length=32), nullable=False),
        sa.Column("request_sha256", sa.String(length=64), nullable=False),
        sa.Column("idempotency_key", sa.String(length=256), nullable=False),
        sa.Column("request_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_document_lifecycle_ledger_request_id", "document_lifecycle_ledger", ["request_id"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_document_lifecycle_ledger_request_id", table_name="document_lifecycle_ledger")
    op.drop_table("document_lifecycle_ledger")
    op.drop_constraint("ck_agent_jobs_type", "agent_jobs", type_="check")
    op.create_check_constraint("ck_agent_jobs_type", "agent_jobs", _OLD)
