from __future__ import annotations

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


def downgrade() -> None:
    op.drop_constraint("ck_agent_jobs_type", "agent_jobs", type_="check")
    op.create_check_constraint("ck_agent_jobs_type", "agent_jobs", _OLD)
