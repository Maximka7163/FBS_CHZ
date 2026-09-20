"""Physical spool execution durability.

Revision ID: 0020_printing_physical_spool
Revises: 0019_printing_printer_profiles

Adds only safe execution evidence. No FULL KM, raster, queue/port path,
raw DEVMODE, spool bytes or arbitrary printer command data.
"""

from alembic import op
import sqlalchemy as sa


revision = "0020_printing_physical_spool"
down_revision = "0019_printing_printer_profiles"
branch_labels = None
depends_on = None


_STATES = (
    "REQUESTED","AUTHORIZED","PAYLOAD_AVAILABLE","PAYLOAD_ISSUED","PAYLOAD_DELIVERED",
    "RENDERED_VERIFIED","SPOOL_SUBMITTING","SPOOL_JOB_CREATED","SPOOLER_ACCEPTED",
    "FAILED_PRE_SPOOL","BLOCKED","UNKNOWN_AFTER_SPOOL","CANCELLED_PRE_SPOOL",
)


def _quoted(values):
    return ",".join(repr(value) for value in values)


def upgrade() -> None:
    op.add_column("print_executions", sa.Column("printer_profile_id", sa.String(36), nullable=True))
    op.add_column("print_executions", sa.Column("printer_profile_fingerprint", sa.String(64), nullable=True))
    op.add_column("print_executions", sa.Column("windows_spool_job_id", sa.BigInteger(), nullable=True))
    op.add_column("print_executions", sa.Column("last_windows_status", sa.String(64), nullable=True))
    op.add_column("print_executions", sa.Column("rendered_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("print_executions", sa.Column("spool_submitting_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("print_executions", sa.Column("spool_job_created_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("print_executions", sa.Column("spooler_accepted_at", sa.DateTime(timezone=True), nullable=True))

    op.create_foreign_key(
        "fk_print_execution_printer_profile_tenant",
        "print_executions",
        "printer_profiles",
        ["printer_profile_id","organisation_id","participant_id"],
        ["id","organisation_id","participant_id"],
        ondelete="RESTRICT",
    )
    op.create_index("ix_print_execution_printer_profile", "print_executions", ["printer_profile_id"])
    op.create_index("ix_print_execution_windows_spool_job", "print_executions", ["windows_spool_job_id"])

    op.drop_constraint("ck_print_execution_state", "print_executions", type_="check")
    op.create_check_constraint(
        "ck_print_execution_state",
        "print_executions",
        "state IN (" + _quoted(_STATES) + ")",
    )
    op.drop_index("uq_print_execution_item_nonterminal", table_name="print_executions")
    op.create_index(
        "uq_print_execution_item_nonterminal",
        "print_executions",
        ["print_job_item_id"],
        unique=True,
        postgresql_where=sa.text(
            "state IN ('REQUESTED','AUTHORIZED','PAYLOAD_AVAILABLE','PAYLOAD_ISSUED',"
            "'PAYLOAD_DELIVERED','RENDERED_VERIFIED','SPOOL_SUBMITTING','SPOOL_JOB_CREATED')"
        ),
    )
    op.create_check_constraint(
        "ck_print_execution_spool_job_positive",
        "print_executions",
        "windows_spool_job_id IS NULL OR windows_spool_job_id > 0",
    )
    op.create_check_constraint(
        "ck_print_execution_profile_fingerprint",
        "print_executions",
        "printer_profile_fingerprint IS NULL OR length(printer_profile_fingerprint)=64",
    )


def downgrade() -> None:
    op.drop_constraint("ck_print_execution_profile_fingerprint", "print_executions", type_="check")
    op.drop_constraint("ck_print_execution_spool_job_positive", "print_executions", type_="check")
    op.drop_index("uq_print_execution_item_nonterminal", table_name="print_executions")
    op.create_index(
        "uq_print_execution_item_nonterminal",
        "print_executions",
        ["print_job_item_id"],
        unique=True,
        postgresql_where=sa.text(
            "state IN ('REQUESTED','AUTHORIZED','PAYLOAD_AVAILABLE','PAYLOAD_ISSUED','PAYLOAD_DELIVERED')"
        ),
    )
    op.drop_constraint("ck_print_execution_state", "print_executions", type_="check")
    op.create_check_constraint(
        "ck_print_execution_state",
        "print_executions",
        "state IN ('REQUESTED','AUTHORIZED','PAYLOAD_AVAILABLE','PAYLOAD_ISSUED',"
        "'PAYLOAD_DELIVERED','FAILED_PRE_SPOOL','BLOCKED','CANCELLED_PRE_SPOOL')",
    )

    op.drop_index("ix_print_execution_windows_spool_job", table_name="print_executions")
    op.drop_index("ix_print_execution_printer_profile", table_name="print_executions")
    op.drop_constraint("fk_print_execution_printer_profile_tenant", "print_executions", type_="foreignkey")

    for name in (
        "spooler_accepted_at","spool_job_created_at","spool_submitting_at","rendered_at",
        "last_windows_status","windows_spool_job_id","printer_profile_fingerprint","printer_profile_id",
    ):
        op.drop_column("print_executions", name)
