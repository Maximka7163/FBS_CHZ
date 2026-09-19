"""M13 immutable tamper-evident tenant audit history.

Revision ID: 0014_m13_audit_history
Revises: 0013_m12_users_roles
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.orm import Session

revision = "0014_m13_audit_history"
down_revision = "0013_m12_users_roles"
branch_labels = None
depends_on = None

AUDIT_FORMAT_VERSION = "SELLARI_AUDIT_V1"
CHECKPOINT_FORMAT_VERSION = "SELLARI_AUDIT_CHECKPOINT_V1"

CATEGORIES = (
    "SECURITY","AUTHORIZATION","TENANT_ADMIN","INTEGRATION","IMPORT","CONTROL",
    "CIS_READ","REFERENCE_READ","DOCUMENT","TURNOVER","AGGREGATION","EDO","SUZ",
    "WB","OZON","REPORT","AGENT","SYSTEM",
)
ACTORS = ("USER","SYSTEM","WORKER","WINDOWS_AGENT","CLI_ADMIN","BOOTSTRAP","REMOTE_SYSTEM")
OUTCOMES = ("SUCCESS","DENIED","FAILED","PENDING","CONFLICT","CANCELLED","AMBIGUOUS")
AUTH_DECISIONS = ("ALLOW","DENY","NOT_APPLICABLE")
SUBJECTS = (
    "USER","SESSION","MEMBERSHIP","INVITATION","ORGANISATION","PARTICIPANT","IMPORT",
    "EVENT","CONTROL_RUN","AGENT_JOB","WRITE_OPERATION","DOCUMENT_OPERATION",
    "TURNOVER_OPERATION","AGGREGATION_OPERATION","EDO_OBJECT","SUZ_CONNECTION",
    "SUZ_ORDER","WB_CONNECTION","WB_OBJECT","OZON_CONNECTION","OZON_OBJECT",
    "REPORT_JOB","REPORT_ARTIFACT","INTEGRATION_CONNECTION","MARKING_IDENTIFIER",
    "AUDIT_CHAIN","AUDIT_CHECKPOINT",
)


def _quoted(values: tuple[str, ...]) -> str:
    return ",".join("'" + value + "'" for value in values)


def upgrade() -> None:
    op.create_unique_constraint(
        "uq_participants_id_organisation_m13",
        "participants",
        ["id", "organisation_id"],
    )

    op.add_column("agent_jobs", sa.Column("correlation_id", sa.String(128), nullable=True))
    op.add_column("agent_jobs", sa.Column("causation_id", sa.String(128), nullable=True))
    op.create_index("ix_agent_jobs_correlation_id", "agent_jobs", ["correlation_id"])
    op.create_index("ix_agent_jobs_causation_id", "agent_jobs", ["causation_id"])

    op.add_column("report_jobs", sa.Column("correlation_id", sa.String(128), nullable=True))
    op.add_column("report_jobs", sa.Column("causation_id", sa.String(128), nullable=True))
    op.create_index("ix_report_jobs_correlation_id", "report_jobs", ["correlation_id"])
    op.create_index("ix_report_jobs_causation_id", "report_jobs", ["causation_id"])

    op.create_table(
        "audit_chain_heads",
        sa.Column("chain_id", sa.String(36), primary_key=True),
        sa.Column("scope_kind", sa.String(16), nullable=False),
        sa.Column(
            "organisation_id",
            sa.String(36),
            sa.ForeignKey("organisations.id", ondelete="RESTRICT"),
            nullable=True,
        ),
        sa.Column("head_sequence", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("head_hash", sa.String(64), nullable=False, server_default="0" * 64),
        sa.Column("audit_format_version", sa.String(32), nullable=False, server_default=AUDIT_FORMAT_VERSION),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("scope_kind IN ('SYSTEM','ORGANISATION')", name="ck_audit_chain_scope_kind"),
        sa.CheckConstraint(
            "(scope_kind='SYSTEM' AND organisation_id IS NULL) OR "
            "(scope_kind='ORGANISATION' AND organisation_id IS NOT NULL)",
            name="ck_audit_chain_scope_binding",
        ),
        sa.CheckConstraint("head_sequence >= 0", name="ck_audit_chain_head_sequence"),
        sa.CheckConstraint("head_hash ~ '^[0-9a-f]{64}$'", name="ck_audit_chain_head_hash"),
    )
    op.create_index("ix_audit_chain_heads_scope_kind", "audit_chain_heads", ["scope_kind"])
    op.create_index("ix_audit_chain_heads_organisation_id", "audit_chain_heads", ["organisation_id"])
    op.execute(
        "CREATE UNIQUE INDEX uq_audit_chain_system ON audit_chain_heads(scope_kind) "
        "WHERE scope_kind='SYSTEM'"
    )
    op.execute(
        "CREATE UNIQUE INDEX uq_audit_chain_organisation ON audit_chain_heads(organisation_id) "
        "WHERE scope_kind='ORGANISATION'"
    )

    op.create_table(
        "audit_events",
        sa.Column("event_id", sa.String(36), primary_key=True),
        sa.Column(
            "chain_id",
            sa.String(36),
            sa.ForeignKey("audit_chain_heads.chain_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("sequence", sa.BigInteger(), nullable=False),
        sa.Column(
            "organisation_id",
            sa.String(36),
            sa.ForeignKey("organisations.id", ondelete="RESTRICT"),
            nullable=True,
        ),
        sa.Column("participant_id", sa.String(36), nullable=True),
        sa.Column("category", sa.String(32), nullable=False),
        sa.Column("event_type", sa.String(96), nullable=False),
        sa.Column("action", sa.String(96), nullable=False),
        sa.Column("outcome", sa.String(16), nullable=False),
        sa.Column("authorization_decision", sa.String(24), nullable=False),
        sa.Column("actor_kind", sa.String(24), nullable=False),
        sa.Column(
            "actor_user_id",
            sa.BigInteger(),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=True,
        ),
        sa.Column(
            "actor_membership_id",
            sa.String(36),
            sa.ForeignKey("organisation_memberships.id", ondelete="RESTRICT"),
            nullable=True,
        ),
        sa.Column("actor_role_snapshot", sa.String(16), nullable=True),
        sa.Column("permission_snapshot_json", sa.JSON(), nullable=True),
        sa.Column("subject_type", sa.String(40), nullable=False),
        sa.Column("subject_id", sa.String(256), nullable=False),
        sa.Column("secondary_subject_type", sa.String(40), nullable=True),
        sa.Column("secondary_subject_id", sa.String(256), nullable=True),
        sa.Column("request_id", sa.String(128), nullable=True),
        sa.Column("correlation_id", sa.String(128), nullable=True),
        sa.Column("causation_id", sa.String(128), nullable=True),
        sa.Column("operation_id", sa.String(128), nullable=True),
        sa.Column("agent_job_id", sa.String(128), nullable=True),
        sa.Column("event_key", sa.String(256), nullable=True),
        sa.Column("before_sha256", sa.String(64), nullable=True),
        sa.Column("after_sha256", sa.String(64), nullable=True),
        sa.Column("evidence_hashes_json", sa.JSON(), nullable=False, server_default=sa.text("'[]'::json")),
        sa.Column("metadata_sanitized_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")),
        sa.Column("previous_event_hash", sa.String(64), nullable=False),
        sa.Column("event_hash", sa.String(64), nullable=False),
        sa.Column("audit_format_version", sa.String(32), nullable=False, server_default=AUDIT_FORMAT_VERSION),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("chain_id", "sequence", name="uq_audit_events_chain_sequence"),
        sa.UniqueConstraint("chain_id", "event_key", name="uq_audit_events_chain_event_key"),
        sa.ForeignKeyConstraint(
            ["participant_id", "organisation_id"],
            ["participants.id", "participants.organisation_id"],
            name="fk_audit_events_participant_organisation",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(f"category IN ({_quoted(CATEGORIES)})", name="ck_audit_event_category"),
        sa.CheckConstraint(f"actor_kind IN ({_quoted(ACTORS)})", name="ck_audit_event_actor_kind"),
        sa.CheckConstraint(f"outcome IN ({_quoted(OUTCOMES)})", name="ck_audit_event_outcome"),
        sa.CheckConstraint(
            f"authorization_decision IN ({_quoted(AUTH_DECISIONS)})",
            name="ck_audit_event_authorization_decision",
        ),
        sa.CheckConstraint(f"subject_type IN ({_quoted(SUBJECTS)})", name="ck_audit_event_subject_type"),
        sa.CheckConstraint(
            "secondary_subject_type IS NULL OR secondary_subject_type IN (" + _quoted(SUBJECTS) + ")",
            name="ck_audit_event_secondary_subject_type",
        ),
        sa.CheckConstraint("sequence >= 1", name="ck_audit_event_sequence"),
        sa.CheckConstraint("previous_event_hash ~ '^[0-9a-f]{64}$'", name="ck_audit_event_previous_hash"),
        sa.CheckConstraint("event_hash ~ '^[0-9a-f]{64}$'", name="ck_audit_event_hash"),
        sa.CheckConstraint(
            "(participant_id IS NULL) OR (organisation_id IS NOT NULL)",
            name="ck_audit_event_participant_requires_org",
        ),
    )
    for name, cols in (
        ("ix_audit_events_chain_id", ["chain_id"]),
        ("ix_audit_events_organisation_id", ["organisation_id"]),
        ("ix_audit_events_participant_id", ["participant_id"]),
        ("ix_audit_events_category", ["category"]),
        ("ix_audit_events_event_type", ["event_type"]),
        ("ix_audit_events_action", ["action"]),
        ("ix_audit_events_outcome", ["outcome"]),
        ("ix_audit_events_actor_kind", ["actor_kind"]),
        ("ix_audit_events_actor_user_id", ["actor_user_id"]),
        ("ix_audit_events_subject_type", ["subject_type"]),
        ("ix_audit_events_subject_id", ["subject_id"]),
        ("ix_audit_events_request_id", ["request_id"]),
        ("ix_audit_events_correlation_id", ["correlation_id"]),
        ("ix_audit_events_occurred_at", ["occurred_at"]),
    ):
        op.create_index(name, "audit_events", cols)
    op.execute("CREATE INDEX ix_audit_events_chain_sequence_desc ON audit_events(chain_id, sequence DESC)")
    op.create_index("ix_audit_events_org_occurred", "audit_events", ["organisation_id", "occurred_at"])
    op.create_index("ix_audit_events_org_category", "audit_events", ["organisation_id", "category"])
    op.create_index("ix_audit_events_org_actor", "audit_events", ["organisation_id", "actor_user_id"])
    op.create_index(
        "ix_audit_events_org_subject",
        "audit_events",
        ["organisation_id", "subject_type", "subject_id"],
    )
    op.create_index(
        "ix_audit_events_org_participant",
        "audit_events",
        ["organisation_id", "participant_id"],
    )
    op.create_index(
        "ix_audit_events_org_correlation",
        "audit_events",
        ["organisation_id", "correlation_id"],
    )

    op.create_table(
        "audit_checkpoints",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "chain_id",
            sa.String(36),
            sa.ForeignKey("audit_chain_heads.chain_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("through_sequence", sa.BigInteger(), nullable=False),
        sa.Column("head_event_hash", sa.String(64), nullable=False),
        sa.Column("previous_checkpoint_hash", sa.String(64), nullable=False),
        sa.Column("checkpoint_hash", sa.String(64), nullable=False),
        sa.Column(
            "checkpoint_format_version",
            sa.String(40),
            nullable=False,
            server_default=CHECKPOINT_FORMAT_VERSION,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "chain_id",
            "through_sequence",
            name="uq_audit_checkpoint_chain_sequence",
        ),
        sa.CheckConstraint("through_sequence >= 1", name="ck_audit_checkpoint_sequence"),
        sa.CheckConstraint("head_event_hash ~ '^[0-9a-f]{64}$'", name="ck_audit_checkpoint_head_hash"),
        sa.CheckConstraint(
            "previous_checkpoint_hash ~ '^[0-9a-f]{64}$'",
            name="ck_audit_checkpoint_previous_hash",
        ),
        sa.CheckConstraint("checkpoint_hash ~ '^[0-9a-f]{64}$'", name="ck_audit_checkpoint_hash"),
    )
    op.create_index("ix_audit_checkpoints_chain_id", "audit_checkpoints", ["chain_id"])

    op.execute(
        """
        CREATE OR REPLACE FUNCTION m13_reject_audit_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
          RAISE EXCEPTION 'M13 immutable audit rows are append-only';
        END;
        $$;
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_audit_events_no_update
        BEFORE UPDATE ON audit_events
        FOR EACH ROW EXECUTE FUNCTION m13_reject_audit_mutation()
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_audit_events_no_delete
        BEFORE DELETE ON audit_events
        FOR EACH ROW EXECUTE FUNCTION m13_reject_audit_mutation()
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_audit_checkpoints_no_update
        BEFORE UPDATE ON audit_checkpoints
        FOR EACH ROW EXECUTE FUNCTION m13_reject_audit_mutation()
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_audit_checkpoints_no_delete
        BEFORE DELETE ON audit_checkpoints
        FOR EACH ROW EXECUTE FUNCTION m13_reject_audit_mutation()
        """
    )

    # Seal existing M12 history only as a deterministic PRE_M13_UNSEALED_HISTORY manifest.
    # This does not claim historical tamper evidence before M13.
    from wbcz_web.services.audit_history import LegacyHistorySealer
    session = Session(bind=op.get_bind())
    LegacyHistorySealer(session).seal_all()
    session.flush()


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS trg_audit_checkpoints_no_delete ON audit_checkpoints")
    op.execute("DROP TRIGGER IF EXISTS trg_audit_checkpoints_no_update ON audit_checkpoints")
    op.execute("DROP TRIGGER IF EXISTS trg_audit_events_no_delete ON audit_events")
    op.execute("DROP TRIGGER IF EXISTS trg_audit_events_no_update ON audit_events")
    op.execute("DROP FUNCTION IF EXISTS m13_reject_audit_mutation()")

    op.drop_table("audit_checkpoints")
    op.drop_table("audit_events")
    op.drop_table("audit_chain_heads")

    op.drop_index("ix_report_jobs_causation_id", table_name="report_jobs")
    op.drop_index("ix_report_jobs_correlation_id", table_name="report_jobs")
    op.drop_column("report_jobs", "causation_id")
    op.drop_column("report_jobs", "correlation_id")

    op.drop_index("ix_agent_jobs_causation_id", table_name="agent_jobs")
    op.drop_index("ix_agent_jobs_correlation_id", table_name="agent_jobs")
    op.drop_column("agent_jobs", "causation_id")
    op.drop_column("agent_jobs", "correlation_id")

    op.drop_constraint("uq_participants_id_organisation_m13", "participants", type_="unique")
