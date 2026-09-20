"""Sensitive printing payload delivery foundation.

Revision ID: 0018_printing_sensitive_delivery
Revises: 0017_printing_local_foundation

Phase A only: durable authorization/reservation/key metadata. No plaintext FULL KM,
HPKE ciphertext, recipient private key, spooler state, or physical printer capability.
"""

from alembic import op
import sqlalchemy as sa


revision = "0018_printing_sensitive_delivery"
down_revision = "0017_printing_local_foundation"
branch_labels = None
depends_on = None


_EXECUTION_STATES = (
    "REQUESTED","AUTHORIZED","PAYLOAD_AVAILABLE","PAYLOAD_ISSUED",
    "PAYLOAD_DELIVERED","FAILED_PRE_SPOOL","BLOCKED","CANCELLED_PRE_SPOOL",
)


def upgrade() -> None:
    op.create_unique_constraint(
        "uq_stored_full_km_id_tenant", "stored_full_km_items",
        ["id", "organisation_id", "participant_id"],
    )
    op.create_unique_constraint(
        "uq_print_job_id_tenant", "print_jobs",
        ["id", "organisation_id", "participant_id"],
    )
    op.create_unique_constraint(
        "uq_print_job_item_id_tenant", "print_job_items",
        ["id", "organisation_id", "participant_id"],
    )

    op.create_table(
        "agent_binding_encryption_keys",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organisation_id", sa.String(36), sa.ForeignKey("organisations.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("participant_id", sa.String(36), nullable=False),
        sa.Column("agent_binding_id", sa.String(36), nullable=False),
        sa.Column("algorithm", sa.String(64), nullable=False),
        sa.Column("public_key", sa.LargeBinary(), nullable=False),
        sa.Column("public_key_fingerprint", sa.String(64), nullable=False),
        sa.Column("key_version", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(16), nullable=False, server_default="ACTIVE"),
        sa.Column("registered_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("retiring_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(
            ["participant_id","organisation_id"], ["participants.id","participants.organisation_id"],
            name="fk_print_agent_key_participant_organisation", ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["agent_binding_id","organisation_id","participant_id"],
            ["agent_bindings.id","agent_bindings.organisation_id","agent_bindings.participant_id"],
            name="fk_print_agent_key_binding_tenant", ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("agent_binding_id","key_version",name="uq_print_agent_key_binding_version"),
        sa.UniqueConstraint("public_key_fingerprint",name="uq_print_agent_key_fingerprint"),
        sa.UniqueConstraint("id","organisation_id","participant_id",name="uq_print_agent_key_id_tenant"),
        sa.CheckConstraint("algorithm = 'HPKE_DHKEM_X25519_HKDF_SHA256_AES128GCM'",name="ck_print_agent_key_algorithm"),
        sa.CheckConstraint("octet_length(public_key) = 32",name="ck_print_agent_key_public_length"),
        sa.CheckConstraint("key_version >= 1",name="ck_print_agent_key_version_positive"),
        sa.CheckConstraint("state IN ('ACTIVE','RETIRING','REVOKED')",name="ck_print_agent_key_state"),
    )
    op.create_index("ix_print_agent_key_organisation","agent_binding_encryption_keys",["organisation_id"])
    op.create_index("ix_print_agent_key_participant","agent_binding_encryption_keys",["participant_id"])
    op.create_index("ix_print_agent_key_binding","agent_binding_encryption_keys",["agent_binding_id"])
    op.create_index(
        "uq_print_agent_key_active_binding","agent_binding_encryption_keys",["agent_binding_id"],
        unique=True, postgresql_where=sa.text("state='ACTIVE'"),
    )

    op.create_table(
        "print_encryption_key_intents",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organisation_id", sa.String(36), sa.ForeignKey("organisations.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("participant_id", sa.String(36), nullable=False),
        sa.Column("agent_binding_id", sa.String(36), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("purpose", sa.String(24), nullable=False),
        sa.Column("state", sa.String(16), nullable=False, server_default="PENDING"),
        sa.Column("expected_active_key_id", sa.String(36), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by_user_id", sa.BigInteger(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("correlation_id", sa.String(128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(
            ["participant_id","organisation_id"], ["participants.id","participants.organisation_id"],
            name="fk_print_key_intent_participant_organisation", ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["agent_binding_id","organisation_id","participant_id"],
            ["agent_bindings.id","agent_bindings.organisation_id","agent_bindings.participant_id"],
            name="fk_print_key_intent_binding_tenant", ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["expected_active_key_id","organisation_id","participant_id"],
            ["agent_binding_encryption_keys.id","agent_binding_encryption_keys.organisation_id","agent_binding_encryption_keys.participant_id"],
            name="fk_print_key_intent_expected_key_tenant", ondelete="RESTRICT",
        ),
        sa.CheckConstraint("purpose IN ('FIRST_REGISTRATION','ROTATE','REPLACE_LOST')",name="ck_print_key_intent_purpose"),
        sa.CheckConstraint("state IN ('PENDING','USED','EXPIRED','REVOKED')",name="ck_print_key_intent_state"),
    )
    for name, cols in (
        ("ix_print_key_intent_organisation",["organisation_id"]),
        ("ix_print_key_intent_participant",["participant_id"]),
        ("ix_print_key_intent_binding",["agent_binding_id"]),
        ("ix_print_key_intent_expires",["expires_at"]),
    ):
        op.create_index(name,"print_encryption_key_intents",cols)

    op.create_table(
        "print_executions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organisation_id", sa.String(36), sa.ForeignKey("organisations.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("participant_id", sa.String(36), nullable=False),
        sa.Column("print_job_id", sa.String(36), nullable=False),
        sa.Column("print_job_item_id", sa.String(36), nullable=False),
        sa.Column("stored_full_km_item_id", sa.String(36), nullable=False),
        sa.Column("template_version_id", sa.String(36), sa.ForeignKey("print_template_versions.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("agent_binding_id", sa.String(36), nullable=False),
        sa.Column("attempt_number", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(32), nullable=False, server_default="REQUESTED"),
        sa.Column("payload_sha256", sa.String(64), nullable=False),
        sa.Column("layout_sha256", sa.String(64), nullable=False),
        sa.Column("agent_version", sa.String(64), nullable=False),
        sa.Column("print_protocol_version", sa.String(32), nullable=False),
        sa.Column("renderer_version", sa.String(64), nullable=True),
        sa.Column("authorized_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("payload_delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("terminal_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("safe_error_code", sa.String(96), nullable=True),
        sa.Column("correlation_id", sa.String(128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(
            ["participant_id","organisation_id"], ["participants.id","participants.organisation_id"],
            name="fk_print_execution_participant_organisation", ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["print_job_id","organisation_id","participant_id"],
            ["print_jobs.id","print_jobs.organisation_id","print_jobs.participant_id"],
            name="fk_print_execution_job_tenant", ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["print_job_item_id","organisation_id","participant_id"],
            ["print_job_items.id","print_job_items.organisation_id","print_job_items.participant_id"],
            name="fk_print_execution_item_tenant", ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["stored_full_km_item_id","organisation_id","participant_id"],
            ["stored_full_km_items.id","stored_full_km_items.organisation_id","stored_full_km_items.participant_id"],
            name="fk_print_execution_stored_tenant", ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["agent_binding_id","organisation_id","participant_id"],
            ["agent_bindings.id","agent_bindings.organisation_id","agent_bindings.participant_id"],
            name="fk_print_execution_binding_tenant", ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("print_job_item_id","attempt_number",name="uq_print_execution_item_attempt"),
        sa.UniqueConstraint("id","organisation_id","participant_id",name="uq_print_execution_id_tenant"),
        sa.CheckConstraint("attempt_number >= 1",name="ck_print_execution_attempt_positive"),
        sa.CheckConstraint("state IN (" + ",".join(repr(x) for x in _EXECUTION_STATES) + ")",name="ck_print_execution_state"),
    )
    for name, cols in (
        ("ix_print_execution_organisation",["organisation_id"]),
        ("ix_print_execution_participant",["participant_id"]),
        ("ix_print_execution_job",["print_job_id"]),
        ("ix_print_execution_item",["print_job_item_id"]),
        ("ix_print_execution_stored",["stored_full_km_item_id"]),
        ("ix_print_execution_binding",["agent_binding_id"]),
        ("ix_print_execution_state",["state"]),
        ("ix_print_execution_correlation",["correlation_id"]),
    ):
        op.create_index(name,"print_executions",cols)
    op.create_index(
        "uq_print_execution_item_nonterminal","print_executions",["print_job_item_id"],unique=True,
        postgresql_where=sa.text("state IN ('REQUESTED','AUTHORIZED','PAYLOAD_AVAILABLE','PAYLOAD_ISSUED','PAYLOAD_DELIVERED')"),
    )

    op.create_table(
        "print_payload_delivery_reservations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organisation_id", sa.String(36), sa.ForeignKey("organisations.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("participant_id", sa.String(36), nullable=False),
        sa.Column("print_execution_id", sa.String(36), nullable=False),
        sa.Column("print_job_id", sa.String(36), nullable=False),
        sa.Column("print_job_item_id", sa.String(36), nullable=False),
        sa.Column("stored_full_km_item_id", sa.String(36), nullable=False),
        sa.Column("agent_binding_id", sa.String(36), nullable=False),
        sa.Column("agent_encryption_key_id", sa.String(36), nullable=False),
        sa.Column("payload_sha256", sa.String(64), nullable=False),
        sa.Column("state", sa.String(16), nullable=False, server_default="AVAILABLE"),
        sa.Column("issue_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("max_issue_count", sa.Integer(), nullable=False),
        sa.Column("authorized_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("first_issued_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_issued_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_context_sha256", sa.String(64), nullable=True),
        sa.Column("safe_error_code", sa.String(96), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(
            ["participant_id","organisation_id"], ["participants.id","participants.organisation_id"],
            name="fk_print_reservation_participant_organisation", ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["print_execution_id","organisation_id","participant_id"],
            ["print_executions.id","print_executions.organisation_id","print_executions.participant_id"],
            name="fk_print_reservation_execution_tenant", ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["print_job_id","organisation_id","participant_id"],
            ["print_jobs.id","print_jobs.organisation_id","print_jobs.participant_id"],
            name="fk_print_reservation_job_tenant", ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["print_job_item_id","organisation_id","participant_id"],
            ["print_job_items.id","print_job_items.organisation_id","print_job_items.participant_id"],
            name="fk_print_reservation_item_tenant", ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["stored_full_km_item_id","organisation_id","participant_id"],
            ["stored_full_km_items.id","stored_full_km_items.organisation_id","stored_full_km_items.participant_id"],
            name="fk_print_reservation_stored_tenant", ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["agent_binding_id","organisation_id","participant_id"],
            ["agent_bindings.id","agent_bindings.organisation_id","agent_bindings.participant_id"],
            name="fk_print_reservation_binding_tenant", ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["agent_encryption_key_id","organisation_id","participant_id"],
            ["agent_binding_encryption_keys.id","agent_binding_encryption_keys.organisation_id","agent_binding_encryption_keys.participant_id"],
            name="fk_print_reservation_key_tenant", ondelete="RESTRICT",
        ),
        sa.CheckConstraint("state IN ('AVAILABLE','ISSUED','ACKNOWLEDGED','EXPIRED','REVOKED','BLOCKED')",name="ck_print_reservation_state"),
        sa.CheckConstraint("issue_count >= 0 AND issue_count <= max_issue_count",name="ck_print_reservation_issue_count"),
        sa.CheckConstraint("max_issue_count >= 1 AND max_issue_count <= 10",name="ck_print_reservation_max_issue_count"),
        sa.CheckConstraint("expires_at > authorized_at",name="ck_print_reservation_expiry"),
    )
    for name, cols in (
        ("ix_print_reservation_organisation",["organisation_id"]),
        ("ix_print_reservation_participant",["participant_id"]),
        ("ix_print_reservation_execution",["print_execution_id"]),
        ("ix_print_reservation_job",["print_job_id"]),
        ("ix_print_reservation_item",["print_job_item_id"]),
        ("ix_print_reservation_stored",["stored_full_km_item_id"]),
        ("ix_print_reservation_binding",["agent_binding_id"]),
        ("ix_print_reservation_key",["agent_encryption_key_id"]),
        ("ix_print_reservation_expires",["expires_at"]),
        ("ix_print_reservation_state",["state"]),
    ):
        op.create_index(name,"print_payload_delivery_reservations",cols)
    op.create_index(
        "uq_print_reservation_execution_active","print_payload_delivery_reservations",["print_execution_id"],
        unique=True,postgresql_where=sa.text("state IN ('AVAILABLE','ISSUED')"),
    )


def downgrade() -> None:
    op.drop_index("uq_print_reservation_execution_active", table_name="print_payload_delivery_reservations")
    for name in (
        "ix_print_reservation_state","ix_print_reservation_expires","ix_print_reservation_key",
        "ix_print_reservation_binding","ix_print_reservation_stored","ix_print_reservation_item",
        "ix_print_reservation_job","ix_print_reservation_execution","ix_print_reservation_participant",
        "ix_print_reservation_organisation",
    ):
        op.drop_index(name, table_name="print_payload_delivery_reservations")
    op.drop_table("print_payload_delivery_reservations")

    op.drop_index("uq_print_execution_item_nonterminal", table_name="print_executions")
    for name in (
        "ix_print_execution_correlation","ix_print_execution_state","ix_print_execution_binding",
        "ix_print_execution_stored","ix_print_execution_item","ix_print_execution_job",
        "ix_print_execution_participant","ix_print_execution_organisation",
    ):
        op.drop_index(name, table_name="print_executions")
    op.drop_table("print_executions")

    for name in (
        "ix_print_key_intent_expires","ix_print_key_intent_binding",
        "ix_print_key_intent_participant","ix_print_key_intent_organisation",
    ):
        op.drop_index(name, table_name="print_encryption_key_intents")
    op.drop_table("print_encryption_key_intents")

    op.drop_index("uq_print_agent_key_active_binding", table_name="agent_binding_encryption_keys")
    for name in ("ix_print_agent_key_binding","ix_print_agent_key_participant","ix_print_agent_key_organisation"):
        op.drop_index(name, table_name="agent_binding_encryption_keys")
    op.drop_table("agent_binding_encryption_keys")

    op.drop_constraint("uq_print_job_item_id_tenant","print_job_items",type_="unique")
    op.drop_constraint("uq_print_job_id_tenant","print_jobs",type_="unique")
    op.drop_constraint("uq_stored_full_km_id_tenant","stored_full_km_items",type_="unique")
