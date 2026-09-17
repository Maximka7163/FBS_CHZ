from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0009_m8_suz"
down_revision = "0008_m7_edo_lite_foundation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "suz_connections",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True, nullable=False),
        sa.Column("participant_inn", sa.String(length=12), nullable=False),
        sa.Column("oms_id", sa.Text(), nullable=False),
        sa.Column("oms_connection", sa.Text(), nullable=False),
        sa.Column("environment", sa.String(length=32), nullable=False),
        sa.Column("installation_name", sa.Text(), nullable=False),
        sa.Column("token_issued_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("token_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_auth_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("token_fingerprint", sa.String(length=64), nullable=True),
        sa.Column("connection_state", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(
            "connection_state IN ('NOT_ACQUIRED','ACTIVE','EXPIRED','SUPERSEDED','INVALIDATED')",
            name="ck_suz_connection_state",
        ),
        sa.UniqueConstraint("oms_connection", name="uq_suz_connections_oms_connection"),
    )
    op.create_index("ix_suz_connections_participant_inn", "suz_connections", ["participant_inn"], unique=False)
    op.create_index("ix_suz_connections_oms_connection", "suz_connections", ["oms_connection"], unique=True)

    op.create_table(
        "suz_orders",
        sa.Column("operation_id", sa.String(length=128), primary_key=True, nullable=False),
        sa.Column("connection_id", sa.BigInteger(), sa.ForeignKey("suz_connections.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("remote_order_id", sa.Text(), nullable=True),
        sa.Column("request_sha256", sa.String(length=64), nullable=False),
        sa.Column("raw_release_method", sa.Text(), nullable=False),
        sa.Column("raw_order_status", sa.Text(), nullable=True),
        sa.Column("raw_buffer_status", sa.Text(), nullable=True),
        sa.Column("requested_count", sa.Integer(), nullable=False),
        sa.Column("generated_count", sa.Integer(), nullable=True),
        sa.Column("fetched_count", sa.Integer(), nullable=True),
        sa.Column("reconciliation_state", sa.String(length=64), nullable=False),
        sa.Column("submission_state", sa.String(length=64), nullable=False),
        sa.Column("last_error_code", sa.Text(), nullable=True),
        sa.Column("last_error_message_redacted", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("requested_count > 0", name="ck_suz_order_requested_count_positive"),
        sa.CheckConstraint("generated_count IS NULL OR generated_count >= 0", name="ck_suz_order_generated_count_nonnegative"),
        sa.CheckConstraint("fetched_count IS NULL OR fetched_count >= 0", name="ck_suz_order_fetched_count_nonnegative"),
        sa.CheckConstraint(
            "submission_state IN ('NOT_SUBMITTED','SUBMISSION_UNKNOWN','REMOTE_LOOKUP_REQUIRED','REMOTE_CONFIRMED','CONFLICT','MANUAL_REVIEW')",
            name="ck_suz_order_submission_state",
        ),
    )
    op.create_index("ix_suz_orders_connection_id", "suz_orders", ["connection_id"], unique=False)
    op.create_index("ix_suz_orders_remote_order_id", "suz_orders", ["remote_order_id"], unique=False)

    op.create_table(
        "suz_order_items",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True, nullable=False),
        sa.Column("order_operation_id", sa.String(length=128), sa.ForeignKey("suz_orders.operation_id", ondelete="CASCADE"), nullable=False),
        sa.Column("gtin", sa.Text(), nullable=False),
        sa.Column("quantity", sa.Integer(), nullable=False),
        sa.Column("serial_mode", sa.String(length=32), nullable=False),
        sa.Column("serial_count", sa.Integer(), nullable=False),
        sa.Column("serials_sha256", sa.String(length=64), nullable=True),
        sa.Column("raw_template_id", sa.Text(), nullable=True),
        sa.Column("raw_cis_type", sa.Text(), nullable=True),
        sa.Column("raw_create_method_type", sa.Text(), nullable=True),
        sa.Column("service_provider_id", sa.Text(), nullable=True),
        sa.Column("producer", sa.Text(), nullable=True),
        sa.UniqueConstraint("order_operation_id", "gtin", name="uq_suz_order_item_gtin"),
        sa.CheckConstraint("quantity > 0", name="ck_suz_order_item_quantity_positive"),
        sa.CheckConstraint("serial_count >= 0", name="ck_suz_order_item_serial_count_nonnegative"),
        sa.CheckConstraint("serial_mode IN ('OPERATOR','SELF_MADE')", name="ck_suz_order_item_serial_mode"),
    )
    op.create_index("ix_suz_order_items_order_operation_id", "suz_order_items", ["order_operation_id"], unique=False)

    op.create_table(
        "suz_km_vault",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True, nullable=False),
        sa.Column("order_operation_id", sa.String(length=128), sa.ForeignKey("suz_orders.operation_id", ondelete="CASCADE"), nullable=False),
        sa.Column("gtin", sa.Text(), nullable=False),
        sa.Column("remote_block_id", sa.Text(), nullable=True),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("nonce", sa.LargeBinary(), nullable=False),
        sa.Column("auth_tag", sa.LargeBinary(), nullable=False),
        sa.Column("key_version", sa.String(length=64), nullable=False),
        sa.Column("vault_format_version", sa.String(length=64), nullable=False),
        sa.Column("aad_hash", sa.String(length=64), nullable=False),
        sa.Column("plaintext_sha256", sa.String(length=64), nullable=False),
        sa.Column("ciphertext_sha256", sa.String(length=64), nullable=False),
        sa.Column("code_count", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("code_count >= 0", name="ck_suz_km_vault_code_count_nonnegative"),
    )
    op.create_index("ix_suz_km_vault_order_operation_id", "suz_km_vault", ["order_operation_id"], unique=False)

    op.create_table(
        "suz_code_blocks",
        sa.Column("local_block_id", sa.String(length=128), primary_key=True, nullable=False),
        sa.Column("order_operation_id", sa.String(length=128), sa.ForeignKey("suz_orders.operation_id", ondelete="CASCADE"), nullable=False),
        sa.Column("gtin", sa.Text(), nullable=False),
        sa.Column("remote_block_id", sa.Text(), nullable=True),
        sa.Column("remote_package_id", sa.Text(), nullable=True),
        sa.Column("code_count", sa.Integer(), nullable=False),
        sa.Column("exact_payload_sha256", sa.String(length=64), nullable=False),
        sa.Column("vault_entry_id", sa.BigInteger(), sa.ForeignKey("suz_km_vault.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("fetch_state", sa.String(length=64), nullable=False),
        sa.Column("recovery_state", sa.String(length=64), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("committed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("code_count >= 0", name="ck_suz_code_block_count_nonnegative"),
        sa.UniqueConstraint("vault_entry_id", name="uq_suz_code_blocks_vault_entry_id"),
    )
    op.create_index("ix_suz_code_blocks_order_operation_id", "suz_code_blocks", ["order_operation_id"], unique=False)
    op.create_index("ix_suz_code_blocks_remote_block_id", "suz_code_blocks", ["remote_block_id"], unique=False)

    op.create_table(
        "suz_reconciliation_events",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True, nullable=False),
        sa.Column("order_operation_id", sa.String(length=128), sa.ForeignKey("suz_orders.operation_id", ondelete="CASCADE"), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("from_state", sa.String(length=64), nullable=True),
        sa.Column("to_state", sa.String(length=64), nullable=True),
        sa.Column("raw_order_status", sa.Text(), nullable=True),
        sa.Column("raw_buffer_status", sa.Text(), nullable=True),
        sa.Column("error_code", sa.Text(), nullable=True),
        sa.Column("details_redacted", sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")),
        sa.Column("evidence_sha256", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_suz_reconciliation_events_order_operation_id", "suz_reconciliation_events", ["order_operation_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_suz_reconciliation_events_order_operation_id", table_name="suz_reconciliation_events")
    op.drop_table("suz_reconciliation_events")
    op.drop_index("ix_suz_code_blocks_remote_block_id", table_name="suz_code_blocks")
    op.drop_index("ix_suz_code_blocks_order_operation_id", table_name="suz_code_blocks")
    op.drop_table("suz_code_blocks")
    op.drop_index("ix_suz_km_vault_order_operation_id", table_name="suz_km_vault")
    op.drop_table("suz_km_vault")
    op.drop_index("ix_suz_order_items_order_operation_id", table_name="suz_order_items")
    op.drop_table("suz_order_items")
    op.drop_index("ix_suz_orders_remote_order_id", table_name="suz_orders")
    op.drop_index("ix_suz_orders_connection_id", table_name="suz_orders")
    op.drop_table("suz_orders")
    op.drop_index("ix_suz_connections_oms_connection", table_name="suz_connections")
    op.drop_index("ix_suz_connections_participant_inn", table_name="suz_connections")
    op.drop_table("suz_connections")
