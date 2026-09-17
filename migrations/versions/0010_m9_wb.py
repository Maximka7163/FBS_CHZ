from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0010_m9_wb"
down_revision = "0009_m8_suz"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "wb_connections",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True, nullable=False),
        sa.Column("environment", sa.String(length=24), nullable=False),
        sa.Column("participant_inn", sa.String(length=12), nullable=False),
        sa.Column("wb_sid", sa.Text(), nullable=True),
        sa.Column("wb_tin", sa.String(length=12), nullable=True),
        sa.Column("token_type", sa.String(length=32), nullable=False),
        sa.Column("token_categories", sa.JSON(), nullable=False, server_default=sa.text("'[]'::json")),
        sa.Column("token_scopes", sa.JSON(), nullable=False, server_default=sa.text("'[]'::json")),
        sa.Column("token_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("secret_ref", sa.Text(), nullable=False),
        sa.Column("rate_profile", sa.String(length=64), nullable=True),
        sa.Column("connection_state", sa.String(length=32), nullable=False),
        sa.Column("last_verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_wb_connections_participant_inn", "wb_connections", ["participant_inn"], unique=False)

    op.create_table(
        "wb_orders",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True, nullable=False),
        sa.Column("connection_id", sa.BigInteger(), sa.ForeignKey("wb_connections.id", ondelete="CASCADE"), nullable=False),
        sa.Column("assembly_order_id", sa.BigInteger(), nullable=False),
        sa.Column("order_uid", sa.Text(), nullable=True),
        sa.Column("rid", sa.Text(), nullable=True),
        sa.Column("srid", sa.Text(), nullable=True),
        sa.Column("nm_id", sa.BigInteger(), nullable=True),
        sa.Column("chrt_id", sa.BigInteger(), nullable=True),
        sa.Column("article", sa.Text(), nullable=True),
        sa.Column("barcode", sa.Text(), nullable=True),
        sa.Column("skus", sa.JSON(), nullable=False, server_default=sa.text("'[]'::json")),
        sa.Column("warehouse_id", sa.BigInteger(), nullable=True),
        sa.Column("office_id", sa.BigInteger(), nullable=True),
        sa.Column("supply_id", sa.Text(), nullable=True),
        sa.Column("sticker_id", sa.Text(), nullable=True),
        sa.Column("fulfillment_model", sa.String(length=16), nullable=False, server_default="FBS"),
        sa.Column("raw_supplier_status", sa.Text(), nullable=True),
        sa.Column("raw_wb_status", sa.Text(), nullable=True),
        sa.Column("created_at_raw", sa.Text(), nullable=True),
        sa.Column("updated_at_raw", sa.Text(), nullable=True),
        sa.Column("created_at_parsed", sa.DateTime(timezone=True), nullable=True),
        sa.Column("price_evidence", sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")),
        sa.Column("currency_evidence", sa.String(length=8), nullable=True),
        sa.Column("is_b2b", sa.Boolean(), nullable=True),
        sa.Column("source", sa.String(length=16), nullable=False),
        sa.Column("source_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("raw_evidence_ref", sa.Text(), nullable=True),
        sa.Column("raw_evidence_hash", sa.String(length=64), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("connection_id", "assembly_order_id", name="uq_wb_order_connection_assembly"),
    )
    op.create_index("ix_wb_orders_connection_id", "wb_orders", ["connection_id"], unique=False)

    op.create_table(
        "wb_marking_bindings",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True, nullable=False),
        sa.Column("order_id", sa.BigInteger(), sa.ForeignKey("wb_orders.id", ondelete="CASCADE"), nullable=False),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("nonce", sa.LargeBinary(), nullable=False),
        sa.Column("auth_tag", sa.LargeBinary(), nullable=False),
        sa.Column("key_version", sa.String(length=64), nullable=False),
        sa.Column("vault_format", sa.String(length=64), nullable=False),
        sa.Column("aad_hash", sa.String(length=64), nullable=False),
        sa.Column("fingerprint_sha256", sa.String(length=64), nullable=False),
        sa.Column("masked_value", sa.Text(), nullable=False),
        sa.Column("source", sa.String(length=16), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("validation_state", sa.String(length=32), nullable=False),
        sa.Column("conflict_state", sa.String(length=32), nullable=False),
        sa.Column("source_evidence_hash", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_wb_marking_bindings_order_id", "wb_marking_bindings", ["order_id"], unique=False)
    op.create_index("ix_wb_marking_bindings_fingerprint_sha256", "wb_marking_bindings", ["fingerprint_sha256"], unique=False)

    op.create_table(
        "wb_events",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True, nullable=False),
        sa.Column("connection_id", sa.BigInteger(), sa.ForeignKey("wb_connections.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source", sa.String(length=16), nullable=False),
        sa.Column("source_family", sa.String(length=40), nullable=False),
        sa.Column("source_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("assembly_order_id", sa.BigInteger(), nullable=True),
        sa.Column("rid", sa.Text(), nullable=True),
        sa.Column("srid", sa.Text(), nullable=True),
        sa.Column("raw_status", sa.Text(), nullable=True),
        sa.Column("raw_cancel_type", sa.Text(), nullable=True),
        sa.Column("raw_evidence_sanitized", sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")),
        sa.Column("raw_evidence_hash", sa.String(length=64), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("connection_id", "source", "source_fingerprint", name="uq_wb_event_evidence"),
    )
    op.create_index("ix_wb_events_connection_id", "wb_events", ["connection_id"], unique=False)

    op.create_table(
        "wb_returns",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True, nullable=False),
        sa.Column("connection_id", sa.BigInteger(), sa.ForeignKey("wb_connections.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source", sa.String(length=16), nullable=False),
        sa.Column("source_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("order_id_raw", sa.Text(), nullable=True),
        sa.Column("srid", sa.Text(), nullable=True),
        sa.Column("nm_id", sa.BigInteger(), nullable=True),
        sa.Column("barcode", sa.Text(), nullable=True),
        sa.Column("sticker_id", sa.Text(), nullable=True),
        sa.Column("shk_id", sa.Text(), nullable=True),
        sa.Column("ready_to_return_dt_raw", sa.Text(), nullable=True),
        sa.Column("ready_to_return_dt_parsed", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_dt_raw", sa.Text(), nullable=True),
        sa.Column("completed_dt_parsed", sa.DateTime(timezone=True), nullable=True),
        sa.Column("timestamp_semantics", sa.String(length=32), nullable=False),
        sa.Column("raw_return_status", sa.Text(), nullable=True),
        sa.Column("raw_return_type", sa.Text(), nullable=True),
        sa.Column("raw_evidence_hash", sa.String(length=64), nullable=False),
        sa.Column("evidence_state", sa.String(length=32), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_wb_returns_connection_id", "wb_returns", ["connection_id"], unique=False)

    op.create_table(
        "wb_sync_cursors",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True, nullable=False),
        sa.Column("connection_id", sa.BigInteger(), sa.ForeignKey("wb_connections.id", ondelete="CASCADE"), nullable=False),
        sa.Column("feed", sa.String(length=40), nullable=False),
        sa.Column("window_start_raw", sa.Text(), nullable=True),
        sa.Column("window_end_raw", sa.Text(), nullable=True),
        sa.Column("next_cursor", sa.BigInteger(), nullable=True),
        sa.Column("snapshot_time", sa.Text(), nullable=True),
        sa.Column("offset", sa.BigInteger(), nullable=True),
        sa.Column("last_change_date", sa.Text(), nullable=True),
        sa.Column("year", sa.Integer(), nullable=True),
        sa.Column("month", sa.Integer(), nullable=True),
        sa.Column("cycle_id", sa.Text(), nullable=True),
        sa.Column("generation", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("connection_id", "feed", name="uq_wb_sync_cursor_connection_feed"),
    )
    op.create_index("ix_wb_sync_cursors_connection_id", "wb_sync_cursors", ["connection_id"], unique=False)

    op.create_table(
        "wb_reconciliation",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True, nullable=False),
        sa.Column("connection_id", sa.BigInteger(), sa.ForeignKey("wb_connections.id", ondelete="CASCADE"), nullable=False),
        sa.Column("order_id", sa.BigInteger(), sa.ForeignKey("wb_orders.id", ondelete="CASCADE"), nullable=True),
        sa.Column("state", sa.String(length=48), nullable=False),
        sa.Column("decision", sa.String(length=48), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("evidence_redacted", sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_wb_reconciliation_connection_id", "wb_reconciliation", ["connection_id"], unique=False)
    op.create_index("ix_wb_reconciliation_order_id", "wb_reconciliation", ["order_id"], unique=False)

    op.create_table(
        "wb_paid_evidence",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True, nullable=False),
        sa.Column("connection_id", sa.BigInteger(), sa.ForeignKey("wb_connections.id", ondelete="CASCADE"), nullable=False),
        sa.Column("order_id", sa.BigInteger(), sa.ForeignKey("wb_orders.id", ondelete="CASCADE"), nullable=True),
        sa.Column("source", sa.String(length=40), nullable=False),
        sa.Column("raw_amount", sa.Text(), nullable=False),
        sa.Column("currency", sa.String(length=8), nullable=True),
        sa.Column("scale", sa.Integer(), nullable=True),
        sa.Column("contract_status", sa.String(length=40), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_wb_paid_evidence_connection_id", "wb_paid_evidence", ["connection_id"], unique=False)
    op.create_index("ix_wb_paid_evidence_order_id", "wb_paid_evidence", ["order_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_wb_paid_evidence_order_id", table_name="wb_paid_evidence")
    op.drop_index("ix_wb_paid_evidence_connection_id", table_name="wb_paid_evidence")
    op.drop_table("wb_paid_evidence")
    op.drop_index("ix_wb_reconciliation_order_id", table_name="wb_reconciliation")
    op.drop_index("ix_wb_reconciliation_connection_id", table_name="wb_reconciliation")
    op.drop_table("wb_reconciliation")
    op.drop_index("ix_wb_sync_cursors_connection_id", table_name="wb_sync_cursors")
    op.drop_table("wb_sync_cursors")
    op.drop_index("ix_wb_returns_connection_id", table_name="wb_returns")
    op.drop_table("wb_returns")
    op.drop_index("ix_wb_events_connection_id", table_name="wb_events")
    op.drop_table("wb_events")
    op.drop_index("ix_wb_marking_bindings_fingerprint_sha256", table_name="wb_marking_bindings")
    op.drop_index("ix_wb_marking_bindings_order_id", table_name="wb_marking_bindings")
    op.drop_table("wb_marking_bindings")
    op.drop_index("ix_wb_orders_connection_id", table_name="wb_orders")
    op.drop_table("wb_orders")
    op.drop_index("ix_wb_connections_participant_inn", table_name="wb_connections")
    op.drop_table("wb_connections")
