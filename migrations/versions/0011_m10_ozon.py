from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0011_m10_ozon"
down_revision = "0010_m9_wb"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ozon_connections",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True, nullable=False),
        sa.Column("participant_inn", sa.String(length=12), nullable=False),
        sa.Column("client_id", sa.Text(), nullable=False),
        sa.Column("api_key_secret_ref", sa.Text(), nullable=False),
        sa.Column("api_key_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("roles_metadata", sa.JSON(), nullable=False, server_default=sa.text("'[]'::json")),
        sa.Column("capability_metadata", sa.JSON(), nullable=False, server_default=sa.text("'[]'::json")),
        sa.Column("connection_state", sa.String(length=32), nullable=False),
        sa.Column("last_verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_ozon_connections_participant_inn", "ozon_connections", ["participant_inn"], unique=False)

    op.create_table(
        "ozon_postings",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True, nullable=False),
        sa.Column("connection_id", sa.BigInteger(), sa.ForeignKey("ozon_connections.id", ondelete="CASCADE"), nullable=False),
        sa.Column("posting_number", sa.Text(), nullable=False),
        sa.Column("order_id_opaque", sa.Text(), nullable=True),
        sa.Column("raw_status", sa.Text(), nullable=True),
        sa.Column("raw_substatus", sa.Text(), nullable=True),
        sa.Column("integration_type_flow_raw", sa.Text(), nullable=True),
        sa.Column("sorting_center_raw", sa.Text(), nullable=True),
        sa.Column("source_capability", sa.String(length=48), nullable=False),
        sa.Column("source_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("raw_sanitized_hash", sa.String(length=64), nullable=False),
        sa.Column("raw_created_at", sa.Text(), nullable=True),
        sa.Column("raw_updated_at", sa.Text(), nullable=True),
        sa.Column("local_reconciliation_state", sa.String(length=48), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("connection_id", "posting_number", name="uq_ozon_posting_connection_number"),
    )
    op.create_index("ix_ozon_postings_connection_id", "ozon_postings", ["connection_id"], unique=False)

    op.create_table(
        "ozon_items",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True, nullable=False),
        sa.Column("posting_id", sa.BigInteger(), sa.ForeignKey("ozon_postings.id", ondelete="CASCADE"), nullable=False),
        sa.Column("item_ref_opaque", sa.Text(), nullable=True),
        sa.Column("product_id_opaque", sa.Text(), nullable=True),
        sa.Column("offer_id_opaque", sa.Text(), nullable=True),
        sa.Column("sku_opaque", sa.Text(), nullable=True),
        sa.Column("barcode_opaque", sa.Text(), nullable=True),
        sa.Column("warehouse_id_opaque", sa.Text(), nullable=True),
        sa.Column("delivery_method_id_opaque", sa.Text(), nullable=True),
        sa.Column("exemplar_id_opaque", sa.Text(), nullable=True),
        sa.Column("quantity_raw", sa.Text(), nullable=True),
        sa.Column("relation_metadata_sanitized", sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")),
        sa.Column("source_capability", sa.String(length=48), nullable=False),
        sa.Column("source_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_ozon_items_posting_id", "ozon_items", ["posting_id"], unique=False)

    op.create_table(
        "ozon_marking_bindings",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True, nullable=False),
        sa.Column("connection_id", sa.BigInteger(), sa.ForeignKey("ozon_connections.id", ondelete="CASCADE"), nullable=False),
        sa.Column("posting_id", sa.BigInteger(), sa.ForeignKey("ozon_postings.id", ondelete="CASCADE"), nullable=True),
        sa.Column("item_id", sa.BigInteger(), sa.ForeignKey("ozon_items.id", ondelete="CASCADE"), nullable=True),
        sa.Column("exemplar_id_opaque", sa.Text(), nullable=True),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("nonce", sa.LargeBinary(), nullable=False),
        sa.Column("auth_tag", sa.LargeBinary(), nullable=False),
        sa.Column("key_version", sa.String(length=64), nullable=False),
        sa.Column("vault_format", sa.String(length=64), nullable=False),
        sa.Column("aad_hash", sa.String(length=64), nullable=False),
        sa.Column("plaintext_sha256", sa.String(length=64), nullable=False),
        sa.Column("ciphertext_sha256", sa.String(length=64), nullable=False),
        sa.Column("masked_value", sa.Text(), nullable=False),
        sa.Column("source_capability", sa.String(length=48), nullable=False),
        sa.Column("source_evidence_hash", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_ozon_marking_bindings_connection_id", "ozon_marking_bindings", ["connection_id"], unique=False)
    op.create_index("ix_ozon_marking_bindings_posting_id", "ozon_marking_bindings", ["posting_id"], unique=False)
    op.create_index("ix_ozon_marking_bindings_item_id", "ozon_marking_bindings", ["item_id"], unique=False)
    op.create_index("ix_ozon_marking_bindings_plaintext_sha256", "ozon_marking_bindings", ["plaintext_sha256"], unique=False)

    op.create_table(
        "ozon_events",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True, nullable=False),
        sa.Column("connection_id", sa.BigInteger(), sa.ForeignKey("ozon_connections.id", ondelete="CASCADE"), nullable=False),
        sa.Column("posting_id", sa.BigInteger(), sa.ForeignKey("ozon_postings.id", ondelete="CASCADE"), nullable=True),
        sa.Column("source_capability", sa.String(length=48), nullable=False),
        sa.Column("source_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("evidence_type", sa.String(length=48), nullable=False),
        sa.Column("conflict_state", sa.String(length=32), nullable=False),
        sa.Column("remote_identities_sanitized", sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")),
        sa.Column("raw_evidence_sanitized", sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")),
        sa.Column("raw_sanitized_hash", sa.String(length=64), nullable=False),
        sa.Column("evidence_hash", sa.String(length=64), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("connection_id", "source_capability", "source_fingerprint", name="uq_ozon_event_evidence"),
    )
    op.create_index("ix_ozon_events_connection_id", "ozon_events", ["connection_id"], unique=False)
    op.create_index("ix_ozon_events_posting_id", "ozon_events", ["posting_id"], unique=False)

    op.create_table(
        "ozon_returns",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True, nullable=False),
        sa.Column("connection_id", sa.BigInteger(), sa.ForeignKey("ozon_connections.id", ondelete="CASCADE"), nullable=False),
        sa.Column("posting_id", sa.BigInteger(), sa.ForeignKey("ozon_postings.id", ondelete="CASCADE"), nullable=True),
        sa.Column("return_id_opaque", sa.Text(), nullable=True),
        sa.Column("report_id_opaque", sa.Text(), nullable=True),
        sa.Column("raw_status", sa.Text(), nullable=True),
        sa.Column("raw_type", sa.Text(), nullable=True),
        sa.Column("source_capability", sa.String(length=48), nullable=False),
        sa.Column("source_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("raw_evidence_sanitized", sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")),
        sa.Column("raw_sanitized_hash", sa.String(length=64), nullable=False),
        sa.Column("evidence_state", sa.String(length=32), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_ozon_returns_connection_id", "ozon_returns", ["connection_id"], unique=False)
    op.create_index("ix_ozon_returns_posting_id", "ozon_returns", ["posting_id"], unique=False)

    op.create_table(
        "ozon_sync_cursors",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True, nullable=False),
        sa.Column("connection_id", sa.BigInteger(), sa.ForeignKey("ozon_connections.id", ondelete="CASCADE"), nullable=False),
        sa.Column("feed", sa.String(length=48), nullable=False),
        sa.Column("capability", sa.String(length=48), nullable=True),
        sa.Column("cycle_id", sa.Text(), nullable=True),
        sa.Column("cursor_opaque", sa.Text(), nullable=True),
        sa.Column("offset_opaque", sa.Text(), nullable=True),
        sa.Column("window_start_raw", sa.Text(), nullable=True),
        sa.Column("window_end_raw", sa.Text(), nullable=True),
        sa.Column("snapshot_opaque", sa.Text(), nullable=True),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error_redacted", sa.Text(), nullable=True),
        sa.Column("generation", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("connection_id", "feed", name="uq_ozon_sync_cursor_connection_feed"),
    )
    op.create_index("ix_ozon_sync_cursors_connection_id", "ozon_sync_cursors", ["connection_id"], unique=False)

    op.create_table(
        "ozon_reconciliation",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True, nullable=False),
        sa.Column("connection_id", sa.BigInteger(), sa.ForeignKey("ozon_connections.id", ondelete="CASCADE"), nullable=False),
        sa.Column("posting_id", sa.BigInteger(), sa.ForeignKey("ozon_postings.id", ondelete="CASCADE"), nullable=True),
        sa.Column("state", sa.String(length=48), nullable=False),
        sa.Column("decision", sa.String(length=48), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("evidence_redacted", sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_ozon_reconciliation_connection_id", "ozon_reconciliation", ["connection_id"], unique=False)
    op.create_index("ix_ozon_reconciliation_posting_id", "ozon_reconciliation", ["posting_id"], unique=False)

    op.create_table(
        "ozon_paid_evidence",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True, nullable=False),
        sa.Column("connection_id", sa.BigInteger(), sa.ForeignKey("ozon_connections.id", ondelete="CASCADE"), nullable=False),
        sa.Column("posting_id", sa.BigInteger(), sa.ForeignKey("ozon_postings.id", ondelete="CASCADE"), nullable=True),
        sa.Column("source", sa.String(length=48), nullable=False),
        sa.Column("raw_amount", sa.Text(), nullable=False),
        sa.Column("currency", sa.String(length=8), nullable=True),
        sa.Column("scale", sa.Integer(), nullable=True),
        sa.Column("semantics", sa.String(length=64), nullable=False),
        sa.Column("confidence_state", sa.String(length=32), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_ozon_paid_evidence_connection_id", "ozon_paid_evidence", ["connection_id"], unique=False)
    op.create_index("ix_ozon_paid_evidence_posting_id", "ozon_paid_evidence", ["posting_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_ozon_paid_evidence_posting_id", table_name="ozon_paid_evidence")
    op.drop_index("ix_ozon_paid_evidence_connection_id", table_name="ozon_paid_evidence")
    op.drop_table("ozon_paid_evidence")
    op.drop_index("ix_ozon_reconciliation_posting_id", table_name="ozon_reconciliation")
    op.drop_index("ix_ozon_reconciliation_connection_id", table_name="ozon_reconciliation")
    op.drop_table("ozon_reconciliation")
    op.drop_index("ix_ozon_sync_cursors_connection_id", table_name="ozon_sync_cursors")
    op.drop_table("ozon_sync_cursors")
    op.drop_index("ix_ozon_returns_posting_id", table_name="ozon_returns")
    op.drop_index("ix_ozon_returns_connection_id", table_name="ozon_returns")
    op.drop_table("ozon_returns")
    op.drop_index("ix_ozon_events_posting_id", table_name="ozon_events")
    op.drop_index("ix_ozon_events_connection_id", table_name="ozon_events")
    op.drop_table("ozon_events")
    op.drop_index("ix_ozon_marking_bindings_plaintext_sha256", table_name="ozon_marking_bindings")
    op.drop_index("ix_ozon_marking_bindings_item_id", table_name="ozon_marking_bindings")
    op.drop_index("ix_ozon_marking_bindings_posting_id", table_name="ozon_marking_bindings")
    op.drop_index("ix_ozon_marking_bindings_connection_id", table_name="ozon_marking_bindings")
    op.drop_table("ozon_marking_bindings")
    op.drop_index("ix_ozon_items_posting_id", table_name="ozon_items")
    op.drop_table("ozon_items")
    op.drop_index("ix_ozon_postings_connection_id", table_name="ozon_postings")
    op.drop_table("ozon_postings")
    op.drop_index("ix_ozon_connections_participant_inn", table_name="ozon_connections")
    op.drop_table("ozon_connections")
