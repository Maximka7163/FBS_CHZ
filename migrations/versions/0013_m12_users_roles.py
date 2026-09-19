"""M12 users, roles, tenant isolation and hardened sessions.

Revision ID: 0013_m12_users_roles
Revises: 0012_m11_reports
"""
from alembic import op
import sqlalchemy as sa

revision="0013_m12_users_roles"
down_revision="0012_m11_reports"
branch_labels=None
depends_on=None

PERMISSIONS=[
"imports:read","imports:create","control:run","cis:read","reference:read","documents:read","documents:write",
"turnover:read","turnover:write","aggregation:read","aggregation:write","edo:read","edo:write",
"suz:read","suz:manage","wb:read","ozon:read","reports:create","reports:read","reports:download",
"reports:download_sensitive","integrations:read","integrations:manage","members:read","members:manage",
"roles:manage","organisation:manage","audit:read"]
VIEWER={"imports:read","cis:read","reference:read","documents:read","turnover:read","aggregation:read","edo:read","suz:read","wb:read","ozon:read","reports:read","reports:download","integrations:read","members:read"}
OPERATOR=VIEWER|{"imports:create","control:run","documents:write","turnover:write","aggregation:write","reports:create","reports:download_sensitive"}
ADMIN=OPERATOR|{"integrations:manage","members:manage","roles:manage","audit:read"}
ROLE_MAP={"VIEWER":VIEWER,"OPERATOR":OPERATOR,"ADMIN":ADMIN,"OWNER":set(PERMISSIONS)}

def _drop_single_column_uniques(table:str,column:str)->None:
    bind=op.get_bind();ins=sa.inspect(bind)
    for item in ins.get_unique_constraints(table):
        if item.get("column_names")==[column] and item.get("name"):
            op.drop_constraint(item["name"],table,type_="unique")
    for item in ins.get_indexes(table):
        if item.get("unique") and item.get("column_names")==[column] and item.get("name"):
            op.drop_index(item["name"],table_name=table)

def _drop_foreign_keys_for_column(table:str,column:str)->None:
    bind=op.get_bind();ins=sa.inspect(bind)
    for item in ins.get_foreign_keys(table):
        if item.get("constrained_columns")==[column] and item.get("name"):
            op.drop_constraint(item["name"],table,type_="foreignkey")

def _surrogate_pk(table:str,legacy_key:str,unique_name:str)->None:
    seq=f"{table}_m12_id_seq"
    op.add_column(table,sa.Column("id",sa.BigInteger(),nullable=True))
    op.execute(sa.text(f"CREATE SEQUENCE {seq}"))
    op.execute(sa.text(f"ALTER SEQUENCE {seq} OWNED BY {table}.id"))
    op.execute(sa.text(f"UPDATE {table} SET id=nextval('{seq}') WHERE id IS NULL"))
    op.alter_column(table,"id",nullable=False,server_default=sa.text(f"nextval('{seq}'::regclass)"))
    op.drop_constraint(f"{table}_pkey",table,type_="primary")
    op.create_primary_key(f"pk_{table}",table,["id"])
    op.create_unique_constraint(unique_name,table,["organisation_id","participant_id",legacy_key])

def upgrade()->None:
    op.create_table("organisations",
        sa.Column("id",sa.String(36),primary_key=True),sa.Column("name",sa.String(200),nullable=False),
        sa.Column("is_active",sa.Boolean(),nullable=False,server_default=sa.true()),
        sa.Column("created_by_user_id",sa.BigInteger(),sa.ForeignKey("users.id",ondelete="SET NULL"),nullable=True),
        sa.Column("created_at",sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()),
        sa.Column("updated_at",sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()))
    op.create_index("ix_organisations_is_active","organisations",["is_active"])
    op.create_table("participants",
        sa.Column("id",sa.String(36),primary_key=True),
        sa.Column("organisation_id",sa.String(36),sa.ForeignKey("organisations.id",ondelete="CASCADE"),nullable=False),
        sa.Column("inn",sa.String(12),nullable=False),sa.Column("display_name",sa.String(200),nullable=True),
        sa.Column("verification_state",sa.String(24),nullable=False,server_default="UNVERIFIED"),
        sa.Column("is_active",sa.Boolean(),nullable=False,server_default=sa.true()),
        sa.Column("created_at",sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()),
        sa.Column("updated_at",sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()),
        sa.UniqueConstraint("organisation_id","inn",name="uq_participants_organisation_inn"),
        sa.UniqueConstraint("inn",name="uq_participants_inn"),
        sa.CheckConstraint("verification_state IN ('UNVERIFIED','PENDING_VERIFICATION','VERIFIED','REJECTED')",name="ck_participants_verification_state"))
    for col in ("organisation_id","inn","verification_state","is_active"):op.create_index(f"ix_participants_{col}","participants",[col])
    op.create_table("participant_claims",
        sa.Column("id",sa.String(36),primary_key=True),
        sa.Column("claimant_user_id",sa.BigInteger(),sa.ForeignKey("users.id",ondelete="CASCADE"),nullable=False),
        sa.Column("target_organisation_id",sa.String(36),sa.ForeignKey("organisations.id",ondelete="CASCADE"),nullable=True),
        sa.Column("claimed_inn",sa.String(12),nullable=False),
        sa.Column("state",sa.String(24),nullable=False,server_default="PENDING_VERIFICATION"),
        sa.Column("verification_method",sa.String(64),nullable=True),
        sa.Column("verification_metadata",sa.JSON(),nullable=False,server_default=sa.text("'{}'::json")),
        sa.Column("evidence_refs",sa.JSON(),nullable=False,server_default=sa.text("'[]'::json")),
        sa.Column("decided_at",sa.DateTime(timezone=True),nullable=True),
        sa.Column("created_at",sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()),
        sa.Column("updated_at",sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()),
        sa.CheckConstraint("state IN ('PENDING_VERIFICATION','VERIFIED','REJECTED','CANCELLED')",name="ck_participant_claim_state"))
    for col in ("claimant_user_id","target_organisation_id","claimed_inn","state"):op.create_index(f"ix_participant_claims_{col}","participant_claims",[col])
    op.create_table("organisation_memberships",
        sa.Column("id",sa.String(36),primary_key=True),sa.Column("organisation_id",sa.String(36),sa.ForeignKey("organisations.id",ondelete="CASCADE"),nullable=False),
        sa.Column("user_id",sa.BigInteger(),sa.ForeignKey("users.id",ondelete="CASCADE"),nullable=False),
        sa.Column("role",sa.String(16),nullable=False),sa.Column("is_active",sa.Boolean(),nullable=False,server_default=sa.true()),
        sa.Column("created_by_user_id",sa.BigInteger(),sa.ForeignKey("users.id",ondelete="SET NULL"),nullable=True),
        sa.Column("created_at",sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()),
        sa.Column("updated_at",sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()),
        sa.UniqueConstraint("organisation_id","user_id",name="uq_membership_organisation_user"),
        sa.CheckConstraint("role IN ('OWNER','ADMIN','OPERATOR','VIEWER')",name="ck_membership_role"))
    for col in ("organisation_id","user_id","role","is_active"):op.create_index(f"ix_organisation_memberships_{col}","organisation_memberships",[col])
    op.create_table("permissions",sa.Column("code",sa.String(64),primary_key=True),sa.Column("description",sa.String(255),nullable=False))
    op.create_table("role_permissions",sa.Column("role",sa.String(16),primary_key=True),sa.Column("permission_code",sa.String(64),sa.ForeignKey("permissions.code",ondelete="CASCADE"),primary_key=True),sa.CheckConstraint("role IN ('OWNER','ADMIN','OPERATOR','VIEWER')",name="ck_role_permissions_role"))
    for code in PERMISSIONS:op.execute(sa.text("INSERT INTO permissions(code,description) VALUES (:c,:d)").bindparams(c=code,d=code))
    for role,codes in ROLE_MAP.items():
        for code in codes:op.execute(sa.text("INSERT INTO role_permissions(role,permission_code) VALUES (:r,:c)").bindparams(r=role,c=code))
    op.create_table("organisation_invitations",
        sa.Column("id",sa.String(36),primary_key=True),sa.Column("organisation_id",sa.String(36),sa.ForeignKey("organisations.id",ondelete="CASCADE"),nullable=False),
        sa.Column("participant_id",sa.String(36),sa.ForeignKey("participants.id",ondelete="SET NULL"),nullable=True),
        sa.Column("token_hash",sa.String(64),nullable=False,unique=True),
        sa.Column("invitee_username",sa.String(128),nullable=True),
        sa.Column("invited_user_id",sa.BigInteger(),sa.ForeignKey("users.id",ondelete="SET NULL"),nullable=True),
        sa.Column("invited_email_normalized",sa.String(320),nullable=True),
        sa.Column("role",sa.String(16),nullable=False),sa.Column("state",sa.String(16),nullable=False,server_default="PENDING"),
        sa.Column("invited_by_user_id",sa.BigInteger(),sa.ForeignKey("users.id",ondelete="RESTRICT"),nullable=False),
        sa.Column("accepted_by_user_id",sa.BigInteger(),sa.ForeignKey("users.id",ondelete="SET NULL"),nullable=True),
        sa.Column("expires_at",sa.DateTime(timezone=True),nullable=False),sa.Column("accepted_at",sa.DateTime(timezone=True),nullable=True),
        sa.Column("revoked_at",sa.DateTime(timezone=True),nullable=True),sa.Column("created_at",sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()),
        sa.CheckConstraint("role IN ('OWNER','ADMIN','OPERATOR','VIEWER')",name="ck_invitations_role"),
        sa.CheckConstraint("state IN ('PENDING','ACCEPTED','REVOKED','EXPIRED')",name="ck_invitations_state"),
        sa.CheckConstraint("invitee_username IS NOT NULL OR invited_user_id IS NOT NULL OR invited_email_normalized IS NOT NULL",name="ck_invitations_intended_identity"))
    for col in ("organisation_id","token_hash","invitee_username","invited_user_id","invited_email_normalized","state","expires_at"):op.create_index(f"ix_organisation_invitations_{col}","organisation_invitations",[col])
    op.create_table("password_history",sa.Column("id",sa.BigInteger(),primary_key=True,autoincrement=True),sa.Column("user_id",sa.BigInteger(),sa.ForeignKey("users.id",ondelete="CASCADE"),nullable=False),sa.Column("password_hash",sa.Text(),nullable=False),sa.Column("created_at",sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()))
    op.create_index("ix_password_history_user_id","password_history",["user_id"])
    op.create_table("login_attempts",sa.Column("id",sa.BigInteger(),primary_key=True,autoincrement=True),sa.Column("username_hash",sa.String(64),nullable=False),sa.Column("remote_hash",sa.String(64),nullable=False),sa.Column("successful",sa.Boolean(),nullable=False),sa.Column("attempted_at",sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()))
    for col in ("username_hash","remote_hash","attempted_at"):op.create_index(f"ix_login_attempts_{col}","login_attempts",[col])
    op.create_table("login_throttle_state",
        sa.Column("user_id",sa.BigInteger(),sa.ForeignKey("users.id",ondelete="CASCADE"),primary_key=True),
        sa.Column("consecutive_failures",sa.Integer(),nullable=False,server_default="0"),
        sa.Column("blocked_until",sa.DateTime(timezone=True),nullable=True),
        sa.Column("password_locked",sa.Boolean(),nullable=False,server_default=sa.false()),
        sa.Column("last_failure_at",sa.DateTime(timezone=True),nullable=True),
        sa.Column("last_success_at",sa.DateTime(timezone=True),nullable=True),
        sa.Column("updated_at",sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()),
        sa.CheckConstraint("consecutive_failures >= 0",name="ck_login_throttle_nonnegative"))
    op.create_index("ix_login_throttle_state_blocked_until","login_throttle_state",["blocked_until"])
    op.create_index("ix_login_throttle_state_password_locked","login_throttle_state",["password_locked"])
    op.create_table("security_bootstrap",sa.Column("id",sa.BigInteger(),primary_key=True),sa.Column("completed_at",sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()),sa.Column("organisation_id",sa.String(36),sa.ForeignKey("organisations.id",ondelete="RESTRICT"),nullable=False),sa.Column("owner_user_id",sa.BigInteger(),sa.ForeignKey("users.id",ondelete="RESTRICT"),nullable=False),sa.Column("participant_id",sa.String(36),sa.ForeignKey("participants.id",ondelete="RESTRICT"),nullable=False),sa.Column("metadata_json",sa.JSON(),nullable=False,server_default=sa.text("'{}'::json")))
    op.execute("CREATE UNIQUE INDEX uq_users_username_normalized ON users (lower(username))")
    op.add_column("users",sa.Column("email_normalized",sa.String(320),nullable=True))
    op.add_column("users",sa.Column("email_verified_at",sa.DateTime(timezone=True),nullable=True))
    op.add_column("users",sa.Column("account_state",sa.String(24),nullable=False,server_default="ACTIVE"))
    op.create_unique_constraint("uq_users_email_normalized","users",["email_normalized"])
    op.create_index("ix_users_email_normalized","users",["email_normalized"])
    op.create_index("ix_users_account_state","users",["account_state"])
    op.create_check_constraint("ck_users_account_state","users","account_state IN ('PENDING_VERIFICATION','ACTIVE','DISABLED','TOMBSTONED')")
    op.add_column("users",sa.Column("password_changed_at",sa.DateTime(timezone=True),nullable=True))
    op.add_column("users",sa.Column("password_version",sa.Integer(),nullable=False,server_default="1"))
    op.add_column("users",sa.Column("password_must_change",sa.Boolean(),nullable=False,server_default=sa.false()))
    op.execute("UPDATE users SET password_changed_at=created_at WHERE password_changed_at IS NULL");op.alter_column("users","password_changed_at",nullable=False)
    for name,col in (("csrf_token_hash",sa.String(64)),("active_organisation_id",sa.String(36)),("active_participant_id",sa.String(36)),("client_ip_hash",sa.String(64)),("user_agent_hash",sa.String(64))):op.add_column("sessions",sa.Column(name,col,nullable=True))
    op.add_column("sessions",sa.Column("password_version",sa.Integer(),nullable=False,server_default="1"))
    op.add_column("sessions",sa.Column("last_seen_at",sa.DateTime(timezone=True),nullable=True))
    op.create_foreign_key("fk_sessions_active_org","sessions","organisations",["active_organisation_id"],["id"],ondelete="SET NULL")
    op.create_foreign_key("fk_sessions_active_participant","sessions","participants",["active_participant_id"],["id"],ondelete="SET NULL")
    op.execute("UPDATE sessions SET last_seen_at=created_at WHERE last_seen_at IS NULL");op.alter_column("sessions","last_seen_at",nullable=False)
    for col in ("active_organisation_id","active_participant_id","last_seen_at"):op.create_index(f"ix_sessions_{col}","sessions",[col])
    tenant_tables=("imports","events","control_runs","previews","audit_log","agent_jobs","report_jobs","write_operations","document_lifecycle_ledger","turnover_operation_ledger","aggregation_operation_ledger","edo_lite_ledger","edo_lite_annual_quota","suz_connections","wb_connections","ozon_connections")
    for table in tenant_tables:
        op.add_column(table,sa.Column("organisation_id",sa.String(36),nullable=True));op.add_column(table,sa.Column("participant_id",sa.String(36),nullable=True))
        op.create_foreign_key(f"fk_{table}_m12_org",table,"organisations",["organisation_id"],["id"],ondelete="RESTRICT")
        op.create_foreign_key(f"fk_{table}_m12_participant",table,"participants",["participant_id"],["id"],ondelete="RESTRICT")
        op.create_index(f"ix_{table}_organisation_id",table,["organisation_id"]);op.create_index(f"ix_{table}_participant_id",table,["participant_id"])
    op.add_column("events",sa.Column("source_event_id",sa.String(64),nullable=True));op.execute("UPDATE events SET source_event_id=event_id WHERE source_event_id IS NULL");op.create_index("ix_events_source_event_id","events",["source_event_id"]);op.create_unique_constraint("uq_events_tenant_source_event","events",["organisation_id","participant_id","source_event_id"])
    _drop_single_column_uniques("write_operations","business_fingerprint")
    op.create_unique_constraint("uq_write_operations_tenant_business_fingerprint","write_operations",["organisation_id","participant_id","business_fingerprint"])
    for table in ("document_lifecycle_ledger","turnover_operation_ledger","aggregation_operation_ledger"):
        _drop_single_column_uniques(table,"request_id");op.create_unique_constraint(f"uq_{table}_tenant_request_id",table,["organisation_id","participant_id","request_id"])

    # M7 local identities are tenant business keys; official schema registry remains global reference data.
    _surrogate_pk("edo_lite_ledger","operation_id","uq_edo_lite_ledger_tenant_operation")
    _surrogate_pk("edo_lite_annual_quota","year","uq_edo_lite_quota_tenant_year")

    # M8 connection identity is remote-opaque but local uniqueness is tenant scoped.
    _drop_single_column_uniques("suz_connections","oms_connection")
    op.create_unique_constraint(
        "uq_suz_connections_tenant_oms_connection",
        "suz_connections",["organisation_id","participant_id","oms_connection"],
    )

    # M8 order operation_id remains a local semantic identifier, but database identity
    # is surrogate + connection scoped so two tenants may use the same local name.
    order_seq="suz_orders_m12_id_seq"
    op.add_column("suz_orders",sa.Column("id",sa.BigInteger(),nullable=True))
    op.execute(sa.text(f"CREATE SEQUENCE {order_seq}"))
    op.execute(sa.text(f"ALTER SEQUENCE {order_seq} OWNED BY suz_orders.id"))
    op.execute(sa.text(f"UPDATE suz_orders SET id=nextval('{order_seq}') WHERE id IS NULL"))
    op.alter_column("suz_orders","id",nullable=False,server_default=sa.text(f"nextval('{order_seq}'::regclass)"))

    child_tables=("suz_order_items","suz_km_vault","suz_code_blocks","suz_reconciliation_events")
    for table in child_tables:
        op.add_column(table,sa.Column("order_id",sa.BigInteger(),nullable=True))
        op.execute(sa.text(
            f"UPDATE {table} child SET order_id=parent.id "
            "FROM suz_orders parent WHERE child.order_operation_id=parent.operation_id"
        ))
        _drop_foreign_keys_for_column(table,"order_operation_id")

    op.drop_constraint("suz_orders_pkey","suz_orders",type_="primary")
    op.create_primary_key("pk_suz_orders","suz_orders",["id"])
    op.create_unique_constraint("uq_suz_orders_connection_operation","suz_orders",["connection_id","operation_id"])
    op.create_unique_constraint("uq_suz_orders_id_operation","suz_orders",["id","operation_id"])
    for table in child_tables:
        op.alter_column(table,"order_id",nullable=False)
        op.create_foreign_key(
            f"fk_{table}_m12_order",
            table,"suz_orders",["order_id","order_operation_id"],["id","operation_id"],
            ondelete="CASCADE",
        )
        op.create_index(f"ix_{table}_order_id",table,["order_id"])
    op.drop_constraint("uq_suz_order_item_gtin","suz_order_items",type_="unique")
    op.create_unique_constraint("uq_suz_order_item_order_gtin","suz_order_items",["order_id","gtin"])

    block_seq="suz_code_blocks_m12_id_seq"
    op.add_column("suz_code_blocks",sa.Column("id",sa.BigInteger(),nullable=True))
    op.execute(sa.text(f"CREATE SEQUENCE {block_seq}"))
    op.execute(sa.text(f"ALTER SEQUENCE {block_seq} OWNED BY suz_code_blocks.id"))
    op.execute(sa.text(f"UPDATE suz_code_blocks SET id=nextval('{block_seq}') WHERE id IS NULL"))
    op.alter_column("suz_code_blocks","id",nullable=False,server_default=sa.text(f"nextval('{block_seq}'::regclass)"))
    op.drop_constraint("suz_code_blocks_pkey","suz_code_blocks",type_="primary")
    op.create_primary_key("pk_suz_code_blocks","suz_code_blocks",["id"])
    op.create_unique_constraint("uq_suz_code_blocks_order_local","suz_code_blocks",["order_id","local_block_id"])

    # Remote True API document identifiers remain opaque; local uniqueness is tenant scoped.
    _drop_single_column_uniques("write_operations","document_id")
    op.create_unique_constraint(
        "uq_write_operations_tenant_document_id",
        "write_operations",["organisation_id","participant_id","document_id"],
    )

def downgrade()->None:
    raise RuntimeError("M12 security migration is forward-only; restore from backup for rollback")
