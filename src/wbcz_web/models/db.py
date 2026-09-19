from __future__ import annotations
from datetime import datetime
from decimal import Decimal
from typing import Any
from uuid import uuid4
from sqlalchemy import BigInteger,Boolean,CheckConstraint,DateTime,ForeignKey,Integer,JSON,Numeric,String,Text,UniqueConstraint,func
from sqlalchemy.orm import DeclarativeBase,Mapped,mapped_column,relationship

class Base(DeclarativeBase):pass
def uuid_text()->str:return str(uuid4())

class User(Base):
    __tablename__="users"
    id:Mapped[int]=mapped_column(BigInteger,primary_key=True,autoincrement=True)
    username:Mapped[str]=mapped_column(String(128),unique=True,nullable=False,index=True)
    email_normalized:Mapped[str|None]=mapped_column(String(320),unique=True,nullable=True,index=True)
    email_verified_at:Mapped[datetime|None]=mapped_column(DateTime(timezone=True),nullable=True)
    account_state:Mapped[str]=mapped_column(String(24),nullable=False,default="ACTIVE",index=True)
    password_hash:Mapped[str]=mapped_column(Text,nullable=False)
    is_active:Mapped[bool]=mapped_column(Boolean,nullable=False,default=True) # legacy compatibility; account_state is the lifecycle source
    is_admin:Mapped[bool]=mapped_column(Boolean,nullable=False,default=False) # legacy only; never an authorization source
    password_changed_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),nullable=False,server_default=func.now())
    password_version:Mapped[int]=mapped_column(Integer,nullable=False,default=1)
    password_must_change:Mapped[bool]=mapped_column(Boolean,nullable=False,default=False)
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),nullable=False,server_default=func.now())
    __table_args__=(CheckConstraint("account_state IN ('PENDING_VERIFICATION','ACTIVE','DISABLED','TOMBSTONED')",name="ck_users_account_state"),)

class SessionRecord(Base):
    __tablename__="sessions"
    id:Mapped[str]=mapped_column(String(36),primary_key=True,default=uuid_text)
    user_id:Mapped[int]=mapped_column(ForeignKey("users.id",ondelete="CASCADE"),nullable=False,index=True)
    token_hash:Mapped[str]=mapped_column(String(64),unique=True,nullable=False,index=True)
    csrf_token_hash:Mapped[str|None]=mapped_column(String(64),nullable=True)
    active_organisation_id:Mapped[str|None]=mapped_column(ForeignKey("organisations.id",ondelete="SET NULL"),nullable=True,index=True)
    active_participant_id:Mapped[str|None]=mapped_column(ForeignKey("participants.id",ondelete="SET NULL"),nullable=True,index=True)
    password_version:Mapped[int]=mapped_column(Integer,nullable=False,default=1)
    client_ip_hash:Mapped[str|None]=mapped_column(String(64),nullable=True)
    user_agent_hash:Mapped[str|None]=mapped_column(String(64),nullable=True)
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),nullable=False,server_default=func.now())
    last_seen_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),nullable=False,server_default=func.now(),index=True)
    expires_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),nullable=False,index=True)
    revoked_at:Mapped[datetime|None]=mapped_column(DateTime(timezone=True),nullable=True)
    user:Mapped[User]=relationship()

class ImportRecord(Base):
    __tablename__="imports"
    id:Mapped[str]=mapped_column(String(36),primary_key=True,default=uuid_text)
    organisation_id:Mapped[str|None]=mapped_column(ForeignKey("organisations.id",ondelete="RESTRICT"),nullable=True,index=True)
    participant_id:Mapped[str|None]=mapped_column(ForeignKey("participants.id",ondelete="RESTRICT"),nullable=True,index=True)
    fingerprint:Mapped[str]=mapped_column(String(64),nullable=False,index=True)
    filename:Mapped[str]=mapped_column(String(255),nullable=False)
    imported_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),nullable=False,server_default=func.now())
    imported_by:Mapped[int]=mapped_column(ForeignKey("users.id"),nullable=False)
    repeated_of_id:Mapped[str|None]=mapped_column(ForeignKey("imports.id"),nullable=True)
    new_events:Mapped[int]=mapped_column(Integer,nullable=False,default=0)
    duplicate_events:Mapped[int]=mapped_column(Integer,nullable=False,default=0)
    rejected_rows:Mapped[int]=mapped_column(Integer,nullable=False,default=0)
    row_count:Mapped[int]=mapped_column(Integer,nullable=False,default=0)
    unique_kiz:Mapped[int]=mapped_column(Integer,nullable=False,default=0)
    sales:Mapped[int]=mapped_column(Integer,nullable=False,default=0)
    returns:Mapped[int]=mapped_column(Integer,nullable=False,default=0)
    dated:Mapped[int]=mapped_column(Integer,nullable=False,default=0)
    undated:Mapped[int]=mapped_column(Integer,nullable=False,default=0)

class EventRecord(Base):
    __tablename__="events"
    event_id:Mapped[str]=mapped_column(String(64),primary_key=True) # tenant-scoped storage id
    source_event_id:Mapped[str|None]=mapped_column(String(64),nullable=True,index=True)
    organisation_id:Mapped[str|None]=mapped_column(ForeignKey("organisations.id",ondelete="RESTRICT"),nullable=True,index=True)
    participant_id:Mapped[str|None]=mapped_column(ForeignKey("participants.id",ondelete="RESTRICT"),nullable=True,index=True)
    kiz:Mapped[str]=mapped_column(Text,nullable=False,index=True)
    task_number:Mapped[str]=mapped_column(Text,nullable=False)
    sticker:Mapped[str]=mapped_column(Text,nullable=False)
    operation:Mapped[str]=mapped_column(String(16),nullable=False)
    occurred_at:Mapped[datetime|None]=mapped_column(DateTime(timezone=True),nullable=True,index=True)
    receipt_number:Mapped[str|None]=mapped_column(Text,nullable=True)
    fiscal_drive_number:Mapped[str|None]=mapped_column(Text,nullable=True)
    amount:Mapped[Decimal]=mapped_column(Numeric(18,2),nullable=False)
    currency:Mapped[str]=mapped_column(String(3),nullable=False)
    legal_entity_sale:Mapped[bool|None]=mapped_column(Boolean,nullable=True)
    payload:Mapped[dict[str,Any]]=mapped_column(JSON,nullable=False)
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),nullable=False,server_default=func.now())
    __table_args__=(UniqueConstraint("organisation_id","participant_id","source_event_id",name="uq_events_tenant_source_event"),)

class ImportRow(Base):
    __tablename__="import_rows"
    id:Mapped[int]=mapped_column(BigInteger,primary_key=True,autoincrement=True)
    import_id:Mapped[str]=mapped_column(ForeignKey("imports.id",ondelete="CASCADE"),nullable=False,index=True)
    row_number:Mapped[int]=mapped_column(Integer,nullable=False)
    event_id:Mapped[str|None]=mapped_column(ForeignKey("events.event_id"),nullable=True,index=True)
    error:Mapped[str|None]=mapped_column(Text,nullable=True)
    __table_args__=(UniqueConstraint("import_id","row_number",name="uq_import_row_number"),)

class ControlRun(Base):
    __tablename__="control_runs"
    id:Mapped[str]=mapped_column(String(36),primary_key=True,default=uuid_text)
    organisation_id:Mapped[str|None]=mapped_column(ForeignKey("organisations.id",ondelete="RESTRICT"),nullable=True,index=True)
    participant_id:Mapped[str|None]=mapped_column(ForeignKey("participants.id",ondelete="RESTRICT"),nullable=True,index=True)
    import_id:Mapped[str]=mapped_column(ForeignKey("imports.id",ondelete="CASCADE"),nullable=False,index=True)
    user_id:Mapped[int]=mapped_column(ForeignKey("users.id"),nullable=False)
    mode:Mapped[str]=mapped_column(String(32),nullable=False)
    provider:Mapped[str]=mapped_column(String(64),nullable=False)
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),nullable=False,server_default=func.now())

class CheckRecord(Base):
    __tablename__="checks"
    id:Mapped[int]=mapped_column(BigInteger,primary_key=True,autoincrement=True)
    run_id:Mapped[str]=mapped_column(ForeignKey("control_runs.id",ondelete="CASCADE"),nullable=False,index=True)
    event_id:Mapped[str]=mapped_column(ForeignKey("events.event_id",ondelete="CASCADE"),nullable=False,index=True)
    source:Mapped[str]=mapped_column(String(64),nullable=False)
    snapshot:Mapped[dict[str,Any]|None]=mapped_column(JSON,nullable=True)
    decision:Mapped[str]=mapped_column(String(32),nullable=False,index=True)
    reason:Mapped[str]=mapped_column(String(96),nullable=False)
    error:Mapped[str|None]=mapped_column(Text,nullable=True)
    checked_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),nullable=False,server_default=func.now())

class PreviewRecord(Base):
    __tablename__="previews"
    id:Mapped[str]=mapped_column(String(36),primary_key=True,default=uuid_text)
    organisation_id:Mapped[str|None]=mapped_column(ForeignKey("organisations.id",ondelete="RESTRICT"),nullable=True,index=True)
    participant_id:Mapped[str|None]=mapped_column(ForeignKey("participants.id",ondelete="RESTRICT"),nullable=True,index=True)
    import_id:Mapped[str]=mapped_column(ForeignKey("imports.id",ondelete="CASCADE"),nullable=False,index=True)
    user_id:Mapped[int]=mapped_column(ForeignKey("users.id"),nullable=False)
    mode:Mapped[str]=mapped_column(String(32),nullable=False)
    selected_count:Mapped[int]=mapped_column(Integer,nullable=False)
    eligible_count:Mapped[int]=mapped_column(Integer,nullable=False)
    withdraw_count:Mapped[int]=mapped_column(Integer,nullable=False)
    return_count:Mapped[int]=mapped_column(Integer,nullable=False)
    excluded_count:Mapped[int]=mapped_column(Integer,nullable=False)
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),nullable=False,server_default=func.now())

class PreviewItem(Base):
    __tablename__="preview_items"
    id:Mapped[int]=mapped_column(BigInteger,primary_key=True,autoincrement=True)
    preview_id:Mapped[str]=mapped_column(ForeignKey("previews.id",ondelete="CASCADE"),nullable=False,index=True)
    event_id:Mapped[str]=mapped_column(ForeignKey("events.event_id"),nullable=False)
    included:Mapped[bool]=mapped_column(Boolean,nullable=False)
    decision:Mapped[str|None]=mapped_column(String(32),nullable=True)
    reason:Mapped[str|None]=mapped_column(String(96),nullable=True)

class AuditLog(Base):
    __tablename__="audit_log"
    id:Mapped[int]=mapped_column(BigInteger,primary_key=True,autoincrement=True)
    occurred_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),nullable=False,server_default=func.now(),index=True)
    action:Mapped[str]=mapped_column(String(64),nullable=False,index=True)
    user_id:Mapped[int|None]=mapped_column(ForeignKey("users.id"),nullable=True)
    organisation_id:Mapped[str|None]=mapped_column(ForeignKey("organisations.id",ondelete="SET NULL"),nullable=True,index=True)
    participant_id:Mapped[str|None]=mapped_column(ForeignKey("participants.id",ondelete="SET NULL"),nullable=True,index=True)
    entity_type:Mapped[str|None]=mapped_column(String(32),nullable=True)
    entity_id:Mapped[str|None]=mapped_column(String(128),nullable=True)
    metadata_json:Mapped[dict[str,Any]]=mapped_column(JSON,nullable=False,default=dict)
