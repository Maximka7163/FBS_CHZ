from __future__ import annotations

import hashlib
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session


@dataclass(frozen=True, slots=True)
class TenantContext:
    user_id: int | None
    organisation_id: str
    participant_id: str
    participant_inn: str
    role: str | None = None


class TenantScopeRequired(PermissionError):
    pass


def active_tenant(db: Session) -> TenantContext:
    value=db.info.get("tenant_scope")
    if not isinstance(value,dict):
        raise TenantScopeRequired("active tenant scope required")
    organisation_id=value.get("organisation_id");participant_id=value.get("participant_id");participant_inn=value.get("participant_inn")
    if not organisation_id or not participant_id or not participant_inn:
        raise TenantScopeRequired("active organisation and participant required")
    from wbcz_web.models import OrganisationRecord, ParticipantRecord
    organisation=db.get(OrganisationRecord,str(organisation_id))
    participant=db.scalar(select(ParticipantRecord).where(
        ParticipantRecord.id==str(participant_id),
        ParticipantRecord.organisation_id==str(organisation_id),
        ParticipantRecord.is_active.is_(True),
        ParticipantRecord.verification_state=="VERIFIED",
    ))
    if (
        organisation is None or not organisation.is_active or participant is None
        or participant.inn!=str(participant_inn)
    ):
        raise TenantScopeRequired("active tenant scope is not verified")
    return TenantContext(
        user_id=value.get("user_id"),
        organisation_id=str(organisation_id),
        participant_id=str(participant_id),
        participant_inn=str(participant_inn),
        role=str(value.get("role")) if value.get("role") else None,
    )


def optional_tenant(db:Session)->TenantContext|None:
    try:return active_tenant(db)
    except TenantScopeRequired:return None


def bootstrap_completed(db:Session)->bool:
    from wbcz_web.models import BootstrapRecord
    return db.get(BootstrapRecord,1) is not None


def participant_inn_for_runtime(db:Session,legacy_fallback_inn:str)->str:
    scope=optional_tenant(db)
    if scope is not None:
        return scope.participant_inn
    if bootstrap_completed(db):
        raise TenantScopeRequired("post-bootstrap tenant scope required")
    if not legacy_fallback_inn:
        raise TenantScopeRequired("legacy participant INN unavailable")
    return legacy_fallback_inn


def bind_tenant_scope(
    db:Session,
    *,
    organisation_id:str|None,
    participant_id:str|None,
    user_id:int|None=None,
    role:str|None=None,
)->TenantContext:
    if not organisation_id or not participant_id:
        raise TenantScopeRequired("tenant-owned object has no tenant scope")
    from wbcz_web.models import OrganisationRecord,ParticipantRecord
    organisation=db.get(OrganisationRecord,organisation_id)
    participant=db.scalar(select(ParticipantRecord).where(
        ParticipantRecord.id==participant_id,
        ParticipantRecord.organisation_id==organisation_id,
        ParticipantRecord.is_active.is_(True),
        ParticipantRecord.verification_state=="VERIFIED",
    ))
    if organisation is None or not organisation.is_active or participant is None:
        raise TenantScopeRequired("tenant scope is inactive or invalid")
    db.info["tenant_scope"]={
        "user_id":user_id,"organisation_id":organisation_id,"participant_id":participant_id,
        "participant_inn":participant.inn,"role":role,
    }
    return active_tenant(db)


def tenant_namespace(db:Session,namespace:str,external_id:str)->str:
    scope=active_tenant(db)
    raw=f"m12:{namespace}:v1:{scope.organisation_id}:{scope.participant_id}:{external_id}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def tenant_operation_id(db:Session,namespace:str,external_id:str,*,prefix:str="op_")->str:
    return prefix+tenant_namespace(db,namespace,external_id)[:32]


def assert_object_scope(db:Session,organisation_id:str|None,participant_id:str|None)->TenantContext:
    scope=active_tenant(db)
    if organisation_id!=scope.organisation_id or participant_id!=scope.participant_id:
        raise KeyError("object not found")
    return scope


def scoped_agent_job(db:Session,job_id:str):
    from wbcz_web.models import AgentJobRecord
    scope=optional_tenant(db)
    stmt=select(AgentJobRecord).where(AgentJobRecord.job_id==job_id)
    if scope is not None:
        stmt=stmt.where(
            AgentJobRecord.organisation_id==scope.organisation_id,
            AgentJobRecord.participant_id==scope.participant_id,
        )
    elif bootstrap_completed(db):
        raise TenantScopeRequired("post-bootstrap tenant scope required")
    else:
        stmt=stmt.where(
            AgentJobRecord.organisation_id.is_(None),
            AgentJobRecord.participant_id.is_(None),
        )
    return db.scalar(stmt)
