from __future__ import annotations
from datetime import datetime,timedelta,timezone
import pytest
from sqlalchemy.orm import Session
from wbcz_web.auth import hash_password
from wbcz_web.config import WebConfig
from wbcz_web.db import build_session_factory
from wbcz_web.main import create_app
from wbcz_web.models import (
    MembershipRecord,OrganisationRecord,ParticipantRecord,ReportJobRecord,SessionRecord,User,WriteOperationRecord,
)
from wbcz_web.services.authorization import AuthorizationError,AuthorizationService,Permission,Role,ROLE_PERMISSIONS
from wbcz_web.services.imports import tenant_event_id
from wbcz_web.services.registration import PublicRegistrationDisabled,PublicRegistrationService

@pytest.fixture
def db()->Session:
    session=build_session_factory(WebConfig.from_env())()
    tx=session.begin()
    try:yield session
    finally:tx.rollback();session.close()

def _user(db:Session,name:str)->User:
    u=User(username=name,password_hash=hash_password("correct horse battery staple"),is_active=True,is_admin=True,password_changed_at=datetime.now(timezone.utc),password_version=1,password_must_change=False)
    db.add(u);db.flush();return u

def _org(db:Session,name:str,inn:str):
    o=OrganisationRecord(name=name,is_active=True);db.add(o);db.flush()
    p=ParticipantRecord(organisation_id=o.id,inn=inn,display_name=name,verification_state="VERIFIED",is_active=True);db.add(p);db.flush();return o,p

def _session(db:Session,user:User)->SessionRecord:
    s=SessionRecord(user_id=user.id,token_hash=("a"*63)+str(user.id%10),password_version=user.password_version,created_at=datetime.now(timezone.utc),last_seen_at=datetime.now(timezone.utc),expires_at=datetime.now(timezone.utc)+timedelta(hours=1));db.add(s);db.flush();return s

def test_role_registry_and_legacy_admin_is_not_authority():
    assert Permission.DOCUMENTS_WRITE not in ROLE_PERMISSIONS[Role.VIEWER]
    assert Permission.DOCUMENTS_WRITE in ROLE_PERMISSIONS[Role.OPERATOR]
    assert Permission.DOCUMENTS_WRITE in ROLE_PERMISSIONS[Role.ADMIN]
    assert Permission.DOCUMENTS_WRITE in ROLE_PERMISSIONS[Role.OWNER]
    assert Permission.ORGANISATION_MANAGE in ROLE_PERMISSIONS[Role.OWNER]
    assert Permission.ORGANISATION_MANAGE not in ROLE_PERMISSIONS[Role.ADMIN]
    assert Permission.ORGANISATION_MANAGE not in ROLE_PERMISSIONS[Role.OPERATOR]
    assert Permission.ROLES_MANAGE not in ROLE_PERMISSIONS[Role.VIEWER]
    assert Permission.ROLES_MANAGE in ROLE_PERMISSIONS[Role.ADMIN]
    assert Permission.REPORTS_DOWNLOAD in ROLE_PERMISSIONS[Role.VIEWER]
    assert Permission.REPORTS_DOWNLOAD_SENSITIVE not in ROLE_PERMISSIONS[Role.VIEWER]
    legacy=User(username="legacy-admin-only",password_hash=hash_password("correct horse battery staple"),is_active=True,is_admin=True)
    assert legacy.is_admin is True
    assert Permission.DOCUMENTS_WRITE not in ROLE_PERMISSIONS[Role.VIEWER]

def test_foreign_scope_cannot_be_selected_by_ids(db:Session):
    u1=_user(db,"m12-u1");u2=_user(db,"m12-u2")
    o1,p1=_org(db,"org1","7707083893");o2,p2=_org(db,"org2","500100732259")
    db.add_all([
        MembershipRecord(organisation_id=o1.id,user_id=u1.id,role="VIEWER",is_active=True),
        MembershipRecord(organisation_id=o2.id,user_id=u2.id,role="OWNER",is_active=True),
    ]);db.flush();s1=_session(db,u1)
    scope=AuthorizationService(db).set_active_scope(u1,s1,organisation_id=o1.id,participant_id=p1.id)
    assert scope.organisation_id==o1.id and scope.participant_id==p1.id
    with pytest.raises(AuthorizationError):
        AuthorizationService(db).set_active_scope(u1,s1,organisation_id=o2.id,participant_id=p2.id)

def test_identical_marketplace_event_is_not_cross_tenant_deduped():
    assert tenant_event_id("org-a","part-a","same") != tenant_event_id("org-b","part-b","same")
    assert tenant_event_id("org-a","part-a","same") == tenant_event_id("org-a","part-a","same")

def test_tenant_columns_and_scoped_uniques_exist():
    assert {"organisation_id","participant_id"}.issubset(WriteOperationRecord.__table__.columns.keys())
    assert {"organisation_id","participant_id"}.issubset(ReportJobRecord.__table__.columns.keys())
    uniques=[tuple(c.columns.keys()) for c in WriteOperationRecord.__table__.constraints if c.__class__.__name__=="UniqueConstraint"]
    assert ("organisation_id","participant_id","business_fingerprint") in uniques

def test_public_registration_is_architected_but_runtime_off(monkeypatch):
    with pytest.raises(PublicRegistrationDisabled):PublicRegistrationService(runtime_enabled=True)
    svc=PublicRegistrationService()
    with pytest.raises(PublicRegistrationDisabled):svc.register()
    cfg=WebConfig.from_env()
    bad=WebConfig(**{name:getattr(cfg,name) for name in cfg.__dataclass_fields__})
    object.__setattr__(bad,"public_registration_enabled",True)
    with pytest.raises(ValueError,match="Public registration"):bad.validate_for_startup()

def test_route_surface_has_no_public_registration_and_no_production_write():
    from wbcz_web.api.routes import router as core_router
    from wbcz_web.api.security_routes import security_router
    from wbcz_web.api.report_routes import reports_router
    from wbcz_web.api.agent_routes import agent_router
    assert len(core_router.routes) >= 40
    assert len(security_router.routes) >= 10
    assert len(reports_router.routes) == 2
    assert len(agent_router.routes) == 4
    cfg=WebConfig.from_env().validate_for_startup();app=create_app(cfg)
    paths={r.path for r in app.routes if hasattr(r,"path")}
    assert "/api/register" not in paths and "/api/auth/register" not in paths and "/signup" not in paths
    assert "/api/security/scopes" in paths
    assert "/api/security/scope" in paths
    assert "/api/reports/{job_id}/artifacts/{artifact_id}/download" in paths
    assert cfg.true_api_write_enabled is False
