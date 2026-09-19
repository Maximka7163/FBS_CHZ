from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime,timedelta,timezone
from decimal import Decimal
from hashlib import sha256
from io import BytesIO
import os
import threading
from pathlib import Path
from uuid import uuid4

import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient
from openpyxl import Workbook
from sqlalchemy import create_engine,func,select,text
from sqlalchemy.orm import Session,sessionmaker

from wbcz.m11_reports import ArtifactRole,FilesystemReportArtifactStore,ReportSensitivity
from wbcz_web.auth import hash_password,token_hash
from wbcz_web.config import WebConfig
from wbcz_web.db import build_session_factory
from wbcz_web.main import create_app
from wbcz_web.models import (
    AgentJobRecord,AggregationOperationLedgerRecord,AuditLog,Base,BootstrapRecord,ControlRun,
    DocumentLifecycleLedgerRecord,EdoLiteAnnualQuotaRecord,EdoLiteLedgerRecord,EventRecord,ImportRecord,InvitationRecord,MembershipRecord,
    OrganisationRecord,OzonConnectionRecord,OzonEventRecord,ParticipantRecord,PreviewRecord,ReportArtifactRecord,
    ReportJobRecord,ReportSnapshotRecord,SessionRecord,SuzCodeBlockRecord,SuzConnectionRecord,SuzKmVaultRecord,SuzOrderRecord,TurnoverOperationLedgerRecord,
    User,WbConnectionRecord,WbEventRecord,WriteOperationRecord,
)
from wbcz_web.repositories import ImportRepository
from wbcz_web.services import AuthService,AuthenticationError
from wbcz_web.services.authorization import (
    ActiveScope,AuthorizationError,AuthorizationService,BootstrapService,MembershipService,
    Permission,Role,ROLE_PERMISSIONS,
)
from wbcz_web.services.imports import FileImportService
from wbcz_web.services.report_downloads import (
    ReportArtifactIntegrityError,ReportDownloadService,ReportDownloadUnavailable,
)
from wbcz_web.services.reports import EnvironmentArtifactKeyProvider


DB_URL=os.getenv("WBCZ_TEST_DATABASE_URL") or os.getenv("WBCZ_DATABASE_URL")
pytestmark=pytest.mark.skipif(not DB_URL,reason="M12 integration tests require PostgreSQL")
NOW=lambda:datetime.now(timezone.utc)
PASSWORD="correct horse battery staple"
HEADERS=["№ задания","Стикер","КИЗ","Номер чека","Стоимость","Валюта","Номер фискального накопителя","Дата","Тип операции","Признак продажи юрлицу"]


@pytest.fixture
def db()->Session:
    session=build_session_factory(WebConfig.from_env())()
    tx=session.begin()
    session.execute(text("""
        TRUNCATE TABLE
          agent_jobs, report_jobs, edo_lite_ledger, edo_lite_annual_quota,
          suz_connections, wb_connections, ozon_connections,
          write_operations, document_lifecycle_ledger, turnover_operation_ledger,
          aggregation_operation_ledger, imports, users, organisations
        RESTART IDENTITY CASCADE
    """))
    try:
        yield session
    finally:
        tx.rollback()
        session.close()


def _user(db:Session,name:str,*,legacy_admin:bool=False)->User:
    row=User(
        username=name,password_hash=hash_password(PASSWORD),is_active=True,is_admin=legacy_admin,
        password_changed_at=NOW(),password_version=1,password_must_change=False,
    )
    db.add(row);db.flush();return row


def _org(db:Session,name:str,inn:str,*,verified:bool=True):
    org=OrganisationRecord(name=name,is_active=True);db.add(org);db.flush()
    participant=ParticipantRecord(
        organisation_id=org.id,inn=inn,display_name=name,
        verification_state="VERIFIED" if verified else "UNVERIFIED",is_active=True,
    )
    db.add(participant);db.flush();return org,participant


def _membership(db:Session,user:User,org:OrganisationRecord,role:Role)->MembershipRecord:
    row=MembershipRecord(organisation_id=org.id,user_id=user.id,role=role.value,is_active=True)
    db.add(row);db.flush();return row


def _session(db:Session,user:User,*,raw:str|None=None)->tuple[SessionRecord,str]:
    raw=raw or ("m12-session-"+uuid4().hex)
    row=SessionRecord(
        user_id=user.id,token_hash=token_hash(raw),password_version=user.password_version,
        created_at=NOW(),last_seen_at=NOW(),expires_at=NOW()+timedelta(hours=2),
    )
    db.add(row);db.flush();return row,raw


def _scope(db:Session,user:User,session:SessionRecord,org:OrganisationRecord,participant:ParticipantRecord):
    return AuthorizationService(db).set_active_scope(
        user,session,organisation_id=org.id,participant_id=participant.id,
    )


def _xlsx(*,task:str="T-1",kiz:str="KIZ-M12-001")->bytes:
    wb=Workbook();ws=wb.active;ws.title="КИЗ";ws.append(HEADERS)
    ws.append([task,"S-1",kiz,"CHK-1",100,"RUB","FN-1","12:00:00 01.08.2026","Продажа","нет"])
    out=BytesIO();wb.save(out);return out.getvalue()


def _seed_ab(db:Session):
    ua=_user(db,"m12-a-"+uuid4().hex[:8],legacy_admin=True)
    ub=_user(db,"m12-b-"+uuid4().hex[:8],legacy_admin=True)
    dual=_user(db,"m12-dual-"+uuid4().hex[:8],legacy_admin=True)
    oa,pa=_org(db,"Org A","7707083893")
    ob,pb=_org(db,"Org B","500100732259")
    _membership(db,ua,oa,Role.OWNER);_membership(db,ub,ob,Role.OWNER)
    _membership(db,dual,oa,Role.VIEWER);_membership(db,dual,ob,Role.OPERATOR)
    sa,_=_session(db,ua);sb,_=_session(db,ub);sd,_=_session(db,dual)
    return ua,ub,dual,oa,pa,ob,pb,sa,sb,sd


def test_multi_org_scope_and_unverified_participant_fail_closed(db:Session):
    ua,ub,dual,oa,pa,ob,pb,sa,sb,sd=_seed_ab(db)
    authz=AuthorizationService(db)
    a=authz.set_active_scope(dual,sd,organisation_id=oa.id,participant_id=pa.id)
    assert a.organisation_id==oa.id and a.role is Role.VIEWER
    b=authz.set_active_scope(dual,sd,organisation_id=ob.id,participant_id=pb.id)
    assert b.organisation_id==ob.id and b.role is Role.OPERATOR
    with pytest.raises(AuthorizationError):
        authz.set_active_scope(ua,sa,organisation_id=ob.id,participant_id=pb.id)
    _,unverified=_org(db,"Unverified","781201234567",verified=False)
    with pytest.raises(AuthorizationError):
        authz.set_active_scope(ua,sa,organisation_id=oa.id,participant_id=unverified.id)


def test_tenant_aware_file_event_dedup_and_kiz_history(db:Session):
    ua,ub,_,oa,pa,ob,pb,sa,sb,_=_seed_ab(db)
    base=_xlsx();variant=_xlsx(task="T-2")
    scope_a=_scope(db,ua,sa,oa,pa)
    one=FileImportService(db).import_xlsx("same.xlsx",base,ua.id)
    ids_a1=ImportRepository(db).import_event_ids(one.id)
    two=FileImportService(db).import_xlsx("same.xlsx",base,ua.id)
    ids_a2=ImportRepository(db).import_event_ids(two.id)
    assert one.new_events==1 and two.new_events==0 and two.duplicate_events==1
    assert two.repeated_of_id==one.id and ids_a1==ids_a2
    FileImportService(db).import_xlsx("variant.xlsx",variant,ua.id)
    assert len(ImportRepository(db).history_for_kiz("KIZ-M12-001"))==2

    scope_b=_scope(db,ub,sb,ob,pb)
    three=FileImportService(db).import_xlsx("same.xlsx",base,ub.id)
    ids_b=ImportRepository(db).import_event_ids(three.id)
    assert three.new_events==1 and three.duplicate_events==0 and three.repeated_of_id is None
    assert ids_b[0]!=ids_a1[0]
    assert len(ImportRepository(db).history_for_kiz("KIZ-M12-001"))==1

    db.info.pop("tenant_scope",None)
    db.add(BootstrapRecord(id=1,organisation_id=oa.id,owner_user_id=ua.id,participant_id=pa.id,metadata_json={"test":True}))
    db.flush()
    with pytest.raises(PermissionError):
        ImportRepository(db).list_recent()


def _domain_roots(db:Session,org:OrganisationRecord,part:ParticipantRecord,user:User,suffix:str):
    imp=ImportRecord(
        organisation_id=org.id,participant_id=part.id,fingerprint=(suffix*64)[:64],
        filename=f"{suffix}.xlsx",imported_by=user.id,
    );db.add(imp);db.flush()
    event=EventRecord(
        event_id=(suffix+"e"*64)[:64],source_event_id=(suffix+"s"*64)[:64],
        organisation_id=org.id,participant_id=part.id,kiz=f"KIZ-{suffix}",task_number="T",
        sticker="S",operation="SALE",amount=Decimal("1.00"),currency="RUB",payload={},
    );db.add(event);db.flush()
    control=ControlRun(
        import_id=imp.id,organisation_id=org.id,participant_id=part.id,user_id=user.id,
        mode="CONTROL",provider="test",
    )
    preview=PreviewRecord(
        import_id=imp.id,organisation_id=org.id,participant_id=part.id,user_id=user.id,
        mode="AUTO",selected_count=0,eligible_count=0,withdraw_count=0,return_count=0,excluded_count=0,
    )
    job=AgentJobRecord(
        job_id=f"job-{suffix}",organisation_id=org.id,participant_id=part.id,job_type="CIS_INFO",
        operation_id=f"read-{suffix}",purpose="CIS_INVENTORY",poll_attempt=0,
        payload_sha256=(suffix+"a"*64)[:64],
        payload_json={"job_type":"CIS_INFO","operation_id":f"read-{suffix}","pg":"lp","expected_inn":part.inn,"cises":[]},
        state="PENDING",available_at=NOW(),delivery_count=0,
    )
    m4=DocumentLifecycleLedgerRecord(
        operation_id=f"m4-{suffix}",organisation_id=org.id,participant_id=part.id,
        request_id="req-shared",job_type="DOCUMENT_LIST",
        request_sha256=(suffix+"b"*64)[:64],idempotency_key=f"idem-{suffix}",request_json={},
    )
    m5=TurnoverOperationLedgerRecord(
        operation_id=f"m5-{suffix}",organisation_id=org.id,participant_id=part.id,
        request_id="turn-shared",operation_kind="LP_INTRODUCE_GOODS",document_type="LP_INTRODUCE_GOODS",
        document_sha256=(suffix+"c"*64)[:64],request_sha256=(suffix+"d"*64)[:64],
        idempotency_key=f"idem5-{suffix}",precondition_snapshot={},expected_postcondition={},
        reconciliation_state="RECONCILIATION_PENDING",reconciliation_json={},
    )
    m6=AggregationOperationLedgerRecord(
        operation_id=f"m6-{suffix}",organisation_id=org.id,participant_id=part.id,
        request_id="agg-shared",operation_kind="FORM_TRANSPORT_PACKAGE",
        document_type="AGGREGATION_DOCUMENT",document_sha256=(suffix+"f"*64)[:64],
        request_sha256=(suffix+"g"*64)[:64],idempotency_key=f"idem6-{suffix}",
        child_set_hash=(suffix+"h"*64)[:64],relation_delta="FORM",
        precondition_snapshot={},expected_relation_delta={},reconciliation_state="RECONCILIATION_PENDING",
        reconciliation_json={},raw_history_evidence=[],
    )
    m7=EdoLiteLedgerRecord(
        operation_id="m7-shared-operation",organisation_id=org.id,participant_id=part.id,
        direction="UNKNOWN",normalized_local_state="FOUNDATION",evidence_json={},
    )
    suz=SuzConnectionRecord(
        organisation_id=org.id,participant_id=part.id,participant_inn=part.inn,
        oms_id=f"oms-{suffix}",oms_connection="shared-oms-connection",
        environment="PRODUCTION",installation_name=f"inst-{suffix}",connection_state="ACTIVE",
    )
    wb=WbConnectionRecord(
        organisation_id=org.id,participant_id=part.id,environment="PRODUCTION",
        participant_inn=part.inn,wb_tin=part.inn,token_type="PERSONAL",
        token_categories=[],token_scopes=[],secret_ref=f"wb-secret-{suffix}",connection_state="HEALTHY",
    )
    oz=OzonConnectionRecord(
        organisation_id=org.id,participant_id=part.id,participant_inn=part.inn,
        client_id=f"client-{suffix}",api_key_secret_ref=f"oz-secret-{suffix}",
        roles_metadata=[],capability_metadata=[],connection_state="HEALTHY",
    )
    report=ReportJobRecord(
        id=f"rpt-{suffix}",organisation_id=org.id,participant_id=part.id,origin="LOCAL",
        participant_inn=part.inn,report_type="DOCUMENT_LIFECYCLE",report_schema_version="1",
        output_format="CSV",sensitivity_class="NORMAL",filters_sanitized_json={},
        request_fingerprint_sha256=(suffix+"r"*64)[:64],state="READY",remote_metadata_sanitized={},
        remote_create_ambiguous=False,requested_at=NOW(),attempt_count=0,
    )
    write=WriteOperationRecord(
        operation_id=f"op-{suffix}",organisation_id=org.id,participant_id=part.id,
        business_fingerprint="f"*64,event_id=event.event_id,decision="READY_TO_WITHDRAW",
        document_type="LK_RECEIPT",operation_reason="DISTANCE",pg="lp",expected_inn=part.inn,
        document_sha256=sha256(b"x").hexdigest(),product_document_base64="eA==",
        state="AWAITING_SIGNATURE",document_id="REMOTE-DOC-SHARED",
    )
    db.add(suz);db.flush()
    suz_order=SuzOrderRecord(
        operation_id="shared-suz-operation",connection_id=suz.id,remote_order_id="REMOTE-ORDER-SHARED",
        request_sha256="9"*64,raw_release_method="REMAINS",requested_count=1,
        reconciliation_state="FOUNDATION",submission_state="NOT_SUBMITTED",
    )
    db.add_all([control,preview,job,m4,m5,m6,m7,suz_order,wb,oz,report,write]);db.flush()
    return {
        "import":imp.id,"event":event.event_id,"control_run":control.id,"preview":preview.id,
        "agent_job":job.job_id,"write_operation":write.operation_id,"document_lifecycle":m4.operation_id,
        "turnover_operation":m5.operation_id,"aggregation_operation":m6.operation_id,
        "edo_lite":m7.id,"suz_connection":suz.id,"suz_order":suz_order.id,"wb_connection":wb.id,
        "ozon_connection":oz.id,"report_job":report.id,
    }


def test_object_authorization_covers_m1_to_m11_roots_and_null_scope(db:Session):
    ua,ub,_,oa,pa,ob,pb,sa,sb,_=_seed_ab(db)
    aroot=_domain_roots(db,oa,pa,ua,"a")
    broot=_domain_roots(db,ob,pb,ub,"b")
    scope_a=_scope(db,ua,sa,oa,pa)
    authz=AuthorizationService(db)
    permissions={
        "import":Permission.IMPORTS_READ,"event":Permission.IMPORTS_READ,"control_run":Permission.CONTROL_RUN,
        "preview":Permission.CONTROL_RUN,"agent_job":Permission.CIS_READ,"write_operation":Permission.CONTROL_RUN,
        "document_lifecycle":Permission.DOCUMENTS_READ,"turnover_operation":Permission.TURNOVER_READ,
        "aggregation_operation":Permission.AGGREGATION_READ,"edo_lite":Permission.EDO_READ,
        "suz_connection":Permission.SUZ_READ,"suz_order":Permission.SUZ_READ,"wb_connection":Permission.WB_READ,
        "ozon_connection":Permission.OZON_READ,"report_job":Permission.REPORTS_READ,
    }
    for kind,perm in permissions.items():
        authz.authorize_object(scope_a,perm,kind,aroot[kind])
        with pytest.raises(KeyError):
            authz.authorize_object(scope_a,perm,kind,broot[kind])
    null_imp=ImportRecord(fingerprint="n"*64,filename="legacy.xlsx",imported_by=ua.id)
    db.add(null_imp);db.flush()
    with pytest.raises(KeyError):
        authz.authorize_object(scope_a,Permission.IMPORTS_READ,"import",null_imp.id)


def test_same_business_fingerprint_is_allowed_across_tenants(db:Session):
    ua,ub,_,oa,pa,ob,pb,sa,sb,_=_seed_ab(db)
    _domain_roots(db,oa,pa,ua,"x")
    _domain_roots(db,ob,pb,ub,"y")
    rows=list(db.scalars(select(WriteOperationRecord).where(WriteOperationRecord.business_fingerprint=="f"*64)))
    assert len(rows)==2
    assert {(r.organisation_id,r.participant_id) for r in rows}=={(oa.id,pa.id),(ob.id,pb.id)}


def test_m7_m8_m9_m10_idempotency_keys_do_not_cross_tenants(db:Session):
    ua,ub,_,oa,pa,ob,pb,sa,sb,_=_seed_ab(db)
    aroot=_domain_roots(db,oa,pa,ua,"ia")
    broot=_domain_roots(db,ob,pb,ub,"ib")

    qa=EdoLiteAnnualQuotaRecord(
        organisation_id=oa.id,participant_id=pa.id,year=2026,
        local_observed_outgoing_count=1,source_evidence="tenant-a",
    )
    qb=EdoLiteAnnualQuotaRecord(
        organisation_id=ob.id,participant_id=pb.id,year=2026,
        local_observed_outgoing_count=1,source_evidence="tenant-b",
    )
    db.add_all([qa,qb])

    for root,label in ((aroot,"a"),(broot,"b")):
        order=db.get(SuzOrderRecord,root["suz_order"]);assert order is not None
        vault=SuzKmVaultRecord(
            order_id=order.id,order_operation_id=order.operation_id,gtin="04600000000001",
            ciphertext=(b"x"+label.encode()),nonce=b"n"*12,auth_tag=b"a"*16,
            key_version="v1",vault_format_version="v1",aad_hash=("a" if label=="a" else "b")*64,
            plaintext_sha256=("c" if label=="a" else "d")*64,
            ciphertext_sha256=("e" if label=="a" else "f")*64,code_count=1,
        )
        db.add(vault);db.flush()
        db.add(SuzCodeBlockRecord(
            local_block_id="shared-local-block",order_id=order.id,order_operation_id=order.operation_id,
            gtin="04600000000001",code_count=1,exact_payload_sha256=("1" if label=="a" else "2")*64,
            vault_entry_id=vault.id,fetch_state="FOUNDATION",recovery_state="FOUNDATION",received_at=NOW(),
        ))

    for connection_id,label in ((aroot["wb_connection"],"a"),(broot["wb_connection"],"b")):
        db.add(WbEventRecord(
            connection_id=connection_id,source="WB_API",source_family="ORDER_FEED",
            source_fingerprint="3"*64,raw_evidence_sanitized={"tenant":label},
            raw_evidence_hash=("4" if label=="a" else "5")*64,observed_at=NOW(),
        ))
    for connection_id,label in ((aroot["ozon_connection"],"a"),(broot["ozon_connection"],"b")):
        db.add(OzonEventRecord(
            connection_id=connection_id,source_capability="POSTING_FBS",
            source_fingerprint="6"*64,evidence_type="STATUS",conflict_state="NONE",
            remote_identities_sanitized={"tenant":label},raw_evidence_sanitized={},
            raw_sanitized_hash=("7" if label=="a" else "8")*64,
            evidence_hash=("9" if label=="a" else "a")*64,observed_at=NOW(),
        ))
    db.flush()

    assert db.scalar(select(EdoLiteAnnualQuotaRecord).where(
        EdoLiteAnnualQuotaRecord.organisation_id==oa.id,EdoLiteAnnualQuotaRecord.year==2026
    )) is qa
    assert db.scalar(select(EdoLiteAnnualQuotaRecord).where(
        EdoLiteAnnualQuotaRecord.organisation_id==ob.id,EdoLiteAnnualQuotaRecord.year==2026
    )) is qb
    assert len(list(db.scalars(select(SuzOrderRecord).where(SuzOrderRecord.operation_id=="shared-suz-operation"))))==2
    assert len(list(db.scalars(select(SuzCodeBlockRecord).where(SuzCodeBlockRecord.local_block_id=="shared-local-block"))))==2
    assert len(list(db.scalars(select(WbEventRecord).where(WbEventRecord.source_fingerprint=="3"*64))))==2
    assert len(list(db.scalars(select(OzonEventRecord).where(OzonEventRecord.source_fingerprint=="6"*64))))==2


def test_rbac_admin_limits_last_owner_and_invitation_safety(db:Session):
    owner=_user(db,"owner-"+uuid4().hex[:8]);admin=_user(db,"admin-"+uuid4().hex[:8]);invitee=_user(db,"invitee-"+uuid4().hex[:8])
    org,part=_org(db,"Invite Org","6677889900")
    owner_m=_membership(db,owner,org,Role.OWNER);admin_m=_membership(db,admin,org,Role.ADMIN)
    osession,_=_session(db,owner);asession,_=_session(db,admin)
    owner_scope=_scope(db,owner,osession,org,part)
    admin_scope=_scope(db,admin,asession,org,part)
    svc=MembershipService(db)
    with pytest.raises(AuthorizationError):svc.change_role(owner_scope,owner_m.id,Role.ADMIN)
    with pytest.raises(AuthorizationError):svc.create_invitation(
        admin_scope,invitee_username=invitee.username,role=Role.ADMIN,participant_id=part.id,expires_at=NOW()+timedelta(hours=1)
    )
    row,raw=svc.create_invitation(
        owner_scope,invitee_username=invitee.username,role=Role.ADMIN,participant_id=part.id,expires_at=NOW()+timedelta(hours=1)
    )
    assert row.token_hash==token_hash(raw) and row.token_hash!=raw and len(raw)>=32
    wrong=_user(db,"wrong-invitee-"+uuid4().hex[:8])
    with pytest.raises(AuthorizationError):svc.accept_invitation(wrong,raw)
    assert row.state=="PENDING"
    member=svc.accept_invitation(invitee,raw)
    assert member.role==Role.ADMIN.value and member.organisation_id==org.id
    with pytest.raises(AuthorizationError):svc.accept_invitation(invitee,raw)

    other=_user(db,"other-"+uuid4().hex[:8])
    exp,_=svc.create_invitation(
        owner_scope,invitee_username=other.username,role=Role.VIEWER,participant_id=None,expires_at=NOW()-timedelta(seconds=1)
    )
    with pytest.raises(AuthorizationError):svc.accept_invitation(other,_)
    assert exp.state=="EXPIRED"

    third=_user(db,"third-"+uuid4().hex[:8])
    other_owner=_user(db,"other-owner-"+uuid4().hex[:8])
    other_org,other_part=_org(db,"Other Invite Org","7733557799")
    _membership(db,other_owner,other_org,Role.OWNER)
    other_session,_=_session(db,other_owner)
    other_scope=_scope(db,other_owner,other_session,other_org,other_part)
    foreign_invite,_foreign_token=svc.create_invitation(
        other_scope,invitee_username=third.username,role=Role.VIEWER,participant_id=other_part.id,expires_at=NOW()+timedelta(hours=1)
    )
    with pytest.raises(KeyError):svc.revoke_invitation(owner_scope,foreign_invite.id)

    rev,rev_token=svc.create_invitation(
        owner_scope,invitee_username=third.username,role=Role.VIEWER,participant_id=None,expires_at=NOW()+timedelta(hours=1)
    )
    svc.revoke_invitation(owner_scope,rev.id)
    assert rev.state=="REVOKED"
    with pytest.raises(AuthorizationError):svc.accept_invitation(third,rev_token)


def test_invitation_concurrent_acceptance_is_single_use():
    engine=create_engine(DB_URL,future=True)
    factory=sessionmaker(bind=engine,expire_on_commit=False)
    tag=uuid4().hex[:10]
    inn=str(810000000000+(int(tag[:8],16)%100000000000))
    with factory() as seed:
        owner=_user(seed,f"invite-owner-{tag}")
        invitee=_user(seed,f"invite-user-{tag}")
        org,part=_org(seed,f"Invite Race {tag}",inn)
        _membership(seed,owner,org,Role.OWNER)
        actor=ActiveScope(owner.id,org.id,part.id,part.inn,Role.OWNER,ROLE_PERMISSIONS[Role.OWNER])
        invitation,raw=MembershipService(seed).create_invitation(
            actor,invitee_username=invitee.username,role=Role.VIEWER,participant_id=part.id,
            expires_at=NOW()+timedelta(hours=1),
        )
        seed.commit()
        ids=(owner.id,invitee.id,org.id,part.id,invitation.id)
    barrier=threading.Barrier(2)

    def accept_once()->str:
        with factory() as db2:
            user=db2.get(User,ids[1]);assert user is not None
            barrier.wait(timeout=10)
            try:
                MembershipService(db2).accept_invitation(user,raw)
                db2.commit()
                return "accepted"
            except AuthorizationError:
                db2.rollback()
                return "blocked"

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            a=pool.submit(accept_once);b=pool.submit(accept_once)
            assert sorted([a.result(timeout=20),b.result(timeout=20)])==["accepted","blocked"]
        with factory() as check:
            invitation=check.get(InvitationRecord,ids[4]);assert invitation is not None
            assert invitation.state=="ACCEPTED" and invitation.accepted_by_user_id==ids[1]
            memberships=list(check.scalars(select(MembershipRecord).where(
                MembershipRecord.organisation_id==ids[2],MembershipRecord.user_id==ids[1],
                MembershipRecord.is_active.is_(True),
            )))
            assert len(memberships)==1
    finally:
        with factory() as cleanup:
            for row in list(cleanup.scalars(select(InvitationRecord).where(InvitationRecord.organisation_id==ids[2]))):
                cleanup.delete(row)
            for row in list(cleanup.scalars(select(MembershipRecord).where(MembershipRecord.organisation_id==ids[2]))):
                cleanup.delete(row)
            participant=cleanup.get(ParticipantRecord,ids[3])
            if participant is not None:cleanup.delete(participant)
            organisation=cleanup.get(OrganisationRecord,ids[2])
            if organisation is not None:cleanup.delete(organisation)
            for user_id in (ids[0],ids[1]):
                user=cleanup.get(User,user_id)
                if user is not None:cleanup.delete(user)
            cleanup.commit()
        engine.dispose()


def test_last_owner_concurrent_demotion_preserves_one_active_owner():
    engine=create_engine(DB_URL,future=True)
    factory=sessionmaker(bind=engine,expire_on_commit=False)
    tag=uuid4().hex[:10]
    inn=str(700000000000+(int(tag[:8],16)%100000000000))
    with factory() as seed:
        u1=_user(seed,f"race-owner-a-{tag}")
        u2=_user(seed,f"race-owner-b-{tag}")
        org,part=_org(seed,f"Race Org {tag}",inn)
        m1=_membership(seed,u1,org,Role.OWNER)
        m2=_membership(seed,u2,org,Role.OWNER)
        seed.commit()
        ids=(u1.id,u2.id,org.id,part.id,m1.id,m2.id,part.inn)
    barrier=threading.Barrier(2)

    def attempt(user_id:int,membership_id:str)->str:
        with factory() as db2:
            scope=ActiveScope(
                user_id=user_id,organisation_id=ids[2],participant_id=ids[3],
                participant_inn=ids[6],role=Role.OWNER,permissions=ROLE_PERMISSIONS[Role.OWNER],
            )
            barrier.wait(timeout=10)
            try:
                MembershipService(db2).change_role(scope,membership_id,Role.ADMIN)
                db2.commit()
                return "demoted"
            except AuthorizationError:
                db2.rollback()
                return "blocked"

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            fa=pool.submit(attempt,ids[0],ids[4])
            fb=pool.submit(attempt,ids[1],ids[5])
            results=sorted([fa.result(timeout=20),fb.result(timeout=20)])
        assert results==["blocked","demoted"]
        with factory() as check:
            owners=check.scalar(select(func.count()).select_from(MembershipRecord).where(
                MembershipRecord.organisation_id==ids[2],
                MembershipRecord.role==Role.OWNER.value,
                MembershipRecord.is_active.is_(True),
            ))
            assert owners==1
    finally:
        with factory() as cleanup:
            for membership_id in (ids[4],ids[5]):
                row=cleanup.get(MembershipRecord,membership_id)
                if row is not None: cleanup.delete(row)
            participant=cleanup.get(ParticipantRecord,ids[3])
            if participant is not None: cleanup.delete(participant)
            organisation=cleanup.get(OrganisationRecord,ids[2])
            if organisation is not None: cleanup.delete(organisation)
            for user_id in (ids[0],ids[1]):
                user=cleanup.get(User,user_id)
                if user is not None: cleanup.delete(user)
            cleanup.commit()
        engine.dispose()


def test_auth_absolute_idle_throttle_password_and_disable(db:Session):
    user=_user(db,"auth-"+uuid4().hex[:8])
    cfg=replace(WebConfig.from_env(),session_ttl_seconds=3600,session_idle_timeout_seconds=300,login_throttle_max_failures=3)
    svc=AuthService(db,cfg)
    _,raw=svc.login(user.username,PASSWORD,csrf_token="csrf-a",remote_address="198.51.100.10",user_agent="m12")
    _,session=svc.authenticate_token(raw)
    assert svc.csrf_matches(session,"csrf-a")
    session.last_seen_at=NOW()-timedelta(seconds=301);db.flush()
    with pytest.raises(AuthenticationError):svc.authenticate_token(raw)
    assert session.revoked_at is not None

    _,absolute=svc.login(user.username,PASSWORD,remote_address="198.51.100.11")
    row=svc.sessions.active_by_hash(token_hash(absolute));assert row is not None
    row.expires_at=NOW()-timedelta(seconds=1);db.flush()
    with pytest.raises(AuthenticationError):svc.authenticate_token(absolute)

    throttle_user=_user(db,"throttle-"+uuid4().hex[:8])
    remote="203.0.113."+str((throttle_user.id%200)+1)
    for _ in range(3):
        with pytest.raises(AuthenticationError):AuthService(db,cfg).login(throttle_user.username,"wrong-password-value",remote_address=remote)
    with pytest.raises(AuthenticationError):AuthService(db,cfg).login(throttle_user.username,PASSWORD,remote_address=remote)
    assert db.scalar(select(AuditLog).where(AuditLog.action=="LOGIN_THROTTLED").limit(1)) is not None

    _,pw_token=AuthService(db,cfg).login(user.username,PASSWORD,remote_address="192.0.2.55")
    AuthService(db,cfg).change_password(user,current_password=PASSWORD,new_password="new correct horse battery staple")
    with pytest.raises(AuthenticationError):AuthService(db,cfg).authenticate_token(pw_token)

    _,disabled_token=AuthService(db,cfg).login(user.username,"new correct horse battery staple",remote_address="192.0.2.56")
    user.is_active=False;db.flush()
    with pytest.raises(AuthenticationError):AuthService(db,cfg).authenticate_token(disabled_token)


def test_logout_all_password_rehash_and_membership_changes_are_immediate(db:Session):
    user=_user(db,"policy-"+uuid4().hex[:8])
    org,part=_org(db,"Policy Org","7722334455")
    membership=_membership(db,user,org,Role.OPERATOR)
    cfg=WebConfig.from_env()

    # Legacy Argon2id hashes with weaker parameters remain usable and rehash on success.
    weak=PasswordHasher(time_cost=1,memory_cost=8192,parallelism=1)
    user.password_hash=weak.hash(PASSWORD);db.flush()
    old_hash=user.password_hash
    _,raw1=AuthService(db,cfg).login(user.username,PASSWORD,remote_address="192.0.2.101")
    assert user.password_hash!=old_hash and user.password_hash.startswith("$argon2id$")

    session1=db.scalar(select(SessionRecord).where(SessionRecord.token_hash==token_hash(raw1)));assert session1 is not None
    _scope(db,user,session1,org,part)
    _,raw2=AuthService(db,cfg).login(user.username,PASSWORD,remote_address="192.0.2.102")
    revoked=AuthService(db,cfg).logout_all(user.id)
    assert revoked>=2
    with pytest.raises(AuthenticationError):AuthService(db,cfg).authenticate_token(raw1)
    with pytest.raises(AuthenticationError):AuthService(db,cfg).authenticate_token(raw2)

    # New active session is revoked immediately when role changes.
    _,raw3=AuthService(db,cfg).login(user.username,PASSWORD,remote_address="192.0.2.103")
    session3=db.scalar(select(SessionRecord).where(SessionRecord.token_hash==token_hash(raw3)));assert session3 is not None
    scope=_scope(db,user,session3,org,part)
    MembershipService(db).change_role(
        ActiveScope(user.id,org.id,part.id,part.inn,Role.OWNER,ROLE_PERMISSIONS[Role.OWNER]),
        membership.id,Role.VIEWER,
    )
    with pytest.raises(AuthenticationError):AuthService(db,cfg).authenticate_token(raw3)

    # Membership removal also kills active tenant session immediately.
    _,raw4=AuthService(db,cfg).login(user.username,PASSWORD,remote_address="192.0.2.104")
    session4=db.scalar(select(SessionRecord).where(SessionRecord.token_hash==token_hash(raw4)));assert session4 is not None
    _scope(db,user,session4,org,part)
    MembershipService(db).remove(
        ActiveScope(user.id,org.id,part.id,part.inn,Role.OWNER,ROLE_PERMISSIONS[Role.OWNER]),
        membership.id,
    )
    with pytest.raises(AuthenticationError):AuthService(db,cfg).authenticate_token(raw4)


def test_bootstrap_backfills_roles_and_rejects_conflicting_inn(db:Session):
    owner=_user(db,"legacy-owner-"+uuid4().hex[:8],legacy_admin=False)
    admin=_user(db,"legacy-admin-"+uuid4().hex[:8],legacy_admin=True)
    operator=_user(db,"legacy-operator-"+uuid4().hex[:8],legacy_admin=False)
    legacy_session,_=_session(db,operator)
    job=AgentJobRecord(
        job_id="legacy-"+uuid4().hex,job_type="CIS_INFO",operation_id="legacy-read",purpose="CIS_INVENTORY",
        poll_attempt=0,payload_sha256="1"*64,
        payload_json={"job_type":"CIS_INFO","operation_id":"legacy-read","pg":"lp","expected_inn":"7707083893","cises":[]},
        state="PENDING",available_at=NOW(),delivery_count=0,
    );db.add(job);db.flush()
    user,org,part,_=BootstrapService(db).bootstrap(
        username=owner.username,password="bootstrap secure password 123",
        organisation_name="Legacy Org",participant_inn="7707083893",
    )
    memberships={m.user_id:m.role for m in db.scalars(select(MembershipRecord).where(MembershipRecord.organisation_id==org.id))}
    assert memberships[user.id]=="OWNER"
    assert memberships[admin.id]=="ADMIN"
    assert memberships[operator.id]=="OPERATOR"
    db.refresh(job)
    db.refresh(legacy_session)
    assert job.organisation_id==org.id and job.participant_id==part.id
    assert legacy_session.revoked_at is not None
    assert db.get(BootstrapRecord,1) is not None
    with pytest.raises(AuthorizationError):
        BootstrapService(db).bootstrap(
            username=owner.username,password="another secure password 123",
            organisation_name="Second",participant_inn="7707083893",
        )


def test_bootstrap_conflicting_historical_inns_rolls_back_before_org_creation(db:Session):
    user=_user(db,"legacy-conflict-"+uuid4().hex[:8])
    for n,inn in enumerate(("7707083893","500100732259"),start=1):
        db.add(AgentJobRecord(
            job_id=f"conflict-{n}-{uuid4().hex}",job_type="CIS_INFO",operation_id=f"legacy-{n}",
            purpose="CIS_INVENTORY",poll_attempt=0,payload_sha256=str(n)*64,
            payload_json={"job_type":"CIS_INFO","operation_id":f"legacy-{n}","pg":"lp","expected_inn":inn,"cises":[]},
            state="PENDING",available_at=NOW(),delivery_count=0,
        ))
    db.flush();before=list(db.scalars(select(OrganisationRecord)))
    with pytest.raises(AuthorizationError,match="conflicting"):
        BootstrapService(db).bootstrap(
            username=user.username,password="bootstrap secure password 123",
            organisation_name="Conflict",participant_inn="7707083893",
        )
    assert list(db.scalars(select(OrganisationRecord)))==before
    assert db.get(BootstrapRecord,1) is None


@pytest.fixture
def web_env():
    engine=create_engine(DB_URL,future=True)
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    factory=sessionmaker(bind=engine,expire_on_commit=False)
    cfg=replace(
        WebConfig.from_env(),environment="test",agent_enabled=True,
        agent_machine_token="m12-agent-machine-token-1234567890",true_api_write_enabled=False,
        login_throttle_max_failures=3,
    ).validate_for_startup()
    with factory() as seed:
        user=_user(seed,"browser-"+uuid4().hex[:8])
        org,part=_org(seed,"Browser Org","7712345678")
        _membership(seed,user,org,Role.OWNER)
        username=user.username;org_id=org.id;part_id=part.id
        seed.commit()
    app=create_app(cfg,session_factory=factory)
    try:
        with TestClient(app) as client:
            yield client,factory,cfg,username,org_id,part_id
    finally:
        engine.dispose()


def test_session_bound_csrf_rotation_and_browser_agent_isolation(web_env):
    client,factory,cfg,username,org_id,part_id=web_env
    csrf=client.get("/api/auth/csrf").json()["csrf_token"]
    login=client.post("/api/auth/login",json={"username":username,"password":PASSWORD},headers={"X-CSRF-Token":csrf})
    assert login.status_code==200
    first_cookie=client.cookies.get(cfg.session_cookie_name)
    assert first_cookie
    switched=client.post("/api/security/scope",json={"organisation_id":org_id,"participant_id":part_id},headers={"X-CSRF-Token":csrf})
    assert switched.status_code==200,switched.text

    csrf2=client.get("/api/auth/csrf").json()["csrf_token"]
    assert csrf2!=csrf
    stale=client.post(
        "/api/security/scope",
        json={"organisation_id":org_id,"participant_id":part_id},
        headers={"X-CSRF-Token":csrf},
    )
    assert stale.status_code==403
    rebound=client.post(
        "/api/security/scope",
        json={"organisation_id":org_id,"participant_id":part_id},
        headers={"X-CSRF-Token":csrf2},
    )
    assert rebound.status_code==200,rebound.text
    second=client.post("/api/auth/login",json={"username":username,"password":PASSWORD},headers={"X-CSRF-Token":csrf2})
    assert second.status_code==200,second.text
    second_cookie=client.cookies.get(cfg.session_cookie_name)
    assert second_cookie and second_cookie!=first_cookie
    with factory() as check:
        old=check.scalar(select(SessionRecord).where(SessionRecord.token_hash==token_hash(first_cookie)))
        assert old is not None and old.revoked_at is not None

    # Browser session is never accepted as Windows-agent machine authentication.
    agent=client.get("/api/agent/v1/jobs/next")
    assert agent.status_code in {401,403}


def test_x_forwarded_for_is_not_trusted_for_login_throttling(web_env):
    client,_,cfg,username,_,_=web_env
    for i,forwarded in enumerate(("198.51.100.1","198.51.100.2","198.51.100.3"),start=1):
        csrf=client.get("/api/auth/csrf").json()["csrf_token"]
        response=client.post(
            "/api/auth/login",
            json={"username":f"unknown-user-{i}-{uuid4().hex[:6]}","password":"wrong-password-value"},
            headers={"X-CSRF-Token":csrf,"X-Forwarded-For":forwarded},
        )
        assert response.status_code==401
    csrf=client.get("/api/auth/csrf").json()["csrf_token"]
    blocked=client.post(
        "/api/auth/login",
        json={"username":username,"password":PASSWORD},
        headers={"X-CSRF-Token":csrf,"X-Forwarded-For":"203.0.113.200"},
    )
    assert blocked.status_code==401


def _report_job(db:Session,org,part,suffix:str,*,sensitivity:str="NORMAL",snapshot_id:str|None=None):
    row=ReportJobRecord(
        id=f"rpt-download-{suffix}",organisation_id=org.id,participant_id=part.id,origin="LOCAL",
        participant_inn=part.inn,report_type="DOCUMENT_LIFECYCLE",report_schema_version="1",
        output_format="CSV",sensitivity_class=sensitivity,filters_sanitized_json={},
        request_fingerprint_sha256=(suffix+"q"*64)[:64],state="READY",snapshot_id=snapshot_id,
        remote_metadata_sanitized={},remote_create_ambiguous=False,requested_at=NOW(),attempt_count=0,
    );db.add(row);db.flush();return row


def test_m11_download_authorization_sensitive_integrity_and_internal_block(db:Session,tmp_path:Path,monkeypatch):
    ua,ub,dual,oa,pa,ob,pb,sa,sb,sd=_seed_ab(db)
    viewer_scope=_scope(db,dual,sd,oa,pa)
    cfg=replace(WebConfig.from_env(),report_artifact_root=str(tmp_path),report_temp_root=str(tmp_path/"tmp"))
    normal=_report_job(db,oa,pa,"normal")
    data=b"tenant-a-report"
    (tmp_path/"normal.bin").write_bytes(data)
    art=ReportArtifactRecord(
        artifact_id="art-normal",report_job_id=normal.id,artifact_role="OUTPUT",publication_key="pub-normal",
        state="READY",storage_backend="FILESYSTEM",storage_key="normal.bin",format="CSV",mime="text/csv",
        safe_filename="normal.csv",byte_size=len(data),sha256=sha256(data).hexdigest(),
        sensitivity_class="NORMAL",encryption_metadata={},
    );db.add(art);db.flush()
    handle=ReportDownloadService(db,cfg).open_download(viewer_scope,job_id=normal.id,artifact_id=art.artifact_id)
    assert not hasattr(handle,"storage_key") and not hasattr(handle,"path")
    assert b"".join(handle.chunks())==data

    other_scope=_scope(db,ub,sb,ob,pb)
    with pytest.raises(KeyError):
        ReportDownloadService(db,cfg).open_download(other_scope,job_id=normal.id,artifact_id=art.artifact_id)

    # Same organisation but a foreign participant is equally opaque.
    pa2=ParticipantRecord(
        organisation_id=oa.id,inn="7722445566",display_name="Org A second participant",
        verification_state="VERIFIED",is_active=True,
    );db.add(pa2);db.flush()
    foreign_participant_scope=_scope(db,dual,sd,oa,pa2)
    with pytest.raises(KeyError):
        ReportDownloadService(db,cfg).open_download(foreign_participant_scope,job_id=normal.id,artifact_id=art.artifact_id)
    viewer_scope=_scope(db,dual,sd,oa,pa)

    # State/deletion/expiry gates cannot be bypassed with a valid artifact id.
    art.state="PENDING";db.flush()
    with pytest.raises(ReportDownloadUnavailable):
        ReportDownloadService(db,cfg).open_download(viewer_scope,job_id=normal.id,artifact_id=art.artifact_id)
    art.state="READY";art.deleted_at=NOW();db.flush()
    with pytest.raises(ReportDownloadUnavailable):
        ReportDownloadService(db,cfg).open_download(viewer_scope,job_id=normal.id,artifact_id=art.artifact_id)
    art.deleted_at=None;art.expires_at=NOW()-timedelta(seconds=1);db.flush()
    with pytest.raises(ReportDownloadUnavailable):
        ReportDownloadService(db,cfg).open_download(viewer_scope,job_id=normal.id,artifact_id=art.artifact_id)
    art.expires_at=None;db.flush()

    # MARKING_SENSITIVE requires the separate permission and authenticated decryption.
    snap=ReportSnapshotRecord(
        id="snap-sensitive",report_job_id="placeholder",strategy="MATERIALIZED_IMMUTABLE",snapshot_at=NOW(),
        source_domains=[],source_tables=[],high_water_metadata={},source_filter_sanitized={},
        descriptor_sha256="d"*64,schema_version="1",row_count=1,
    )
    db.add(snap);db.flush()
    sensitive=_report_job(db,oa,pa,"sensitive",sensitivity=ReportSensitivity.MARKING_SENSITIVE.value,snapshot_id=snap.id)
    snap.report_job_id=sensitive.id;db.flush()
    monkeypatch.setenv("WBCZ_REPORT_ARTIFACT_KEY_HEX","11"*32)
    source=tmp_path/"source.csv";source.write_bytes(b"secret-report")
    store=FilesystemReportArtifactStore(tmp_path,key_provider=EnvironmentArtifactKeyProvider(),key_version=cfg.report_artifact_key_version)
    stored=store.put_file(
        source,sensitive=True,
        aad_context={"artifact_id":"art-sensitive","report_job_id":sensitive.id,"snapshot_sha256":snap.descriptor_sha256,"role":ArtifactRole.OUTPUT.value},
        safe_suffix=".csv.enc",
    )
    sensitive_art=ReportArtifactRecord(
        artifact_id="art-sensitive",report_job_id=sensitive.id,artifact_role="OUTPUT",publication_key="pub-sensitive",
        state="READY",storage_backend=stored.storage_backend,storage_key=stored.storage_key,format="CSV",mime="text/csv",
        safe_filename="sensitive.csv",byte_size=stored.plaintext_byte_size,sha256=stored.plaintext_sha256,
        sensitivity_class=ReportSensitivity.MARKING_SENSITIVE.value,encryption_metadata=dict(stored.encryption_metadata),
        encryption_version=stored.encryption_version,
    );db.add(sensitive_art);db.flush()
    with pytest.raises(AuthorizationError):
        ReportDownloadService(db,cfg).open_download(viewer_scope,job_id=sensitive.id,artifact_id=sensitive_art.artifact_id)

    # OWNER has the sensitive download permission.
    owner_scope=_scope(db,ua,sa,oa,pa)
    secured=ReportDownloadService(db,cfg).open_download(owner_scope,job_id=sensitive.id,artifact_id=sensitive_art.artifact_id)
    assert b"".join(secured.chunks())==b"secret-report"
    stored_path=tmp_path/sensitive_art.storage_key
    payload=bytearray(stored_path.read_bytes());payload[-1]^=1;stored_path.write_bytes(payload)
    with pytest.raises(ReportArtifactIntegrityError):
        ReportDownloadService(db,cfg).open_download(owner_scope,job_id=sensitive.id,artifact_id=sensitive_art.artifact_id)

    internal=ReportArtifactRecord(
        artifact_id="art-internal",report_job_id=normal.id,artifact_role="SNAPSHOT_INTERNAL",
        publication_key="pub-internal",state="READY",storage_backend="FILESYSTEM",storage_key="internal-not-downloadable.bin",
        format="JSON",mime="application/json",safe_filename="internal.json",byte_size=len(data),
        sha256=sha256(data).hexdigest(),sensitivity_class="NORMAL",encryption_metadata={},
    );db.add(internal);db.flush()
    with pytest.raises(KeyError):
        ReportDownloadService(db,cfg).open_download(owner_scope,job_id=normal.id,artifact_id=internal.artifact_id)

    actions=set(db.scalars(select(AuditLog.action).where(AuditLog.action.like("REPORT_DOWNLOAD%"))))
    assert {"REPORT_DOWNLOAD_ALLOWED","REPORT_DOWNLOAD_DENIED","REPORT_DOWNLOAD_INTEGRITY_FAILED"}.issubset(actions)


def test_m11_business_sensitive_viewer_allowed_and_marking_requires_sensitive_permission(
    db:Session,tmp_path:Path,monkeypatch
):
    ua,ub,viewer,oa,pa,ob,pb,sa,sb,viewer_session=_seed_ab(db)
    viewer_scope=_scope(db,viewer,viewer_session,oa,pa)
    operator=_user(db,"m11-operator-"+uuid4().hex[:8])
    _membership(db,operator,oa,Role.OPERATOR)
    operator_session,_=_session(db,operator)
    operator_scope=_scope(db,operator,operator_session,oa,pa)
    cfg=replace(WebConfig.from_env(),report_artifact_root=str(tmp_path),report_temp_root=str(tmp_path/"tmp"))
    monkeypatch.setenv("WBCZ_REPORT_ARTIFACT_KEY_HEX","22"*32)
    store=FilesystemReportArtifactStore(
        tmp_path,key_provider=EnvironmentArtifactKeyProvider(),key_version=cfg.report_artifact_key_version
    )

    def encrypted_artifact(suffix:str,sensitivity:str,payload:bytes):
        snap=ReportSnapshotRecord(
            id=f"snap-{suffix}",report_job_id="placeholder",strategy="MATERIALIZED_IMMUTABLE",snapshot_at=NOW(),
            source_domains=[],source_tables=[],high_water_metadata={},source_filter_sanitized={},
            descriptor_sha256=(suffix+"d"*64)[:64],schema_version="1",row_count=1,
        )
        db.add(snap);db.flush()
        job=_report_job(db,oa,pa,suffix,sensitivity=sensitivity,snapshot_id=snap.id)
        snap.report_job_id=job.id;db.flush()
        source=tmp_path/f"{suffix}.csv";source.write_bytes(payload)
        artifact_id=f"art-{suffix}"
        stored=store.put_file(
            source,sensitive=True,
            aad_context={
                "artifact_id":artifact_id,"report_job_id":job.id,
                "snapshot_sha256":snap.descriptor_sha256,"role":ArtifactRole.OUTPUT.value,
            },
            safe_suffix=".csv.enc",
        )
        art=ReportArtifactRecord(
            artifact_id=artifact_id,report_job_id=job.id,artifact_role=ArtifactRole.OUTPUT.value,
            publication_key=f"pub-{suffix}",state="READY",storage_backend=stored.storage_backend,
            storage_key=stored.storage_key,format="CSV",mime="text/csv",safe_filename=f"{suffix}.csv",
            byte_size=stored.plaintext_byte_size,sha256=stored.plaintext_sha256,
            sensitivity_class=sensitivity,encryption_metadata=dict(stored.encryption_metadata),
            encryption_version=stored.encryption_version,
        )
        db.add(art);db.flush()
        return job,art

    business_job,business_art=encrypted_artifact(
        "business",ReportSensitivity.BUSINESS_SENSITIVE.value,b"business-sensitive"
    )
    viewer_download=ReportDownloadService(db,cfg).open_download(
        viewer_scope,job_id=business_job.id,artifact_id=business_art.artifact_id
    )
    assert b"".join(viewer_download.chunks())==b"business-sensitive"

    marking_job,marking_art=encrypted_artifact(
        "marking",ReportSensitivity.MARKING_SENSITIVE.value,b"marking-sensitive"
    )
    with pytest.raises(AuthorizationError):
        ReportDownloadService(db,cfg).open_download(
            viewer_scope,job_id=marking_job.id,artifact_id=marking_art.artifact_id
        )
    operator_download=ReportDownloadService(db,cfg).open_download(
        operator_scope,job_id=marking_job.id,artifact_id=marking_art.artifact_id
    )
    assert b"".join(operator_download.chunks())==b"marking-sensitive"
