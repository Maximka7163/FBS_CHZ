from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import os
from uuid import uuid4

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from wbcz.models import canonical_json
from wbcz.ozon_foundation import M10_EXECUTABLE_READ_CAPABILITIES, M10_WIRE_READY
from wbcz.wb_fbs import StatefulWbRateLimiter, WbHttpResponse
from wbcz.windows_agent import AgentAuthError, AgentJob, AgentJobType, AgentResult, P0_PG
from wbcz_web.auth import hash_password
from wbcz_web.config import WebConfig
from wbcz_web.db import build_session_factory
from wbcz_web.models import (
    AgentBindingRecord,
    AgentCertificateObservationRecord,
    AgentJobRecord,
    AuditEventRecord,
    IntegrationHealthCheckRecord,
    MembershipRecord,
    OrganisationRecord,
    OzonConnectionRecord,
    ParticipantRecord,
    SuzConnectionRecord,
    TrueApiConnectionRecord,
    User,
    WbConnectionRecord,
)
from wbcz_web.repositories import SqlAlchemyAgentJobStore
from wbcz_web.services.agent_bindings import AgentBindingService
from wbcz_web.services.audit_history import AUDIT_EVENT_REGISTRY
from wbcz_web.services.authorization import Permission, ROLE_PERMISSIONS, Role
from wbcz_web.services.integration_secrets import (
    InMemorySecretProvider,
    ReadOnlySecretProvider,
    SecretProviderAtomicRotationUnsupported,
    SecretProviderWriteUnavailable,
    require_safe_rotation,
)
from wbcz_web.services.integration_settings import IntegrationNotFound, IntegrationSettingsService
from wbcz_web.services.integration_status import (
    agent_runtime_status,
    capability_projection,
    certificate_expiry_status,
)
from wbcz_web.services.tenant import bind_tenant_scope


DB_URL = os.getenv("WBCZ_TEST_DATABASE_URL") or os.getenv("WBCZ_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DB_URL, reason="M14 PostgreSQL tests require WBCZ_TEST_DATABASE_URL")
NOW = lambda: datetime.now(timezone.utc)
AUDIT_KEY = b"m14-test-audit-pseudonym-key-0123456789abcdef"


@pytest.fixture
def db() -> Session:
    factory = build_session_factory(WebConfig.from_env())
    session = factory()
    session.execute(text("TRUNCATE TABLE users, organisations RESTART IDENTITY CASCADE"))
    session.commit()
    session.info["audit_pseudonym_key"] = AUDIT_KEY
    session.info["audit_pseudonym_key_id"] = "m14-test-v1"
    try:
        yield session
    finally:
        session.rollback()
        session.execute(text("TRUNCATE TABLE users, organisations RESTART IDENTITY CASCADE"))
        session.commit()
        session.close()


def _config(**changes) -> WebConfig:
    cfg = WebConfig.from_env()
    cfg = replace(
        cfg,
        environment="test",
        agent_enabled=True,
        agent_machine_token="LEGACY-M14-TEST-TOKEN-0123456789",
        agent_legacy_bootstrap_enabled=True,
        true_api_write_enabled=False,
        true_api_reports_enabled=False,
        audit_pseudonym_key=AUDIT_KEY.decode(),
        audit_pseudonym_key_id="m14-test-v1",
        **changes,
    )
    return cfg.validate_for_startup()


def _user(db: Session, name: str) -> User:
    row = User(
        username=name,
        password_hash=hash_password("correct horse battery staple"),
        is_active=True,
        is_admin=False,
        password_changed_at=NOW(),
        password_version=1,
        password_must_change=False,
        account_state="ACTIVE",
    )
    db.add(row)
    db.flush()
    return row


def _tenant(db: Session, label: str, inn: str, *, organisation: OrganisationRecord | None = None):
    user = _user(db, "u-" + label + "-" + uuid4().hex[:6])
    org = organisation or OrganisationRecord(name="org-" + label, is_active=True, created_by_user_id=user.id)
    if organisation is None:
        db.add(org)
        db.flush()
    participant = ParticipantRecord(
        organisation_id=org.id,
        inn=inn,
        display_name="participant-" + label,
        verification_state="VERIFIED",
        is_active=True,
    )
    db.add(participant)
    db.flush()
    db.add(MembershipRecord(
        organisation_id=org.id,
        user_id=user.id,
        role="OWNER",
        is_active=True,
        created_by_user_id=user.id,
    ))
    db.flush()
    return user, org, participant


def _scope(db: Session, user: User, org: OrganisationRecord, participant: ParticipantRecord) -> None:
    bind_tenant_scope(
        db,
        organisation_id=org.id,
        participant_id=participant.id,
        user_id=user.id,
        role="OWNER",
    )
    db.info["audit_trace"] = {
        "request_id": "req-" + uuid4().hex,
        "correlation_id": "corr-" + uuid4().hex,
        "causation_id": None,
    }


class FakeWbAdapter:
    def __init__(self, *, tin: str, status: int = 200) -> None:
        self.tin = tin
        self.status = status
        self.calls: list[dict] = []

    def send(self, *, method, url, headers, params, json_body):
        self.calls.append({
            "method": method,
            "url": url,
            "headers": dict(headers),
            "params": dict(params or {}),
            "json_body": json_body,
        })
        body = (
            ('{"sid":"SID-M14","tin":"' + self.tin + '","name":"Synthetic seller"}').encode()
            if self.status == 200 else b'{"error":"synthetic"}'
        )
        return WbHttpResponse(self.status, "application/json", body, {})


def _activate_secret(provider: InMemorySecretProvider, value: str, purpose: str = "test"):
    staged = provider.stage("scope", purpose, value)
    return provider.activate(staged)


def test_m14_permission_matrix_reuses_m12_without_new_role():
    assert Permission.INTEGRATIONS_READ in ROLE_PERMISSIONS[Role.VIEWER]
    assert Permission.INTEGRATIONS_MANAGE not in ROLE_PERMISSIONS[Role.VIEWER]
    assert Permission.INTEGRATIONS_READ in ROLE_PERMISSIONS[Role.OPERATOR]
    assert Permission.INTEGRATIONS_MANAGE not in ROLE_PERMISSIONS[Role.OPERATOR]
    assert Permission.INTEGRATIONS_MANAGE in ROLE_PERMISSIONS[Role.ADMIN]
    assert Permission.INTEGRATIONS_MANAGE in ROLE_PERMISSIONS[Role.OWNER]
    assert set(Role) == {Role.VIEWER, Role.OPERATOR, Role.ADMIN, Role.OWNER}


def test_status_truthfulness_and_project_thresholds_are_independent():
    caps = {x["name"]: x for x in capability_projection(
        true_api_configured=True,
        true_api_auth_ready=True,
        agent_ready=True,
        wb_ready=True,
        true_api_write_enabled=False,
        reports_enabled=False,
    )}
    assert caps["TRUE_API_AUTH"]["status"] == "READY"
    assert caps["CIS_READ"]["status"] == "READY"
    assert caps["EDO_READ"]["status"] == "READY"
    assert caps["EDO_XML_WRITE"]["status"] == "BLOCKED_CONTRACT"
    assert caps["SUZ_ORDER"]["status"] == "BLOCKED_CONTRACT"
    assert caps["OZON_READ"]["status"] == "BLOCKED_CONTRACT"
    assert caps["TRUE_API_PRODUCTION_WRITE"]["status"] == "BLOCKED_FEATURE_GATE"

    now = datetime(2026, 9, 19, tzinfo=timezone.utc)
    assert agent_runtime_status(state="ACTIVE", last_seen_at=None, now=now) == "UNKNOWN"
    assert agent_runtime_status(state="ACTIVE", last_seen_at=now - timedelta(seconds=120), now=now) == "ONLINE"
    assert agent_runtime_status(state="ACTIVE", last_seen_at=now - timedelta(seconds=121), now=now) == "STALE"
    assert agent_runtime_status(state="ACTIVE", last_seen_at=now - timedelta(seconds=601), now=now) == "OFFLINE"
    assert agent_runtime_status(state="DISABLED", last_seen_at=now, now=now) == "DISABLED"

    assert certificate_expiry_status(now, now=now) == "EXPIRED"
    assert certificate_expiry_status(now + timedelta(days=7), now=now) == "EXPIRING_CRITICAL"
    assert certificate_expiry_status(now + timedelta(days=30), now=now) == "EXPIRING_SOON"
    assert certificate_expiry_status(now + timedelta(days=31), now=now) == "VALID"


def test_secret_provider_is_vendor_neutral_redacted_and_no_plaintext_fallback():
    secret = "WB-M14-PLAINTEXT-CANARY"
    provider = InMemorySecretProvider()
    staged = provider.stage("tenant", "wb", secret)
    assert secret not in repr(staged)
    active = provider.activate(staged)
    value = provider.get(active.ref)
    assert value.value == secret
    assert secret not in repr(value)
    assert secret not in str(value)
    provider.revoke(active.ref, active.version)
    with pytest.raises(Exception):
        provider.get(active.ref)

    readonly = ReadOnlySecretProvider()
    with pytest.raises(SecretProviderWriteUnavailable):
        readonly.stage("tenant", "wb", secret)
    with pytest.raises(SecretProviderAtomicRotationUnsupported):
        require_safe_rotation(readonly)

    unsafe = InMemorySecretProvider(stage_activate=False)
    with pytest.raises(SecretProviderAtomicRotationUnsupported):
        require_safe_rotation(unsafe)


def test_m14_audit_registry_contains_required_redacted_events():
    required = {
        "CONNECTION_CREATED","CONNECTION_UPDATED","CONNECTION_ENABLED",
        "CONNECTION_DISABLED","CONNECTION_ARCHIVED","SECRET_SET","SECRET_ROTATED",
        "SECRET_REVOKED","CONNECTION_CHECK_STARTED","CONNECTION_CHECK_COMPLETED",
        "CONNECTION_CHECK_FAILED","CERTIFICATE_SELECTION_CHANGED",
        "AGENT_BINDING_CREATED","AGENT_BINDING_CHANGED","AGENT_BINDING_DISABLED",
    }
    assert required <= set(AUDIT_EVENT_REGISTRY)


def test_sensitive_true_api_and_agent_columns_are_absent():
    true_cols = set(TrueApiConnectionRecord.__table__.columns.keys())
    forbidden = {"bearer","uuid_token","pin","private_key","pfx","container_password"}
    assert not (true_cols & forbidden)
    binding_cols = set(AgentBindingRecord.__table__.columns.keys())
    assert "credential_hash" in binding_cols
    assert "credential" not in binding_cols
    assert "machine_token" not in binding_cols
    cert_cols = set(AgentCertificateObservationRecord.__table__.columns.keys())
    assert not (cert_cols & {"private_key","pin","pfx","container_password","container_path"})


def test_agent_binding_hash_rotation_and_cross_tenant_job_routing(db: Session):
    ua, oa, pa = _tenant(db, "a", "7707083893")
    ub, ob, pb = _tenant(db, "b", "500100732259")

    _scope(db, ua, oa, pa)
    binding_a, raw_a = AgentBindingService(db).create(
        installation_id=str(uuid4()), display_name="Agent A", user_id=ua.id
    )
    assert raw_a not in binding_a.credential_hash
    assert binding_a.credential_hash == hashlib.sha256(
        ("m14-agent-credential:v1:" + raw_a).encode()
    ).hexdigest()

    _scope(db, ub, ob, pb)
    binding_b, raw_b = AgentBindingService(db).create(
        installation_id=str(uuid4()), display_name="Agent B", user_id=ub.id
    )

    def enqueue_for(user, org, participant, label):
        _scope(db, user, org, participant)
        job = AgentJob(
            job_id=f"job-m14-{label}",
            job_type=AgentJobType.INTEGRATION_HEALTH,
            operation_id=f"health-{label}",
            pg=P0_PG,
            expected_inn=participant.inn,
            read_payload={"check_id":f"check-{label}","check_kind":"TRUE_API","read_probe":"NOT_TESTED"},
        )
        SqlAlchemyAgentJobStore(db, lease_seconds=90).enqueue(job, purpose="INTEGRATION_HEALTH")
        return job

    job_a = enqueue_for(ua, oa, pa, "a")
    job_b = enqueue_for(ub, ob, pb, "b")
    db.flush()
    assert db.get(AgentJobRecord, job_a.job_id).agent_binding_id == binding_a.id
    assert db.get(AgentJobRecord, job_b.job_id).agent_binding_id == binding_b.id

    legacy_job = AgentJob(
        job_id="legacy-null-job",
        job_type=AgentJobType.CIS_INFO,
        operation_id="legacy-null-op",
        pg=P0_PG,
        expected_inn=pa.inn,
        read_payload={"cises":["SYNTHETIC-KIZ-M14"]},
    )
    legacy_payload, legacy_digest = SqlAlchemyAgentJobStore._digest(legacy_job)
    db.add(AgentJobRecord(
        job_id="legacy-null-job",
        organisation_id=oa.id,
        participant_id=pa.id,
        agent_binding_id=None,
        job_type="CIS_INFO",
        operation_id="legacy-null-op",
        purpose="CIS_INVENTORY",
        poll_attempt=0,
        payload_sha256=legacy_digest,
        payload_json=legacy_payload,
        state="PENDING",
    ))
    db.flush()

    scoped_a = SqlAlchemyAgentJobStore(
        db, lease_seconds=90, agent_binding_id=binding_a.id,
        organisation_id=oa.id, participant_id=pa.id,
    )
    leased = scoped_a.fetch_one()
    assert leased is not None and leased.job_id == job_a.job_id
    assert scoped_a.fetch_one() is None
    assert db.get(AgentJobRecord, "legacy-null-job").state == "PENDING"
    assert db.get(AgentJobRecord, job_b.job_id).state == "PENDING"

    _scope(db, ua, oa, pa)
    principal = AgentBindingService(db).authenticate(raw_a, mark_poll=True)
    assert principal.binding_id == binding_a.id
    assert principal.participant_id == pa.id

    _, rotated = AgentBindingService(db).rotate_credential(binding_a.id, user_id=ua.id)
    with pytest.raises(AgentAuthError):
        AgentBindingService(db).authenticate(raw_a)
    assert AgentBindingService(db).authenticate(rotated).binding_id == binding_a.id

    AgentBindingService(db).disable(binding_a.id, user_id=ua.id)
    with pytest.raises(AgentAuthError):
        AgentBindingService(db).authenticate(rotated)
    assert raw_a not in str(db.scalars(select(AgentBindingRecord)).all())
    assert raw_b not in str(db.scalars(select(AgentBindingRecord)).all())


def test_cutover_forbids_new_null_jobs_for_unbound_participant(db: Session):
    ua, oa, pa = _tenant(db, "cut-a", "7724490000")
    ub, ob, pb = _tenant(db, "cut-b", "7811088331")
    _scope(db, ua, oa, pa)
    AgentBindingService(db).create(
        installation_id=str(uuid4()), display_name="Primary A", user_id=ua.id
    )
    _scope(db, ub, ob, pb)
    job = AgentJob(
        job_id="cutover-unbound-b",
        job_type=AgentJobType.CIS_INFO,
        operation_id="cutover-unbound-b-op",
        pg=P0_PG,
        expected_inn=pb.inn,
        read_payload={"cises":["SYNTHETIC-KIZ-M14-B"]},
    )
    with pytest.raises(PermissionError):
        SqlAlchemyAgentJobStore(db, lease_seconds=90).enqueue(job, purpose="CIS_INVENTORY")


def test_tenant_object_lookup_is_non_enumerating_across_orgs_and_participants(db: Session):
    ua, oa, pa = _tenant(db, "scope-a", "5900000004")
    ub, ob, pb = _tenant(db, "scope-b", "5400000000")
    provider = InMemorySecretProvider()
    cfg = _config()

    _scope(db, ua, oa, pa)
    service_a = IntegrationSettingsService(db, cfg, secret_provider=provider)
    wb_a = service_a.create_wb({"display_name":"A"}, user_id=ua.id)

    _scope(db, ub, ob, pb)
    service_b = IntegrationSettingsService(db, cfg, secret_provider=provider)
    with pytest.raises(IntegrationNotFound):
        service_b._get("wb", wb_a["id"])

    # Same organisation, different verified participant remains isolated.
    pc = ParticipantRecord(
        organisation_id=ob.id,
        inn="6670000005",
        display_name="participant-c",
        verification_state="VERIFIED",
        is_active=True,
    )
    db.add(pc); db.flush()
    bind_tenant_scope(db, organisation_id=ob.id, participant_id=pc.id, user_id=ub.id, role="OWNER")
    service_c = IntegrationSettingsService(db, cfg, secret_provider=provider)
    with pytest.raises(IntegrationNotFound):
        service_c._get("wb", wb_a["id"])


def test_true_api_health_is_typed_agent_job_and_preserves_write_gate(db: Session):
    user, org, participant = _tenant(db, "true", "7800000000")
    _scope(db, user, org, participant)
    binding, _ = AgentBindingService(db).create(
        installation_id=str(uuid4()), display_name="True API Agent", user_id=user.id
    )
    cfg = _config()
    service = IntegrationSettingsService(db, cfg, secret_provider=ReadOnlySecretProvider())
    conn = service.create_true_api(
        environment="PRODUCTION", primary_agent_binding_id=binding.id, user_id=user.id
    )
    started = service.check("true-api", conn["id"], user_id=user.id)
    assert started["overall_status"] == "CHECKING"

    check = db.get(IntegrationHealthCheckRecord, started["id"])
    jobs = list(db.scalars(select(AgentJobRecord).where(
        AgentJobRecord.agent_binding_id == binding.id,
        AgentJobRecord.purpose == "INTEGRATION_HEALTH",
    )))
    assert len(jobs) == 1
    job = jobs[0]
    assert job.job_type == "INTEGRATION_HEALTH"
    assert job.payload_json["read_payload"] == {
        "check_id": check.id, "check_kind":"TRUE_API", "read_probe":"NOT_TESTED"
    }
    assert not list(db.scalars(select(AgentJobRecord).where(
        AgentJobRecord.purpose.in_(["WRITE","REPORT_AGENT"])
    )))

    thumb = "A" * 40
    result = AgentResult(
        job.job_id,
        job.operation_id,
        "HEALTH_READY",
        read_result={
            "type":"M14_INTEGRATION_HEALTH",
            "check_id":check.id,
            "components":{
                "AGENT_REACHABILITY":{"status":"READY"},
                "CRYPTO_PROVIDER":{"status":"READY"},
                "CERTIFICATE_PRESENT":{"status":"READY"},
                "CERTIFICATE_TIME_VALIDITY":{"status":"READY"},
                "CERTIFICATE_PRIVATE_KEY":{"status":"READY"},
                "CERTIFICATE_COMPATIBILITY":{"status":"READY"},
                "CERTIFICATE_PARTICIPANT_MATCH":{"status":"READY"},
                "TRUE_API_AUTH":{"status":"READY"},
                "TRUE_API_READ_PROBE":{"status":"NOT_TESTED"},
                "WRITE_FEATURE_GATE":{"status":"DISABLED"},
            },
            "certificate":{
                "thumbprint":thumb,
                "subject":f"CN=Synthetic, INN={participant.inn}",
                "issuer":"CN=Synthetic CA",
                "certificate_inn":participant.inn,
                "valid_from":(NOW()-timedelta(days=1)).isoformat(),
                "valid_to":(NOW()+timedelta(days=90)).isoformat(),
                "algorithm":"1.2.643.7.1.1.1.1",
                "has_private_key":True,
                "crypto_provider":"Crypto-Pro GOST R 34.10-2012",
                "compatibility":"GOST_CRYPTOPRO",
                "serial":"SYNTHETIC-M14",
            },
            "read_probe":"NOT_TESTED",
        },
    )
    service.apply_agent_health_result(binding, result)
    db.flush()
    assert check.overall_status == "READY"
    assert check.component_statuses_json["TRUE_API_AUTH"]["status"] == "READY"
    assert check.component_statuses_json["TRUE_API_READ_PROBE"]["status"] == "NOT_TESTED"
    cert = db.get(AgentCertificateObservationRecord, db.get(TrueApiConnectionRecord, conn["id"]).observed_certificate_observation_id)
    assert cert is not None and cert.readiness_state == "READY" and cert.match_state == "MATCH"
    caps = {x["name"]:x["status"] for x in service.environment_capabilities()["capabilities"]}
    assert caps["TRUE_API_AUTH"] == "READY"
    assert caps["EDO_READ"] == "READY"
    assert caps["EDO_XML_WRITE"] == "BLOCKED_CONTRACT"
    assert caps["TRUE_API_PRODUCTION_WRITE"] == "BLOCKED_FEATURE_GATE"


def test_certificate_selection_is_pending_until_matching_local_observation(db: Session):
    user, org, participant = _tenant(db, "cert", "6900000003")
    _scope(db, user, org, participant)
    binding, _ = AgentBindingService(db).create(
        installation_id=str(uuid4()), display_name="Certificate Agent", user_id=user.id
    )
    service = IntegrationSettingsService(db, _config(), secret_provider=ReadOnlySecretProvider())
    conn = service.create_true_api(
        environment="PRODUCTION", primary_agent_binding_id=binding.id, user_id=user.id
    )
    desired = "B" * 40
    selected = service.select_certificate(conn["id"], desired, user_id=user.id)
    assert selected["requires_local_action"] is True
    assert selected["certificate"]["selection_state"] == "PENDING_LOCAL_APPLY"
    assert not hasattr(db.get(TrueApiConnectionRecord, conn["id"]), "pin")
    assert not hasattr(db.get(TrueApiConnectionRecord, conn["id"]), "private_key")


def test_wb_remote_check_uses_only_accepted_seller_info_and_matches_participant(db: Session):
    user, org, participant = _tenant(db, "wb", "6600000005")
    _scope(db, user, org, participant)
    provider = InMemorySecretProvider()
    active = _activate_secret(provider, "WB-M14-SECRET-CANARY", "wb")
    adapter = FakeWbAdapter(tin=participant.inn)
    service = IntegrationSettingsService(
        db, _config(), secret_provider=provider, wb_http_adapter=adapter,
        wb_rate_limiter=StatefulWbRateLimiter(),
    )
    dto = service.create_wb(
        {"display_name":"WB M14","environment":"PRODUCTION","token_type":"PERSONAL","token_categories":["ANY"]},
        user_id=user.id,
    )
    row = db.get(WbConnectionRecord, int(dto["id"]))
    row.active_secret_ref = active.ref
    row.active_secret_version = active.version
    row.secret_rotation_state = "ACTIVE"
    row.secret_configured_at = NOW()
    db.flush()

    health = service.check("wb", dto["id"], user_id=user.id)
    assert health["overall_status"] == "READY"
    assert len(adapter.calls) == 1
    call = adapter.calls[0]
    assert call["method"] == "GET"
    assert call["url"] == "https://common-api.wildberries.ru/api/v1/seller-info"
    assert call["json_body"] is None
    assert call["headers"]["Authorization"] == "WB-M14-SECRET-CANARY"
    assert "WB-M14-SECRET-CANARY" not in str(service.dto("wb", row))
    audit_blob = str(list(db.scalars(select(AuditEventRecord))))
    assert "WB-M14-SECRET-CANARY" not in audit_blob


def test_wb_tin_mismatch_fails_closed(db: Session):
    user, org, participant = _tenant(db, "wb-mismatch", "6400000004")
    _scope(db, user, org, participant)
    provider = InMemorySecretProvider()
    active = _activate_secret(provider, "WB-M14-MISMATCH-CANARY", "wb")
    adapter = FakeWbAdapter(tin="7707083893")
    service = IntegrationSettingsService(
        db, _config(), secret_provider=provider, wb_http_adapter=adapter,
        wb_rate_limiter=StatefulWbRateLimiter(),
    )
    dto = service.create_wb({"display_name":"WB mismatch"}, user_id=user.id)
    row = db.get(WbConnectionRecord, int(dto["id"]))
    row.active_secret_ref = active.ref
    row.active_secret_version = active.version
    db.flush()
    health = service.check("wb", dto["id"], user_id=user.id)
    assert health["overall_status"] == "ERROR"
    assert health["error_code"] == "REMOTE_IDENTITY_MISMATCH"


def test_ozon_and_suz_are_local_only_and_contract_blocked(db: Session):
    user, org, participant = _tenant(db, "local", "6300000000")
    _scope(db, user, org, participant)
    AgentBindingService(db).create(
        installation_id=str(uuid4()), display_name="Local Agent", user_id=user.id
    )
    provider = InMemorySecretProvider()
    cfg = _config()
    service = IntegrationSettingsService(db, cfg, secret_provider=provider)

    ozon = service.create_ozon(
        {"display_name":"Ozon M14","client_id":"CLIENT-M14","environment":"PRODUCTION"},
        user_id=user.id,
    )
    secret = _activate_secret(provider, "OZON-M14-SECRET-CANARY", "ozon")
    ozon_row = db.get(OzonConnectionRecord, int(ozon["id"]))
    ozon_row.active_secret_ref = secret.ref
    ozon_row.active_secret_version = secret.version
    db.flush()
    ozon_health = service.check("ozon", ozon["id"], user_id=user.id)
    assert ozon_health["overall_status"] == "BLOCKED"
    assert ozon_health["components"]["REMOTE_WIRE"]["status"] == "BLOCKED"
    assert service.dto("ozon", ozon_row)["contract_status"] == "BLOCKED"
    assert not M10_WIRE_READY and M10_EXECUTABLE_READ_CAPABILITIES == ()

    suz = service.create_suz(
        {
            "display_name":"SUZ M14","oms_id":"OMS-M14","oms_connection":"OMS-CONNECTION-M14",
            "environment":"PRODUCTION","installation_name":"Synthetic",
        },
        user_id=user.id,
    )
    suz_row = db.get(SuzConnectionRecord, int(suz["id"]))
    suz_health = service.check("suz", suz["id"], user_id=user.id)
    assert suz_health["overall_status"] == "BLOCKED"
    assert suz_health["components"]["SUZ_CORE_WIRE"]["status"] == "BLOCKED"
    assert suz_row.blocker_code == "OFFICIAL_SUZ_PROGRAMMER_MANUAL_NOT_PINNED"


def test_safe_dto_and_environment_capabilities_never_expose_storage_refs(db: Session):
    user, org, participant = _tenant(db, "safe", "6200000007")
    _scope(db, user, org, participant)
    provider = InMemorySecretProvider()
    service = IntegrationSettingsService(db, _config(), secret_provider=provider)
    wb = service.create_wb({"display_name":"Safe WB"}, user_id=user.id)
    row = db.get(WbConnectionRecord, int(wb["id"]))
    active = _activate_secret(provider, "M14-SAFE-DTO-CANARY", "wb")
    row.active_secret_ref = active.ref
    row.active_secret_version = active.version
    db.flush()
    blob = str(service.dto("wb", row)) + str(service.environment_capabilities())
    assert "M14-SAFE-DTO-CANARY" not in blob
    assert active.ref not in blob
    for forbidden in ("database_url","machine_token","private_key","pin","pfx","secret_ref"):
        assert forbidden not in service.environment_capabilities()


def test_m14_health_table_is_append_style(db: Session):
    user, org, participant = _tenant(db, "health", "6100000009")
    _scope(db, user, org, participant)
    provider = InMemorySecretProvider()
    service = IntegrationSettingsService(db, _config(integration_check_cooldown_seconds=1), secret_provider=provider)
    ozon = service.create_ozon(
        {"display_name":"Ozon health","client_id":"CID-HEALTH","environment":"PRODUCTION"},
        user_id=user.id,
    )
    first = service.check("ozon", ozon["id"], user_id=user.id)
    assert first["overall_status"] == "ERROR"
    assert db.scalar(select(IntegrationHealthCheckRecord).where(
        IntegrationHealthCheckRecord.id == first["id"]
    )) is not None
    rows = list(db.scalars(select(IntegrationHealthCheckRecord).where(
        IntegrationHealthCheckRecord.connection_id == ozon["id"]
    )))
    assert len(rows) == 1
    assert rows[0].completed_at is not None


def _p0_candidate(participant_inn: str, thumbprint: str, **overrides):
    value = {
        "thumbprint": thumbprint,
        "subject": f"CN=Synthetic, INN={participant_inn}",
        "issuer": "CN=Synthetic CA",
        "serial": thumbprint[-16:],
        "certificate_inn": participant_inn,
        "valid_from": (NOW() - timedelta(days=1)).isoformat(),
        "valid_to": (NOW() + timedelta(days=90)).isoformat(),
        "has_private_key": True,
        "public_key_oid": "1.2.643.7.1.1.1.1",
        "signature_oid": "1.2.643.7.1.1.3.2",
        "crypto_provider": "Crypto-Pro GOST R 34.10",
        "compatibility": "GOST_CRYPTOPRO",
    }
    value.update(overrides)
    return value


def test_p0_certificate_inventory_auto_select_multiple_and_invalid_candidates(db: Session):
    user, org, participant = _tenant(db, "cert-inventory", "7707083893")
    _scope(db, user, org, participant)
    binding, _ = AgentBindingService(db).create(
        installation_id=str(uuid4()), display_name="Discovery Agent", user_id=user.id
    )
    service = IntegrationSettingsService(db, _config(), secret_provider=ReadOnlySecretProvider())
    service.create_true_api(
        environment="PRODUCTION", primary_agent_binding_id=binding.id, user_id=user.id
    )

    empty = service.record_certificate_inventory(
        binding.id, candidates=[], selected_thumbprint=None, cryptopro_available=True
    )
    assert empty["candidates"] == []
    assert service.certificate_status()["reason_code"] == "CERTIFICATE_NOT_FOUND"

    thumb = "A" * 40
    one = service.record_certificate_inventory(
        binding.id,
        candidates=[_p0_candidate(participant.inn, thumb)],
        selected_thumbprint=None,
        cryptopro_available=True,
    )
    assert one["auto_selected"] is True
    assert one["desired_certificate_thumbprint"] == thumb
    assert one["selection_state"] == "PENDING_LOCAL_APPLY"
    applied = service.record_certificate_inventory(
        binding.id,
        candidates=[_p0_candidate(participant.inn, thumb)],
        selected_thumbprint=thumb,
        cryptopro_available=True,
    )
    assert applied["selection_state"] == "READY"
    assert service.certificate_status()["status"] == "READY"

    user2, org2, participant2 = _tenant(db, "cert-multiple", "500100732259")
    _scope(db, user2, org2, participant2)
    binding2, _ = AgentBindingService(db).create(
        installation_id=str(uuid4()), display_name="Multi Agent", user_id=user2.id
    )
    service2 = IntegrationSettingsService(db, _config(), secret_provider=ReadOnlySecretProvider())
    conn2 = service2.create_true_api(
        environment="PRODUCTION", primary_agent_binding_id=binding2.id, user_id=user2.id
    )
    a, b = "B" * 40, "C" * 40
    multiple = service2.record_certificate_inventory(
        binding2.id,
        candidates=[_p0_candidate(participant2.inn, a), _p0_candidate(participant2.inn, b)],
        selected_thumbprint=None,
        cryptopro_available=True,
    )
    assert multiple["auto_selected"] is False
    assert multiple["desired_certificate_thumbprint"] is None
    assert service2.certificate_status()["reason_code"] == "CERTIFICATE_SELECTION_REQUIRED"
    service2.select_certificate(conn2["id"], b, user_id=user2.id)
    applied2 = service2.record_certificate_inventory(
        binding2.id,
        candidates=[_p0_candidate(participant2.inn, a), _p0_candidate(participant2.inn, b)],
        selected_thumbprint=b,
        cryptopro_available=True,
    )
    assert applied2["selection_state"] == "READY"

    user3, org3, participant3 = _tenant(db, "cert-invalid", "7811088331")
    _scope(db, user3, org3, participant3)
    binding3, _ = AgentBindingService(db).create(
        installation_id=str(uuid4()), display_name="Invalid Agent", user_id=user3.id
    )
    service3 = IntegrationSettingsService(db, _config(), secret_provider=ReadOnlySecretProvider())
    service3.create_true_api(environment="PRODUCTION", primary_agent_binding_id=binding3.id, user_id=user3.id)
    bad = service3.record_certificate_inventory(
        binding3.id,
        candidates=[
            _p0_candidate(participant3.inn, "D" * 40, has_private_key=False),
            _p0_candidate(participant3.inn, "E" * 40, valid_to=(NOW() - timedelta(days=1)).isoformat()),
            _p0_candidate("7707083893", "F" * 40),
        ],
        selected_thumbprint=None,
        cryptopro_available=True,
    )
    reasons = {item["reason_code"] for item in bad["candidates"]}
    assert {"CERTIFICATE_NO_PRIVATE_KEY", "CERTIFICATE_EXPIRED", "CERTIFICATE_PARTICIPANT_MISMATCH"} <= reasons
    assert not any(item["readiness_state"] == "READY" for item in bad["candidates"])


def test_p0_true_api_check_stops_before_real_auth_until_authorized(db: Session):
    user, org, participant = _tenant(db, "local-readiness", "7707083893")
    _scope(db, user, org, participant)
    binding, _ = AgentBindingService(db).create(
        installation_id=str(uuid4()), display_name="Local readiness Agent", user_id=user.id
    )
    cfg = _config(true_api_real_read_enabled=False)
    service = IntegrationSettingsService(db, cfg, secret_provider=ReadOnlySecretProvider())
    conn = service.create_true_api(
        environment="PRODUCTION", primary_agent_binding_id=binding.id, user_id=user.id
    )
    thumb = "9" * 40
    service.record_certificate_inventory(
        binding.id,
        candidates=[_p0_candidate(participant.inn, thumb)],
        selected_thumbprint=thumb,
        cryptopro_available=True,
    )
    health = service.check("true-api", conn["id"], user_id=user.id)
    assert health["overall_status"] == "BLOCKED"
    assert health["error_code"] == "REAL_CERT_READ_ONLY_AUTHORIZATION_REQUIRED"
    assert health["components"]["TRUE_API_AUTH"]["status"] == "BLOCKED"
    assert db.scalar(select(func.count()).select_from(AgentJobRecord).where(
        AgentJobRecord.purpose == "INTEGRATION_HEALTH"
    )) == 0
