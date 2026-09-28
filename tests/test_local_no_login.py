from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace
from uuid import uuid4
import os

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker

import wbcz_web.admin as admin_module
from wbcz_local.app import create_local_app
from wbcz_local.bridge import LocalTrueApiReadBridge
from wbcz_local.browser_session import LOCAL_BROWSER_SESSION_COOKIE
from wbcz_web.auth import hash_password, verify_password
from wbcz_web.auth.passwords import MIN_PASSWORD_LENGTH
from wbcz_web.config import WebConfig
from wbcz_web.main import create_app
from wbcz_web.models import Base, SessionRecord, User
from wbcz_web.models.security import (
    BootstrapRecord,
    MembershipRecord,
    ParticipantRecord,
)
from wbcz_web.services.authorization import BootstrapService


DB_URL = os.getenv("WBCZ_TEST_DATABASE_URL")
INN = "1234567890"
OWNER_PASSWORD = "existing-local-owner-password"


def _config(database_url: str) -> WebConfig:
    return WebConfig(
        database_url=database_url,
        own_inn=INN,
        environment="test",
        trusted_hosts=("127.0.0.1", "localhost", "testserver"),
        agent_enabled=False,
        agent_legacy_bootstrap_enabled=False,
        fbs_dry_run_only=True,
        true_api_real_read_enabled=True,
        true_api_write_enabled=False,
        printing_enabled=False,
        print_execution_enabled=False,
        suz_full_km_remote_acquisition_enabled=False,
        web_process_count=1,
    ).validate_for_startup()


@pytest.fixture
def local_factory():
    if not DB_URL:
        pytest.skip("WBCZ_TEST_DATABASE_URL requires PostgreSQL")

    schema = f"local_no_login_{uuid4().hex}"
    admin_engine = create_engine(DB_URL, future=True)
    with admin_engine.begin() as connection:
        connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')

    engine = create_engine(
        DB_URL,
        future=True,
        connect_args={"options": f"-csearch_path={schema}"},
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    try:
        yield factory
    finally:
        engine.dispose()
        with admin_engine.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        admin_engine.dispose()


def _seed_owner(factory, *, password: str = OWNER_PASSWORD):
    with factory() as db:
        user, organisation, participant, _ = BootstrapService(db).bootstrap(
            username="owner",
            password=password,
            organisation_name="Sellari Local",
            participant_inn=INN,
            participant_name="WB FBS",
        )
        db.commit()
        return user.id, organisation.id, participant.id, user.password_hash


def _local_app(factory, tmp_path, *, true_api_bridge=None):
    (tmp_path / "index.html").write_text(
        "<!doctype html><title>Sellari</title><div id='app'></div>",
        encoding="utf-8",
    )
    return create_local_app(
        _config(DB_URL or "postgresql+psycopg://unused:unused@127.0.0.1:5432/unused"),
        session_factory=factory,
        frontend_dist=tmp_path,
        true_api_bridge=true_api_bridge,
    )


def _local_client(factory, tmp_path) -> TestClient:
    return TestClient(_local_app(factory, tmp_path))


@pytest.mark.skipif(not DB_URL, reason="PostgreSQL required")
def test_local_root_and_protected_api_use_owner_without_login(local_factory, tmp_path) -> None:
    user_id, organisation_id, participant_id, password_hash = _seed_owner(local_factory)
    with _local_client(local_factory, tmp_path) as client:
        root = client.get("/")
        assert root.status_code == 200
        assert "location" not in root.headers

        me = client.get("/api/me")
        assert me.status_code == 200
        assert me.json()["id"] == user_id
        assert me.json()["role"] == "OWNER"
        assert me.json()["organisation_id"] == organisation_id
        assert me.json()["participant_id"] == participant_id
        assert me.json()["participant_inn"] == INN

        workspace = client.get("/api/workspace")
        assert workspace.status_code == 200
        assert client.post("/api/auth/login", json={}).status_code in {404, 405}
        assert client.post("/api/auth/logout").status_code in {404, 405}

    with local_factory() as db:
        assert db.get(User, user_id).password_hash == password_hash
        assert db.scalar(select(func.count()).select_from(SessionRecord)) == 0


@pytest.mark.skipif(not DB_URL, reason="PostgreSQL required")
def test_local_owner_missing_fails_closed_without_login_fallback(local_factory, tmp_path) -> None:
    with _local_client(local_factory, tmp_path) as client:
        response = client.get("/api/me")
        assert response.status_code == 503
        assert response.json()["detail"]["code"] == "LOCAL_OWNER_IDENTITY_UNAVAILABLE"
        assert "missing" in response.json()["detail"]["message"]
        assert client.post("/api/auth/login", json={}).status_code in {404, 405}


@pytest.mark.skipif(not DB_URL, reason="PostgreSQL required")
def test_local_multiple_valid_owners_fail_closed(local_factory, tmp_path) -> None:
    _, organisation_id, _, _ = _seed_owner(local_factory)
    with local_factory() as db:
        second = User(
            username="second-owner",
            password_hash=hash_password("second-owner-regression-password"),
            is_active=True,
            is_admin=False,
            account_state="ACTIVE",
            password_must_change=False,
        )
        db.add(second)
        db.flush()
        db.add(
            MembershipRecord(
                organisation_id=organisation_id,
                user_id=second.id,
                role="OWNER",
                is_active=True,
                created_by_user_id=second.id,
            )
        )
        db.commit()

    with _local_client(local_factory, tmp_path) as client:
        response = client.get("/api/me")
        assert response.status_code == 503
        assert response.json()["detail"]["code"] == "LOCAL_OWNER_IDENTITY_UNAVAILABLE"
        assert "ambiguous" in response.json()["detail"]["message"]


@pytest.mark.skipif(not DB_URL, reason="PostgreSQL required")
def test_fresh_local_bootstrap_has_no_application_password_prompt_and_is_single_use(
    local_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = _config(DB_URL)
    args = SimpleNamespace(
        username="owner",
        organisation="Sellari Local",
        inn=INN,
        participant_name="WB FBS",
    )
    synthetic_verifier = "synthetic-local-only-verifier-0123456789ABCDEF"
    monkeypatch.setattr(admin_module.secrets, "token_urlsafe", lambda _size: synthetic_verifier)
    monkeypatch.setattr(
        admin_module.getpass,
        "getpass",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("application password prompt must not be used")
        ),
    )

    with local_factory() as db:
        assert admin_module._bootstrap_local_owner(args, db, cfg) == 0
        user = db.scalar(select(User))
        assert user is not None
        assert user.password_hash != synthetic_verifier
        assert user.password_hash.startswith("$argon2id$")
        assert verify_password(user.password_hash, synthetic_verifier) is True
        assert db.scalar(select(func.count()).select_from(User)) == 1
        assert db.scalar(
            select(func.count())
            .select_from(MembershipRecord)
            .where(MembershipRecord.role == "OWNER")
        ) == 1
        bootstrap = db.get(BootstrapRecord, 1)
        assert bootstrap is not None
        assert synthetic_verifier not in repr(bootstrap.metadata_json)

        original_hash = user.password_hash
        assert admin_module._bootstrap_local_owner(args, db, cfg) == 2
        assert db.scalar(select(func.count()).select_from(User)) == 1
        assert db.get(User, user.id).password_hash == original_hash


@pytest.mark.skipif(not DB_URL, reason="PostgreSQL required")
def test_existing_local_owner_hash_participant_and_bootstrap_are_preserved(local_factory) -> None:
    user_id, organisation_id, participant_id, original_hash = _seed_owner(local_factory)
    cfg = _config(DB_URL)
    args = SimpleNamespace(
        username="owner",
        organisation="Changed Name Must Not Apply",
        inn=INN,
        participant_name="Changed Participant Must Not Apply",
    )

    with local_factory() as db:
        participant_before = db.get(ParticipantRecord, participant_id)
        assert participant_before is not None
        original_inn = participant_before.inn
        assert admin_module._bootstrap_local_owner(args, db, cfg) == 2

        user = db.get(User, user_id)
        participant = db.get(ParticipantRecord, participant_id)
        bootstrap = db.get(BootstrapRecord, 1)
        assert user is not None and participant is not None and bootstrap is not None
        assert user.password_hash == original_hash
        assert participant.inn == original_inn == INN
        assert bootstrap.organisation_id == organisation_id
        assert bootstrap.owner_user_id == user_id
        assert bootstrap.participant_id == participant_id
        assert db.scalar(
            select(func.count())
            .select_from(MembershipRecord)
            .where(MembershipRecord.role == "OWNER")
        ) == 1


@pytest.mark.skipif(not DB_URL, reason="PostgreSQL required")
def test_non_local_app_still_requires_session_and_verifies_password(local_factory) -> None:
    user_id, _, _, _ = _seed_owner(local_factory)
    server_config = replace(
        _config(DB_URL),
        audit_pseudonym_key="synthetic-non-local-audit-key-0000000000000001",
        audit_pseudonym_key_id="local-no-login-test-v1",
    ).validate_for_startup()
    app = create_app(server_config, session_factory=local_factory)
    assert not hasattr(app.state, "local_principal_resolver")

    with TestClient(app) as client:
        assert client.get("/api/me").status_code == 401

        csrf = client.get("/api/auth/csrf").json()["csrf_token"]
        bad = client.post(
            "/api/auth/login",
            headers={"X-CSRF-Token": csrf},
            json={"username": "owner", "password": "wrong-password-value"},
        )
        assert bad.status_code == 401

        csrf = client.get("/api/auth/csrf").json()["csrf_token"]
        good = client.post(
            "/api/auth/login",
            headers={"X-CSRF-Token": csrf},
            json={"username": "owner", "password": OWNER_PASSWORD},
        )
        assert good.status_code == 200
        assert good.json()["id"] == user_id
        assert client.get("/api/me").status_code == 200

    assert MIN_PASSWORD_LENGTH == 15
    with pytest.raises(ValueError):
        hash_password("too-short")


@pytest.mark.skipif(not DB_URL, reason="PostgreSQL required")
def test_local_network_and_csrf_guards_remain_active(local_factory, tmp_path) -> None:
    _seed_owner(local_factory)
    with _local_client(local_factory, tmp_path) as client:
        unsafe_host = client.get("/api/me", headers={"Host": "evil.example"})
        assert unsafe_host.status_code == 400

        external_origin = client.get("/api/me", headers={"Origin": "https://evil.example"})
        assert external_origin.status_code == 200
        assert "access-control-allow-origin" not in external_origin.headers

        csrf_blocked = client.post("/api/local/auth/prepare")
        assert csrf_blocked.status_code == 403



@pytest.mark.skipif(not DB_URL, reason="PostgreSQL required")
def test_local_browser_sessions_are_unique_stable_and_secure(local_factory, tmp_path) -> None:
    user_id, _, _, _ = _seed_owner(local_factory)
    app = _local_app(local_factory, tmp_path)

    with TestClient(app) as client_a, TestClient(app) as client_b:
        first_a = client_a.get("/api/me")
        first_b = client_b.get("/api/me")
        assert first_a.status_code == 200
        assert first_b.status_code == 200

        session_a = client_a.cookies.get(LOCAL_BROWSER_SESSION_COOKIE)
        session_b = client_b.cookies.get(LOCAL_BROWSER_SESSION_COOKIE)
        assert session_a
        assert session_b
        assert session_a != session_b
        assert session_a != f"local-owner:{user_id}"
        assert session_b != f"local-owner:{user_id}"

        second_a = client_a.get("/api/me")
        assert second_a.status_code == 200
        assert client_a.cookies.get(LOCAL_BROWSER_SESSION_COOKIE) == session_a

        cookie_header = first_a.headers.get("set-cookie", "").lower()
        assert LOCAL_BROWSER_SESSION_COOKIE.lower() + "=" in cookie_header
        assert "httponly" in cookie_header
        assert "samesite=strict" in cookie_header
        assert "path=/" in cookie_header
        assert "domain=" not in cookie_header
        assert "secure" not in cookie_header


@pytest.mark.skipif(not DB_URL, reason="PostgreSQL required")
def test_forged_local_browser_session_cookie_is_rotated(local_factory, tmp_path) -> None:
    _seed_owner(local_factory)
    app = _local_app(local_factory, tmp_path)
    attacker_chosen = "A" * 43

    with TestClient(app) as client:
        client.cookies.set(
            LOCAL_BROWSER_SESSION_COOKIE,
            attacker_chosen,
            domain="testserver.local",
            path="/",
        )
        response = client.get("/api/me")
        assert response.status_code == 200
        issued = client.cookies.get(LOCAL_BROWSER_SESSION_COOKIE)
        assert issued
        assert issued != attacker_chosen
        assert LOCAL_BROWSER_SESSION_COOKIE.lower() in response.headers.get("set-cookie", "").lower()


class _BindingDiscovery:
    def __init__(self, thumbprint: str) -> None:
        self.thumbprint = thumbprint

    def discover(self) -> dict:
        return {
            "candidates": [{
                "thumbprint": self.thumbprint,
                "subject": "CN=Sellari Local Binding Test",
                "certificate_inn": INN,
                "valid_from": "2020-01-01T00:00:00+00:00",
                "valid_to": "2035-01-01T00:00:00+00:00",
                "has_private_key": True,
                "crypto_provider": "Crypto-Pro GOST R 34.10-2012",
                "public_key_oid": "1.2.643.7.1.1.1.1",
            }]
        }


class _BindingRuntime:
    def __init__(self, challenge: str) -> None:
        self.challenge = challenge
        self.complete_calls = 0

    def prepare_auth_challenge(self):
        return "local-browser-binding-uuid", self.challenge

    def complete_auth(self, *, uuid: str, signature_base64: str):
        assert uuid == "local-browser-binding-uuid"
        assert signature_base64 == "BROWSER-CADES-ATTACHED-SIGNATURE"
        self.complete_calls += 1
        return {
            "authenticated": True,
            "expire_date": "2030-01-01T00:00:00+00:00",
            "read_only": True,
            "business_write_enabled": False,
            "tls": {"gost_session_verified": True},
        }

    def clear_session(self) -> None:
        return None

    def close(self) -> None:
        return None


@pytest.mark.skipif(not DB_URL, reason="PostgreSQL required")
def test_browser_cades_prepare_complete_is_bound_to_same_local_client(
    local_factory,
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _seed_owner(local_factory)
    thumbprint = "A" * 40
    challenge = "exact-local-browser-session-challenge"
    runtime = _BindingRuntime(challenge)
    bridge = LocalTrueApiReadBridge(
        settings_path=tmp_path / "true_api_read.json",
        audit_log_path=tmp_path / "true_api_read_audit.jsonl",
        discovery=_BindingDiscovery(thumbprint),
        cms_signature_info=lambda _signature: (thumbprint, challenge.encode("utf-8")),
    )
    monkeypatch.setattr(bridge, "_build_runtime", lambda _participant_inn: runtime)
    monkeypatch.setattr(
        "wbcz_local.bridge.inspect_local_cryptopro_foundation",
        lambda: SimpleNamespace(
            csp_available=True,
            gost_transport_available=True,
            cryptcp_available=False,
        ),
    )

    app = _local_app(local_factory, tmp_path, true_api_bridge=bridge)
    payload = {
        "signature_base64": "BROWSER-CADES-ATTACHED-SIGNATURE",
        "selected_certificate_thumbprint": thumbprint,
    }

    with TestClient(app) as client_a, TestClient(app) as client_b:
        csrf_a = client_a.get("/api/auth/csrf").json()["csrf_token"]
        csrf_b = client_b.get("/api/auth/csrf").json()["csrf_token"]
        session_a = client_a.cookies.get(LOCAL_BROWSER_SESSION_COOKIE)
        session_b = client_b.cookies.get(LOCAL_BROWSER_SESSION_COOKIE)
        assert session_a and session_b and session_a != session_b

        prepared_response = client_a.post(
            "/api/local/auth/prepare",
            headers={"X-CSRF-Token": csrf_a},
        )
        assert prepared_response.status_code == 200
        prepared = prepared_response.json()
        attempt_id = prepared["attempt_id"]
        assert bridge._attempts[attempt_id].session_id == session_a

        cross_client = client_b.post(
            "/api/local/auth/complete",
            headers={"X-CSRF-Token": csrf_b},
            json={"attempt_id": attempt_id, **payload},
        )
        assert cross_client.status_code == 409
        assert cross_client.json()["detail"]["code"] == "AUTH_ATTEMPT_MISMATCH"
        assert runtime.complete_calls == 0

        same_client = client_a.post(
            "/api/local/auth/complete",
            headers={"X-CSRF-Token": csrf_a},
            json={"attempt_id": attempt_id, **payload},
        )
        assert same_client.status_code == 200
        assert same_client.json()["authenticated"] is True
        assert runtime.complete_calls == 1
