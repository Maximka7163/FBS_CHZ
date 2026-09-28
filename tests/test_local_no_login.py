from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4
import os

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker

import wbcz_web.admin as admin_module
from wbcz_local.app import create_local_app
from wbcz_web.auth import MIN_PASSWORD_LENGTH, hash_password, verify_password
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


def _local_client(factory, tmp_path) -> TestClient:
    (tmp_path / "index.html").write_text(
        "<!doctype html><title>Sellari</title><div id='app'></div>",
        encoding="utf-8",
    )
    app = create_local_app(
        _config(DB_URL or "postgresql+psycopg://unused:unused@127.0.0.1:5432/unused"),
        session_factory=factory,
        frontend_dist=tmp_path,
    )
    return TestClient(app)


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
        assert client.post("/api/auth/login", json={}).status_code == 404
        assert client.post("/api/auth/logout").status_code == 404

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
        assert client.post("/api/auth/login", json={}).status_code == 404


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
    app = create_app(_config(DB_URL), session_factory=local_factory)
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
