from __future__ import annotations

from pathlib import Path
import os

import pytest
from alembic import command
from alembic.config import Config as AlembicConfig
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker

from wbcz_web.auth import hash_password
from wbcz_web.config import WebConfig
from wbcz_web.main import create_app
from wbcz_web.models import Base, User

DB_URL = os.getenv("WBCZ_TEST_DATABASE_URL")


def _safe_prod_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WBCZ_ENV", "production")
    monkeypatch.setenv("WBCZ_DATABASE_URL", "postgresql+psycopg://wbcz:a-strong-production-db-password@marking-postgres:5432/wbcz")
    monkeypatch.setenv("WBCZ_OWN_INN", "1234567890")
    monkeypatch.setenv("WBCZ_COOKIE_SECURE", "true")
    monkeypatch.setenv("WBCZ_DEBUG", "false")
    monkeypatch.setenv("WBCZ_TRUSTED_HOSTS", "mark.sellari.ru")
    monkeypatch.setenv("WBCZ_BUILD_SHA", "a" * 40)
    monkeypatch.setenv("WBCZ_APP_VERSION", "0.5.1")


def test_production_rejects_insecure_cookie_config(monkeypatch):
    _safe_prod_env(monkeypatch)
    monkeypatch.setenv("WBCZ_COOKIE_SECURE", "false")
    with pytest.raises(ValueError, match="WBCZ_COOKIE_SECURE"):
        WebConfig.from_env()


def test_production_rejects_debug(monkeypatch):
    _safe_prod_env(monkeypatch)
    monkeypatch.setenv("WBCZ_DEBUG", "true")
    with pytest.raises(ValueError, match="WBCZ_DEBUG"):
        WebConfig.from_env()


def test_production_rejects_wildcard_host_and_unknown_build(monkeypatch):
    _safe_prod_env(monkeypatch)
    monkeypatch.setenv("WBCZ_TRUSTED_HOSTS", "*")
    with pytest.raises(ValueError, match="Wildcard"):
        WebConfig.from_env()
    _safe_prod_env(monkeypatch)
    monkeypatch.setenv("WBCZ_BUILD_SHA", "unknown")
    with pytest.raises(ValueError, match="WBCZ_BUILD_SHA"):
        WebConfig.from_env()


def test_frontend_production_api_is_same_origin():
    source = (Path(__file__).parents[1] / "frontend" / "src" / "api.ts").read_text(encoding="utf-8")
    assert '"/api/' in source
    assert "http://localhost" not in source
    assert "https://localhost" not in source
    assert "http://127.0.0.1" not in source
    assert "https://127.0.0.1" not in source


def test_prod_compose_keeps_postgres_internal_and_backend_loopback_only():
    text = (Path(__file__).parents[1] / "docker-compose.prod.yml").read_text(encoding="utf-8")
    postgres = text.split("  marking-postgres:", 1)[1].split("  marking-backend:", 1)[0]
    backend = text.split("  marking-backend:", 1)[1].split("volumes:", 1)[0]
    assert "\n    ports:" not in postgres
    assert "expose:" in postgres
    assert "- marking_internal" in postgres
    assert "- marking_proxy" not in postgres
    assert "127.0.0.1:${WBCZ_BACKEND_PORT" in backend
    assert "- marking_internal" in backend
    assert "- marking_proxy" in backend
    assert "marking_internal:" in text and "internal: true" in text
    assert "marking_proxy:" in text


def test_backend_dockerfile_healthcheck_targets_api_health():
    text = (Path(__file__).parents[1] / "Dockerfile.backend").read_text(encoding="utf-8")
    assert "HEALTHCHECK" in text
    assert "/api/health" in text


@pytest.mark.skipif(not DB_URL, reason="WBCZ_TEST_DATABASE_URL requires PostgreSQL")
def test_production_routes_health_version_auth_and_capabilities():
    engine = create_engine(DB_URL, future=True)
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    production_url = "postgresql+psycopg://wbcz:a-strong-production-db-password@marking-postgres:5432/wbcz"
    config = WebConfig(
        production_url,
        "1234567890",
        "production",
        3600,
        True,
        "wbcz_session",
        "wbcz_csrf",
        False,
        ("mark.sellari.ru",),
        "0.5.1",
        "b" * 40,
    )
    app = create_app(config, session_factory=factory)
    with factory() as db:
        db.add(User(username="owner", password_hash=hash_password("very-secure-password"), is_active=True, is_admin=True))
        db.commit()
    with TestClient(app, base_url="https://mark.sellari.ru") as client:
        assert app.debug is False
        route_paths = {getattr(route, "path", None) for route in app.routes}
        assert not {"/register", "/signup", "/api/register", "/api/auth/register", "/docs", "/openapi.json"}.intersection(route_paths)
        health = client.get("/api/health")
        assert health.status_code == 200 and health.json() == {"status": "ok", "service": "wbcz-web"}
        version = client.get("/api/version")
        assert version.status_code == 200 and version.json() == {"application_version": "0.5.1", "build_sha": "b" * 40}
        csrf = client.get("/api/auth/csrf").json()["csrf_token"]
        login = client.post("/api/auth/login", json={"username": "owner", "password": "very-secure-password"}, headers={"X-CSRF-Token": csrf})
        assert login.status_code == 200
        caps = client.get("/api/capabilities")
        assert caps.json() == {"true_api": "offline-dry-run", "true_api_write": False, "document_signing": False, "submission": False, "windows_bridge": False, "registration": False}
        assert client.post("/api/submit", headers={"X-CSRF-Token": csrf}).status_code == 404
        assert client.post("/api/lk/documents/create", headers={"X-CSRF-Token": csrf}).status_code == 404
    Base.metadata.drop_all(engine)
    engine.dispose()


@pytest.mark.skipif(not DB_URL, reason="WBCZ_TEST_DATABASE_URL requires PostgreSQL")
def test_migration_from_empty_postgres_succeeds(monkeypatch):
    engine = create_engine(DB_URL, future=True)
    with engine.begin() as connection:
        connection.exec_driver_sql("DROP SCHEMA public CASCADE")
        connection.exec_driver_sql("CREATE SCHEMA public")
    monkeypatch.setenv("WBCZ_ENV", "test")
    monkeypatch.setenv("WBCZ_DATABASE_URL", DB_URL)
    monkeypatch.setenv("WBCZ_OWN_INN", "1234567890")
    alembic = AlembicConfig(str(Path(__file__).parents[1] / "alembic.ini"))
    command.upgrade(alembic, "head")
    tables = set(inspect(engine).get_table_names())
    assert {"users", "sessions", "imports", "import_rows", "events", "control_runs", "checks", "previews", "preview_items", "audit_log"}.issubset(tables)
    engine.dispose()
