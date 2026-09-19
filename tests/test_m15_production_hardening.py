from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from dataclasses import replace
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from wbcz.agent_cli import WindowsAgentConfig
from wbcz.m11_reports import DISPENSER_CAPABILITIES, DispenserCapabilityName
from wbcz.windows_agent_runtime import DurableDispenserRateLimiter, WindowsAgentReplayStore
from wbcz_web.config import WebConfig
from wbcz_web.main import create_app
from wbcz_web.services.agent_enrollment import AgentHandshake, ProtocolCompatibility, evaluate_protocol
from wbcz_web.services.production_hardening import (
    RetryClassification,
    classify_failure,
    parse_retry_after,
    retry_decision,
    sanitize_operational_data,
)
from wbcz_web.services.production_secrets import EncryptedVersionedFilesystemSecretProvider
from wbcz_web.services.worker_runtime import ProductionWorkerRuntime
from wbcz_web.services.integration_secrets import SecretProviderError


NOW = datetime(2026, 9, 19, 12, 0, tzinfo=timezone.utc)


def test_retry_classifier_never_blind_retries_ambiguous_write_and_agent_offline_is_free():
    ambiguous = retry_decision(
        RetryClassification.AMBIGUOUS_AFTER_SEND,
        semantic_retry_count=0,
        now=NOW,
        rng=lambda _a, _b: 0.0,
    )
    assert ambiguous.retry is False
    assert ambiguous.terminal_reason == "AMBIGUOUS_AFTER_SEND"

    offline = retry_decision(
        RetryClassification.AGENT_OFFLINE,
        semantic_retry_count=999,
        now=NOW,
        rng=lambda _a, _b: 0.5,
    )
    assert offline.retry is True
    assert offline.consumes_semantic_attempt is False
    assert classify_failure(ambiguous_after_send=True) is RetryClassification.AMBIGUOUS_AFTER_SEND
    assert classify_failure(error_code="AGENT_OFFLINE") is RetryClassification.AGENT_OFFLINE


def test_retry_after_delta_http_date_and_operation_deadline_are_bounded():
    assert parse_retry_after("17", now=NOW) == 17.0
    assert parse_retry_after("Sat, 19 Sep 2026 12:00:20 GMT", now=NOW) == 20.0
    assert parse_retry_after("not-a-date", now=NOW) is None

    decision = retry_decision(
        RetryClassification.REMOTE_429,
        semantic_retry_count=1,
        retry_after="120",
        now=NOW,
        operation_deadline=NOW + timedelta(seconds=30),
        rng=lambda _a, _b: 0.0,
    )
    assert decision.retry is True
    assert decision.delay_seconds == 30.0


def test_redaction_canaries_are_absent_from_operational_output():
    canaries = {
        "cis": "010123456789012821ABC",
        "kiz": "FULL-KIZ-CANARY",
        "session_token": "SESSION-CANARY-012345678901234567890",
        "csrf_token": "CSRF-CANARY-012345678901234567890",
        "invite_token": "INVITE-CANARY-012345678901234567890",
        "agent_credential": "AGENT-CANARY-012345678901234567890",
        "wb_token": "WB-CANARY-012345678901234567890",
        "ozon_api_key": "OZON-CANARY-012345678901234567890",
        "true_api_bearer": "TRUEAPI-CANARY-012345678901234567890",
        "pin": "12345678",
        "private_key": "-----BEGIN PRIVATE KEY-----\nCANARY\n-----END PRIVATE KEY-----",
        "database_url": "postgresql+psycopg://user:DB-PASSWORD-CANARY@db/wbcz",
        "artifact_key": "ARTIFACT-KEY-CANARY",
        "audit_key": "AUDIT-KEY-CANARY",
        "master_key": "MASTER-KEY-CANARY",
    }
    safe = sanitize_operational_data({"nested": canaries, "message": "Bearer BEARER-CANARY-01234567890"})
    rendered = repr(safe)
    for value in canaries.values():
        assert value not in rendered
    assert "BEARER-CANARY-01234567890" not in rendered


def test_agent_protocol_compatibility_window_and_minimum_agent_version():
    cfg = SimpleNamespace(
        agent_protocol_current="m15-v1",
        agent_protocol_minimum="m14-v1",
        agent_minimum_version="0.5.1",
    )
    assert evaluate_protocol(
        AgentHandshake("m15-v1", "0.5.1", ("CIS_INFO",), ("TYPED_JOBS",)),
        config=cfg,
    ) == ProtocolCompatibility.COMPATIBLE
    assert evaluate_protocol(
        AgentHandshake("m13-v1", "0.5.1", ("CIS_INFO",), ("TYPED_JOBS",)),
        config=cfg,
    ) == ProtocolCompatibility.UPGRADE_REQUIRED
    assert evaluate_protocol(
        AgentHandshake("m16-v1", "0.5.1", ("CIS_INFO",), ("TYPED_JOBS",)),
        config=cfg,
    ) == ProtocolCompatibility.UNSUPPORTED
    assert evaluate_protocol(
        AgentHandshake("m15-v1", "0.4.9", ("CIS_INFO",), ("TYPED_JOBS",)),
        config=cfg,
    ) == ProtocolCompatibility.UPGRADE_REQUIRED


def test_encrypted_filesystem_secret_provider_roundtrip_wrong_key_and_plaintext_absent(tmp_path: Path):
    key_path = tmp_path / "master.key"
    key_path.write_bytes(b"k" * 32)
    root = tmp_path / "secrets"
    provider = EncryptedVersionedFilesystemSecretProvider(root, master_key_path=key_path)
    secret = "M15-PLAINTEXT-CANARY-" + "X" * 40

    staged = provider.stage("org-a/participant-a", "wb-token", secret)
    assert secret not in repr(staged)
    version = provider.activate(staged)
    assert provider.get(version.ref).value == secret

    on_disk = b"".join(path.read_bytes() for path in root.rglob("*") if path.is_file())
    assert secret.encode() not in on_disk

    wrong_key = tmp_path / "wrong.key"
    wrong_key.write_bytes(b"x" * 32)
    wrong = EncryptedVersionedFilesystemSecretProvider(root, master_key_path=wrong_key)
    with pytest.raises(SecretProviderError, match="SECRET_DECRYPT_FAILED"):
        wrong.get(version.ref)

    version_file = next(path for path in root.rglob("*.json") if path.name.startswith("v_"))
    corrupted = bytearray(version_file.read_bytes())
    corrupted[-2] ^= 1
    version_file.write_bytes(corrupted)
    with pytest.raises(SecretProviderError):
        provider.get(version.ref)


def test_production_compose_keeps_write_gate_off_and_wires_worker_artifact_secret_volumes():
    root = Path(__file__).parents[1]
    compose = (root / "docker-compose.prod.yml").read_text(encoding="utf-8")
    assert "marking-worker:" in compose
    assert 'WBCZ_TRUE_API_WRITE_ENABLED: "false"' in compose
    assert 'WBCZ_AGENT_LEGACY_BOOTSTRAP_ENABLED: "false"' in compose
    assert "marking_artifacts:/var/lib/wbcz/artifacts" in compose
    assert "marking_secret_store:/var/lib/wbcz/secret-store" in compose
    assert "marking-postgres" in compose
    postgres = compose.split("  marking-postgres:", 1)[1].split("  marking-migrate:", 1)[0]
    assert "\n    ports:" not in postgres


def test_live_does_not_touch_database_and_ready_fails_closed_when_database_is_down():
    class BrokenSessionFactory:
        def __call__(self):
            raise RuntimeError("synthetic database outage")

    cfg = replace(
        WebConfig.from_env(),
        environment="test",
        trusted_hosts=("testserver",),
        build_sha="a" * 40,
    ).validate_for_startup()
    app = create_app(
        cfg,
        session_factory=BrokenSessionFactory(),
    )
    client = TestClient(app)
    live = client.get("/api/live")
    assert live.status_code == 200
    assert live.json()["status"] == "live"
    ready = client.get("/api/ready")
    assert ready.status_code == 503
    assert ready.json()["reason_code"] == "DATABASE_UNAVAILABLE"
    assert "postgresql" not in repr(ready.json()).lower()


def test_worker_drain_stops_new_claims_without_execution():
    runtime = ProductionWorkerRuntime(
        session_factory=None,
        config=SimpleNamespace(),
        worker_id="worker-drain",
        instance_id="instance-drain",
        draining=True,
    )
    calls = []
    runtime.heartbeat = lambda **kwargs: calls.append(kwargs)
    runtime._claim = lambda: (_ for _ in ()).throw(AssertionError("draining worker must not claim"))
    runtime._execute = lambda _claim: (_ for _ in ()).throw(AssertionError("draining worker must not execute"))
    assert runtime.run_once() is False
    assert calls == [{"state": "DRAINING"}]


def test_m11_rate_window_survives_agent_restart(tmp_path: Path):
    db_path = tmp_path / "replay.sqlite"
    capability = DISPENSER_CAPABILITIES[DispenserCapabilityName.CREATE_EXPORT]
    with WindowsAgentReplayStore(db_path) as first_store:
        limiter = DurableDispenserRateLimiter(first_store, wall_clock=lambda: 1000.0)
        for _ in range(capability.requests_per_minute):
            assert limiter.consume(capability, scope_key="participant-a", now_monotonic=0.0).allowed
    with WindowsAgentReplayStore(db_path) as second_store:
        restarted = DurableDispenserRateLimiter(second_store, wall_clock=lambda: 1000.0)
        decision = restarted.consume(capability, scope_key="participant-a", now_monotonic=0.0)
        assert decision.allowed is False
        assert decision.retry_after_seconds > 0


def test_strict_production_config_rejects_legacy_agent_bootstrap_and_missing_runtime_paths():
    base = WebConfig.from_env()
    unsafe = replace(
        base,
        environment="production",
        process_role="web",
        app_url="https://mark.example.test",
        trusted_proxy_cidrs=("127.0.0.1/32",),
        agent_legacy_bootstrap_enabled=True,
        agent_machine_token="X" * 40,
        report_artifact_root="/var/lib/wbcz/artifacts",
        report_temp_root="/var/lib/wbcz/tmp",
        secret_provider_root="/var/lib/wbcz/secret-store",
        secret_provider_master_key_path="/run/keys/secret.key",
        artifact_keyring_root="/run/keys/artifacts",
        audit_key_path="/run/keys/audit.key",
        backup_status_path="/run/status/backup.json",
    )
    with pytest.raises(ValueError, match="LEGACY_BOOTSTRAP"):
        unsafe.validate_m15_production_runtime()

    missing = replace(unsafe, agent_legacy_bootstrap_enabled=False, agent_machine_token="", secret_provider_root=None)
    with pytest.raises(ValueError, match="SECRET_PROVIDER_ROOT"):
        missing.validate_m15_production_runtime()


def test_windows_agent_config_does_not_accept_missing_participant_credential(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("WBCZ_AGENT_BACKEND_URL", "https://agent.example.test")
    monkeypatch.setenv("WBCZ_PARTICIPANT_INN", "7800000000")
    monkeypatch.setenv("WBCZ_AGENT_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("WBCZ_AGENT_MACHINE_TOKEN", raising=False)
    with pytest.raises(ValueError, match="enrollment is required"):
        WindowsAgentConfig.from_env()
