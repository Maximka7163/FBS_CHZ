from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from wbcz_web.services.agent_enrollment import AgentHandshake, ProtocolCompatibility, evaluate_protocol
from wbcz_web.services.production_hardening import (
    RetryClassification,
    classify_failure,
    parse_retry_after,
    retry_decision,
    sanitize_operational_data,
)
from wbcz_web.services.production_secrets import EncryptedVersionedFilesystemSecretProvider
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
