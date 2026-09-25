from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from wbcz.cis_inventory import MAX_BATCH, decision_state_from_cis_info
from wbcz.models import Decision, Event, Operation
from wbcz.control_engine import decide
from wbcz.write_pipeline import InvalidWriteOperation
from wbcz_web.api.routes import capabilities
from wbcz_web.config import WebConfig
from wbcz_web.services.agent_orchestration import AgentOrchestrationBroker
from wbcz_web.services.cis_inventory import CisInventoryService, CisInventoryUnavailable


ROOT = Path(__file__).parents[1]


def source(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def _compose_config(real_read: str | None) -> dict:
    env = os.environ.copy()
    env.update({
        "WBCZ_POSTGRES_DB": "wbcz_gate_test",
        "WBCZ_POSTGRES_SUPERUSER_PASSWORD": "synthetic-superuser-password",
        "WBCZ_APP_DB_PASSWORD": "synthetic-app-password",
        "WBCZ_MIGRATOR_DB_PASSWORD": "synthetic-migrator-password",
        "WBCZ_BACKUP_DB_PASSWORD": "synthetic-backup-password",
        "WBCZ_APP_VERSION": "0.5.1",
        "WBCZ_BUILD_SHA": "a" * 40,
        "WBCZ_DATABASE_URL": "postgresql+psycopg://app:pass@db/wbcz",
        "WBCZ_MIGRATION_DATABASE_URL": "postgresql+psycopg://migrator:pass@db/wbcz",
        "WBCZ_OWN_INN": "1234567890",
        "WBCZ_APP_URL": "https://mark.example.test",
        "WBCZ_TRUSTED_HOSTS": "mark.example.test",
        "WBCZ_TRUSTED_PROXY_CIDRS": "127.0.0.1/32",
        "WBCZ_REPORT_ARTIFACT_KEY_VERSION": "artifact-v1",
        "WBCZ_AUDIT_PSEUDONYM_KEY_ID": "audit-v1",
    })
    env.pop("WBCZ_TRUE_API_REAL_READ_ENABLED", None)
    if real_read is not None:
        env["WBCZ_TRUE_API_REAL_READ_ENABLED"] = real_read
    result = subprocess.run(
        ["docker", "compose", "-f", "docker-compose.prod.yml", "config", "--format", "json"],
        cwd=ROOT,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


class _NoPersistenceAccess:
    def __getattr__(self, name: str):
        raise AssertionError(f"write preparation touched persistence while hard-stopped: {name}")


def test_p0_production_read_and_write_gates_are_explicitly_closed() -> None:
    compose = source("docker-compose.prod.yml")
    env_example = source(".env.production.example")
    required_compose = (
        'WBCZ_FBS_DRY_RUN_ONLY: "true"',
        'WBCZ_TRUE_API_WRITE_ENABLED: "false"',
        'WBCZ_TRUE_API_REAL_READ_ENABLED: ${WBCZ_TRUE_API_REAL_READ_ENABLED:-false}',
        'WBCZ_PRINTING_ENABLED: "false"',
        'WBCZ_PRINT_EXECUTION_ENABLED: "false"',
        'WBCZ_SUZ_FULL_KM_REMOTE_ACQUISITION_ENABLED: "false"',
        'WBCZ_AGENT_ENABLED: "true"',
        'WBCZ_AGENT_LEGACY_BOOTSTRAP_ENABLED: "false"',
    )
    for value in required_compose:
        assert value in compose
    for value in (
        "WBCZ_FBS_DRY_RUN_ONLY=true",
        "WBCZ_TRUE_API_WRITE_ENABLED=false",
        "WBCZ_TRUE_API_REAL_READ_ENABLED=false",
        "WBCZ_PRINTING_ENABLED=false",
        "WBCZ_PRINT_EXECUTION_ENABLED=false",
        "WBCZ_SUZ_FULL_KM_REMOTE_ACQUISITION_ENABLED=false",
    ):
        assert value in env_example


def test_p0_production_live_read_gate_defaults_false_and_explicit_true_is_read_only() -> None:
    safety = {
        "WBCZ_FBS_DRY_RUN_ONLY": "true",
        "WBCZ_TRUE_API_WRITE_ENABLED": "false",
        "WBCZ_PRINTING_ENABLED": "false",
        "WBCZ_PRINT_EXECUTION_ENABLED": "false",
        "WBCZ_SUZ_FULL_KM_REMOTE_ACQUISITION_ENABLED": "false",
    }
    default = _compose_config(None)
    enabled = _compose_config("true")
    for service_name in ("marking-backend", "marking-worker"):
        default_env = default["services"][service_name]["environment"]
        enabled_env = enabled["services"][service_name]["environment"]
        assert default_env["WBCZ_TRUE_API_REAL_READ_ENABLED"] == "false"
        assert enabled_env["WBCZ_TRUE_API_REAL_READ_ENABLED"] == "true"
        for name, value in safety.items():
            assert default_env[name] == value
            assert enabled_env[name] == value


def test_p0_real_read_alone_keeps_mutation_capabilities_closed() -> None:
    live = WebConfig(
        database_url="postgresql+psycopg://app:pass@db/wbcz",
        own_inn="1234567890",
        agent_enabled=True,
        agent_machine_token="focused-test-agent-token-0123456789",
        true_api_real_read_enabled=True,
        true_api_write_enabled=False,
        fbs_dry_run_only=True,
        printing_enabled=False,
        print_execution_enabled=False,
        suz_full_km_remote_acquisition_enabled=False,
    )
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(config=live)))
    live_caps = capabilities(request, None)
    assert live_caps["true_api"] == "windows-agent"
    assert live_caps["true_api_write"] is False
    assert live_caps["document_signing"] is False
    assert live_caps["submission"] is False

    offline = replace(live, true_api_real_read_enabled=False)
    offline_request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(config=offline)))
    assert capabilities(offline_request, None)["true_api"] == "offline-dry-run"

    broker = AgentOrchestrationBroker(_NoPersistenceAccess(), live)  # type: ignore[arg-type]
    with pytest.raises(InvalidWriteOperation, match="FBS_DRY_RUN_ONLY"):
        broker.prepare_approved_write("must-not-be-read", None)  # type: ignore[arg-type]

    assert live.true_api_write_enabled is False
    assert live.printing_enabled is False
    assert live.print_execution_enabled is False
    assert live.suz_full_km_remote_acquisition_enabled is False


def test_p0_focused_ci_uses_synthetic_audit_key_and_production_still_requires_explicit_audit_key() -> None:
    workflow = source(".github/workflows/p0-chz-connection-focused.yml")
    assert 'WBCZ_AUDIT_PSEUDONYM_KEY: "focused-ci-test-only-pseudonym-key-20260924"' in workflow

    cfg = WebConfig(
        database_url="postgresql+psycopg://app:strong-test-password@db.example.test/wbcz",
        own_inn="1234567890",
        environment="production",
        cookie_secure=True,
        trusted_hosts=("mark.example.test",),
        build_sha="abcdef1",
        audit_pseudonym_key=None,
        audit_key_path=None,
    )
    with pytest.raises(ValueError, match="WBCZ_AUDIT_KEY_PATH or WBCZ_AUDIT_PSEUDONYM_KEY"):
        cfg.validate_for_startup()


def test_p0_production_cis_service_stops_before_real_certificate_auth() -> None:
    cfg = replace(
        WebConfig.from_env(),
        environment="production",
        agent_enabled=True,
        true_api_real_read_enabled=False,
    )
    with pytest.raises(CisInventoryUnavailable, match="REAL_CERT_READ_ONLY_AUTHORIZATION_REQUIRED"):
        CisInventoryService(None, cfg)  # type: ignore[arg-type]


def test_p0_official_true_api_states_feed_existing_decision_matrix(event: Event) -> None:
    introduced = decision_state_from_cis_info({
        "status": "INTRODUCED",
        "statusEx": "EMPTY",
        "ownerInn": "1234567890",
        "productGroup": "lp",
    })
    retired = decision_state_from_cis_info({
        "status": "RETIRED",
        "statusEx": "EMPTY",
        "withdrawReason": "DISTANCE",
        "ownerInn": "1234567890",
        "productGroup": "lp",
    })
    assert decide(replace(event, operation=Operation.SALE), introduced, "1234567890").decision is Decision.READY_TO_WITHDRAW
    assert decide(replace(event, operation=Operation.RETURN), introduced, "1234567890").decision is Decision.ALREADY_DONE
    assert decide(replace(event, operation=Operation.SALE), retired, "1234567890").decision is Decision.ALREADY_DONE
    assert decide(replace(event, operation=Operation.RETURN), retired, "1234567890").decision is Decision.READY_TO_RETURN


def test_p0_batch_control_uses_existing_cis_info_and_1000_boundary() -> None:
    orchestration = source("src/wbcz_web/services/agent_orchestration.py")
    assert MAX_BATCH == 1000
    assert 'CONTROL_CIS_BATCH = "CONTROL_CIS_BATCH"' in orchestration
    assert "job_type=AgentJobType.CIS_INFO" in orchestration
    assert "range(0, len(unique_cises), MAX_BATCH)" in orchestration
    assert '"unique_ki_pending"' in orchestration
    assert '"api_requests_queued"' in orchestration


def test_p0_agent_control_plane_is_certificate_only_until_read_gate() -> None:
    cli = source("src/wbcz/agent_cli.py")
    http = source("src/wbcz/agent_http.py")
    routes = source("src/wbcz_web/api/agent_routes.py")
    assert 'AGENT_RUNTIME_CONFIG_PATH = "/api/agent/v2/runtime-config"' in http
    assert 'AGENT_CERTIFICATES_PATH = "/api/agent/v2/certificates"' in http
    assert '@agent_v2_control_router.get("/runtime-config")' in routes
    assert '@agent_v2_control_router.post("/certificates")' in routes
    assert "if not self._real_read_enabled or self.agent is None:" in cli
    assert "CERTIFICATE_DISCOVERY_V1" in cli
    assert "CERTIFICATE_SELECTION_V1" in cli


def test_p0_ignored_wb_rows_keep_import_row_provenance_without_becoming_errors() -> None:
    imports = source("src/wbcz_web/services/imports.py")
    assert "for row_number in parsed.ignored_rows:" in imports
    assert "ImportRow(import_id=record.id,row_number=row_number,event_id=None,error=None)" in imports
    assert "record.rejected_rows=len(parsed.issues)" in imports


def test_p0_frontend_exposes_truthful_integration_and_wb_count_semantics() -> None:
    main = source("frontend/src/main.ts")
    api = source("frontend/src/api.ts")
    for text in (
        "Настройки → Интеграции",
        "Честный знак / True API",
        "Wildberries",
        "Ozon",
        "СУЗ",
        "Только чтение",
        "Отправка документов в ЧЗ отключена",
        "Токен сохранён",
        "Данные доступа сохранены",
        "Параметры СУЗ сохранены",
        "DRY RUN",
    ):
        assert text in main
    assert "Все ${view.items.length}" in main
    assert "queueKiInfo" in api
    assert "certificateStatus" in api
