from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from wbcz.cis_inventory import MAX_BATCH, decision_state_from_cis_info
from wbcz.models import Decision, Event, Operation
from wbcz.control_engine import decide
from wbcz_web.config import WebConfig
from wbcz_web.services.cis_inventory import CisInventoryService, CisInventoryUnavailable


ROOT = Path(__file__).parents[1]


def source(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_p0_production_read_and_write_gates_are_explicitly_closed() -> None:
    compose = source("docker-compose.prod.yml")
    env_example = source(".env.production.example")
    required_compose = (
        'WBCZ_FBS_DRY_RUN_ONLY: "true"',
        'WBCZ_TRUE_API_WRITE_ENABLED: "false"',
        'WBCZ_TRUE_API_REAL_READ_ENABLED: "false"',
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
