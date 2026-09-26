from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from wbcz_web.config import WebConfig
from wbcz_local.app import (
    LOCAL_BIND_HOST,
    assert_local_foundation_safety,
    create_local_app,
)
from wbcz_local.bridge import LocalTrueApiBridgeFoundation
from wbcz_local.__main__ import _loopback_host


ROOT = Path(__file__).parents[1]


def _config(**changes) -> WebConfig:
    base = WebConfig(
        database_url="postgresql+psycopg://sellari_local:test@127.0.0.1:5432/sellari_local",
        own_inn="1234567890",
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
    return replace(base, **changes)


def test_local_app_is_loopback_fbs_surface_and_serves_frontend(tmp_path: Path) -> None:
    (tmp_path / "index.html").write_text("<!doctype html><title>Sellari</title>", encoding="utf-8")
    app = create_local_app(
        _config(),
        session_factory=lambda: None,
        frontend_dist=tmp_path,
    )
    paths = {getattr(route, "path", None) for route in app.routes}
    assert LOCAL_BIND_HOST == "127.0.0.1"
    assert "/api/auth/login" in paths
    assert "/api/files" in paths
    assert "/api/files/{import_id}/control" in paths
    assert "/api/local/true-api/status" in paths
    assert "/api/local/true-api/authenticate" in paths
    assert "/api/local/true-api/cises-info" in paths
    assert "/api/cis-inventory/info" not in paths
    assert "/api/live" in paths
    assert "/api/integrations" not in paths
    assert "/api/agent/status" not in paths
    assert "/api/agent/v1/jobs/next" not in paths
    assert "/api/printing/jobs" not in paths
    assert "/api/security/memberships" not in paths
    assert any(getattr(route, "name", "") == "sellari-local-ui" for route in app.routes)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("fbs_dry_run_only", False, "FBS_DRY_RUN_ONLY"),
        ("true_api_real_read_enabled", False, "real read"),
        ("true_api_write_enabled", True, "business writes"),
        ("agent_enabled", True, "VPS/agent"),
        ("printing_enabled", True, "printing"),
        ("print_execution_enabled", True, "printing"),
        ("suz_full_km_remote_acquisition_enabled", True, "SUZ"),
        ("trusted_hosts", ("0.0.0.0",), "loopback"),
    ],
)
def test_local_foundation_safety_fails_closed(field: str, value, message: str) -> None:
    config = _config()
    with pytest.raises(ValueError, match=message):
        assert_local_foundation_safety(replace(config, **{field: value}))


def test_local_foundation_accepts_only_closed_gates() -> None:
    config = _config()
    assert_local_foundation_safety(config)
    assert config.fbs_dry_run_only is True
    assert config.true_api_real_read_enabled is True
    assert config.true_api_write_enabled is False
    assert config.agent_enabled is False
    assert config.printing_enabled is False
    assert config.print_execution_enabled is False
    assert config.suz_full_km_remote_acquisition_enabled is False


def test_local_cli_refuses_non_loopback_bind() -> None:
    assert _loopback_host("127.0.0.1") == "127.0.0.1"
    assert _loopback_host("::1") == "::1"
    with pytest.raises(Exception):
        _loopback_host("0.0.0.0")
    with pytest.raises(Exception):
        _loopback_host("192.168.1.10")


def test_local_true_api_bridge_exposes_read_auth_but_no_business_signing() -> None:
    bridge = LocalTrueApiBridgeFoundation()
    assert callable(bridge.diagnostics)
    assert callable(bridge.authenticate)
    assert callable(bridge.read_states)
    public = {name for name in dir(bridge) if not name.startswith("_")}
    assert "sign" not in public
    assert "submit" not in public
    assert "create_document" not in public
    result = bridge.diagnostics()
    assert result["business_write_enabled"] is False


def test_local_scripts_pin_closed_gates_and_single_loopback_endpoint() -> None:
    setup = (ROOT / "Setup-Local.ps1").read_text(encoding="utf-8")
    start = (ROOT / "Start-Sellari.ps1").read_text(encoding="utf-8")
    common = (ROOT / "scripts" / "local" / "Common-Local.ps1").read_text(encoding="utf-8")
    readme = (ROOT / "LOCAL_README.md").read_text(encoding="utf-8")

    for marker in (
        "WBCZ_FBS_DRY_RUN_ONLY=true",
        "WBCZ_TRUE_API_REAL_READ_ENABLED=true",
        "WBCZ_TRUE_API_WRITE_ENABLED=false",
        "WBCZ_AGENT_ENABLED=false",
        "WBCZ_PRINTING_ENABLED=false",
        "WBCZ_PRINT_EXECUTION_ENABLED=false",
        "WBCZ_SUZ_FULL_KM_REMOTE_ACQUISITION_ENABLED=false",
    ):
        assert marker in setup
    assert '"--host", "127.0.0.1"' in start
    assert "Assert-SellariLocalSafety" in start
    assert "LOCALAPPDATA" in common
    assert "does **not** redistribute CryptoPro" in readme
    assert "WBCZ_TRUE_API_REAL_READ_ENABLED=true" in setup
    assert "stunnel_msspi.exe" in setup
    assert "cryptcp.exe" in setup
    assert "WBCZ_TRUE_API_WRITE_ENABLED=true" not in setup


def test_local_frontend_build_hides_non_fbs_settings_without_changing_default_build() -> None:
    main = (ROOT / "frontend" / "src" / "main.ts").read_text(encoding="utf-8")
    setup = (ROOT / "Setup-Local.ps1").read_text(encoding="utf-8")
    assert 'VITE_SELLARI_LOCAL_FBS_ONLY === "true"' in main
    assert 'LOCAL_FBS_ONLY ? ""' in main
    assert '!LOCAL_FBS_ONLY && viewFromUrl() === "integrations"' in main
    assert '$env:VITE_SELLARI_LOCAL_FBS_ONLY = "true"' in setup


def test_local_foundation_does_not_modify_production_entrypoint_contract() -> None:
    production_main = (ROOT / "src" / "wbcz_web" / "main.py").read_text(encoding="utf-8")
    compose = (ROOT / "docker-compose.prod.yml").read_text(encoding="utf-8")
    assert 'app = create_app()' in production_main
    assert 'CMD ["uvicorn","wbcz_web.main:app"' not in compose
    assert 'WBCZ_TRUE_API_WRITE_ENABLED: "false"' in compose
    assert 'WBCZ_FBS_DRY_RUN_ONLY: "true"' in compose
