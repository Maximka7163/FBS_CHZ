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
from wbcz_local import preflight as local_preflight_module
from wbcz_local.preflight import find_local_psql


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
    assert "/api/auth/login" not in paths
    assert "/api/auth/logout" not in paths
    assert app.state.local_single_user_no_login is True
    assert callable(app.state.local_principal_resolver)
    assert "/api/files" in paths
    assert "/api/files/{import_id}/control" in paths
    assert "/api/local/true-api/status" in paths
    assert "/api/local/auth/prepare" in paths
    assert "/api/local/auth/complete" in paths
    assert "/api/local/true-api/authenticate" not in paths
    assert "/api/local/true-api/certificate" not in paths
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


def test_local_true_api_bridge_exposes_typed_browser_auth_but_no_signing() -> None:
    bridge = LocalTrueApiBridgeFoundation()
    assert callable(bridge.diagnostics)
    assert callable(bridge.prepare_auth)
    assert callable(bridge.complete_auth)
    assert callable(bridge.read_states)
    public = {name for name in dir(bridge) if not name.startswith("_")}
    assert "authenticate" not in public
    assert "sign" not in public
    assert "sign_bytes" not in public
    assert "sign_file" not in public
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
    assert "stunnel_msspi.exe" not in setup
    assert "WBCZ_CRYPTOPRO_STUNNEL" not in setup
    assert "cryptcp.exe" in setup
    assert 'throw "CryptoPro cryptcp.exe was not detected' not in setup
    assert "local True API does not require it" in setup
    assert "native Windows WinHTTP / SSPI / CryptoPro" in setup
    assert "WBCZ_TRUE_API_WRITE_ENABLED=true" not in setup
    assert "D54CFE9186C4B6DBE9ED73D83F289D31DA7B50000B48BA3E7C278E820578086B" in setup
    assert "Publish-SellariPinnedArtifact" in setup
    assert "Assert-SellariPinnedSha256" in setup
    assert "Invoke-WebRequest" in setup and "-OutFile $cadesApiTemp" in setup
    assert "-OutFile $cadesApiPath" not in setup
    assert "Get-FileHash" in common
    assert "SHA256" in common
    assert "CreateObjectAsync" not in setup
    assert "RandomNumberGenerator]::Fill" not in setup
    assert "[Convert]::ToHexString" not in setup
    assert "New-SellariSecureHex -ByteCount 24" in setup
    assert "$psql = Find-SellariPsql" in setup
    assert setup.count("Invoke-SellariPsqlScalar") >= 3
    assert "function New-SellariSecureHex" in common
    assert "RandomNumberGenerator]::Create()" in common
    assert "$rng.GetBytes($bytes)" in common
    assert "[System.BitConverter]::ToString($bytes)" in common
    assert "function Find-SellariPsql" in common
    assert "PostgreSQL\\16\\bin\\psql.exe" in common
    assert "function Invoke-SellariPsqlScalar" in common
    assert "function Invoke-SellariPsqlNative" in common
    assert "function Test-SellariPsqlReady" in common
    assert "function Invoke-SellariPsqlRequired" in common
    assert '$ErrorActionPreference = "Continue"' in common
    assert "$ErrorActionPreference = $previousErrorActionPreference" in common
    assert "2> $stderrPath" in common
    assert "& $psql " not in setup
    assert "Test-SellariPsqlReady -PsqlPath $psql" in setup
    assert setup.count("Invoke-SellariPsqlRequired -PsqlPath $psql") == 4
    assert "Create the local Sellari owner password" not in setup
    assert 'Read-Host "Local owner username"' not in setup
    assert "bootstrap-local-owner" in setup
    assert "bootstrap-owner $OwnerUsername" not in setup


def test_local_frontend_build_hides_non_fbs_settings_without_changing_default_build() -> None:
    main = (ROOT / "frontend" / "src" / "main.ts").read_text(encoding="utf-8")
    setup = (ROOT / "Setup-Local.ps1").read_text(encoding="utf-8")
    assert 'VITE_SELLARI_LOCAL_FBS_ONLY === "true"' in main
    assert 'LOCAL_FBS_ONLY ? ""' in main
    assert '!LOCAL_FBS_ONLY && viewFromUrl() === "integrations"' in main
    assert '$env:VITE_SELLARI_LOCAL_FBS_ONLY = "true"' in setup
    assert "renderLocalStartupError" in main
    assert "Вход по логину и паролю в локальном режиме не используется." in main


def test_local_foundation_does_not_modify_production_entrypoint_contract() -> None:
    production_main = (ROOT / "src" / "wbcz_web" / "main.py").read_text(encoding="utf-8")
    compose = (ROOT / "docker-compose.prod.yml").read_text(encoding="utf-8")
    assert 'app = create_app()' in production_main
    assert 'CMD ["uvicorn","wbcz_web.main:app"' not in compose
    assert 'WBCZ_TRUE_API_WRITE_ENABLED: "false"' in compose
    assert 'WBCZ_FBS_DRY_RUN_ONLY: "true"' in compose


def test_preflight_psql_discovery_prefers_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    path_psql = tmp_path / "path" / "psql.exe"
    path_psql.parent.mkdir(parents=True)
    path_psql.write_bytes(b"")
    monkeypatch.setattr(
        local_preflight_module.shutil,
        "which",
        lambda name: str(path_psql) if name == "psql" else None,
    )

    found = find_local_psql(windows=True, environ={})
    assert found == str(path_psql.resolve())


def test_preflight_psql_discovery_uses_standard_postgresql_16_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    standard_root = tmp_path / "Program Files"
    standard_psql = standard_root / "PostgreSQL" / "16" / "bin" / "psql.exe"
    standard_psql.parent.mkdir(parents=True)
    standard_psql.write_bytes(b"")
    monkeypatch.setattr(local_preflight_module.shutil, "which", lambda _name: None)

    found = find_local_psql(
        windows=True,
        environ={
            "ProgramW6432": str(standard_root),
            "ProgramFiles": str(standard_root),
        },
    )
    assert found == str(standard_psql.resolve())


def test_preflight_psql_discovery_genuine_miss(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(local_preflight_module.shutil, "which", lambda _name: None)

    found = find_local_psql(
        windows=True,
        environ={
            "ProgramW6432": str(tmp_path / "missing"),
            "ProgramFiles": str(tmp_path / "missing"),
            "ProgramFiles(x86)": str(tmp_path / "missing-x86"),
        },
    )
    assert found is None


def test_local_postgresql_reachability_is_independent_from_psql_client_discovery(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class CryptoStatus:
        csp_available = True
        csp_version = "5.0.13000"
        csp_version_supported = True
        csp_license_valid = True
        cryptopro_tls_sspi_available = True
        winhttp_available = True
        winhttp_gost_transport_initializable = True
        cryptcp_available = False
        cryptcp_path = None
        gost_transport_available = True

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def execute(self, _statement):
            return 1

    class Engine:
        def connect(self):
            return Connection()

        def dispose(self):
            pass

    frontend = tmp_path / "dist"
    frontend.mkdir()
    (frontend / "index.html").write_text("<!doctype html>", encoding="utf-8")

    monkeypatch.setattr(local_preflight_module.platform, "system", lambda: "Windows")
    monkeypatch.setattr(local_preflight_module, "frontend_dist_from_env", lambda: frontend)
    monkeypatch.setattr(local_preflight_module, "inspect_local_cryptopro_foundation", lambda: CryptoStatus())
    monkeypatch.setattr(local_preflight_module, "find_local_psql", lambda **_kwargs: None)
    monkeypatch.setattr(local_preflight_module.WebConfig, "from_env", staticmethod(lambda: object()))
    monkeypatch.setattr(local_preflight_module, "assert_local_foundation_safety", lambda _config: None)
    monkeypatch.setattr(local_preflight_module, "build_engine", lambda _config: Engine())

    result = local_preflight_module.local_preflight()
    checks = {item["name"]: item for item in result["checks"]}

    assert checks["postgresql_client"]["ok"] is False
    assert checks["local_postgresql"]["ok"] is True
    assert checks["local_postgresql"]["detail"] == "reachable"
    assert result["ok"] is False


def test_start_sellari_uses_python_preflight_without_path_only_psql_check() -> None:
    start = (ROOT / "Start-Sellari.ps1").read_text(encoding="utf-8")
    preflight = (ROOT / "src" / "wbcz_local" / "preflight.py").read_text(encoding="utf-8")

    assert "-m wbcz_local.preflight --json" in start
    assert "Get-Command psql" not in start
    assert 'shutil.which("psql") or shutil.which("psql.exe")' in preflight
    assert '"PostgreSQL" / "16" / "bin" / "psql.exe"' in preflight


def test_local_preflight_reports_true_api_readiness_separately_from_app_readiness() -> None:
    preflight = (ROOT / "src" / "wbcz_local" / "preflight.py").read_text(encoding="utf-8")
    assert '"true_api_local_ready"' in preflight
    assert '"true_api_live_verified": False' in preflight
    assert "APP_READY=" in preflight
    assert "TRUE_API_LOCAL_READY=" in preflight
    assert "TRUE_API_LIVE_VERIFIED=false" in preflight
    assert 'print("READY"' not in preflight
    assert "stunnel_msspi" not in preflight
