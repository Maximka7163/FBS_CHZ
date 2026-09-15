from __future__ import annotations

from pathlib import Path

from wbcz_web.config import WebConfig

ROOT = Path(__file__).parents[1]
ACCEPTED = "bcb567a8f1e4e9261d68fa800ccc96e76518c596"
ACCEPTED_BRANCH = "ui/p0-production-workflow"


def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_runtime_package_pins_exact_accepted_source():
    builder = text("scripts/build_p0_runtime_bundle.py")
    assert f'APPROVED_SOURCE_SHA = "{ACCEPTED}"' in builder
    assert f'APPROVED_SOURCE_BRANCH = "{ACCEPTED_BRANCH}"' in builder
    assert 'EXPECTED_ALEMBIC_HEAD = "0002_p0_agent_wiring"' in builder
    assert '"src/wbcz/document_assembler.py"' in builder
    assert '"src/wbcz_web/api/agent_routes.py"' in builder
    assert '"candidate_name": "P0_TEST_CANDIDATE"' in builder


def test_production_write_is_off_at_package_boundary():
    env = text(".env.production.example")
    compose = text("docker-compose.prod.yml")
    bootstrap = text("deploy/init-production-env.sh")
    assert "WBCZ_TRUE_API_WRITE_ENABLED=false" in env
    assert "WBCZ_TRUE_API_WRITE_ENABLED: ${WBCZ_TRUE_API_WRITE_ENABLED:-false}" in compose
    assert "WBCZ_TRUE_API_WRITE_ENABLED=false" in bootstrap
    assert ACCEPTED in bootstrap
    cfg = WebConfig(
        database_url="postgresql+psycopg://u:p@db/x",
        own_inn="1234567890",
        environment="test",
    ).validate_for_startup()
    assert cfg.true_api_write_enabled is False


def test_agent_machine_secret_is_not_baked_into_package_files():
    env = text(".env.production.example")
    compose = text("docker-compose.prod.yml")
    helper = text("deploy/configure-agent-machine-secret.sh")
    assert "WBCZ_AGENT_MACHINE_TOKEN=\n" in env
    assert "WBCZ_AGENT_MACHINE_TOKEN: ${WBCZ_AGENT_MACHINE_TOKEN:-}" in compose
    assert "TOKEN_PRINTED=NO" in helper
    assert "WBCZ_TRUE_API_WRITE_ENABLED=false" in helper


def test_frontend_bundle_boundary_forbids_direct_agent_true_api_and_local_storage():
    builder = text("scripts/build_p0_runtime_bundle.py")
    for marker in (
        "markirovka.crpt.ru",
        "WBCZ_AGENT_MACHINE_TOKEN",
        "/api/agent/",
        "localStorage",
        "-----BEGIN PRIVATE KEY-----",
    ):
        assert marker in builder


def test_windows_preflight_launcher_forces_write_off_and_has_no_create_call():
    preflight = text("windows-agent/Preflight-WbczAgent.ps1")
    common = text("windows-agent/Runtime-Common.ps1")
    assert "preflight" in preflight
    assert "create_document" not in preflight
    assert "/lk/documents/create" not in preflight
    assert "$env:WBCZ_AGENT_PRODUCTION_WRITE_ENABLED = 'false'" in common
    assert "$env:WBCZ_TRUE_API_WRITE_ENABLED = 'false'" in common


def test_windows_secret_flow_uses_csprng_dpapi_and_does_not_print_token():
    token = text("windows-agent/New-WbczMachineToken.ps1")
    assert "RandomNumberGenerator" in token
    assert "ConvertFrom-SecureString" in token
    assert "Set-Clipboard" in token
    assert "Write-Output $token" not in token
    assert "TOKEN_PRINTED=NO" in token


def test_windows_uninstall_and_capture_boundaries_exist():
    uninstall = text("windows-agent/Uninstall-WbczAgent.ps1")
    capture = text("windows-agent/Save-WbczContractCapture.ps1")
    assert "CRYPTOPRO_CHANGED=NO" in uninstall
    assert "CERTIFICATE_CHANGED=NO" in uninstall
    assert "[switch]$EnableCapture" in capture
    assert "request_headers_captured = $false" in capture
    assert "request_body_captured = $false" in capture
    assert "bearer_token_captured = $false" in capture
    assert "machine_token_captured = $false" in capture
    assert "signature_captured = $false" in capture


def test_runtime_runbook_protects_unrelated_services_and_requires_https():
    runbook = text("docs/P0_RUNTIME_DEPLOYMENT_RUNBOOK.md")
    for service in ("Sellari", "DeltaMetric", "tg-bot-wb"):
        assert service in runbook
    assert "HTTPS" in runbook
    assert "0002_p0_agent_wiring" in runbook
    assert "WBCZ_TRUE_API_WRITE_ENABLED=false" in runbook
    assert ACCEPTED in runbook
