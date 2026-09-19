from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).parents[1]
M15_BASE = "ce71f9e049bc7d65a0221001b2c7e5aa701f2243"
RUNTIME_COMMITS = {
    "734c9139fa141cd49bc765a26afc3f25530acc8b": "OBSOLETE_SUPERSEDED",
    "bc29f798f214c35b0b0b48f27f85ecd13ad93a50": "OBSOLETE_SUPERSEDED",
    "072fa3d302197727222d2f17c76aa5b0a374ae2d": "OBSOLETE_SUPERSEDED",
    "d68505d36b2983c22fc2927a67fcb25b721fcf47": "REQUIRED_PORT",
    "161b5dfb17350de91e6f10bbf3c9ae08232f0e20": "OBSOLETE_SUPERSEDED",
    "4f2af430fe83d367aa458e74ea99b4d03c34cd4c": "ALREADY_EQUIVALENT",
    "693312bfa6572916db511712451267d155d37dca": "ALREADY_EQUIVALENT",
    "d007620ea44301de4121fd916e2796b65a199506": "REQUIRED_PORT",
}


def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_all_eight_divergent_commits_are_classified_without_cherry_pick_claim() -> None:
    audit = text("docs/P0_RC1_RECONCILIATION_AUDIT.md")
    assert M15_BASE in audit
    assert "No commit was blindly cherry-picked" in audit
    for sha, classification in RUNTIME_COMMITS.items():
        assert sha in audit
        assert classification in audit


def test_rc1_bundle_targets_current_m15_runtime_not_legacy_p0_sha() -> None:
    builder = text("scripts/build_p0_rc1_runtime_bundle.py")
    assert 'EXPECTED_ALEMBIC_HEAD = "0016_m15_production_hardening"' in builder
    assert 'source_branch != "release/p0-rc1"' in builder
    assert "858a329b56c2cabae62e9814f540072e8a048d3f" not in builder
    assert '"src/wbcz_ui"' not in builder
    assert '"src/wbcz/agent_identity.py"' in builder
    assert '"src/wbcz_web/api/enrollment_routes.py"' in builder
    assert '"src/wbcz_web/worker.py"' in builder


def test_production_write_and_legacy_agent_bootstrap_remain_fail_closed() -> None:
    compose = text("docker-compose.prod.yml")
    common = text("windows-agent/Runtime-Common.ps1")
    assert 'WBCZ_TRUE_API_WRITE_ENABLED: "false"' in compose
    assert 'WBCZ_AGENT_LEGACY_BOOTSTRAP_ENABLED: "false"' in compose
    assert "$env:WBCZ_AGENT_PRODUCTION_WRITE_ENABLED = 'false'" in common
    assert "$env:WBCZ_TRUE_API_WRITE_ENABLED = 'false'" in common


def test_windows_runtime_package_uses_current_enrollment_model_without_baked_credentials() -> None:
    common = text("windows-agent/Runtime-Common.ps1")
    config = text("windows-agent/Set-WbczAgentConfig.ps1")
    readme = text("windows-agent/README.txt")
    assert "WBCZ_AGENT_CREDENTIAL_PATH" in common
    assert "Remove-Item Env:WBCZ_AGENT_MACHINE_TOKEN" in common
    assert "agent-credential.dpapi" in config
    assert "production_write = $false" in config
    assert "wbcz-agent enroll" in readme
    assert "New-WbczMachineToken" not in readme
    assert "configure-agent-machine-secret" not in readme


def test_windows_preflight_helper_cannot_create_business_document() -> None:
    preflight = text("windows-agent/Preflight-WbczAgent.ps1")
    assert "preflight" in preflight
    assert "create_document" not in preflight
    assert "/lk/documents/create" not in preflight
    assert "PRODUCTION_WRITE=false" in preflight


def test_installer_preserves_data_on_package_refresh() -> None:
    installer = text("windows-agent/Install-WbczAgent.ps1")
    assert "EXISTING_DATA_PRESERVED=YES" in installer
    assert "Remove-Item -LiteralPath $app" in installer
    assert "Remove-Item -LiteralPath $root -Recurse" not in installer


def test_rc1_runbook_requires_external_gates_and_forbids_runtime_actions() -> None:
    runbook = text("docs/P0_RC1_RUNTIME_RUNBOOK.md")
    assert "does not authorize" in runbook
    assert "0016_m15_production_hardening" in runbook
    assert "WBCZ_TRUE_API_WRITE_ENABLED=false" in runbook
    assert "separate future approval" in runbook
    assert "init-production-env.sh" in runbook
