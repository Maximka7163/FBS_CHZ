from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).parents[1]


def source(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def _service(compose: str, name: str, next_name: str | None = None) -> str:
    block = compose.split(f"  {name}:", 1)[1]
    if next_name is not None:
        block = block.split(f"  {next_name}:", 1)[0]
    return block


def test_backend_http_readiness_healthcheck_is_preserved() -> None:
    dockerfile = source("Dockerfile.backend")
    compose = source("docker-compose.prod.yml")
    backend = _service(compose, "marking-backend", "marking-worker")

    assert "HEALTHCHECK " in dockerfile
    assert "http://127.0.0.1:8765/api/ready" in dockerfile
    assert "WBCZ_HEALTHCHECK_HOST" in dockerfile
    assert "healthcheck:\n      disable: true" not in backend


def test_worker_disables_inherited_web_http_healthcheck_only() -> None:
    compose = source("docker-compose.prod.yml")
    worker = _service(compose, "marking-worker", "volumes")

    assert 'command: ["python", "-m", "wbcz_web.worker"]' in worker
    assert "healthcheck:\n      disable: true" in worker
    assert "/api/ready" not in worker


def test_worker_keeps_runtime_heartbeat_and_dry_run_safety_contract() -> None:
    compose = source("docker-compose.prod.yml")
    backend = _service(compose, "marking-backend", "marking-worker")
    worker = _service(compose, "marking-worker", "volumes")

    assert 'WBCZ_WORKER_HEARTBEAT_SECONDS: ${WBCZ_WORKER_HEARTBEAT_SECONDS:-15}' in backend
    assert '<<: *runtime_environment' in worker
    assert 'WBCZ_PROCESS_ROLE: worker' in worker

    for invariant in (
        'WBCZ_FBS_DRY_RUN_ONLY: "true"',
        'WBCZ_TRUE_API_WRITE_ENABLED: "false"',
        'WBCZ_PRINTING_ENABLED: "false"',
        'WBCZ_PRINT_EXECUTION_ENABLED: "false"',
        'WBCZ_SUZ_FULL_KM_REMOTE_ACQUISITION_ENABLED: "false"',
        'WBCZ_AGENT_ENABLED: "true"',
        'WBCZ_AGENT_LEGACY_BOOTSTRAP_ENABLED: "false"',
    ):
        assert invariant in backend
