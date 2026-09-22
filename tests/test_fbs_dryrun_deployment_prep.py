from __future__ import annotations

import os
from pathlib import Path
import json

from alembic import command
from alembic.config import Config as AlembicConfig
import pytest
from sqlalchemy import create_engine, text

from wbcz_web.services.production_hardening import EXPECTED_MIGRATION_REVISION
from scripts.build_fbs_dryrun_runtime_bundle import _write_metadata

ROOT = Path(__file__).parents[1]
DB_URL = os.getenv("WBCZ_TEST_DATABASE_URL")
TARGET = "0020_printing_physical_spool"
M15 = "0016_m15_production_hardening"

def source(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")

def test_current_runtime_and_compose_are_aligned_to_0020() -> None:
    compose = source("docker-compose.prod.yml")
    assert EXPECTED_MIGRATION_REVISION == TARGET
    assert 'command: ["alembic", "upgrade", "0020_printing_physical_spool"]' in compose
    assert 'command: ["alembic", "upgrade", "0016_m15_production_hardening"]' not in compose

def test_compose_and_env_example_are_hard_dry_run_only() -> None:
    compose = source("docker-compose.prod.yml")
    env_example = source(".env.production.example")
    for value in (
        'WBCZ_FBS_DRY_RUN_ONLY: "true"',
        'WBCZ_AGENT_ENABLED: "true"',
        'WBCZ_AGENT_LEGACY_BOOTSTRAP_ENABLED: "false"',
        'WBCZ_TRUE_API_WRITE_ENABLED: "false"',
        'WBCZ_PRINTING_ENABLED: "false"',
        'WBCZ_PRINT_EXECUTION_ENABLED: "false"',
        'WBCZ_SUZ_FULL_KM_REMOTE_ACQUISITION_ENABLED: "false"',
    ):
        assert value in compose
    for value in (
        "WBCZ_FBS_DRY_RUN_ONLY=true",
        "WBCZ_AGENT_ENABLED=true",
        "WBCZ_TRUE_API_WRITE_ENABLED=false",
        "WBCZ_PRINTING_ENABLED=false",
        "WBCZ_PRINT_EXECUTION_ENABLED=false",
        "WBCZ_SUZ_FULL_KM_REMOTE_ACQUISITION_ENABLED=false",
    ):
        assert value in env_example

def test_fbs_bundle_has_separate_exact_sha_and_0020_contract() -> None:
    builder = source("scripts/build_fbs_dryrun_runtime_bundle.py")
    historical = source("scripts/build_p0_rc1_runtime_bundle.py")
    assert 'EXPECTED_ALEMBIC_HEAD = "0020_printing_physical_spool"' in builder
    assert 'EXPECTED_SOURCE_BRANCH = "fbs/server-dryrun-deployment-prep-001"' in builder
    assert '"fbs_dry_run_only": True' in builder
    assert '"agent_enabled": True' in builder
    assert '"legacy_global_agent_bootstrap": False' in builder
    assert '"true_api_write_enabled": False' in builder
    assert '"printing_enabled": False' in builder
    assert '"print_execution_enabled": False' in builder
    assert '"suz_full_km_remote_acquisition_enabled": False' in builder
    assert "source_root HEAD does not match source_sha" in builder
    assert "SHA256SUMS" in builder
    assert "SECRET_MARKERS" in builder
    assert 'EXPECTED_ALEMBIC_HEAD = "0016_m15_production_hardening"' in historical
    assert 'source_branch != "release/p0-rc1"' in historical

def test_fbs_release_metadata_claims_current_head_not_historical_m15(tmp_path) -> None:
    _write_metadata(
        tmp_path,
        source_sha="a" * 40,
        source_branch="fbs/server-dryrun-deployment-prep-001",
        build_timestamp_utc="2026-09-22T00:00:00Z",
        builder_sha="b" * 40,
    )
    data = json.loads((tmp_path / "RELEASE.json").read_text(encoding="utf-8"))
    assert data["alembic_head"] == TARGET
    assert data["fbs_dry_run_only"] is True
    assert data["agent_enabled"] is True
    assert data["legacy_global_agent_bootstrap"] is False
    assert data["true_api_write_enabled"] is False
    assert M15 not in data.values()


def test_dryrun_release_document_declares_0020_and_historical_predecessor_only() -> None:
    runbook = source("docs/FBS_SERVER_DRYRUN_DEPLOYMENT_PREP.md")
    assert "0020_printing_physical_spool" in runbook
    assert "WBCZ_FBS_DRY_RUN_ONLY=true" in runbook
    assert "WBCZ_TRUE_API_WRITE_ENABLED=false" in runbook
    assert "does **not**" in runbook
    assert "database at `0016_m15_production_hardening` upgrades" in runbook

def _reset_database() -> None:
    assert DB_URL is not None
    engine = create_engine(DB_URL, future=True)
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql("DROP SCHEMA public CASCADE")
            connection.exec_driver_sql("CREATE SCHEMA public")
    finally:
        engine.dispose()

def _upgrade(target: str) -> None:
    assert DB_URL is not None
    old = os.environ.get("WBCZ_DATABASE_URL")
    os.environ["WBCZ_DATABASE_URL"] = DB_URL
    os.environ.setdefault("WBCZ_ENV", "test")
    os.environ.setdefault("WBCZ_OWN_INN", "1234567890")
    try:
        command.upgrade(AlembicConfig(str(ROOT / "alembic.ini")), target)
    finally:
        if old is None: os.environ.pop("WBCZ_DATABASE_URL", None)
        else: os.environ["WBCZ_DATABASE_URL"] = old

def _revision() -> str:
    assert DB_URL is not None
    engine = create_engine(DB_URL, future=True)
    try:
        with engine.connect() as connection:
            return str(connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one())
    finally:
        engine.dispose()

@pytest.mark.skipif(not DB_URL, reason="WBCZ_TEST_DATABASE_URL requires PostgreSQL")
def test_fresh_database_reaches_exact_0020() -> None:
    _reset_database()
    _upgrade(TARGET)
    assert _revision() == TARGET

@pytest.mark.skipif(not DB_URL, reason="WBCZ_TEST_DATABASE_URL requires PostgreSQL")
def test_0016_database_upgrades_through_printing_chain_to_exact_0020() -> None:
    _reset_database()
    _upgrade(M15)
    assert _revision() == M15
    _upgrade(TARGET)
    assert _revision() == TARGET
