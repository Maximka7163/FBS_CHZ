from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tarfile

import pytest

ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location("build_offline_bundle", ROOT / "scripts" / "build_offline_bundle.py")
assert SPEC and SPEC.loader
bundle = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bundle)

SOURCE_SHA = "cc3054eefba5d07c45dbb2e27d9fc2ba37c91555"
SOURCE_BRANCH = "web/v0.5.1-deployment-package"
FIXED_TIMESTAMP = "2026-09-12T19:06:03Z"
BUILDER_SHA = "f" * 40
INIT_SCRIPT = ROOT / "deploy" / "init-production-env.sh"
NORMALIZE_SCRIPT = ROOT / "deploy" / "normalize-release-permissions.sh"
DOCKERFILE = ROOT / "Dockerfile.backend"
RUNBOOK = ROOT / "docs" / "WEB_V052_OFFLINE_DEPLOY_RUNBOOK.md"


def _write(path: Path, text: str = "fixture\n") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _fixture_source(tmp_path: Path) -> Path:
    source = tmp_path / "source"
    for relative in bundle.ROOT_FILES:
        _write(source / relative)
    for relative in bundle.DOC_FILES:
        _write(source / relative)
    _write(source / "src/wbcz/__init__.py")
    _write(source / "src/wbcz_web/__init__.py")
    _write(source / "migrations/env.py")
    _write(source / "migrations/versions/0001.py")
    _write(source / "deploy/nginx/mark.sellari.ru.conf.example")
    _write(source / "frontend/dist/index.html", '<script src="/assets/app.js"></script>\n')
    _write(source / "frontend/dist/assets/app.js", 'fetch("/api/health", {credentials:"same-origin"});\n')
    return source


def _build(tmp_path: Path, name: str) -> tuple[Path, Path]:
    source = _fixture_source(tmp_path / name)
    output = tmp_path / name / "out"
    return bundle.build_bundle(
        source_root=source,
        packaging_root=ROOT,
        output_dir=output,
        source_sha=SOURCE_SHA,
        source_branch=SOURCE_BRANCH,
        build_timestamp_utc=FIXED_TIMESTAMP,
        builder_sha=BUILDER_SHA,
    )


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _extract(archive: Path, target: Path) -> Path:
    with tarfile.open(archive, "r:gz") as tar:
        tar.extractall(target, filter="data")
    return target / bundle.ARCHIVE_PREFIX


def _parse_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        if not raw or raw.startswith("#"):
            continue
        key, value = raw.split("=", 1)
        values[key] = value
    return values


def _run_init(target: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["WBCZ_INIT_TEST_MODE"] = "1"
    env["WBCZ_ENV_FILE_TARGET"] = str(target)
    return subprocess.run(
        ["sh", str(INIT_SCRIPT)],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def test_bundle_is_reproducible_and_complete(tmp_path):
    first, _ = _build(tmp_path, "first")
    second, _ = _build(tmp_path, "second")
    assert first.name == "sellari-marking-0.5.1-cc3054eefba5-r3.tar.gz"
    assert _digest(first) == _digest(second)
    with tarfile.open(first, "r:gz") as tar:
        names = set(tar.getnames())
    prefix = bundle.ARCHIVE_PREFIX
    required = {
        f"{prefix}/RELEASE.json",
        f"{prefix}/SHA256SUMS",
        f"{prefix}/Dockerfile.backend",
        f"{prefix}/docker-compose.prod.yml",
        f"{prefix}/alembic.ini",
        f"{prefix}/.env.production.example",
        f"{prefix}/frontend/index.html",
        f"{prefix}/deploy/nginx/mark.sellari.ru.conf.example",
        f"{prefix}/deploy/nginx/mark.sellari.ru.http-staging.conf.example",
        f"{prefix}/deploy/init-production-env.sh",
        f"{prefix}/deploy/normalize-release-permissions.sh",
        f"{prefix}/docs/WEB_V052_OFFLINE_DEPLOY_RUNBOOK.md",
    }
    assert required.issubset(names)


def test_release_json_has_exact_approved_source_sha_and_v2_metadata(tmp_path):
    archive, _ = _build(tmp_path, "release")
    root = _extract(archive, tmp_path / "extract")
    metadata = json.loads((root / "RELEASE.json").read_text(encoding="utf-8"))
    assert metadata["application_version"] == "0.5.1"
    assert metadata["source_git_sha"] == SOURCE_SHA
    assert metadata["source_branch"] == SOURCE_BRANCH
    assert metadata["frontend_built_from_sha"] == SOURCE_SHA
    assert metadata["build_timestamp_utc"] == FIXED_TIMESTAMP
    assert metadata["bundle_format"] == "sellari-marking-offline-v2"
    assert metadata["operator_safe_env_bootstrap"] is True
    assert metadata["runtime_permission_hardening"] is True
    assert metadata["release_permission_normalization"] is True


def test_internal_sha256s_verify_all_files(tmp_path):
    archive, _ = _build(tmp_path, "sums")
    root = _extract(archive, tmp_path / "extract")
    for line in (root / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        expected, relative = line.split("  ", 1)
        assert _digest(root / relative) == expected


def test_archive_sidecar_verifies_final_archive(tmp_path):
    archive, sidecar = _build(tmp_path, "sidecar")
    expected, name = sidecar.read_text(encoding="utf-8").strip().split("  ", 1)
    assert name == archive.name
    assert expected == _digest(archive)


def test_archive_excludes_git_secrets_private_data_and_desktop_live_api(tmp_path):
    source = _fixture_source(tmp_path / "forbidden")
    _write(source / ".git/config", "token=do-not-package\n")
    _write(source / ".env.production", "SECRET=do-not-package\n")
    _write(source / "private.xlsx", "do-not-package\n")
    _write(source / "src/wbcz_ui/live_true_api.py", "do-not-package\n")
    output = tmp_path / "forbidden" / "out"
    archive, _ = bundle.build_bundle(
        source_root=source,
        packaging_root=ROOT,
        output_dir=output,
        source_sha=SOURCE_SHA,
        source_branch=SOURCE_BRANCH,
        build_timestamp_utc=FIXED_TIMESTAMP,
        builder_sha=BUILDER_SHA,
    )
    with tarfile.open(archive, "r:gz") as tar:
        names = tar.getnames()
    assert not any("/.git/" in name or name.endswith("/.git") for name in names)
    assert not any(name.endswith("/.env.production") for name in names)
    assert not any(name.endswith(".xlsx") for name in names)
    assert not any("/src/wbcz_ui/" in name for name in names)


def test_production_frontend_is_prebuilt_same_origin_and_has_no_localhost(tmp_path):
    archive, _ = _build(tmp_path, "frontend")
    root = _extract(archive, tmp_path / "extract")
    frontend_text = "\n".join(
        p.read_text(encoding="utf-8", errors="ignore")
        for p in (root / "frontend").rglob("*") if p.is_file()
    )
    assert "/api/" in frontend_text
    assert "localhost" not in frontend_text
    assert "127.0.0.1" not in frontend_text
    assert not (root / "frontend/package.json").exists()
    assert not (root / "frontend/node_modules").exists()


def test_offline_runbook_requires_no_github_access_or_node_on_vps():
    text = RUNBOOK.read_text(encoding="utf-8")
    assert "git clone" not in text
    assert "git fetch" not in text
    assert "git checkout" not in text
    assert "No Git and no Node/npm are required on the VPS" in text
    assert "sha256sum -c SHA256SUMS" in text
    assert SOURCE_SHA in text


def test_runbook_validates_compose_without_resolved_config_leak():
    text = RUNBOOK.read_text(encoding="utf-8")
    assert "config -q" in text
    assert not re.search(r"config\s*>\s*/tmp", text)
    assert not re.search(r"config\s+--format\s+(json|yaml)", text)
    assert "/tmp/sellari-marking-compose" not in text
    assert "Do not redirect rendered Compose configuration" in text


def test_runbook_defines_qwen_secret_boundary_and_mock_inn():
    text = RUNBOOK.read_text(encoding="utf-8")
    assert "Qwen/server automation is **not trusted for production secrets**" in text
    assert "THIS IS A MOCK/STAGING PARTICIPANT INN." in text
    assert "WBCZ_OWN_INN=1234567890" in text
    assert "WBCZ_DATABASE_URL" in text
    assert "WBCZ_POSTGRES_PASSWORD" in text
    assert "Owner bootstrap is not part of the deployment helper" in text


def test_init_script_creates_0600_env_with_fixed_safe_values(tmp_path):
    target = tmp_path / "runtime" / ".env.production"
    result = _run_init(target)
    assert result.returncode == 0, result.stderr
    assert target.is_file()
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    values = _parse_env(target)
    assert values["WBCZ_ENV"] == "production"
    assert values["WBCZ_OWN_INN"] == "1234567890"
    assert values["WBCZ_SESSION_TTL_SECONDS"] == "43200"
    assert values["WBCZ_COOKIE_SECURE"] == "true"
    assert values["WBCZ_SESSION_COOKIE_NAME"] == "wbcz_session"
    assert values["WBCZ_CSRF_COOKIE_NAME"] == "wbcz_csrf"
    assert values["WBCZ_DEBUG"] == "false"
    assert values["WBCZ_TRUSTED_HOSTS"] == "mark.sellari.ru"
    assert values["WBCZ_APP_VERSION"] == "0.5.1"
    assert values["WBCZ_BUILD_SHA"] == SOURCE_SHA
    assert values["WBCZ_HEALTHCHECK_HOST"] == "mark.sellari.ru"
    assert values["WBCZ_POSTGRES_DB"] == "wbcz"
    assert values["WBCZ_POSTGRES_USER"] == "wbcz"
    assert values["WBCZ_BACKEND_IMAGE"] == "sellari-marking-backend"
    assert values["WBCZ_BACKEND_PORT"] == "8765"


def test_generated_db_secret_is_256_bits_hex_and_shared_with_database_url(tmp_path):
    target = tmp_path / ".env.production"
    result = _run_init(target)
    assert result.returncode == 0, result.stderr
    values = _parse_env(target)
    secret = values["WBCZ_POSTGRES_PASSWORD"]
    assert re.fullmatch(r"[0-9a-f]{64}", secret)
    assert len(bytes.fromhex(secret)) == 32
    assert values["WBCZ_DATABASE_URL"] == (
        f"postgresql+psycopg://wbcz:{secret}@marking-postgres:5432/wbcz"
    )


def test_init_script_output_never_contains_generated_secret_or_database_url(tmp_path):
    target = tmp_path / ".env.production"
    result = _run_init(target)
    assert result.returncode == 0, result.stderr
    values = _parse_env(target)
    secret = values["WBCZ_POSTGRES_PASSWORD"]
    output = result.stdout + result.stderr
    assert secret not in output
    assert values["WBCZ_DATABASE_URL"] not in output
    assert "WBCZ_POSTGRES_PASSWORD=" not in output
    assert "WBCZ_DATABASE_URL=" not in output
    assert "DB_SECRET_GENERATED=YES" in result.stdout


def test_init_script_refuses_to_overwrite_existing_env(tmp_path):
    target = tmp_path / ".env.production"
    first = _run_init(target)
    assert first.returncode == 0, first.stderr
    before = target.read_bytes()
    second = _run_init(target)
    assert second.returncode != 0
    assert target.read_bytes() == before
    secret = _parse_env(target)["WBCZ_POSTGRES_PASSWORD"]
    assert secret not in second.stdout
    assert secret not in second.stderr
    assert "refusing to overwrite" in second.stderr.lower()


def test_init_script_target_override_is_test_harness_only(tmp_path):
    target = tmp_path / ".env.production"
    env = os.environ.copy()
    env.pop("WBCZ_INIT_TEST_MODE", None)
    env["WBCZ_ENV_FILE_TARGET"] = str(target)
    result = subprocess.run(
        ["sh", str(INIT_SCRIPT)],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode != 0
    assert not target.exists()
    assert "allowed only in WBCZ_INIT_TEST_MODE=1" in result.stderr


def test_packaged_init_script_is_executable_and_env_file_is_not_packaged(tmp_path):
    archive, _ = _build(tmp_path, "init-script")
    with tarfile.open(archive, "r:gz") as tar:
        members = {member.name: member for member in tar.getmembers()}
    script_name = f"{bundle.ARCHIVE_PREFIX}/deploy/init-production-env.sh"
    normalize_name = f"{bundle.ARCHIVE_PREFIX}/deploy/normalize-release-permissions.sh"
    assert script_name in members
    assert normalize_name in members
    assert members[script_name].mode == 0o755
    assert members[normalize_name].mode == 0o755
    assert not any(name.endswith("/.env.production") for name in members)


def test_operator_hardening_preserves_true_api_write_sign_submission_safety():
    text = RUNBOOK.read_text(encoding="utf-8")
    assert "true_api=mock" in text
    assert "true_api_write=false" in text
    assert "document_signing=false" in text
    assert "submission=false" in text
    assert "windows_bridge=false" in text
    assert "registration=false" in text


def test_bundle_builder_rejects_unapproved_source_sha(tmp_path):
    source = _fixture_source(tmp_path / "wrong")
    with pytest.raises(ValueError, match="source SHA must be approved exact SHA"):
        bundle.build_bundle(
            source_root=source,
            packaging_root=ROOT,
            output_dir=tmp_path / "wrong" / "out",
            source_sha="0" * 40,
            source_branch=SOURCE_BRANCH,
            build_timestamp_utc=FIXED_TIMESTAMP,
            builder_sha=BUILDER_SHA,
        )


def test_hardened_dockerfile_normalizes_alembic_permissions_before_runtime_user():
    text = DOCKERFILE.read_text(encoding="utf-8")
    assert "find /app/migrations -type d -exec chmod 0755 {} +" in text
    assert "find /app/migrations -type f -exec chmod 0644 {} +" in text
    assert "chmod 0644 /app/alembic.ini" in text
    assert "USER wbcz" in text
    assert text.index("chmod 0644 /app/alembic.ini") < text.index("USER wbcz")
    assert "chmod 0777" not in text
    assert "USER root" not in text


def test_bundle_uses_packaging_hardened_dockerfile_not_frozen_source_copy(tmp_path):
    archive, _ = _build(tmp_path, "dockerfile")
    root = _extract(archive, tmp_path / "extract")
    assert (root / "Dockerfile.backend").read_bytes() == DOCKERFILE.read_bytes()


def test_archive_normalizes_release_and_frontend_modes(tmp_path):
    archive, _ = _build(tmp_path, "modes")
    with tarfile.open(archive, "r:gz") as tar:
        members = {member.name: member for member in tar.getmembers()}
    prefix = bundle.ARCHIVE_PREFIX
    assert members[f"{prefix}/frontend"].mode == 0o755
    assert members[f"{prefix}/frontend/index.html"].mode == 0o644
    assert members[f"{prefix}/migrations"].mode == 0o755
    assert members[f"{prefix}/migrations/env.py"].mode == 0o644
    assert members[f"{prefix}/migrations/versions"].mode == 0o755


def test_release_normalizer_is_non_writable_and_runbook_requires_it():
    script = NORMALIZE_SCRIPT.read_text(encoding="utf-8")
    runbook = RUNBOOK.read_text(encoding="utf-8")
    assert "find \"$TARGET\" -type d -exec chmod 0755 {} +" in script
    assert "find \"$TARGET\" -type f -exec chmod 0644 {} +" in script
    assert "chmod 0777" not in script
    assert "normalize-release-permissions.sh" in runbook
    assert "RELEASE_PERMISSIONS_NORMALIZED=YES" in runbook
