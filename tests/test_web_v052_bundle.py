from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
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


def test_bundle_is_reproducible_and_complete(tmp_path):
    first, _ = _build(tmp_path, "first")
    second, _ = _build(tmp_path, "second")
    assert first.name == "sellari-marking-0.5.1-cc3054eefba5.tar.gz"
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
        f"{prefix}/docs/WEB_V052_OFFLINE_DEPLOY_RUNBOOK.md",
    }
    assert required.issubset(names)


def test_release_json_has_exact_approved_source_sha(tmp_path):
    archive, _ = _build(tmp_path, "release")
    root = _extract(archive, tmp_path / "extract")
    metadata = json.loads((root / "RELEASE.json").read_text(encoding="utf-8"))
    assert metadata["application_version"] == "0.5.1"
    assert metadata["source_git_sha"] == SOURCE_SHA
    assert metadata["source_branch"] == SOURCE_BRANCH
    assert metadata["frontend_built_from_sha"] == SOURCE_SHA
    assert metadata["build_timestamp_utc"] == FIXED_TIMESTAMP


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
    text = (ROOT / "docs/WEB_V052_OFFLINE_DEPLOY_RUNBOOK.md").read_text(encoding="utf-8")
    assert "git clone" not in text
    assert "git fetch" not in text
    assert "git checkout" not in text
    assert "No Git and no Node/npm are required on the VPS" in text
    assert "sha256sum -c SHA256SUMS" in text
    assert SOURCE_SHA in text


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
