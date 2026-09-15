from __future__ import annotations

import argparse
import datetime as dt
import gzip
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import tarfile
import tempfile

APP_VERSION = "0.5.1"
APPROVED_SOURCE_SHA = "858a329b56c2cabae62e9814f540072e8a048d3f"
APPROVED_SOURCE_BRANCH = "p0/document-assembler-001"
EXPECTED_ALEMBIC_HEAD = "0002_p0_agent_wiring"
ARCHIVE_PREFIX = f"sellari-marking-p0-{APP_VERSION}-{APPROVED_SOURCE_SHA[:12]}-r1"

SOURCE_ROOT_FILES = (
    "alembic.ini",
    ".env.production.example",
    ".dockerignore",
    "pyproject.toml",
)
SOURCE_DIRS = (
    "src/wbcz",
    "src/wbcz_web",
    "migrations",
)
SOURCE_FILES = (
    "src/wbcz_ui/__init__.py",
    "src/wbcz_ui/live_true_api.py",
    "src/wbcz_ui/_live_true_api_base.py",
)
PACKAGING_FILES = (
    "Dockerfile.backend",
    "docker-compose.prod.yml",
    "deploy/init-production-env.sh",
    "deploy/normalize-release-permissions.sh",
    "deploy/configure-agent-machine-secret.sh",
    "deploy/nginx/mark.sellari.ru.conf.example",
    "deploy/nginx/mark.sellari.ru.http-staging.conf.example",
    "docs/P0_RUNTIME_DEPLOYMENT_RUNBOOK.md",
)

FORBIDDEN_PARTS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".pytest_cache"}
FORBIDDEN_FILENAMES = {".env", ".env.production"}
FORBIDDEN_SUFFIXES = {".xlsx", ".xls", ".sqlite", ".sqlite3", ".db", ".pem", ".key", ".p12", ".pfx", ".pyc"}
SECRET_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"github_pat_",
    b"ghp_",
)


def _copy_file(root: Path, bundle: Path, relative: str) -> None:
    source = root / relative
    if not source.is_file():
        raise FileNotFoundError(f"required file missing: {relative}")
    target = bundle / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)


def _copy_tree(root: Path, bundle: Path, relative: str) -> None:
    source = root / relative
    if not source.is_dir():
        raise FileNotFoundError(f"required directory missing: {relative}")
    for path in sorted(p for p in source.rglob("*") if p.is_file()):
        rel = path.relative_to(root)
        if any(part in FORBIDDEN_PARTS for part in rel.parts):
            continue
        if path.suffix.lower() in FORBIDDEN_SUFFIXES:
            continue
        target = bundle / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)


def _copy_frontend(source_root: Path, bundle: Path) -> None:
    dist = source_root / "frontend" / "dist"
    if not (dist / "index.html").is_file():
        raise FileNotFoundError("frontend/dist/index.html missing")
    for path in sorted(p for p in dist.rglob("*") if p.is_file()):
        rel = path.relative_to(dist)
        target = bundle / "frontend" / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
    text = "\n".join(
        p.read_text(encoding="utf-8", errors="ignore")
        for p in sorted((bundle / "frontend").rglob("*")) if p.is_file()
    )
    if "localhost" in text or "127.0.0.1" in text:
        raise ValueError("production frontend contains localhost address")
    if "/api/" not in text:
        raise ValueError("production frontend lacks same-origin /api/ calls")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _write_metadata(bundle: Path, *, source_branch: str, timestamp: str, builder_sha: str) -> None:
    metadata = {
        "application_version": APP_VERSION,
        "source_git_sha": APPROVED_SOURCE_SHA,
        "source_branch": source_branch,
        "frontend_built_from_sha": APPROVED_SOURCE_SHA,
        "bundle_builder_git_sha": builder_sha,
        "build_timestamp_utc": timestamp,
        "bundle_format": "sellari-marking-p0-runtime-v1",
        "backend_image": f"sellari-marking-backend:{APPROVED_SOURCE_SHA}",
        "alembic_head": EXPECTED_ALEMBIC_HEAD,
        "runtime_user": "wbcz",
        "runtime_permission_hardening": True,
        "release_permission_normalization": True,
        "operator_safe_env_bootstrap": True,
        "agent_api_path": "/api/agent/v1",
        "true_api_write_default": False,
        "production_true_api_transport": "windows-outbound-agent-only",
        "timestamp_policy": "accepted_source_commit_timestamp",
    }
    (bundle / "RELEASE.json").write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _scan(bundle: Path) -> None:
    for path in sorted(bundle.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(bundle)
        if any(part in FORBIDDEN_PARTS for part in rel.parts):
            raise ValueError(f"forbidden path: {rel.as_posix()}")
        if path.name in FORBIDDEN_FILENAMES or path.suffix.lower() in FORBIDDEN_SUFFIXES:
            raise ValueError(f"forbidden file: {rel.as_posix()}")
        data = path.read_bytes()
        for marker in SECRET_MARKERS:
            if marker in data:
                raise ValueError(f"secret-like marker: {rel.as_posix()}")
    env = (bundle / ".env.production.example").read_text(encoding="utf-8")
    if "WBCZ_TRUE_API_WRITE_ENABLED=false" not in env:
        raise ValueError("production example must keep True API write disabled")
    if "WBCZ_AGENT_MACHINE_TOKEN=" not in env:
        raise ValueError("production example must contain empty machine-token field")
    if not (bundle / "migrations/versions/0002_p0_agent_wiring.py").is_file():
        raise ValueError("migration 0002 missing")
    if not (bundle / "src/wbcz/document_assembler.py").is_file():
        raise ValueError("P0 document assembler missing")
    if not (bundle / "src/wbcz_web/api/agent_routes.py").is_file():
        raise ValueError("agent routes missing")


def _write_sums(bundle: Path) -> None:
    files = sorted(p for p in bundle.rglob("*") if p.is_file() and p.name != "SHA256SUMS")
    lines = [f"{_sha256(p)}  {p.relative_to(bundle).as_posix()}" for p in files]
    (bundle / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _timestamp(value: str) -> tuple[int, str]:
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include timezone")
    utc = parsed.astimezone(dt.timezone.utc).replace(microsecond=0)
    return int(utc.timestamp()), utc.isoformat().replace("+00:00", "Z")


def _add(tar: tarfile.TarFile, path: Path, arcname: PurePosixPath, mtime: int) -> None:
    info = tar.gettarinfo(str(path), arcname.as_posix())
    info.uid = info.gid = 0
    info.uname = info.gname = "root"
    info.mtime = mtime
    if path.is_dir():
        info.mode = 0o755
        tar.addfile(info)
        return
    info.mode = 0o755 if path.suffix == ".sh" else 0o644
    with path.open("rb") as stream:
        tar.addfile(info, stream)


def _archive(bundle: Path, output: Path, mtime: int) -> None:
    with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as tmp:
        tar_path = Path(tmp.name)
    try:
        with tarfile.open(tar_path, "w", format=tarfile.PAX_FORMAT) as tar:
            _add(tar, bundle, PurePosixPath(bundle.name), mtime)
            for path in sorted(bundle.rglob("*"), key=lambda p: p.relative_to(bundle).as_posix()):
                _add(tar, path, PurePosixPath(bundle.name) / PurePosixPath(path.relative_to(bundle).as_posix()), mtime)
        with tar_path.open("rb") as source, output.open("wb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, compresslevel=9, mtime=mtime) as gz:
                shutil.copyfileobj(source, gz)
    finally:
        tar_path.unlink(missing_ok=True)


def build_bundle(*, source_root: Path, packaging_root: Path, output_dir: Path, source_sha: str,
                 source_branch: str, build_timestamp_utc: str, builder_sha: str) -> tuple[Path, Path]:
    if source_sha != APPROVED_SOURCE_SHA:
        raise ValueError(f"source SHA must equal accepted P0 SHA {APPROVED_SOURCE_SHA}")
    if source_branch != APPROVED_SOURCE_BRANCH:
        raise ValueError(f"source branch must equal {APPROVED_SOURCE_BRANCH}")
    mtime, normalized = _timestamp(build_timestamp_utc)
    output_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="wbcz-p0-runtime-") as temp:
        bundle = Path(temp) / ARCHIVE_PREFIX
        bundle.mkdir()
        for rel in SOURCE_ROOT_FILES:
            _copy_file(source_root, bundle, rel)
        for rel in SOURCE_DIRS:
            _copy_tree(source_root, bundle, rel)
        for rel in SOURCE_FILES:
            _copy_file(source_root, bundle, rel)
        for rel in PACKAGING_FILES:
            _copy_file(packaging_root, bundle, rel)
        _copy_frontend(source_root, bundle)
        _write_metadata(bundle, source_branch=source_branch, timestamp=normalized, builder_sha=builder_sha)
        _scan(bundle)
        _write_sums(bundle)
        archive = output_dir / f"{ARCHIVE_PREFIX}.tar.gz"
        _archive(bundle, archive, mtime)
    sidecar = output_dir / f"{archive.name}.sha256"
    sidecar.write_text(f"{_sha256(archive)}  {archive.name}\n", encoding="utf-8")
    return archive, sidecar


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--source-root", required=True, type=Path)
    p.add_argument("--packaging-root", required=True, type=Path)
    p.add_argument("--output-dir", required=True, type=Path)
    p.add_argument("--source-sha", required=True)
    p.add_argument("--source-branch", required=True)
    p.add_argument("--build-timestamp-utc", required=True)
    p.add_argument("--builder-sha", required=True)
    a = p.parse_args()
    archive, sidecar = build_bundle(
        source_root=a.source_root.resolve(), packaging_root=a.packaging_root.resolve(),
        output_dir=a.output_dir.resolve(), source_sha=a.source_sha,
        source_branch=a.source_branch, build_timestamp_utc=a.build_timestamp_utc,
        builder_sha=a.builder_sha,
    )
    print(archive)
    print(sidecar)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())