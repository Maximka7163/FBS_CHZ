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
APPROVED_SOURCE_SHA = "cc3054eefba5d07c45dbb2e27d9fc2ba37c91555"
APPROVED_SOURCE_BRANCH = "web/v0.5.1-deployment-package"
ARCHIVE_PREFIX = f"sellari-marking-{APP_VERSION}-{APPROVED_SOURCE_SHA[:12]}-r3"

ROOT_FILES = (
    "docker-compose.prod.yml",
    "alembic.ini",
    ".env.production.example",
    ".dockerignore",
    "pyproject.toml",
)
DOC_FILES = (
    "docs/WEB_V051_PRODUCTION_PACKAGE.md",
    "docs/WEB_V051_ROLLBACK.md",
    "docs/WEB_V051_SECRETS.md",
)
SOURCE_DIRS = (
    "src/wbcz",
    "src/wbcz_web",
    "migrations",
)
PACKAGING_FILES = (
    "Dockerfile.backend",
    "deploy/nginx/mark.sellari.ru.http-staging.conf.example",
    "deploy/init-production-env.sh",
    "deploy/normalize-release-permissions.sh",
    "docs/WEB_V052_OFFLINE_DEPLOY_RUNBOOK.md",
)

FORBIDDEN_PARTS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
}
FORBIDDEN_FILENAMES = {
    ".env",
    ".env.production",
}
FORBIDDEN_SUFFIXES = {
    ".xlsx",
    ".xls",
    ".sqlite",
    ".sqlite3",
    ".db",
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".pyc",
}
SECRET_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"github_pat_",
    b"ghp_",
)


def _copy_file(source_root: Path, bundle_root: Path, relative: str) -> None:
    source = source_root / relative
    if not source.is_file():
        raise FileNotFoundError(f"required production file missing: {relative}")
    target = bundle_root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)


def _copy_packaging_file(packaging_root: Path, bundle_root: Path, relative: str) -> None:
    source = packaging_root / relative
    if not source.is_file():
        raise FileNotFoundError(f"required packaging file missing: {relative}")
    target = bundle_root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)


def _copy_tree(source_root: Path, bundle_root: Path, relative: str) -> None:
    source = source_root / relative
    if not source.is_dir():
        raise FileNotFoundError(f"required production directory missing: {relative}")
    for path in sorted(p for p in source.rglob("*") if p.is_file()):
        rel = path.relative_to(source_root)
        if any(part in FORBIDDEN_PARTS for part in rel.parts):
            continue
        if path.suffix.lower() in FORBIDDEN_SUFFIXES:
            continue
        target = bundle_root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)


def _copy_frontend_dist(source_root: Path, bundle_root: Path) -> None:
    dist = source_root / "frontend" / "dist"
    if not (dist / "index.html").is_file():
        raise FileNotFoundError("frontend/dist/index.html missing; build production frontend first")
    for path in sorted(p for p in dist.rglob("*") if p.is_file()):
        rel = path.relative_to(dist)
        target = bundle_root / "frontend" / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
    text = "\n".join(
        path.read_text(encoding="utf-8", errors="ignore")
        for path in sorted((bundle_root / "frontend").rglob("*"))
        if path.is_file()
    )
    if "localhost" in text or "127.0.0.1" in text:
        raise ValueError("production frontend contains localhost/127.0.0.1")
    if "/api/" not in text:
        raise ValueError("production frontend does not contain same-origin /api/ calls")


def _write_release_metadata(
    bundle_root: Path,
    *,
    source_sha: str,
    source_branch: str,
    build_timestamp_utc: str,
    builder_sha: str,
) -> None:
    metadata = {
        "application_version": APP_VERSION,
        "source_git_sha": source_sha,
        "source_branch": source_branch,
        "build_timestamp_utc": build_timestamp_utc,
        "frontend_built_from_sha": source_sha,
        "bundle_builder_git_sha": builder_sha,
        "bundle_format": "sellari-marking-offline-v2",
        "operator_safe_env_bootstrap": True,
        "runtime_permission_hardening": True,
        "release_permission_normalization": True,
        "timestamp_policy": "approved_source_commit_timestamp",
    }
    (bundle_root / "RELEASE.json").write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _scan_bundle(bundle_root: Path) -> None:
    for path in sorted(bundle_root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(bundle_root)
        if any(part in FORBIDDEN_PARTS for part in rel.parts):
            raise ValueError(f"forbidden path in bundle: {rel.as_posix()}")
        if path.name in FORBIDDEN_FILENAMES or path.suffix.lower() in FORBIDDEN_SUFFIXES:
            raise ValueError(f"forbidden file in bundle: {rel.as_posix()}")
        data = path.read_bytes()
        for marker in SECRET_MARKERS:
            if marker in data:
                raise ValueError(f"secret-like marker in bundle: {rel.as_posix()}")
    if (bundle_root / "src" / "wbcz_ui").exists():
        raise ValueError("desktop/live True API package must not be included in VPS bundle")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _write_internal_sums(bundle_root: Path) -> None:
    files = sorted(
        p for p in bundle_root.rglob("*")
        if p.is_file() and p.name != "SHA256SUMS"
    )
    lines = [f"{_sha256(path)}  {path.relative_to(bundle_root).as_posix()}" for path in files]
    (bundle_root / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _parse_timestamp(timestamp: str) -> tuple[int, str]:
    parsed = dt.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("build timestamp must include UTC offset")
    utc = parsed.astimezone(dt.timezone.utc).replace(microsecond=0)
    return int(utc.timestamp()), utc.isoformat().replace("+00:00", "Z")


def _add_tar_entry(tar: tarfile.TarFile, path: Path, arcname: PurePosixPath, mtime: int) -> None:
    info = tar.gettarinfo(str(path), arcname.as_posix())
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    info.mtime = mtime
    if path.is_dir():
        info.mode = 0o755
        tar.addfile(info)
        return
    info.mode = 0o755 if path.name.endswith(".sh") else 0o644
    with path.open("rb") as stream:
        tar.addfile(info, stream)


def _write_reproducible_archive(bundle_root: Path, output: Path, mtime: int) -> None:
    root_name = bundle_root.name
    with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as tmp:
        tar_path = Path(tmp.name)
    try:
        with tarfile.open(tar_path, "w", format=tarfile.PAX_FORMAT) as tar:
            _add_tar_entry(tar, bundle_root, PurePosixPath(root_name), mtime)
            for path in sorted(bundle_root.rglob("*"), key=lambda p: p.relative_to(bundle_root).as_posix()):
                arc = PurePosixPath(root_name) / PurePosixPath(path.relative_to(bundle_root).as_posix())
                _add_tar_entry(tar, path, arc, mtime)
        with tar_path.open("rb") as source, output.open("wb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, compresslevel=9, mtime=mtime) as gz:
                shutil.copyfileobj(source, gz)
    finally:
        tar_path.unlink(missing_ok=True)


def build_bundle(
    *,
    source_root: Path,
    packaging_root: Path,
    output_dir: Path,
    source_sha: str,
    source_branch: str,
    build_timestamp_utc: str,
    builder_sha: str,
) -> tuple[Path, Path]:
    if source_sha != APPROVED_SOURCE_SHA:
        raise ValueError(f"source SHA must be approved exact SHA {APPROVED_SOURCE_SHA}")
    if source_branch != APPROVED_SOURCE_BRANCH:
        raise ValueError(f"source branch must be {APPROVED_SOURCE_BRANCH}")
    mtime, normalized_timestamp = _parse_timestamp(build_timestamp_utc)
    output_dir.mkdir(parents=True, exist_ok=True)
    bundle_name = ARCHIVE_PREFIX
    with tempfile.TemporaryDirectory(prefix="wbcz-offline-bundle-") as tmp:
        bundle_root = Path(tmp) / bundle_name
        bundle_root.mkdir()
        for relative in ROOT_FILES:
            _copy_file(source_root, bundle_root, relative)
        for relative in SOURCE_DIRS:
            _copy_tree(source_root, bundle_root, relative)
        for relative in DOC_FILES:
            _copy_file(source_root, bundle_root, relative)
        _copy_file(source_root, bundle_root, "deploy/nginx/mark.sellari.ru.conf.example")
        for relative in PACKAGING_FILES:
            _copy_packaging_file(packaging_root, bundle_root, relative)
        _copy_frontend_dist(source_root, bundle_root)
        _write_release_metadata(
            bundle_root,
            source_sha=source_sha,
            source_branch=source_branch,
            build_timestamp_utc=normalized_timestamp,
            builder_sha=builder_sha,
        )
        _scan_bundle(bundle_root)
        _write_internal_sums(bundle_root)
        archive = output_dir / f"{bundle_name}.tar.gz"
        _write_reproducible_archive(bundle_root, archive, mtime)
    sidecar = output_dir / f"{archive.name}.sha256"
    sidecar.write_text(f"{_sha256(archive)}  {archive.name}\n", encoding="utf-8")
    return archive, sidecar


def main() -> int:
    parser = argparse.ArgumentParser(description="Build deterministic Sellari marking offline deployment bundle")
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--packaging-root", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--source-branch", required=True)
    parser.add_argument("--build-timestamp-utc", required=True)
    parser.add_argument("--builder-sha", required=True)
    args = parser.parse_args()
    archive, sidecar = build_bundle(
        source_root=args.source_root.resolve(),
        packaging_root=args.packaging_root.resolve(),
        output_dir=args.output_dir.resolve(),
        source_sha=args.source_sha,
        source_branch=args.source_branch,
        build_timestamp_utc=args.build_timestamp_utc,
        builder_sha=args.builder_sha,
    )
    print(archive)
    print(sidecar)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
