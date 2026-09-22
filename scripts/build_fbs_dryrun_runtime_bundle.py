from __future__ import annotations

import argparse
import datetime as dt
import gzip
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile

APP_VERSION = "0.5.1"
EXPECTED_ALEMBIC_HEAD = "0020_printing_physical_spool"
EXPECTED_SOURCE_BRANCH = "fix/fbs-dryrun-artifact-closure-001"
ARCHIVE_FORMAT = "sellari-marking-fbs-dryrun-v1"

ROOT_FILES = (
    "Dockerfile.backend", "docker-compose.prod.yml", "alembic.ini",
    ".env.production.example", ".dockerignore", "pyproject.toml",
    "requirements.production.lock",
)
SOURCE_DIRS = ("src/wbcz", "src/wbcz_web", "migrations", "deploy/nginx", "deploy/postgres")
OPERATIONAL_FILES = (
    "docs/FBS_SERVER_DRYRUN_DEPLOYMENT_PREP.md",
    "docs/M15_WINDOWS_AGENT_OPERATIONS.md",
    "scripts/m15_backup_contract.py",
    "scripts/m15_release_safety.py",
    "scripts/m15_restore_verify.py",
    "scripts/m15_secret_scan.py",
    "scripts/m15_verify_dependency_lock.py",
)
FORBIDDEN_PARTS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".pytest_cache"}
FORBIDDEN_FILENAMES = {".env", ".env.production"}
FORBIDDEN_SUFFIXES = {".xlsx", ".xls", ".sqlite", ".sqlite3", ".db", ".pem", ".key", ".p12", ".pfx", ".pyc"}
SECRET_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"github_pat_", b"ghp_",
)
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")

def _tracked_files(root: Path) -> set[str]:
    raw = subprocess.check_output(
        ["git", "-C", str(root), "ls-files", "-z"],
    )
    return {item.decode("utf-8") for item in raw.split(b"\0") if item}


def _copy_file(root: Path, bundle: Path, relative: str, tracked: set[str]) -> None:
    if relative not in tracked:
        raise ValueError(f"required bundle source is not Git-tracked: {relative}")
    source = root / relative
    if not source.is_file() or source.is_symlink():
        raise FileNotFoundError(f"required FBS dry-run file missing or unsafe: {relative}")
    target = bundle / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)


def _copy_tree(root: Path, bundle: Path, relative: str, tracked: set[str]) -> None:
    prefix = relative.rstrip("/") + "/"
    candidates = sorted(path for path in tracked if path.startswith(prefix))
    if not candidates:
        raise FileNotFoundError(f"required tracked FBS dry-run directory missing: {relative}")
    for rel_text in candidates:
        rel = Path(rel_text)
        path = root / rel
        if not path.is_file() or path.is_symlink():
            raise FileNotFoundError(f"tracked FBS dry-run file missing or unsafe: {rel_text}")
        if any(part in FORBIDDEN_PARTS for part in rel.parts):
            continue
        if path.name in FORBIDDEN_FILENAMES or path.suffix.lower() in FORBIDDEN_SUFFIXES:
            continue
        target = bundle / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)


def _copy_frontend_dist(dist: Path, bundle: Path) -> None:
    if not (dist / "index.html").is_file():
        raise FileNotFoundError("frontend/dist/index.html missing; build the accepted frontend first")
    for path in sorted(p for p in dist.rglob("*") if p.is_file()):
        rel = path.relative_to(dist)
        target = bundle / "frontend" / "dist" / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
    joined = b"\n".join(p.read_bytes() for p in sorted((bundle / "frontend" / "dist").rglob("*")) if p.is_file())
    if b"http://localhost" in joined or b"http://127.0.0.1" in joined:
        raise ValueError("production frontend contains localhost URL")

def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def _timestamp(value: str) -> tuple[int, str]:
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("build timestamp must include timezone")
    utc = parsed.astimezone(dt.timezone.utc).replace(microsecond=0)
    return int(utc.timestamp()), utc.isoformat().replace("+00:00", "Z")

def _verify_source(source_root: Path, source_sha: str, source_branch: str, builder_sha: str) -> None:
    if _SHA_RE.fullmatch(source_sha) is None or _SHA_RE.fullmatch(builder_sha) is None:
        raise ValueError("source_sha and builder_sha must be exact lowercase 40-char git SHAs")
    if builder_sha != source_sha:
        raise ValueError("single-tree builder_sha must equal source_sha")
    if source_branch != EXPECTED_SOURCE_BRANCH:
        raise ValueError(f"FBS dry-run bundle must be built from {EXPECTED_SOURCE_BRANCH}")
    actual = subprocess.check_output(
        ["git", "-C", str(source_root), "rev-parse", "HEAD"],
        text=True,
    ).strip()
    if actual != source_sha:
        raise ValueError("source_root HEAD does not match source_sha")
    dirty = subprocess.check_output(
        ["git", "-C", str(source_root), "status", "--porcelain=v1", "--untracked-files=all"],
        text=True,
    )
    if dirty.strip():
        raise ValueError("source tree must be clean: staged, unstaged and untracked changes are forbidden")

def _write_metadata(bundle: Path, *, source_sha: str, source_branch: str, build_timestamp_utc: str, builder_sha: str) -> None:
    metadata = {
        "application_version": APP_VERSION,
        "release_candidate": "FBS-SERVER-DRYRUN-001",
        "bundle_format": ARCHIVE_FORMAT,
        "source_git_sha": source_sha,
        "source_branch": source_branch,
        "frontend_built_from_sha": source_sha,
        "bundle_builder_git_sha": builder_sha,
        "build_timestamp_utc": build_timestamp_utc,
        "alembic_head": EXPECTED_ALEMBIC_HEAD,
        "fbs_dry_run_only": True,
        "agent_enabled": True,
        "legacy_global_agent_bootstrap": False,
        "true_api_write_enabled": False,
        "printing_enabled": False,
        "print_execution_enabled": False,
        "suz_full_km_remote_acquisition_enabled": False,
        "production_true_api_transport": "windows-outbound-agent-only",
        "production_actions_performed": False,
    }
    (bundle / "RELEASE.json").write_text(json.dumps(metadata, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

def _scan(bundle: Path) -> None:
    for path in sorted(bundle.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(bundle)
        if any(part in FORBIDDEN_PARTS for part in rel.parts):
            raise ValueError(f"forbidden path in FBS dry-run bundle: {rel.as_posix()}")
        if path.name in FORBIDDEN_FILENAMES or path.suffix.lower() in FORBIDDEN_SUFFIXES:
            raise ValueError(f"forbidden file in FBS dry-run bundle: {rel.as_posix()}")
        data = path.read_bytes()
        for marker in SECRET_MARKERS:
            if marker in data:
                raise ValueError(f"secret-like marker in FBS dry-run bundle: {rel.as_posix()}")
    compose = (bundle / "docker-compose.prod.yml").read_text(encoding="utf-8")
    required_compose = (
        'WBCZ_FBS_DRY_RUN_ONLY: "true"',
        'WBCZ_AGENT_ENABLED: "true"',
        'WBCZ_AGENT_LEGACY_BOOTSTRAP_ENABLED: "false"',
        'WBCZ_TRUE_API_WRITE_ENABLED: "false"',
        'WBCZ_PRINTING_ENABLED: "false"',
        'WBCZ_PRINT_EXECUTION_ENABLED: "false"',
        'WBCZ_SUZ_FULL_KM_REMOTE_ACQUISITION_ENABLED: "false"',
        'command: ["alembic", "upgrade", "0020_printing_physical_spool"]',
    )
    for expected in required_compose:
        if expected not in compose:
            raise ValueError(f"FBS dry-run compose invariant missing: {expected}")
    if 'command: ["alembic", "upgrade", "0016_m15_production_hardening"]' in compose:
        raise ValueError("FBS dry-run compose still targets historical M15 migration")
    if not (bundle / f"migrations/versions/{EXPECTED_ALEMBIC_HEAD}.py").is_file():
        raise ValueError("0020 migration head missing from FBS dry-run bundle")
    if (bundle / "src/wbcz_ui").exists():
        raise ValueError("desktop/live True API package must not be shipped in VPS bundle")

def _write_sums(bundle: Path) -> None:
    files = sorted(p for p in bundle.rglob("*") if p.is_file() and p.name != "SHA256SUMS")
    lines = [f"{_sha256(path)}  {path.relative_to(bundle).as_posix()}" for path in files]
    (bundle / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")

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

def build_bundle(*, source_root: Path, frontend_dist: Path, output_dir: Path, source_sha: str, source_branch: str, build_timestamp_utc: str, builder_sha: str) -> tuple[Path, Path]:
    _verify_source(source_root, source_sha, source_branch, builder_sha)
    source_root = source_root.resolve()
    frontend_dist = frontend_dist.resolve()
    output_dir = output_dir.resolve()
    if frontend_dist == source_root or source_root in frontend_dist.parents:
        raise ValueError("frontend_dist must be outside the verified Git source tree")
    if output_dir == source_root or source_root in output_dir.parents:
        raise ValueError("output_dir must be outside the verified Git source tree")
    tracked = _tracked_files(source_root)
    mtime, normalized = _timestamp(build_timestamp_utc)
    output_dir.mkdir(parents=True, exist_ok=True)
    prefix = f"sellari-marking-fbs-dryrun-{APP_VERSION}-{source_sha[:12]}"
    with tempfile.TemporaryDirectory(prefix="wbcz-fbs-dryrun-") as temp:
        bundle = Path(temp) / prefix
        bundle.mkdir()
        for relative in ROOT_FILES:
            _copy_file(source_root, bundle, relative, tracked)
        for relative in SOURCE_DIRS:
            _copy_tree(source_root, bundle, relative, tracked)
        for relative in OPERATIONAL_FILES:
            _copy_file(source_root, bundle, relative, tracked)
        _copy_frontend_dist(frontend_dist, bundle)
        _write_metadata(bundle, source_sha=source_sha, source_branch=source_branch, build_timestamp_utc=normalized, builder_sha=builder_sha)
        _scan(bundle)
        _write_sums(bundle)
        archive = output_dir / f"{prefix}.tar.gz"
        _archive(bundle, archive, mtime)
    sidecar = output_dir / f"{archive.name}.sha256"
    sidecar.write_text(f"{_sha256(archive)}  {archive.name}\n", encoding="utf-8")
    return archive, sidecar

def main() -> int:
    parser = argparse.ArgumentParser(description="Build deterministic FBS server dry-run VPS archive")
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--frontend-dist", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--source-branch", required=True)
    parser.add_argument("--build-timestamp-utc", required=True)
    parser.add_argument("--builder-sha", required=True)
    args = parser.parse_args()
    archive, sidecar = build_bundle(
        source_root=args.source_root.resolve(), frontend_dist=args.frontend_dist.resolve(),
        output_dir=args.output_dir.resolve(),
        source_sha=args.source_sha, source_branch=args.source_branch,
        build_timestamp_utc=args.build_timestamp_utc, builder_sha=args.builder_sha,
    )
    print(archive)
    print(sidecar)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
