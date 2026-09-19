from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tomllib


ROOT = Path(__file__).resolve().parents[1]
MIGRATION = "0016_m15_production_hardening"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_sha() -> str:
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()


def build_manifest(*, sbom_path: Path | None = None) -> dict:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    build_sha = git_sha()
    lock = ROOT / "requirements.production.lock"
    frontend_lock = ROOT / "frontend/package-lock.json"
    if not lock.is_file() or not frontend_lock.is_file():
        raise RuntimeError("committed production dependency locks are required")
    tracked = [
        "pyproject.toml",
        "docker-compose.prod.yml",
        "Dockerfile.backend",
        "migrations/versions/0016_m15_production_hardening.py",
        "deploy/nginx/mark.sellari.ru.conf.example",
        "requirements.production.lock",
        "frontend/package-lock.json",
    ]
    checksums = {name: sha256_file(ROOT / name) for name in tracked}
    sbom_sha = sha256_file(sbom_path) if sbom_path is not None and sbom_path.is_file() else None
    return {
        "schema": "wbcz-m15-release-v1",
        "build_sha": build_sha,
        "app_version": pyproject["project"]["version"],
        "migration_revision": MIGRATION,
        "dependency_lock_sha256": sha256_file(lock),
        "frontend_lock_sha256": sha256_file(frontend_lock),
        "sbom_sha256": sbom_sha,
        "ci": {
            "github_run_id": os.getenv("GITHUB_RUN_ID"),
            "github_run_attempt": os.getenv("GITHUB_RUN_ATTEMPT"),
            "github_workflow": os.getenv("GITHUB_WORKFLOW"),
        },
        "image_digest": os.getenv("WBCZ_IMAGE_DIGEST") or None,
        "agent_protocol_current": "m15-v1",
        "agent_protocol_minimum": "m14-v1",
        "minimum_agent_version": pyproject["project"]["version"],
        "feature_gate_defaults": {
            "public_registration": False,
            "true_api_production_write": False,
            "wb_mutation": False,
            "ozon_mutation": False,
            "legacy_global_agent_bootstrap": False,
            "m7_xml_write": False,
            "m8_suz_wire": False,
            "m10_ozon_wire": False,
        },
        "known_external_blockers": {
            "M7": "M7_FULL_XML_WRITE_BLOCKED_ON_OFFICIAL_XSD",
            "M8": "M8_FULL_SUZ_WIRE_BLOCKED_ON_OFFICIAL_CORE_SUZ_ARTIFACTS",
            "M10": "M10_WIRE_READY=NO;M10_EXECUTABLE_READ_CAPABILITIES=NONE",
        },
        "artifact_checksums": checksums,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--sbom", default=None)
    args = parser.parse_args()
    payload = build_manifest(sbom_path=Path(args.sbom) if args.sbom else None)
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
