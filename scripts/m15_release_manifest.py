from __future__ import annotations

import argparse
import hashlib
import json
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


def build_manifest() -> dict:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    tracked = [
        "pyproject.toml",
        "docker-compose.prod.yml",
        "Dockerfile.backend",
        "migrations/versions/0016_m15_production_hardening.py",
        "deploy/nginx/mark.sellari.ru.conf.example",
        "requirements.production.lock",
        "frontend/package-lock.json",
    ]
    checksums = {
        name: sha256_file(ROOT / name)
        for name in tracked
        if (ROOT / name).is_file()
    }
    return {
        "schema": "wbcz-m15-release-v1",
        "build_sha": git_sha(),
        "app_version": pyproject["project"]["version"],
        "migration_revision": MIGRATION,
        "agent_protocol_current": "m15-v1",
        "agent_protocol_minimum": "m14-v1",
        "minimum_agent_version": pyproject["project"]["version"],
        "feature_gate_defaults": {
            "public_registration": False,
            "true_api_production_write": False,
            "legacy_global_agent_bootstrap": False,
            "m7_xml_write": False,
            "m8_suz_wire": False,
            "m10_ozon_wire": False,
        },
        "known_external_blockers": {
            "M7": "M7_FULL_XML_WRITE_BLOCKED_ON_OFFICIAL_XSD",
            "M8": "M8_FULL_SUZ_WIRE_BLOCKED_ON_OFFICIAL_CORE_SUZ_ARTIFACTS",
            "M10": "M10_WIRE_READY=NO",
        },
        "artifact_checksums": checksums,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    payload = build_manifest()
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
