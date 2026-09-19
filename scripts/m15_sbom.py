from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
EXACT = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s;]+)$")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def locked_components(path: Path) -> list[dict]:
    components = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = EXACT.fullmatch(line)
        if not match:
            raise ValueError(f"non-exact production lock entry: {line}")
        name, version = match.groups()
        components.append({
            "type": "library",
            "name": name,
            "version": version,
            "purl": f"pkg:pypi/{name.lower().replace('_','-')}@{version}",
        })
    return sorted(components, key=lambda item: item["name"].lower())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--lock", default="requirements.production.lock")
    parser.add_argument("--build-sha", default=None)
    args = parser.parse_args()
    lock = (ROOT / args.lock).resolve()
    components = locked_components(lock)
    payload = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {"type": "application", "name": "wbcz-core"},
            "properties": [
                {"name": "wbcz:dependency-lock-sha256", "value": sha256(lock)},
                {"name": "wbcz:build-sha", "value": args.build_sha or "runtime"},
            ],
        },
        "components": components,
    }
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
