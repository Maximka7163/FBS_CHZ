from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys


REQUIRED = {
    "postgres_base_backup", "wal_archive", "pg_dump_custom",
    "artifact_backup", "secret_store_backup", "crypto_recovery_material",
    "release_manifest", "created_at",
}


def validate_manifest(data: dict) -> list[str]:
    errors = []
    missing = sorted(REQUIRED - set(data))
    if missing:
        errors.append("missing: " + ",".join(missing))
    for key in REQUIRED - {"created_at"}:
        item = data.get(key)
        if not isinstance(item, dict) or not item.get("verified"):
            errors.append(f"{key}: verified=true required")
    try:
        created = datetime.fromisoformat(str(data.get("created_at", "")).replace("Z", "+00:00"))
        age = (datetime.now(timezone.utc) - created.astimezone(timezone.utc)).total_seconds()
        if age < 0 or age > 24 * 60 * 60:
            errors.append("backup manifest age exceeds project validation window")
    except ValueError:
        errors.append("created_at invalid")
    targets = data.get("project_targets") or {}
    if targets and targets != {"db_rpo_minutes": 15, "artifact_secret_rpo_minutes": 60, "rto_hours": 4}:
        errors.append("project recovery targets differ from accepted M15 policy")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest")
    args = parser.parse_args()
    try:
        data = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"backup manifest invalid: {type(exc).__name__}", file=sys.stderr)
        return 1
    errors = validate_manifest(data if isinstance(data, dict) else {})
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("M15 backup contract: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
