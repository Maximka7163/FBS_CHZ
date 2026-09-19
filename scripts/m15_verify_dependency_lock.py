from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import re
import sys
import tomllib


ROOT = Path(__file__).resolve().parents[1]
EXACT = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s;]+)(?:\s*;\s*(.+))?$")


def norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def direct_runtime_names() -> set[str]:
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    raw = list(data["project"].get("dependencies", ()))
    raw.extend(data["project"].get("optional-dependencies", {}).get("web", ()))
    names: set[str] = set()
    for item in raw:
        match = re.match(r"^([A-Za-z0-9_.-]+)", item)
        if not match:
            raise ValueError(f"cannot parse direct dependency: {item}")
        names.add(norm(match.group(1)))
    return names


def parse_lock(path: Path) -> dict[str, str]:
    locked: dict[str, str] = {}
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if " @ " in line or line.startswith(("-e ", "--editable ")):
            raise ValueError(f"line {number}: URL/editable dependencies are forbidden")
        match = EXACT.fullmatch(line)
        if not match:
            raise ValueError(f"line {number}: dependency must be exact name==version")
        name, version, marker = match.groups()
        key = norm(name)
        if not version or any(token in version for token in ("*", ">", "<", "~=")):
            raise ValueError(f"line {number}: invalid exact version")
        if marker:
            # Freeze output should not need markers for this single production
            # Python target. Reject them so the release set is unambiguous.
            raise ValueError(f"line {number}: environment markers are forbidden in production lock")
        if key in locked and locked[key] != version:
            raise ValueError(f"line {number}: duplicate package with conflicting version")
        locked[key] = version
    if not locked:
        raise ValueError("production dependency lock is empty")
    return locked


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", default="requirements.production.lock")
    args = parser.parse_args()
    path = (ROOT / args.lock).resolve()
    try:
        locked = parse_lock(path)
        missing = sorted(direct_runtime_names() - set(locked))
        if missing:
            raise ValueError("direct production dependencies missing from lock: " + ",".join(missing))
    except (OSError, ValueError) as exc:
        print(f"M15 dependency lock invalid: {exc}", file=sys.stderr)
        return 1
    print(f"M15 dependency lock: OK packages={len(locked)} sha256={sha256(path)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
