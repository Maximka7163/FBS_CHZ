from __future__ import annotations

import argparse
import importlib.metadata
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    components = []
    for dist in sorted(importlib.metadata.distributions(), key=lambda item: (item.metadata.get("Name") or "").lower()):
        name = dist.metadata.get("Name")
        if not name:
            continue
        components.append({"type": "library", "name": name, "version": dist.version})
    payload = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"component": {"type": "application", "name": "wbcz-core"}},
        "components": components,
    }
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
