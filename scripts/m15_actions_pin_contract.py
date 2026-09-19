from __future__ import annotations

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
USES = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)", re.MULTILINE)
FULL_SHA = re.compile(r"^[^@]+@[0-9a-f]{40}$")


def main() -> int:
    findings = []
    required = (
        ROOT / ".github/workflows/m14-integration-settings-validation.yml",
        ROOT / ".github/workflows/m15-production-hardening-validation.yml",
    )
    for path in required:
        text = path.read_text(encoding="utf-8")
        for value in USES.findall(text):
            # Local reusable actions/workflows are versioned by this repository.
            if value.startswith("./"):
                continue
            if not FULL_SHA.fullmatch(value):
                findings.append(f"{path.relative_to(ROOT)}: mutable action reference {value}")
    if findings:
        print("\n".join(findings), file=sys.stderr)
        return 1
    print("M15 active release workflows immutable action pin contract: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
