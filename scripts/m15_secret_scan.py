from __future__ import annotations

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
SCAN_ROOTS = [ROOT / "src", ROOT / "deploy", ROOT / "docker-compose.prod.yml", ROOT / ".env.production.example"]
PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
ASSIGNMENT = re.compile(r"(?i)(?:token|password|secret|api[_-]?key|bearer|pin)\s*[=:]\s*['\"]?[A-Za-z0-9._~+/-]{24,}")
ALLOW = ("REPLACE_WITH", "test-only", "SYNTHETIC", "CANARY", "${")


def files():
    for root in SCAN_ROOTS:
        if root.is_file():
            yield root
        elif root.is_dir():
            for path in root.rglob("*"):
                if path.is_file() and path.suffix.lower() in {".py", ".yml", ".yaml", ".sh", ".toml", ".example"}:
                    yield path


def main() -> int:
    findings = []
    for path in files():
        text = path.read_text(encoding="utf-8", errors="replace")
        if PRIVATE_KEY.search(text):
            findings.append(f"{path.relative_to(ROOT)}: private-key marker")
        for match in ASSIGNMENT.finditer(text):
            sample = match.group(0)
            if not any(marker in sample for marker in ALLOW):
                findings.append(f"{path.relative_to(ROOT)}: suspicious credential assignment")
    if findings:
        print("\n".join(findings), file=sys.stderr)
        return 1
    print("M15 secret scan: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
