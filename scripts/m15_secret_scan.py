from __future__ import annotations

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
SCAN_ROOTS = [ROOT / "src", ROOT / "deploy", ROOT / "docker-compose.prod.yml", ROOT / ".env.production.example"]
PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
# Only quoted literal assignments are treated as hard-coded credentials.
# Expressions such as token = provision_agent_credential() are code, not secrets.
LITERAL_ASSIGNMENT = re.compile(
    r"""(?ix)
    (?:token|password|secret|api[_-]?key|bearer|pin)
    \s*[=:]\s*
    (?P<quote>['"])
    (?P<value>[^'"\r\n]{20,})
    (?P=quote)
    """
)
DB_CREDENTIAL = re.compile(r"postgres(?:ql)?(?:\+[^:]+)?://[^\s:@/]+:(?P<password>[^\s@/]{8,})@", re.IGNORECASE)
ALLOW = ("REPLACE_WITH", "test-only", "TEST", "SYNTHETIC", "CANARY", "${", "<REDACTED", "example")


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
        if path.suffix.lower() in {".env", ".example", ".yml", ".yaml", ".toml", ".json"}:
            for match in LITERAL_ASSIGNMENT.finditer(text):
                sample = match.group("value")
                if not any(marker.casefold() in sample.casefold() for marker in ALLOW):
                    findings.append(f"{path.relative_to(ROOT)}: suspicious quoted credential literal")
            for match in DB_CREDENTIAL.finditer(text):
                password = match.group("password")
                if not any(marker.casefold() in password.casefold() for marker in ALLOW):
                    findings.append(f"{path.relative_to(ROOT)}: hard-coded database URL credential")
    if findings:
        print("\n".join(findings), file=sys.stderr)
        return 1
    print("M15 secret scan: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
