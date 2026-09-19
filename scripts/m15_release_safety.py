from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from typing import Any


SENSITIVE_KEY = re.compile(
    r"(?:^|_)(?:password|passwd|session_token|csrf_token|invite_token|agent_credential|"
    r"wb_token|ozon_api_key|true_api_bearer|bearer|pin|private_key|database_url|"
    r"master_key|artifact_key|audit_key)(?:$|_)",
    re.IGNORECASE,
)
SENSITIVE_VALUE = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/-]{8,}", re.IGNORECASE),
    re.compile(r"postgres(?:ql)?(?:\+[^:]+)?://[^\s:@/]+:[^\s@/]+@", re.IGNORECASE),
)
CANARIES = (
    "FULL-KIZ-CANARY", "SESSION-CANARY", "CSRF-CANARY", "INVITE-CANARY",
    "AGENT-CANARY", "WB-CANARY", "OZON-CANARY", "TRUEAPI-CANARY",
    "ARTIFACT-KEY-CANARY", "AUDIT-KEY-CANARY", "MASTER-KEY-CANARY",
)


def walk(value: Any, path: str = "$") -> list[str]:
    findings: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            name = str(key)
            if SENSITIVE_KEY.search(name):
                findings.append(f"{path}.{name}: forbidden sensitive field name")
            findings.extend(walk(item, f"{path}.{name}"))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            findings.extend(walk(item, f"{path}[{index}]"))
    elif isinstance(value, str):
        if any(canary in value for canary in CANARIES):
            findings.append(f"{path}: redaction canary leaked")
        if any(pattern.search(value) for pattern in SENSITIVE_VALUE):
            findings.append(f"{path}: secret-like value leaked")
    return findings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("files", nargs="+")
    args = parser.parse_args()
    findings: list[str] = []
    for raw in args.files:
        path = Path(raw)
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            findings.append(f"{path}: invalid JSON ({type(exc).__name__})")
            continue
        findings.extend(f"{path}: {item}" for item in walk(value))
    if findings:
        print("\n".join(findings), file=sys.stderr)
        return 1
    print("M15 release artifact safety: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
