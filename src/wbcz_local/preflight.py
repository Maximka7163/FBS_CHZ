from __future__ import annotations

import argparse
import json
import platform
import shutil
import sys

from sqlalchemy import text

from wbcz_web.config import WebConfig
from wbcz_web.db import build_engine

from .app import assert_local_foundation_safety, frontend_dist_from_env
from .bridge import inspect_local_cryptopro_foundation


def local_preflight() -> dict:
    checks: list[dict] = []

    windows = platform.system().lower() == "windows"
    checks.append({
        "name": "windows",
        "ok": windows,
        "detail": platform.platform(),
        "required": True,
    })

    python_ok = sys.version_info >= (3, 12)
    checks.append({
        "name": "python",
        "ok": python_ok,
        "detail": sys.version.split()[0],
        "required": True,
    })

    frontend = frontend_dist_from_env()
    checks.append({
        "name": "frontend_build",
        "ok": (frontend / "index.html").is_file(),
        "detail": str(frontend),
        "required": True,
    })

    crypto = inspect_local_cryptopro_foundation()
    checks.append({
        "name": "cryptopro_csp",
        "ok": crypto.cryptopro_csp_detected,
        "detail": crypto.cryptcp_path or "CryptoPro CSP/cryptcp not detected",
        "required": True,
    })
    checks.append({
        "name": "cryptopro_stunnel",
        "ok": bool(crypto.stunnel_path),
        "detail": crypto.stunnel_path or "CryptoPro stunnel_msspi.exe not detected",
        "required": True,
    })

    psql = shutil.which("psql")
    checks.append({
        "name": "postgresql_client",
        "ok": bool(psql),
        "detail": psql or "psql not found in PATH",
        "required": True,
    })

    config_error: str | None = None
    database_error: str | None = None
    try:
        config = WebConfig.from_env()
        assert_local_foundation_safety(config)
    except Exception as exc:
        config = None
        config_error = f"{type(exc).__name__}: {exc}"
    checks.append({
        "name": "local_safety_config",
        "ok": config is not None,
        "detail": "fail-closed gates verified" if config is not None else config_error,
        "required": True,
    })

    if config is not None:
        engine = build_engine(config)
        try:
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))
        except Exception as exc:
            database_error = f"{type(exc).__name__}: {exc}"
        finally:
            engine.dispose()
    checks.append({
        "name": "local_postgresql",
        "ok": config is not None and database_error is None,
        "detail": "reachable" if config is not None and database_error is None else (database_error or "config unavailable"),
        "required": True,
    })

    required_failures = [item["name"] for item in checks if item["required"] and not item["ok"]]
    return {
        "ok": not required_failures,
        "required_failures": required_failures,
        "checks": checks,
        "safety": {
            "true_api_real_read_enabled": True,
            "true_api_write_enabled": False,
            "fbs_dry_run_only": True,
            "printing_enabled": False,
            "print_execution_enabled": False,
            "suz_full_km_remote_acquisition_enabled": False,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Check Sellari local WB FBS environment")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = local_preflight()
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        for item in result["checks"]:
            marker = "OK" if item["ok"] else ("WARN" if not item["required"] else "FAIL")
            print(f"[{marker}] {item['name']}: {item['detail']}")
        print("READY" if result["ok"] else "NOT READY")
    raise SystemExit(0 if result["ok"] else 2)


if __name__ == "__main__":
    main()
