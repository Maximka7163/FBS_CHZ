from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import sys
from pathlib import Path

from sqlalchemy import text

from wbcz_web.config import WebConfig
from wbcz_web.db import build_engine

from .app import assert_local_foundation_safety, frontend_dist_from_env
from .bridge import inspect_local_cryptopro_foundation


def find_local_psql(
    *,
    windows: bool | None = None,
    environ: dict[str, str] | None = None,
) -> str | None:
    path_hit = shutil.which("psql") or shutil.which("psql.exe")
    if path_hit:
        return str(Path(path_hit).resolve())

    is_windows = platform.system().lower() == "windows" if windows is None else windows
    if not is_windows:
        return None

    env = os.environ if environ is None else environ
    roots: list[str] = []
    for key in ("ProgramW6432", "ProgramFiles", "ProgramFiles(x86)"):
        value = env.get(key)
        if value and value not in roots:
            roots.append(value)
    if r"C:\Program Files" not in roots:
        roots.append(r"C:\Program Files")

    for root in roots:
        candidate = Path(root) / "PostgreSQL" / "16" / "bin" / "psql.exe"
        if candidate.is_file():
            return str(candidate.resolve())
    return None


def local_preflight() -> dict:
    checks: list[dict] = []

    def add(
        name: str,
        ok: bool,
        detail: str,
        *,
        app_required: bool = False,
        true_api_required: bool = False,
    ) -> None:
        checks.append({
            "name": name,
            "ok": bool(ok),
            "detail": detail,
            "required": app_required,
            "app_required": app_required,
            "true_api_required": true_api_required,
        })

    windows = platform.system().lower() == "windows"
    add("windows", windows, platform.platform(), app_required=True, true_api_required=True)
    add(
        "python",
        sys.version_info >= (3, 12),
        sys.version.split()[0],
        app_required=True,
    )

    frontend = frontend_dist_from_env()
    add(
        "frontend_build",
        (frontend / "index.html").is_file(),
        str(frontend),
        app_required=True,
    )

    crypto = inspect_local_cryptopro_foundation()
    add(
        "cryptopro_csp",
        crypto.csp_available,
        "CryptoPro CSP detected" if crypto.csp_available else "CryptoPro CSP not detected",
        true_api_required=True,
    )
    add(
        "cryptopro_csp_version",
        crypto.csp_version_supported,
        crypto.csp_version or "CryptoPro CSP release version unavailable",
        true_api_required=True,
    )
    add(
        "cryptopro_csp_license",
        crypto.csp_license_valid,
        "licensed CSP runtime verified" if crypto.csp_license_valid else "CSP license could not be verified",
        true_api_required=True,
    )
    add(
        "cryptopro_tls_sspi",
        crypto.cryptopro_tls_sspi_available,
        "CryptoPro CSP + Windows SSPI structural path ready"
        if crypto.cryptopro_tls_sspi_available
        else "CryptoPro/SSPI structural path unavailable",
        true_api_required=True,
    )
    add(
        "winhttp",
        crypto.winhttp_available,
        "winhttp.dll available" if crypto.winhttp_available else "winhttp.dll unavailable",
        true_api_required=True,
    )
    add(
        "winhttp_gost_transport",
        crypto.winhttp_gost_transport_initializable,
        "native WinHTTP transport initialized without network I/O"
        if crypto.winhttp_gost_transport_initializable
        else "native WinHTTP transport cannot be initialized",
        true_api_required=True,
    )
    add(
        "browser_cades",
        False,
        "runtime-only: checked in Yandex Browser/Chromium",
        true_api_required=True,
    )
    add(
        "eligible_ukep_visible",
        False,
        "runtime-only: browser-visible certificate is intersected with participant-bound eligible certificates",
        true_api_required=True,
    )
    add(
        "cryptcp_optional",
        True,
        crypto.cryptcp_path
        or "cryptcp.exe absent; not required by Browser CAdES or WinHTTP transport",
    )

    psql = find_local_psql(windows=windows)
    add(
        "postgresql_client",
        bool(psql),
        psql or "psql not found in PATH or standard PostgreSQL 16 Windows locations",
        app_required=True,
    )

    config_error: str | None = None
    database_error: str | None = None
    try:
        config = WebConfig.from_env()
        assert_local_foundation_safety(config)
    except Exception as exc:
        config = None
        config_error = f"{type(exc).__name__}: {exc}"
    add(
        "local_safety_config",
        config is not None,
        "fail-closed gates verified" if config is not None else (config_error or "invalid"),
        app_required=True,
    )

    if config is not None:
        engine = build_engine(config)
        try:
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))
        except Exception as exc:
            database_error = f"{type(exc).__name__}: {exc}"
        finally:
            engine.dispose()
    add(
        "local_postgresql",
        config is not None and database_error is None,
        "reachable"
        if config is not None and database_error is None
        else (database_error or "config unavailable"),
        app_required=True,
    )

    app_failures = [
        item["name"] for item in checks
        if item["app_required"] and not item["ok"]
    ]
    true_api_failures = [
        item["name"] for item in checks
        if item["true_api_required"] and not item["ok"]
    ]
    return {
        "ok": not app_failures,
        "app_ready": not app_failures,
        "required_failures": app_failures,
        "true_api_local_ready": not true_api_failures,
        "true_api_local_ready_failures": true_api_failures,
        "true_api_live_verified": False,
        "checks": checks,
        "safety": {
            "true_api_real_read_enabled": True,
            "true_api_write_enabled": False,
            "fbs_dry_run_only": True,
            "agent_enabled": False,
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
            marker = "OK" if item["ok"] else (
                "FAIL" if item["app_required"] else "INFO"
            )
            print(f"[{marker}] {item['name']}: {item['detail']}")
        print(f"APP_READY={'true' if result['app_ready'] else 'false'}")
        print(
            "TRUE_API_LOCAL_READY="
            + ("true" if result["true_api_local_ready"] else "false")
        )
        print("TRUE_API_LIVE_VERIFIED=false")
    raise SystemExit(0 if result["app_ready"] else 2)


if __name__ == "__main__":
    main()
