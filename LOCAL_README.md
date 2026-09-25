# Sellari Marking — local WB FBS foundation

This branch is the Windows local-only foundation for one operational contour: **Wildberries FBS + Честный знак**.

## What runs locally

- one FastAPI endpoint bound to `127.0.0.1:8765`;
- the backend serves the built frontend from the same origin;
- local PostgreSQL stores FBS imports/history/control state;
- the normal local app mounts only the FBS/auth/health API surface;
- the repository contains the existing CryptoPro/True API code plus a local diagnostics-only bridge foundation.

There is no VPS requirement, no Vercel requirement, no server-side CryptoPro, and no Ozon/SUZ/printing runtime in the local application.

## Prerequisites

Windows 10/11 workstation with:

- licensed CryptoPro CSP and authorised UKEP already installed;
- Python 3.12+;
- Node.js/npm (needed by one-time setup to build the UI);
- PostgreSQL 16 with `psql` available in PATH.

Sellari does **not** redistribute CryptoPro CSP, cryptcp/stunnel binaries, private keys, certificate containers, PINs, or secrets.

## First setup

```powershell
.\Setup-Local.ps1
```

The setup:

1. refuses non-Windows systems;
2. detects CryptoPro;
3. creates `.venv-local` and installs Sellari/open-source Python dependencies;
4. builds the frontend in local-FBS-only mode;
5. creates per-user config/data/log/run folders under `%LOCALAPPDATA%\SellariMarking\`;
6. provisions/reuses local PostgreSQL database `sellari_local`;
7. runs existing Alembic migrations;
8. bootstraps one local OWNER + participant on first run;
9. runs the local preflight.

The PostgreSQL administrator password is used only for local database provisioning and is not written to the repository or local.env.

## Daily use

```powershell
.\Start-Sellari.ps1
```

This is non-interactive after setup. It checks the environment, starts the local service in the background, waits for health readiness, and opens:

`http://127.0.0.1:8765/`

Stop:

```powershell
.\Stop-Sellari.ps1
```

Diagnostics:

```powershell
.\Check-Local.ps1
```

## Safety state of this foundation

These gates are mandatory and checked by both PowerShell and Python:

- `WBCZ_FBS_DRY_RUN_ONLY=true`
- `WBCZ_TRUE_API_REAL_READ_ENABLED=false`
- `WBCZ_TRUE_API_WRITE_ENABLED=false`
- `WBCZ_AGENT_ENABLED=false`
- `WBCZ_PRINTING_ENABLED=false`
- `WBCZ_PRINT_EXECUTION_ENABLED=false`
- `WBCZ_SUZ_FULL_KM_REMOTE_ACQUISITION_ENABLED=false`

The phase-058 bridge performs diagnostics only. It has no arbitrary-sign endpoint and does not authenticate to True API. Real `/auth/key -> УКЭП -> simpleSignIn -> /cises/info` activation is intentionally deferred to the next accepted task.

Private key material and PIN remain inside the local CryptoPro/token boundary.

## Local data

Default per-user root:

`%LOCALAPPDATA%\SellariMarking\`

It contains local config, logs and runtime state. Secrets are never committed to git.

The current production deployment remains separate and is not decommissioned or modified by this foundation.
