# Sellari Marking — local WB FBS

This branch is the Windows local-only Sellari runtime for one operational contour: **Wildberries FBS + Честный знак**.

## What runs locally

- one FastAPI endpoint bound to `127.0.0.1:8765`;
- the backend serves the built frontend from the same origin;
- local PostgreSQL stores FBS imports/history/control state;
- the local runtime mounts only the WB FBS/auth/health and local True API read-only surfaces;
- CryptoPro CSP, authorised UKEP and GOST TLS are used on the same Windows workstation;
- real `/cises/info` reads are executed directly by the local Sellari process.

There is no VPS requirement, no Vercel requirement, no server-side CryptoPro, and no Ozon/SUZ/printing runtime in the local application.

## Prerequisites

Windows 10/11 workstation with:

- licensed CryptoPro CSP and authorised UKEP already installed;
- CryptoPro `cryptcp.exe`;
- CryptoPro `stunnel_msspi.exe` for GOST TLS;
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
2. detects CryptoPro CSP, `cryptcp.exe` and `stunnel_msspi.exe`;
3. creates `.venv-local` and installs Sellari/open-source Python dependencies;
4. builds the frontend in local-FBS-only mode;
5. creates per-user config/data/log/run folders under `%LOCALAPPDATA%\SellariMarking\`;
6. provisions/reuses local PostgreSQL database `sellari_local`;
7. runs existing Alembic migrations;
8. bootstraps one local OWNER + participant on first run;
9. writes only local paths/configuration and closed mutation gates;
10. runs the local preflight.

The PostgreSQL administrator password is used only for local database provisioning and is not written to the repository or local.env.

## Daily use

```powershell
.\Start-Sellari.ps1
```

After setup this is non-interactive. It verifies fail-closed settings, starts local PostgreSQL if needed, runs the preflight, starts Sellari in the background and opens:

`http://127.0.0.1:8765/`

Stop:

```powershell
.\Stop-Sellari.ps1
```

Diagnostics:

```powershell
.\Check-Local.ps1
```

## Exact local True API read flow

1. Sellari discovers CurrentUser\My certificates using local Windows/CryptoPro metadata only.
2. The operator selects an eligible GOST CryptoPro UKEP certificate in the local UI.
3. The selected thumbprint and participant INN may be stored in `%LOCALAPPDATA%\SellariMarking\config\true_api_read.json`. They are public certificate metadata, not key material.
4. On **Войти через CryptoPro / УКЭП**, Sellari sends exactly one `GET /api/v3/true-api/auth/key` through the local CryptoPro `stunnel_msspi.exe` GOST TLS tunnel.
5. The exact returned `data` challenge is written to a temporary file and signed locally by `cryptcp.exe` with the selected certificate. Sellari never supplies or stores the PIN; any PIN interaction remains inside CryptoPro/token UI.
6. Sellari sends `POST /api/v3/true-api/auth/simpleSignIn` with the challenge UUID, attached CMS signature, participant INN and `unitedToken=true`.
7. The returned `uuidToken` exists only in process memory. It is not written to local.env, PostgreSQL, the selection JSON or audit log.
8. FBS control and the single-KI lookup use the in-memory bearer for `POST /api/v3/true-api/cises/info?pg=lp`.
9. The response is normalized to the existing conservative `KiState` model and existing FBS decision engine.
10. If CryptoPro, selected certificate, GOST session, authentication or bearer session is unavailable, the read fails closed. No mock fallback is used while local real-read mode is enabled.

The production transport allowlist remains limited to:

- `GET /auth/key`
- `POST /auth/simpleSignIn`
- `POST /cises/info?pg=lp`

There is no arbitrary-sign HTTP endpoint and no business-document signing method in the local bridge.

## Safety state

These settings are mandatory and checked by both PowerShell and Python:

- `WBCZ_FBS_DRY_RUN_ONLY=true`
- `WBCZ_TRUE_API_REAL_READ_ENABLED=true`
- `WBCZ_TRUE_API_WRITE_ENABLED=false`
- `WBCZ_AGENT_ENABLED=false`
- `WBCZ_PRINTING_ENABLED=false`
- `WBCZ_PRINT_EXECUTION_ENABLED=false`
- `WBCZ_SUZ_FULL_KM_REMOTE_ACQUISITION_ENABLED=false`

Real read does **not** enable withdrawals, returns, business-document submission, printing, or SUZ acquisition. Bulk actions remain blocked by `FBS_DRY_RUN_ONLY` before any write preparation.

Private key material and PIN remain inside the local CryptoPro/token boundary.

## Manual Windows acceptance — one KIZ

Run this only after code QA accepts the branch. Use one real KIZ that is safe to inspect read-only.

1. On the target Windows 10/11 workstation, verify licensed CryptoPro CSP and authorised UKEP are already working outside Sellari.
2. Clone/update this branch and run:
   ```powershell
   .\Setup-Local.ps1
   ```
3. Confirm `Check-Local.ps1` reports Windows, CryptoPro CSP, `cryptcp.exe`, `stunnel_msspi.exe`, PostgreSQL, frontend and fail-closed settings as ready.
4. Run:
   ```powershell
   .\Start-Sellari.ps1
   ```
5. Sign in to the local Sellari UI at `http://127.0.0.1:8765/`.
6. In the **Честный знак / CryptoPro** block select the intended UKEP certificate. Check that the shown INN/certificate belongs to the expected participant.
7. Click **Войти через CryptoPro / УКЭП**. If CryptoPro/token asks for PIN, enter it only in the native CryptoPro/token prompt.
8. Confirm the UI changes to **Подключено · только чтение**.
9. Use the single-KI field with exactly one real KIZ. Confirm a current state/owner is returned.
10. Upload one WB FBS XLSX and click **Проверить КИЗ**. Confirm the resulting decisions use current ЧЗ state and the UI still says **Отправка в ЧЗ отключена**.
11. Confirm there is no withdrawal/return submission, no business document, no printing, and no SUZ call.
12. Stop Sellari with:
    ```powershell
    .\Stop-Sellari.ps1
    ```
13. Optional security check: inspect `%LOCALAPPDATA%\SellariMarking\config\true_api_read.json` and the audit log. Neither should contain the PIN, private key, CMS signature, challenge data or uuidToken.

## Local data

Default per-user root:

`%LOCALAPPDATA%\SellariMarking\`

It contains local config, logs and runtime state. The certificate-selection file contains only thumbprint + participant INN. Secrets are never committed to git.

The current production deployment remains separate and is not decommissioned or modified by this local branch.
