# Sellari Marking — local WB FBS

This branch is the Windows local-only Sellari runtime for one operational contour: **Wildberries FBS + Честный знак**.

## What runs locally

- one FastAPI endpoint bound to `127.0.0.1:8765`;
- the backend serves the built frontend from the same origin;
- local PostgreSQL stores FBS imports/history/control state;
- the local runtime mounts only the WB FBS/auth/health and local True API read-only surfaces;
- CryptoPro CSP + Browser CAdES plug-in sign auth challenges in Yandex Browser/Chromium;
- authorised UKEP stays inside CryptoPro/token; GOST TLS is handled separately by local stunnel_msspi;
- real `/cises/info` reads are executed directly by the local Sellari process.

There is no VPS requirement, no Vercel requirement, no server-side CryptoPro, and no Ozon/SUZ/printing runtime in the local application.

## Prerequisites

Windows 10/11 workstation with:

- licensed CryptoPro CSP and authorised UKEP already installed;
- CryptoPro Browser plug-in / CAdES support in Yandex Browser or compatible Chromium;
- CryptoPro `stunnel_msspi.exe` for real True API GOST TLS reads (UI may start without it);
- `cryptcp.exe` is optional legacy diagnostics only and is not required for Browser CAdES auth;
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
2. detects CryptoPro CSP independently; reports Browser CAdES at runtime, `stunnel_msspi.exe` as transport readiness, and `cryptcp.exe` as optional diagnostics;
3. downloads the audited CryptoPro `cadesplugin_api.js` 2.4.5 activation script to a temporary file, verifies pinned SHA-256 `D54CFE9186C4B6DBE9ED73D83F289D31DA7B50000B48BA3E7C278E820578086B`, and publishes it only on an exact match (the file is gitignored and not vendored);
4. creates `.venv-local` and installs Sellari/open-source Python dependencies;
5. builds the frontend in local-FBS-only mode;
6. creates per-user config/data/log/run folders under `%LOCALAPPDATA%\SellariMarking\`;
7. provisions/reuses local PostgreSQL database `sellari_local`;
8. runs existing Alembic migrations;
9. bootstraps one local OWNER + participant on first run;
10. writes only local paths/configuration and closed mutation gates;
11. runs the local preflight.

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

1. The local Bridge discovers CurrentUser\My certificate metadata and identifies participant-bound GOST/CryptoPro UKEP candidates without requiring `cryptcp.exe`.
2. The local UI checks the CryptoPro Browser plug-in in Yandex Browser/Chromium and enumerates browser-visible CurrentUser\My certificates.
3. The user explicitly selects one certificate that is eligible both in browser enumeration and backend participant-INN validation.
4. **Prepare:** the browser calls `POST /api/local/auth/prepare`. The Bridge sends exactly one `GET /api/v3/true-api/auth/key` through the existing CryptoPro `stunnel_msspi.exe` GOST TLS transport.
5. The Bridge stores only in process memory: `attempt_id`, CRPT `uuid`, exact challenge `data`, participant INN, local browser session binding, eligible thumbprints, expiry and used-state. It returns only `attempt_id`, `Base64(UTF8(exact data))`, participant display context and expiry. No `uuidToken` exists yet.
6. **Browser signing:** CAdES uses `CreateObjectAsync`, CurrentUser/My, `CAdESCOM.CPSigner`, `CheckCertificate=true`, then `CAdESCOM.CadesSignedData`. `ContentEncoding=CADESCOM_BASE64_TO_BINARY` is set before `Content`; `SignCades(..., CADESCOM_CADES_BES, false)` creates an attached signature. No trim/newline/BOM/normalisation is applied to the CRPT challenge.
7. **Complete:** the browser calls `POST /api/local/auth/complete` with only `attempt_id`, attached signature and selected thumbprint. Participant INN is never accepted from frontend input; it comes from the server-side attempt/session.
8. The Bridge rejects missing, expired, used, replayed, session-mismatched or certificate-mismatched attempts and re-validates the certificate/participant binding before calling True API. It decodes the attached CMS and calls `SignedCms.CheckSignature(true)`: the `true` argument verifies cryptographic signature integrity without adding an unrelated Windows trust-chain policy; participant/certificate eligibility is enforced separately. Only after successful verification may signer thumbprint/content be trusted.
9. The Bridge requires the verified CMS signer thumbprint to equal the selected participant-bound certificate and the verified attached content to equal the stored UTF-8 challenge byte-for-byte, then sends `POST /api/v3/true-api/auth/simpleSignIn` with the stored CRPT UUID, browser-produced attached CAdES signature, stored participant INN and `unitedToken=true`.
10. The returned `uuidToken` exists only in Bridge process memory. It is never returned to the browser and is not written to localStorage, sessionStorage, PostgreSQL, local.env, selection JSON or logs.
11. FBS control and single-KI lookup use the in-memory bearer for `POST /api/v3/true-api/cises/info?pg=lp`. HTTP 401/403 clears the in-memory session.
12. Missing Browser CAdES prevents signing but does not imply GOST transport failure. Missing/unavailable `stunnel_msspi.exe` is reported as `GOST_TRANSPORT_NOT_READY` on both prepare and authenticated read paths; the UI may still start. There is no OpenSSL or mock fallback.

The production transport allowlist remains limited to:

- `GET /auth/key`
- `POST /auth/simpleSignIn`
- `POST /cises/info?pg=lp`

There is no arbitrary `/sign`, sign-bytes, sign-file or business-document signing endpoint in the local Bridge.

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
3. Confirm `Check-Local.ps1` reports Windows, CryptoPro CSP, PostgreSQL, frontend and fail-closed settings as ready. `cryptcp.exe` is optional. For a real read test, `stunnel_msspi.exe` must additionally be reported as available.
4. Run:
   ```powershell
   .\Start-Sellari.ps1
   ```
5. Sign in to the local Sellari UI at `http://127.0.0.1:8765/`.
6. In the **Честный знак / CryptoPro** block confirm the Browser plug-in is detected and select the intended UKEP certificate. Check that the shown INN/certificate belongs to the expected participant.
7. Click **Подключить Честный знак**. Browser CAdES signs only the one-time auth challenge. If CryptoPro/token asks for PIN, enter it only in the native CryptoPro/token prompt.
8. Confirm the UI changes to **Честный знак подключён · только чтение**.
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
