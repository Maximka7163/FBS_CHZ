# P0 test-candidate runtime deployment runbook

Scope: future, separately approved deployment of frozen `P0_TEST_CANDIDATE` application source `bcb567a8f1e4e9261d68fa800ccc96e76518c596` and migration head `0002_p0_agent_wiring`.

This runbook is documentation only. `P0-TEST-CANDIDATE-PACKAGE-001` does not deploy, migrate production, alter DNS/nginx, access a real certificate or call True API.

## Hard safety boundaries

- Production True API document write MUST remain disabled: `WBCZ_TRUE_API_WRITE_ENABLED=false`.
- Windows agent document write remains disabled: `WBCZ_AGENT_PRODUCTION_WRITE_ENABLED=false`.
- Production True API network transport is Windows outbound agent -> CryptoPro -> GOST TLS -> True API. Do not create a VPS True API client.
- Do not touch unrelated VPS services or databases: **Sellari**, **DeltaMetric**, **tg-bot-wb**, or their DBs.
- Do not change DNS/nginx/TLS during packaging or validation. A publicly reachable HTTPS hostname with a valid certificate is a prerequisite for the Windows agent. Never point the agent at insecure HTTP.

## Artifacts

Expected backend archive: `sellari-marking-p0-0.5.1-bcb567a8f1e4-r1.tar.gz` plus `.sha256`.
Expected source SHA inside `RELEASE.json`: `bcb567a8f1e4e9261d68fa800ccc96e76518c596`.
Expected image metadata: `sellari-marking-backend:bcb567a8f1e4e9261d68fa800ccc96e76518c596`, runtime user `wbcz`.
Expected Alembic head: `0002_p0_agent_wiring`.

## 1. Pre-deploy checks

1. Obtain the private CI artifact and checksum sidecar from the accepted workflow run.
2. On an operator workstation/VPS staging directory, verify `sha256sum -c <archive>.sha256` before extraction.
3. Extract into a **new** release directory. Do not overwrite the current release in place.
4. Run `sh deploy/normalize-release-permissions.sh <new-release-dir>`.
5. Verify `RELEASE.json`, `SHA256SUMS`, source SHA, Alembic head, runtime user and `true_api_write_default=false`.
6. Verify internal files with `sha256sum -c SHA256SUMS` from the extracted release root.
7. Confirm current backend health/version and record the current release pointer/image tag before any change.
8. Confirm database backup/restore path for the marking PostgreSQL database only. Do not inspect or modify unrelated databases.
9. Confirm the public HTTPS hostname that the Windows agent will use already exists and is valid. DNS/nginx changes are out of scope here.

STOP if any SHA, source commit, release metadata or safety flag differs.

## 2. Backup/current release pointer

Before installation, record:

- current release directory or symlink target;
- current backend image tag;
- current `/api/version` output;
- current Alembic revision;
- a marking DB backup identifier/location according to the existing backup procedure.

Do not repoint `current` yet.

## 3. Install release without starting it

1. Place the verified extracted release under the existing marking release root as a new immutable directory.
2. Normalize permissions with `deploy/normalize-release-permissions.sh`.
3. If a production env does not yet exist, create it using `deploy/init-production-env.sh`. The helper refuses overwrite, creates mode 0600, leaves the agent disabled, and writes `WBCZ_TRUE_API_WRITE_ENABLED=false`.
4. If an env already exists, preserve it and verify manually that `WBCZ_TRUE_API_WRITE_ENABLED=false` before continuing.
5. Build the backend image from the new release. Do not recreate/start production services yet.
6. Verify the image default user is `wbcz` and `alembic -c /app/alembic.ini heads` returns exactly `0002_p0_agent_wiring (head)`.

## 4. Migration preview/check

Before applying migration:

1. Read current revision: `alembic -c /app/alembic.ini current` using the marking backend image and marking DB only.
2. Confirm the only intended forward step is to `0002_p0_agent_wiring` when production is still at `0001_web_v05`, or confirm `0002_p0_agent_wiring` if already applied.
3. Inspect migration `migrations/versions/0002_p0_agent_wiring.py` from the verified release.
4. Confirm expected new persistence objects include `write_operations`, `write_audit`, and `agent_jobs` and the append-only audit protection defined by the accepted migration.
5. STOP on an unexpected current revision, multiple heads, or schema drift.

## 5. Apply migration 0002 — only in a separately approved deployment task

Run Alembic upgrade through the new non-root backend image against the marking database only. Then verify:

- `alembic current` = `0002_p0_agent_wiring (head)`;
- `write_operations`, `write_audit`, `agent_jobs` exist;
- legacy web tables remain present;
- no unrelated DB was addressed.

`P0-TEST-CANDIDATE-PACKAGE-001` does **not** execute this step on production.

## 6. Configure agent machine auth

Create one machine token on the Windows machine with `New-WbczMachineToken.ps1`. The token is generated from a CSPRNG, stored DPAPI-encrypted for the Windows user, copied to clipboard once, and never printed.

On VPS run the release helper `deploy/configure-agent-machine-secret.sh`; paste the token into the hidden prompt. The helper:

- updates the restricted production env atomically;
- sets `WBCZ_AGENT_ENABLED=true`;
- stores the same machine token for backend verification;
- refuses to proceed unless `WBCZ_TRUE_API_WRITE_ENABLED=false` is already present;
- never echoes the token.

Immediately clear the Windows clipboard with `Set-Clipboard -Value ""`.

Do not put the token in Git, the deployment archive, shell command arguments, PowerShell history, tickets or logs.

## 7. Start/recreate backend

Only after migration verification and secret configuration:

1. Recreate **marking-backend** using the new verified image/release and existing marking PostgreSQL service.
2. Do not recreate unrelated compose projects/containers.
3. Wait for container health = healthy.
4. Verify `/api/health` and `/api/version`; version must report `bcb567a8f1e4e9261d68fa800ccc96e76518c596`.
5. Verify runtime env from inside the backend reports `WBCZ_TRUE_API_WRITE_ENABLED=false` and `WBCZ_AGENT_ENABLED=true` without printing the token.

## 8. Agent HEAD auth smoke

From an approved client path over the public **HTTPS** hostname, perform `HEAD /api/agent/v1/jobs/next` with the machine Bearer token.

Expected: `204` for valid machine auth, no response body and no token in logs. Invalid/missing token must fail. Do not use browser cookies as machine auth.

This HEAD smoke does not call True API and does not create a document.

## 9. Windows installation and safe preflight

Install the matching Windows package, provision non-secret config with `Set-WbczAgentConfig.ps1`, then run:

`./Preflight-WbczAgent.ps1`

Optional read-only CIS check is explicit only:

`./Preflight-WbczAgent.ps1 -Cis '<KIZ>'`

Preflight may perform certificate/CryptoPro/GOST/backend auth plus True API `/auth/key`, `/auth/simpleSignIn`, and optional `/cises/info` only in the separately approved real runtime test. It must never assemble/sign a business document or call `/lk/documents/create` during preflight.

Do not start the normal polling launcher until a separate task authorizes it.

## 10. Rollback

Application rollback is prepared around the recorded prior release/image:

1. Stop/recreate only `marking-backend` back to the previous image/release pointer.
2. Keep `WBCZ_TRUE_API_WRITE_ENABLED=false` throughout.
3. If the new agent API should be disabled during rollback, set `WBCZ_AGENT_ENABLED=false` while retaining/removing the machine token only through a controlled secret-edit procedure.
4. Verify previous `/api/health` and `/api/version`.

Database rollback is **not** an automatic `alembic downgrade` decision. If migration 0002 must be reversed, stop and use the separately approved DB rollback/restore procedure based on the pre-deploy marking DB backup. Never experiment on production data.

## 11. Contract-capture boundary for later runtime test

The Windows package contains `Save-WbczContractCapture.ps1`. It is OFF unless `-EnableCapture` is explicitly provided. A later approved runtime-contract test may use it to store only:

- HTTP status;
- Content-Type;
- response body encoded as Base64;
- response SHA256;
- request correlation id when available.

It never captures request headers/body, bearer token, machine token, private key/PIN or full signature. Production create remains outside this runbook until separately authorized.
