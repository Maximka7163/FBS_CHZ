# FBS dry-run VPS operator runbook

This runbook records the production layout deployed for Sellari Marking FBS dry-run. It contains no credentials or secret values.

## Current accepted deployment

- Source SHA: `a3b42d0a7499c0d1dcdcf86e2982ec4efd9a5a2c`
- Source branch: `fix/fbs-dryrun-artifact-closure-001`
- Application version: `0.5.1`
- Archive: `sellari-marking-fbs-dryrun-0.5.1-a3b42d0a7499.tar.gz`
- Archive SHA-256: `4d593a713ec3cf95e03666f845494c1e1d8d4c59cb01df62679e1387c7d71105`
- Alembic revision: `0020_printing_physical_spool`
- Release path: `/opt/sellari-marking/releases/a3b42d0a7499c0d1dcdcf86e2982ec4efd9a5a2c`
- Current symlink: `/opt/sellari-marking/current`
- Runtime env: `/opt/sellari-marking/runtime/.env.production` (root-only; never print)
- Sanitized state: `/opt/sellari-marking/runtime/DEPLOYMENT_STATE.json`
- Root-only keys: `/opt/sellari-marking/keys` (never print)
- PostgreSQL volume: `sellari_marking_pgdata`
- Latest verified pre-deployment backup: `/opt/sellari-marking/backups/pre-fbs02-20260922T135917Z`
- Compose file: `docker-compose.prod.yml`
- Compose project: `sellari-marking`
- Backend container: `sellari-marking_marking-backend_1`
- Worker container: `sellari-marking_marking-worker_1`
- PostgreSQL container: `sellari-marking_marking-postgres_1`
- Backend bind: `127.0.0.1:8765`
- Public backend origin: `https://sellari.ru/marking-api`
- Vercel frontend: `https://sellari-marking-fbs.vercel.app`
- Nginx site: `/etc/nginx/sites-enabled/sellari.ru`

The worker image inherits the backend HTTP Docker healthcheck, although the worker does not serve HTTP. Therefore Docker may label the worker unhealthy while its database heartbeat is fresh. Operational worker health is determined by the `worker_heartbeats` record, container running state, restart count and error-free logs.

No application account existed immediately after deployment. Account provisioning is a separate authorized operation and must not invent a company, INN or participant identity.

## Mandatory safety invariants

These values must remain fixed:

```text
WBCZ_FBS_DRY_RUN_ONLY=true
WBCZ_TRUE_API_WRITE_ENABLED=false
WBCZ_PRINTING_ENABLED=false
WBCZ_PRINT_EXECUTION_ENABLED=false
WBCZ_SUZ_FULL_KM_REMOTE_ACQUISITION_ENABLED=false
WBCZ_AGENT_ENABLED=true
WBCZ_AGENT_LEGACY_BOOTSTRAP_ENABLED=false
WBCZ_AGENT_MACHINE_TOKEN=
```

The migrator must run with Agent disabled as defined in the accepted Compose file. Never enroll a Windows Agent, use a certificate, sign, call DISTANCE or REMOTE_SALE_RETURN, mutate Честный знак, enable physical printing, or acquire remote SUZ FULL KM as part of routine deployment.

## Inspect current deployment

Run on the VPS:

```sh
readlink -f /opt/sellari-marking/current
docker inspect -f '{{.Name}} {{.State.Running}} {{if .State.Health}}{{.State.Health.Status}}{{end}} {{.Image}}'   sellari-marking_marking-backend_1   sellari-marking_marking-worker_1   sellari-marking_marking-postgres_1
docker port sellari-marking_marking-backend_1
docker port sellari-marking_marking-postgres_1
cat /opt/sellari-marking/runtime/DEPLOYMENT_STATE.json
```

Do not inspect container environment and do not print `.env.production`.

## Verify an accepted artifact

An architect must supply the exact accepted source SHA and archive SHA-256.

```sh
sha256sum /opt/sellari-marking/incoming/ARCHIVE.tar.gz
cd /opt/sellari-marking/releases/ACCEPTED_SHA
sha256sum -c SHA256SUMS
python3 -c 'import json; d=json.load(open("RELEASE.json")); print(d["source_git_sha"],d["alembic_head"])'
```

STOP if the archive hash, internal hashes, source SHA, Alembic head or safety metadata differ. Never activate `59787d8fdbec4709e6e8ac331497317cfbc4ab33`.

## Create and verify a backup

Create a new timestamped root-only directory. Preserve all earlier backups.

```sh
TS=$(date -u +%Y%m%dT%H%M%SZ)
BACKUP=/opt/sellari-marking/backups/pre-release-$TS
install -d -o root -g root -m 0700 "$BACKUP"
cp -a /opt/sellari-marking/runtime/.env.production "$BACKUP/env.production"
cp -L /etc/nginx/sites-enabled/sellari.ru "$BACKUP/nginx-sellari.ru.conf"
docker exec sellari-marking_marking-postgres_1 sh -c   'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc' > "$BACKUP/database.dump"
sha256sum "$BACKUP/database.dump" > "$BACKUP/database.dump.sha256"
chmod 0600 "$BACKUP"/*
cat "$BACKUP/database.dump" | docker exec -i sellari-marking_marking-postgres_1 pg_restore --list >/dev/null
```

A release that changes schema requires a real restore drill in a disposable PostgreSQL container without host ports or persistent volumes. STOP if archive inspection or the restore drill fails.

## Check and run migration

Read the current revision without exposing a connection string:

```sh
docker exec sellari-marking_marking-postgres_1 sh -c   'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atqc "select version_num from alembic_version"'
```

Run only an already accepted migration:

```sh
cd /opt/sellari-marking/releases/ACCEPTED_SHA
docker-compose   --env-file /opt/sellari-marking/runtime/.env.production   -p sellari-marking   -f docker-compose.prod.yml   --profile maintenance run --rm -T marking-migrate
```

Confirm the exact accepted revision afterward. If migration fails, STOP. Do not retry by deleting tables, stamping Alembic, downgrading, deleting a volume or reinitializing PostgreSQL.

## Safe backend and worker start

First validate the accepted image on an unused loopback port while the old backend remains healthy. After canary readiness succeeds, switch `current` atomically and replace only backend/worker. Do not restart PostgreSQL unnecessarily.

Normal restart of the active accepted release:

```sh
cd /opt/sellari-marking/current
docker-compose   --env-file /opt/sellari-marking/runtime/.env.production   -p sellari-marking   -f docker-compose.prod.yml   up -d --no-deps marking-backend marking-worker
```

Never use `down -v`.

## Health and safety smoke

Local VPS:

```sh
curl -fsS -H 'Host: sellari.ru' http://127.0.0.1:8765/api/live
curl -fsS -H 'Host: sellari.ru' http://127.0.0.1:8765/api/ready
curl -fsS -H 'Host: sellari.ru' http://127.0.0.1:8765/api/version
```

Public HTTPS and Vercel proxy:

```sh
curl -fsS https://sellari.ru/marking-api/api/live
curl -fsS https://sellari.ru/marking-api/api/ready
curl -fsS https://sellari.ru/marking-api/api/version
curl -fsS https://sellari-marking-fbs.vercel.app/api/live
curl -fsS https://sellari-marking-fbs.vercel.app/api/ready
curl -fsS https://sellari-marking-fbs.vercel.app/api/version
```

Worker heartbeat:

```sh
docker exec sellari-marking_marking-postgres_1 sh -c   'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -AtF "|" -c "select role,state,build_sha,round(extract(epoch from now()-heartbeat_at)) from worker_heartbeats order by heartbeat_at desc limit 1"'
```

Expected: role `worker`, state `RUNNING`, accepted SHA, and a small heartbeat age. Also verify restart count and scan recent logs for traceback/exception without printing environment data.

## Nginx and Vercel proxy

Nginx terminates HTTPS on `sellari.ru`. The exact prefix `/marking-api/` proxies to `http://127.0.0.1:8765/` and strips the prefix. Existing Sellari `/api/` routes are independent and must not be changed.

The versioned `frontend/vercel.json` rewrite maps browser `/api/:path*` to:

```text
https://sellari.ru/marking-api/api/:path*
```

This preserves browser same-origin cookies and CSRF. Do not replace it with browser-side direct cross-origin API URLs.

Frontend deployment uses project `sellari-marking-fbs`, root `frontend`, `npm ci`, `npm run build`, output `dist`. Use the existing branch `ops/fbs-dryrun-vercel-001`; do not create a competing deployment branch.

Verify CSRF without logging token or cookie values. Confirm HTTP 200, JSON key `csrf_token`, and a `Secure; SameSite=Lax` CSRF cookie. Login and workspace checks require an already provisioned legitimate account.

## Application rollback restrictions

Application rollback is allowed only when the older application is explicitly confirmed compatible with schema `0020_printing_physical_spool`. The historical release `59787d8f...` is forbidden and must never be activated.

Do not downgrade Alembic. If the schema is incompatible with the prior app, keep the new application and make a forward fix. Database rollback means restore the verified pre-migration backup under a separately approved incident procedure, not `alembic downgrade`.

## If migration fails

STOP immediately. Keep the old backend active. Preserve migration logs, current revision and table count without credentials. Do not delete schema/data, stamp a revision, rerun against a modified artifact or remove volumes. Return the exact error to the architect.

## Update deployment state

After every successful deployment, atomically replace:

```text
/opt/sellari-marking/runtime/DEPLOYMENT_STATE.json
```

Record accepted SHA/hash, application version, Alembic revision, UTC deployment time, all safety booleans, container/image IDs, backup path, public origin and Vercel URL. Never include env values, credentials or key material.

## LOCAL MODEL — ATOMIC OPERATIONS

The local model executes only one approved task at a time. It must not debug or apply autonomous fixes.

### TASK A — report deployed SHA

Command:

```sh
readlink -f /opt/sellari-marking/current
```

Expected: exact approved release directory. STOP if different.

### TASK B — report Alembic revision

Command:

```sh
docker exec sellari-marking_marking-postgres_1 sh -c   'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atqc "select version_num from alembic_version"'
```

Expected: architect-supplied exact revision. STOP if empty or different.

### TASK C — verify archive hash

Command:

```sh
sha256sum /opt/sellari-marking/incoming/APPROVED_ARCHIVE.tar.gz
```

Expected: architect-supplied SHA-256. STOP if different.

### TASK D — inspect containers

Command:

```sh
docker inspect -f '{{.Name}} {{.State.Running}} {{.RestartCount}} {{.Image}}'   sellari-marking_marking-backend_1 sellari-marking_marking-worker_1 sellari-marking_marking-postgres_1
```

Return output only. Do not restart anything.

### TASK E — health smoke

Commands:

```sh
curl -fsS -H 'Host: sellari.ru' http://127.0.0.1:8765/api/live
curl -fsS -H 'Host: sellari.ru' http://127.0.0.1:8765/api/ready
```

Expected: HTTP success and accepted SHA/revision. STOP on any failure.

### TASK F — safe named restart

Run only after explicit architect approval:

```sh
cd /opt/sellari-marking/current
docker-compose --env-file /opt/sellari-marking/runtime/.env.production   -p sellari-marking -f docker-compose.prod.yml   up -d --no-deps marking-backend marking-worker
```

Do not run `down`, `down -v`, migrations or cleanup. Return container status only.

## Never automate

Never automate business identity, user/company creation, real True API calls, Windows Agent enrollment, certificate access, signing, DISTANCE, REMOTE_SALE_RETURN, Честный знак mutation, physical printing, remote SUZ FULL KM, Alembic downgrade/stamp, volume deletion, secret display, DNS cutover, or activation of an unaccepted artifact.