# Web v0.5.2.2 — operator-safe offline deployment runbook

This runbook deploys the approved v0.5.1 application source **without GitHub access from the VPS**, without exposing production database credentials to Qwen/server automation, and without depending on accidental host extraction permissions.

Approved application source SHA:

```text
cc3054eefba5d07c45dbb2e27d9fc2ba37c91555
```

Expected archive name:

```text
sellari-marking-0.5.1-cc3054eefba5-r3.tar.gz
```

The VPS must not receive a GitHub token, SSH deploy key or other repository credential.

Do not modify `/opt/sellari`, `/opt/deltametric` or `/var/www/sellari`.

## A. Trusted-PC preparation

1. Download the private GitHub Actions artifact produced by the approved runtime-permission-hardened bundle workflow on a trusted PC.
2. Extract the Actions wrapper ZIP locally. It must contain:

```text
sellari-marking-0.5.1-cc3054eefba5-r3.tar.gz
sellari-marking-0.5.1-cc3054eefba5-r3.tar.gz.sha256
```

3. Verify the archive before transfer:

```bash
sha256sum -c sellari-marking-0.5.1-cc3054eefba5-r3.tar.gz.sha256
```

Expected result:

```text
sellari-marking-0.5.1-cc3054eefba5-r3.tar.gz: OK
```

4. Transfer only those two files to the VPS by the operator-approved channel.

Do not transfer `.git`, GitHub credentials, production secrets, private XLSX files, local databases, node_modules or Python virtual environments.

## B. Create isolated directories on the VPS

```bash
sudo install -d -m 0750 /opt/sellari-marking
sudo install -d -m 0750 /opt/sellari-marking/incoming
sudo install -d -m 0750 /opt/sellari-marking/runtime
sudo install -d -m 0750 /opt/sellari-marking/releases
sudo install -d -m 0750 /opt/sellari-marking/backups
sudo mv /tmp/sellari-marking-0.5.1-cc3054eefba5-r3.tar.gz /opt/sellari-marking/incoming/
sudo mv /tmp/sellari-marking-0.5.1-cc3054eefba5-r3.tar.gz.sha256 /opt/sellari-marking/incoming/
sudo chown root:root /opt/sellari-marking/incoming/sellari-marking-0.5.1-cc3054eefba5-r3.tar.gz*
sudo chmod 0644 /opt/sellari-marking/incoming/sellari-marking-0.5.1-cc3054eefba5-r3.tar.gz*
```

## C. Verify archive integrity on the VPS

```bash
cd /opt/sellari-marking/incoming
sha256sum -c sellari-marking-0.5.1-cc3054eefba5-r3.tar.gz.sha256
```

Do not continue unless the result is exactly `OK`.

## D. Extract and normalize the immutable release tree

```bash
APP_SHA=cc3054eefba5d07c45dbb2e27d9fc2ba37c91555
RELEASE_DIR="/opt/sellari-marking/releases/${APP_SHA}"
sudo install -d -m 0755 "$RELEASE_DIR"
sudo tar -xzf /opt/sellari-marking/incoming/sellari-marking-0.5.1-cc3054eefba5-r3.tar.gz \
  -C "$RELEASE_DIR" \
  --strip-components=1
sudo sh "$RELEASE_DIR/deploy/normalize-release-permissions.sh" "$RELEASE_DIR"
cd "$RELEASE_DIR"
```

Expected safe normalization output:

```text
RELEASE_PERMISSIONS_NORMALIZED=YES
PATH=/opt/sellari-marking/releases/cc3054eefba5d07c45dbb2e27d9fc2ba37c91555
DIRECTORY_MODE=0755
REGULAR_FILE_MODE=0644
```

The bundle already records deterministic archive modes, but this explicit deployment step is required because a host extraction/umask/previous-copy path may otherwise leave restrictive modes. The normalizer touches only the immutable release tree: directories become `0755`, ordinary release files `0644`, bundled shell helpers `0755`, ownership `root:root`. It does not touch `/opt/sellari-marking/runtime/.env.production` or any database secret.

This also guarantees nginx can traverse `/opt/sellari-marking/current/frontend` and read the static production frontend. This is infrastructure permission normalization only; no frontend source or design is changed.

Verify every trusted production file from the bundle manifest:

```bash
sha256sum -c SHA256SUMS
```

Every line must end in `OK`.

## E. Verify RELEASE.json

```bash
grep -F '"application_version": "0.5.1"' RELEASE.json
grep -F '"source_git_sha": "cc3054eefba5d07c45dbb2e27d9fc2ba37c91555"' RELEASE.json
grep -F '"frontend_built_from_sha": "cc3054eefba5d07c45dbb2e27d9fc2ba37c91555"' RELEASE.json
grep -F '"bundle_format": "sellari-marking-offline-v2"' RELEASE.json
grep -F '"operator_safe_env_bootstrap": true' RELEASE.json
grep -F '"runtime_permission_hardening": true' RELEASE.json
grep -F '"release_permission_normalization": true' RELEASE.json
```

The bundle contains no `.git` directory. Do not install GitHub credentials on the VPS.

## F. Initialize production environment without exposing the DB secret

For the first isolated marking deployment, run only the bundled deterministic bootstrap helper:

```bash
cd /opt/sellari-marking/releases/cc3054eefba5d07c45dbb2e27d9fc2ba37c91555
sudo ./deploy/init-production-env.sh
```

Production default target:

```text
/opt/sellari-marking/runtime/.env.production
```

The helper uses `set -eu` and `umask 077`, creates the environment file mode `0600`, generates 256 bits of PostgreSQL password entropy locally on the VPS, writes the same secret into `WBCZ_POSTGRES_PASSWORD` and `WBCZ_DATABASE_URL`, never prints it, refuses overwrite, and does not create an owner account.

Expected safe output:

```text
ENV_CREATED=YES
PATH=/opt/sellari-marking/runtime/.env.production
MODE=production
BUILD_SHA=cc3054eefba5d07c45dbb2e27d9fc2ba37c91555
TRUSTED_HOST=mark.sellari.ru
COOKIE_SECURE=true
DEBUG=false
DB_SECRET_GENERATED=YES
```

The fixed deployment/staging participant identifier is:

```text
WBCZ_OWN_INN=1234567890
```

**THIS IS A MOCK/STAGING PARTICIPANT INN.** It is not production legal-entity configuration. Before any future real True API / Windows Bridge activation, replacing it with the real participant INN must be a separate trusted operation outside Qwen/server automation.

Fixed values also include `WBCZ_ENV=production`, `WBCZ_SESSION_TTL_SECONDS=43200`, `WBCZ_COOKIE_SECURE=true`, `WBCZ_SESSION_COOKIE_NAME=wbcz_session`, `WBCZ_CSRF_COOKIE_NAME=wbcz_csrf`, `WBCZ_DEBUG=false`, `WBCZ_TRUSTED_HOSTS=mark.sellari.ru`, `WBCZ_APP_VERSION=0.5.1`, `WBCZ_BUILD_SHA=cc3054eefba5d07c45dbb2e27d9fc2ba37c91555`, `WBCZ_HEALTHCHECK_HOST=mark.sellari.ru`, `WBCZ_POSTGRES_DB=wbcz`, `WBCZ_POSTGRES_USER=wbcz`, `WBCZ_BACKEND_IMAGE=sellari-marking-backend`, and `WBCZ_BACKEND_PORT=8765`.

Validate Compose without rendering or saving interpolated configuration:

```bash
docker compose \
  --env-file /opt/sellari-marking/runtime/.env.production \
  -f docker-compose.prod.yml \
  config -q
```

Do not redirect rendered Compose configuration to `/tmp` or any other file.

## G. Qwen/server-automation secret boundary

After environment initialization, Qwen/server automation is **not trusted for production secrets** and must not:

- receive, choose or regenerate the database password in chat;
- read `.env.production` with `cat`;
- search secret values with `grep`;
- print file contents with `sed -n` or equivalent tools;
- run `docker compose config` in any mode that emits interpolated configuration;
- run `docker inspect` against container environment data;
- run `printenv` for the marking container;
- print `WBCZ_DATABASE_URL` or `WBCZ_POSTGRES_PASSWORD`.

Allowed diagnostics are safe health/version/capabilities endpoints, container/process status that does not expose environment values, Alembic revision output, and schema/table-name checks that do not print credentials.

## H. Build backend image and verify runtime-user migration visibility

No Git and no Node/npm are required on the VPS for the normal deployment path.

```bash
cd /opt/sellari-marking/releases/cc3054eefba5d07c45dbb2e27d9fc2ba37c91555
docker compose \
  --env-file /opt/sellari-marking/runtime/.env.production \
  -f docker-compose.prod.yml \
  build marking-backend
```

`Dockerfile.backend` normalizes `/app/alembic.ini` and `/app/migrations` permissions inside the image **before** switching to `USER wbcz`. It therefore does not depend on modes inherited from the host Docker build context. The final runtime user remains `wbcz`; the container is not run as root.

Before touching the database, verify the default image user can see the one approved Alembic head:

```bash
docker compose \
  --env-file /opt/sellari-marking/runtime/.env.production \
  -f docker-compose.prod.yml \
  run --rm -T marking-backend sh -ec '
    test "$(id -un)" = wbcz
    test -r /app/alembic.ini
    test -x /app/migrations
    test -r /app/migrations/env.py
    test -x /app/migrations/versions
    test -r /app/migrations/versions/0001_web_v05_initial.py
    test "$(alembic -c /app/alembic.ini heads)" = "0001_web_v05 (head)"
  '
```

This command is read-only with respect to the production DB.

The frontend is already present under `frontend/` as a production Vite dist artifact.

## I. Start dedicated PostgreSQL only

```bash
docker compose \
  --env-file /opt/sellari-marking/runtime/.env.production \
  -f docker-compose.prod.yml \
  up -d marking-postgres

docker compose \
  --env-file /opt/sellari-marking/runtime/.env.production \
  -f docker-compose.prod.yml \
  ps
```

PostgreSQL must not have a public host port.

## J. Apply migration explicitly and prove schema state

Run exactly once for this deployment step, before backend workers:

```bash
docker compose \
  --env-file /opt/sellari-marking/runtime/.env.production \
  -f docker-compose.prod.yml \
  run --rm marking-backend alembic -c /app/alembic.ini upgrade head
```

Do not accept exit code alone as proof of migration. Verify revision:

```bash
docker compose \
  --env-file /opt/sellari-marking/runtime/.env.production \
  -f docker-compose.prod.yml \
  run --rm -T marking-backend alembic -c /app/alembic.ini current
```

Expected stdout revision line:

```text
0001_web_v05 (head)
```

Then verify expected table names without printing connection credentials:

```bash
docker compose \
  --env-file /opt/sellari-marking/runtime/.env.production \
  -f docker-compose.prod.yml \
  run --rm -T marking-backend python - <<'PY'
import os
from sqlalchemy import create_engine, inspect
expected = {
    "users", "sessions", "imports", "events", "import_rows",
    "control_runs", "checks", "previews", "preview_items", "audit_log",
}
engine = create_engine(os.environ["WBCZ_DATABASE_URL"])
try:
    tables = set(inspect(engine).get_table_names())
finally:
    engine.dispose()
missing = sorted(expected - tables)
if missing:
    raise SystemExit("missing expected web tables: " + ",".join(missing))
print("DATABASE_SCHEMA=0001_web_v05")
print("EXPECTED_WEB_TABLES=YES")
PY
```

Do not run concurrent migration commands.

## K. Bootstrap the first owner — separate trusted interactive operation

Owner bootstrap is not part of the deployment helper and must never be automated by Qwen.

Run this directly in the trusted operator terminal only after migration acceptance:

```bash
docker compose \
  --env-file /opt/sellari-marking/runtime/.env.production \
  -f docker-compose.prod.yml \
  run --rm marking-backend \
  wbcz-web-admin create-user owner --admin
```

The command requests `Password:` and `Confirm password:` through `getpass`.

**Do not send the owner password to Qwen, server automation, ChatGPT, shell history, environment variables or command-line arguments.**

## L. Start backend while DNS is still absent

```bash
docker compose \
  --env-file /opt/sellari-marking/runtime/.env.production \
  -f docker-compose.prod.yml \
  up -d marking-backend
```

Verify backend directly through host loopback and the expected Host header:

```bash
curl --fail --silent --show-error -H 'Host: mark.sellari.ru' http://127.0.0.1:8765/api/health
curl --fail --silent --show-error -H 'Host: mark.sellari.ru' http://127.0.0.1:8765/api/version
curl --fail --silent --show-error -H 'Host: mark.sellari.ru' http://127.0.0.1:8765/api/capabilities
```

Expected health response:

```json
{"status":"ok","service":"wbcz-web"}
```

The version response must contain the exact approved SHA. Capabilities must preserve the safety boundary below.

## M. Activate static frontend release

```bash
sudo ln -sfn \
  /opt/sellari-marking/releases/cc3054eefba5d07c45dbb2e27d9fc2ba37c91555 \
  /opt/sellari-marking/current
```

Do not copy files into `/var/www/sellari`.

Because section D normalized release directories to `0755` and regular static files to `0644`, nginx can traverse and read `current/frontend` regardless of restrictive modes inherited during initial extraction.

## N. Stage dedicated HTTP nginx server while DNS is absent

Copy only the provided staging template:

```bash
sudo cp deploy/nginx/mark.sellari.ru.http-staging.conf.example /etc/nginx/conf.d/mark.sellari.ru.conf.pending
sudo nginx -t
```

Do not continue unless `nginx -t` succeeds. After operator review, enable it using the host's normal nginx procedure and reload nginx. DNS may still be absent.

## O. Production activation order

Only after DNS-independent staging checks pass:

1. Create DNS `A` for `mark.sellari.ru`.
2. Verify DNS resolution.
3. Issue a separate TLS certificate.
4. Use the provided production nginx template plus host-managed TLS directives.
5. `sudo nginx -t`.
6. Reload nginx normally.
7. Verify HTTPS health/version.
8. Perform final browser acceptance.

## P. Safety boundary that must remain unchanged

```text
true_api=mock
true_api_write=false
document_signing=false
submission=false
windows_bridge=false
registration=false
```

Do not install CryptoPro, УКЭП keys, production True API credentials or Windows Bridge components on this VPS for v0.5.1.

## Q. Backup and rollback

Before any later application/schema update follow `docs/WEB_V051_ROLLBACK.md` exactly. Create a PostgreSQL logical dump before migrations and retain the previous image/tag and frontend release directory. Do not automatically run database downgrade migrations unless a specific migration has been reviewed as safely reversible.
