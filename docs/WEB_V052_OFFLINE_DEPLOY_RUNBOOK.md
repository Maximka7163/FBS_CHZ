# Web v0.5.2 — offline deployment runbook

This runbook deploys the approved v0.5.1 application source **without GitHub access from the VPS**.

Approved application source SHA:

```text
cc3054eefba5d07c45dbb2e27d9fc2ba37c91555
```

Expected archive name:

```text
sellari-marking-0.5.1-cc3054eefba5.tar.gz
```

The VPS must not receive a GitHub token, SSH deploy key or other repository credential.

Do not modify `/opt/sellari`, `/opt/deltametric` or `/var/www/sellari`.

## A. Trusted-PC preparation

1. Download the private GitHub Actions artifact produced by the approved v0.5.2 bundle workflow on a trusted PC.
2. Extract the Actions wrapper ZIP locally. It must contain:

```text
sellari-marking-0.5.1-cc3054eefba5.tar.gz
sellari-marking-0.5.1-cc3054eefba5.tar.gz.sha256
```

3. Verify the archive before transfer:

```bash
sha256sum -c sellari-marking-0.5.1-cc3054eefba5.tar.gz.sha256
```

Expected result:

```text
sellari-marking-0.5.1-cc3054eefba5.tar.gz: OK
```

4. Transfer only those two files to the VPS by the operator-approved channel, for example:

```bash
scp sellari-marking-0.5.1-cc3054eefba5.tar.gz \
    sellari-marking-0.5.1-cc3054eefba5.tar.gz.sha256 \
    <operator>@<vps>:/tmp/
```

Do not transfer `.git`, GitHub credentials, production secrets, private XLSX files, local databases, node_modules or Python virtual environments.

## B. Create isolated directories on the VPS

```bash
sudo install -d -m 0750 /opt/sellari-marking
sudo install -d -m 0750 /opt/sellari-marking/incoming
sudo install -d -m 0750 /opt/sellari-marking/runtime
sudo install -d -m 0750 /opt/sellari-marking/releases
sudo install -d -m 0750 /opt/sellari-marking/backups
sudo mv /tmp/sellari-marking-0.5.1-cc3054eefba5.tar.gz /opt/sellari-marking/incoming/
sudo mv /tmp/sellari-marking-0.5.1-cc3054eefba5.tar.gz.sha256 /opt/sellari-marking/incoming/
sudo chown root:root /opt/sellari-marking/incoming/sellari-marking-0.5.1-cc3054eefba5.tar.gz*
sudo chmod 0644 /opt/sellari-marking/incoming/sellari-marking-0.5.1-cc3054eefba5.tar.gz*
```

## C. Verify archive integrity on the VPS

```bash
cd /opt/sellari-marking/incoming
sha256sum -c sellari-marking-0.5.1-cc3054eefba5.tar.gz.sha256
```

Do not continue unless the result is exactly `OK`.

## D. Extract into the isolated release directory

```bash
APP_SHA=cc3054eefba5d07c45dbb2e27d9fc2ba37c91555
sudo install -d -m 0755 "/opt/sellari-marking/releases/${APP_SHA}"
sudo tar -xzf /opt/sellari-marking/incoming/sellari-marking-0.5.1-cc3054eefba5.tar.gz \
  -C "/opt/sellari-marking/releases/${APP_SHA}" \
  --strip-components=1
cd "/opt/sellari-marking/releases/${APP_SHA}"
```

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
```

All three commands must print the matching line and exit successfully.

The bundle contains no `.git` directory. Do not install GitHub credentials on the VPS.

## F. Prepare production configuration

For a first deployment:

```bash
sudo cp .env.production.example /opt/sellari-marking/runtime/.env.production
sudo chmod 0600 /opt/sellari-marking/runtime/.env.production
sudoedit /opt/sellari-marking/runtime/.env.production
```

The operator must set real production values. In particular:

```text
WBCZ_ENV=production
WBCZ_BUILD_SHA=cc3054eefba5d07c45dbb2e27d9fc2ba37c91555
WBCZ_APP_VERSION=0.5.1
WBCZ_TRUSTED_HOSTS=mark.sellari.ru
WBCZ_COOKIE_SECURE=true
WBCZ_DEBUG=false
```

`WBCZ_DATABASE_URL` and PostgreSQL credentials must use the dedicated marking database only.

Validate without starting anything:

```bash
docker compose \
  --env-file /opt/sellari-marking/runtime/.env.production \
  -f docker-compose.prod.yml \
  config >/tmp/sellari-marking-compose.yml
```

## G. Build backend image from the bundle

No Git and no Node/npm are required on the VPS for the normal deployment path.

```bash
cd /opt/sellari-marking/releases/cc3054eefba5d07c45dbb2e27d9fc2ba37c91555
docker compose \
  --env-file /opt/sellari-marking/runtime/.env.production \
  -f docker-compose.prod.yml \
  build marking-backend
```

The frontend is already present under `frontend/` as a production Vite dist artifact.

## H. Start dedicated PostgreSQL only

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

## I. Apply migration explicitly

Run exactly once for this deployment step, before backend workers:

```bash
docker compose \
  --env-file /opt/sellari-marking/runtime/.env.production \
  -f docker-compose.prod.yml \
  run --rm marking-backend alembic upgrade head
```

Do not run concurrent migration commands.

## J. Bootstrap the first owner — trusted interactive operation

Run this directly in the trusted operator terminal:

```bash
docker compose \
  --env-file /opt/sellari-marking/runtime/.env.production \
  -f docker-compose.prod.yml \
  run --rm marking-backend \
  wbcz-web-admin create-user owner --admin
```

The command requests `Password:` and `Confirm password:` through `getpass`.

**Do not send the user password to Qwen, server automation, ChatGPT, shell history, environment variables or command-line arguments.** The password bootstrap is a separate trusted interactive operation.

## K. Start backend while DNS is still absent

```bash
docker compose \
  --env-file /opt/sellari-marking/runtime/.env.production \
  -f docker-compose.prod.yml \
  up -d marking-backend
```

Verify backend directly through host loopback and the expected Host header:

```bash
curl --fail --silent --show-error \
  -H 'Host: mark.sellari.ru' \
  http://127.0.0.1:8765/api/health

curl --fail --silent --show-error \
  -H 'Host: mark.sellari.ru' \
  http://127.0.0.1:8765/api/version
```

Expected health response:

```json
{"status":"ok","service":"wbcz-web"}
```

The version response must contain the exact approved SHA.

## L. Activate the static frontend release

```bash
sudo ln -sfn \
  /opt/sellari-marking/releases/cc3054eefba5d07c45dbb2e27d9fc2ba37c91555 \
  /opt/sellari-marking/current
```

Do not copy files into `/var/www/sellari`.

## M. Stage a dedicated HTTP nginx server while DNS is absent

The current host default server may display another site for unknown hosts. Therefore create a dedicated `server_name mark.sellari.ru` before DNS exists.

Copy only the provided staging template:

```bash
sudo cp \
  deploy/nginx/mark.sellari.ru.http-staging.conf.example \
  /etc/nginx/conf.d/mark.sellari.ru.conf.pending
sudo nginx -t
```

Do not continue unless `nginx -t` succeeds.

After the server operator has reviewed the pending file, enable it using the host's normal nginx procedure and reload nginx.

Then verify routing locally without DNS:

```bash
curl --fail --silent --show-error \
  -H 'Host: mark.sellari.ru' \
  http://127.0.0.1/api/health

curl --fail --silent --show-error \
  -H 'Host: mark.sellari.ru' \
  http://127.0.0.1/api/version

curl --fail --silent --show-error \
  -H 'Host: mark.sellari.ru' \
  http://127.0.0.1/ | head
```

At this stage DNS may still be absent.

## N. Production activation order

Only after the DNS-independent staging checks above pass:

1. Create the DNS `A` record for `mark.sellari.ru` pointing to the approved VPS address.
2. Wait until the operator verifies DNS resolution from the required networks.
3. Issue a **separate** TLS certificate for `mark.sellari.ru` using the host's approved certificate process.
4. Replace/extend the staging HTTP configuration with `deploy/nginx/mark.sellari.ru.conf.example` plus the real host-managed TLS directives.
5. Run `sudo nginx -t`.
6. Reload nginx using the host's normal procedure.
7. Verify:

```bash
curl --fail https://mark.sellari.ru/api/health
curl --fail https://mark.sellari.ru/api/version
```

8. Perform final browser acceptance: login, no registration route, XLSX upload, control, preview and logout.

DNS is therefore **not a prerequisite** for the internal staging deployment.

## O. Safety boundary that must remain unchanged

Production capabilities remain:

```text
true_api=mock
true_api_write=false
document_signing=false
submission=false
windows_bridge=false
registration=false
```

Do not install CryptoPro, УКЭП keys, production True API credentials or Windows Bridge components on this VPS for v0.5.1.

## P. Backup and rollback

Before any later application/schema update follow `docs/WEB_V051_ROLLBACK.md` exactly. Create a PostgreSQL logical dump before migrations and retain the previous image/tag and frontend release directory. Do not automatically run database downgrade migrations unless a specific migration has been reviewed as safely reversible.
