# Web v0.5.1 — deploy runbook

This document is an execution runbook only. It must not be used to redesign the architecture. Do not modify `/opt/sellari`, `/opt/deltametric` or `/var/www/sellari`.

## 0. Preconditions

Required on the host: Git access to the private repository, Docker Engine + Docker Compose plugin, nginx already managed by the server operator, and TLS material for `mark.sellari.ru` managed outside this repository.

Target layout:

```text
/opt/sellari-marking/
  repo/
  runtime/.env.production
  releases/<git-sha>/frontend/
  current -> releases/<git-sha>
  backups/
```

## 1. Prepare isolated directories

```bash
sudo install -d -m 0750 /opt/sellari-marking
sudo install -d -m 0750 /opt/sellari-marking/runtime /opt/sellari-marking/releases /opt/sellari-marking/backups
```

Clone only into the isolated directory if `repo/` does not already exist:

```bash
cd /opt/sellari-marking
git clone git@github.com:Maximka7163/FBS_CHZ.git repo
```

## 2. Checkout the approved release ref

Replace `<APP_GIT_SHA>` only with the SHA approved for deployment.

```bash
cd /opt/sellari-marking/repo
git fetch origin web/v0.5.1-deployment-package
git checkout --detach <APP_GIT_SHA>
test "$(git rev-parse HEAD)" = "<APP_GIT_SHA>"
```

Do not merge `main` during deployment.

## 3. Create production environment file

```bash
sudo cp .env.production.example /opt/sellari-marking/runtime/.env.production
sudo chmod 0600 /opt/sellari-marking/runtime/.env.production
sudoedit /opt/sellari-marking/runtime/.env.production
```

Set real values. `WBCZ_BUILD_SHA` must exactly equal `git rev-parse HEAD`. `WBCZ_DATABASE_URL` must point to host `marking-postgres` and its password must be URL-encoded if it contains reserved URL characters. `WBCZ_POSTGRES_PASSWORD` and the password embedded in `WBCZ_DATABASE_URL` must represent the same secret.

Validate interpolation without starting containers:

```bash
docker compose --env-file /opt/sellari-marking/runtime/.env.production -f docker-compose.prod.yml config >/tmp/sellari-marking-compose.yml
```

## 4. Build backend image

```bash
cd /opt/sellari-marking/repo
docker compose --env-file /opt/sellari-marking/runtime/.env.production -f docker-compose.prod.yml build marking-backend
```

The backend image contains no frontend dev server and no automatic migration entrypoint.

## 5. Build and stage frontend static artifact

```bash
cd /opt/sellari-marking/repo
APP_GIT_SHA="$(git rev-parse HEAD)"
rm -rf "/tmp/wbcz-frontend-${APP_GIT_SHA}"
docker build -f frontend/Dockerfile.production --target artifact --output "type=local,dest=/tmp/wbcz-frontend-${APP_GIT_SHA}" .
sudo install -d -m 0755 "/opt/sellari-marking/releases/${APP_GIT_SHA}/frontend"
sudo cp -a "/tmp/wbcz-frontend-${APP_GIT_SHA}/." "/opt/sellari-marking/releases/${APP_GIT_SHA}/frontend/"
```

## 6. Start only dedicated PostgreSQL

```bash
docker compose --env-file /opt/sellari-marking/runtime/.env.production -f docker-compose.prod.yml up -d marking-postgres
docker compose --env-file /opt/sellari-marking/runtime/.env.production -f docker-compose.prod.yml ps
```

PostgreSQL must have no host `ports:` mapping.

## 7. Apply migrations explicitly

This is the only migration command for v0.5.1. It is intentionally separate from backend worker startup to avoid migration races.

```bash
docker compose --env-file /opt/sellari-marking/runtime/.env.production -f docker-compose.prod.yml run --rm marking-backend alembic upgrade head
```

Do not run multiple migration commands concurrently.

## 8. Bootstrap first owner interactively

Run once after migrations. Do not place the password in environment variables, shell arguments, scripts or chat logs.

```bash
docker compose --env-file /opt/sellari-marking/runtime/.env.production -f docker-compose.prod.yml run --rm marking-backend wbcz-web-admin create-user owner --admin
```

The command prompts for `Password:` and `Confirm password:` through `getpass`.

## 9. Start backend

```bash
docker compose --env-file /opt/sellari-marking/runtime/.env.production -f docker-compose.prod.yml up -d marking-backend
docker compose --env-file /opt/sellari-marking/runtime/.env.production -f docker-compose.prod.yml ps
```

Backend host exposure must be loopback-only: `127.0.0.1:<port> -> 8765`.

Check directly from the host:

```bash
curl --fail --header 'Host: mark.sellari.ru' http://127.0.0.1:8765/api/health
curl --fail --header 'Host: mark.sellari.ru' http://127.0.0.1:8765/api/version
```

Expected health body: `{"status":"ok","service":"wbcz-web"}`. The version response must show the approved git SHA.

## 10. Activate frontend release

```bash
APP_GIT_SHA="$(git rev-parse HEAD)"
sudo ln -sfn "/opt/sellari-marking/releases/${APP_GIT_SHA}" /opt/sellari-marking/current
```

Do not copy frontend files into `/var/www/sellari`.

## 11. Prepare nginx config

Copy the template to a staging path, add only the TLS `listen`/certificate directives already approved and managed on this host, then validate before enabling. Do not guess certificate paths.

```bash
sudo cp deploy/nginx/mark.sellari.ru.conf.example /etc/nginx/conf.d/mark.sellari.ru.conf.pending
sudoedit /etc/nginx/conf.d/mark.sellari.ru.conf.pending
sudo nginx -t
```

Only after a human confirms the TLS lines and `nginx -t` passes should the server operator rename/enable the pending config and reload nginx. This repository does not perform that action.

## 12. Post-deploy verification

After the operator has enabled nginx:

```bash
curl --fail https://mark.sellari.ru/api/health
curl --fail https://mark.sellari.ru/api/version
```

Then verify through a browser: login page, no registration flow, XLSX upload, control run, preview, logout. Production capabilities must still deny True API writes, signing, submission and Windows Bridge.
