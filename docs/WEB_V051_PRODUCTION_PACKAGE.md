# Web v0.5.1 — production package

## Scope

This package prepares the isolated marking service for `mark.sellari.ru`. It does not deploy anything and does not integrate with Sellari or «Коллег».

Production path:

`host nginx -> static frontend + /api reverse proxy -> marking-backend -> dedicated marking-postgres`

The compose project contains only `marking-backend` and `marking-postgres`. PostgreSQL has no published host port. Backend is published only on host loopback for the host nginx reverse proxy. The Docker network is internal.

## Artifacts

- `Dockerfile.backend` — Python 3.12 production backend, non-root runtime, read-only root filesystem in compose, Docker healthcheck.
- `frontend/Dockerfile.production` — Node build stage that exports static Vite output. It does not run a Vite dev server.
- `docker-compose.prod.yml` — isolated marking-only production topology.
- `.env.production.example` — names and safe placeholders only.
- `deploy/nginx/mark.sellari.ru.conf.example` — nginx template; no real certificate path.
- `migrations/` + `alembic.ini` — migration assets copied into backend image.

## Fixed safety boundary

Production True API remains mock/read-only only. The application capabilities remain:

- `true_api = mock`
- `true_api_write = false`
- `document_signing = false`
- `submission = false`
- `windows_bridge = false`
- `registration = false`

No CryptoPro, УКЭП private key, production True API credentials or signing capability belong on this server package.

## Production frontend

The browser API client uses relative `/api/...` URLs with `credentials=same-origin`. The production frontend is built as static files. The development Vite proxy is build tooling only and is not shipped to the browser bundle.

Build static artifact:

```bash
docker build -f frontend/Dockerfile.production --target artifact --output type=local,dest=/tmp/wbcz-frontend .
```

The exported directory contains `index.html` and hashed assets and can be installed under `/opt/sellari-marking/releases/<git-sha>/frontend`.

## Production configuration fail-closed rules

In `WBCZ_ENV=production`, startup rejects:

- non-PostgreSQL storage;
- missing/structurally incomplete database URL;
- known placeholder/weak database password values;
- `WBCZ_COOKIE_SECURE=false`;
- `WBCZ_DEBUG=true`;
- empty trusted host configuration;
- wildcard trusted host `*`;
- missing/non-SHA `WBCZ_BUILD_SHA`;
- invalid owner INN;
- invalid session TTL or cookie-name collision.

Production docs/OpenAPI routes are disabled. Public registration remains absent.

## Version/build identity

`GET /api/version` returns only:

```json
{"application_version":"0.5.1","build_sha":"<git-sha>"}
```

No secret or credential is exposed.
