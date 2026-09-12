# Web v0.5.1 — backup and rollback

## Before every application update

Record the current application identity:

```bash
cd /opt/sellari-marking/repo
git rev-parse HEAD
docker compose --env-file /opt/sellari-marking/runtime/.env.production -f docker-compose.prod.yml images
readlink -f /opt/sellari-marking/current
```

Create a PostgreSQL logical backup before any migration:

```bash
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
docker compose --env-file /opt/sellari-marking/runtime/.env.production -f docker-compose.prod.yml exec -T marking-postgres sh -c 'PGPASSWORD="$POSTGRES_PASSWORD" pg_dump -h 127.0.0.1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc' > "/opt/sellari-marking/backups/wbcz-${STAMP}.dump"
chmod 0600 "/opt/sellari-marking/backups/wbcz-${STAMP}.dump"
```

Also retain the previous backend image/tag and previous `/opt/sellari-marking/releases/<sha>/frontend` directory. Back up `/opt/sellari-marking/runtime/.env.production` only to a root-only secure secret backup location; do not commit or place it in a public artifact.

The named Docker volume is `sellari_marking_pgdata`. A filesystem-level volume copy is optional defense in depth; the PostgreSQL logical dump is the required pre-migration backup.

## Application-only rollback

If no incompatible database migration was applied:

1. Set `WBCZ_BUILD_SHA` in the runtime env file back to the previous approved SHA.
2. Ensure the previous backend image tag still exists locally.
3. Point `/opt/sellari-marking/current` back to the previous release directory.
4. Run:

```bash
docker compose --env-file /opt/sellari-marking/runtime/.env.production -f docker-compose.prod.yml up -d --no-build marking-backend
sudo nginx -t
```

Reload nginx only if the frontend symlink/config change requires it under the host's normal procedure.

## Migration rollback policy

Do not automatically run `alembic downgrade` in production. A schema downgrade is allowed only when a specific migration has been reviewed as reversible and the application/data compatibility is known.

If a new migration is not safely reversible, rollback is a coordinated restore: stop the new backend, restore the pre-migration PostgreSQL dump into the dedicated database, start the previous backend image, and point the frontend symlink at the matching previous release. Treat application image + schema/data version as one release unit.

Never restore into Sellari or DeltaMetric databases.
