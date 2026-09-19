#!/bin/sh
set -eu

: "${POSTGRES_DB:?POSTGRES_DB is required}"
: "${POSTGRES_USER:?POSTGRES_USER is required}"
: "${WBCZ_APP_DB_PASSWORD:?WBCZ_APP_DB_PASSWORD is required}"
: "${WBCZ_MIGRATOR_DB_PASSWORD:?WBCZ_MIGRATOR_DB_PASSWORD is required}"
: "${WBCZ_BACKUP_DB_PASSWORD:?WBCZ_BACKUP_DB_PASSWORD is required}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB"   --set=app_password="$WBCZ_APP_DB_PASSWORD"   --set=migrator_password="$WBCZ_MIGRATOR_DB_PASSWORD"   --set=backup_password="$WBCZ_BACKUP_DB_PASSWORD" <<'SQL'
DO $do$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='wbcz_migrator') THEN
    CREATE ROLE wbcz_migrator LOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='wbcz_app') THEN
    CREATE ROLE wbcz_app LOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='wbcz_backup') THEN
    CREATE ROLE wbcz_backup LOGIN;
  END IF;
END
$do$;

ALTER ROLE wbcz_migrator PASSWORD :'migrator_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
ALTER ROLE wbcz_app PASSWORD :'app_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
ALTER ROLE wbcz_backup PASSWORD :'backup_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
ALTER SCHEMA public OWNER TO wbcz_migrator;
GRANT USAGE ON SCHEMA public TO wbcz_app, wbcz_backup;
GRANT CONNECT ON DATABASE :"DBNAME" TO wbcz_migrator, wbcz_app, wbcz_backup;

ALTER DEFAULT PRIVILEGES FOR ROLE wbcz_migrator IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO wbcz_app;
ALTER DEFAULT PRIVILEGES FOR ROLE wbcz_migrator IN SCHEMA public
  GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO wbcz_app;
ALTER DEFAULT PRIVILEGES FOR ROLE wbcz_migrator IN SCHEMA public
  GRANT SELECT ON TABLES TO wbcz_backup;
GRANT pg_read_all_data TO wbcz_backup;

REVOKE CREATE ON SCHEMA public FROM wbcz_app;
SQL
