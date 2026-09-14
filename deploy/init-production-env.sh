#!/bin/sh
set -eu

umask 077

APP_VERSION="0.5.1"
APP_SHA="858a329b56c2cabae62e9814f540072e8a048d3f"
TRUSTED_HOST="mark.sellari.ru"
DEFAULT_TARGET="/opt/sellari-marking/runtime/.env.production"

if [ "${WBCZ_INIT_TEST_MODE:-0}" = "1" ]; then
    TARGET="${WBCZ_ENV_FILE_TARGET:?WBCZ_ENV_FILE_TARGET is required in WBCZ_INIT_TEST_MODE}"
    OWN_INN="${WBCZ_BOOTSTRAP_OWN_INN:-1234567890}"
else
    if [ -n "${WBCZ_ENV_FILE_TARGET:-}" ]; then
        printf '%s\n' 'ERROR: WBCZ_ENV_FILE_TARGET is allowed only in WBCZ_INIT_TEST_MODE=1' >&2
        exit 64
    fi
    TARGET="$DEFAULT_TARGET"
    OWN_INN="${WBCZ_BOOTSTRAP_OWN_INN:-}"
    if [ -z "$OWN_INN" ]; then
        if [ ! -r /dev/tty ]; then
            printf '%s\n' 'ERROR: WBCZ own INN must be supplied interactively or via WBCZ_BOOTSTRAP_OWN_INN.' >&2
            exit 64
        fi
        printf '%s' 'Participant INN (10 or 12 digits): ' >/dev/tty
        IFS= read -r OWN_INN </dev/tty
    fi
fi
case "$OWN_INN" in
    ''|*[!0-9]*) printf '%s\n' 'ERROR: participant INN must contain digits only' >&2; exit 64 ;;
esac
case "${#OWN_INN}" in
    10|12) : ;;
    *) printf '%s\n' 'ERROR: participant INN must be 10 or 12 digits' >&2; exit 64 ;;
esac

TARGET_DIR=$(dirname -- "$TARGET")
if [ ! -d "$TARGET_DIR" ]; then
    install -d -m 0750 "$TARGET_DIR"
fi
if [ -e "$TARGET" ]; then
    printf 'ERROR: production env already exists: %s\n' "$TARGET" >&2
    printf '%s\n' 'STOP: refusing to overwrite; replacement requires a separate trusted operator action.' >&2
    exit 65
fi

DB_SECRET=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
if [ "${#DB_SECRET}" -ne 64 ]; then
    printf '%s\n' 'ERROR: failed to generate a 256-bit database secret' >&2
    exit 66
fi
case "$DB_SECRET" in
    *[!0-9a-f]*) printf '%s\n' 'ERROR: generated database secret has an unexpected format' >&2; exit 66 ;;
esac

TMP_FILE=$(mktemp "${TARGET}.tmp.XXXXXX")
cleanup() { rm -f "$TMP_FILE"; }
trap cleanup EXIT HUP INT TERM

cat > "$TMP_FILE" <<EOF
WBCZ_ENV=production
WBCZ_DATABASE_URL=postgresql+psycopg://wbcz:${DB_SECRET}@marking-postgres:5432/wbcz
WBCZ_OWN_INN=${OWN_INN}
WBCZ_SESSION_TTL_SECONDS=43200
WBCZ_COOKIE_SECURE=true
WBCZ_SESSION_COOKIE_NAME=wbcz_session
WBCZ_CSRF_COOKIE_NAME=wbcz_csrf
WBCZ_DEBUG=false
WBCZ_TRUSTED_HOSTS=${TRUSTED_HOST}
WBCZ_APP_VERSION=${APP_VERSION}
WBCZ_BUILD_SHA=${APP_SHA}
WBCZ_HEALTHCHECK_HOST=${TRUSTED_HOST}
WBCZ_POSTGRES_DB=wbcz
WBCZ_POSTGRES_USER=wbcz
WBCZ_POSTGRES_PASSWORD=${DB_SECRET}
WBCZ_BACKEND_IMAGE=sellari-marking-backend
WBCZ_BACKEND_PORT=8765
WBCZ_ORGANISATION_TYPE=
WBCZ_ACTIVITY_FIAS_ID=
WBCZ_ACTIVITY_KPP=
WBCZ_REMOTE_SALE_RETURN_PAID=
WBCZ_AGENT_ENABLED=false
WBCZ_AGENT_MACHINE_TOKEN=
WBCZ_AGENT_JOB_LEASE_SECONDS=90
WBCZ_AGENT_POLL_INITIAL_SECONDS=10
WBCZ_AGENT_POLL_MAX_SECONDS=120
WBCZ_AGENT_POLL_MAX_ATTEMPTS=60
WBCZ_TRUE_API_WRITE_ENABLED=false
EOF
chmod 0600 "$TMP_FILE"

if ! ln "$TMP_FILE" "$TARGET" 2>/dev/null; then
    printf 'ERROR: production env already exists or could not be created: %s\n' "$TARGET" >&2
    printf '%s\n' 'STOP: refusing to overwrite.' >&2
    exit 67
fi
rm -f "$TMP_FILE"
trap - EXIT HUP INT TERM
unset DB_SECRET OWN_INN

printf '%s\n' \
    'ENV_CREATED=YES' \
    "PATH=${TARGET}" \
    'MODE=production' \
    "BUILD_SHA=${APP_SHA}" \
    "TRUSTED_HOST=${TRUSTED_HOST}" \
    'COOKIE_SECURE=true' \
    'DEBUG=false' \
    'AGENT_ENABLED=false' \
    'TRUE_API_WRITE=false' \
    'DB_SECRET_GENERATED=YES'