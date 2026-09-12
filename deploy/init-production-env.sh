#!/bin/sh
set -eu

umask 077

APP_VERSION="0.5.1"
APP_SHA="cc3054eefba5d07c45dbb2e27d9fc2ba37c91555"
TRUSTED_HOST="mark.sellari.ru"
DEFAULT_TARGET="/opt/sellari-marking/runtime/.env.production"

# Target override exists only for the unit-test harness. Production execution
# must use the fixed /opt path and must not accept an arbitrary destination.
if [ "${WBCZ_INIT_TEST_MODE:-0}" = "1" ]; then
    TARGET="${WBCZ_ENV_FILE_TARGET:?WBCZ_ENV_FILE_TARGET is required in WBCZ_INIT_TEST_MODE}"
else
    if [ -n "${WBCZ_ENV_FILE_TARGET:-}" ]; then
        printf '%s\n' 'ERROR: WBCZ_ENV_FILE_TARGET is allowed only in WBCZ_INIT_TEST_MODE=1' >&2
        exit 64
    fi
    TARGET="$DEFAULT_TARGET"
fi

TARGET_DIR=$(dirname -- "$TARGET")
if [ ! -d "$TARGET_DIR" ]; then
    install -d -m 0750 "$TARGET_DIR"
fi

if [ -e "$TARGET" ]; then
    printf 'ERROR: production env already exists: %s\n' "$TARGET" >&2
    printf '%s\n' 'STOP: refusing to overwrite; replacement requires a separate trusted operator action.' >&2
    exit 65
fi

# 32 bytes from the kernel CSPRNG = 256 bits. Hex keeps the value URL-safe.
DB_SECRET=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
if [ "${#DB_SECRET}" -ne 64 ]; then
    printf '%s\n' 'ERROR: failed to generate a 256-bit database secret' >&2
    exit 66
fi
case "$DB_SECRET" in
    *[!0-9a-f]*)
        printf '%s\n' 'ERROR: generated database secret has an unexpected format' >&2
        exit 66
        ;;
esac

TMP_FILE=$(mktemp "${TARGET}.tmp.XXXXXX")
cleanup() {
    rm -f "$TMP_FILE"
}
trap cleanup EXIT HUP INT TERM

cat > "$TMP_FILE" <<EOF
WBCZ_ENV=production
WBCZ_DATABASE_URL=postgresql+psycopg://wbcz:${DB_SECRET}@marking-postgres:5432/wbcz
WBCZ_OWN_INN=1234567890
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
EOF
chmod 0600 "$TMP_FILE"

# Hard-link publication is atomic and fails if TARGET appeared concurrently.
if ! ln "$TMP_FILE" "$TARGET" 2>/dev/null; then
    printf 'ERROR: production env already exists or could not be created: %s\n' "$TARGET" >&2
    printf '%s\n' 'STOP: refusing to overwrite.' >&2
    exit 67
fi
rm -f "$TMP_FILE"
trap - EXIT HUP INT TERM
unset DB_SECRET

printf '%s\n' \
    'ENV_CREATED=YES' \
    "PATH=${TARGET}" \
    'MODE=production' \
    "BUILD_SHA=${APP_SHA}" \
    "TRUSTED_HOST=${TRUSTED_HOST}" \
    'COOKIE_SECURE=true' \
    'DEBUG=false' \
    'DB_SECRET_GENERATED=YES'
