#!/bin/sh
set -eu

ROOT=${1:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)}
IMAGE_TAG=${2:-sellari-marking-backend:restrictive-mode-regression}
TMP_ROOT=$(mktemp -d)
CONTEXT="$TMP_ROOT/context"
cleanup() {
    rm -rf "$TMP_ROOT"
}
trap cleanup EXIT HUP INT TERM
mkdir -p "$CONTEXT"

# Copy a buildable context while excluding local/generated state.
(
    cd "$ROOT"
    tar \
        --exclude=.git \
        --exclude=frontend/node_modules \
        --exclude=.venv \
        --exclude=venv \
        --exclude='__pycache__' \
        --exclude='.pytest_cache' \
        -cf - .
) | tar -xf - -C "$CONTEXT"

# Reproduce the defect class: the build-context owner can read the files, but
# copied modes would prevent the image's unrelated runtime user from reading or
# traversing Alembic assets unless Dockerfile.backend normalizes them.
chmod 0600 "$CONTEXT/alembic.ini"
find "$CONTEXT/migrations" -type d -exec chmod 0700 {} +
find "$CONTEXT/migrations" -type f -exec chmod 0600 {} +

docker build -f "$CONTEXT/Dockerfile.backend" -t "$IMAGE_TAG" "$CONTEXT"

OUTPUT=$(docker run --rm --entrypoint sh "$IMAGE_TAG" -ec '
    test "$(id -un)" = "wbcz"
    test -r /app/alembic.ini
    test -x /app/migrations
    test -r /app/migrations/env.py
    test -x /app/migrations/versions
    test -r /app/migrations/versions/0001_web_v05_initial.py
    test -r /app/migrations/versions/0002_p0_write_pipeline.py
    stat -c "%a" /app/alembic.ini | grep -qx "644"
    stat -c "%a" /app/migrations | grep -qx "755"
    stat -c "%a" /app/migrations/versions | grep -qx "755"
    stat -c "%a" /app/migrations/env.py | grep -qx "644"
    stat -c "%a" /app/migrations/versions/0001_web_v05_initial.py | grep -qx "644"
    stat -c "%a" /app/migrations/versions/0002_p0_write_pipeline.py | grep -qx "644"
    alembic -c /app/alembic.ini heads
')

[ "$OUTPUT" = "0002_p0_write_pipeline (head)" ]
printf '%s\n' \
    'DEFAULT_RUNTIME_USER=wbcz' \
    'ALEMBIC_HEADS_DEFAULT_USER=0002_p0_write_pipeline' \
    'RESTRICTIVE_MODE_REGRESSION=PASS'
