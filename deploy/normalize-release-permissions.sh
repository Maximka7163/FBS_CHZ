#!/bin/sh
set -eu

# Normalize the extracted immutable release tree so nginx and Docker build
# contexts do not depend on source/archive/host umask modes. Runtime secrets
# live outside this tree under /opt/sellari-marking/runtime and are untouched.
TARGET=${1:?usage: normalize-release-permissions.sh /opt/sellari-marking/releases/<sha>}

case "$TARGET" in
    /opt/sellari-marking/releases/*) ;;
    *)
        printf 'ERROR: refusing to normalize unexpected path: %s\n' "$TARGET" >&2
        exit 64
        ;;
esac

if [ ! -d "$TARGET" ]; then
    printf 'ERROR: release directory not found: %s\n' "$TARGET" >&2
    exit 66
fi

# Release contents are code/config/static assets only. Keep them readable and
# traversable, but never group/world-writable.
find "$TARGET" -type d -exec chmod 0755 {} +
find "$TARGET" -type f -exec chmod 0644 {} +
find "$TARGET/deploy" -type f -name '*.sh' -exec chmod 0755 {} +
chown -R root:root "$TARGET"

printf '%s\n' \
    'RELEASE_PERMISSIONS_NORMALIZED=YES' \
    "PATH=${TARGET}" \
    'DIRECTORY_MODE=0755' \
    'REGULAR_FILE_MODE=0644'
