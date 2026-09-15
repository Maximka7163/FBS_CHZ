#!/bin/sh
set -eu

umask 077
DEFAULT_TARGET="/opt/sellari-marking/runtime/.env.production"

if [ "${WBCZ_AGENT_SECRET_TEST_MODE:-0}" = "1" ]; then
    TARGET="${WBCZ_ENV_FILE_TARGET:?WBCZ_ENV_FILE_TARGET is required in test mode}"
else
    if [ -n "${WBCZ_ENV_FILE_TARGET:-}" ]; then
        printf '%s\n' 'ERROR: WBCZ_ENV_FILE_TARGET is test-only' >&2
        exit 64
    fi
    TARGET="$DEFAULT_TARGET"
fi

if [ ! -f "$TARGET" ]; then
    printf 'ERROR: production env not found: %s\n' "$TARGET" >&2
    exit 65
fi

TOKEN=""
if [ -t 0 ] && [ -r /dev/tty ]; then
    printf '%s' 'Paste machine token (input hidden): ' >/dev/tty
    stty -echo </dev/tty
    trap 'stty echo </dev/tty 2>/dev/null || true' EXIT HUP INT TERM
    IFS= read -r TOKEN </dev/tty
    stty echo </dev/tty
    trap - EXIT HUP INT TERM
    printf '\n' >/dev/tty
else
    IFS= read -r TOKEN
fi

if [ "${#TOKEN}" -lt 32 ]; then
    printf '%s\n' 'ERROR: machine token must be at least 32 characters' >&2
    exit 66
fi
case "$TOKEN" in
    *[!A-Za-z0-9._~-]*) printf '%s\n' 'ERROR: machine token contains unsupported characters' >&2; exit 66 ;;
esac

if ! grep -q '^WBCZ_TRUE_API_WRITE_ENABLED=false$' "$TARGET"; then
    printf '%s\n' 'ERROR: production env does not prove WBCZ_TRUE_API_WRITE_ENABLED=false' >&2
    exit 67
fi

TMP=$(mktemp "${TARGET}.agent.XXXXXX")
cleanup() { rm -f "$TMP"; }
trap cleanup EXIT HUP INT TERM
SEEN_ENABLED=0
SEEN_TOKEN=0
while IFS= read -r LINE || [ -n "$LINE" ]; do
    case "$LINE" in
        WBCZ_AGENT_ENABLED=*)
            printf '%s\n' 'WBCZ_AGENT_ENABLED=true' >> "$TMP"
            SEEN_ENABLED=1
            ;;
        WBCZ_AGENT_MACHINE_TOKEN=*)
            printf 'WBCZ_AGENT_MACHINE_TOKEN=%s\n' "$TOKEN" >> "$TMP"
            SEEN_TOKEN=1
            ;;
        *) printf '%s\n' "$LINE" >> "$TMP" ;;
    esac
done < "$TARGET"
[ "$SEEN_ENABLED" -eq 1 ] || printf '%s\n' 'WBCZ_AGENT_ENABLED=true' >> "$TMP"
[ "$SEEN_TOKEN" -eq 1 ] || printf 'WBCZ_AGENT_MACHINE_TOKEN=%s\n' "$TOKEN" >> "$TMP"
chmod 0600 "$TMP"
cat "$TMP" > "$TARGET"
chmod 0600 "$TARGET"
rm -f "$TMP"
trap - EXIT HUP INT TERM
unset TOKEN LINE

printf '%s\n' \
  'AGENT_MACHINE_AUTH_CONFIGURED=YES' \
  'AGENT_ENABLED=true' \
  'TRUE_API_WRITE=false' \
  'TOKEN_PRINTED=NO'