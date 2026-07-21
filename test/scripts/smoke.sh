#!/usr/bin/env bash
set -uo pipefail

# smoke.sh - minimal container lifecycle smoke test
#
# Validates the core sdme path: create -> start -> boot -> exec -> ps -> stop -> rm.
# This is the gate test: if smoke fails, all other tests should be skipped.
#
# Usage:
#   sudo ./test/scripts/smoke.sh [--base-fs NAME] [--report-dir DIR]

source "$(dirname "$0")/lib.sh"

BASE_FS="${BASE_FS:-ubuntu}"
REPORT_DIR="."
CT_NAME="smoke-test"

TIMEOUT_BOOT=$(scale_timeout 120)
TIMEOUT_TEST=$(scale_timeout 60)

parse_standard_args "Minimal container lifecycle smoke test." "$@"

log() { echo "==> $*"; }

cleanup() {
    log "Cleaning up smoke test..."
    cleanup_container "$CT_NAME"
}

trap cleanup EXIT INT TERM

# -- Preflight -----------------------------------------------------------------

ensure_root
ensure_sdme

# -- Import base rootfs -------------------------------------------------------

log "Importing base rootfs ($BASE_FS)"
if ! ensure_base_fs "$BASE_FS" "${DISTRO_IMAGES[$BASE_FS]}"; then
    fail "base rootfs import failed"
    write_gate smoke fail
    print_summary || true
    exit 1
fi
ok "base rootfs import"

# -- Create --------------------------------------------------------------------

log "Creating container"
if output=$(timeout "$TIMEOUT_BOOT" "$SDME" create --name "$CT_NAME" -r "$BASE_FS" 2>&1); then
    ok "create"
else
    fail "create: $output"
    write_gate smoke fail
    print_summary || true
    exit 1
fi

# -- Start ---------------------------------------------------------------------

log "Starting container"
if output=$(timeout "$TIMEOUT_BOOT" "$SDME" start "$CT_NAME" -t 120 2>&1); then
    ok "start"
else
    fail "start: $output"
    write_gate smoke fail
    print_summary || true
    exit 1
fi

# -- Boot wait -----------------------------------------------------------------

log "Waiting for boot"
if output=$(timeout "$TIMEOUT_TEST" "$SDME" exec "$CT_NAME" \
        /usr/bin/systemctl is-system-running --wait 2>&1); then
    ok "boot (is-system-running)"
else
    # "degraded" is acceptable (some units may have failed, but systemd booted).
    if [[ "$output" == *"degraded"* ]]; then
        ok "boot (degraded, acceptable)"
    else
        fail "boot: $output"
        write_gate smoke fail
        print_summary || true
        exit 1
    fi
fi

# -- Exec ----------------------------------------------------------------------

log "Executing command"
if output=$(timeout "$TIMEOUT_TEST" "$SDME" exec "$CT_NAME" -- /usr/bin/echo ok 2>&1); then
    if [[ "$output" == *"ok"* ]]; then
        ok "exec echo"
    else
        fail "exec echo: unexpected output: $output"
    fi
else
    fail "exec echo: $output"
fi

# -- PS ------------------------------------------------------------------------

log "Checking sdme ps"
if "$SDME" ps 2>/dev/null | awk 'NR>1 {print $1}' | grep -qx "$CT_NAME"; then
    ok "ps shows container"
else
    fail "ps does not show $CT_NAME"
fi

# -- Health --------------------------------------------------------------------

# poll_health NAME EXPECTED TIMEOUT: wait until the ps HEALTH column for
# NAME equals EXPECTED. Health follows is-system-running inside the
# container, which flips asynchronously after a unit fails or is reset.
poll_health() {
    local name="$1" expected="$2" deadline=$((SECONDS + $3)) h
    while ((SECONDS < deadline)); do
        h=$("$SDME" ps 2>/dev/null | awk -v n="$name" '$1 == n {print $3}')
        [[ "$h" == "$expected" ]] && return 0
        sleep 2
    done
    return 1
}

log "Checking health reporting (is-system-running)"
# Clear units that may have failed during boot so health starts from ok.
"$SDME" exec "$CT_NAME" -- /usr/bin/systemctl reset-failed >/dev/null 2>&1
if poll_health "$CT_NAME" ok "$TIMEOUT_TEST"; then
    ok "health ok on running container"
else
    fail "health not ok on running container"
fi

# A failed unit inside the container must surface as degraded.
"$SDME" exec "$CT_NAME" -- /usr/bin/systemd-run --unit smoke-degraded \
    -p Type=oneshot /bin/false >/dev/null 2>&1 || true
if poll_health "$CT_NAME" degraded "$TIMEOUT_TEST"; then
    ok "health degraded after unit failure"
else
    fail "health did not report degraded after unit failure"
fi

# Clearing the failed unit must bring health back to ok.
"$SDME" exec "$CT_NAME" -- /usr/bin/systemctl reset-failed >/dev/null 2>&1
if poll_health "$CT_NAME" ok "$TIMEOUT_TEST"; then
    ok "health ok after reset-failed"
else
    fail "health did not recover after reset-failed"
fi

# -- Stop ----------------------------------------------------------------------

log "Stopping container"
if output=$(timeout "$TIMEOUT_TEST" "$SDME" stop "$CT_NAME" 2>&1); then
    ok "stop"
else
    fail "stop: $output"
fi

# -- Remove --------------------------------------------------------------------

log "Removing container"
if output=$("$SDME" rm -f "$CT_NAME" 2>&1); then
    ok "rm"
else
    fail "rm: $output"
fi

# -- New with command (join path) ----------------------------------------------

# Test the full create -> start -> join path with a command.
# This catches bugs where machinectl_shell swallows stdout.
log "Testing new with command (join path)"
NEW_CT="smoke-new-cmd"
if output=$(timeout "$TIMEOUT_BOOT" "$SDME" new --name "$NEW_CT" -r "$BASE_FS" -- /usr/bin/echo join-ok 2>&1); then
    if [[ "$output" == *"join-ok"* ]]; then
        ok "new with command"
    else
        fail "new with command: output missing 'join-ok': $output"
    fi
else
    fail "new with command: $output"
fi
"$SDME" rm -f "$NEW_CT" 2>/dev/null || true

# -- Gate + Summary ------------------------------------------------------------

if [[ $_fail -eq 0 ]]; then
    write_gate smoke pass
else
    write_gate smoke fail
fi

print_summary
