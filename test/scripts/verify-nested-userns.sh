#!/usr/bin/env bash
set -euo pipefail

# verify-nested-userns.sh - end-to-end test for nested user namespace range
# reservation.
#
# Tests:
#   1. `sdme create --userns --userns-nested 2` reserves a 196608-wide UID/GID
#      range and writes USERNS_RANGE to the state file.
#   2. The container boots and nspawn receives the expanded range (verified
#      via /proc/self/uid_map inside the container).
#   3. A second container with the same flags gets a different, non-overlapping
#      range (conflict-free allocation).

source "$(dirname "$0")/lib.sh"

# Re-declare VFLAG as an array (lib.sh sets it as a string).
VFLAG=()
if [[ -n "$VERBOSE" ]]; then
    VFLAG=("-v")
fi

PREFIX="vfy-nested-userns"
BASEFS="${PREFIX}-base"
CTR1="${PREFIX}-outer1"
CTR2="${PREFIX}-outer2"
BOOT_TIMEOUT=$(scale_timeout 120)
TEST_TIMEOUT=$(scale_timeout 30)
DATADIR="/var/lib/sdme"

cleanup() {
    cleanup_prefix "${PREFIX}-"
}
trap cleanup EXIT INT TERM

ensure_root
ensure_sdme
require_gate smoke

# We only need one base rootfs for these tests.
# Clean up leftover containers first so the base rootfs we import is not
# removed by cleanup_prefix.
cleanup_prefix "${PREFIX}-"

if ! ensure_base_fs "$BASEFS" "${DISTRO_IMAGES[ubuntu]}"; then
    echo "error: failed to import base rootfs" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Read a state key for a container.
state_key() {
    local name="$1" key="$2"
    grep "^${key}=" "${DATADIR}/state/${name}" 2>/dev/null | cut -d= -f2- || true
}

# Read the length of the UID-0 mapping from inside a container.
container_uid_map_len() {
    local name="$1"
    timeout "$TEST_TIMEOUT" "$SDME" exec "$name" -- \
        /bin/sh -c "awk '\$1 == 0 {print \$3}' /proc/self/uid_map" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Test 1: --userns --userns-nested 2 reserves 196608 IDs and persists it.
# ---------------------------------------------------------------------------
echo "=== Test 1: state persistence for nested userns range ==="

if ! output=$(timeout "$BOOT_TIMEOUT" "$SDME" create -r "$BASEFS" --userns --userns-nested 2 "$CTR1" "${VFLAG[@]}" 2>&1); then
    fail "create --userns --userns-nested 2 failed: $output"
    print_summary
    exit 1
fi

range=$(state_key "$CTR1" "USERNS_RANGE")
shift_val=$(state_key "$CTR1" "USERNS_SHIFT")
userns=$(state_key "$CTR1" "USERNS")

if [[ "$userns" == "yes" ]]; then
    ok "state records USERNS=yes"
else
    fail "USERNS not set in state (got '$userns')"
fi

if [[ "$range" == "196608" ]]; then
    ok "state records USERNS_RANGE=196608 (3 x 64K)"
else
    fail "USERNS_RANGE mismatch (expected 196608, got '$range')"
fi

if [[ -n "$shift_val" ]] && [[ "$shift_val" =~ ^[0-9]+$ ]]; then
    ok "state records USERNS_SHIFT=$shift_val"
else
    fail "USERNS_SHIFT missing or invalid (got '$shift_val')"
fi

# ---------------------------------------------------------------------------
# Test 2: booted container sees the expanded range inside.
# ---------------------------------------------------------------------------
echo "=== Test 2: runtime uid_map length inside container ==="

if ! timeout "$BOOT_TIMEOUT" "$SDME" start "$CTR1" -t "$BOOT_TIMEOUT" "${VFLAG[@]}" 2>&1; then
    fail "start $CTR1 failed"
    print_summary
    exit 1
fi

map_len=$(container_uid_map_len "$CTR1")
if [[ "$map_len" == "196608" ]]; then
    ok "container /proc/self/uid_map length is 196608"
else
    fail "container uid_map length mismatch (expected 196608, got '$map_len')"
fi

# ---------------------------------------------------------------------------
# Test 3: second container gets a different, non-overlapping range.
# ---------------------------------------------------------------------------
echo "=== Test 3: conflict-free allocation for a second container ==="

if ! output=$(timeout "$BOOT_TIMEOUT" "$SDME" create -r "$BASEFS" --userns --userns-nested 2 "$CTR2" "${VFLAG[@]}" 2>&1); then
    fail "create second nested userns container failed: $output"
    print_summary
    exit 1
fi

range2=$(state_key "$CTR2" "USERNS_RANGE")
shift2=$(state_key "$CTR2" "USERNS_SHIFT")

if [[ "$range2" != "196608" ]]; then
    fail "second container USERNS_RANGE mismatch (expected 196608, got '$range2')"
fi

if [[ -n "$shift2" ]] && [[ "$shift2" =~ ^[0-9]+$ ]]; then
    ok "second container USERNS_SHIFT=$shift2"
else
    fail "second container USERNS_SHIFT missing or invalid"
fi

if [[ "$shift_val" != "$shift2" ]]; then
    ok "second container got a different USERNS_SHIFT"
else
    fail "second container got the same USERNS_SHIFT ($shift_val)"
fi

# Verify non-overlap: [shift, shift+range) vs [shift2, shift2+range2).
# Since both ranges are 196608, different shifts are sufficient, but check
# explicitly to be safe.
if [[ "$shift_val" -lt "$shift2" && $((shift_val + range)) -le "$shift2" ]] || \
   [[ "$shift2" -lt "$shift_val" && $((shift2 + range2)) -le "$shift_val" ]]; then
    ok "allocated ranges do not overlap"
else
    fail "allocated ranges overlap (shift1=$shift_val range1=$range shift2=$shift2 range2=$range2)"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print_summary
