#!/usr/bin/env bash
set -euo pipefail

# verify-diff.sh - end-to-end test for sdme diff
#
# Tests:
#   1. Added file detection
#   2. Modified file detection
#   3. Deleted file detection (via rm inside container)
#   4. Mixed changes (A/M/D together)
#   5. --stat output
#   6. --name-only output
#   7. Path filter
#   8. Range diff between two containers
#   9. Empty diff (no changes)

source "$(dirname "$0")/lib.sh"

PREFIX="vfy-diff"
CTR1="${PREFIX}-ctr1"
CTR2="${PREFIX}-ctr2"
CTR_EMPTY="${PREFIX}-empty"
BOOT_TIMEOUT=$(scale_timeout 60)

cleanup() {
    cleanup_prefix "${PREFIX}-"
}

trap cleanup EXIT INT TERM

ensure_root
ensure_sdme
require_gate smoke
ensure_default_base_fs

# Clean stale artifacts from prior runs.
cleanup_prefix "${PREFIX}-"

# ---------------------------------------------------------------------------
# Setup: create a container and mutate its filesystem
# ---------------------------------------------------------------------------
echo "=== Setup: creating containers ==="

DATADIR=$($SDME config get | awk -F' = ' '/^datadir/{print $2}')
for ctr in "$CTR1" "$CTR2" "$CTR_EMPTY"; do
    $SDME rm -f "$ctr" 2>/dev/null || true
    rm -rf "${DATADIR}/containers/${ctr}"
done
$SDME create "$CTR1" $VFLAG
$SDME create "$CTR2" $VFLAG
$SDME create "$CTR_EMPTY" $VFLAG

# Mutate CTR1 upper layer directly (container is stopped, upper is writable).
UPPER="${DATADIR}/containers/${CTR1}/upper"

# Added file
mkdir -p "${UPPER}/tmp"
echo "new content" > "${UPPER}/tmp/diff-test-added.txt"

# Modified file
mkdir -p "${UPPER}/etc"
echo "modified-hostname" > "${UPPER}/etc/hostname"

# Deleted file: create an overlayfs whiteout (char device 0,0)
mknod "${UPPER}/etc/diff-test-deleted" c 0 0

# ---------------------------------------------------------------------------
# Test 1: Added file detection
# ---------------------------------------------------------------------------
echo "=== Test 1: added file detection ==="

output=$($SDME diff "$CTR1" -- /tmp)
if echo "$output" | grep -q "A.*/tmp/diff-test-added.txt"; then
    ok "added file detection"
else
    fail "added file detection: expected A /tmp/diff-test-added.txt, got: $output"
fi

# ---------------------------------------------------------------------------
# Test 2: Modified file detection
# ---------------------------------------------------------------------------
echo "=== Test 2: modified file detection ==="

output=$($SDME diff "$CTR1" -- /etc/hostname)
if echo "$output" | grep -q "M.*/etc/hostname"; then
    ok "modified file detection"
else
    fail "modified file detection: expected M /etc/hostname, got: $output"
fi

# ---------------------------------------------------------------------------
# Test 3: Deleted file detection
# ---------------------------------------------------------------------------
echo "=== Test 3: deleted file detection ==="

output=$($SDME diff "$CTR1" -- /etc/diff-test-deleted)
if echo "$output" | grep -q "D.*/etc/diff-test-deleted"; then
    ok "deleted file detection"
else
    fail "deleted file detection: expected D /etc/diff-test-deleted, got: $output"
fi

# ---------------------------------------------------------------------------
# Test 4: Mixed changes (all A/M/D in one diff)
# ---------------------------------------------------------------------------
echo "=== Test 4: mixed A/M/D ==="

output=$($SDME diff "$CTR1")
has_a=false
has_m=false
has_d=false
echo "$output" | grep -q "^A" && has_a=true
echo "$output" | grep -q "^M" && has_m=true
echo "$output" | grep -q "^D" && has_d=true

if $has_a && $has_m && $has_d; then
    ok "mixed A/M/D"
else
    fail "mixed A/M/D: expected all three change types, got: a=$has_a m=$has_m d=$has_d"
fi

# ---------------------------------------------------------------------------
# Test 5: --stat output
# ---------------------------------------------------------------------------
echo "=== Test 5: --stat output ==="

output=$($SDME diff "$CTR1" --stat)
if echo "$output" | grep -q "file(s) changed" &&
   echo "$output" | grep -q "added" &&
   echo "$output" | grep -q "modified" &&
   echo "$output" | grep -q "deleted"; then
    ok "--stat output"
else
    fail "--stat output: unexpected format: $output"
fi

# ---------------------------------------------------------------------------
# Test 6: --name-only output
# ---------------------------------------------------------------------------
echo "=== Test 6: --name-only output ==="

output=$($SDME diff "$CTR1" --name-only)
# --name-only should not have A/M/D prefixes
if echo "$output" | grep -q "/tmp/diff-test-added.txt" &&
   ! echo "$output" | grep -q "^A"; then
    ok "--name-only output"
else
    fail "--name-only output: unexpected format: $output"
fi

# ---------------------------------------------------------------------------
# Test 7: Path filter
# ---------------------------------------------------------------------------
echo "=== Test 7: path filter ==="

output=$($SDME diff "$CTR1" -- /tmp)
if echo "$output" | grep -q "/tmp/diff-test-added.txt" &&
   ! echo "$output" | grep -q "/etc/"; then
    ok "path filter"
else
    fail "path filter: expected only /tmp entries, got: $output"
fi

# ---------------------------------------------------------------------------
# Test 8: Range diff between two containers
# ---------------------------------------------------------------------------
echo "=== Test 8: range diff ==="

# CTR2 has a different mutation.
UPPER2="${DATADIR}/containers/${CTR2}/upper"
mkdir -p "${UPPER2}/tmp"
echo "ctr2-only" > "${UPPER2}/tmp/diff-test-ctr2.txt"

output=$($SDME diff "${CTR1}..${CTR2}")
if echo "$output" | grep -q "/tmp/diff-test-ctr2.txt"; then
    ok "range diff"
else
    fail "range diff: expected /tmp/diff-test-ctr2.txt in output, got: $output"
fi

# ---------------------------------------------------------------------------
# Test 9: Empty diff (no changes)
# ---------------------------------------------------------------------------
echo "=== Test 9: empty diff ==="

output=$($SDME diff "$CTR_EMPTY" -- /tmp)
if [[ -z "$output" ]]; then
    ok "empty diff"
else
    fail "empty diff: expected no output for /tmp, got: $output"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print_summary
