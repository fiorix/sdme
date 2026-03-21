#!/usr/bin/env bash
set -uo pipefail

# verify-interrupt.sh - verify SIGINT/SIGTERM aborts multi-container loops
#
# Tests that Ctrl+C (SIGINT) during batch operations (rm -a, start --all,
# fs rm) exits immediately with code 130 instead of continuing to process
# remaining items. Uses vfy-int- prefix for all artifacts.
#
# Requires: root, sdme in PATH, a bootable base rootfs (ubuntu by default).

source "$(dirname "$0")/lib.sh"

PREFIX="vfy-int-"
BASE_FS="${BASE_FS:-ubuntu}"
REPORT_DIR="."
TMPDIR=$(mktemp -d /tmp/vfy-int-XXXXXX)

log() { echo "==> $*"; }

cleanup() {
    log "Cleaning up ${PREFIX} artifacts..."
    cleanup_prefix "$PREFIX"
    rm -rf "$TMPDIR"
}

trap cleanup EXIT INT TERM

# Helper: create N containers with the given prefix.
create_containers() {
    local count="$1"
    for i in $(seq 1 "$count"); do
        local name="${PREFIX}c${i}"
        if ! $SDME create -r "$BASE_FS" "$name" >/dev/null 2>&1; then
            echo "error: failed to create $name" >&2
            return 1
        fi
    done
}

# Helper: count containers matching the prefix.
count_prefix_containers() {
    local n
    n=$($SDME ps 2>/dev/null | awk 'NR>1 {print $1}' | grep -c "^${PREFIX}") || true
    echo "${n:-0}"
}

# Helper: count rootfs entries matching the prefix.
count_prefix_rootfs() {
    local n
    n=$($SDME fs ls 2>/dev/null | awk 'NR>1 {print $1}' | grep -c "^${PREFIX}") || true
    echo "${n:-0}"
}

# =============================================================================
# Test: rm -a with SIGINT
# =============================================================================

test_rm_interrupt() {
    log "Test: rm -a + SIGINT"

    # Create enough containers so the loop takes measurable time.
    local count=20
    if ! create_containers "$count"; then
        record "rm/interrupt" FAIL "failed to create test containers"
        return
    fi

    local before
    before=$(count_prefix_containers)
    if [[ "$before" -ne "$count" ]]; then
        record "rm/interrupt" FAIL "expected $count containers, got $before"
        return
    fi

    # Run rm -a -f in background, send SIGINT quickly.
    local errfile="$TMPDIR/rm-stderr"
    $SDME rm -a -f >/dev/null 2>"$errfile" &
    local pid=$!
    sleep 0.01
    kill -INT "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null
    local rc=$?

    local after
    after=$(count_prefix_containers)
    local stderr
    stderr=$(cat "$errfile" 2>/dev/null)

    if [[ "$rc" -ne 130 ]]; then
        record "rm/exit-code" FAIL "expected 130, got $rc; stderr: $stderr"
    else
        record "rm/exit-code" PASS "exit code 130"
    fi

    if [[ "$after" -gt 0 ]]; then
        record "rm/remaining" PASS "$after of $before containers survived"
    else
        record "rm/remaining" FAIL "all containers were removed (interrupt too late)"
    fi

    if echo "$stderr" | grep -q "interrupted, exiting"; then
        record "rm/message" PASS "got 'interrupted, exiting'"
    else
        record "rm/message" FAIL "missing message; stderr: $stderr"
    fi

    # Clean up remaining containers for next test.
    cleanup_prefix "$PREFIX"
}

# =============================================================================
# Test: start --all with SIGINT
# =============================================================================

test_start_interrupt() {
    log "Test: start --all + SIGINT"

    # Create 3 containers with the bootable base rootfs.
    if ! create_containers 3; then
        record "start/exit-code" FAIL "failed to create test containers"
        record "start/message" SKIP "create failed"
        record "start/short-circuit" SKIP "create failed"
        return
    fi

    local before
    before=$(count_prefix_containers)

    # Run start --all in background, send SIGINT after 1s (during boot).
    local errfile="$TMPDIR/start-stderr"
    $SDME start --all >/dev/null 2>"$errfile" &
    local pid=$!
    sleep 1
    kill -INT "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null
    local rc=$?

    local stderr
    stderr=$(cat "$errfile" 2>/dev/null)

    if [[ "$rc" -ne 130 ]]; then
        record "start/exit-code" FAIL "expected 130, got $rc; stderr: $stderr"
    else
        record "start/exit-code" PASS "exit code 130"
    fi

    if echo "$stderr" | grep -q "interrupted, exiting"; then
        record "start/message" PASS "got 'interrupted, exiting'"
    else
        record "start/message" FAIL "missing message; stderr: $stderr"
    fi

    # Verify not all containers were started (at least one should still be stopped).
    local running
    running=$($SDME ps 2>/dev/null | awk 'NR>1 {print $1, $2}' | grep "^${PREFIX}" | grep -c "running") || true
    running="${running:-0}"

    if [[ "$running" -lt "$before" ]]; then
        record "start/short-circuit" PASS "$running of $before started before interrupt"
    else
        record "start/short-circuit" FAIL "all $before containers started (interrupt too late)"
    fi

    cleanup_prefix "$PREFIX"
}

# =============================================================================
# Test: fs rm with SIGINT
# =============================================================================

test_fs_rm_interrupt() {
    log "Test: fs rm + SIGINT"

    # Create several rootfs copies so the loop takes measurable time.
    local count=10
    for i in $(seq 1 "$count"); do
        local name="${PREFIX}fs${i}"
        if ! $SDME fs import "$name" /var/lib/sdme/fs/"$BASE_FS" -f >/dev/null 2>&1; then
            record "fs-rm/interrupt" FAIL "failed to import $name"
            return
        fi
    done

    local before
    before=$(count_prefix_rootfs)
    if [[ "$before" -ne "$count" ]]; then
        record "fs-rm/interrupt" FAIL "expected $count rootfs, got $before"
        return
    fi

    # Run fs rm on all entries in one command, send SIGINT quickly.
    local targets
    targets=$($SDME fs ls 2>/dev/null | awk 'NR>1 {print $1}' | grep "^${PREFIX}" | tr '\n' ' ')
    local errfile="$TMPDIR/fsrm-stderr"
    # shellcheck disable=SC2086
    $SDME fs rm -f $targets >/dev/null 2>"$errfile" &
    local pid=$!
    sleep 0.01
    kill -INT "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null
    local rc=$?

    local after
    after=$(count_prefix_rootfs)
    local stderr
    stderr=$(cat "$errfile" 2>/dev/null)

    if [[ "$rc" -ne 130 ]]; then
        record "fs-rm/exit-code" FAIL "expected 130, got $rc; stderr: $stderr"
    else
        record "fs-rm/exit-code" PASS "exit code 130"
    fi

    if [[ "$after" -gt 0 ]]; then
        record "fs-rm/remaining" PASS "$after of $before rootfs survived"
    else
        record "fs-rm/remaining" FAIL "all rootfs removed (interrupt too late)"
    fi

    # Clean up remaining rootfs entries.
    local leftover
    leftover=$($SDME fs ls 2>/dev/null | awk 'NR>1 {print $1}' | grep "^${PREFIX}" || true)
    for name in $leftover; do
        $SDME fs rm -f "$name" 2>/dev/null || true
    done
}

# =============================================================================

main() {
    parse_standard_args "Verify that SIGINT aborts multi-container loops immediately." "$@"

    ensure_root
    ensure_sdme

    ensure_default_base_fs

    echo ""
    echo "Interrupt handling tests"
    echo "========================"
    echo "base-fs: $BASE_FS"
    echo ""

    # Clean slate.
    cleanup_prefix "$PREFIX"

    test_rm_interrupt
    test_start_interrupt
    test_fs_rm_interrupt

    generate_standard_report "interrupt" "Interrupt Handling Tests"

    echo ""
    print_summary
}

main "$@"
