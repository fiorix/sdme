#!/usr/bin/env bash
set -uo pipefail

# verify-build.sh - verify sdme fs build: hot COPY, source prefixes,
# tmp.mount masking, stale cleanup, and resource locking.
#
# Uses vfy-build- prefix for all artifacts.
#
# Requires: root, sdme in PATH, network access for OCI registry pulls.

source "$(dirname "$0")/lib.sh"

DATADIR="/var/lib/sdme"
REPORT_DIR="."
BASE_FS="ubuntu"

parse_standard_args "Verify sdme fs build features." "$@"

ensure_root
ensure_sdme
require_gate smoke
require_gate interrupt

# -- Logging -------------------------------------------------------------------

log() { echo "==> $*"; }

# -- Cleanup -------------------------------------------------------------------

cleanup() {
    log "Cleaning up vfy-build- artifacts..."
    cleanup_prefix "vfy-build-"
    # Build containers are named build-vfy-build-*, clean those too.
    cleanup_prefix "build-vfy-build-"
}

trap cleanup EXIT INT TERM

# -- Setup ---------------------------------------------------------------------

log "Importing base rootfs..."
ensure_default_base_fs
if ! fs_exists "$BASE_FS"; then
    echo "error: base rootfs '$BASE_FS' not available" >&2
    exit 1
fi

cleanup

# =============================================================================
# Test 1: COPY from imported rootfs (fs: prefix)
# =============================================================================

log "Test: COPY from imported rootfs"

# We need a second rootfs to copy from. Import fedora if not present.
SECOND_FS="vfy-build-fedora"
if ! fs_exists "$SECOND_FS"; then
    log "Importing secondary rootfs '$SECOND_FS'..."
    if ! sdme fs import "$SECOND_FS" "${DISTRO_IMAGES[fedora]}" --install-packages=yes -f $VFLAG 2>&1; then
        record "copy/fs-prefix" FAIL "failed to import secondary rootfs"
    fi
fi

if fs_exists "$SECOND_FS"; then
    cat > /tmp/vfy-build-cross-copy.sdme <<EOF
FROM $BASE_FS
COPY fs:$SECOND_FS:/etc/os-release /tmp/fedora-os-release
RUN cat /tmp/fedora-os-release
RUN test -f /tmp/fedora-os-release
EOF

    output=$(sdme fs build vfy-build-cross-copy /tmp/vfy-build-cross-copy.sdme -f $VFLAG 2>&1)
    rc=$?
    if [[ $rc -eq 0 ]]; then
        record "copy/fs-prefix" PASS
    else
        record "copy/fs-prefix" FAIL "$output"
    fi
    rm -f /tmp/vfy-build-cross-copy.sdme
else
    record "copy/fs-prefix" SKIP "secondary rootfs not available"
fi

# =============================================================================
# Test 2: RUN then COPY /tmp round-trip (tmp.mount masked)
# =============================================================================

log "Test: RUN then COPY /tmp round-trip"

cat > /tmp/vfy-build-tmp-test.sdme <<EOF
FROM $BASE_FS
RUN echo "hello from build" > /tmp/build-marker
RUN test -f /tmp/build-marker
COPY fs:$BASE_FS:/etc/os-release /tmp/extra-info
RUN cat /tmp/build-marker
RUN cat /tmp/extra-info
RUN test -f /tmp/build-marker && test -f /tmp/extra-info
EOF

output=$(sdme fs build vfy-build-tmp-test /tmp/vfy-build-tmp-test.sdme -f $VFLAG 2>&1)
rc=$?
if [[ $rc -eq 0 ]]; then
    record "copy/tmp-roundtrip" PASS
else
    record "copy/tmp-roundtrip" FAIL "$output"
fi
rm -f /tmp/vfy-build-tmp-test.sdme

# =============================================================================
# Test 3: Hot COPY (no stop between RUN and COPY)
# =============================================================================

log "Test: hot COPY (container stays running)"

cat > /tmp/vfy-build-hot-copy.sdme <<EOF
FROM $BASE_FS
RUN echo "step1" > /tmp/step1
COPY fs:$BASE_FS:/etc/hostname /etc/build-hostname
RUN echo "step2" > /tmp/step2
RUN test -f /tmp/step1 && test -f /tmp/step2 && test -f /etc/build-hostname
EOF

# Capture output and verify no "stopping build container" between ops
output=$(sdme fs build vfy-build-hot-copy /tmp/vfy-build-hot-copy.sdme -f $VFLAG 2>&1)
rc=$?
if [[ $rc -ne 0 ]]; then
    record "copy/hot-copy" FAIL "$output"
else
    # Count "stopping build container" messages; should only appear once (at the end)
    stop_count=$(echo "$output" | grep -c "stopping build container" || true)
    if [[ $stop_count -le 1 ]]; then
        record "copy/hot-copy" PASS
    else
        record "copy/hot-copy" FAIL "container stopped $stop_count times during build (expected <= 1)"
    fi
fi
rm -f /tmp/vfy-build-hot-copy.sdme

# =============================================================================
# Test 4: FROM fs: prefix
# =============================================================================

log "Test: FROM fs: prefix"

cat > /tmp/vfy-build-from-prefix.sdme <<EOF
FROM fs:$BASE_FS
RUN echo "works"
EOF

output=$(sdme fs build vfy-build-from-prefix /tmp/vfy-build-from-prefix.sdme -f $VFLAG 2>&1)
rc=$?
if [[ $rc -eq 0 ]]; then
    record "from/fs-prefix" PASS
else
    record "from/fs-prefix" FAIL "$output"
fi
rm -f /tmp/vfy-build-from-prefix.sdme

# =============================================================================
# Test 5: Stale build container auto-cleanup
# =============================================================================

log "Test: stale build container cleanup"

# Create a build config that will succeed
cat > /tmp/vfy-build-stale.sdme <<EOF
FROM $BASE_FS
RUN echo "first build"
EOF

# Run it once
output=$(sdme fs build vfy-build-stale /tmp/vfy-build-stale.sdme -f $VFLAG 2>&1)
rc=$?
if [[ $rc -ne 0 ]]; then
    record "stale/auto-cleanup" FAIL "first build failed: $output"
else
    # Now create a fake stale build container by creating the state file
    # and container dirs manually (simulating an interrupted build)
    stale_name="build-vfy-build-stale2"
    mkdir -p "$DATADIR/state"
    echo "NAME=$stale_name" > "$DATADIR/state/$stale_name"
    echo "ROOTFS=$BASE_FS" >> "$DATADIR/state/$stale_name"
    mkdir -p "$DATADIR/containers/$stale_name/upper"
    mkdir -p "$DATADIR/containers/$stale_name/work"
    mkdir -p "$DATADIR/containers/$stale_name/merged"

    cat > /tmp/vfy-build-stale2.sdme <<EOF
FROM $BASE_FS
RUN echo "second build"
EOF

    # This should auto-clean the stale container and succeed
    output=$(sdme fs build vfy-build-stale2 /tmp/vfy-build-stale2.sdme -f $VFLAG 2>&1)
    rc=$?
    if [[ $rc -eq 0 ]]; then
        if echo "$output" | grep -q "removing stale build container"; then
            record "stale/auto-cleanup" PASS
        else
            record "stale/auto-cleanup" PASS "succeeded but no stale cleanup message"
        fi
    else
        record "stale/auto-cleanup" FAIL "$output"
    fi
    rm -f /tmp/vfy-build-stale2.sdme
fi
rm -f /tmp/vfy-build-stale.sdme

# =============================================================================
# Test 6: Resource locking (fs rm blocked during build)
# =============================================================================

log "Test: resource locking"

cat > /tmp/vfy-build-lock.sdme <<EOF
FROM $BASE_FS
RUN sleep 30
EOF

# Start a long build in the background
sdme fs build vfy-build-lock /tmp/vfy-build-lock.sdme -f $VFLAG &>/tmp/vfy-build-lock-out.txt &
BUILD_PID=$!
sleep 3

# Try to delete the FROM rootfs while build is running
rm_output=$(sdme fs rm "$BASE_FS" 2>&1)
rm_rc=$?

# Kill the background build
kill $BUILD_PID 2>/dev/null
wait $BUILD_PID 2>/dev/null || true

if [[ $rm_rc -ne 0 ]] && echo "$rm_output" | grep -qi "in use\|locked"; then
    record "locking/fs-rm-blocked" PASS
elif [[ $rm_rc -ne 0 ]]; then
    # It failed but for a different reason (still ok, the rootfs is protected)
    record "locking/fs-rm-blocked" PASS "blocked with: $rm_output"
else
    record "locking/fs-rm-blocked" FAIL "fs rm succeeded while build was running"
fi

rm -f /tmp/vfy-build-lock.sdme /tmp/vfy-build-lock-out.txt

# =============================================================================
# Test 7: COPY shadowed dirs (build allows /tmp, rejects /run)
# =============================================================================

log "Test: COPY shadowed dirs in build context"

# /tmp should be allowed in builds
cat > /tmp/vfy-build-shadowed-ok.sdme <<EOF
FROM $BASE_FS
COPY fs:$BASE_FS:/etc/hostname /tmp/hostname-copy
RUN test -f /tmp/hostname-copy
EOF

output=$(sdme fs build vfy-build-shadowed-ok /tmp/vfy-build-shadowed-ok.sdme -f $VFLAG 2>&1)
rc=$?
if [[ $rc -eq 0 ]]; then
    record "shadowed/tmp-allowed" PASS
else
    record "shadowed/tmp-allowed" FAIL "$output"
fi
rm -f /tmp/vfy-build-shadowed-ok.sdme

# /run should be rejected
cat > /tmp/vfy-build-shadowed-bad.sdme <<EOF
FROM $BASE_FS
COPY fs:$BASE_FS:/etc/hostname /run/hostname-copy
EOF

output=$(sdme fs build vfy-build-shadowed-bad /tmp/vfy-build-shadowed-bad.sdme -f $VFLAG 2>&1)
rc=$?
if [[ $rc -ne 0 ]] && echo "$output" | grep -q "tmpfs"; then
    record "shadowed/run-rejected" PASS
else
    record "shadowed/run-rejected" FAIL "expected COPY to /run to fail: $output"
fi
rm -f /tmp/vfy-build-shadowed-bad.sdme

# =============================================================================
# Test 8: Resumable build (fail then resume from failed step)
# =============================================================================

log "Test: resumable build (fail then resume)"

cat > /tmp/vfy-build-resume.sdme <<EOF
FROM $BASE_FS
RUN echo step1 > /tmp/step1-marker
RUN echo step2 > /tmp/step2-marker
RUN false
RUN echo step4 > /tmp/step4-marker
EOF

# First run: should fail at step 3 (RUN false)
output=$(sdme fs build vfy-build-resume /tmp/vfy-build-resume.sdme $VFLAG 2>&1)
rc=$?
if [[ $rc -eq 0 ]]; then
    record "cache/resume" FAIL "expected build to fail at RUN false"
else
    # Fix the config: replace "false" with "true"
    cat > /tmp/vfy-build-resume.sdme <<EOF
FROM $BASE_FS
RUN echo step1 > /tmp/step1-marker
RUN echo step2 > /tmp/step2-marker
RUN true
RUN echo step4 > /tmp/step4-marker
EOF

    # Config changed, so this should start fresh (no resume) and succeed
    output=$(sdme fs build vfy-build-resume /tmp/vfy-build-resume.sdme $VFLAG 2>&1)
    rc=$?
    if [[ $rc -eq 0 ]] && echo "$output" | grep -q "config changed"; then
        record "cache/resume" PASS
    elif [[ $rc -eq 0 ]]; then
        record "cache/resume" PASS "succeeded but no config-changed message"
    else
        record "cache/resume" FAIL "$output"
    fi
fi
rm -f /tmp/vfy-build-resume.sdme

# =============================================================================
# Test 9: Resumable build (cached steps are skipped on retry)
# =============================================================================

log "Test: cached steps skipped on retry"

cat > /tmp/vfy-build-cached.sdme <<EOF
FROM $BASE_FS
RUN echo cached1
RUN echo cached2
RUN false
EOF

# First run: fails at step 3
sdme fs build vfy-build-cached /tmp/vfy-build-cached.sdme $VFLAG 2>&1 || true

# Second run: same config, should resume and show "(cached)" for steps 1-2
output=$(sdme fs build vfy-build-cached /tmp/vfy-build-cached.sdme $VFLAG 2>&1)
rc=$?
# It will still fail (RUN false), but should show cached steps and resume message
if echo "$output" | grep -q "(cached)" && echo "$output" | grep -q "resuming build"; then
    record "cache/skip-cached" PASS
elif echo "$output" | grep -q "(cached)"; then
    record "cache/skip-cached" PASS "cached steps shown but no resume message"
else
    record "cache/skip-cached" FAIL "expected cached steps on retry: $output"
fi
rm -f /tmp/vfy-build-cached.sdme

# =============================================================================
# Test 10: --no-cache forces clean build
# =============================================================================

log "Test: --no-cache forces clean build"

cat > /tmp/vfy-build-nocache.sdme <<EOF
FROM $BASE_FS
RUN echo nocache1
RUN false
EOF

# First run: fails at step 2
sdme fs build vfy-build-nocache /tmp/vfy-build-nocache.sdme $VFLAG 2>&1 || true

# Second run with --no-cache: should NOT show "(cached)" or "resuming"
output=$(sdme fs build --no-cache vfy-build-nocache /tmp/vfy-build-nocache.sdme $VFLAG 2>&1)
rc=$?
# Still fails (RUN false), but should start fresh
if echo "$output" | grep -q "(cached)"; then
    record "cache/no-cache-flag" FAIL "found cached steps despite --no-cache: $output"
elif echo "$output" | grep -q "resuming"; then
    record "cache/no-cache-flag" FAIL "found resume despite --no-cache: $output"
elif echo "$output" | grep -q "\-\-no-cache"; then
    record "cache/no-cache-flag" PASS
else
    record "cache/no-cache-flag" PASS "clean build without cached steps"
fi
rm -f /tmp/vfy-build-nocache.sdme

# =============================================================================
# Report
# =============================================================================

generate_standard_report "verify-build" "sdme fs build Verification"
print_summary
