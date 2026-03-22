#!/usr/bin/env bash
set -euo pipefail

# verify-cp.sh - end-to-end test for sdme cp
#
# Tests:
#   1. host → rootfs
#   2. rootfs → host
#   3. host → stopped container
#   4. stopped container → host
#   5. host → running container
#   6. running container → host
#   7. shadowed dir rejection (stopped container)
#   8. shadowed dir OK on running container
#   9. host → running container /tmp
#  10. running container /tmp → host
#  11. --force device node

source "$(dirname "$0")/lib.sh"

PREFIX="vfy-cp"
TMPDIR=$(mktemp -d /tmp/${PREFIX}-XXXXXX)
CTR_STOPPED="${PREFIX}-stopped"
CTR_RUNNING="${PREFIX}-running"
BOOT_TIMEOUT=$(scale_timeout 60)

cleanup() {
    cleanup_prefix "${PREFIX}-"
    rm -rf "$TMPDIR"
}

trap cleanup EXIT INT TERM

ensure_root
ensure_sdme
require_gate smoke
ensure_default_base_fs

# Clean stale artifacts from prior runs.
cleanup_prefix "${PREFIX}-"
mkdir -p "$TMPDIR"

# ---------------------------------------------------------------------------
# Test 1: host → rootfs
# ---------------------------------------------------------------------------
echo "=== Test 1: host → rootfs ==="

echo "cp-test-data" > "$TMPDIR/test-file"
if $SDME cp "$TMPDIR/test-file" "fs:ubuntu:/etc/cp-test-marker" $VFLAG; then
    # Verify file exists in the rootfs.
    rootfs_file="/var/lib/sdme/fs/ubuntu/etc/cp-test-marker"
    if [[ -f "$rootfs_file" ]] && grep -q "cp-test-data" "$rootfs_file"; then
        ok "host → rootfs"
    else
        fail "host → rootfs: file not found or wrong content"
    fi
    # Clean up marker from rootfs.
    rm -f "$rootfs_file"
else
    fail "host → rootfs: command failed"
fi

# ---------------------------------------------------------------------------
# Test 2: rootfs → host
# ---------------------------------------------------------------------------
echo "=== Test 2: rootfs → host ==="

if $SDME cp "fs:ubuntu:/etc/hostname" "$TMPDIR/hostname-rootfs" $VFLAG; then
    if [[ -f "$TMPDIR/hostname-rootfs" ]] && [[ -s "$TMPDIR/hostname-rootfs" ]]; then
        ok "rootfs → host"
    else
        fail "rootfs → host: file missing or empty"
    fi
else
    fail "rootfs → host: command failed"
fi

# ---------------------------------------------------------------------------
# Test 3: host → stopped container
# ---------------------------------------------------------------------------
echo "=== Test 3: host → stopped container ==="

$SDME create -r ubuntu "$CTR_STOPPED" $VFLAG 2>/dev/null
echo "stopped-marker" > "$TMPDIR/marker"
if $SDME cp "$TMPDIR/marker" "$CTR_STOPPED:/etc/marker" $VFLAG; then
    # Start and verify content.
    if $SDME start "$CTR_STOPPED" --timeout "$BOOT_TIMEOUT" $VFLAG; then
        actual=$($SDME exec "$CTR_STOPPED" -- /usr/bin/cat /etc/marker 2>/dev/null) || true
        actual="${actual%"${actual##*[![:space:]]}"}"
        if [[ "$actual" == "stopped-marker" ]]; then
            ok "host → stopped container"
        else
            fail "host → stopped container: expected 'stopped-marker', got '$actual'"
        fi
        stop_container "$CTR_STOPPED"
    else
        fail "host → stopped container: failed to start container"
    fi
else
    fail "host → stopped container: cp failed"
fi

# ---------------------------------------------------------------------------
# Test 4: stopped container → host
# ---------------------------------------------------------------------------
echo "=== Test 4: stopped container → host ==="

if $SDME cp "$CTR_STOPPED:/etc/hostname" "$TMPDIR/hostname-out" $VFLAG; then
    if [[ -f "$TMPDIR/hostname-out" ]]; then
        ok "stopped container → host"
    else
        fail "stopped container → host: output file not found"
    fi
else
    fail "stopped container → host: cp failed"
fi

# ---------------------------------------------------------------------------
# Test 5: host → running container
# ---------------------------------------------------------------------------
echo "=== Test 5: host → running container ==="

$SDME create -r ubuntu "$CTR_RUNNING" $VFLAG 2>/dev/null
$SDME start "$CTR_RUNNING" --timeout "$BOOT_TIMEOUT" $VFLAG
echo "running-marker" > "$TMPDIR/running-file"
cp_output=$($SDME cp "$TMPDIR/running-file" "$CTR_RUNNING:/etc/running-marker" $VFLAG 2>&1) || {
    fail "host → running container: cp failed"
    stop_container "$CTR_RUNNING"
    print_summary
    exit 0
}
actual=$($SDME exec "$CTR_RUNNING" -- /usr/bin/cat /etc/running-marker 2>/dev/null) || true
actual="${actual%"${actual##*[![:space:]]}"}"
if [[ "$actual" == "running-marker" ]]; then
    ok "host → running container"
else
    fail "host → running container: expected 'running-marker', got '$actual'"
fi
# Check for consistency warning.
if echo "$cp_output" | grep -q "consistency"; then
    ok "host → running container: consistency warning"
else
    fail "host → running container: expected consistency warning in stderr"
fi

# ---------------------------------------------------------------------------
# Test 6: running container → host
# ---------------------------------------------------------------------------
echo "=== Test 6: running container → host ==="

cp_output=$($SDME cp "$CTR_RUNNING:/etc/hostname" "$TMPDIR/running-hostname" $VFLAG 2>&1) || true
if [[ -f "$TMPDIR/running-hostname" ]] && [[ -s "$TMPDIR/running-hostname" ]]; then
    ok "running container → host"
else
    fail "running container → host: file missing or empty"
fi
if echo "$cp_output" | grep -q "consistency"; then
    ok "running container → host: consistency warning"
else
    fail "running container → host: expected consistency warning in stderr"
fi

stop_container "$CTR_RUNNING"

# ---------------------------------------------------------------------------
# Test 7: shadowed dir rejection (stopped container)
# ---------------------------------------------------------------------------
echo "=== Test 7: shadowed dir rejection ==="

echo "bad" > "$TMPDIR/bad-file"
if $SDME cp "$TMPDIR/bad-file" "$CTR_STOPPED:/tmp/bad" 2>/dev/null; then
    fail "shadowed dir: should have been rejected"
else
    ok "shadowed dir rejected (/tmp)"
fi

if $SDME cp "$TMPDIR/bad-file" "$CTR_STOPPED:/run/bad" 2>/dev/null; then
    fail "shadowed dir: /run should have been rejected"
else
    ok "shadowed dir rejected (/run)"
fi

if $SDME cp "$TMPDIR/bad-file" "$CTR_STOPPED:/dev/shm/bad" 2>/dev/null; then
    fail "shadowed dir: /dev/shm should have been rejected"
else
    ok "shadowed dir rejected (/dev/shm)"
fi

# ---------------------------------------------------------------------------
# Test 8: copy to running container (non-shadowed path)
# ---------------------------------------------------------------------------
echo "=== Test 8: copy to running container (non-shadowed path) ==="

$SDME start "$CTR_RUNNING" --timeout "$BOOT_TIMEOUT" $VFLAG
echo "var-tmp-ok" > "$TMPDIR/vartmp-ok"
if $SDME cp "$TMPDIR/vartmp-ok" "$CTR_RUNNING:/var/tmp/ok" $VFLAG 2>/dev/null; then
    actual=$($SDME exec "$CTR_RUNNING" -- /usr/bin/cat /var/tmp/ok 2>/dev/null) || true
    actual="${actual%"${actual##*[![:space:]]}"}"
    if [[ "$actual" == "var-tmp-ok" ]]; then
        ok "copy to running container (/var/tmp)"
    else
        fail "copy to running container: expected 'var-tmp-ok', got '$actual'"
    fi
else
    fail "copy to running container: cp to /var/tmp failed"
fi

# ---------------------------------------------------------------------------
# Test 9: host → running container /tmp
# ---------------------------------------------------------------------------
echo "=== Test 9: host → running container /tmp ==="

echo "tmp-marker-data" > "$TMPDIR/tmp-marker"
if $SDME cp "$TMPDIR/tmp-marker" "$CTR_RUNNING:/tmp/tmp-marker" $VFLAG 2>/dev/null; then
    actual=$($SDME exec "$CTR_RUNNING" -- /usr/bin/cat /tmp/tmp-marker 2>/dev/null) || true
    actual="${actual%"${actual##*[![:space:]]}"}"
    if [[ "$actual" == "tmp-marker-data" ]]; then
        ok "host → running container /tmp"
    else
        fail "host → running container /tmp: expected 'tmp-marker-data', got '$actual'"
    fi
else
    fail "host → running container /tmp: cp failed"
fi

# ---------------------------------------------------------------------------
# Test 10: running container /tmp → host
# ---------------------------------------------------------------------------
echo "=== Test 10: running container /tmp → host ==="

$SDME exec "$CTR_RUNNING" -- /bin/sh -c 'echo from-container-tmp > /tmp/outfile' 2>/dev/null || true
if $SDME cp "$CTR_RUNNING:/tmp/outfile" "$TMPDIR/from-tmp" $VFLAG 2>/dev/null; then
    if [[ -f "$TMPDIR/from-tmp" ]] && grep -q "from-container-tmp" "$TMPDIR/from-tmp"; then
        ok "running container /tmp → host"
    else
        fail "running container /tmp → host: file missing or wrong content"
    fi
else
    fail "running container /tmp → host: cp failed"
fi

stop_container "$CTR_RUNNING"

# ---------------------------------------------------------------------------
# Test 11: --force device node
# ---------------------------------------------------------------------------
echo "=== Test 11: --force device node ==="

# Create a char device node inside a stopped container's upper layer.
dev_dir="/var/lib/sdme/containers/$CTR_STOPPED/upper/dev"
mkdir -p "$dev_dir"
mknod "$dev_dir/testdev" c 1 5 2>/dev/null || {
    skipped "device node test (mknod failed)"
    print_summary
    exit 0
}

# Without --force, should fail.
if $SDME cp "$CTR_STOPPED:/dev/testdev" "$TMPDIR/devout" 2>/dev/null; then
    fail "device node: should have been refused without --force"
else
    ok "device node refused without --force"
fi

# With --force, should succeed.
if $SDME cp --force "$CTR_STOPPED:/dev/testdev" "$TMPDIR/devout-force" $VFLAG 2>/dev/null; then
    ok "device node copied with --force"
else
    fail "device node: --force copy failed"
fi

# Clean up the test device.
rm -f "$dev_dir/testdev"

# ---------------------------------------------------------------------------
# Test 12: hard link preservation via sdme cp
# ---------------------------------------------------------------------------
echo "=== Test 12: hard link preservation ==="

hl_src="$TMPDIR/hl-src"
hl_dst="$TMPDIR/hl-dst"
mkdir -p "$hl_src"
echo "hardlink-data" > "$hl_src/original"
ln "$hl_src/original" "$hl_src/link"

# Verify source has nlink=2.
src_nlink=$(stat -c %h "$hl_src/original")
if [[ "$src_nlink" -ne 2 ]]; then
    fail "hard link: source nlink=$src_nlink, expected 2"
else
    # Copy into rootfs.
    if $SDME cp "$hl_src/" "fs:ubuntu:/tmp/hl-test/" $VFLAG 2>/dev/null; then
        rootfs_dir="/var/lib/sdme/fs/ubuntu/tmp/hl-test"
        if [[ -f "$rootfs_dir/original" ]] && [[ -f "$rootfs_dir/link" ]]; then
            ino_a=$(stat -c %i "$rootfs_dir/original")
            ino_b=$(stat -c %i "$rootfs_dir/link")
            nlink=$(stat -c %h "$rootfs_dir/original")
            if [[ "$ino_a" == "$ino_b" ]] && [[ "$nlink" -eq 2 ]]; then
                ok "hard link preservation"
            else
                fail "hard link: inodes differ ($ino_a != $ino_b) or nlink=$nlink"
            fi
        else
            fail "hard link: files not found in rootfs"
        fi
        rm -rf "$rootfs_dir"
    else
        fail "hard link: sdme cp failed"
    fi
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print_summary
