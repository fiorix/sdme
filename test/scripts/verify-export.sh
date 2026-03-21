#!/usr/bin/env bash
set -euo pipefail

# verify-export.sh - end-to-end test for sdme fs export
#
# Tests:
#   1. Directory export
#   2. Tarball export (uncompressed, gzip, bzip2, xz, zstd)
#   3. Raw disk image export (ext4 auto-size, explicit --size)
#   4. Btrfs raw disk image export (auto-size, explicit --size)
#   5. Format override (--fmt)
#   6. Nonexistent rootfs (error case)
#   7. Timezone: dir export, tar export, raw image export, invalid timezone

source "$(dirname "$0")/lib.sh"

TMPDIR=$(mktemp -d /tmp/vfy-export-XXXXXX)

# Check if a tar archive contains a given path.
# Runs in a subshell with pipefail disabled to avoid SIGPIPE failures.
tar_contains() {
    local archive="$1" path="$2"
    shift 2
    # $@ contains optional tar flags (e.g. -z, -j, -J)
    ( set +o pipefail; tar "$@" -tf "$archive" 2>/dev/null | grep -q "$path" )
}

cleanup() {
    # Unmount any leftover loop mounts under TMPDIR.
    mount | grep "$TMPDIR" | awk '{print $3}' | while read -r mp; do
        umount "$mp" 2>/dev/null || true
    done || true
    rm -rf "$TMPDIR"
}

trap cleanup EXIT INT TERM

ensure_root
ensure_sdme
require_gate smoke
require_gate interrupt
ensure_base_fs ubuntu docker.io/ubuntu:24.04

# Check optional dependencies for some tests.
HAS_ZSTDCAT=true
if ! command -v zstdcat &>/dev/null; then
    echo "note: zstdcat not found; tar.zst test will be skipped"
    HAS_ZSTDCAT=false
fi

HAS_MKFS_EXT4=true
if ! command -v mkfs.ext4 &>/dev/null; then
    echo "note: mkfs.ext4 not found; ext4 raw image tests will be skipped"
    HAS_MKFS_EXT4=false
fi

HAS_MKFS_BTRFS=true
if ! command -v mkfs.btrfs &>/dev/null; then
    echo "note: mkfs.btrfs not found; btrfs raw image tests will be skipped"
    HAS_MKFS_BTRFS=false
fi

# ---------------------------------------------------------------------------
# Test 1: Directory export
# ---------------------------------------------------------------------------
echo "=== Test 1: Directory export ==="

outdir="$TMPDIR/dir-export"
if $SDME fs export fs:ubuntu "$outdir" $VFLAG; then
    if [[ -d "$outdir" ]] && [[ -f "$outdir/etc/os-release" ]]; then
        ok "dir export"
    else
        fail "dir export: output missing expected files"
    fi
else
    fail "dir export: command failed"
fi
rm -rf "$outdir"

# ---------------------------------------------------------------------------
# Test 2: Tarball export (uncompressed)
# ---------------------------------------------------------------------------
echo "=== Test 2: tar export ==="

tarfile="$TMPDIR/out.tar"
if $SDME fs export fs:ubuntu "$tarfile" $VFLAG; then
    if [[ -f "$tarfile" ]] && tar_contains "$tarfile" "etc/os-release"; then
        ok "tar export"
    else
        fail "tar export: missing etc/os-release in archive"
    fi
else
    fail "tar export: command failed"
fi
rm -f "$tarfile"

# ---------------------------------------------------------------------------
# Test 3: tar.gz export
# ---------------------------------------------------------------------------
echo "=== Test 3: tar.gz export ==="

targz="$TMPDIR/out.tar.gz"
if $SDME fs export fs:ubuntu "$targz" $VFLAG; then
    if [[ -f "$targz" ]] && tar_contains "$targz" "etc/os-release" -z; then
        ok "tar.gz export"
    else
        fail "tar.gz export: missing etc/os-release in archive"
    fi
else
    fail "tar.gz export: command failed"
fi
rm -f "$targz"

# ---------------------------------------------------------------------------
# Test 4: tar.bz2 export
# ---------------------------------------------------------------------------
echo "=== Test 4: tar.bz2 export ==="

tarbz2="$TMPDIR/out.tar.bz2"
if $SDME fs export fs:ubuntu "$tarbz2" $VFLAG; then
    if [[ -f "$tarbz2" ]] && tar_contains "$tarbz2" "etc/os-release" -j; then
        ok "tar.bz2 export"
    else
        fail "tar.bz2 export: missing etc/os-release in archive"
    fi
else
    fail "tar.bz2 export: command failed"
fi
rm -f "$tarbz2"

# ---------------------------------------------------------------------------
# Test 5: tar.xz export
# ---------------------------------------------------------------------------
echo "=== Test 5: tar.xz export ==="

tarxz="$TMPDIR/out.tar.xz"
if $SDME fs export fs:ubuntu "$tarxz" $VFLAG; then
    if [[ -f "$tarxz" ]] && tar_contains "$tarxz" "etc/os-release" -J; then
        ok "tar.xz export"
    else
        fail "tar.xz export: missing etc/os-release in archive"
    fi
else
    fail "tar.xz export: command failed"
fi
rm -f "$tarxz"

# ---------------------------------------------------------------------------
# Test 6: tar.zst export
# ---------------------------------------------------------------------------
echo "=== Test 6: tar.zst export ==="

if [[ "$HAS_ZSTDCAT" == "true" ]]; then
    tarzst="$TMPDIR/out.tar.zst"
    if $SDME fs export fs:ubuntu "$tarzst" $VFLAG; then
        if [[ -f "$tarzst" ]] && ( set +o pipefail; zstdcat "$tarzst" | tar t 2>/dev/null | grep -q "etc/os-release" ); then
            ok "tar.zst export"
        else
            fail "tar.zst export: missing etc/os-release in archive"
        fi
    else
        fail "tar.zst export: command failed"
    fi
    rm -f "$tarzst"
else
    skipped "tar.zst export (zstdcat not available)"
fi

# ---------------------------------------------------------------------------
# Test 7: Raw disk image export (auto-size)
# ---------------------------------------------------------------------------
echo "=== Test 7: raw export ==="

if [[ "$HAS_MKFS_EXT4" == "true" ]]; then
    rawimg="$TMPDIR/out.raw"
    if $SDME fs export fs:ubuntu "$rawimg" $VFLAG; then
        if [[ -f "$rawimg" ]]; then
            mntpoint="$TMPDIR/rawmnt"
            mkdir -p "$mntpoint"
            if mount -o loop,ro "$rawimg" "$mntpoint"; then
                if [[ -f "$mntpoint/etc/os-release" ]]; then
                    ok "raw export"
                else
                    fail "raw export: missing etc/os-release in image"
                fi
                umount "$mntpoint"
            else
                fail "raw export: failed to mount image"
            fi
        else
            fail "raw export: output file not created"
        fi
    else
        fail "raw export: command failed"
    fi
    rm -f "$rawimg"
else
    skipped "raw export (mkfs.ext4 not available)"
fi

# ---------------------------------------------------------------------------
# Test 8: Raw disk image export with --size
# ---------------------------------------------------------------------------
echo "=== Test 8: raw export --size ==="

if [[ "$HAS_MKFS_EXT4" == "true" ]]; then
    rawimg2="$TMPDIR/out2.raw"
    if $SDME fs export fs:ubuntu "$rawimg2" --size 2G $VFLAG; then
        if [[ -f "$rawimg2" ]]; then
            actual_size=$(stat -c%s "$rawimg2")
            expected_size=2147483648
            if [[ "$actual_size" -eq "$expected_size" ]]; then
                ok "raw export --size 2G"
            else
                fail "raw export --size 2G: expected $expected_size bytes, got $actual_size"
            fi
        else
            fail "raw export --size: output file not created"
        fi
    else
        fail "raw export --size: command failed"
    fi
    rm -f "$rawimg2"
else
    skipped "raw export --size (mkfs.ext4 not available)"
fi

# ---------------------------------------------------------------------------
# Test 9: Format override (--fmt)
# ---------------------------------------------------------------------------
echo "=== Test 9: format override ==="

noext="$TMPDIR/noext"
if $SDME fs export fs:ubuntu "$noext" --fmt tar.gz $VFLAG; then
    if [[ -f "$noext" ]] && tar_contains "$noext" "etc/os-release" -z; then
        ok "format override (--fmt tar.gz)"
    else
        fail "format override: file not a valid tar.gz"
    fi
else
    fail "format override: command failed"
fi
rm -f "$noext"

# ---------------------------------------------------------------------------
# Test 10: Nonexistent rootfs (error case)
# ---------------------------------------------------------------------------
echo "=== Test 10: nonexistent rootfs ==="

if $SDME fs export fs:nonexistent "$TMPDIR/nope" 2>/dev/null; then
    fail "nonexistent rootfs should error"
else
    ok "nonexistent rootfs rejected"
fi

# ---------------------------------------------------------------------------
# Test 11: Btrfs raw disk image export (auto-size)
# ---------------------------------------------------------------------------
echo "=== Test 11: btrfs raw export ==="

if [[ "$HAS_MKFS_BTRFS" == "true" ]]; then
    rawbtrfs="$TMPDIR/out-btrfs.raw"
    if $SDME fs export fs:ubuntu "$rawbtrfs" --filesystem btrfs $VFLAG; then
        if [[ -f "$rawbtrfs" ]]; then
            mntpoint="$TMPDIR/btrfsmnt"
            mkdir -p "$mntpoint"
            if mount -o loop,ro "$rawbtrfs" "$mntpoint"; then
                if [[ -f "$mntpoint/etc/os-release" ]]; then
                    ok "btrfs raw export"
                else
                    fail "btrfs raw export: missing etc/os-release in image"
                fi
                umount "$mntpoint"
            else
                fail "btrfs raw export: failed to mount image"
            fi
        else
            fail "btrfs raw export: output file not created"
        fi
    else
        fail "btrfs raw export: command failed"
    fi
    rm -f "$rawbtrfs"
else
    skipped "btrfs raw export (mkfs.btrfs not available)"
fi

# ---------------------------------------------------------------------------
# Test 12: Btrfs raw disk image export with --size
# ---------------------------------------------------------------------------
echo "=== Test 12: btrfs raw export --size ==="

if [[ "$HAS_MKFS_BTRFS" == "true" ]]; then
    rawbtrfs2="$TMPDIR/out-btrfs2.raw"
    if $SDME fs export fs:ubuntu "$rawbtrfs2" --filesystem btrfs --size 2G $VFLAG; then
        if [[ -f "$rawbtrfs2" ]]; then
            actual_size=$(stat -c%s "$rawbtrfs2")
            expected_size=2147483648
            if [[ "$actual_size" -eq "$expected_size" ]]; then
                ok "btrfs raw export --size 2G"
            else
                fail "btrfs raw export --size 2G: expected $expected_size bytes, got $actual_size"
            fi
        else
            fail "btrfs raw export --size: output file not created"
        fi
    else
        fail "btrfs raw export --size: command failed"
    fi
    rm -f "$rawbtrfs2"
else
    skipped "btrfs raw export --size (mkfs.btrfs not available)"
fi

# ---------------------------------------------------------------------------
# Test 13: Directory export with --timezone
# ---------------------------------------------------------------------------
echo "=== Test 13: dir export --timezone ==="

outdir="$TMPDIR/dir-tz-export"
if $SDME fs export fs:ubuntu "$outdir" --timezone America/New_York $VFLAG; then
    if [[ -L "$outdir/etc/localtime" ]]; then
        target=$(readlink "$outdir/etc/localtime")
        if [[ "$target" == "../usr/share/zoneinfo/America/New_York" ]]; then
            ok "dir export --timezone localtime symlink"
        else
            fail "dir export --timezone: expected ../usr/share/zoneinfo/America/New_York, got $target"
        fi
    else
        fail "dir export --timezone: /etc/localtime is not a symlink"
    fi
    if [[ -f "$outdir/etc/timezone" ]]; then
        tz_content=$(cat "$outdir/etc/timezone")
        if [[ "$tz_content" == "America/New_York" ]]; then
            ok "dir export --timezone /etc/timezone"
        else
            fail "dir export --timezone: expected America/New_York, got $tz_content"
        fi
    else
        fail "dir export --timezone: /etc/timezone not found"
    fi
else
    fail "dir export --timezone: command failed"
fi
rm -rf "$outdir"

# ---------------------------------------------------------------------------
# Test 14: Tarball export with --timezone
# ---------------------------------------------------------------------------
echo "=== Test 14: tar export --timezone ==="

tarfile="$TMPDIR/tz-out.tar"
if $SDME fs export fs:ubuntu "$tarfile" --timezone UTC $VFLAG; then
    if [[ -f "$tarfile" ]] && tar_contains "$tarfile" "etc/localtime" && tar_contains "$tarfile" "etc/timezone"; then
        ok "tar export --timezone"
    else
        fail "tar export --timezone: missing etc/localtime or etc/timezone in archive"
    fi
else
    fail "tar export --timezone: command failed"
fi
rm -f "$tarfile"

# ---------------------------------------------------------------------------
# Test 15: Raw image export with --timezone
# ---------------------------------------------------------------------------
echo "=== Test 15: raw export --timezone ==="

if [[ "$HAS_MKFS_EXT4" == "true" ]]; then
    rawimg="$TMPDIR/tz-out.raw"
    if $SDME fs export fs:ubuntu "$rawimg" --timezone Europe/London $VFLAG; then
        if [[ -f "$rawimg" ]]; then
            mntpoint="$TMPDIR/tz-rawmnt"
            mkdir -p "$mntpoint"
            if mount -o loop,ro "$rawimg" "$mntpoint"; then
                if [[ -L "$mntpoint/etc/localtime" ]]; then
                    target=$(readlink "$mntpoint/etc/localtime")
                    if [[ "$target" == "../usr/share/zoneinfo/Europe/London" ]]; then
                        ok "raw export --timezone"
                    else
                        fail "raw export --timezone: expected ../usr/share/zoneinfo/Europe/London, got $target"
                    fi
                else
                    fail "raw export --timezone: /etc/localtime is not a symlink"
                fi
                umount "$mntpoint"
            else
                fail "raw export --timezone: failed to mount image"
            fi
        else
            fail "raw export --timezone: output file not created"
        fi
    else
        fail "raw export --timezone: command failed"
    fi
    rm -f "$rawimg"
else
    skipped "raw export --timezone (mkfs.ext4 not available)"
fi

# ---------------------------------------------------------------------------
# Test 16: Invalid timezone (error case)
# ---------------------------------------------------------------------------
echo "=== Test 16: invalid timezone ==="

if $SDME fs export fs:ubuntu "$TMPDIR/tz-bad" --timezone Fake/Zone 2>/dev/null; then
    fail "invalid timezone should error"
    rm -rf "$TMPDIR/tz-bad"
else
    ok "invalid timezone rejected"
fi

# ---------------------------------------------------------------------------
# Test 17: Smart error — container not found, rootfs exists (hint)
# ---------------------------------------------------------------------------
echo "=== Test 17: smart error hint (container not found, rootfs exists) ==="

# Bare name defaults to container; "ubuntu" is a rootfs, not a container.
err_output=$($SDME fs export ubuntu "$TMPDIR/hint-test" 2>&1 || true)
if echo "$err_output" | grep -q "fs:ubuntu"; then
    ok "smart error: hint suggests fs:ubuntu"
else
    fail "smart error: expected hint about fs:ubuntu, got: $err_output"
fi

# ---------------------------------------------------------------------------
# Test 18: Smart error — rootfs not found, container exists (hint)
# ---------------------------------------------------------------------------
echo "=== Test 18: smart error hint (rootfs not found, container exists) ==="

# Create and stop a container for this test.
ctr_name="export-hint-test"
if $SDME create -r ubuntu "$ctr_name" $VFLAG 2>/dev/null; then
    err_output=$($SDME fs export "fs:$ctr_name" "$TMPDIR/hint-test2" 2>&1 || true)
    if echo "$err_output" | grep -q "without the fs: prefix"; then
        ok "smart error: hint suggests dropping fs: prefix"
    else
        fail "smart error: expected hint about dropping prefix, got: $err_output"
    fi
    $SDME rm "$ctr_name" 2>/dev/null || true
else
    fail "smart error: failed to create test container"
fi

# ---------------------------------------------------------------------------
# Test 19: Container export (stopped)
# ---------------------------------------------------------------------------
echo "=== Test 19: container export (stopped) ==="

ctr_name="export-ctr-test"
if $SDME create -r ubuntu "$ctr_name" $VFLAG 2>/dev/null; then
    outdir="$TMPDIR/ctr-export"
    if $SDME fs export "$ctr_name" "$outdir" $VFLAG; then
        if [[ -d "$outdir" ]] && [[ -f "$outdir/etc/os-release" ]]; then
            ok "container export (stopped)"
        else
            fail "container export: output missing expected files"
        fi
    else
        fail "container export: command failed"
    fi
    rm -rf "$outdir"
    $SDME rm "$ctr_name" 2>/dev/null || true
else
    fail "container export: failed to create test container"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print_summary
