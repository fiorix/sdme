#!/usr/bin/env bash
set -euo pipefail

# verify-storage.sh - end-to-end test for the btrfs storage backend
#
# Tests (Mode B: loopback btrfs pool on a non-btrfs datadir):
#   1. Lifecycle: create --storage btrfs, boot, exec, stop, rm (subvol deleted)
#   2. Offline cp into/from a stopped btrfs container
#   3. Offline export of a stopped btrfs container (tar)
#   4. btrfs-native diff (A/M/D)
#   5. Symlink-escape protection: cp a file over a base symlink does not follow
#   6. Disk cap: --disk N caps writes with ENOSPC; ps reports used/limit
#      (skipped when btrfs-progs lacks simple quotas, needs >= 6.7)
#   7. Base subvolume invalidation on fs rm
#
# The btrfs pool image ({datadir}/btrfs-pool.img) is shared infrastructure and
# is intentionally left in place between runs; only this test's prefixed
# containers and rootfs are cleaned up.

source "$(dirname "$0")/lib.sh"

PREFIX="vfy-storage"
BASEFS="${PREFIX}-base"
CTR="${PREFIX}-ctr"
BOOT_TIMEOUT=$(scale_timeout 60)

cleanup() {
    cleanup_prefix "${PREFIX}-"
}
trap cleanup EXIT INT TERM

ensure_root
ensure_sdme
require_gate smoke

# btrfs backend requires btrfs-progs. Skip the whole script if unavailable.
if ! command -v btrfs >/dev/null 2>&1 || ! command -v mkfs.btrfs >/dev/null 2>&1; then
    skipped "btrfs-progs not installed; skipping btrfs storage tests"
    print_summary
    exit 0
fi

cleanup_prefix "${PREFIX}-"

DATADIR=$($SDME config get | awk -F' = ' '/^datadir/{print $2}')

# Import a small base rootfs to snapshot from (idempotent; OCI cache is fast).
echo "=== Setup: importing base rootfs '$BASEFS' ==="
if ! fs_exists "$BASEFS"; then
    $SDME fs import "$BASEFS" "${DISTRO_IMAGES[debian]}" $VFLAG --install-packages=yes -f
fi

subvol_exists() { btrfs subvolume show "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------------------
# Test 1: lifecycle
# ---------------------------------------------------------------------------
echo "=== Test 1: btrfs container lifecycle ==="
$SDME create "$CTR" -r "$BASEFS" --storage btrfs $VFLAG
POOLSUB="${DATADIR}/pool/containers/${CTR}"
if subvol_exists "$POOLSUB"; then ok "create provisions a subvolume"; else fail "no container subvolume after create"; fi

if timeout "$BOOT_TIMEOUT" $SDME start "$CTR" $VFLAG; then
    sleep 2
    if $SDME exec "$CTR" -- true 2>/dev/null; then ok "boot + exec"; else fail "exec in booted btrfs container"; fi
    stop_container "$CTR"
else
    fail "btrfs container failed to boot"
fi

# ---------------------------------------------------------------------------
# Test 2: offline cp into and out of the stopped container
# ---------------------------------------------------------------------------
echo "=== Test 2: offline cp ==="
TMPD=$(mktemp -d)
echo "storage-marker" > "$TMPD/marker"
$SDME cp "$TMPD/marker" "$CTR":/etc/storage-marker $VFLAG
if $SDME cp "$CTR":/etc/storage-marker "$TMPD/back" 2>/dev/null && diff -q "$TMPD/marker" "$TMPD/back" >/dev/null; then
    ok "cp into/out of stopped btrfs container"
else
    fail "cp roundtrip on stopped btrfs container"
fi

# ---------------------------------------------------------------------------
# Test 3: offline export
# ---------------------------------------------------------------------------
echo "=== Test 3: offline export ==="
if $SDME fs export "$CTR" "$TMPD/export.tar" --fmt tar $VFLAG >/dev/null 2>&1 && [[ -s "$TMPD/export.tar" ]]; then
    ok "export stopped btrfs container to tar"
else
    fail "export of stopped btrfs container"
fi

# ---------------------------------------------------------------------------
# Test 4: btrfs-native diff
# ---------------------------------------------------------------------------
echo "=== Test 4: btrfs diff ==="
# The marker copied in Test 2 is an Added file relative to the base rootfs.
if $SDME diff "$CTR" 2>/dev/null | grep -qE '^A[[:space:]]+/etc/storage-marker$'; then
    ok "diff reports an added file"
else
    fail "diff missing the added /etc/storage-marker"
fi

# ---------------------------------------------------------------------------
# Test 5: symlink-escape protection (cp over a base symlink must not follow it)
# ---------------------------------------------------------------------------
echo "=== Test 5: symlink-escape protection ==="
# Plant an absolute symlink in the stopped container's subvolume, pointing at a
# host file. A guarded cp must shadow it (write a real file), never follow it.
ESCAPE="$TMPD/escape-target"
ln -sf "$ESCAPE" "${POOLSUB}/etc/escape-link"
echo "attacker" > "$TMPD/payload"
$SDME cp "$TMPD/payload" "$CTR":/etc/escape-link $VFLAG
if [[ ! -e "$ESCAPE" ]] && [[ -f "${POOLSUB}/etc/escape-link" ]] && \
   [[ ! -L "${POOLSUB}/etc/escape-link" ]]; then
    ok "cp shadowed the base symlink (no host escape)"
else
    fail "cp followed a base symlink out of the subvolume"
fi

# ---------------------------------------------------------------------------
# Test 6: disk cap (squota). Needs btrfs-progs >= 6.7 for 'quota enable --simple'.
# ---------------------------------------------------------------------------
echo "=== Test 6: disk cap ==="
CAP="${PREFIX}-cap"
if $SDME create "$CAP" -r "$BASEFS" --storage btrfs --disk 250M $VFLAG 2>"$TMPD/caperr"; then
    if grep -q '^DISK=250M' "${DATADIR}/state/${CAP}"; then ok "state records DISK cap"; else fail "state missing DISK cap"; fi
    if timeout "$BOOT_TIMEOUT" $SDME start "$CAP" $VFLAG; then
        sleep 2
        out=$($SDME exec "$CAP" -- sh -c 'dd if=/dev/zero of=/var/blob bs=1M count=500 2>&1; echo EXIT:$?' 2>/dev/null || true)
        if echo "$out" | grep -qiE "no space left|quota exceeded"; then
            ok "write hit the disk cap (ENOSPC/quota)"
        else
            fail "write did not hit the disk cap"
        fi
        if $SDME ps 2>/dev/null | awk -v n="$CAP" '$1==n' | grep -qE '/250M'; then
            ok "ps reports used/limit"
        else
            fail "ps missing disk usage"
        fi
        stop_container "$CAP"
    else
        fail "capped btrfs container failed to boot"
    fi
    $SDME rm -f "$CAP" 2>/dev/null || true
else
    if grep -qi "quota" "$TMPD/caperr"; then
        skipped "disk cap unsupported (btrfs-progs lacks simple quotas, needs >= 6.7)"
    else
        fail "create --disk failed: $(cat "$TMPD/caperr")"
    fi
fi

# ---------------------------------------------------------------------------
# Test 7: rm deletes the subvolume; fs rm invalidates the base subvolume
# ---------------------------------------------------------------------------
echo "=== Test 7: teardown + base invalidation ==="
$SDME rm -f "$CTR" 2>/dev/null || true
if ! subvol_exists "$POOLSUB"; then ok "rm deleted the container subvolume"; else fail "container subvolume survived rm"; fi

POOLBASE="${DATADIR}/pool/fs/${BASEFS}"
if subvol_exists "$POOLBASE"; then
    $SDME fs rm -f "$BASEFS" 2>/dev/null || true
    if ! subvol_exists "$POOLBASE"; then ok "fs rm invalidated the base subvolume"; else fail "base subvolume survived fs rm"; fi
else
    skipped "base subvolume not present (already invalidated)"
fi

rm -rf "$TMPD"
print_summary
