#!/usr/bin/env bash
set -uo pipefail

# verify-pool.sh - end-to-end test for the Mode B btrfs loopback pool
#
# When the datadir is not on btrfs, sdme keeps btrfs subvolumes in a loopback
# pool: {datadir}/btrfs-pool.img mounted at {datadir}/pool by a generated mount
# unit (see src/storage/pool.rs). A host whose datadir is btrfs never runs that
# code, so this suite brings its own datadir, an ext4 filesystem on a loop
# image selected with --config, and behaves the same on every host.
#
# Tests:
#   1. Pool setup: the first --storage btrfs create makes the image and the
#      mount unit, mounts the pool, and puts the container in a subvolume
#   2. Leftover pod rootfs on the pool: create fails fast, kube delete reclaims
#      the subvolume and is idempotent, and the pod can be created again
#   3. Failed container creation removes the pod subvolume it built
#   4. Cold pool, leftover: with the pool unmounted, an overlay create of the
#      same pod still fails fast on the leftover subvolume, and kube delete
#      mounts the pool and removes it
#   5. Cold pool, boot: the container unit requires the pool mount, so starting
#      the unit with the pool unmounted mounts it first
#
# Everything lives under $POOL_ROOT and is removed on exit, including the pool
# mount unit, which no sdme command removes.

source "$(dirname "$0")/lib.sh"

PREFIX="vfy-pool"
BASE_FS="${BASE_FS:-ubuntu}"
POOL_ROOT="/var/tmp/sdme-e2e-pool"
POOL_IMG="$POOL_ROOT/datadir.img"
POOL_CONF="$POOL_ROOT/sdme.conf"
# Read by lib.sh's kube_* path helpers.
DATADIR="$POOL_ROOT/datadir"
KUBE_STORAGE="btrfs"
KFLAG=$(kube_storage_args)
CTR="${PREFIX}-ct"
TIMEOUT_BOOT=$(scale_timeout 120)

# sdme against the scratch datadir.
psdme() {
    "$SDME" --config "$POOL_CONF" "$@"
}

pool_unit() {
    systemd-escape -p --suffix=mount "$DATADIR/pool"
}

pool_mounted() {
    mountpoint -q "$DATADIR/pool"
}

# Unmount the pool. A container that has just stopped can keep it busy for a
# moment, so retry.
pool_unmount() {
    local unit i
    unit=$(pool_unit)
    for i in 1 2 3 4 5 6 7 8 9 10; do
        systemctl stop "$unit" 2>/dev/null
        pool_mounted || return 0
        sleep 1
    done
    return 1
}

teardown() {
    local name unit
    if [[ -f "$POOL_CONF" ]] && mountpoint -q "$DATADIR"; then
        for name in $(psdme ps 2>/dev/null | awk 'NR>1 {print $1}' | grep "^${PREFIX}-" || true); do
            psdme stop --kill "$name" >/dev/null 2>&1 || true
            psdme rm -f "$name" >/dev/null 2>&1 || true
        done
    fi
    # Host state that a container in the scratch datadir leaves outside it.
    rm -rf /etc/systemd/system/sdme@"${PREFIX}"-*.service.d
    rmdir "/var/lib/machines/${PREFIX}-rb" 2>/dev/null || true

    unit=$(pool_unit)
    pool_unmount || umount -l "$DATADIR/pool" 2>/dev/null || true
    rm -f "/etc/systemd/system/$unit"
    systemctl daemon-reload
    systemctl reset-failed "$unit" 2>/dev/null || true

    if mountpoint -q "$DATADIR"; then
        umount "$DATADIR" 2>/dev/null || umount -l "$DATADIR" 2>/dev/null || true
    fi
    # Never delete through a mount that would not go away.
    if mountpoint -q "$DATADIR"; then
        echo "warning: $DATADIR is still mounted; leaving $POOL_ROOT in place" >&2
        return
    fi
    rm -rf "$POOL_ROOT"
}

trap teardown EXIT INT TERM

pod_yaml() {
    local pod_name="$1" yaml_file
    yaml_file=$(mktemp /tmp/pool-test-XXXXXX.yaml)
    cat > "$yaml_file" <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: $pod_name
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    command: ["/bin/sh", "-c", "sleep infinity"]
YAML
    echo "$yaml_file"
}

# -- Preflight -----------------------------------------------------------------

ensure_root
ensure_sdme
require_gate smoke
require_gate interrupt

for tool in mkfs.ext4 mkfs.btrfs btrfs losetup systemd-escape; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        trap - EXIT INT TERM
        skipped "$tool not installed; skipping the loopback pool tests"
        print_summary
        exit 0
    fi
done

ensure_default_base_fs
HOST_DATADIR=$("$SDME" config get | awk -F' = ' '/^datadir/{print $2}')
HOST_CACHE=$("$SDME" config get | awk -F' = ' '/^oci_cache_dir/{print $2}')

# -- Setup: an ext4 datadir on a loop image ------------------------------------

echo "=== Setup: scratch ext4 datadir at $DATADIR ==="
teardown
mkdir -p "$DATADIR"
truncate -s 12G "$POOL_IMG"
if ! mkfs.ext4 -q -F "$POOL_IMG" || ! mount -o loop "$POOL_IMG" "$DATADIR"; then
    fail "could not create and mount the scratch ext4 datadir"
    print_summary
    exit 1
fi

# Start from the host's settings so both datadirs agree on the shared template
# unit, then point this config at the scratch datadir. The image cache stays
# the host's, so the pods here pull nothing the other suites already have.
if [[ -f /etc/sdme.conf ]]; then
    cp /etc/sdme.conf "$POOL_CONF"
fi
psdme config set datadir "$DATADIR" >/dev/null
psdme config set btrfs_pool_size 6G >/dev/null
psdme config set oci_cache_dir "${HOST_CACHE:-$HOST_DATADIR/cache/oci}" >/dev/null

if [[ "$(stat -f -c %T "$DATADIR")" == "btrfs" ]]; then
    fail "scratch datadir is btrfs; this suite needs a Mode B datadir"
    print_summary
    exit 1
fi

echo "=== Setup: importing base rootfs '$BASE_FS' from $HOST_DATADIR/fs/$BASE_FS ==="
if ! psdme fs import "$HOST_DATADIR/fs/$BASE_FS" --name "$BASE_FS" --install-packages=no $VFLAG 2>&1; then
    fail "could not import the base rootfs into the scratch datadir"
    print_summary
    exit 1
fi

# -- Test 1: pool setup --------------------------------------------------------

echo "=== Test 1: the first btrfs create builds and mounts the pool ==="

UNIT=$(pool_unit)
if [[ -e "$DATADIR/btrfs-pool.img" ]] || pool_mounted; then
    fail "pool exists before any btrfs create"
fi

if output=$(psdme create --name "$CTR" -r "$BASE_FS" --storage btrfs $VFLAG 2>&1); then
    ok "create --storage btrfs on a non-btrfs datadir"
else
    fail "create --storage btrfs: $output"
fi

if [[ -f "$DATADIR/btrfs-pool.img" && -f "/etc/systemd/system/$UNIT" ]] && pool_mounted \
    && [[ "$(stat -f -c %T "$DATADIR/pool")" == "btrfs" ]]; then
    ok "pool image, mount unit, and btrfs mount exist"
else
    fail "pool image, mount unit ($UNIT), or mount missing"
fi

if btrfs subvolume show "$DATADIR/pool/containers/$CTR" >/dev/null 2>&1; then
    ok "container root is a subvolume in the pool"
else
    fail "no subvolume at $DATADIR/pool/containers/$CTR"
fi

# -- Test 2: leftover pod rootfs on the pool -----------------------------------

echo "=== Test 2: leftover pod rootfs on the pool ==="

POD="${PREFIX}-orphan"
ROOTFS_DIR=$(kube_fs_dir "kube-$POD")
YAML=$(pod_yaml "$POD")

if ! output=$(psdme kube create -f "$YAML" --base-fs "$BASE_FS" $KFLAG 2>&1); then
    fail "orphan: initial kube create failed: $output"
else
    # sdme rm removes the container and keeps its rootfs.
    psdme rm -f "$POD" >/dev/null 2>&1
    if [[ ! -f "$DATADIR/state/$POD" ]] && btrfs subvolume show "$ROOTFS_DIR" >/dev/null 2>&1; then
        ok "orphan: sdme rm leaves the pod subvolume in the pool"
    else
        fail "orphan: expected no state file and a subvolume at $ROOTFS_DIR"
    fi

    # The create must stop before the base copy and before any pull.
    rc=0
    output=$(psdme kube create -f "$YAML" --base-fs "$BASE_FS" $KFLAG 2>&1) || rc=$?
    if [[ $rc -ne 0 ]] \
        && grep -q "rootfs 'kube-$POD' already exists but no container claims it" <<<"$output" \
        && grep -q "sdme kube delete $POD" <<<"$output" \
        && ! grep -qE "pulling|copying base rootfs|extracting layer" <<<"$output" \
        && [[ -d "$ROOTFS_DIR" && ! -f "$DATADIR/state/$POD" ]]; then
        ok "orphan: create over the leftover subvolume fails fast"
    else
        fail "orphan: create over the leftover subvolume: rc=$rc, output: $output"
    fi

    rc=0
    output=$(psdme kube delete "$POD" 2>&1) || rc=$?
    if [[ $rc -eq 0 ]] && grep -q "removing orphaned rootfs: kube-$POD" <<<"$output" \
        && [[ ! -e "$ROOTFS_DIR" ]]; then
        ok "orphan: kube delete removes the leftover subvolume"
    else
        fail "orphan: kube delete without a container: rc=$rc, output: $output"
    fi

    if output=$(psdme kube delete "$POD" 2>&1); then
        ok "orphan: kube delete with nothing left succeeds"
    else
        fail "orphan: second kube delete: $output"
    fi

    if output=$(psdme kube create -f "$YAML" --base-fs "$BASE_FS" $KFLAG 2>&1) \
        && [[ -f "$DATADIR/state/$POD" ]] && btrfs subvolume show "$ROOTFS_DIR" >/dev/null 2>&1; then
        ok "orphan: the pod can be created again"
    else
        fail "orphan: create after the cleanup: $output"
    fi
    psdme kube delete "$POD" --force >/dev/null 2>&1 || true
fi
rm -f "$YAML"

# -- Test 3: failed container creation -----------------------------------------

echo "=== Test 3: a failed container creation removes the pod subvolume ==="

POD="${PREFIX}-rb"
ROOTFS_DIR=$(kube_fs_dir "kube-$POD")
YAML=$(pod_yaml "$POD")
MACHINE_DIR="/var/lib/machines/$POD"

# Container creation refuses a name that /var/lib/machines already holds. That
# check runs after the pod rootfs is committed, so it fails the create at the
# point where the subvolume exists and no container claims it yet.
mkdir -p "$MACHINE_DIR"
rc=0
output=$(psdme kube create -f "$YAML" --base-fs "$BASE_FS" $KFLAG 2>&1) || rc=$?
rmdir "$MACHINE_DIR"
rm -f "$YAML"

if [[ $rc -ne 0 ]] && grep -q "conflicting machine found" <<<"$output" \
    && [[ ! -e "$ROOTFS_DIR" && ! -f "$DATADIR/state/$POD" ]]; then
    ok "rollback: failed create leaves no subvolume"
else
    fail "rollback: rc=$rc, subvolume present: $([[ -e "$ROOTFS_DIR" ]] && echo yes || echo no), output: $output"
fi
psdme kube delete "$POD" --force >/dev/null 2>&1 || true

# -- Test 4: cold pool, delete -------------------------------------------------

echo "=== Test 4: a leftover subvolume in an unmounted pool is found and removed ==="

POD="${PREFIX}-cold"
ROOTFS_DIR=$(kube_fs_dir "kube-$POD")
YAML=$(pod_yaml "$POD")

if ! output=$(psdme kube create -f "$YAML" --base-fs "$BASE_FS" $KFLAG 2>&1); then
    fail "cold delete: kube create failed: $output"
else
    psdme rm -f "$POD" >/dev/null 2>&1

    # An overlay create of the same pod never needs the pool, and still has to
    # find the leftover subvolume inside it.
    if ! pool_unmount; then
        fail "cold create: could not unmount the pool"
    else
        rc=0
        output=$(psdme kube create -f "$YAML" --base-fs "$BASE_FS" --storage overlay 2>&1) || rc=$?
        if [[ $rc -ne 0 ]] \
            && grep -q "rootfs 'kube-$POD' already exists but no container claims it" <<<"$output" \
            && ! grep -qE "pulling|copying base rootfs|extracting layer" <<<"$output" \
            && [[ ! -e "$DATADIR/fs/kube-$POD" && ! -f "$DATADIR/state/$POD" ]]; then
            ok "cold create: overlay create finds the leftover in an unmounted pool"
        else
            fail "cold create: rc=$rc, output: $output"
            psdme kube delete "$POD" --force >/dev/null 2>&1 || true
        fi
    fi

    if ! pool_unmount; then
        fail "cold delete: could not unmount the pool"
    else
        rc=0
        output=$(psdme kube delete "$POD" 2>&1) || rc=$?
        if [[ $rc -eq 0 ]] && grep -q "removing orphaned rootfs: kube-$POD" <<<"$output" \
            && pool_mounted && [[ ! -e "$ROOTFS_DIR" ]]; then
            ok "cold delete: pool mounted and leftover subvolume removed"
        else
            fail "cold delete: rc=$rc, pool mounted: $(pool_mounted && echo yes || echo no), output: $output"
        fi
    fi
    psdme kube delete "$POD" --force >/dev/null 2>&1 || true
fi
rm -f "$YAML"

# -- Test 5: cold pool, boot ---------------------------------------------------

echo "=== Test 5: the container unit brings the pool mount up ==="

SERVICE="sdme@${CTR}.service"

# A first start through sdme writes the drop-in the unit boots from.
if ! output=$(timeout "$TIMEOUT_BOOT" "$SDME" --config "$POOL_CONF" start "$CTR" -t "$TIMEOUT_BOOT" $VFLAG 2>&1); then
    fail "cold boot: sdme start failed: $output"
else
    ok "btrfs container boots from the pool"

    requires=$(systemctl show -p RequiresMountsFor --value "$SERVICE")
    if grep -qw "$DATADIR/pool" <<<"$requires"; then
        ok "cold boot: unit has RequiresMountsFor for the pool"
    else
        fail "cold boot: RequiresMountsFor is '$requires', expected $DATADIR/pool"
    fi

    psdme stop "$CTR" >/dev/null 2>&1 || psdme stop --kill "$CTR" >/dev/null 2>&1
    if ! pool_unmount; then
        fail "cold boot: could not unmount the pool"
    else
        # What a host boot does for an enabled container: systemd starts the
        # unit and sdme is not involved, so nothing but the unit's own
        # dependency can mount the pool.
        if timeout "$TIMEOUT_BOOT" systemctl start "$SERVICE" 2>&1 \
            && pool_mounted && [[ "$(systemctl is-active "$SERVICE")" == "active" ]]; then
            ok "cold boot: starting the unit mounted the pool and booted the container"
        else
            fail "cold boot: unit state $(systemctl is-active "$SERVICE"), pool mounted: $(pool_mounted && echo yes || echo no)"
        fi
    fi
    psdme stop --kill "$CTR" >/dev/null 2>&1 || true
fi

# -- Summary -------------------------------------------------------------------

print_summary
