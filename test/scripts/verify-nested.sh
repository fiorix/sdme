#!/usr/bin/env bash
set -euo pipefail

# verify-nested.sh - end-to-end test for running sdme inside a user-namespaced
# sdme container ("nested"), replicating the devsrv platform topology:
# an outer container with --storage btrfs --userns --userns-nested=32 whose
# rootfs hosts the nested sdme's data root on an init_user_ns-owned superblock.
#
# Covers the nested-operation fixes:
#   1. Outer topology boots (btrfs + userns + nested range of (1+32)*65536 IDs).
#   2. Nested `sdme fs import --install-packages=yes` (chroot /dev staging).
#   3. Nested container creates fail fast with the named cause: nested nspawn
#      boots are blocked by kernel rules (mknod requires CAP_MKNOD in the
#      initial user namespace; proc/sysfs have matching ownership rules), and
#      the create-time preflight surfaces that in seconds, not a boot timeout.
#   4. Explicit nested `--storage btrfs` fails fast with the documented error.
#   5. Subvolume deletion: without user_subvol_rm_allowed the destroy ioctl
#      EPERMs and the subvolume is parked in .trash (with the warning); with
#      the option, destroy succeeds and nested `sdme prune` empties the trash.
#   6. Nested kube create fails fast with the same mknod preflight.
#   7. After cleanup, zero stale subvolumes remain (verified from the host).
#
# Skips entirely when the sdme datadir is not btrfs (the outer container needs
# a btrfs rootfs). Runs serially (Stage 3): it toggles user_subvol_rm_allowed
# on the shared data root, which requires a mount restart.

source "$(dirname "$0")/lib.sh"

PREFIX="vfy-nested"
BASEFS="${PREFIX}-base"
OUTER="${PREFIX}-outer"
NESTED_FS="${PREFIX}-ubuntu"
INNER1="${PREFIX}-in1"
INNER2="${PREFIX}-in2"
BADCTR="${PREFIX}-bad"
LEGACY_A="${PREFIX}-legacy-a"
LEGACY_B="${PREFIX}-legacy-b"
KUBE_POD="vfy-kube-redis"
DATADIR="/var/lib/sdme"
BOOT_TIMEOUT=$(scale_timeout 180)
IMPORT_TIMEOUT=$(scale_timeout 900)
EXEC_TIMEOUT=$(scale_timeout 30)

VFLAG=()
if [[ -n "$VERBOSE" ]]; then
    VFLAG=("-v")
fi

# Nested sdme invocation inside the outer container.
nsdme() {
    timeout "$IMPORT_TIMEOUT" "$SDME" exec "$OUTER" -- /usr/local/bin/sdme "$@"
}

# Host view of the outer container's root and of the nested datadir.
pool_subroot() {
    if [[ "$(stat -f -c %T "$DATADIR")" == "btrfs" ]]; then
        echo "$DATADIR/btrfs"
    else
        echo "$DATADIR/pool"
    fi
}
outer_root() { echo "$(pool_subroot)/containers/$OUTER"; }
nested_datadir() { echo "$(outer_root)/var/lib/sdme"; }

state_key() {
    local name="$1" key="$2"
    grep "^${key}=" "${DATADIR}/state/${name}" 2>/dev/null | cut -d= -f2- || true
}

subvol_count_matching() {
    sudo btrfs subvolume list "$DATADIR" 2>/dev/null | grep -c "$1" || true
}

mount_has_rm_allowed() {
    findmnt -n -o FS-OPTIONS "$DATADIR" | tr ',' '\n' | grep -qx user_subvol_rm_allowed
}

mount_unit() {
    systemd-escape -p --suffix=mount "$DATADIR"
}

# btrfs mount options are sticky across remounts: an omitted option is kept,
# so clearing user_subvol_rm_allowed needs a fresh mount. Prefer restarting
# the systemd mount unit when one manages the datadir; fall back to a manual
# umount+mount. The restart fails (EBUSY) while containers hold mounts, so
# this is only called when no test containers exist.
set_rm_allowed() {
    # $1 = on|off
    if [[ "$1" == "on" ]]; then
        mount -o remount,rw,user_subvol_rm_allowed "$DATADIR"
        return
    fi
    if ! mount_has_rm_allowed; then
        return 0
    fi
    local unit
    unit=$(mount_unit)
    if systemctl cat "$unit" >/dev/null 2>&1; then
        systemctl restart "$unit"
    else
        local src
        src=$(findmnt -n -o SOURCE "$DATADIR")
        umount "$DATADIR"
        mount -t btrfs -o noatime "$src" "$DATADIR"
    fi
}

# Networking for the outer container. On a devsrv host, the platform bridge
# vz-devsrv-plat (DHCP+NAT, already allowed by the host firewall) is the exact
# topology the tiers use. Elsewhere, create a self-owned bridge with a runtime
# networkd file providing DHCP+NAT; note that a restrictive host firewall may
# need an inbound allow rule for it (UFW default-deny drops DHCP replies).
BRIDGE="vz-devsrv-plat"
FALLBACK_BRIDGE="vznested"
setup_network() {
    if [[ -f /etc/systemd/network/80-container-vz.network ]]; then
        if ! ip link show "$BRIDGE" >/dev/null 2>&1; then
            ip link add "$BRIDGE" type bridge
            ip link set "$BRIDGE" up
        fi
        return
    fi
    BRIDGE="$FALLBACK_BRIDGE"
    cat > "/run/systemd/network/60-sdme-${PREFIX}.network" <<'EOF'
[Match]
Kind=bridge
Name=vznested

[Network]
Address=10.238.0.1/24
LinkLocalAddressing=no
DHCPServer=yes
IPMasquerade=both

[DHCPServer]
PoolOffset=10
PoolSize=100
EmitDNS=yes
DNS=8.8.8.8
EOF
    ip link show "$BRIDGE" >/dev/null 2>&1 || ip link add "$BRIDGE" type bridge
    ip link set "$BRIDGE" up
    networkctl reload
    sleep 2
}

teardown_network() {
    if [[ "$BRIDGE" == "$FALLBACK_BRIDGE" ]]; then
        rm -f "/run/systemd/network/60-sdme-${PREFIX}.network"
        ip link del "$BRIDGE" 2>/dev/null || true
        networkctl reload
    fi
}

cleanup() {
    # Nested resources first (best-effort; outer may be unreachable).
    timeout 120 "$SDME" exec "$OUTER" -- /usr/local/bin/sdme rm "$INNER1" "$INNER2" &>/dev/null || true
    timeout 120 "$SDME" exec "$OUTER" -- /usr/local/bin/sdme kube delete "$KUBE_POD" &>/dev/null || true
    timeout 60 "$SDME" exec "$OUTER" -- /usr/local/bin/sdme fs rm "$NESTED_FS" &>/dev/null || true
    cleanup_prefix "${PREFIX}-"
    cleanup_prefix "vfy-kube-"
    teardown_network
    set_rm_allowed off 2>/dev/null || true
}
trap cleanup EXIT INT TERM

ensure_root
ensure_sdme
require_gate smoke

if [[ "$(stat -f -c %T "$DATADIR")" != "btrfs" ]]; then
    echo "SKIP: sdme datadir is not btrfs; the outer container needs a btrfs rootfs"
    print_summary
    exit 0
fi

# Phase A of the deletion test needs user_subvol_rm_allowed OFF. The option is
# sticky across remounts, so clear it now (fresh mount via set_rm_allowed),
# before this script has created any containers that would keep the mount busy.
if ! set_rm_allowed off || mount_has_rm_allowed; then
    echo "error: could not clear user_subvol_rm_allowed on $DATADIR (mount busy?)" >&2
    exit 1
fi

cleanup_prefix "${PREFIX}-"

if ! ensure_base_fs "$BASEFS" "${DISTRO_IMAGES[ubuntu]}"; then
    echo "error: failed to import base rootfs" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Setup: seed systemd-container into the outer base rootfs (host chroot), so
# the nested sdme can spawn systemd-nspawn containers. The resolv.conf swap
# follows the same pattern as ensure_python3_in_rootfs.
# ---------------------------------------------------------------------------
echo "=== Setup: seed systemd-container into outer base rootfs ==="
root_fs="$DATADIR/fs/$BASEFS"
tmp_resolv=$(mktemp)
had_resolv=0
if [[ -e "$root_fs/etc/resolv.conf" || -L "$root_fs/etc/resolv.conf" ]]; then
    cp -a "$root_fs/etc/resolv.conf" "$tmp_resolv"
    had_resolv=1
fi
rm -f "$root_fs/etc/resolv.conf"
cp -L /etc/resolv.conf "$root_fs/etc/resolv.conf"
seed_ok=0
if DEBIAN_FRONTEND=noninteractive chroot "$root_fs" apt-get -o APT::Sandbox::User="" update >/dev/null 2>&1 && \
   DEBIAN_FRONTEND=noninteractive chroot "$root_fs" apt-get -o APT::Sandbox::User="" install -y systemd-container btrfs-progs >/dev/null 2>&1; then
    seed_ok=1
fi
rm -f "$root_fs/etc/resolv.conf"
if [[ $had_resolv -eq 1 ]]; then
    cp -a "$tmp_resolv" "$root_fs/etc/resolv.conf"
fi
rm -f "$tmp_resolv"
if [[ $seed_ok -ne 1 ]]; then
    echo "error: failed to seed systemd-container into $BASEFS" >&2
    exit 1
fi
ok "systemd-container seeded into outer base rootfs"

# ---------------------------------------------------------------------------
# Test 1: outer topology (btrfs + userns + nested range) boots.
# ---------------------------------------------------------------------------
echo "=== Test 1: outer container topology ==="

setup_network

if ! output=$(timeout "$BOOT_TIMEOUT" "$SDME" create -r "$BASEFS" \
    --storage btrfs --userns --userns-nested 32 --network-bridge "$BRIDGE" \
    --started -t "$BOOT_TIMEOUT" "$OUTER" "${VFLAG[@]}" 2>&1); then
    fail "outer create failed: $output"
    print_summary
    exit 1
fi
ok "outer container created and started (btrfs, userns, userns-nested=32)"

map_len=$(timeout "$EXEC_TIMEOUT" "$SDME" exec "$OUTER" -- \
    /bin/sh -c "awk '\$1 == 0 {print \$3}' /proc/self/uid_map" 2>/dev/null || true)
if [[ "$map_len" == "2162688" ]]; then
    ok "outer uid_map length is (1+32)*65536 = 2162688"
else
    fail "outer uid_map length mismatch (expected 2162688, got '$map_len')"
fi

# Install the freshly built sdme inside the outer container. `sdme cp` refuses
# writes into a running btrfs+userns container, so pipe through exec tee
# (stdout discarded; it would contain the binary itself).
if ! output=$("$SDME" exec "$OUTER" -- /usr/bin/tee /usr/local/bin/sdme < /usr/local/bin/sdme 2>&1 >/dev/null); then
    fail "installing sdme into outer failed: $output"
    print_summary
    exit 1
fi
if ! output=$("$SDME" exec "$OUTER" -- chmod +x /usr/local/bin/sdme 2>&1); then
    fail "chmod sdme in outer failed: $output"
    print_summary
    exit 1
fi
if nsdme --version >/dev/null 2>&1; then
    ok "nested sdme runs inside the outer container"
else
    fail "nested sdme does not run"
    print_summary
    exit 1
fi

# ---------------------------------------------------------------------------
# Test 2: nested fs import --install-packages=yes (chroot /dev staging).
# ---------------------------------------------------------------------------
echo "=== Test 2: nested fs import with package installation ==="

import_ok=0
if output=$(nsdme fs import "$NESTED_FS" "${DISTRO_IMAGES[ubuntu]}" --install-packages=yes -f "${VFLAG[@]}" 2>&1); then
    import_ok=1
fi
if [[ $import_ok -eq 1 ]]; then
    ok "nested fs import --install-packages=yes succeeded"
else
    echo "$output" | tail -5
    fail "nested fs import failed (chroot /dev staging broken or no network)"
    print_summary
    exit 1
fi

# ---------------------------------------------------------------------------
# Test 3: nested container creates fail fast with the named cause.
#
# Nested (user-namespaced) nspawn boots are blocked by kernel rules beyond
# sdme's control: mknod of device nodes requires CAP_MKNOD in the initial
# user namespace, so the inner nspawn cannot set up /dev, and proc/sysfs
# mounts have matching ownership restrictions. The create-time preflight
# probes mknod and fails in seconds instead of surfacing as a boot timeout.
# ---------------------------------------------------------------------------
echo "=== Test 3: nested create fails fast with named cause ==="

start_s=$SECONDS
rc=0
output=$(nsdme create -r "$NESTED_FS" --storage auto --userns --started -t "$BOOT_TIMEOUT" "$INNER1" 2>&1) || rc=$?
elapsed=$((SECONDS - start_s))
if [[ $rc -ne 0 ]] && echo "$output" | grep -q "mknod" && echo "$output" | grep -q "initial user namespace"; then
    ok "nested create fails fast naming the mknod/userns restriction (${elapsed}s)"
else
    fail "expected mknod preflight failure (rc=$rc): $(echo "$output" | tail -3)"
fi
if [[ ! -e "$(nested_datadir)/state/$INNER1" ]]; then
    ok "failed create left no state behind"
else
    fail "failed create left state behind"
fi

rc=0
output=$(nsdme create -r "$NESTED_FS" --storage auto "$INNER2" 2>&1) || rc=$?
if [[ $rc -ne 0 ]] && echo "$output" | grep -q "mknod"; then
    ok "nested create without --userns also fails fast with mknod preflight"
else
    fail "expected mknod preflight failure without --userns (rc=$rc): $(echo "$output" | tail -3)"
fi

# ---------------------------------------------------------------------------
# Test 4: explicit nested --storage btrfs is a hard error, fast.
# ---------------------------------------------------------------------------
echo "=== Test 4: explicit nested --storage btrfs fails fast ==="

start_s=$SECONDS
rc=0
output=$(nsdme create -r "$NESTED_FS" --storage btrfs "$BADCTR" 2>&1) || rc=$?
elapsed=$((SECONDS - start_s))
if [[ $rc -ne 0 ]] && echo "$output" | grep -q "cannot boot inside a user-namespaced"; then
    ok "explicit --storage btrfs fails with the documented error"
else
    fail "expected hard error for nested --storage btrfs (rc=$rc): $(echo "$output" | tail -3)"
fi
if [[ $elapsed -lt 60 ]] && [[ ! -e "$(nested_datadir)/state/$BADCTR" ]]; then
    ok "failure was fast ($elapsed s) and left no state behind"
else
    fail "failure was slow ($elapsed s) or left state behind"
fi

# ---------------------------------------------------------------------------
# Test 5: nested subvolume deletion, without and with user_subvol_rm_allowed.
# Legacy subvolumes are created by the nested context itself so they get the
# same recorded owner a nested sdme would produce (through the idmapped
# rootfs: the outer's root); state file and bookkeeping dir come from the host.
# ---------------------------------------------------------------------------
echo "=== Test 5: nested subvolume deletion paths ==="

inject_legacy() {
    local name="$1"
    local ndd; ndd=$(nested_datadir)
    mkdir -p "$ndd/btrfs/containers" "$ndd/containers/$name" "$ndd/state"
    "$SDME" exec "$OUTER" -- \
        btrfs subvolume create "/var/lib/sdme/btrfs/containers/$name" >/dev/null
    printf 'NAME=%s\nROOTFS=%s\nSTORAGE=btrfs\n' "$name" "$NESTED_FS" > "$ndd/state/$name"
}

# Phase A: without the mount option, destroy EPERMs and parks in .trash.
set_rm_allowed off
if mount_has_rm_allowed; then
    fail "test setup: could not clear user_subvol_rm_allowed"
fi

inject_legacy "$LEGACY_A"
rc=0
output=$(nsdme rm "$LEGACY_A" 2>&1) || rc=$?
if [[ $rc -eq 0 ]] && echo "$output" | grep -q "user_subvol_rm_allowed"; then
    ok "rm without the option warns about user_subvol_rm_allowed"
else
    fail "expected user_subvol_rm_allowed warning (rc=$rc): $(echo "$output" | tail -3)"
fi
if [[ ! -e "$(nested_datadir)/btrfs/containers/$LEGACY_A" ]] && \
   sudo btrfs subvolume list "$DATADIR" | grep -qF ".trash/${LEGACY_A}."; then
    ok "denied destroy parked the subvolume in .trash"
else
    fail "subvolume was not parked in .trash as expected"
fi

# Phase B: with the option, destroy succeeds directly.
set_rm_allowed on
if ! mount_has_rm_allowed; then
    fail "test setup: could not set user_subvol_rm_allowed"
fi

inject_legacy "$LEGACY_B"
rc=0
output=$(nsdme rm "$LEGACY_B" 2>&1) || rc=$?
if [[ $rc -eq 0 ]] && \
   ! sudo btrfs subvolume list "$DATADIR" | grep -qF "containers/${LEGACY_B}" && \
   ! sudo btrfs subvolume list "$DATADIR" | grep -qF ".trash/${LEGACY_B}."; then
    ok "destroy with user_subvol_rm_allowed removed the subvolume directly"
else
    fail "destroy with the option failed (rc=$rc): $(echo "$output" | tail -3)"
fi

# Nested prune destroys the phase A trash entry. The base rootfs is excluded:
# with no containers yet it is an "unused filesystem" prune candidate too.
rc=0
output=$(nsdme prune --force --except="$NESTED_FS" 2>&1) || rc=$?
if ! sudo btrfs subvolume list "$DATADIR" | grep -qF ".trash/${LEGACY_A}."; then
    ok "nested sdme prune destroyed the parked trash entry"
else
    fail "trash entry survived nested prune (rc=$rc): $(echo "$output" | tail -3)"
fi

# ---------------------------------------------------------------------------
# Test 6: nested kube create fails fast with the same named cause.
# ---------------------------------------------------------------------------
echo "=== Test 6: nested kube create fails fast ==="

if ! output=$("$SDME" exec "$OUTER" -- /usr/bin/tee /root/redis-pod.yaml < "$(dirname "$0")/../kube/redis-pod.yaml" 2>&1 >/dev/null); then
    fail "installing redis-pod.yaml into outer failed: $output"
fi

start_s=$SECONDS
rc=0
output=$(nsdme kube create --base-fs "$NESTED_FS" -f /root/redis-pod.yaml --userns 2>&1) || rc=$?
elapsed=$((SECONDS - start_s))
if [[ $rc -ne 0 ]] && echo "$output" | grep -q "mknod"; then
    ok "nested kube create fails fast with mknod preflight (${elapsed}s)"
else
    fail "expected mknod preflight failure for kube create (rc=$rc): $(echo "$output" | tail -3)"
fi

# ---------------------------------------------------------------------------
# Test 7: cleanup leaves zero stale subvolumes (verified from the host).
# ---------------------------------------------------------------------------
echo "=== Test 7: zero stale subvolumes after cleanup ==="

nsdme rm "$INNER1" "$INNER2" >/dev/null 2>&1 || true
nsdme fs rm "$NESTED_FS" >/dev/null 2>&1 || true
cleanup_prefix "${PREFIX}-"
cleanup_prefix "vfy-kube-"
stale=$(subvol_count_matching "$PREFIX")
if [[ "$stale" == "0" ]]; then
    ok "no stale subvolumes remain"
else
    fail "$stale stale subvolume(s) remain:"
    sudo btrfs subvolume list "$DATADIR" | grep "$PREFIX" || true
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print_summary
