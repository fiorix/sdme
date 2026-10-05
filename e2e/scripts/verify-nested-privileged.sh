#!/usr/bin/env bash
set -euo pipefail

# verify-nested-privileged.sh - end-to-end test for nested workloads inside a
# privileged sdme container (created without --userns, --hardened, or
# --strict), the topology docs/nesting.md lists as supported.
#
# Tests:
#   1. Inner sdme containers in a privileged outer container on btrfs: an
#      overlay clone of the outer root, with and without --userns; then, from
#      a rootfs imported by the nested sdme, overlay, btrfs, and btrfs with
#      --userns.
#   2. Removing the outer container from the host destroys the subvolumes the
#      nested sdme created inside it.
#   3. In a privileged outer container on overlay, an inner container does not
#      start: its root would be an overlay on top of an overlay.
#   4. Docker with the btrfs storage driver in a --network-veth container runs
#      a container on its default bridge, with no --capability flag, and
#      `sdme rm` removes the subvolumes Docker created.
#
# No test needs network access from inside a container, so nothing here
# depends on the host handing out a DHCP lease: packages are seeded into the
# base rootfs from the host, the nested import reads the base rootfs through
# a bind mount, and the Docker image is imported from files already in the
# container.
#
# Skips entirely when btrfs-progs is not installed.

source "$(dirname "$0")/lib.sh"

# Re-declare VFLAG as an array (lib.sh sets it as a string).
VFLAG=()
if [[ -n "$VERBOSE" ]]; then
    VFLAG=("-v")
fi

PREFIX="vfy-npriv"
BASEFS="${PREFIX}-base"
OUTER="${PREFIX}-outer"
OVL_OUTER="${PREFIX}-ovl"
DOCKER_CT="${PREFIX}-docker"
NESTED_FS="inner-ubuntu"
BOOT_TIMEOUT=$(scale_timeout 180)
IMPORT_TIMEOUT=$(scale_timeout 600)
TEST_TIMEOUT=$(scale_timeout 60)

# Run the nested sdme inside a container.
#   nsdme <container> <args...>
nsdme() {
    local ct="$1"
    shift
    timeout "$IMPORT_TIMEOUT" "$SDME" exec "$ct" -- /usr/local/bin/sdme "$@"
}

# Directory holding the btrfs container subvolumes (Mode A or Mode B).
pool_subroot() {
    if [[ "$(stat -f -c %T "$DATADIR")" == "btrfs" ]]; then
        echo "$DATADIR/btrfs"
    else
        echo "$DATADIR/pool"
    fi
}

# Count the subvolumes whose path contains a string, as seen from the host.
subvol_count_matching() {
    btrfs subvolume list "$(pool_subroot)" 2>/dev/null | grep -c "$1" || true
}

# Whether a nested container is listed as running.
#   inner_running <outer> <inner>
inner_running() {
    nsdme "$1" ps 2>/dev/null | awk -v n="$2" '$1 == n && $2 == "running" {f=1} END {exit !f}'
}

# Create and boot a nested container, and record the result.
#   inner_boots <description> <inner> <create args...>
inner_boots() {
    local desc="$1" inner="$2" output
    shift 2
    if output=$(nsdme "$OUTER" create --name "$inner" "$@" --started -t "$BOOT_TIMEOUT" 2>&1) \
        && inner_running "$OUTER" "$inner"; then
        ok "$desc"
    else
        fail "$desc: $(tail -3 <<<"$output")"
    fi
}

# Whether root inside a nested container maps to a non-root ID of the outer.
inner_is_userns() {
    local map
    map=$(nsdme "$OUTER" exec "$1" -- /bin/cat /proc/self/uid_map 2>/dev/null || true)
    awk '$1 == 0 && $2 != 0 {f=1} END {exit !f}' <<<"$map"
}

# Copy the sdme binary under test into a running container.
install_sdme() {
    "$SDME" cp "$SDME_BIN" "$1:/usr/local/bin/sdme" "${VFLAG[@]}" >/dev/null 2>&1 \
        && nsdme "$1" --version >/dev/null 2>&1
}

cleanup() {
    cleanup_prefix "${PREFIX}-"
}
trap cleanup EXIT INT TERM

ensure_root
ensure_sdme
require_gate smoke
require_gate interrupt

if ! command -v btrfs >/dev/null 2>&1 || ! command -v mkfs.btrfs >/dev/null 2>&1; then
    skipped "btrfs-progs not installed; skipping privileged nesting tests"
    print_summary
    exit 0
fi

DATADIR=$("$SDME" config get | awk -F' = ' '/^datadir/{print $2}')
# The binary under test, which is also the one installed in the containers.
SDME_BIN=$(command -v "$SDME")

# Clean up leftovers first so the base rootfs imported below is not removed
# by cleanup_prefix.
cleanup_prefix "${PREFIX}-"

if ! ensure_base_fs "$BASEFS" "${DISTRO_IMAGES[ubuntu]}"; then
    echo "error: failed to import base rootfs" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Setup: seed the packages the nested workloads need into the base rootfs
# (host chroot, same resolv.conf swap as ensure_python3_in_rootfs). Docker is
# left disabled so only the container of test 4 starts it: in a host-network
# container it has no network namespace of its own to configure.
# ---------------------------------------------------------------------------
echo "=== Setup: seed nested runtimes into the base rootfs ==="
root_fs="$DATADIR/fs/$BASEFS"
tmp_resolv=$(mktemp)
had_resolv=0
if [[ -e "$root_fs/etc/resolv.conf" || -L "$root_fs/etc/resolv.conf" ]]; then
    cp -a "$root_fs/etc/resolv.conf" "$tmp_resolv"
    had_resolv=1
fi
rm -f "$root_fs/etc/resolv.conf"
cp -L "$(host_resolv_conf)" "$root_fs/etc/resolv.conf"
seed_ok=0
if DEBIAN_FRONTEND=noninteractive chroot "$root_fs" apt-get -o APT::Sandbox::User="" update >/dev/null 2>&1 && \
   DEBIAN_FRONTEND=noninteractive chroot "$root_fs" apt-get -o APT::Sandbox::User="" install -y \
       systemd-container btrfs-progs docker.io busybox-static >/dev/null 2>&1 && \
   chroot "$root_fs" systemctl disable docker.service docker.socket >/dev/null 2>&1; then
    seed_ok=1
fi
mkdir -p "$root_fs/etc/docker"
echo '{ "storage-driver": "btrfs" }' > "$root_fs/etc/docker/daemon.json"
rm -f "$root_fs/etc/resolv.conf"
if [[ $had_resolv -eq 1 ]]; then
    cp -a "$tmp_resolv" "$root_fs/etc/resolv.conf"
fi
rm -f "$tmp_resolv"
if [[ $seed_ok -ne 1 ]]; then
    echo "error: failed to seed nested runtimes into $BASEFS" >&2
    exit 1
fi
ok "nested runtimes seeded into the base rootfs"

# ---------------------------------------------------------------------------
# Test 1: inner sdme containers in a privileged outer container on btrfs.
# ---------------------------------------------------------------------------
echo "=== Test 1: inner sdme containers, privileged btrfs outer ==="

# The base rootfs is bound read-only into the outer container so the nested
# sdme can import it as a directory, with no registry pull.
if ! output=$(timeout "$BOOT_TIMEOUT" "$SDME" create --name "$OUTER" -r "$BASEFS" \
    --storage btrfs -b "$root_fs:/mnt/base:ro" \
    --started -t "$BOOT_TIMEOUT" "${VFLAG[@]}" 2>&1); then
    fail "outer container create failed: $(tail -3 <<<"$output")"
    print_summary
    exit 1
fi
if install_sdme "$OUTER"; then
    ok "privileged btrfs outer container runs the nested sdme"
else
    fail "nested sdme does not run in the outer container"
    print_summary
    exit 1
fi

inner_boots "inner container boots on an overlay clone of the outer root" in-clone
inner_boots "inner container boots on an overlay clone with --userns" in-clone-userns --userns
if inner_is_userns in-clone-userns; then
    ok "inner --userns container has a mapped root"
else
    fail "inner --userns container root is not mapped"
fi
nsdme "$OUTER" rm -f in-clone in-clone-userns >/dev/null 2>&1 || true

if output=$(nsdme "$OUTER" fs import /mnt/base --name "$NESTED_FS" 2>&1); then
    ok "nested sdme imports a rootfs"
else
    fail "nested fs import failed: $(tail -3 <<<"$output")"
fi

inner_boots "inner container boots on overlay from the imported rootfs" in-ovl \
    -r "$NESTED_FS" --storage overlay
inner_boots "inner container boots on btrfs from the imported rootfs" in-btrfs \
    -r "$NESTED_FS" --storage btrfs
inner_boots "inner container boots on btrfs with --userns" in-btrfs-userns \
    -r "$NESTED_FS" --storage btrfs --userns
if inner_is_userns in-btrfs-userns; then
    ok "inner btrfs --userns container has a mapped root"
else
    fail "inner btrfs --userns container root is not mapped"
fi

# ---------------------------------------------------------------------------
# Test 2: removing the outer container destroys the nested subvolumes.
# ---------------------------------------------------------------------------
# The inner btrfs containers are left in place on purpose: the nested sdme's
# base and container subvolumes live inside the outer container's subvolume.
echo "=== Test 2: outer removal destroys nested subvolumes ==="

nested_subvols=$(subvol_count_matching "containers/$OUTER/var/lib/sdme/")
if [[ "$nested_subvols" -gt 0 ]]; then
    ok "nested sdme created subvolumes inside the outer container ($nested_subvols)"
else
    fail "no nested subvolumes found inside the outer container"
fi

if output=$(timeout "$BOOT_TIMEOUT" "$SDME" rm -f "$OUTER" "${VFLAG[@]}" 2>&1) \
    && [[ "$(subvol_count_matching "containers/$OUTER")" == "0" ]] \
    && [[ ! -e "$(pool_subroot)/containers/$OUTER" ]]; then
    ok "removing the outer container left no subvolume behind"
else
    fail "outer removal left subvolumes behind: $(subvol_count_matching "containers/$OUTER") remain; $(tail -3 <<<"$output")"
fi

# ---------------------------------------------------------------------------
# Test 3: a privileged outer container on overlay cannot start an inner one.
# ---------------------------------------------------------------------------
echo "=== Test 3: inner container on an overlay outer does not start ==="

if ! output=$(timeout "$BOOT_TIMEOUT" "$SDME" create --name "$OVL_OUTER" -r "$BASEFS" \
    --storage overlay --started -t "$BOOT_TIMEOUT" "${VFLAG[@]}" 2>&1) \
    || ! install_sdme "$OVL_OUTER"; then
    fail "overlay outer container setup failed: $(tail -3 <<<"$output")"
else
    rc=0
    start=$(date +%s)
    output=$(nsdme "$OVL_OUTER" create --name in-ovl --started -t "$TEST_TIMEOUT" 2>&1) || rc=$?
    elapsed=$(( $(date +%s) - start ))
    # The unit fails in ExecStartPre: the journal excerpt sdme prints names
    # the overlay mount on the inner container's merged directory.
    if [[ $rc -ne 0 ]] && ! inner_running "$OVL_OUTER" in-ovl \
        && grep -Eq "mount: .*containers/in-ovl/merged" <<<"$output"; then
        ok "inner container on an overlay outer fails at the overlay mount (${elapsed}s)"
    else
        fail "expected an overlay mount failure (rc=$rc): $(tail -5 <<<"$output")"
    fi
fi
cleanup_container "$OVL_OUTER" >/dev/null 2>&1 || true

# ---------------------------------------------------------------------------
# Test 4: Docker with the btrfs storage driver.
# ---------------------------------------------------------------------------
# The flags are the ones docs/nesting.md and the Docker tutorial give.
# --network-veth is what grants CAP_NET_ADMIN, over the container's own
# network namespace; no --capability flag is passed.
echo "=== Test 4: Docker on the btrfs storage driver ==="

dexec() {
    timeout "$IMPORT_TIMEOUT" "$SDME" exec "$DOCKER_CT" -- /bin/sh -c "$1"
}

if ! output=$(timeout "$BOOT_TIMEOUT" "$SDME" create --name "$DOCKER_CT" -r "$BASEFS" \
    --storage btrfs --network-veth \
    --system-call-filter bpf --system-call-filter keyctl --system-call-filter add_key \
    --started -t "$BOOT_TIMEOUT" "${VFLAG[@]}" 2>&1); then
    fail "Docker container create failed: $(tail -3 <<<"$output")"
    print_summary
    exit 1
fi

capbnd=$(dexec "grep '^CapBnd:' /proc/1/status" 2>/dev/null | awk '{print $2}' | tr -d '[:space:]')
if [[ -n "$capbnd" ]] && (( (16#${capbnd} & (1 << 12)) != 0 )); then
    ok "--network-veth container has CAP_NET_ADMIN without --capability"
else
    fail "CAP_NET_ADMIN not in bounding set (CapBnd='$capbnd')"
fi

if output=$(dexec "systemctl start docker && docker info" 2>&1) \
    && grep -q "Storage Driver: btrfs" <<<"$output"; then
    ok "Docker runs on the btrfs storage driver"
else
    fail "Docker did not come up on btrfs: $(tail -5 <<<"$output")"
fi

# A one-binary image built from the container's own static busybox.
if output=$(dexec "mkdir -p /tmp/img/bin && cp /usr/bin/busybox /tmp/img/bin/busybox \
        && tar -C /tmp/img -c . | docker import - ${PREFIX}:local \
        && docker run --rm ${PREFIX}:local /bin/busybox echo nested-docker-ok" 2>&1) \
    && grep -q "nested-docker-ok" <<<"$output"; then
    ok "docker run on the default bridge from a locally imported image"
else
    fail "docker run failed: $(tail -5 <<<"$output")"
fi

docker_subvols=$(subvol_count_matching "containers/$DOCKER_CT/var/lib/docker/btrfs/subvolumes/")
if [[ "$docker_subvols" -gt 0 ]]; then
    ok "Docker's btrfs driver created subvolumes under the container ($docker_subvols)"
else
    fail "Docker created no subvolumes under the container"
fi

if output=$(timeout "$BOOT_TIMEOUT" "$SDME" rm -f "$DOCKER_CT" "${VFLAG[@]}" 2>&1) \
    && [[ "$(subvol_count_matching "containers/$DOCKER_CT")" == "0" ]] \
    && [[ ! -e "$(pool_subroot)/containers/$DOCKER_CT" ]]; then
    ok "sdme rm removed the container and Docker's subvolumes"
else
    fail "sdme rm left subvolumes behind: $(subvol_count_matching "containers/$DOCKER_CT") remain; $(tail -3 <<<"$output")"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print_summary
