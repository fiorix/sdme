#!/usr/bin/env bash
set -euo pipefail

# build-nixos-rootfs.sh - Build a NixOS rootfs externally and import it via sdme.
#
# Imports docker.io/nixos/nix as a temporary rootfs, runs nix-build in a chroot
# to produce a NixOS system closure, reconstructs a clean rootfs from the closure,
# and imports the result via sdme.
#
# Requires: root, sdme in PATH, internet access (pulls nixos/nix image and nixpkgs).
#
# Usage: build-nixos-rootfs.sh <rootfs-name> [--nix-file <path>] [--channel <channel>]

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NIX_FILE="${SCRIPT_DIR}/../nix/sdme-nixos.nix"
CHANNEL="nixos-unstable"
VERBOSE=""

usage() {
    cat <<EOF
Usage: $(basename "$0") <rootfs-name> [OPTIONS]

Build a NixOS rootfs from docker.io/nixos/nix and import it via sdme.

Options:
  --nix-file FILE   Path to .nix expression (default: test/nix/sdme-nixos.nix)
  --channel CHAN     Nixpkgs channel (default: nixos-unstable)
  -v, --verbose     Verbose output
  --help            Show help
EOF
}

if [[ $# -lt 1 ]]; then
    usage >&2
    exit 1
fi

FS_NAME="$1"
shift

while [[ $# -gt 0 ]]; do
    case "$1" in
        --nix-file)
            shift
            NIX_FILE="$1"
            ;;
        --channel)
            shift
            CHANNEL="$1"
            ;;
        -v|--verbose)
            VERBOSE="-v"
            ;;
        --help)
            usage
            exit 0
            ;;
        *)
            echo "error: unknown option: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
    shift
done

if [[ "$(id -u)" -ne 0 ]]; then
    echo "error: must be run as root" >&2
    exit 1
fi

if ! command -v sdme >/dev/null 2>&1; then
    echo "error: sdme not found in PATH" >&2
    exit 1
fi

if [[ ! -f "$NIX_FILE" ]]; then
    echo "error: nix file not found: $NIX_FILE" >&2
    exit 1
fi

log() { echo "==> $*"; }

DATADIR="/var/lib/sdme"
TMP_FS="_build-nix-tmp-$$"

cleanup() {
    log "Cleaning up temporary rootfs..."
    sdme fs rm "$TMP_FS" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Step 1: Import docker.io/nixos/nix as a temporary rootfs.
log "Importing docker.io/nixos/nix as temporary rootfs '$TMP_FS'"
sdme fs import "$TMP_FS" docker.io/nixos/nix $VERBOSE --install-packages=no -f

ROOTFS="$DATADIR/fs/$TMP_FS"

# Step 2: Write the nix expression into the temporary rootfs.
log "Writing nix expression to $ROOTFS/tmp/sdme-nixos.nix"
mkdir -p "$ROOTFS/tmp"
cp "$NIX_FILE" "$ROOTFS/tmp/sdme-nixos.nix"

# Step 3: Set up chroot environment.
log "Setting up chroot environment"
mount -t proc proc "$ROOTFS/proc"
mount -t sysfs sysfs "$ROOTFS/sys"
mount --bind /dev "$ROOTFS/dev"
mkdir -p "$ROOTFS/etc"
cp /etc/resolv.conf "$ROOTFS/etc/resolv.conf" 2>/dev/null || true

chroot_cleanup() {
    umount "$ROOTFS/proc" 2>/dev/null || true
    umount "$ROOTFS/sys" 2>/dev/null || true
    umount "$ROOTFS/dev" 2>/dev/null || true
    cleanup
}
trap chroot_cleanup EXIT INT TERM

# Step 4: Run nix-build inside the chroot.
log "Running nix-build (channel: $CHANNEL)"
chroot "$ROOTFS" /bin/sh -c "
    export PATH=/root/.nix-profile/bin:/nix/var/nix/profiles/default/bin:\$PATH
    export NIX_REMOTE=
    export NIX_PATH='nixpkgs=https://github.com/NixOS/nixpkgs/archive/refs/heads/${CHANNEL}.tar.gz'
    TOPLEVEL=\$(nix-build /tmp/sdme-nixos.nix --no-out-link --option sandbox false --option filter-syscalls false)
    mkdir -p /sbin
    ln -sf \"\$TOPLEVEL/init\" /sbin/init
    nix-store -qR \"\$TOPLEVEL\" > /tmp/sdme-nix-closure.txt
"

# Step 5: Tear down chroot mounts before rebuilding.
umount "$ROOTFS/proc" 2>/dev/null || true
umount "$ROOTFS/sys" 2>/dev/null || true
umount "$ROOTFS/dev" 2>/dev/null || true

# Reset trap to skip chroot unmounts.
trap cleanup EXIT INT TERM

# Step 6: Read closure and rebuild clean rootfs.
log "Rebuilding clean NixOS rootfs from closure"

CLOSURE_FILE="$ROOTFS/tmp/sdme-nix-closure.txt"
if [[ ! -f "$CLOSURE_FILE" ]]; then
    echo "error: closure list not found at $CLOSURE_FILE" >&2
    exit 1
fi

INIT_TARGET=$(readlink "$ROOTFS/sbin/init")
if [[ -z "$INIT_TARGET" ]]; then
    echo "error: /sbin/init symlink not found" >&2
    exit 1
fi

CLEAN_DIR="$DATADIR/fs/.${FS_NAME}.nixbuild-$$"
rm -rf "$CLEAN_DIR"

# Create skeleton directories.
for d in nix/store bin sbin etc root run tmp var/log var/lib proc sys dev; do
    mkdir -p "$CLEAN_DIR/$d"
done

# Move closure store paths from temporary rootfs to clean rootfs.
while IFS= read -r store_path; do
    [[ -z "$store_path" ]] && continue
    rel="${store_path#/}"
    src="$ROOTFS/$rel"
    dst="$CLEAN_DIR/$rel"
    if [[ -e "$src" ]]; then
        mv "$src" "$dst"
    elif [[ -n "$VERBOSE" ]]; then
        echo "  warning: store path not found: $src"
    fi
done < "$CLOSURE_FILE"

# Create /sbin/init symlink.
ln -sf "$INIT_TARGET" "$CLEAN_DIR/sbin/init"

# Set /tmp permissions.
chmod 1777 "$CLEAN_DIR/tmp"

# Write os-release so sdme detects the rootfs as NixOS.
cat > "$CLEAN_DIR/etc/os-release" <<'OSEOF'
NAME="NixOS"
ID=nixos
PRETTY_NAME="NixOS (sdme)"
OSEOF

# Step 7: Import the clean rootfs via sdme.
log "Importing clean NixOS rootfs as '$FS_NAME'"
sdme fs import "$FS_NAME" "$CLEAN_DIR" $VERBOSE -f

# Clean up the temporary build directory.
rm -rf "$CLEAN_DIR"

log "Done. NixOS rootfs '$FS_NAME' is ready."
