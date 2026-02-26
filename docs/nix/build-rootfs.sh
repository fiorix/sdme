#!/usr/bin/env bash
#
# Build a NixOS rootfs suitable for sdme containers.
#
# Usage: sudo ./build-rootfs.sh [output-dir]
#
# Requires: nix (with daemon running)
#
# The script builds the NixOS system closure from container.nix, then
# assembles a rootfs directory that systemd-nspawn can boot. The result
# can be imported directly with: sdme fs import nixos <output-dir>
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NIX_EXPR="$SCRIPT_DIR/container.nix"
OUTPUT="${1:-$SCRIPT_DIR/nixos-rootfs}"

if [[ $EUID -ne 0 ]]; then
    echo "error: must run as root" >&2
    exit 1
fi

# Source nix if not already in PATH.
if ! command -v nix-build &>/dev/null; then
    for f in /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh \
             /etc/profile.d/nix.sh; do
        if [[ -f "$f" ]]; then
            # shellcheck source=/dev/null
            . "$f"
            break
        fi
    done
fi

if ! command -v nix-build &>/dev/null; then
    echo "error: nix not found; install it first: https://nixos.org/download" >&2
    exit 1
fi

echo "Building NixOS system closure..."
TOPLEVEL="$(nix-build "$NIX_EXPR" --no-out-link)"
echo "  toplevel: $TOPLEVEL"

echo "Copying nix store closure into rootfs..."
rm -rf "$OUTPUT"
mkdir -p "$OUTPUT"/{nix/store,bin,sbin,etc,root,run,tmp,var/log,var/lib,proc,sys,dev}

NPATHS=$(nix-store -qR "$TOPLEVEL" | wc -l)
echo "  $NPATHS store paths to copy"

nix-store -qR "$TOPLEVEL" | while read -r p; do
    cp -a "$p" "$OUTPUT/nix/store/"
done

# /sbin/init: systemd-nspawn looks here for the init binary.
ln -sf "$TOPLEVEL/init" "$OUTPUT/sbin/init"

# /etc/os-release for distro detection.
cat > "$OUTPUT/etc/os-release" <<'EOF'
NAME="NixOS"
ID=nixos
VERSION="26.05 (dev)"
VERSION_CODENAME=dev
PRETTY_NAME="NixOS 26.05 (dev)"
HOME_URL="https://nixos.org"
EOF

chmod 1777 "$OUTPUT/tmp"

echo "Rootfs ready at $OUTPUT"
echo ""
echo "Import with:"
echo "  sdme fs import nixos $OUTPUT"
