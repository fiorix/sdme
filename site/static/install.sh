#!/bin/sh
set -eu

REPO="fiorix/sdme"
INSTALL_DIR="/usr/local/bin"

die() {
    echo "error: $1" >&2
    exit 1
}

OS=$(uname -s)
[ "$OS" = "Linux" ] || die "unsupported OS: $OS (only Linux is supported)"

ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  BINARY="sdme-x86_64-linux" ;;
    aarch64) BINARY="sdme-aarch64-linux" ;;
    *)       die "unsupported architecture: $ARCH (only x86_64 and aarch64 are supported)" ;;
esac

LATEST=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed 's/.*"tag_name": *"//;s/".*//')
[ -n "$LATEST" ] || die "failed to determine latest release"

URL="https://github.com/${REPO}/releases/download/${LATEST}/${BINARY}"

echo "Installing sdme ${LATEST} (${ARCH}) to ${INSTALL_DIR}/sdme..."

TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

curl -fSL -o "$TMP" "$URL" || die "download failed: $URL"

SUMS_URL="https://github.com/${REPO}/releases/download/${LATEST}/SHA256SUMS"
EXPECTED=$(curl -fsSL "$SUMS_URL" | grep "/${BINARY}$" | awk '{print $1}')
[ -n "$EXPECTED" ] || die "failed to fetch checksum from SHA256SUMS"

ACTUAL=$(sha256sum "$TMP" | awk '{print $1}')
[ "$EXPECTED" = "$ACTUAL" ] || die "checksum mismatch: expected $EXPECTED, got $ACTUAL"

chmod +x "$TMP"
mv "$TMP" "${INSTALL_DIR}/sdme"

echo "sdme ${LATEST} installed to ${INSTALL_DIR}/sdme"
