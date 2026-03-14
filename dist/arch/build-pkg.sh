#!/usr/bin/env bash
set -euo pipefail

# Build an Arch Linux .pkg.tar.zst package from pre-built artifacts.
# Usage: ./dist/arch/build-pkg.sh [TARGET]
#   TARGET defaults to x86_64-unknown-linux-musl

TARGET="${1:-x86_64-unknown-linux-musl}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Map Rust target to Arch architecture
case "$TARGET" in
    x86_64-*)  ARCH="x86_64" ;;
    aarch64-*) ARCH="aarch64" ;;
    *) echo "error: unsupported target: $TARGET" >&2; exit 1 ;;
esac

# Read version from Cargo.toml
VERSION=$(grep '^version' "$PROJECT_DIR/Cargo.toml" | head -1 | sed 's/.*"\(.*\)".*/\1/')
PKGREL=1
PKGVER="${VERSION}-${PKGREL}"
PKGNAME="sdme"

# Locate pre-built artifacts
BINARY="$PROJECT_DIR/target/$TARGET/release/sdme"
MANPAGE="$PROJECT_DIR/dist/sdme.1"
COMPLETIONS_DIR="$PROJECT_DIR/dist/out/completions"
APPARMOR_DIR="$PROJECT_DIR/dist/out/apparmor"
INSTALL_FILE="$PROJECT_DIR/dist/arch/sdme.install"

for f in "$BINARY" "$MANPAGE" "$COMPLETIONS_DIR/sdme.bash" "$COMPLETIONS_DIR/_sdme" \
         "$COMPLETIONS_DIR/sdme.fish" "$APPARMOR_DIR/sdme-default" "$INSTALL_FILE"; do
    if [[ ! -f "$f" ]]; then
        echo "error: required file not found: $f" >&2
        exit 1
    fi
done

# Check build dependencies
for cmd in bsdtar fakeroot zstd; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "error: $cmd not found in PATH" >&2
        echo "  install with: sudo apt-get install libarchive-tools fakeroot zstd" >&2
        exit 1
    fi
done

STAGING=$(mktemp -d)
trap 'rm -rf "$STAGING"' EXIT

# Stage package contents
install -Dm755 "$BINARY" "$STAGING/usr/bin/sdme"
install -Dm644 "$MANPAGE" "$STAGING/usr/share/man/man1/sdme.1"
install -Dm644 "$COMPLETIONS_DIR/sdme.bash" "$STAGING/usr/share/bash-completion/completions/sdme"
install -Dm644 "$COMPLETIONS_DIR/_sdme" "$STAGING/usr/share/zsh/site-functions/_sdme"
install -Dm644 "$COMPLETIONS_DIR/sdme.fish" "$STAGING/usr/share/fish/vendor_completions.d/sdme.fish"
install -Dm644 "$APPARMOR_DIR/sdme-default" "$STAGING/etc/apparmor.d/sdme-default"

# Generate .PKGINFO
BUILDDATE=$(date +%s)
INSTALLED_SIZE=$(du -sb "$STAGING" | cut -f1)

cat > "$STAGING/.PKGINFO" <<EOF
pkgname = ${PKGNAME}
pkgver = ${PKGVER}
pkgdesc = Lightweight systemd-nspawn containers with overlayfs
url = https://github.com/fiorix/sdme
builddate = ${BUILDDATE}
packager = CI
size = ${INSTALLED_SIZE}
arch = ${ARCH}
license = MIT
depend = systemd>=252
optdepend = qemu-base: QCOW2 disk image import support
optdepend = apparmor: security profile support
backup = etc/apparmor.d/sdme-default
EOF

# Copy .INSTALL
cp "$INSTALL_FILE" "$STAGING/.INSTALL"

# Generate .MTREE
cd "$STAGING"
fakeroot -- bsdtar \
    --format=mtree \
    --options='!all,use-set,type,uid,gid,mode,time,size,md5,sha256,link' \
    -czf .MTREE \
    .PKGINFO .INSTALL *

# Build final package
OUTPUT_DIR="$PROJECT_DIR/target/$TARGET/pkg"
mkdir -p "$OUTPUT_DIR"
OUTPUT="${OUTPUT_DIR}/${PKGNAME}-${VERSION}-${PKGREL}-${ARCH}.pkg.tar.zst"

fakeroot -- bsdtar -cf - .PKGINFO .INSTALL .MTREE * | zstd -c -T0 --ultra -20 > "$OUTPUT"

echo "Built: $OUTPUT"
echo "  size: $(du -h "$OUTPUT" | cut -f1)"
