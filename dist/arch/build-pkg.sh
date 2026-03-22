#!/usr/bin/env bash
set -euo pipefail

# Build an Arch Linux .pkg.tar.zst package from pre-built artifacts.
# Usage: ./dist/arch/build-pkg.sh [TARGET]
#   Without TARGET, uses the native binary at target/release/sdme.
#   With TARGET (e.g. x86_64-unknown-linux-musl), uses target/$TARGET/release/sdme.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Resolve architecture and binary path
if [[ -n "${1:-}" ]]; then
    TARGET="$1"
    case "$TARGET" in
        x86_64-*)  ARCH="x86_64" ;;
        aarch64-*) ARCH="aarch64" ;;
        *) echo "error: unsupported target: $TARGET" >&2; exit 1 ;;
    esac
    BINARY="$PROJECT_DIR/target/$TARGET/release/sdme"
else
    ARCH="$(uname -m)"
    BINARY="$PROJECT_DIR/target/release/sdme"
fi

# Read version from Cargo.toml
VERSION=$(grep '^version' "$PROJECT_DIR/Cargo.toml" | head -1 | sed 's/.*"\(.*\)".*/\1/')
PKGREL=1
PKGVER="${VERSION}-${PKGREL}"
PKGNAME="sdme"

# Locate pre-built artifacts
COMPLETIONS_DIR="$PROJECT_DIR/dist/out/completions"
APPARMOR_DIR="$PROJECT_DIR/dist/out/apparmor"
INSTALL_FILE="$PROJECT_DIR/dist/arch/sdme.install"

for f in "$BINARY" "$COMPLETIONS_DIR/sdme.bash" "$COMPLETIONS_DIR/_sdme" \
         "$COMPLETIONS_DIR/sdme.fish" "$APPARMOR_DIR/sdme-default" "$INSTALL_FILE"; do
    if [[ ! -f "$f" ]]; then
        echo "error: required file not found: $f" >&2
        exit 1
    fi
done

# Check build dependencies
for cmd in bsdtar zstd; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "error: $cmd not found in PATH" >&2
        exit 1
    fi
done

# fakeroot is only needed when not running as root
FAKEROOT=""
if [[ $(id -u) -ne 0 ]]; then
    if ! command -v fakeroot &>/dev/null; then
        echo "error: fakeroot not found in PATH (required when not running as root)" >&2
        exit 1
    fi
    FAKEROOT="fakeroot --"
fi

STAGING=$(mktemp -d)
trap 'rm -rf "$STAGING"' EXIT

# Stage package contents
install -Dm755 "$BINARY" "$STAGING/usr/bin/sdme"
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
pkgdesc = The systemd machine editor
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
$FAKEROOT bsdtar \
    --format=mtree \
    --options='!all,use-set,type,uid,gid,mode,time,size,md5,sha256,link' \
    -czf .MTREE \
    .PKGINFO .INSTALL *

# Build final package
if [[ -n "${TARGET:-}" ]]; then
    OUTPUT_DIR="$PROJECT_DIR/target/$TARGET/pkg"
else
    OUTPUT_DIR="$PROJECT_DIR/target/pkg"
fi
mkdir -p "$OUTPUT_DIR"
OUTPUT="${OUTPUT_DIR}/${PKGNAME}-${VERSION}-${PKGREL}-${ARCH}.pkg.tar.zst"

$FAKEROOT bsdtar -cf - .PKGINFO .INSTALL .MTREE * | zstd -c -T0 --ultra -20 > "$OUTPUT"

echo "Built: $OUTPUT"
echo "  size: $(du -h "$OUTPUT" | cut -f1)"
