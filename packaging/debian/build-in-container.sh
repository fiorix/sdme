#!/usr/bin/env bash
#
# Build the sdme Debian source + binary package in a clean Ubuntu environment,
# e.g. an sdme Ubuntu container, for a Launchpad PPA:
#
#   sudo mkdir -p dev/deb-out
#   sudo sdme new debbuild -r ubuntu \
#       -b "$PWD:/src:ro" -b "$PWD/dev/deb-out:/out" \
#       -- bash /src/packaging/debian/build-in-container.sh
#
# Target: Ubuntu 26.04 (resolute). A vendored dep (zbus) is edition 2024, so the
# apt-provided rustc must be >= 1.85; 24.04 LTS (rustc 1.75-1.80) cannot build it.
#
# The source package (.dsc + _source.changes) is UNSIGNED; sign and upload it
# yourself (needs your GPG key registered on Launchpad):
#   debsign -k <KEYID> dev/deb-out/sdme_*_source.changes
#   dput ppa:fiorix/sdme dev/deb-out/sdme_*_source.changes
#
# Source modes (SDME_SRC_SOURCE): crates (default, published crate) | local.

set -euo pipefail

SRC=${SRC:-/src}
OUT=${OUT:-/out}
MODE=${SDME_SRC_SOURCE:-crates}
crate=sdme

# Install the toolchain (root), then drop to a non-root "builder" and re-exec.
# Launchpad/sbuild build unprivileged: rustc/cargo come from apt (not rustup),
# and the cargo test in dh_auto_test has tests that fail as root (USER=root).
if [ "$(id -u)" -eq 0 ]; then
    export DEBIAN_FRONTEND=noninteractive
    echo ">> installing build toolchain (root)"
    apt-get update -qq
    apt-get install -y --no-install-recommends \
        build-essential debhelper devscripts dpkg-dev lintian \
        cargo rustc git ca-certificates curl xz-utils >/dev/null
    id builder &>/dev/null || useradd -m builder
    mkdir -p "$OUT"; chmod 0777 "$OUT"
    exec runuser -u builder -- env -u SUDO_USER -u SUDO_UID -u SUDO_GID \
        -u SUDO_COMMAND HOME=/home/builder USER=builder LOGNAME=builder \
        SRC="$SRC" OUT="$OUT" SDME_SRC_SOURCE="$MODE" bash "$0"
fi

# ---- from here on we run as the unprivileged "builder" user ----
export HOME="${HOME:-/home/builder}"
export CARGO_NET_OFFLINE=false   # vendoring below needs the network
git config --global --add safe.directory "$SRC" 2>/dev/null || true

version=$(grep -m1 '^version' "$SRC/Cargo.toml" | cut -d'"' -f2)
[ -n "$version" ] || { echo "error: cannot read version from $SRC/Cargo.toml" >&2; exit 1; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
srcdir="$work/$crate-$version"

echo ">> building $crate $version ($MODE mode) as $(id -un)"
echo ">> apt cargo/rustc: $(cargo --version), $(rustc --version)"

# 1. Obtain pristine upstream source at $srcdir (no debian/, no vendor/).
mkdir -p "$srcdir"
case "$MODE" in
  crates)
    echo ">> fetching $crate $version from crates.io"
    # crates.io returns 403 without a descriptive User-Agent (crawler policy).
    curl -fL -A "sdme-debian-build (https://github.com/fiorix/sdme)" \
        -o "$work/$crate-$version.crate" \
        "https://crates.io/api/v1/crates/$crate/$version/download"
    tar -xf "$work/$crate-$version.crate" -C "$work"
    ;;
  local)
    echo ">> packaging working tree (git archive HEAD)"
    git -C "$SRC" archive --format=tar HEAD | tar -x -C "$srcdir"
    ;;
  *) echo "error: unknown SDME_SRC_SOURCE=$MODE (use crates|local)" >&2; exit 1 ;;
esac
[ -f "$srcdir/Cargo.lock" ] || { echo "error: no Cargo.lock in source" >&2; exit 1; }

# 2. Vendor the full Cargo.lock closure (needs network).
echo ">> vendoring crates"
( cd "$srcdir" && cargo vendor --locked vendor >/dev/null )
for c in tonic prost tokio; do
    ls -d "$srcdir"/vendor/"$c"* >/dev/null 2>&1 \
        || echo "WARN: $c not vendored; the offline probe build may fail"
done
tar -C "$srcdir" -caf "$work/vendor.tar.xz" vendor
rm -rf "$srcdir/vendor"

# 3. Pristine orig tarball (upstream source only), then add the debian/ dir with
#    the vendored crates. The subsequent build runs fully offline.
tar -C "$work" -czf "$work/${crate}_${version}.orig.tar.gz" "$crate-$version"
cp -a "$SRC/packaging/debian/debian" "$srcdir/debian"
mv "$work/vendor.tar.xz" "$srcdir/debian/vendor.tar.xz"

# 4. Source package (unsigned) for the PPA, then an offline binary build to
#    verify it compiles + tests pass exactly as Launchpad will.
cd "$srcdir"
echo ">> dpkg-buildpackage -S (source package)"
dpkg-buildpackage -S -sa -us -uc
echo ">> dpkg-buildpackage -b (binary, offline via --frozen)"
dpkg-buildpackage -b -us -uc

echo ">> lintian (informational)"
lintian "$work"/${crate}_*_source.changes 2>&1 | head -20 || true

# 5. Collect artifacts and report the binary size (stripped probe).
mkdir -p "$OUT"
cp -vf "$work"/${crate}_*.dsc "$work"/${crate}_*.tar.* "$work"/${crate}_*.changes \
       "$work"/${crate}_*.buildinfo "$work"/${crate}_*.deb "$OUT/" 2>/dev/null || true
deb=$(ls "$work"/${crate}_*_*.deb 2>/dev/null | head -1)
if [ -n "$deb" ]; then
    echo ">> built: $(basename "$deb") ($(du -h "$deb" | cut -f1))"
    dpkg-deb -c "$deb" | awk '{print $6}' | grep -E 'bin/sdme|apparmor|completions' || true
    tmp=$(mktemp -d); dpkg-deb -x "$deb" "$tmp"
    echo ">> installed /usr/bin/sdme: $(stat -c%s "$tmp/usr/bin/sdme") bytes"
fi
echo ">> done. artifacts in $OUT:"
ls -1 "$OUT"
