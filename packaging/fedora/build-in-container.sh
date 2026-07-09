#!/usr/bin/env bash
#
# Build the sdme SRPM + RPM inside a clean Fedora environment, e.g. an sdme
# Fedora container:
#
#   sudo mkdir -p dev/fedora-out
#   sudo sdme new fedbuild -r fedora \
#       -b "$PWD:/src:ro" -b "$PWD/dev/fedora-out:/out" \
#       -- bash /src/packaging/fedora/build-in-container.sh
#
# The spec is read from $SRC (default /src, may be read-only); all artifacts
# (SRPM, RPM, vendor tarball, spec) land in $OUT (default /out).
#
# Source modes (SDME_SRPM_SOURCE):
#   crates  (default) Build the PUBLISHED crate. Source0 is fetched from
#           crates.io (matching the spec's %{crates_source}) and the vendor
#           tarball is generated from that crate's Cargo.lock, so Source0 and
#           Source1 stay consistent. This is the artifact for COPR / official
#           Fedora review.
#   local   Build the working tree at $SRC (git archive HEAD), for testing
#           unreleased changes. Produces a matching <crate>-<ver>.crate locally.
#           NOT a valid official artifact: its source is not on crates.io.
#
# Vendoring needs network; the subsequent rpmbuild runs fully offline against
# the vendor tarball, matching how Koji/mock build.

set -euo pipefail

SRC=${SRC:-/src}
OUT=${OUT:-/out}
MODE=${SDME_SRPM_SOURCE:-crates}
crate=sdme
spec="$SRC/packaging/fedora/$crate.spec"

# Install the toolchain (root), then drop to a non-root "builder" user and
# re-exec. Real builders (Koji/mock/COPR) run unprivileged: rpmbuild as root is
# discouraged, and several unit tests in %check assume a non-root builder (they
# set SUDO_USER to the current user and expect it to resolve, which USER=root
# defeats). A real user also gives a proper HOME and drops sudo's SUDO_* vars.
# curl is needed by spectool / the crates.io fallback; shadow-utils for useradd.
if [ "$(id -u)" -eq 0 ]; then
    echo ">> installing build toolchain (root)"
    dnf -y install rust cargo cargo-rpm-macros rpm-build rpmdevtools \
        shadow-utils git tar xz curl >/dev/null
    id builder &>/dev/null || useradd -m builder
    mkdir -p "$OUT"; chmod 0777 "$OUT"   # let the builder write artifacts here
    exec runuser -u builder -- env -u SUDO_USER -u SUDO_UID -u SUDO_GID \
        -u SUDO_COMMAND HOME=/home/builder USER=builder LOGNAME=builder \
        SRC="$SRC" OUT="$OUT" SDME_SRPM_SOURCE="$MODE" bash "$0"
fi

# ---- from here on we run as the unprivileged "builder" user ----
export HOME="${HOME:-/home/builder}"
# $SRC is a foreign-owned (host uid) read-only bind mount; let git operate on it.
git config --global --add safe.directory "$SRC"

[ -f "$spec" ] || { echo "error: spec not found at $spec" >&2; exit 1; }
# The spec's Version: tag is the single source of truth (it also drives the
# %{crates_source} URL, so a bumped-but-unpublished version fails loudly below).
version=$(grep -m1 '^Version:' "$spec" | awk '{print $2}')
[ -n "$version" ] || { echo "error: could not read Version from $spec" >&2; exit 1; }
tarball="$crate-$version.crate"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
srcdir="$work/$crate-$version"

echo ">> building $crate $version ($MODE mode) as $(id -un) -> $OUT"

rpmdev-setuptree
cp "$spec" ~/rpmbuild/SPECS/

# 2. Obtain Source0 as ~/rpmbuild/SOURCES/<crate>-<version>.crate and unpack a
#    copy for vendoring. A .crate is a gzipped tar with a <crate>-<version>/
#    top-level dir, so both modes yield the same on-disk layout at $srcdir.
case "$MODE" in
  crates)
    # Fetch the published crate, named exactly as the spec's Source0 basename.
    echo ">> fetching $tarball from crates.io"
    spectool -g -R ~/rpmbuild/SPECS/"$crate.spec" || true
    if [ ! -f ~/rpmbuild/SOURCES/"$tarball" ]; then
        curl -fL -o ~/rpmbuild/SOURCES/"$tarball" \
            "https://crates.io/api/v1/crates/$crate/$version/download" \
          || { echo "error: $crate $version not on crates.io; publish it or use SDME_SRPM_SOURCE=local" >&2; exit 1; }
    fi
    tar -xf ~/rpmbuild/SOURCES/"$tarball" -C "$work"
    ;;
  local)
    git -C "$SRC" rev-parse --is-inside-work-tree >/dev/null 2>&1 \
        || { echo "error: $SRC is not a git work tree; local mode needs it" >&2; exit 1; }
    echo ">> packaging working tree (git archive HEAD)"
    mkdir -p "$srcdir"
    git -C "$SRC" archive --format=tar HEAD | tar -x -C "$srcdir"
    # Package a matching .crate so rpmbuild resolves Source0 to the same layout.
    tar -C "$work" -czf ~/rpmbuild/SOURCES/"$tarball" "$crate-$version"
    ;;
  *)
    echo "error: unknown SDME_SRPM_SOURCE=$MODE (use 'crates' or 'local')" >&2
    exit 1
    ;;
esac

[ -f "$srcdir/Cargo.lock" ] \
    || { echo "error: no Cargo.lock in the source; cannot vendor reproducibly" >&2; exit 1; }

# 3. Vendor the full Cargo.lock closure (needs network). Optional/probe-feature
#    crates are in the lock, so they are captured too.
echo ">> vendoring crates"
( cd "$srcdir" && cargo vendor --locked vendor >/dev/null )

# Sanity check: the embedded probe (built by build.rs) needs these offline.
for c in tonic prost tokio; do
    ls -d "$srcdir"/vendor/"$c"* >/dev/null 2>&1 \
        || echo "WARN: $c not vendored; the offline probe build may fail"
done

tar -C "$srcdir" -caf ~/rpmbuild/SOURCES/"$crate-$version-vendor.tar.xz" vendor

# 4. Build SRPM + binary RPM (offline against the vendor tarball).
echo ">> rpmbuild"
rpmbuild -ba ~/rpmbuild/SPECS/"$crate.spec"

# 5. Collect artifacts. Force-overwrite: $OUT may hold stale, differently-owned
#    files from earlier runs, and a plain cp cannot truncate a file it does not
#    own even in a world-writable dir (cp -f unlinks and recreates instead).
mkdir -p "$OUT"
cp -vf ~/rpmbuild/SOURCES/"$crate-$version-vendor.tar.xz" "$OUT/"
cp -f "$spec" "$OUT/"
find ~/rpmbuild/SRPMS ~/rpmbuild/RPMS -name '*.rpm' -exec cp -vf {} "$OUT/" \;

echo ">> done. artifacts in $OUT:"
ls -1 "$OUT"
