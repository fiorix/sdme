#!/usr/bin/env bash
#
# Build sdme SRPM + RPM inside a clean Fedora environment, e.g. an sdme
# Fedora container:
#
#   sudo mkdir -p dev/fedora-out
#   sudo sdme new fedbuild -r fedora \
#       -b "$PWD:/src:ro" -b "$PWD/dev/fedora-out:/out"
#   # inside the container:
#   bash /src/packaging/fedora/build-in-container.sh
#
# The source tree is read from $SRC (default /src, may be read-only) and all
# artifacts (SRPM, RPM, vendor tarball, spec) land in $OUT (default /out).
#
# Vendoring downloads the full Cargo.lock crate closure, so the container
# needs network access. The subsequent rpmbuild runs fully offline against the
# vendor tarball, matching how Koji/mock build.

set -euo pipefail

SRC=${SRC:-/src}
OUT=${OUT:-/out}
crate=sdme

version=$(grep -m1 '^version' "$SRC/Cargo.toml" | cut -d'"' -f2)
[ -n "$version" ] || { echo "error: could not read version from $SRC/Cargo.toml" >&2; exit 1; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
srcdir="$work/$crate-$version"

echo ">> building $crate $version -> $OUT"

# 1. Build toolchain.
echo ">> installing build toolchain"
dnf -y install rust cargo cargo-rpm-macros rpm-build rpmdevtools git tar xz >/dev/null
rpmdev-setuptree

# 2. Clean source copy. Prefer git archive (tracked files only); otherwise
#    copy and strip build/scratch dirs.
mkdir -p "$srcdir"
if git -C "$SRC" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git -C "$SRC" archive --format=tar HEAD | tar -x -C "$srcdir"
else
    cp -a "$SRC"/. "$srcdir"/
    rm -rf "$srcdir/target" "$srcdir/dev" "$srcdir/.git"
fi

# 3. Vendor the crate dependencies (needs network). Driven by Cargo.lock, so
#    the full closure including optional/probe-feature crates is captured.
echo ">> vendoring crates"
( cd "$srcdir" && cargo vendor --locked vendor >/dev/null )

# Sanity check: the embedded probe (built by build.rs) needs these offline.
for c in tonic prost tokio; do
    ls -d "$srcdir"/vendor/"$c"* >/dev/null 2>&1 \
        || echo "WARN: $c not vendored; the offline probe build may fail"
done

# 4. Assemble rpmbuild inputs.
tar -C "$srcdir" -caf ~/rpmbuild/SOURCES/"$crate-$version"-vendor.tar.xz vendor
rm -rf "$srcdir/vendor"
tar -C "$work" -czf ~/rpmbuild/SOURCES/"$crate-$version".tar.gz "$crate-$version"
cp "$SRC/packaging/fedora/$crate.spec" ~/rpmbuild/SPECS/

# 5. Build SRPM + binary RPM.
echo ">> rpmbuild"
rpmbuild -ba ~/rpmbuild/SPECS/"$crate.spec"

# 6. Collect artifacts.
mkdir -p "$OUT"
cp -v ~/rpmbuild/SOURCES/"$crate-$version"-vendor.tar.xz "$OUT/"
cp "$SRC/packaging/fedora/$crate.spec" "$OUT/"
find ~/rpmbuild/SRPMS ~/rpmbuild/RPMS -name '*.rpm' -exec cp -v {} "$OUT/" \;

echo ">> done. artifacts in $OUT:"
ls -1 "$OUT"
