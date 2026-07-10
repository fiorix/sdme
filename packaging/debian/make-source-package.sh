#!/usr/bin/env bash
#
# Assemble the sdme Debian SOURCE package (no compile) for a Launchpad PPA
# upload, versioned <version>-1~resolute1 for Ubuntu 26.04 (resolute). Run from
# the repo root, e.g. a CI checkout at the release tag:
#
#   packaging/debian/make-source-package.sh <upstream-version> [outdir]
#
# Produces the .dsc, orig + debian tarballs, and _source.changes in <outdir>
# (default ./deb-src-out). The result is UNSIGNED; sign it (debsign) and upload
# it (dput ppa:fiorix/sdme) afterwards. Needs cargo (to vendor), dpkg-dev,
# debhelper and devscripts. Network is used for vendoring; the eventual
# Launchpad build is offline against the vendor tarball.

set -euo pipefail

version="${1:?usage: make-source-package.sh <version> [outdir]}"
outdir="${2:-$PWD/deb-src-out}"
crate=sdme
series=resolute
repo="$PWD"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
srcdir="$work/$crate-$version"
mkdir -p "$srcdir" "$outdir"

# git's safe.directory can only live in global/user config, which needs HOME
# (unset under `sdme exec`; always set on a CI runner, where this is a no-op).
export HOME="${HOME:-/root}"
git config --global --add safe.directory "$repo" 2>/dev/null || true

# Pristine upstream source (tracked files) unpacking to sdme-<version>/.
git -C "$repo" archive --format=tar HEAD | tar -x -C "$srcdir"
[ -f "$srcdir/Cargo.lock" ] || { echo "error: no Cargo.lock in source" >&2; exit 1; }

# Vendor the full crate closure (needs network).
( cd "$srcdir" && cargo vendor --locked vendor >/dev/null )

# orig tarball: pristine upstream, without vendor/ or a top-level debian/.
mv "$srcdir/vendor" "$work/vendor"
tar -C "$work" -czf "$work/${crate}_${version}.orig.tar.gz" "$crate-$version"

# debian/ packaging: the committed template + the vendor tarball + a changelog
# templated for this version and series (the committed changelog is ignored).
cp -a "$repo/packaging/debian/debian" "$srcdir/debian"
tar -C "$work" -caf "$srcdir/debian/vendor.tar.xz" vendor
cat > "$srcdir/debian/changelog" <<EOF
$crate ($version-1~${series}1) $series; urgency=medium

  * Release $version.

 -- Alexandre Fiori <fiorix@gmail.com>  $(date -R)
EOF

# Source-only package (unsigned).
( cd "$srcdir" && dpkg-buildpackage -S -sa -us -uc )

cp -vf "$work"/${crate}_*.dsc "$work"/${crate}_*.tar.* \
       "$work"/${crate}_*_source.changes "$work"/${crate}_*_source.buildinfo \
       "$outdir/" 2>/dev/null || true
echo ">> unsigned source package in $outdir:"
ls -1 "$outdir"
