#!/usr/bin/env bash
#
# Build the sdme SRPM from the current tree, for Copr's make_srpm method.
# Invoked (from the repo root) by .copr/Makefile as:  make-srpm.sh <outdir>
#
# Runs as root in Copr's SRPM chroot, which HAS network, so it vendors the crate
# closure here. The resulting SRPM bundles Source0 (a source tarball) + Source1
# (the vendor tarball), so Copr's RPM phase builds fully offline, like Koji.
#
# This only assembles the SRPM (rpmbuild -bs); no compile and no %check run
# here, so running as root is fine. The compile + %check happen unprivileged in
# Copr's mock RPM phase.

set -euo pipefail

outdir="${1:?usage: make-srpm.sh <outdir>}"
crate=sdme
spec="packaging/fedora/$crate.spec"

# Source0 below is built from the current tree, not downloaded, so the spec's
# Version is the only thing naming the result. When it lags Cargo.toml the SRPM
# ships new code under an old version, which is exactly how v0.14.0 reached Copr
# labelled 0.13.1-1. Fail here rather than publish that again.
bash packaging/check-versions.sh

version=$(grep -m1 '^Version:' "$spec" | awk '{print $2}')
[ -n "$version" ] || { echo "error: cannot read Version from $spec" >&2; exit 1; }

export HOME=/root
echo ">> building $crate $version SRPM -> $outdir"
dnf -y install rust cargo cargo-rpm-macros rpm-build rpmdevtools git tar xz >/dev/null
rpmdev-setuptree
git config --global --add safe.directory "$PWD" 2>/dev/null || true

# Source0: source tarball of tracked files, unpacking to <crate>-<version>/ to
# match the spec's %autosetup. Named .crate to match the %{crates_source} base.
git archive --format=tar --prefix="$crate-$version/" HEAD \
    | gzip -n > ~/rpmbuild/SOURCES/"$crate-$version.crate"

# Source1: the vendored crate closure (needs network, available in this phase).
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
tar -xf ~/rpmbuild/SOURCES/"$crate-$version.crate" -C "$work"
( cd "$work/$crate-$version" && cargo vendor --locked vendor >/dev/null )
tar -C "$work/$crate-$version" -caf ~/rpmbuild/SOURCES/"$crate-$version-vendor.tar.xz" vendor

cp "$spec" ~/rpmbuild/SPECS/
rpmbuild -bs ~/rpmbuild/SPECS/"$crate.spec"
cp ~/rpmbuild/SRPMS/"$crate"-*.src.rpm "$outdir/"
echo ">> wrote: $(ls "$outdir"/"$crate"-*.src.rpm)"
