#!/usr/bin/env bash
#
# Render an AUR package from its template in packaging/arch/aur/<pkgbase>/:
#
#   packaging/arch/make-aur-package.sh <pkgbase> [version] [outdir]
#
# Produces <outdir>/<pkgbase>/{PKGBUILD,.SRCINFO,sdme.install}: exactly what the
# AUR git repo holds, and nothing else. Version defaults to Cargo.toml; CI passes
# the tag. Fetches the upstream artifacts to compute the source checksums, so the
# network and the tag (for sdme) or the published release (for sdme-bin) must
# already exist.
#
# Never pushes. The `aur` job in .github/workflows/release.yml commits and pushes
# what this leaves behind, the same split as make-source-package.sh (build) and
# the launchpad job (sign + upload).
#
# Needs makepkg (for .SRCINFO), so it only runs on Arch. From a non-Arch host use
# build-in-container.sh, which runs this in an Arch container as a non-root user.

set -euo pipefail

pkgbase="${1:?usage: make-aur-package.sh <pkgbase> [version] [outdir]}"
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"

version="${2:-}"
[ -n "$version" ] || version=$(grep -m1 '^version' "$repo/Cargo.toml" | cut -d'"' -f2)
[ -n "$version" ] || { echo "error: cannot read version from $repo/Cargo.toml" >&2; exit 1; }

outdir="${3:-$PWD/aur-out}"
tpl="$here/aur/$pkgbase/PKGBUILD.in"
[ -f "$tpl" ] || { echo "error: no template at $tpl" >&2; exit 1; }

dest="$outdir/$pkgbase"
rm -rf "$dest"
mkdir -p "$dest"

# sha256 of what a URL serves, without keeping the body around.
sha256_url() {
    curl -fsSL --retry 3 "$1" | sha256sum | cut -d' ' -f1
}

echo ">> rendering $pkgbase $version"

case "$pkgbase" in
  sdme)
    src=$(sha256_url "https://github.com/fiorix/sdme/archive/v$version.tar.gz")
    sed -e "s|@PKGVER@|$version|g" \
        -e "s|@SHA256_SRC@|$src|g" \
        "$tpl" > "$dest/PKGBUILD"
    ;;
  sdme-bin)
    # Read the checksums out of the release's own SHA256SUMS rather than
    # recomputing them: that asset is what a user would verify against, so if it
    # disagrees with the binaries we want the mismatch to surface here.
    sums=$(curl -fsSL --retry 3 \
        "https://github.com/fiorix/sdme/releases/download/v$version/SHA256SUMS")
    # Lines read "<hash>  sdme-x86_64-linux/sdme-x86_64-linux" (artifact dir +
    # file), so match on the basename.
    x86=$(awk '$2 ~ /sdme-x86_64-linux$/ {print $1; exit}' <<<"$sums")
    arm=$(awk '$2 ~ /sdme-aarch64-linux$/ {print $1; exit}' <<<"$sums")
    [ -n "$x86" ] || { echo "error: no x86_64 checksum in SHA256SUMS for v$version" >&2; exit 1; }
    [ -n "$arm" ] || { echo "error: no aarch64 checksum in SHA256SUMS for v$version" >&2; exit 1; }
    lic=$(sha256_url "https://raw.githubusercontent.com/fiorix/sdme/v$version/LICENSE")
    sed -e "s|@PKGVER@|$version|g" \
        -e "s|@SHA256_X86_64@|$x86|g" \
        -e "s|@SHA256_AARCH64@|$arm|g" \
        -e "s|@SHA256_LICENSE@|$lic|g" \
        "$tpl" > "$dest/PKGBUILD"
    ;;
  *)
    echo "error: unknown pkgbase: $pkgbase (expected sdme or sdme-bin)" >&2
    exit 1
    ;;
esac

if grep -q '@[A-Z0-9_]\+@' "$dest/PKGBUILD"; then
    echo "error: unsubstituted placeholders in $dest/PKGBUILD:" >&2
    grep -o '@[A-Z0-9_]\+@' "$dest/PKGBUILD" >&2
    exit 1
fi

# An AUR repo is self-contained: install= names a file that must be committed
# next to the PKGBUILD. build-pkg.sh uses the same one, hence the copy.
cp "$here/sdme.install" "$dest/sdme.install"

( cd "$dest" && makepkg --printsrcinfo > .SRCINFO )

# A pkgbase that disagrees with the repo name is rejected by the AUR's
# server-side hook. Catch it here rather than at push time.
got=$(awk '/^pkgbase = /{print $3; exit}' "$dest/.SRCINFO")
[ "$got" = "$pkgbase" ] || { echo "error: pkgbase is '$got', expected '$pkgbase'" >&2; exit 1; }
got=$(awk '/^\tpkgver = /{print $3; exit}' "$dest/.SRCINFO")
[ "$got" = "$version" ] || { echo "error: .SRCINFO pkgver is '$got', expected '$version'" >&2; exit 1; }

echo ">> $pkgbase $version rendered in $dest:"
ls -1A "$dest"
