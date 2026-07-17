#!/usr/bin/env bash
#
# Render and test-build both AUR packages in a clean Arch environment, e.g. an
# sdme Arch container, since makepkg does not exist on a non-Arch host:
#
#   sudo sdme fs import archlinux docker.io/archlinux/archlinux:base
#   mkdir -p dev/aur-out
#   sudo sdme new aurbuild -r archlinux \
#       -b "$PWD:/src:ro" -b "$PWD/dev/aur-out:/out" \
#       -- bash /src/packaging/arch/build-in-container.sh
#
# Leaves each package's PKGBUILD + .SRCINFO + sdme.install in /out/<pkgbase>/,
# ready to commit to the AUR, plus the built .pkg.tar.zst so you can inspect it.
# Nothing is pushed; see packaging/arch/aur/README.md for the push.
#
# Version defaults to Cargo.toml; pass one to override. `sdme` builds from the
# GitHub tag tarball and `sdme-bin` from the release assets, so that version must
# already be tagged and released upstream: this checks the published artifacts,
# not your working tree.

set -euo pipefail

SRC=${SRC:-/src}
OUT=${OUT:-/out}
VERSION=${1:-}

# Install the toolchain as root, then drop to "builder" and re-exec: makepkg
# refuses to run as root, as does the AUR's own tooling.
if [ "$(id -u)" -eq 0 ]; then
    echo ">> installing build toolchain (root)"
    # Refresh the keyring first: an fs imported before a signing key rotation
    # fails the upgrade below on "signature is unknown trust".
    pacman -Sy --needed --noconfirm archlinux-keyring >/dev/null
    # curl for make-aur-package.sh's checksum fetches; rust for sdme's build().
    # base-devel brings makepkg, fakeroot and bsdtar.
    pacman -Su --needed --noconfirm base-devel rust curl >/dev/null
    id builder &>/dev/null || useradd -m builder
    mkdir -p "$OUT"; chmod 0777 "$OUT"
    exec runuser -u builder -- env -u SUDO_USER -u SUDO_UID -u SUDO_GID \
        -u SUDO_COMMAND HOME=/home/builder USER=builder LOGNAME=builder \
        SRC="$SRC" OUT="$OUT" bash "$0" ${VERSION:+"$VERSION"}
fi

# ---- from here on we run as the unprivileged "builder" user ----
export HOME="${HOME:-/home/builder}"

if [ -z "$VERSION" ]; then
    VERSION=$(grep -m1 '^version' "$SRC/Cargo.toml" | cut -d'"' -f2)
fi
[ -n "$VERSION" ] || { echo "error: cannot read version from $SRC/Cargo.toml" >&2; exit 1; }

echo ">> building AUR packages for sdme $VERSION as $(id -un)"
echo ">> pacman rust: $(pacman -Q rust 2>/dev/null || echo '?')"

for pkgbase in sdme sdme-bin; do
    echo
    echo "======== $pkgbase ========"
    bash "$SRC/packaging/arch/make-aur-package.sh" "$pkgbase" "$VERSION" "$OUT"

    # Test-build. Nothing validates a PKGBUILD server-side, so a broken one would
    # ship to users the moment it is pushed; this is the only gate there is.
    # Deps are installed above, so no -s (which would want sudo).
    ( cd "$OUT/$pkgbase" && makepkg -f --noconfirm )

    pkg=$(ls "$OUT/$pkgbase"/*.pkg.tar.zst 2>/dev/null | head -1)
    [ -n "$pkg" ] || { echo "error: $pkgbase produced no package" >&2; exit 1; }
    echo ">> built: $(basename "$pkg") ($(du -h "$pkg" | cut -f1))"
    bsdtar -tf "$pkg" | grep -E 'usr/bin/sdme|apparmor|completions|licenses' || true
done

echo
echo ">> done. artifacts in $OUT:"
ls -1 "$OUT"
