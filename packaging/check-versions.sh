#!/usr/bin/env bash
#
# Assert that every hand-written packaging version agrees with Cargo.toml, which
# is sdme's single source of truth for the version:
#
#   packaging/check-versions.sh
#
# Most channels derive their version and cannot drift, so they are not checked:
#
#   .deb             cargo deb, reads Cargo.toml
#   .rpm (release)   cargo generate-rpm, reads Cargo.toml
#   .pkg.tar.zst     packaging/arch/build-pkg.sh, greps Cargo.toml
#   Launchpad PPA    packaging/debian/make-source-package.sh, from the git tag
#   AUR              packaging/arch/make-aur-package.sh, from the git tag
#
# Only the Fedora spec and the Debian changelog carry a version a human has to
# type, so only they can rot. They did: v0.14.0 reached Copr labelled 0.13.1-1,
# because make-srpm.sh takes the version from the spec but builds Source0 from
# the current tree, so the RPM shipped 0.14.0 code under the older version.
#
# Run by the release workflow's `test` job (which every publishing job depends
# on) and by make-srpm.sh, so a stale version fails before anything is published.

set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"

version=$(grep -m1 '^version' "$repo/Cargo.toml" | cut -d'"' -f2)
[ -n "$version" ] || { echo "error: cannot read version from $repo/Cargo.toml" >&2; exit 1; }

rc=0
report() {
    if [ "${2:-}" = "$version" ]; then
        printf '  ok   %-26s %s\n' "$1" "$2"
    else
        printf '  BAD  %-26s %s (expected %s)\n' "$1" "${2:-<unreadable>}" "$version"
        rc=1
    fi
}

echo "Cargo.toml version: $version"
report "packaging/fedora/sdme.spec" \
    "$(grep -m1 '^Version:' "$repo/packaging/fedora/sdme.spec" | awk '{print $2}')"
# The Debian changelog version is <upstream>-<debian revision>, e.g.
# 0.14.0-1~resolute1. Only the upstream half is ours to match.
report "packaging/debian/.../changelog" \
    "$(head -1 "$repo/packaging/debian/debian/changelog" | sed -n 's/^[^(]*(\([^-)]*\).*/\1/p')"

if [ "$rc" -ne 0 ]; then
    echo >&2
    echo "error: packaging versions disagree with Cargo.toml." >&2
    echo "       run: packaging/bump-version.sh $version" >&2
fi
exit "$rc"
