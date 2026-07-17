#!/usr/bin/env bash
#
# Bump sdme's version everywhere a human would otherwise have to remember to:
#
#   packaging/bump-version.sh <X.Y.Z>
#
# Cargo.toml is the source of truth. Everything else either derives its version
# automatically (see check-versions.sh for the list) or is rewritten here:
#
#   Cargo.toml                        [package] version
#   Cargo.lock                        sdme's own entry, via cargo metadata
#   packaging/fedora/sdme.spec        Version, Release, and a %changelog entry
#   packaging/debian/debian/changelog a new top entry
#
# The generated changelog entries say "Release <version>." Rewrite them with
# something a reader would benefit from before committing; the Fedora one is
# user-visible in `dnf changelog`. Leaves everything uncommitted for review.

set -euo pipefail

version="${1:?usage: bump-version.sh <X.Y.Z>}"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
    { echo "error: not an X.Y.Z version: $version" >&2; exit 1; }

repo="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo"

maintainer='Alexandre Fiori <fiorix@gmail.com>'
# The Debian revision the PPA publishes under; see make-source-package.sh, which
# templates the same thing from the tag for CI. This copy is what the local
# fallback build (packaging/debian/build-in-container.sh) uses.
series=resolute

old=$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)
[ -n "$old" ] || { echo "error: cannot read version from Cargo.toml" >&2; exit 1; }
if [ "$old" = "$version" ]; then
    echo ">> already at $version; syncing the packaging files anyway"
else
    echo ">> $old -> $version"
fi

# Cargo.toml: the [package] version is the first `version = ` line; dependency
# versions further down must not be touched.
sed -i "0,/^version = \"$old\"/s//version = \"$version\"/" Cargo.toml

# Cargo.lock: let cargo restate sdme's own entry. Not --locked, which would
# refuse precisely because the lock is now out of date, and NOT --no-deps, which
# skips resolution entirely and so leaves the lock untouched: that shipped a
# 0.15.0 Cargo.toml against a 0.14.0 Cargo.lock and broke every --locked build.
cargo metadata --format-version 1 >/dev/null

# Fedora spec: Version, a reset Release, and a new %changelog entry on top.
sed -i "s/^Version:\(\s*\).*/Version:\1$version/" packaging/fedora/sdme.spec
sed -i "s/^Release:\(\s*\).*/Release:\11%{?dist}/" packaging/fedora/sdme.spec
rpm_entry="* $(LC_ALL=C date '+%a %b %d %Y') $maintainer - $version-1
- Release $version.
"
tmp=$(mktemp)
awk -v entry="$rpm_entry" '
    /^%changelog$/ && !done { print; print entry; done = 1; next }
    { print }
' packaging/fedora/sdme.spec > "$tmp" && mv "$tmp" packaging/fedora/sdme.spec

# Debian changelog: a new top entry.
tmp=$(mktemp)
{
    cat <<EOF
sdme ($version-1~${series}1) $series; urgency=medium

  * Release $version.

 -- $maintainer  $(date -R)

EOF
    cat packaging/debian/debian/changelog
} > "$tmp" && mv "$tmp" packaging/debian/debian/changelog

echo
"$repo/packaging/check-versions.sh"
echo
echo ">> bumped to $version. Review the generated changelog entries:"
echo "   packaging/fedora/sdme.spec"
echo "   packaging/debian/debian/changelog"
