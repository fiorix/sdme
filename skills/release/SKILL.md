---
name: release
description: How to cut an sdme release across crates.io, GitHub Releases, Fedora Copr, and the Ubuntu Launchpad PPA. Use when publishing a new sdme version, bumping the version, tagging vX.Y.Z, wiring or debugging the release CI, or when a release build fails on any of those channels.
---

# Releasing sdme

## Channels

A release is tag-driven. Pushing a `vX.Y.Z` tag fans out to three channels via CI; crates.io is one manual command.

- **GitHub Releases** - `.github/workflows/release.yml` (on `v*` tags): builds static musl binaries (x86_64 + aarch64 via cargo-zigbuild), deb/rpm/pkg, and creates the release. `sdme upgrade` reads `https://api.github.com/repos/fiorix/sdme/releases/latest`, so the release must succeed or clients cannot upgrade.
- **Fedora Copr** (`fiorix/sdme`) - an SCM package (build method `make_srpm`) wired by a GitHub webhook. On a tag it runs `.copr/Makefile` -> `packaging/fedora/make-srpm.sh`, which vendors the crate closure and assembles a self-contained SRPM; Copr builds the RPM offline for F43/44/rawhide x {x86_64, aarch64}.
- **Ubuntu Launchpad** (`ppa:fiorix/sdme`) - the `launchpad` job in `release.yml`: `packaging/debian/make-source-package.sh <version>` builds the Debian source package, signs it with the `LAUNCHPAD_GPG_*` secrets, and `dput`s it. Launchpad builds amd64 + arm64. **26.04 (resolute) only** - a vendored dep is Rust edition 2024, needing `rustc >= 1.85`.
- **crates.io** - `cargo publish` (manual, not in CI).

Copr and Launchpad both build from the **tag's tree** (git archive), so the version must be bumped in the tagged commit.

## Cut a release

1. Bump the version in the committed sources CI reads:
   - `Cargo.toml` `version = "X.Y.Z"` (updates `Cargo.lock`; run `cargo build` or `cargo metadata --locked --no-deps` to sync it).
   - `packaging/fedora/sdme.spec` `Version:` to `X.Y.Z`, reset `Release: 1%{?dist}`, and add a `%changelog` entry.
   - The Debian changelog is templated from the tag by `make-source-package.sh`; only bump `packaging/debian/debian/changelog` if you will use the local Debian build fallback.
2. Guard against scratch leaks (crates.io grabs untracked, non-gitignored files):
   ```sh
   cargo package --list --allow-dirty | grep -iE '(^|/)dev/|draft'   # must be empty
   ```
3. Commit ("bump version to X.Y.Z"), then tag and push:
   ```sh
   git tag vX.Y.Z && git push origin main && git push origin vX.Y.Z
   ```
4. Publish the crate from a clean tree (NEVER `--allow-dirty`):
   ```sh
   cargo publish
   ```

## Verify

- **GitHub**: `gh run watch <id>` for the Release workflow; the release appears with `sdme-{x86_64,aarch64}-linux` + deb/rpm/pkg + SHA256SUMS. Confirm `gh api repos/fiorix/sdme/releases/latest --jq .tag_name` is the new tag.
- **Copr**: the build on <https://copr.fedorainfracloud.org/coprs/fiorix/sdme/package/sdme/> goes green.
- **Launchpad**: the `launchpad` job is green, then the PPA accepts + builds at <https://launchpad.net/~fiorix/+archive/ubuntu/sdme>.
- **crates.io**: `curl -sL -A x https://crates.io/api/v1/crates/sdme | jq -r .crate.max_version`.

## Manual fallbacks (when CI fails or predates a fix)

- **Copr**: click **Rebuild** on the package page (builds the default branch), or `copr-cli build sdme <srpm>`.
- **Launchpad**: build in a clean Ubuntu 26.04 sdme container, then sign + upload:
  ```sh
  sudo sdme new debbuild -r ubuntu -b "$PWD:/src:ro" -b "$PWD/dev/deb-out:/out" \
      -- bash /src/packaging/debian/build-in-container.sh
  debsign -k <KEYID> dev/deb-out/sdme_*_source.changes
  dput ppa:fiorix/sdme dev/deb-out/sdme_*_source.changes
  ```
- **GitHub release**: fix `release.yml`, then move the tag to the fix (`git tag -f vX.Y.Z && git push -f origin vX.Y.Z`) to re-run - or cut the next version.

## Gotchas

- **Never `cargo publish --allow-dirty`.** A dirty publish leaked the untracked `dev/` scratch into 0.10.1 (yanked). `dev/` and `.Drafts/` are gitignored and in `Cargo.toml` `exclude`; keep any new scratch dir out of the crate the same way, and always run the `cargo package --list` check above.
- **The embedded probe is stripped by `build.rs`** (`strip --strip-all`, native only) so the binary stays ~12M instead of ~52M. Keep the strip; do not reintroduce `SDME_KUBE_PROBE_PATH`.
- **Copr/Launchpad build from the tag.** Bump `sdme.spec`/`Cargo.toml` in the tagged commit or they build the old version.
- **Debian source build uses `dpkg-buildpackage -S -d`** - the source-only build must not require cargo/rustc debs (the runner has cargo via rustup).
- **cargo-zigbuild is installed with `cargo install --locked`** in `release.yml`; the old `curl | sh` installer broke and killed the 0.10.3 release.
- **Launchpad is 26.04+ only** (edition-2024 `rustc >= 1.85`); 24.04 LTS cannot build current sdme. The GitHub-release static `.deb` covers older Ubuntu/Debian.

## Setup reference

- Copr project `fiorix/sdme`: package `sdme`, source SCM (git, clone `https://github.com/fiorix/sdme.git`, spec `packaging/fedora/sdme.spec`, build method `make_srpm`), auto-rebuild on, webhook from GitHub (fire on push/tag).
- Launchpad: account + CoC, GPG key registered on Launchpad and published to `keyserver.ubuntu.com`, PPA `ppa:fiorix/sdme`.
- GitHub repo secrets: `LAUNCHPAD_GPG_PRIVATE_KEY` (`gpg --armor --export-secret-keys <KEYID>`) and `LAUNCHPAD_GPG_PASSPHRASE`.
- crates.io token in `~/.cargo/credentials.toml` (for manual `cargo publish`).
