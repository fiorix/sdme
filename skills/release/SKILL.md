---
name: release
description: How to cut an sdme release across crates.io, GitHub Releases, Fedora Copr, the Ubuntu Launchpad PPA, and the Arch AUR. Use when publishing a new sdme version, bumping the version, tagging vX.Y.Z, wiring or debugging the release CI, or when a release build fails on any of those channels.
---

# Releasing sdme

## Channels

A release is tag-driven. Pushing a `vX.Y.Z` tag fans out to four channels via CI; crates.io is one manual command.

- **GitHub Releases** - `.github/workflows/release.yml` (on `v*` tags): builds static musl binaries (x86_64 + aarch64 via cargo-zigbuild), deb/rpm/pkg, and creates the release. `sdme upgrade` reads `https://api.github.com/repos/fiorix/sdme/releases/latest`, so the release must succeed or clients cannot upgrade.
- **Fedora Copr** (`fiorix/sdme`) - an SCM package (build method `make_srpm`) poked by the `copr` job in `release.yml`, which POSTs to Copr's custom webhook (`secrets.COPR_WEBHOOK` + `sdme/`). Copr rebuilds its configured committish (the default branch `main`), running `.copr/Makefile` -> `packaging/fedora/make-srpm.sh`, which vendors the crate closure and assembles a self-contained SRPM; Copr builds the RPM offline for each enabled chroot (F43/44/rawhide and CentOS Stream, x {x86_64, aarch64}). The poke makes the trigger visible in the workflow; it does not wait for the Copr build. **Ordering:** Copr builds `main` HEAD, so push `main` before the tag (the release procedure does) or Copr builds the previous version.
- **Ubuntu Launchpad** (`ppa:fiorix/sdme`) - the `launchpad` job in `release.yml`: `packaging/debian/make-source-package.sh <version>` builds the Debian source package, signs it with the `LAUNCHPAD_GPG_*` secrets, and `dput`s it. The upload goes over authenticated SFTP when `secrets.LAUNCHPAD_SSH_PRIVATE_KEY` is set (a `~/.dput.cf` `[ppa]` stanza with `method = sftp`, keyed by an SSH key registered on Launchpad); without the key it falls back to dput's anonymous FTP. Launchpad builds amd64 + arm64. **26.04 (resolute) only** - a vendored dep is Rust edition 2024, needing `rustc >= 1.85`.
- **Arch AUR** (`sdme`, `sdme-bin`) - the `aur` job in `release.yml`, `needs: release`. Renders `packaging/arch/aur/<pkgbase>/PKGBUILD.in` via `packaging/arch/make-aur-package.sh` (version from the tag, checksums from the published artifacts), test-builds each with makepkg in an `archlinux:base-devel` container, then pushes `PKGBUILD` + `.SRCINFO` + `sdme.install` to `ssh://aur@aur.archlinux.org/<pkgbase>.git` using `secrets.AUR_SSH_PRIVATE_KEY`. The AUR has no build service: the push IS the publish and nothing is validated server-side, hence the test build. Nothing is vendored (makepkg has network, unlike the Launchpad and Copr chroots). See `packaging/arch/aur/README.md`.
- **crates.io** - `cargo publish` (manual, not in CI). **It is easy to forget and it has been forgotten**: crates.io sat at 0.12.0 while the project shipped 0.13.0, 0.13.1 and 0.14.0.

Copr and Launchpad both build from the **tag's tree** (git archive), so the version must be bumped in the tagged commit.

## Versions

`Cargo.toml` is the single source of truth. Most channels derive from it or from the tag and cannot drift:

```
  channel            version comes from
  ---------------------------------------------------------------
  .deb               cargo deb, reads Cargo.toml
  .rpm (release)     cargo generate-rpm, reads Cargo.toml
  .pkg.tar.zst       packaging/arch/build-pkg.sh, greps Cargo.toml
  Launchpad PPA      make-source-package.sh, from the git tag
  AUR                make-aur-package.sh, from the git tag
  Fedora Copr        Version: in packaging/fedora/sdme.spec  <- hand-written
  Debian changelog   packaging/debian/debian/changelog       <- hand-written
```

Only the last two are typed by a human, so only they can rot, and they did: **v0.14.0 reached Copr labelled 0.13.1-1**, because `make-srpm.sh` takes the version from the spec but builds Source0 from the current tree, so the SRPM shipped 0.14.0 code under the older version. Two things now prevent that:

- `packaging/bump-version.sh X.Y.Z` rewrites all of them (Cargo.toml, Cargo.lock, the spec's Version/Release/%changelog, the Debian changelog) in one command.
- `packaging/check-versions.sh` asserts they agree. It runs in the release workflow's `test` job, which every publishing job now depends on, and again inside `make-srpm.sh`. A stale version fails the release before anything is published.

## Cut a release

1. Bump the version:
   ```sh
   packaging/bump-version.sh X.Y.Z
   ```
   Then rewrite the two generated "Release X.Y.Z." changelog stubs into something a reader benefits from; the Fedora one is user-visible in `dnf changelog`.
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
- **Copr**: the build on <https://copr.fedorainfracloud.org/coprs/fiorix/sdme/package/sdme/> goes green. Verifying the install from a container: use `dnf upgrade sdme` (or `dnf install --refresh sdme` on a fresh box), not `dnf install`; under DNF5 (F41+) `install` on an already-installed package will not upgrade it and reports "nothing to do" even when the newer RPM is published and visible to `dnf check-update`.
- **Launchpad**: the `launchpad` job is green, then the PPA accepts + builds at <https://launchpad.net/~fiorix/+archive/ubuntu/sdme>.
- **AUR**: the `aur` job is green (both matrix legs), then <https://aur.archlinux.org/packages/sdme> and <https://aur.archlinux.org/packages/sdme-bin> show the new version. A green job with "already at X; nothing to push" means the AUR already had it.
- **crates.io**: `curl -sL -A x https://crates.io/api/v1/crates/sdme | jq -r .crate.max_version`. Check this every release; it is the one channel with no CI safety net.

## Manual fallbacks (when CI fails or predates a fix)

- **Copr**: click **Rebuild** on the package page (builds the default branch), or `copr-cli build sdme <srpm>`.
- **Launchpad**: build in a clean Ubuntu 26.04 sdme container, then sign + upload:
  ```sh
  sudo sdme new --name debbuild -r ubuntu -b "$PWD:/src:ro" -b "$PWD/dev/deb-out:/out" \
      -- bash /src/packaging/debian/build-in-container.sh
  debsign -k <KEYID> dev/deb-out/sdme_*_source.changes
  dput ppa:fiorix/sdme dev/deb-out/sdme_*_source.changes
  ```
- **AUR**: build and push by hand from an Arch container; see the "Manual build + push" section of `packaging/arch/aur/README.md`.
- **GitHub release**: fix `release.yml`, then move the tag to the fix (`git tag -f vX.Y.Z && git push -f origin vX.Y.Z`) to re-run - or cut the next version.

## Gotchas

- **Never `cargo publish --allow-dirty`.** A dirty publish leaked the untracked `dev/` scratch into 0.10.1 (yanked). `dev/` and `.Drafts/` are gitignored and in `Cargo.toml` `exclude`; keep any new scratch dir out of the crate the same way, and always run the `cargo package --list` check above.
- **The embedded probe is stripped by `build.rs`** (`strip --strip-all`, native only) so the binary stays ~12M instead of ~52M. Keep the strip; do not reintroduce `SDME_KUBE_PROBE_PATH`.
- **Copr/Launchpad build from the tag.** Use `packaging/bump-version.sh` in the tagged commit or they build the old version; `check-versions.sh` in the `test` job is the backstop.
- **`Requires: systemd >= 255` is what makes the el9 builds safe.** Stream 9's base systemd is 252, but the CentOS Hyperscale SIG rebases it to 260.x (`.hs.el9`), so a single el9 RPM installs on a Hyperscale-enabled host and is correctly refused on a base Stream 9. Building on Stream 9 is fine regardless: nothing BuildRequires systemd, `%check` only runs unit tests, AppStream carries rust 1.95 (well past the edition-2024 floor of 1.85), and EPEL9 has `cargo-rpm-macros` 26.3. Stream 10 ships 257. Do not reason about a chroot's runtime systemd from its base repos alone: the SIGs rebase it.
- **AUR: `options=(!lto)` in `sdme` is load-bearing** (makepkg's default LTO makes `ring`/`zstd-sys` C objects unlinkable), and **`options=(!strip !debug)` in `sdme-bin`** keeps the released binary byte-identical to its published checksum. See `packaging/arch/aur/README.md`.
- **Debian source build uses `dpkg-buildpackage -S -d`** - the source-only build must not require cargo/rustc debs (the runner has cargo via rustup).
- **cargo-zigbuild is installed with `cargo install --locked`** in `release.yml`; the old `curl | sh` installer broke and killed the 0.10.3 release.
- **Launchpad is 26.04+ only** (edition-2024 `rustc >= 1.85`); 24.04 LTS cannot build current sdme. The GitHub-release static `.deb` covers older Ubuntu/Debian.

## Setup reference

- Copr project `fiorix/sdme`: package `sdme`, source SCM (git, clone `https://github.com/fiorix/sdme.git`, spec `packaging/fedora/sdme.spec`, build method `make_srpm`). Triggered from CI via the project's Custom webhook (Settings -> Integrations), NOT the old GitHub auto-rebuild webhook. The `COPR_WEBHOOK` secret is the custom webhook base `https://copr.fedorainfracloud.org/webhooks/custom/<project_id>/<uuid>/` (trailing slash; the job appends `sdme/`). To migrate off the watch: delete the GitHub repo webhook whose payload URL points at `copr.fedorainfracloud.org/webhooks/github/...` (repo Settings -> Webhooks) so Copr stops auto-building every push and only builds when poked.
- Copr chroots: Fedora 43/44/rawhide, `centos-stream+epel-next-9`, and `centos-stream-10` (x86_64 + aarch64). The Stream 10 chroots additionally need EPEL 10 as an **external repo** on the project (Settings -> External Repositories): `https://dl.fedoraproject.org/pub/epel/10/Everything/$basearch/`. `BuildRequires: cargo-rpm-macros >= 25` is not in Stream 10's own repos, and Copr has no `+epel-next-10` chroot that would bundle it; without the external repo the build fails with `No matching package to install: 'cargo-rpm-macros >= 25'`. The `+epel-next-9` chroot bundles EPEL already, so it needs nothing extra. See `packaging/fedora/README.md`.
- Launchpad: account + CoC, GPG key registered on Launchpad and published to `keyserver.ubuntu.com`, PPA `ppa:fiorix/sdme`. For SFTP uploads, an SSH key whose public half is registered on the Launchpad account (Change details -> SSH keys); the private key goes in the `LAUNCHPAD_SSH_PRIVATE_KEY` secret. Without it, uploads use anonymous FTP.
- AUR: account at <https://aur.archlinux.org/>, a dedicated passphrase-less ed25519 key with its public half on the account (My Account -> SSH Public Key) and its private half in `AUR_SSH_PRIVATE_KEY`. Each package must be created by a first manual push (pushing to a nonexistent repo is what creates it), after which CI maintains it. Full runbook in `packaging/arch/aur/README.md`.
- GitHub repo secrets: `LAUNCHPAD_GPG_PRIVATE_KEY` (`gpg --armor --export-secret-keys <KEYID>`), `LAUNCHPAD_GPG_PASSPHRASE`, `LAUNCHPAD_SSH_PRIVATE_KEY` (SFTP upload key), `COPR_WEBHOOK` (Copr custom webhook base URL), and `AUR_SSH_PRIVATE_KEY` (AUR push key).
- crates.io token in `~/.cargo/credentials.toml` (for manual `cargo publish`).
