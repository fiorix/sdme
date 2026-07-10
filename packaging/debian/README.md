# sdme on Ubuntu (Launchpad PPA)

Available from the PPA:

```bash
sudo add-apt-repository ppa:fiorix/sdme
sudo apt update
sudo apt install sdme
```

- **Ubuntu 26.04 (resolute) or newer only.** A vendored dependency uses Rust edition 2024 (needs `rustc >= 1.85`), so 24.04 LTS (rustc 1.75-1.80) cannot build it. Launchpad builds against each series' packaged rustc, offline.
- sdme requires root on a systemd host.

The rest of this document is for maintainers.

## Packaging

Vendored source package (Ubuntu does not have all crate deps as `librust-*-dev`).

- `debian/` - the source package (control, rules, changelog, copyright, ...). Builds fully offline against `debian/vendor.tar.xz`; `build.rs` builds and strips the embedded probe (installed binary ~12M).
- `make-source-package.sh <version>` - assembles the unsigned Debian **source** package for a version (vendored, changelog templated from the tag). Used by CI.
- `build-in-container.sh` - builds the source **and** binary package in a clean Ubuntu container, for local testing/smoke.

## Releases (automated)

On a `v*` tag, the `launchpad` job in `.github/workflows/release.yml` builds the source package (`make-source-package.sh`, version from the tag), GPG-signs it, and `dput`s it to `ppa:fiorix/sdme`; Launchpad then builds amd64 + arm64. It requires two repo secrets:

- `LAUNCHPAD_GPG_PRIVATE_KEY` - armored export of the GPG key registered on Launchpad (`gpg --armor --export-secret-keys <KEYID>`).
- `LAUNCHPAD_GPG_PASSPHRASE` - that key's passphrase.

Bump the version for a release in `Cargo.toml` and `packaging/fedora/sdme.spec`; the Debian changelog is templated from the tag, so it does not need a manual bump for CI.

## Manual build + upload (fallback)

Requires an Ubuntu 26.04 sdme rootfs (or a host clone on 26.04) and `sudo apt install dput devscripts dpkg-dev`.

```bash
mkdir -p dev/deb-out
sudo sdme new debbuild -r ubuntu \
    -b "$PWD:/src:ro" -b "$PWD/dev/deb-out:/out" \
    -- bash /src/packaging/debian/build-in-container.sh
debsign -k <KEYID> dev/deb-out/sdme_*_source.changes
dput ppa:fiorix/sdme dev/deb-out/sdme_*_source.changes
```

`build-in-container.sh` builds the published crate by default (`-e SDME_SRC_SOURCE=local` for the working tree), runs as a non-root `builder` (matching Launchpad's unprivileged buildd, so `cargo test` passes), and leaves unsigned artifacts in `dev/deb-out/`.

## One-time Launchpad setup (done; kept for reference)

1. Create a Launchpad account and accept the ToS + Ubuntu Code of Conduct.
2. Generate a GPG key and register it on Launchpad: `gpg --full-generate-key`, publish it (`gpg --keyserver keyserver.ubuntu.com --send-keys <KEYID>`), add the fingerprint at <https://launchpad.net/~/+editpgpkeys>, and decrypt the confirmation email. Sign the CoC with the key.
3. Create the PPA `ppa:fiorix/sdme`.
4. Add the two GitHub repo secrets above so CI can sign + upload.

## Notes

- **Target Ubuntu 26.04 only** for now (edition-2024 deps need `rustc >= 1.85`; 24.04 LTS is out). Adding a newer series later means teaching `make-source-package.sh` that series' name.
- The vendor tarball ships as `debian/vendor.tar.xz`, whitelisted in `debian/source/include-binaries`; the Launchpad build runs fully offline.
- The AppArmor profile (`/etc/apparmor.d/sdme-default`) is shipped and loaded by the `postinst`, since Ubuntu uses AppArmor (Fedora, which uses SELinux, omits it).
- `systemd-container` is a hard `Depends` - sdme is useless without systemd-nspawn/machinectl.
- Each Launchpad upload needs a unique version; the CI names it `<version>-1~resolute1`. Re-uploading the same version (e.g. a packaging-only fix) needs a bumped `~resolute<N>` suffix.
