# sdme on Ubuntu (Launchpad PPA)

Once the PPA is published:

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
- `build-in-container.sh` - assembles the source + binary package in a clean Ubuntu container.

## One-time Launchpad setup

1. Create a Launchpad account and accept the ToS + Ubuntu Code of Conduct.
2. Generate a GPG key and register it on Launchpad:
   ```bash
   gpg --full-generate-key
   gpg --keyserver keyserver.ubuntu.com --send-keys <KEYID>
   # then paste the fingerprint at https://launchpad.net/~/+editpgpkeys and
   # decrypt the confirmation email to finish; sign the Code of Conduct too.
   ```
3. Create the PPA on your Launchpad page ("Create a new PPA"), name it `sdme` -> `ppa:fiorix/sdme`.
4. Install upload tools: `sudo apt install dput devscripts dpkg-dev`.

## Build the source package

Requires an Ubuntu 26.04 sdme rootfs (or a host clone on 26.04).

```bash
mkdir -p dev/deb-out
sudo sdme new debbuild -r ubuntu \
    -b "$PWD:/src:ro" -b "$PWD/dev/deb-out:/out" \
    -- bash /src/packaging/debian/build-in-container.sh
```

By default it builds the **published** crate from crates.io; pass `-e SDME_SRC_SOURCE=local` to build the working tree. It installs the toolchain, drops to a non-root `builder` (matching Launchpad's unprivileged buildd, so `cargo test` passes), and produces unsigned artifacts in `dev/deb-out/`.

## Sign and upload

```bash
debsign -k <KEYID> dev/deb-out/sdme_*_source.changes
dput ppa:fiorix/sdme dev/deb-out/sdme_*_source.changes
```

Launchpad then builds the binaries (amd64 + arm64) and publishes the repo.

## Notes

- **Target Ubuntu 26.04 only** for now (edition-2024 deps need `rustc >= 1.85`; 24.04 LTS is out). Adding a newer series later means another changelog entry and upload with that series' distribution.
- The vendor tarball ships as `debian/vendor.tar.xz`, whitelisted in `debian/source/include-binaries`; the Launchpad build runs fully offline.
- The AppArmor profile (`/etc/apparmor.d/sdme-default`) is shipped and loaded by the `postinst`, since Ubuntu uses AppArmor (Fedora, which uses SELinux, omits it).
- `systemd-container` is a hard `Depends` - sdme is useless without systemd-nspawn/machinectl.
- New release: bump `debian/changelog` (upstream version + a fresh `~resolute<N>` revision; each Launchpad upload needs a unique version) and rebuild.
