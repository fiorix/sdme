# sdme on Fedora

sdme is available from a Copr repository:

```bash
sudo dnf copr enable fiorix/sdme
sudo dnf install --setopt=install_weak_deps=False sdme
```

`--setopt=install_weak_deps=False` is optional but recommended: it keeps the install to sdme and systemd-container (~5 MiB). Without it, dnf also installs weak dependencies, and Fedora's systemd-container package Recommends qemu-kvm-core (for systemd-vmspawn), which pulls in the qemu system emulator stack (~40 packages). sdme does not use qemu for container operations, and weak dependencies skipped at install time are not added back by upgrades.

To import QCOW2 disk images, also install qemu-img (provides qemu-nbd):

```bash
sudo dnf install qemu-img
```

- Copr project: <https://copr.fedorainfracloud.org/coprs/fiorix/sdme/>
- Builds for Fedora 43, 44, and rawhide (x86_64 + aarch64).
- sdme requires root on a systemd host.

The rest of this document is for maintainers.

## Packaging

sdme is a leaf Rust application; its crate dependencies are **vendored**
(bundled into the SRPM) rather than packaged as individual `rust-*` crates,
which the Fedora Rust Packaging Guidelines allow for applications.

- `sdme.spec` - source-building spec with vendored dependencies.
- `build-in-container.sh` - builds the SRPM + RPM in a clean Fedora env.

### Build the RPM locally

Requires the sdme Fedora rootfs (`sudo sdme fs import fedora quay.io/fedora/fedora`).

```bash
sudo mkdir -p dev/fedora-out
sudo sdme new fedbuild -r fedora \
    -b "$PWD:/src:ro" -b "$PWD/dev/fedora-out:/out" \
    -- bash /src/packaging/fedora/build-in-container.sh
```

By default the script builds the **published** crate (fetches `Source0` from
crates.io, matching `%{crates_source}`); pass `-e SDME_SRPM_SOURCE=local` to
build the working tree instead. It runs `rpmbuild` as a non-root `builder`
(as mock/Koji do), runs the unit tests in `%check`, and strips the embedded
probe so the installed binary stays small (~11M). Artifacts land in
`dev/fedora-out/`; smoke-test with
`sudo dnf install ./dev/fedora-out/sdme-*.x86_64.rpm && sdme --version`.

### Update the Copr repo on a new release

```bash
copr-cli build sdme dev/fedora-out/sdme-*.src.rpm
```

Or configure the Copr project's SCM/Package method to point at the git repo
with spec `packaging/fedora/sdme.spec` and build automatically on new tags.

### Official Fedora (base repos, no Copr)

Getting `dnf install sdme` from stock Fedora requires package review and, as a
first-time packager, a sponsor:

1. Generate/refresh a canonical spec with `rust2rpm` (vendor mode) and reconcile
   it with `sdme.spec` (in particular the embedded probe build in `build.rs`).
2. Set the `License:` tag to the combined SPDX expression `%cargo_license`
   computes over the vendored tree.
3. Switch `Release:` to `%autorelease` and the changelog to `%autochangelog`
   for dist-git.
4. File a Review Request on Red Hat Bugzilla (component **Package Review**) and,
   as a new packager, block **FE-NEEDSPONSOR** (bug 177841). Link the Copr
   build as evidence it builds cleanly.
5. After approval: request the repo in dist-git (Pagure), import, build in Koji,
   push updates via Bodhi.

References:

- Rust Packaging Guidelines: <https://docs.fedoraproject.org/en-US/packaging-guidelines/Rust/>
- Review process: <https://docs.fedoraproject.org/en-US/package-maintainers/Package_Review_Process/>
- Sponsor policy: <https://docs.fedoraproject.org/en-US/package-maintainers/How_to_Sponsor_a_New_Contributor/>
- Copr user docs: <https://docs.pagure.org/copr.copr/user_documentation.html>

## Notes

- `Source0` uses `%{crates_source}` (the crates.io release tarball), so the
  default build needs no git tag. `rust2rpm sdme` also generates a canonical
  spec from the published crate you can diff against this one.
- The build runs `rpmbuild` as a non-root `builder` user (as mock/Koji do) and
  runs the unit tests in `%check`. `build.rs` strips the embedded probe.
- No AppArmor asset: Fedora uses SELinux, so shipping `/etc/apparmor.d/...`
  would be a no-op and draw review scrutiny. (The Debian package does ship one.)
