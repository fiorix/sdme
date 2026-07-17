# sdme on Fedora and CentOS Stream

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
- Builds for Fedora 43, 44, and rawhide, and CentOS Stream 9 and 10 (x86_64 + aarch64).
- sdme requires root on a systemd host.

## CentOS Stream

**Stream 10** works with the commands above; it ships systemd 257, comfortably over the 255 sdme needs.

**Stream 9** ships systemd 252, so `dnf install sdme` refuses with "nothing provides systemd >= 255". That is the packaging doing its job rather than letting sdme fail at runtime. Enable the [CentOS Hyperscale SIG](https://sigs.centos.org/hyperscale/), which rebases systemd to 260.x on 9-stream:

```bash
sudo dnf install centos-release-hyperscale
sudo dnf upgrade systemd     # 252 -> 260.x (.hs.el9); reboot, it is PID 1
sudo dnf copr enable fiorix/sdme
sudo dnf install --setopt=install_weak_deps=False sdme
```

`centos-release-hyperscale` comes from `extras-common`, which Stream enables by default. dnf would also pull the newer systemd in on its own to satisfy sdme's requirement, but doing it as its own step keeps the PID 1 upgrade (and the reboot it wants) separate from installing sdme.

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

### Releases

On a `v*` tag, the `copr` job in `.github/workflows/release.yml` POSTs to the project's custom webhook. The project has an SCM package (build method `make_srpm`) pointed at this repo; `.copr/Makefile` runs `packaging/fedora/make-srpm.sh`, which vendors the crate closure (Copr's SRPM phase has network) and assembles a self-contained SRPM, and Copr builds the RPM offline. Copr builds `main` HEAD, so push `main` before the tag.

Do not hand-edit `Version:`/`Release:`; run `packaging/bump-version.sh X.Y.Z` in the tagged commit. `make-srpm.sh` names the SRPM from the spec but builds `Source0` from the tree, so a spec lagging `Cargo.toml` ships new code under an old version, which is how v0.14.0 reached Copr labelled 0.13.1-1. `packaging/check-versions.sh` now guards that, both here and in the release workflow's `test` job.

Nothing `BuildRequires` systemd and `%check` runs only unit tests, so the CentOS Stream buildroots turn only on the Rust toolchain being present. The `BuildRequires: cargo-rpm-macros >= 25` is the deciding dependency, and where it lives differs by chroot:

- **`centos-stream+epel-next-9`** bundles EPEL, which supplies `cargo-rpm-macros` (Stream 9's AppStream has rust 1.95). Works out of the box.
- **`centos-stream-10`** has `rust`/`cargo` in AppStream but **not** `cargo-rpm-macros`; Copr offers no `+epel-next-10` variant that would. So the Copr project carries EPEL 10 as an external repo:
  ```
  https://dl.fedoraproject.org/pub/epel/10/Everything/$basearch/
  ```
  Set under Copr -> the project -> Settings -> External Repositories. Without it the build fails at dependency install with `No matching package to install: 'cargo-rpm-macros >= 25'`, which is what happened to the first v0.15.0 build. This is a buildroot concern only; users installing the prebuilt RPM need no external repo.

Hyperscale (see the CentOS Stream section above) is likewise a runtime concern for users, not a buildroot one.

Manual fallback: `copr-cli build sdme dev/fedora-out/sdme-*.src.rpm`, or the **Rebuild** button on the Copr package page (builds the default branch).

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
