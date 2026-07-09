# Packaging sdme for Fedora

sdme is a leaf Rust application. Its transitive crate dependencies are
**vendored** (bundled into the SRPM as a tarball) rather than packaged as
individual `rust-*` crates. The Fedora Rust Packaging Guidelines allow
vendoring for applications, and it is the only practical option here given the
dependency count.

Files:

- `sdme.spec` - source-building spec with vendored dependencies.
- `build-in-container.sh` - builds the SRPM + RPM in a clean Fedora env.

## Local build (Fedora container)

Requires the sdme Fedora rootfs (`sudo sdme fs import fedora quay.io/fedora/fedora`).

```bash
sudo mkdir -p dev/fedora-out
sudo sdme new fedbuild -r fedora \
    -b "$PWD:/src:ro" -b "$PWD/dev/fedora-out:/out" \
    -- bash /src/packaging/fedora/build-in-container.sh
```

By default the script builds the **published** crate: it fetches `Source0`
from crates.io (matching the spec's `%{crates_source}`) and vendors from that
crate's `Cargo.lock`, so the SRPM is exactly what COPR / official Fedora would
build. To test unreleased working-tree changes instead, pass
`-e SDME_SRPM_SOURCE=local` on the `sdme new` line (builds `git archive HEAD`;
not a valid official artifact since the source is not on crates.io).

Artifacts land in `dev/fedora-out/`: the binary RPM, the SRPM, the vendor
tarball, and the spec. Install and smoke-test:

```bash
sudo dnf install ./dev/fedora-out/sdme-*.x86_64.rpm
sdme --version
```

## Track 1: COPR (fast, no gatekeeping)

COPR builds your SRPM and serves it as a dnf repo. No package review, no
sponsor. This is the recommended first step and validates the spec in Fedora's
build system (the same mock stack Koji uses).

1. Log in at <https://copr.fedorainfracloud.org/> with your FAS account.
2. Create project `sdme` (enable the Fedora releases and arches you want).
3. Upload the SRPM built above:

   ```bash
   dnf install copr-cli            # inside Fedora
   # configure ~/.config/copr with the API token from the COPR web UI
   copr-cli build sdme ./dev/fedora-out/sdme-*.src.rpm
   ```

   Or point COPR at the git repo (SCM method) with spec path
   `packaging/fedora/sdme.spec` and let it build on tag/commit.
4. Users then:

   ```bash
   sudo dnf copr enable fiorix/sdme
   sudo dnf install sdme
   ```

## Track 2: official Fedora (dnf install sdme)

Gets sdme into the base Fedora repositories. Slower: requires package review
and, as a first-time packager, a **sponsor**.

1. Generate/refresh the canonical spec with the blessed tool on Fedora:

   ```bash
   dnf install rust2rpm
   # rust2rpm's vendor mode produces the vendor tarball + Provides:
   # bundled(crate(...)) and a license summary. Reconcile its output with
   # sdme.spec here (in particular the embedded probe build in build.rs).
   ```
2. Compute the combined SPDX license expression over the vendored tree with
   `%cargo_license` and set it as the spec's `License:` tag.
3. Switch `Release:` to `%autorelease` and the changelog to `%autochangelog`
   (rpmautospec) for dist-git.
4. File a Review Request on Red Hat Bugzilla, component **Package Review**.
   As a new packager, make the bug block **FE-NEEDSPONSOR** (bug 177841) to
   request a sponsor. Link the COPR build as evidence it builds cleanly.
5. After approval: request the repo in Fedora dist-git (Pagure), import,
   build in Koji, and push updates via Bodhi.

References:

- Rust Packaging Guidelines: <https://docs.fedoraproject.org/en-US/packaging-guidelines/Rust/>
- Review process: <https://docs.fedoraproject.org/en-US/package-maintainers/Package_Review_Process/>
- Sponsor policy: <https://docs.fedoraproject.org/en-US/package-maintainers/How_to_Sponsor_a_New_Contributor/>
- COPR user docs: <https://docs.pagure.org/copr.copr/user_documentation.html>

## Notes

- `Source0` uses `%{crates_source}` (the crates.io release tarball), so the
  default `crates` build needs no git tag. `rust2rpm sdme` also generates a
  canonical spec from the published crate you can diff against this one.
- The build runs `rpmbuild` as a non-root `builder` user (as mock/Koji do) and
  runs the unit tests in `%check`. build.rs strips the embedded probe, keeping
  the installed binary small (~11M rather than ~52M).
- No AppArmor asset: Fedora uses SELinux, so shipping `/etc/apparmor.d/...`
  would be a no-op and would draw review scrutiny.
