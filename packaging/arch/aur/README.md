# sdme on Arch Linux (AUR)

Two packages, both published to the [AUR](https://aur.archlinux.org/):

- [`sdme-bin`](https://aur.archlinux.org/packages/sdme-bin) installs the prebuilt static binary from the GitHub release. Takes seconds.
- [`sdme`](https://aur.archlinux.org/packages/sdme) builds from source with cargo. Takes a few minutes and needs `rust`.

They conflict with each other; install whichever suits you.

```bash
# With an AUR helper:
yay -S sdme-bin        # or: yay -S sdme

# Without one:
git clone https://aur.archlinux.org/sdme-bin.git
cd sdme-bin && makepkg -si
```

- Arch ships systemd-nspawn and machinectl inside the `systemd` package, so there is no separate `systemd-container` to install as there is on Debian and Fedora.
- sdme requires root on a systemd host.
- CachyOS and other Arch derivatives use the same packages.

The rest of this document is for maintainers.

## Packaging

The AUR has no build service. A package IS a git repo holding a `PKGBUILD` and a `.SRCINFO`, and pushing to it publishes immediately, with nothing validated server-side. So a broken PKGBUILD reaches users the moment it lands, which is why CI test-builds before every push.

- `sdme/PKGBUILD.in`, `sdme-bin/PKGBUILD.in` - templates. The version and checksums are placeholders; nothing here carries a version, because that is what left the old checked-in PKGBUILD stranded at 0.4.0 while the project moved on to 0.14.0.
- `../make-aur-package.sh <pkgbase> [version]` - renders a template into `PKGBUILD` + `.SRCINFO` + `sdme.install`, resolving checksums from the published artifacts. Never pushes.
- `../build-in-container.sh` - renders and `makepkg`-builds both packages in an Arch container, for local testing from a non-Arch host.
- `../sdme.install` - the pacman hook that loads the AppArmor profile. Shared with `../build-pkg.sh` (the `.pkg.tar.zst` on GitHub Releases, which is a different artifact and unrelated to the AUR); `make-aur-package.sh` copies it in, since an AUR repo must be self-contained.

Unlike Launchpad and Copr, nothing is vendored. Those two build in network-less chroots and cannot fetch crates; `makepkg` runs on the user's own machine, so `cargo fetch --locked` in `prepare()` is both possible and the Arch convention. `Cargo.lock` plus `--frozen` gives the same dependency pinning a vendor tarball would.

## Releases (automated)

On a `v*` tag, the `aur` job in `.github/workflows/release.yml` renders both packages from the tag, test-builds each with makepkg, and pushes to the AUR. It needs one repo secret, `AUR_SSH_PRIVATE_KEY` (the private half of a key registered on the AUR account); without it the job renders and builds but skips the push, so forks are unaffected.

The job `needs: release`: `sdme-bin` sources that release's assets, and a release that failed to build is not one to hand to Arch users.

No version bump is needed here for a release. Both packages take the version from the tag.

## Manual build + push (fallback)

```bash
sudo sdme fs import archlinux docker.io/archlinux/archlinux:base
mkdir -p dev/aur-out
sudo sdme new aurbuild -r archlinux \
    -b "$PWD:/src:ro" -b "$PWD/dev/aur-out:/out" \
    -- bash /src/packaging/arch/build-in-container.sh
```

That leaves `dev/aur-out/<pkgbase>/` holding the three files the AUR wants, plus the built package and makepkg's `src/`/`pkg/` scratch. Then, for each package:

```bash
git clone ssh://aur@aur.archlinux.org/sdme.git dev/aur-sdme
cp dev/aur-out/sdme/{PKGBUILD,.SRCINFO,sdme.install} dev/aur-sdme/
cd dev/aur-sdme
git add PKGBUILD .SRCINFO sdme.install
git commit -m "upgpkg: sdme 0.14.0-1"
git push origin HEAD:master
```

`HEAD:master`, not `master`: the AUR only accepts a `master` branch, but the local branch is whatever your `init.defaultBranch` is. Cloning an existing package gives you `master` from the remote, but an empty one (a package that does not exist yet) gives the default, and `git push origin master` then fails with "src refspec master does not match any".

It builds the tagged, released version, not your working tree.

## One-time AUR setup (done; kept for reference)

1. Create an account at <https://aur.archlinux.org/> and accept the terms.
2. Generate a dedicated key (no passphrase, since CI uses it): `ssh-keygen -t ed25519 -f ~/.ssh/aur -C "aur@sdme" -N ""`.
3. Add `~/.ssh/aur.pub` to the account under **My Account** -> SSH Public Key.
4. Pin the host key and point ssh at the key:
   ```
   # ~/.ssh/known_hosts
   aur.archlinux.org ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEuBKrPzbawxA/k2g6NcyV5jmqwJ2s+zpgZGZ7tpLIcN

   # ~/.ssh/config
   Host aur.archlinux.org
     User aur
     IdentityFile ~/.ssh/aur
     IdentitiesOnly yes
   ```
   That is the fingerprint the AUR publishes at <https://aur.archlinux.org/>, so pin it rather than accepting whatever answers on first contact.
5. Check it: `ssh aur@aur.archlinux.org help` prints the command list and "Interactive shell is disabled".
6. Create each package with a first push. Cloning a package that does not exist yet gives an empty repo (git warns; that is how creation works) and the first push creates it, so a typo in the repo name silently creates a different package rather than failing. See the manual fallback above for the commands.
7. `gh secret set AUR_SSH_PRIVATE_KEY < ~/.ssh/aur` so CI can take over from the next tag.

## Notes

- **`options=(!lto)` in `sdme` is load-bearing.** makepkg enables LTO by default (`OPTIONS=(... lto)`, `LTOFLAGS="-flto=auto"`) and the `cc` crate passes those CFLAGS through, so `ring` and `zstd-sys` compile their C to LLVM bitcode that the final rustc link cannot resolve. Without it the build dies on `undefined symbol: ZSTD_freeCCtx` and friends.
- **`options=(!strip !debug)` in `sdme-bin`** keeps the released binary byte-identical to the one `SHA256SUMS` attests to. makepkg strips by default, which rewrites the ELF.
- **`cargo fetch --locked` in `prepare()` deliberately omits `--target`**, unlike the usual Arch Rust recipe. `build.rs` spawns a nested `cargo build --features probe` that does not inherit `--frozen`, so the optional probe deps have to be in the registry cache already.
- **`package()` requires the non-empty probe artifact consumed by `include_bytes!`.** `build.rs` fails the build outright if the probe cannot be embedded; the artifact check remains as a packaging backstop. Binary size is not a reliable proxy because the probe-less binary can still be large.
- **The GitHub tag tarball's sha256 is not contractually stable.** Content is git-tree-stable, but GitHub changed its gzip settings once in 2023 and invalidated checksums everywhere. If that recurs, users hit a checksum mismatch and we re-render with a bumped `pkgrel`. crates.io's tarball is immutable but `cargo publish` is manual and happens after the tag, so it would race the release.
- **Re-pushing the same version needs a `pkgrel` bump**; an identical tree is an empty commit, which the CI job treats as a clean no-op.
- **`sdme-bin` is the only channel that never compiles and never fetches a crate**, which is what to reach for when crates.io is unreachable.
- **The two packages differ on self-upgrade.** `sdme` builds with `SDME_CHANNEL=aur`, so `sdme upgrade` refuses and points at pacman (`channel_is_packaged` in `src/update.rs`). `sdme-bin` repackages the release binary, which is built without a channel and so self-manages; `sdme upgrade` there will overwrite the pacman-owned binary, until the next `pacman -Syu` puts it back. That is the same behaviour as the GitHub-release .deb/.rpm/.pkg.tar.zst, which repackage the same binary. Fixing it would mean baking the channel into the released binaries, which would then disable self-upgrade for `install.sh` users too.
