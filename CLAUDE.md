# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

sdme is a lightweight systemd-nspawn container manager with overlayfs. It produces a single binary `sdme` that manages containers from explicit root filesystems, keeping the base rootfs untouched via overlayfs copy-on-write.

Runs on Linux with systemd. Requires root for all operations. Uses kernel overlayfs for copy-on-write storage. By default, containers are overlayfs clones of `/`. Also supports importing rootfs from other distros (Ubuntu, Debian, Fedora, NixOS). Imported rootfs needs systemd and dbus.

## Build & Test

```bash
cargo build --release       # build the binary
cargo test                  # run all tests
cargo test <test_name>      # run a single test
make                        # same as cargo build --release
sudo make install           # install to /usr/local (does NOT rebuild)
```

### Release

Static musl binaries (x86_64 + aarch64) are built with `cargo-zigbuild`. Locally:

```bash
./scripts/build-release.sh            # build all targets to target/dist/
./scripts/build-release.sh -v <target> # build one target, verbose
```

CI: pushing a `v*` tag triggers `.github/workflows/release.yml`, which runs tests, cross-compiles both targets, generates SHA256SUMS, and creates a GitHub release with all artifacts.

## Architecture

The project is a single Rust binary (`src/main.rs`) backed by a shared library (`src/lib.rs`). CLI parsing uses clap with derive.

### Core Concepts

- **Overlayfs CoW storage**: each container gets `upper/work/merged/shared` directories under the datadir. The lower layer is the imported rootfs. Uses kernel overlayfs.
- **Systemd integration**: containers are managed as a systemd template unit (`sdme@.service`). Start goes through D-Bus to systemd. The template unit is auto-installed and auto-updated when content changes.
- **machinectl integration**: `join` and `exec` use `machinectl shell` for container interaction. `stop` uses D-Bus (`TerminateMachine`).
- **DNS resolution**: containers share the host's network namespace. `systemd-resolved` is masked in the overlayfs upper layer at creation time so the host's resolver handles DNS. A placeholder `/etc/resolv.conf` regular file is written so `systemd-nspawn --resolv-conf=auto` can populate it at boot.
- **State files**: container metadata persisted as KEY=VALUE files under `{datadir}/state/{name}`.
- **Health checks**: `sdme ps` detects broken containers (missing dirs, missing rootfs) and reports health status with OS detection via os-release.
- **Conflict detection**: prevents name collisions with existing containers and `/var/lib/machines/`.

### CLI Commands

| Command | Description |
|---------|-------------|
| `sdme new` | Create, start, and enter a new container |
| `sdme create` | Create a new container (overlayfs dirs + state file) |
| `sdme start` | Start a container (installs/updates template unit, starts via D-Bus) |
| `sdme join` | Enter a running container (`machinectl shell`) |
| `sdme exec` | Run a one-off command in a running container (`machinectl shell`) |
| `sdme stop` | Stop one or more running containers (D-Bus `TerminateMachine`) |
| `sdme rm` | Remove containers (stops if running, deletes state + files) |
| `sdme ps` | List containers with status, health, OS, and shared directory |
| `sdme logs` | View container logs (exec's `journalctl`) |
| `sdme fs import` | Import a rootfs from a directory, tarball, URL, OCI image, or QCOW2 disk image |
| `sdme fs ls` | List imported root filesystems |
| `sdme fs rm` | Remove imported root filesystems |
| `sdme fs build` | Build a root filesystem from a build config |
| `sdme set` | Set resource limits on a container (replaces all limits) |
| `sdme config get/set` | View or modify configuration |
| `sdme completions` | Generate shell completions (Bash, Fish, Zsh) |

### Key Modules

| File | Purpose |
|------|---------|
| `src/main.rs` | CLI entry point (clap derive), command dispatch |
| `src/lib.rs` | Shared types: `State` (KEY=VALUE), `validate_name`, `sudo_user`, global interrupt handler (`INTERRUPTED`, `check_interrupted`, `install_interrupt_handler`) |
| `src/containers.rs` | Container create/remove/join/exec/stop/list, overlayfs directory management, DNS setup |
| `src/systemd.rs` | D-Bus helpers (start/status/stop), template unit generation, env files, boot/shutdown waiting |
| `src/system_check.rs` | Version checks (systemd), dependency checks (`find_program`) |
| `src/rootfs.rs` | Rootfs listing, removal, os-release parsing, distro detection |
| `src/import/mod.rs` | Rootfs import orchestration: source detection, URL download (with proxy support), systemd detection |
| `src/import/dir.rs` | Directory-based rootfs import |
| `src/import/tar.rs` | Tarball extraction with magic-byte compression detection |
| `src/import/oci.rs` | OCI container image layer extraction and whiteout handling |
| `src/import/registry.rs` | OCI registry pulling via Distribution Spec (docker.io, quay.io, etc.) |
| `src/import/img.rs` | QCOW2 and raw disk image import via qemu-nbd |
| `src/names.rs` | Container name generation from a Tupi-Guarani wordlist with collision avoidance |
| `src/config.rs` | Config file loading/saving (`~/.config/sdme/sdmerc`) |
| `src/build.rs` | Build config parsing and rootfs build execution |
| `src/copy.rs` | Filesystem tree copying with xattr and special file support |
| `src/mounts.rs` | Bind mount (`BindConfig`) and environment variable (`EnvConfig`) configuration |
| `src/network.rs` | Network configuration validation and state serialization |

### Rust Dependencies

- `clap` — CLI parsing (derive)
- `zbus` — D-Bus communication with systemd (blocking API)
- `libc` — syscalls for rootfs import (lchown, mknod, etc.)
- `anyhow` — error handling
- `serde`/`toml` — config file parsing
- `tar` — archive extraction with xattr support
- `flate2` — gzip decompression
- `bzip2` — bzip2 decompression
- `xz2` — xz/lzma decompression
- `zstd` — zstd decompression
- `serde_json` — JSON parsing (OCI image manifests)
- `ureq` — HTTP client for URL downloads and OCI registry pulling (blocking, rustls TLS)
- `sha2` — SHA-256 hashing (OCI digest verification)
- `clap_complete` — Shell completion generation (Bash, Fish, Zsh)

### External Dependencies

| Program | Package | Required for |
|---------|---------|--------------|
| `systemd` (>= 252) | `systemd` | All commands (D-Bus communication) |
| `systemd-nspawn` | `systemd-container` | Running containers |
| `machinectl` | `systemd-container` | `sdme join`, `sdme exec`, `sdme new` |
| `journalctl` | `systemd` | `sdme logs` |
| `qemu-nbd` | `qemu-utils` | `sdme fs import` (QCOW2 images only) |

Dependencies are checked at runtime before use via `system_check::check_dependencies()`, which resolves each binary in PATH and prints the resolved path with `-v`.

## Design Decisions

- **Root-only**: sdme requires root (`euid == 0`). Checked at program start.
- **Datadir**: always `/var/lib/sdme`.
- **Container management**: `join` and `exec` spawn `machinectl shell` as a child process and forward the exit status; `stop` uses D-Bus (`TerminateMachine`) for clean shutdown.
- **D-Bus**: used for `start_unit`, `daemon_reload`, `is_unit_active`, `get_systemd_version`, `terminate_machine`. Always system bus.
- **Rootfs import sources**: `sdme fs import` auto-detects the source type: URL prefix (`http://`/`https://`) → download + tarball extraction; existing directory → directory copy; QCOW2 disk image (magic bytes `QFI\xfb`) → mount via `qemu-nbd` + copy filesystem tree; existing file → tarball extraction via native Rust crates (`tar`, `flate2`, `bzip2`, `xz2`, `zstd`) with magic-byte compression detection. OCI container images (`.oci.tar.xz`, etc.) are auto-detected after tarball extraction by checking for an `oci-layout` file; the manifest chain is walked and filesystem layers are extracted in order with whiteout marker handling. QCOW2 import loads the `nbd` kernel module, connects the image read-only via `qemu-nbd`, discovers partitions via `/sys/block/`, mounts the largest partition, and copies the tree using the same `copy_tree()` used for directory imports. After import, systemd is detected in the rootfs; if missing, distro-specific packages are installed via chroot (`--install-packages` flag controls this: `auto` prompts interactively, `yes` always installs, `no` refuses if systemd is absent).
- **HTTP proxy support**: URL downloads in `sdme fs import` respect the standard proxy environment variables: `https_proxy`, `HTTPS_PROXY`, `http_proxy`, `HTTP_PROXY`, `all_proxy`, `ALL_PROXY` (first non-empty wins, in that order). `no_proxy`/`NO_PROXY` is also supported. The proxy is configured explicitly via `ureq::Proxy` in `build_http_agent()` (`src/import/mod.rs`), with verbose logging of the selected proxy URI. Since sdme runs as root, users must pass proxy variables through sudo (e.g. `sudo -E` or `sudo https_proxy=... sdme ...`).
- **Rootfs patching at import**: `sdme fs import` patches imported rootfs images for nspawn compatibility: `systemd-resolved` is masked (containers share the host's network namespace and cannot bind 127.0.0.53), `systemd-logind` is unmasked if masked (some OCI images like CentOS/AlmaLinux mask it, but sdme needs logind for `machinectl shell`), and missing packages required by `machinectl shell` (e.g. `util-linux`, `pam` on RHEL-family) are installed via chroot. For host-rootfs containers (no `-r`), `systemd-resolved` is masked in the overlayfs upper layer during `create` instead. A regular-file placeholder `/etc/resolv.conf` is written in the upper layer so `systemd-nspawn --resolv-conf=auto` can populate it at boot.
- **Opaque dirs**: the `-o` / `--overlayfs-opaque-dirs` flag on `create`/`new` marks directories as opaque in the overlayfs upper layer (sets `trusted.overlay.opaque` xattr to `y`), hiding lower-layer contents. For host-rootfs containers (no `-r`), the `host_rootfs_opaque_dirs` config value is applied when no `-o` flags are given (default: `/etc/systemd/system,/var/log`). Paths are validated and normalized by `containers::validate_opaque_dirs()` — must be absolute, no `..`, no duplicates. The merge logic lives in `resolve_opaque_dirs()` in `main.rs`. Set the config to an empty string to disable defaults.
- **Umask check**: `containers::create()` refuses to proceed when the process umask strips read or execute from "other" (`umask & 005 != 0`). A restrictive umask causes files in the overlayfs upper layer to be inaccessible to non-root services (e.g. dbus-daemon as `messagebus`), preventing boot.
- **Bind mounts and env vars**: the `-b`/`--bind` and `-e`/`--env` flags on `create`/`new` add custom bind mounts and environment variables to containers. Configuration is stored in the container's state file and converted to systemd-nspawn flags at start time. Bind mounts are validated (absolute paths, no `..` components). Managed by `BindConfig` and `EnvConfig` in `src/mounts.rs`.
- **OCI registry pulling**: `sdme fs import` supports pulling directly from OCI registries (e.g. `docker.io/ubuntu:24.04`, `quay.io/fedora/fedora`). Implements the OCI Distribution Spec in `src/import/registry.rs` — resolves tags to manifests, walks manifest lists for architecture matching, downloads and extracts layers. Supports `--oci-mode` and `--base-fs` for running OCI application images as systemd services.
- **Interrupt handling**: a global `INTERRUPTED` flag (`src/lib.rs`) and a POSIX signal handler (`libc::sigaction` for `SIGINT`) are installed once in `main()`. Both `sdme fs import` and the boot-wait loops (`wait_for_boot`, `wait_for_dbus`) check this flag, allowing Ctrl+C to cancel long-running operations cleanly. The handler restores the default SIGINT disposition after the first press, so a second Ctrl+C force-kills the process. This handles cases where Rust's stdlib retries `poll()`/`connect()` on EINTR, preventing cooperative cancellation during blocked network connections.
- **Build COPY restrictions**: `sdme fs build` COPY writes directly to the overlayfs upper layer while the container is stopped. Destinations under directories that systemd mounts tmpfs over at boot (`/tmp`, `/run`, `/dev/shm`) are rejected because the tmpfs would hide the copied files in the running container. Destinations under overlayfs opaque directories are also rejected. The validation is in `check_shadowed_dest()` in `src/build.rs`. Errors include the config file path and line number (e.g. `build.sdme:2: COPY to /tmp is not supported: ...`), tracked via the `lineno` field on each `BuildOp` variant.
- **Boot failure cleanup**: `sdme new` removes the just-created container on boot failure, join failure, or Ctrl+C. `sdme start` stops the container on boot failure or Ctrl+C (preserving it on disk for debugging).
- **Input sanitization**: since sdme runs as root and handles untrusted input (tarballs, OCI images, QCOW2 files, URLs), several hardening measures are in place:
  - OCI layer tar paths are sanitized before whiteout handling — `..` components are rejected and leading `/` is stripped — to prevent path traversal that could escape the destination directory (`sanitize_tar_path()` in `import/oci.rs`).
  - OCI digest fields (`algo:hash`) are validated to contain only safe characters (alphanumeric/hex) before being used to construct blob paths, preventing directory traversal via malicious manifests (`resolve_blob()` in `import/oci.rs`).
  - The `--rootfs`/`-r` parameter is validated with `validate_name()` before being used to construct filesystem paths, preventing directory traversal via names like `../state` (`resolve_rootfs()` in `containers.rs`).
  - Opaque directory paths (`-o` flags and `host_rootfs_opaque_dirs` config) are validated by `containers::validate_opaque_dirs()` — must be absolute, no `..` components, no empty strings, no duplicates. Paths are normalized (trailing slashes stripped) before storage. The `config set` handler also normalizes the stored value.
  - URL downloads are capped at 50 GiB (`MAX_DOWNLOAD_SIZE` in `import/mod.rs`) to prevent disk exhaustion from malicious or misbehaving servers.
  - Config files are written with explicit permissions (`0o600` for files, `0o700` for directories) rather than inheriting umask (`config.rs`).
