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

### Key Modules

| File | Purpose |
|------|---------|
| `src/main.rs` | CLI entry point (clap derive), command dispatch |
| `src/lib.rs` | Shared types: `State` (KEY=VALUE), `validate_name`, `sudo_user`, global interrupt handler (`INTERRUPTED`, `check_interrupted`, `install_interrupt_handler`) |
| `src/containers.rs` | Container create/remove/join/exec/stop/list, overlayfs directory management, DNS setup |
| `src/systemd.rs` | D-Bus helpers (start/status/stop), template unit generation, env files, boot/shutdown waiting |
| `src/system_check.rs` | Version checks (systemd), dependency checks (`find_program`) |
| `src/rootfs.rs` | Rootfs listing, removal, os-release parsing, distro detection |
| `src/import.rs` | Rootfs import: directory copy, tarball extraction, URL download (with proxy support), OCI image extraction, QCOW2 disk image import |
| `src/names.rs` | Container name generation from a Tupi-Guarani wordlist with collision avoidance |
| `src/config.rs` | Config file loading/saving (`~/.config/sdme/sdmerc`) |
| `src/build.rs` | Build config parsing and rootfs build execution |
| `src/copy.rs` | Filesystem tree copying with xattr and special file support |
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
- `ureq` — HTTP client for URL downloads (blocking, rustls TLS)
- `ctrlc` — SIGINT handling for graceful cancellation (import and boot-wait)
- `sha2` — SHA-256 hashing (dev-dependency, used in OCI tests)

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
- **Container management**: `join` and `exec` use `machinectl shell`; `stop` uses D-Bus (`TerminateMachine`) for clean shutdown.
- **D-Bus**: used for `start_unit`, `daemon_reload`, `is_unit_active`, `get_systemd_version`, `terminate_machine`. Always system bus.
- **Rootfs import sources**: `sdme fs import` auto-detects the source type: URL prefix (`http://`/`https://`) → download + tarball extraction; existing directory → directory copy; QCOW2 disk image (magic bytes `QFI\xfb`) → mount via `qemu-nbd` + copy filesystem tree; existing file → tarball extraction via native Rust crates (`tar`, `flate2`, `bzip2`, `xz2`, `zstd`) with magic-byte compression detection. OCI container images (`.oci.tar.xz`, etc.) are auto-detected after tarball extraction by checking for an `oci-layout` file; the manifest chain is walked and filesystem layers are extracted in order with whiteout marker handling. QCOW2 import loads the `nbd` kernel module, connects the image read-only via `qemu-nbd`, discovers partitions via `/sys/block/`, mounts the largest partition, and copies the tree using the same `copy_tree()` used for directory imports. After import, systemd is detected in the rootfs; if missing, distro-specific packages are installed via chroot (`--install-packages` flag controls this: `auto` prompts interactively, `yes` always installs, `no` refuses if systemd is absent).
- **HTTP proxy support**: URL downloads in `sdme fs import` respect the standard proxy environment variables: `https_proxy`, `HTTPS_PROXY`, `http_proxy`, `HTTP_PROXY`, `all_proxy`, `ALL_PROXY` (first non-empty wins, in that order). `no_proxy`/`NO_PROXY` is also supported. The proxy is configured explicitly via `ureq::Proxy` in `build_http_agent()` (`src/import.rs`), with verbose logging of the selected proxy URI. Since sdme runs as root, users must pass proxy variables through sudo (e.g. `sudo -E` or `sudo https_proxy=... sdme ...`).
- **DNS in containers**: containers share the host's network namespace (by default; `--private-network` enables isolation). `systemd-resolved` is masked in the overlayfs upper layer during `create` so the container's NSS `resolve` module returns UNAVAIL, falling through to the `dns` module which queries the host's resolver via `/etc/resolv.conf`. A regular-file placeholder is written to shadow any rootfs symlink so `systemd-nspawn --resolv-conf=auto` can populate it at boot.
- **Opaque dirs**: the `-o` / `--overlayfs-opaque-dirs` flag on `create`/`new` marks directories as opaque in the overlayfs upper layer (sets `trusted.overlay.opaque` xattr to `y`), hiding lower-layer contents. For host-rootfs containers (no `-r`), the `host_rootfs_opaque_dirs` config value is applied when no `-o` flags are given (default: `/etc/systemd/system,/var/log`). Paths are validated and normalized by `containers::validate_opaque_dirs()` — must be absolute, no `..`, no duplicates. The merge logic lives in `resolve_opaque_dirs()` in `main.rs`. Set the config to an empty string to disable defaults.
- **Umask check**: `containers::create()` refuses to proceed when the process umask strips read or execute from "other" (`umask & 005 != 0`). A restrictive umask causes files in the overlayfs upper layer to be inaccessible to non-root services (e.g. dbus-daemon as `messagebus`), preventing boot.
- **Interrupt handling**: a global `INTERRUPTED` flag (`src/lib.rs`) and `ctrlc` handler are installed once in `main()`. Both `sdme fs import` and the boot-wait loops (`wait_for_boot`, `wait_for_dbus`) check this flag, allowing Ctrl+C to cancel long-running operations cleanly.
- **Boot failure cleanup**: `sdme new` removes the just-created container on boot failure or Ctrl+C. `sdme start` stops the container on boot failure or Ctrl+C (preserving it on disk for debugging).
- **Input sanitization**: since sdme runs as root and handles untrusted input (tarballs, OCI images, QCOW2 files, URLs), several hardening measures are in place:
  - OCI layer tar paths are sanitized before whiteout handling — `..` components are rejected and leading `/` is stripped — to prevent path traversal that could escape the destination directory (`sanitize_tar_path()` in `import.rs`).
  - OCI digest fields (`algo:hash`) are validated to contain only safe characters (alphanumeric/hex) before being used to construct blob paths, preventing directory traversal via malicious manifests (`resolve_blob()` in `import.rs`).
  - The `--rootfs`/`-r` parameter is validated with `validate_name()` before being used to construct filesystem paths, preventing directory traversal via names like `../state` (`resolve_rootfs()` in `containers.rs`).
  - Opaque directory paths (`-o` flags and `host_rootfs_opaque_dirs` config) are validated by `containers::validate_opaque_dirs()` — must be absolute, no `..` components, no empty strings, no duplicates. Paths are normalized (trailing slashes stripped) before storage. The `config set` handler also normalizes the stored value.
  - URL downloads are capped at 50 GiB (`MAX_DOWNLOAD_SIZE` in `import.rs`) to prevent disk exhaustion from malicious or misbehaving servers.
  - Config files are written with explicit permissions (`0o600` for files, `0o700` for directories) rather than inheriting umask (`config.rs`).
