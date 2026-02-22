# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

sdme is a rewrite of [devctl](https://github.com/fiorix/devctl) — lightweight systemd-nspawn containers with overlayfs. It produces a single binary `sdme` that manages containers from explicit root filesystems, keeping the base rootfs untouched via overlayfs copy-on-write.

Runs on Linux with systemd. Requires root for all operations. Uses kernel overlayfs and `machinectl` for container management.

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
- **machinectl integration**: `join`, `exec`, and `stop` use `machinectl shell` and `machinectl poweroff` for container interaction.
- **State files**: container metadata persisted as KEY=VALUE files under `{datadir}/state/{name}`.
- **Health checks**: `sdme ps` detects broken containers (missing dirs, missing rootfs) and reports health status.
- **Conflict detection**: prevents name collisions with existing containers and `/var/lib/machines/`.

### CLI Commands

| Command | Description |
|---------|-------------|
| `sdme new` | Create, start, and enter a new container |
| `sdme create` | Create a new container (overlayfs dirs + state file) |
| `sdme start` | Start a container (installs/updates template unit, starts via D-Bus) |
| `sdme join` | Enter a running container (`machinectl shell`) |
| `sdme exec` | Run a one-off command in a running container (`machinectl shell`) |
| `sdme stop` | Stop a running container (`machinectl poweroff`) |
| `sdme rm` | Remove containers (stops if running, deletes state + files) |
| `sdme ps` | List containers with status, health, and shared directory |
| `sdme logs` | View container logs (exec's `journalctl`) |
| `sdme rootfs import` | Import a rootfs from a directory, tarball, URL, OCI image, or QCOW2 disk image |
| `sdme rootfs ls` | List imported root filesystems |
| `sdme rootfs rm` | Remove imported root filesystems |
| `sdme config get/set` | View or modify configuration |

### Key Modules

| File | Purpose |
|------|---------|
| `src/main.rs` | CLI entry point (clap derive), command dispatch |
| `src/lib.rs` | Shared types: `State` (KEY=VALUE), `validate_name`, `sudo_user` |
| `src/containers.rs` | Container create/remove/join/exec/stop/list, overlayfs directory management |
| `src/systemd.rs` | D-Bus helpers (start/status), template unit generation, env files |
| `src/system_check.rs` | Version checks (systemd), dependency checks (`find_program`) |
| `src/rootfs.rs` | Rootfs listing, removal, os-release parsing, distro detection |
| `src/import.rs` | Rootfs import: directory copy, tarball extraction, URL download, OCI image extraction, QCOW2 disk image import |
| `src/config.rs` | Config file loading/saving (`~/.config/sdme/sdmerc`) |

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
- `sha2` — SHA-256 hashing (dev-dependency, used in OCI tests)

### External Dependencies

| Program | Package | Required for |
|---------|---------|--------------|
| `systemd` (>= 257) | `systemd` | All commands (D-Bus communication) |
| `systemd-nspawn` | `systemd-container` | Running containers |
| `machinectl` | `systemd-container` | `sdme join`, `sdme exec`, `sdme stop`, `sdme new` |
| `journalctl` | `systemd` | `sdme logs` |
| `qemu-nbd` | `qemu-utils` | `sdme rootfs import` (QCOW2 images only) |

Dependencies are checked at runtime before use via `system_check::check_dependencies()`, which resolves each binary in PATH and prints the resolved path with `-v`.

## Design Decisions

- **Root-only**: sdme requires root (`euid == 0`). Checked at program start.
- **Datadir**: always `/var/lib/sdme`.
- **Container management**: `join` and `exec` use `machinectl shell`; `stop` uses `machinectl poweroff` for clean shutdown.
- **D-Bus**: used for `start_unit`, `daemon_reload`, `is_unit_active`, `get_systemd_version`. Always system bus.
- **Rootfs import sources**: `sdme rootfs import` auto-detects the source type: URL prefix (`http://`/`https://`) → download + tarball extraction; existing directory → directory copy; QCOW2 disk image (magic bytes `QFI\xfb`) → mount via `qemu-nbd` + copy filesystem tree; existing file → tarball extraction via native Rust crates (`tar`, `flate2`, `bzip2`, `xz2`, `zstd`) with magic-byte compression detection. OCI container images (`.oci.tar.xz`, etc.) are auto-detected after tarball extraction by checking for an `oci-layout` file; the manifest chain is walked and filesystem layers are extracted in order with whiteout marker handling. QCOW2 import loads the `nbd` kernel module, connects the image read-only via `qemu-nbd`, discovers partitions via `/sys/block/`, mounts the largest partition, and copies the tree using the same `copy_tree()` used for directory imports.
