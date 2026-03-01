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

- **Overlayfs CoW storage**: each container gets `upper/work/merged` directories under the datadir. The lower layer is the imported rootfs. Uses kernel overlayfs.
- **Systemd integration**: containers are managed as a systemd template unit (`sdme@.service`). Start goes through D-Bus to systemd. The template unit is auto-installed and auto-updated when content changes.
- **machinectl integration**: `join` and `exec` use `machinectl shell` for container interaction. `stop` uses D-Bus (`KillMachine` for graceful/kill, `TerminateMachine` for terminate).
- **DNS resolution**: containers share the host's network namespace. `systemd-resolved` is masked in the overlayfs upper layer at creation time so the host's resolver handles DNS. A placeholder `/etc/resolv.conf` regular file is written so `systemd-nspawn --resolv-conf=auto` can populate it at boot.
- **State files**: container metadata persisted as KEY=VALUE files under `{datadir}/state/{name}`.
- **Health checks**: `sdme ps` detects broken containers (missing dirs, missing rootfs) and reports health status with OS detection via os-release.
### CLI Commands

| Command | Description |
|---------|-------------|
| `sdme new` | Create, start, and enter a new container (accepts same security flags as `create`) |
| `sdme create` | Create a new container (overlayfs dirs + state file). Security flags: `--strict`, `--hardened`, `--drop-capability`, `--capability`, `--no-new-privileges`, `--read-only`, `--system-call-filter`, `--apparmor-profile` |
| `sdme start` | Start a container (installs/updates template unit, starts via D-Bus) |
| `sdme join` | Enter a running container (`machinectl shell`) |
| `sdme exec` | Run a one-off command in a running container (`machinectl shell`) |
| `sdme stop` | Graceful shutdown via `SIGRTMIN+4` (default), `--term` for terminate, `--kill` for force-kill |
| `sdme rm` | Remove containers (stops if running, deletes state + files) |
| `sdme ps` | List containers with status, health, OS, pod/OCI-pod/userns/binds (if any) |
| `sdme logs` | View container logs (exec's `journalctl`) |
| `sdme fs import` | Import a rootfs from a directory, tarball, URL, OCI image, or QCOW2 disk image |
| `sdme fs ls` | List imported root filesystems |
| `sdme fs rm` | Remove imported root filesystems |
| `sdme fs build` | Build a root filesystem from a build config |
| `sdme set` | Set resource limits on a container (replaces all limits) |
| `sdme config get/set` | View or modify configuration |
| `sdme pod new` | Create a new pod (shared network namespace) |
| `sdme pod ls` | List pods |
| `sdme pod rm` | Remove pods |
| `sdme config apparmor-profile` | Print the default AppArmor profile for sdme containers |
| `sdme config completions` | Generate shell completions (Bash, Fish, Zsh) |

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
| `src/security.rs` | Security hardening: `SecurityConfig` (capabilities, seccomp, no-new-privileges, read-only, AppArmor), state file roundtrip, nspawn arg generation, validation |
| `src/pod.rs` | Pod (shared network namespace) lifecycle: create, list, remove, runtime netns management |
| `src/drop_privs/` | Privilege dropping via minimal static ELF binaries (x86_64 and aarch64 machine code emitters, ELF header construction) |

### Rust Dependencies

- `clap`: CLI parsing (derive)
- `zbus`: D-Bus communication with systemd (blocking API)
- `libc`: syscalls for rootfs import (lchown, mknod, etc.), privilege dropping
- `anyhow`: error handling
- `serde`/`toml`: config file parsing
- `tar`: archive extraction with xattr support
- `flate2`: gzip decompression
- `bzip2`: bzip2 decompression
- `xz2`: xz/lzma decompression
- `zstd`: zstd decompression
- `serde_json`: JSON parsing (OCI image manifests)
- `ureq`: HTTP client for URL downloads and OCI registry pulling (blocking, rustls TLS)
- `sha2`: SHA-256 hashing (OCI digest verification)
- `clap_complete`: shell completion generation (Bash, Fish, Zsh)

### External Dependencies

| Program | Package | Required for |
|---------|---------|--------------|
| `systemd` (>= 252) | `systemd` | All commands (D-Bus communication) |
| `systemd-nspawn` | `systemd-container` | Running containers |
| `machinectl` | `systemd-container` | `sdme join`, `sdme exec`, `sdme new` |
| `busctl` | `systemd` | Boot-wait D-Bus probe for `--userns` containers |
| `journalctl` | `systemd` | `sdme logs` |
| `qemu-nbd` | `qemu-utils` | `sdme fs import` (QCOW2 images only) |

Dependencies are checked at runtime before use via `system_check::check_dependencies()`, which resolves each binary in PATH and prints the resolved path with `-v`.

## Design Decisions

- **Root-only**: sdme requires root (`euid == 0`). Checked at program start.
- **Datadir**: always `/var/lib/sdme`.
- **Container management**: `join` and `exec` spawn `machinectl shell` and forward the exit status. `stop` has three tiers: graceful (default; `KillMachine` SIGRTMIN+4 to leader, 90s), terminate (`--term`; `TerminateMachine`, 30s), force-kill (`--kill`; `KillMachine` SIGKILL to all, 15s). `--term` and `--kill` are mutually exclusive. Internal callers use `StopMode::Terminate`.
- **D-Bus**: used for `start_unit`, `daemon_reload`, `is_unit_active`, `get_systemd_version`, `kill_machine`, `terminate_machine`. Always system bus.
- **Rootfs import sources**: `sdme fs import` auto-detects source type: URL, directory, QCOW2 (via `qemu-nbd`), OCI tarball (detected by `oci-layout` file), OCI registry reference, or plain tarball (compression detected from magic bytes). After import, systemd is detected; if missing, distro-specific packages are installed via chroot (`--install-packages` controls this).
- **HTTP proxy support**: URL downloads respect standard proxy env vars (`https_proxy`, `http_proxy`, `all_proxy`, and uppercase variants). Since sdme runs as root, users must pass proxy variables through sudo (e.g. `sudo -E`). Configured in `build_http_agent()` (`src/import/mod.rs`).
- **Rootfs patching at import**: patches imported rootfs for nspawn compatibility: masks `systemd-resolved`, unmasks `systemd-logind` if masked, installs missing packages for `machinectl shell` (e.g. `util-linux`, `pam` on RHEL-family). For host-rootfs containers, resolved is masked in the overlayfs upper layer during `create` instead.
- **Opaque dirs**: `-o` / `--overlayfs-opaque-dirs` on `create`/`new` sets `trusted.overlay.opaque` xattr, hiding lower-layer contents. For host-rootfs containers, `host_rootfs_opaque_dirs` config applies when no `-o` given (default: `/etc/systemd/system,/var/log`). Paths validated by `containers::validate_opaque_dirs()` (absolute, no `..`, no duplicates). Merge logic in `resolve_opaque_dirs()` in `main.rs`. When `/etc/systemd/system` is opaque, the `dbus.service` symlink (alias for the D-Bus implementation, e.g. `dbus-broker.service`) is preserved from the lower layer into the upper layer so `dbus.socket` can activate its service.
- **Umask check**: `containers::create()` refuses to proceed when the process umask strips read or execute from "other" (`umask & 005 != 0`). A restrictive umask causes files in the overlayfs upper layer to be inaccessible to non-root services (e.g. dbus-daemon as `messagebus`), preventing boot.
- **Bind mounts and env vars**: `-b`/`--bind` and `-e`/`--env` on `create`/`new` add custom bind mounts and environment variables. Stored in the state file and converted to systemd-nspawn flags at start time. Bind mounts validated (absolute paths, no `..`). Managed by `BindConfig` and `EnvConfig` in `src/mounts.rs`.
- **OCI registry pulling**: supports pulling from OCI registries (e.g. `docker.io/ubuntu:24.04`). Implements the OCI Distribution Spec in `src/import/registry.rs`; resolves tags to manifests, matches architecture, downloads and extracts layers. Supports `--oci-mode` and `--base-fs` for running OCI app images as systemd services. The `default_base_fs` config key provides a default `--base-fs` value for OCI app imports when the flag is not specified on the command line.
- **Pods**: `sdme pod new` creates a shared network namespace (loopback only) that multiple containers can join. The pod netns is created with `unshare(CLONE_NEWNET)` and bind-mounted to `/run/sdme/pods/{name}/netns`. Persistent state lives at `{datadir}/pods/{name}/state`. Two join mechanisms: `--pod` puts the entire nspawn container in the pod's netns via `--network-namespace-path=` (incompatible with `--userns`/`--hardened` because the kernel blocks `setns(CLONE_NEWNET)` across user namespace boundaries; `--private-network` is automatically omitted since the pod's netns provides equivalent loopback-only isolation); `--oci-pod` bind-mounts the pod's netns into the container and uses an inner systemd drop-in (`NetworkNamespacePath=`) so only the OCI app service process enters the pod's netns — this works with `--hardened` since the netns join happens inside the container (requires an OCI app rootfs with `sdme-oci-app.service`). Both flags can be combined on the same container. Container state stores `POD` and/or `OCI_POD` keys. Pod removal checks both keys.
- **User namespace isolation**: `-u`/`--userns` on `create`/`new` enables user namespace isolation via `--private-users=pick --private-users-ownership=auto`. Container root maps to a high UID on the host (524288+ range, deterministically hashed from machine name). On kernel 6.6+, overlayfs supports idmapped mounts (zero overhead, files stay UID 0 on disk). Stored as `USERNS=yes` in the container state file. Boot-wait D-Bus probing uses `busctl --machine=` for userns containers because (a) the kernel blocks `/proc/{leader}/root/` traversal across user namespace boundaries, and (b) in-process `setns(CLONE_NEWUSER)` requires a single-threaded caller but zbus has already spawned threads. `busctl` handles this internally by forking a helper child. Detection is by comparing inode numbers of `/proc/self/ns/user` vs `/proc/{leader}/ns/user`; standard containers use the direct zbus path unchanged.
- **Security hardening**: Three tiers of security: (1) Individual flags: `--drop-capability` / `--capability` (add/drop Linux capabilities, validated against `KNOWN_CAPS`, accepts with/without `CAP_` prefix), `--no-new-privileges` (blocks privilege escalation via setuid/file capabilities), `--read-only` (mounts rootfs read-only), `--system-call-filter` (seccomp filters, `@group` or `~@group` syntax), `--apparmor-profile` (applied as `AppArmorProfile=` in the systemd unit drop-in, not as an nspawn flag). (2) `--hardened`: enables user namespace isolation, private network, `--no-new-privileges`, and drops capabilities from the `hardened_drop_caps` config key (default: `CAP_SYS_PTRACE,CAP_NET_RAW,CAP_SYS_RAWIO,CAP_SYS_BOOT`). (3) `--strict`: implies `--hardened` plus Docker-equivalent cap drops (retains only Docker's ~14 caps + `CAP_SYS_ADMIN` for systemd), seccomp filters (`~@cpu-emulation,~@debug,~@obsolete,~@raw-io`), and the `sdme-default` AppArmor profile. Constants in `security.rs`: `HARDENED_DROP_CAPS`, `STRICT_DROP_CAPS`, `STRICT_SYSCALL_FILTERS`, `STRICT_APPARMOR_PROFILE`, `APPARMOR_PROFILE` (the profile text). All security options are stored in the state file (`DROP_CAPS`, `ADD_CAPS`, `NO_NEW_PRIVS`, `READ_ONLY`, `SYSCALL_FILTER`, `APPARMOR_PROFILE`) and read back at start time. Managed by `SecurityConfig` in `src/security.rs`. `sdme config apparmor-profile` dumps the default AppArmor profile to stdout for installation.
- **Interrupt handling**: a global `INTERRUPTED` flag (`src/lib.rs`) set by a POSIX `SIGINT` handler (installed without `SA_RESTART`). Import loops, boot-wait loops, and build operations check it for clean Ctrl+C cancellation. Second Ctrl+C force-kills the process. Cleanup paths (e.g. container removal after boot failure in `sdme new`) call `reset_interrupt()` to clear the flag and re-install the handler, ensuring cleanup code that also checks `check_interrupted()` is not short-circuited by a prior Ctrl+C.
- **Build COPY restrictions**: `sdme fs build` COPY writes to the overlayfs upper layer while stopped. Destinations under tmpfs-mounted dirs (`/tmp`, `/run`, `/dev/shm`) or opaque dirs are rejected. Validation in `check_shadowed_dest()` (`src/build.rs`); errors include config file path and line number.
- **Boot failure cleanup**: `sdme new` removes the just-created container on boot failure, join failure, or Ctrl+C. `sdme start` stops the container on boot failure or Ctrl+C (preserving it on disk for debugging). Both reset the interrupt flag before cleanup so that the stop/remove operations (which internally call `check_interrupted()`) can complete.
- **Input sanitization**: sdme runs as root and handles untrusted input; hardening measures:
  - OCI tar paths: `..` rejected, leading `/` stripped (`sanitize_tar_path()` in `import/oci.rs`).
  - OCI digests: validated for safe characters before constructing blob paths (`resolve_blob()` in `import/oci.rs`).
  - Rootfs names (`-r`): validated with `validate_name()` to prevent path traversal (`resolve_rootfs()` in `containers.rs`).
  - Opaque dir paths: must be absolute, no `..`, no duplicates; normalized before storage.
  - URL downloads: capped at 50 GiB (`MAX_DOWNLOAD_SIZE` in `import/mod.rs`).
  - Config files: written with explicit permissions (`0o600` files, `0o700` dirs).
