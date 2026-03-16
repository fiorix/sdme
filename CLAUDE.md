# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

sdme boots systemd-nspawn containers using overlayfs copy-on-write layers, with OCI registry integration and Kubernetes Pod YAML support for local development and testing. It produces a single binary `sdme` that manages containers from explicit root filesystems, keeping the base rootfs untouched.

Runs on Linux with systemd. Requires root for all operations. Uses kernel overlayfs for copy-on-write storage. By default, containers are overlayfs clones of `/`. Also supports importing rootfs from other distros (Ubuntu, Debian, Fedora, NixOS). Imported rootfs needs systemd and dbus.

## Build & Test

```bash
cargo build --release       # build the binary (without probe binary)
cargo test                  # run all tests
cargo test <test_name>      # run a single test
make                        # build probe binary + sdme (with embedded probe)
make deb                    # build .deb package
make rpm                    # build .rpm package
make pkg                    # build .pkg.tar.zst package (Arch Linux)
sudo make install           # install to /usr/local (does NOT rebuild)
```

The probe binary (`sdme-kube-probe`) is built separately and embedded into sdme:
```bash
cargo build --release --features probe --bin sdme-kube-probe  # build probe binary
cargo build --release                                          # build sdme (embeds probe)
```
`make` handles both steps automatically.

### Release

Static musl binaries (x86_64 + aarch64) are built with `cargo-zigbuild`. Locally:

```bash
./dist/build-release.sh            # build all targets to target/dist/
./dist/build-release.sh -v <target> # build one target, verbose
```

CI: pushing a `v*` tag triggers `.github/workflows/release.yml`, which runs tests, cross-compiles both targets, generates SHA256SUMS, and creates a GitHub release with all artifacts.

## Architecture

The project is a single Rust binary (`src/main.rs`) backed by a shared library (`src/lib.rs`). CLI parsing uses clap with derive.

### Core Concepts

- **Overlayfs CoW storage**: each container gets `upper/work/merged` directories under the datadir. The lower layer is the imported rootfs. Uses kernel overlayfs.
- **Systemd integration**: containers are managed as a systemd template unit (`sdme@.service`) with `Type=notify`. Start goes through D-Bus to systemd; the unit is considered active only after `systemd-nspawn` sends `sd_notify(READY=1)`. A 2-minute startup timeout (`TimeoutStartSec=2min`) catches hung boots. Exit code 133 is treated as a successful clean shutdown (`SuccessExitStatus=133`, `RestartForceExitStatus=133`). The template unit is auto-installed and auto-updated when content changes. `TasksMax` is configurable via the `tasks_max` config key (default 16384).
- **machinectl integration**: `join` and `exec` use `machinectl shell` for container interaction. `stop` uses D-Bus (`KillMachine` for graceful/kill, `TerminateMachine` for terminate).
- **DNS resolution**: containers share the host's network namespace. `systemd-resolved` is masked in the overlayfs upper layer at creation time so the host's resolver handles DNS. A placeholder `/etc/resolv.conf` regular file is written so `systemd-nspawn --resolv-conf=auto` can populate it at boot.
- **State files**: container metadata persisted as KEY=VALUE files under `{datadir}/state/{name}`.
- **Health checks**: `sdme ps` detects broken containers (missing dirs, missing rootfs) and reports health status with OS detection via os-release.
### CLI Commands

| Command | Description |
|---------|-------------|
| `sdme new` | Create, start, and enter a new container (accepts same flags as `create`) |
| `sdme create` | Create a new container (overlayfs dirs + state file). Security flags: `--strict`, `--hardened`, `--drop-capability`, `--capability`, `--no-new-privileges`, `--read-only`, `--system-call-filter`, `--apparmor-profile`. OCI flags: `--no-oci-ports`, `--no-oci-volumes`, `--oci-env KEY=VALUE` (sets env vars for the OCI app service via the `/oci/apps/{name}/env` file, separate from `-e` which sets nspawn env vars) |
| `sdme start` | Start one or more containers (installs/updates template unit, starts via D-Bus). Supports `--all` to start all stopped containers |
| `sdme join` | Enter a running container (`machinectl shell`). `--start` starts the container first if stopped. `--oci [APP]` enters the OCI app's PID/IPC/mount namespaces via `nsenter` (default shell: `/bin/sh`; optional app name for multi-container kube pods) |
| `sdme exec` | Run a one-off command in a running container (`machinectl shell`). `--oci [APP]` enters the OCI app's PID, IPC, and mount namespaces via `nsenter` (discovers the app's host PID from its cgroup, then runs `nsenter -t <pid> --pid --ipc --mount`; optional app name for multi-container kube pods) |
| `sdme stop` | Graceful shutdown via `SIGRTMIN+4` (default), `--term` for terminate, `--kill` for force-kill |
| `sdme rm` | Remove containers (stops if running, deletes state + files) |
| `sdme ps` | List containers with status, health, OS, pod/OCI-pod/kube/userns/binds (if any) |
| `sdme logs` | View container logs (exec's `journalctl`). `--oci [APP]` shows the OCI app service logs (`journalctl -u sdme-oci-{name}.service` inside the container; optional app name for multi-container kube pods) |
| `sdme fs import` | Import a rootfs from a directory, tarball, URL, OCI image, or QCOW2 disk image |
| `sdme fs ls` | List imported root filesystems |
| `sdme fs rm` | Remove imported root filesystems |
| `sdme fs build` | Build a root filesystem from a build config |
| `sdme fs export` | Export a rootfs or container to a directory, tarball, or raw disk image (`--filesystem ext4\|btrfs`) |
| `sdme fs cache info/ls/clean` | Manage the OCI blob cache (info, list, clean `[--all]`) |
| `sdme set` | Set resource limits on a container (replaces all limits) |
| `sdme config get/set` | View or modify configuration |
| `sdme pod new` | Create a new pod (shared network namespace) |
| `sdme pod ls` | List pods |
| `sdme pod rm` | Remove pods |
| `sdme kube apply` | Create, start, and enter a container from a Kubernetes Pod YAML (`-f file`, `--base-fs` required) |
| `sdme kube create` | Create a container from a Kubernetes Pod YAML (no start) |
| `sdme kube delete` | Stop and remove a kube container and its rootfs (`--force` allows non-kube containers) |
| `sdme kube secret create/ls/rm` | Manage secrets for kube pods |
| `sdme kube configmap create/ls/rm` | Manage configmaps for kube pods |
| `sdme enable` | Enable containers to auto-start on boot |
| `sdme disable` | Disable container auto-start |
| `sdme config apparmor-profile` | Print the default AppArmor profile for sdme containers |
| `sdme config completions` | Generate shell completions (Bash, Fish, Zsh) |

### dist/ Directory

The `dist/` directory contains both checked-in packaging files and generated build outputs:

- `dist/sdme.1` — man page (checked in)
- `dist/deb/postinst` — Debian post-install script (checked in)
- `dist/out/completions/` — shell completions (generated by `make dist/out/completions`, gitignored)
- `dist/out/apparmor/` — AppArmor profile (generated in CI, gitignored)

### Key Modules

| File | Purpose |
|------|---------|
| `src/main.rs` | CLI entry point (clap derive), command dispatch |
| `src/lib.rs` | Shared types: `State` (KEY=VALUE), `validate_name`, `sudo_user`, global interrupt handler (`INTERRUPTED`, `check_interrupted`, `install_interrupt_handler`) |
| `src/containers.rs` | Container create/remove/join/exec/stop/list, overlayfs directory management, DNS setup, volume directory management |
| `src/systemd.rs` | D-Bus helpers (start/status/stop), template unit generation (`Type=notify`), env files, boot/shutdown waiting |
| `src/system_check.rs` | Version checks (systemd), dependency checks (`find_program`) |
| `src/rootfs.rs` | Rootfs listing, removal, os-release parsing, distro detection |
| `src/export.rs` | Rootfs export (dir copy, tarball creation, raw ext4/btrfs disk image) |
| `src/import/mod.rs` | Rootfs import orchestration: source detection, URL download (with proxy support), systemd detection |
| `src/import/dir.rs` | Directory-based rootfs import |
| `src/import/tar.rs` | Tarball extraction with magic-byte compression detection |
| `src/import/img.rs` | QCOW2 and raw disk image import via qemu-nbd |
| `src/oci/mod.rs` | OCI module index, app name derivation from registry references, sorted-keys helper |
| `src/oci/app.rs` | OCI app setup: user resolution, systemd service unit generation, isolate binary deployment |
| `src/oci/cache.rs` | Content-addressable OCI blob cache with LRU eviction |
| `src/oci/layout.rs` | OCI tarball detection, manifest resolution, layer unpacking with whiteout handling |
| `src/oci/registry.rs` | OCI registry pulling via Distribution Spec (docker.io, quay.io, etc.) |
| `src/oci/rootfs.rs` | OCI rootfs helpers: app name detection, port/volume reading from OCI metadata files |
| `src/names.rs` | Container name generation from a Tupi-Guarani wordlist with collision avoidance |
| `src/config.rs` | Config file loading/saving (`/etc/sdme.conf`) |
| `src/build.rs` | Build config parsing and rootfs build execution |
| `src/copy.rs` | Filesystem tree copying with xattr and special file support, path sanitization |
| `src/mounts.rs` | Bind mount (`BindConfig`) and environment variable (`EnvConfig`) configuration |
| `src/network.rs` | Network configuration validation and state serialization |
| `src/security.rs` | Security hardening: `SecurityConfig` (capabilities, seccomp, no-new-privileges, read-only, AppArmor), state file roundtrip, nspawn arg generation, validation |
| `src/kube/` | Kubernetes Pod YAML support: types, plan validation, container creation, kube delete, shared store abstraction for secrets and configmaps |
| `src/kube/probe/` | Embedded `sdme-kube-probe` binary: CLI entry point, probe runner (failure counting/actions), exec/http/tcp/grpc check implementations |
| `src/pod.rs` | Pod (shared network namespace) lifecycle: create, list, remove, runtime netns management |
| `src/elf.rs` | Shared `Arch` enum and minimal ELF64 header builder for static binaries (used by isolate and devfd_shim) |
| `src/isolate/` | Static ELF binary generation for PID/IPC namespace isolation in OCI app services |
| `src/devfd_shim/` | LD_PRELOAD shim generation for `/dev/fd/` interception in containers |

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
- `serde_yml`: YAML parsing (Kubernetes Pod manifests)
- `tonic`: gRPC client for probe binary (optional, `probe` feature)
- `prost`: protobuf serialization for gRPC health checks (optional, `probe` feature)
- `tokio`: async runtime for gRPC probes (optional, `probe` feature)
- `clap_complete`: shell completion generation (Bash, Fish, Zsh)

### External Dependencies

| Program | Package | Required for |
|---------|---------|--------------|
| `systemd` (>= 252) | `systemd` | All commands (D-Bus communication) |
| `systemd-nspawn` | `systemd-container` | Running containers |
| `machinectl` | `systemd-container` | `sdme join`, `sdme exec`, `sdme new` |
| `busctl` | `systemd` | Boot-wait D-Bus probe for `--userns` containers |
| `journalctl` | `systemd` | `sdme logs` |
| `nsenter` | `util-linux` | `sdme exec --oci`, `sdme join --oci` (namespace entry) |
| `qemu-nbd` | `qemu-utils` | `sdme fs import` (QCOW2 images only) |
| `mkfs.ext4` | `e2fsprogs` | `sdme fs export` (ext4 raw images, default) |
| `mkfs.btrfs` | `btrfs-progs` | `sdme fs export` (btrfs raw images only) |

Dependencies are checked at runtime before use via `system_check::check_dependencies()`, which resolves each binary in PATH and prints the resolved path with `-v`.

## Design Decisions

- **Root-only**: sdme requires root (`euid == 0`). Checked at program start.
- **Datadir**: always `/var/lib/sdme`.
- **Container management**: `join` and `exec` spawn `machinectl shell` and forward the exit status. `stop` has three tiers: graceful (default; `KillMachine` SIGRTMIN+4 to leader, 90s), terminate (`--term`; `TerminateMachine`, 30s), force-kill (`--kill`; `KillMachine` SIGKILL to all, 15s). `--term` and `--kill` are mutually exclusive. Internal callers use `StopMode::Terminate`.
- **D-Bus**: used for `start_unit`, `daemon_reload`, `is_unit_active`, `get_systemd_version`, `kill_machine`, `terminate_machine`. Always system bus.
- **Rootfs import sources**: `sdme fs import` auto-detects source type: URL, directory, QCOW2 (via `qemu-nbd`), OCI tarball (detected by `oci-layout` file), OCI registry reference, or plain tarball (compression detected from magic bytes). After import, systemd is detected; if missing, distro-specific packages are installed via chroot (`--install-packages` controls this). Supported distro families: Debian (apt-get), Fedora (dnf), Arch (pacman), Nix (nix-build), NixOS (no-op, already has systemd).
- **NixOS rootfs via nix-build**: When importing images with the nix package manager (e.g. `docker.io/nixos/nix`), `detect_distro_family()` returns `DistroFamily::Nix` (distinct from `NixOS` which means already-built NixOS). The install path writes an embedded `container.nix` (in `DEFAULT_NIXOS_CONFIG` constant) to `{rootfs}/tmp/sdme-nixos.nix`, then runs `nix-build` in a chroot to produce a full NixOS system closure. After build, `rebuild_nix_rootfs()` replaces the rootfs with a clean directory containing only the NixOS closure store paths and skeleton dirs (`nix/store`, `bin`, `sbin`, `etc`, `root`, `run`, `tmp`, `var`, `proc`, `sys`, `dev`), discarding leftover files from the OCI base image that would interfere with NixOS activation. The closure list is produced by `nix-store -qR` during the chroot step and stored in `/tmp/sdme-nix-closure.txt`; store paths are moved (not copied) to the clean rootfs for efficiency. `/sbin/init` is symlinked to the NixOS toplevel init, and `/etc/os-release` is written with `ID=nixos`. `patch_rootfs_services` is skipped for Nix rootfs because NixOS manages `/etc/systemd/system` as an immutable symlink to the Nix store via activation; creating files there would prevent activation from setting up systemd units. The `DEFAULT_NIXOS_CONFIG` disables `pam_lastlog2` for the `login` and `container-shell` PAM services (`lib.mkForce false`) to work around a linkage issue in nspawn containers. The `--nix-config <PATH>` flag copies a user NixOS configuration to `{rootfs}/tmp/sdme-nixos-extra.nix` which the embedded config imports via NixOS module system (lists merge automatically). The `nixpkgs_channel` config key (default `nixos-unstable`) controls which nixpkgs archive is used. The built rootfs has `nix.nixPath` configured so `nix-env -f '<nixpkgs>' -iA foo` works inside the container (requires `--no-sandbox`). Usage: `sdme fs import mynixos docker.io/nixos/nix --install-packages=yes`.
- **HTTP proxy support**: URL downloads respect standard proxy env vars (`https_proxy`, `http_proxy`, `all_proxy`, and uppercase variants). Since sdme runs as root, users must pass proxy variables through sudo (e.g. `sudo -E`). Configured in `build_http_agent()` (`src/import/mod.rs`). HTTP timeouts are configurable via `http_timeout` (connect/resolve, default 30s) and `http_body_timeout` (body receive, default 300s). Download size is capped by `max_download_size` (default 50G, `0` = unlimited).
- **Rootfs patching at import**: patches imported rootfs for nspawn compatibility: masks `systemd-resolved`, unmasks `systemd-logind` if masked, installs missing packages for `machinectl shell` (e.g. `util-linux`, `pam` on RHEL-family). Skipped for `DistroFamily::Nix` (NixOS manages `/etc` via activation). For host-rootfs containers, resolved is masked in the overlayfs upper layer during `create` instead.
- **Opaque dirs**: `-o` / `--overlayfs-opaque-dirs` on `create`/`new` sets `trusted.overlay.opaque` xattr, hiding lower-layer contents. For host-rootfs containers, `host_rootfs_opaque_dirs` config applies when no `-o` given (default: `/etc/systemd/system,/var/log`). Paths validated by `containers::validate_opaque_dirs()` (absolute, no `..`, no duplicates). Merge logic in `resolve_opaque_dirs()` in `main.rs`. When `/etc/systemd/system` is opaque, the `dbus.service` symlink (alias for the D-Bus implementation, e.g. `dbus-broker.service`) is preserved from the lower layer into the upper layer so `dbus.socket` can activate its service.
- **Umask check**: `containers::create()` refuses to proceed when the process umask strips read or execute from "other" (`umask & 005 != 0`). A restrictive umask causes files in the overlayfs upper layer to be inaccessible to non-root services (e.g. dbus-daemon as `messagebus`), preventing boot.
- **Bind mounts and env vars**: `-b`/`--bind` and `-e`/`--env` on `create`/`new` add custom bind mounts and environment variables. Stored in the state file and converted to systemd-nspawn flags at start time. Bind mounts validated (absolute paths, no `..`). Managed by `BindConfig` and `EnvConfig` in `src/mounts.rs`.
- **OCI port forwarding**: OCI images declare exposed ports in `/oci/apps/{name}/ports` (written at import time). On `create`/`new`, `read_oci_ports()` reads the file and `auto_wire_oci_ports()` (in `main.rs`) merges them into the network config as `--port` rules when the container has a private network namespace. User `--port` flags take priority (matching container ports are skipped). On host-network containers, an informational message is printed instead. Suppressed with `--no-oci-ports`.
- **OCI volume mounts**: OCI images declare volumes in `/oci/apps/{name}/volumes` (written at import time). On `create`/`new`, `read_oci_volumes()` reads the file and `do_create()` creates host-side directories at `{datadir}/volumes/{container}/{volume-name}` with bind mounts to `/oci/apps/{name}/root{volume-path}`. User `--bind` flags take priority (matching container paths are skipped). Volume data survives container removal (`sdme rm` prints the path but does not delete it). Suppressed with `--no-oci-volumes`. Stored as `OCI_VOLUMES` in the state file.
- **OCI registry pulling**: supports pulling from OCI registries (e.g. `docker.io/ubuntu:24.04`). Implements the OCI Distribution Spec in `src/oci/registry.rs`; resolves tags to manifests, matches architecture, downloads and extracts layers. Supports `--oci-mode` and `--base-fs` for running OCI app images as systemd services. The `default_base_fs` config key provides a default `--base-fs` value for OCI app imports when the flag is not specified on the command line. OCI app files are placed under `/oci/apps/{name}/` (root, env, ports, volumes). The app name is derived from the last path component of the registry repository (underscores replaced with hyphens) for registry images, or the rootfs name for non-registry imports. Stored as `OCI_APP={name}` in the container state file.
- **NixOS OCI unit placement**: NixOS activation replaces `/etc/systemd/system` with an immutable symlink to the Nix store, which would destroy OCI app unit files written to the overlayfs upper layer. On NixOS, OCI app units (services, timers, drop-ins) are placed in `/etc/systemd/system.control/` instead; this is the highest-priority persistent unit search path and is not managed by NixOS activation. Detection uses `detect_distro_family()` (os-release `ID=nixos`). The `systemd_unit_dir()` function in `src/oci/app.rs` returns the appropriate relative path. All call sites (OCI app setup, kube volume service, pod drop-ins, hardening drop-ins, service detection in `main.rs`) use this function or check both directories.
- **Pods**: `sdme pod new` creates a shared network namespace (loopback only) that multiple containers can join. The pod netns is created with `unshare(CLONE_NEWNET)` and bind-mounted to `/run/sdme/pods/{name}/netns`. Persistent state lives at `{datadir}/pods/{name}/state`. Two join mechanisms: `--pod` puts the entire nspawn container in the pod's netns via `--network-namespace-path=` (incompatible with `--userns`/`--hardened` because the kernel blocks `setns(CLONE_NEWNET)` across user namespace boundaries; `--private-network` is automatically omitted since the pod's netns provides equivalent loopback-only isolation); `--oci-pod` bind-mounts the pod's netns into the container and uses an inner systemd drop-in (`NetworkNamespacePath=`) so only the OCI app service process enters the pod's netns. `--oci-pod` requires `--private-network` (or `--hardened`/`--strict` which imply it) because systemd-nspawn strips `CAP_NET_ADMIN` on host-network containers and the inner systemd refuses `NetworkNamespacePath=` without that capability. This works with `--hardened` since the netns join happens inside the container's own network namespace (requires an OCI app rootfs with an `sdme-oci-{name}.service` unit). Both flags can be combined on the same container. Container state stores `POD` and/or `OCI_POD` keys. Pod removal checks both keys.
- **User namespace isolation**: `-u`/`--userns` on `create`/`new` enables user namespace isolation via `--private-users=pick --private-users-ownership=auto`. Container root maps to a high UID on the host (524288+ range, deterministically hashed from machine name). On kernel 6.6+, overlayfs supports idmapped mounts (zero overhead, files stay UID 0 on disk). Stored as `USERNS=yes` in the container state file. Boot-wait D-Bus probing uses `busctl --machine=` for userns containers because (a) the kernel blocks `/proc/{leader}/root/` traversal across user namespace boundaries, and (b) in-process `setns(CLONE_NEWUSER)` requires a single-threaded caller but zbus has already spawned threads. `busctl` handles this internally by forking a helper child. Detection is by comparing inode numbers of `/proc/self/ns/user` vs `/proc/{leader}/ns/user`; standard containers use the direct zbus path unchanged. **Limitation**: `--private-users-ownership=auto` uses kernel idmapped mounts, which fail if the rootfs contains files with `security.capability` xattrs (e.g. openSUSE Tumbleweed ships `newuidmap`/`newgidmap` with file capabilities instead of setuid bits). The kernel refuses to create an idmapped mount when `security.capability` xattrs are present because they cannot be safely remapped across user namespace boundaries. Affected rootfs must have these xattrs stripped during import.
- **Security hardening**: Three tiers of security: (1) Individual flags: `--drop-capability` / `--capability` (add/drop Linux capabilities, validated against `KNOWN_CAPS`, accepts with/without `CAP_` prefix), `--no-new-privileges` (blocks privilege escalation via setuid/file capabilities), `--read-only` (mounts rootfs read-only), `--system-call-filter` (seccomp filters, `@group` or `~@group` syntax), `--apparmor-profile` (applied as `AppArmorProfile=` in the systemd unit drop-in, not as an nspawn flag). (2) `--hardened`: enables user namespace isolation, private network, `--no-new-privileges`, and drops capabilities from the `hardened_drop_caps` config key (default: `CAP_SYS_PTRACE,CAP_NET_RAW,CAP_SYS_RAWIO,CAP_SYS_BOOT`). (3) `--strict`: implies `--hardened` plus Docker-equivalent cap drops (retains only Docker's ~14 caps + `CAP_SYS_ADMIN` for systemd), seccomp filters (`~@cpu-emulation,~@debug,~@obsolete,~@raw-io`), and the `sdme-default` AppArmor profile. Constants in `security.rs`: `HARDENED_DROP_CAPS`, `STRICT_DROP_CAPS`, `STRICT_SYSCALL_FILTERS`, `STRICT_APPARMOR_PROFILE`, `APPARMOR_PROFILE` (the profile text). All security options are stored in the state file (`DROP_CAPS`, `ADD_CAPS`, `NO_NEW_PRIVS`, `READ_ONLY`, `SYSCALL_FILTER`, `APPARMOR_PROFILE`) and read back at start time. Managed by `SecurityConfig` in `src/security.rs`. `sdme config apparmor-profile` dumps the default AppArmor profile to stdout for installation.
- **Interrupt handling**: a global `INTERRUPTED` flag (`src/lib.rs`) set by a POSIX `SIGINT` handler (installed without `SA_RESTART`). Import loops, boot-wait loops, and build operations check it for clean Ctrl+C cancellation. Second Ctrl+C force-kills the process. Cleanup paths (e.g. container removal after boot failure in `sdme new`) call `reset_interrupt()` to clear the flag and re-install the handler, ensuring cleanup code that also checks `check_interrupted()` is not short-circuited by a prior Ctrl+C.
- **Rootfs export**: `sdme fs export` exports an imported rootfs or a container's merged overlayfs view. Output formats: directory copy, tarball (uncompressed, gzip, bzip2, xz, zstd), or raw disk image (ext4 default, btrfs via `--filesystem btrfs`; no partition table). Format auto-detected from extension or overridden with `--format`. Container export (`--container`): if running, reads directly from `merged/` with a consistency warning; if stopped, temporarily mounts overlayfs. Raw image: sparse file formatted with `mkfs.ext4` or `mkfs.btrfs`, loop-mounted, tree copied, unmounted. Size auto-calculated as `max(256M, content * 1.5)` or overridden with `--size`. The `default_export_fs` config key sets the default filesystem type when `--filesystem` is not specified (default: `ext4`).
- **VM export**: `sdme fs export --vm` prepares a raw disk image for booting as a standalone VM (e.g. cloud-hypervisor, QEMU). Modifications: serial console login via patched `serial-getty@.service` (strips `BindsTo=dev-*.device` that requires udev), `/etc/fstab` with root device, DNS via `/etc/resolv.conf`, DHCP networking via `systemd-networkd`, hostname. Optional: `--root-password` (SHA-512 crypt in `/etc/shadow`), `--ssh-key` (root authorized key), `--install-packages` (installs udev via chroot using `ChrootGuard` from `src/import/mod.rs`). For VM ext4 images, block size is 1024 and `orphan_file` is disabled (`-b 1024 -O ^orphan_file`) for cloud-hypervisor compatibility. **Limitation**: NixOS activation replaces `/etc/systemd/system` with an immutable symlink, so VM prep files written there may be overwritten on first boot.
- **Build COPY restrictions**: `sdme fs build` COPY writes to the overlayfs upper layer while stopped. Destinations under tmpfs-mounted dirs (`/tmp`, `/run`, `/dev/shm`) or opaque dirs are rejected. Validation in `check_shadowed_dest()` (`src/build.rs`); errors include config file path and line number.
- **Kubernetes Pod YAML**: `sdme kube` accepts `kind: Pod` (v1) and `kind: Deployment` (apps/v1; extracts pod template). Multi-container pods run as a single nspawn container with one systemd service (`sdme-oci-{name}.service`) per app container; all containers share the network namespace and can communicate via localhost. Rootfs is named `kube-{podname}` and built atomically via a staging directory. K8s command/args semantics: `command` overrides Docker ENTRYPOINT, `args` overrides Docker CMD. Volumes: emptyDir (directories at `/oci/volumes/{name}` inside the rootfs, bind-mounted into each app's root by a generated `sdme-kube-volumes.service` oneshot unit), hostPath (nspawn `--bind=` mounts to `/oci/volumes/{name}`), secret (files populated from `{datadir}/secrets/{name}/data/` into `/oci/volumes/{vol}/`), configMap (files populated from `{datadir}/configmaps/{name}/data/` into `/oci/volumes/{vol}/`), and persistentVolumeClaim (host dir at `{datadir}/volumes/{claimName}` bind-mounted to `/oci/volumes/{vol}/`). Secret and configMap volumes support `items` for projected key paths and `defaultMode` for file permissions. The volume mount service runs `mount --bind` in the container's PID 1 mount namespace before app services start (app units have `After=`/`Requires=sdme-kube-volumes.service`); read-only mounts get an additional `remount,ro,bind`. Env vars support `valueFrom` with `secretKeyRef` and `configMapKeyRef` for deferred resolution from secrets/configmaps at create time. `envFrom` bulk-imports all keys from a configMap or secret as env vars, with an optional `prefix`; explicit `env[]` entries take priority over `envFrom` for the same key. Ports are aggregated across all containers; `--private-network` is enabled when any ports are declared. Restart policy mapping: Always=always, OnFailure=on-failure, Never=no. State keys: `KUBE=yes`, `KUBE_CONTAINERS={csv}`, `KUBE_YAML_HASH={sha256}`. `kube delete` removes both the container and its kube rootfs. `sdme ps` shows a `kube:{container_names}` column for kube containers. For multi-container kube pods, `--oci APP` on `exec`, `join`, and `logs` requires the app name to select which container to target; single-container pods auto-select the only app when `--oci` is used without a value.
- **Kubernetes probes**: Four probe types supported via an embedded `sdme-kube-probe` binary deployed at `/oci/.sdme-kube-probe` inside the container rootfs. All three probe types (startup, liveness, readiness) use systemd timer + oneshot service pairs that invoke the probe binary. No shell scripts or external tool dependencies (wget, bash). Startup probe: timer writes `/run/sdme-probe-startup-{name}.done` on success; restarts service on threshold failure. Liveness probe: timer + service that restarts the OCI app service on failure threshold. Readiness probe: timer + service that writes `ready` or `not-ready` to `/oci/apps/{name}/probe-ready` (in overlayfs, readable from host for `sdme ps`). Liveness/readiness timers use `ConditionPathExists=/run/sdme-probe-startup-{name}.done` to gate on startup probe completion when present. Four probe mechanisms: `exec` (chroot + Command, std only), `httpGet` (raw HTTP/1.0 GET via TcpStream, supports custom `httpHeaders`, std only), `tcpSocket` (TcpStream::connect_timeout, std only), `grpc` (gRPC Health Checking Protocol via tonic). Timer units use `BindsTo=sdme-oci-{name}.service` to stop when the main service stops. Probe parameters: `initialDelaySeconds`, `periodSeconds`, `timeoutSeconds`, `failureThreshold`, `successThreshold`. Probe binary is built separately (`cargo build --features probe --bin sdme-kube-probe`) and embedded into sdme via `include_bytes!()` in `build.rs`. `HAS_PROBES=yes` stored in container state. `sdme ps` health column shows `ready`/`not-ready` for kube containers with readiness probes. Probe check validation in `src/kube/plan.rs:build_probe_check()` returns `ProbeCheck` enum (`Exec`, `Http`, `Tcp`, `Grpc`). Unit generation in `src/oci/app.rs:generate_probe_units()`. Probe binary sources in `src/kube/probe/`.
- **Boot failure cleanup**: `sdme new` removes the just-created container on boot failure, join failure, or Ctrl+C. `sdme start` stops the container on boot failure or Ctrl+C (preserving it on disk for debugging). Both reset the interrupt flag before cleanup so that the stop/remove operations (which internally call `check_interrupted()`) can complete.
- **Input sanitization**: sdme runs as root and handles untrusted input; hardening measures:
  - OCI tar paths: `..` rejected, leading `/` stripped (`sanitize_dest_path()` in `src/copy.rs`).
  - OCI digests: validated for safe characters before constructing blob paths (`resolve_blob()` in `src/oci/layout.rs`).
  - Rootfs names (`-r`): validated with `validate_name()` to prevent path traversal (`resolve_rootfs()` in `containers.rs`).
  - Opaque dir paths: must be absolute, no `..`, no duplicates; normalized before storage.
  - URL downloads: capped by `max_download_size` config key (default 50 GiB, `0` = unlimited).
  - Config files: written with explicit permissions (`0o600`).
