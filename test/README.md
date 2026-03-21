# Tests

## Unit tests

sdme has unit tests across 21 modules, all inline in the source files
they test. No external test dependencies are required.

### Running

```bash
cargo test                    # run all tests
cargo test <test_name>        # run a single test
cargo test <module>::         # run tests in a module
cargo test -- --nocapture     # show print output
cargo test -- --list          # list all tests without running
```

### Per-module breakdown

| Module       | Coverage area                                    |
|--------------|--------------------------------------------------|
| build        | Buildfile parsing (FROM/RUN/COPY), copy validate |
| config       | Config loading/saving, defaults, path resolution |
| containers   | Create, state, opaque dirs, OCI ports/volumes/env |
| devfd_shim   | LD_PRELOAD shim ELF generation (x86_64, aarch64) |
| elf          | Shared Arch enum and ELF builder (x86_64, aarch64) |
| export       | Format detection, tar writing, disk image export |
| import       | OCI registry, tarball, directory, disk image     |
| isolate      | PID/IPC namespace isolate ELF (x86_64, aarch64)  |
| kube         | Plan validation, secrets, configmaps             |
| lib          | Utility: sudo_user, resource limits, interrupts  |
| main         | Limits, OCI port auto-wiring, masked services    |
| mounts       | Bind mount and env var configuration             |
| names        | Name generation, collision avoidance             |
| network      | Network config validation, state serialization   |
| oci          | App setup, cache, layout, registry, rootfs       |
| pod          | Pod creation, netns sharing, state persistence   |
| rootfs       | Rootfs listing, removal, os-release, distro      |
| security     | Capabilities, seccomp, AppArmor, hardening modes |
| system_check | Dependency and version checks                    |
| systemd      | D-Bus unit management, boot wait, lifecycle      |
| txn          | Transaction staging, stale cleanup               |

3 tests are ignored by default (require root or network access):

- `import::registry::tests::test_pull_small_image`
- `import::tests::test_import_preserves_devices`
- `import::tests::test_import_preserves_ownership`

### CI

The CI pipeline (`.github/workflows/rust.yml`) runs on every push to
`main` and on pull requests:

1. `cargo fmt --check` (formatting)
2. `cargo clippy --locked -- -D warnings` (lints)
3. `cargo build --locked --verbose` (build)
4. `cargo test --locked --verbose` (all unit tests)

Release builds (`.github/workflows/release.yml`, triggered by `v*` tags)
additionally cross-compile musl binaries for x86_64 and aarch64.

## Prerequisites

- **Root access**: all integration tests require root.
- **systemd-nspawn**: version 252+ with `machinectl`, `journalctl`, `busctl`.
- **systemd-networkd**: must be running on the host for `--network-veth` tests
  (verify-oci.sh). The veth pair requires networkd's DHCP server to assign IPs.
- **AppArmor**: verify-usage.sh (`--strict`) and verify-kube-L2-security.sh
  require AppArmor enabled in the kernel and the `sdme-default` profile loaded
  (`sdme config apparmor-profile | sudo tee /etc/apparmor.d/sdme-default &&
  sudo apparmor_parser -r /etc/apparmor.d/sdme-default`).
- **Free host ports**: `8080` (nginx-unprivileged, used by verify-matrix.sh and
  verify-usage.sh with host-network containers) and `5432` (PostgreSQL health
  checks). See `lib.sh` for the full port inventory.
- **Docker Hub credentials** (optional): long test runs may hit Docker Hub rate
  limits. Configure with `sdme config set docker_user` / `docker_token`.

## Known limitations

### openSUSE + user namespaces (resolved)

openSUSE Tumbleweed ships `/usr/bin/newuidmap` and `/usr/bin/newgidmap`
with `security.capability` xattrs (file capabilities) instead of setuid
bits. The kernel refuses idmapped mounts when these xattrs are present,
which broke `--userns` and `--hardened`. The built-in Suse import prehook
now strips these xattrs automatically. Both export prehooks restore them
so exported rootfs are intact. The stripped binaries are not needed inside
nspawn containers since nspawn manages user namespace mapping itself.

### NixOS + OCI apps (resolved)

NixOS activation replaces `/etc/systemd/system` with an immutable symlink to
the Nix store, which used to destroy sdme's OCI app unit files. This is now
handled by placing OCI app units in `/etc/systemd/system.control/` on NixOS,
the highest-priority persistent unit search path that NixOS activation does not
manage. Detection uses `detect_distro_family()` via os-release; see
`oci::app::systemd_unit_dir()` in `src/oci/app.rs`.

### Redis 8 locale (workaround)

Redis 8+ treats locale configuration failure as fatal. The OCI image's
minimal chroot may lack the locale expected by the base container. The
workaround is to set `LANG=C.UTF-8` via `--oci-env` or the kube YAML
`env` field. The verify-matrix.sh test suite applies this automatically.
See `fix_redis_oci()` in verify-matrix.sh.

## Integration tests

Integration tests run real containers end-to-end. They require root,
a working systemd-nspawn installation, and network access for importing
rootfs from OCI registries.

All scripts are in the `test/scripts/` directory. Set `VERBOSE=1` for
detailed output on any script.

### verify-matrix.sh

Full distro x OCI app verification matrix. Imports distro rootfs from
OCI registries, then tests OCI applications on each distro. Also tests
hardened boot across all distros and hardened OCI app combinations.

```bash
sudo ./test/scripts/verify-matrix.sh
sudo ./test/scripts/verify-matrix.sh --distro ubuntu --app redis   # single cell
sudo ./test/scripts/verify-matrix.sh --report-dir ./test/reports   # custom report dir
```

Each cell verifies: app import with `--base-fs`, container boot,
`sdme-oci-{name}.service` active, journal and status accessible, and
app-specific health check (HTTP 200 for nginx-unprivileged, redis-cli
ping, pg_isready). Additional phases test hardened boot (all distros)
and hardened OCI app combinations.

See `./test/scripts/verify-matrix.sh --help` for all options.

### verify-pods.sh

Pod networking validation. Tests shared network namespace connectivity,
`--private-network` interaction, and error cases.

```bash
sudo ./test/scripts/verify-pods.sh
```

### verify-oci.sh

OCI port forwarding and volume mounting end-to-end validation. Imports
`nginx-unprivileged` as an OCI app on two base distros, verifies that
OCI-declared ports and volumes are auto-wired into the container state,
and confirms nginx serves custom content from a host-side volume through
port-forwarded networking.

```bash
sudo ./test/scripts/verify-oci.sh
sudo ./test/scripts/verify-oci.sh --distro ubuntu  # single distro
```

Each distro cell verifies: base import, app import, PORTS and
OCI_VOLUMES in the state file, host volume directory creation, container
boot, `sdme-oci-{name}.service` active, HTTP 200 on the forwarded port,
and response body containing the test HTML content.

### verify-security.sh

Security hardening and user namespace end-to-end validation. Tests CLI
validation, state persistence, individual security flags, the `--hardened`
bundle, AppArmor persistence, hardened boot, multi-distro `--userns` boot,
and `--userns` with OCI apps.

```bash
sudo ./test/scripts/verify-security.sh
```

### verify-network.sh

Private networking end-to-end validation. Tests service masking state file
assertions (zone auto-unmask, defaults, explicit overrides, empty clears
all), zone connectivity (HTTP via IP, resolved running, LLMNR name
resolution), and bridge connectivity (HTTP via IP, networkd enabled).

```bash
sudo ./test/scripts/verify-network.sh
```

### verify-interrupt.sh

Signal handling validation. Tests that SIGINT (Ctrl+C) during batch
operations (`rm -a`, `start --all`, `fs rm`) exits immediately with
code 130 instead of continuing to process remaining items.

```bash
sudo ./test/scripts/verify-interrupt.sh
```

### verify-export.sh

Export end-to-end validation. Tests rootfs catalogue exports (`fs:`
prefix) for all output formats: directory copy, tarballs (uncompressed,
gzip, bzip2, xz, zstd), raw ext4 and btrfs disk images (auto-size and
explicit `--size`), format override (`--fmt`), `--timezone` (dir, tar,
raw image, invalid timezone rejection), nonexistent rootfs error, smart
error hints (rootfs exists but no container, container exists but no
rootfs), and stopped container export.

```bash
sudo ./test/scripts/verify-export.sh
```

Skips zstd test if `zstdcat` is not available. Skips raw image tests if
`mkfs.ext4` is not available.

### verify-usage.sh

Verifies the commands documented in [usage.md](../docs/usage.md). Walks
through each section of the usage guide and runs the documented commands
to ensure nothing is stale or broken: host clone lifecycle, distro import,
OCI apps (nginx, redis, postgresql with `--oci-env`), `exec --oci`,
`logs --oci`, pods with connectivity, security flags (`--hardened`,
`--strict`, individual), networking (private, veth, zones), resource
limits, bind mounts, environment variables, and configuration.

```bash
sudo ./test/scripts/verify-usage.sh
```

### verify-nixos.sh

NixOS end-to-end verification. Builds a NixOS rootfs externally via
`build-nixos-rootfs.sh` (pulls `docker.io/nixos/nix`, runs `nix-build`
in a chroot, rebuilds a clean rootfs from the closure -- no local nix
required), boots a plain NixOS container, tests an OCI
nginx-unprivileged app, a single-container Kubernetes Pod, and a
multi-service Kubernetes Pod (nginx + redis + mysql) on the NixOS base.

```bash
sudo ./test/scripts/verify-nixos.sh
```

### build-nixos-rootfs.sh

Standalone script that builds a NixOS rootfs and imports it via sdme.
Used by verify-nixos.sh but can also be run directly. Uses the nix
expression at `test/nix/sdme-nixos.nix` by default.

```bash
sudo ./test/scripts/build-nixos-rootfs.sh mynixos
sudo ./test/scripts/build-nixos-rootfs.sh mynixos --nix-file /path/to/custom.nix
sudo ./test/scripts/build-nixos-rootfs.sh mynixos --channel nixos-24.11
```

### Kube Tests

Six-level progression (nine scripts) from basic lifecycle to a full
multi-service stack. All require a base-fs imported (e.g. `ubuntu`).
Run in order:

| Script                         | Level | Tests |
|--------------------------------|-------|-------|
| `verify-kube-L1-basic.sh`     | L1    | ~14   |
| `verify-kube-L2-spec.sh`      | L2    | ~12   |
| `verify-kube-L2-probes.sh`    | L2    | ~41   |
| `verify-kube-L2-security.sh`  | L2    | ~17   |
| `verify-kube-L3-volumes.sh`   | L3    | ~39   |
| `verify-kube-L3-secrets.sh`   | L3    | ~16   |
| `verify-kube-L4-networking.sh`| L4    | ~6    |
| `verify-kube-L5-redis-stack.sh`     | L5    | ~6    |
| `verify-kube-L6-gitea-stack.sh`     | L6    | ~15   |

- **L1-basic**: YAML validation, single-container pod, command
  override, kube delete, shared emptyDir, ps metadata.
- **L2-spec**: terminationGracePeriodSeconds, securityContext,
  initContainers, workingDir, resources, readinessProbe.
- **L2-probes**: startup, liveness, readiness, httpGet, tcpSocket
  probes and combined probe configurations.
- **L2-security**: capabilities add/drop (including ALL),
  allowPrivilegeEscalation, readOnlyRootFilesystem,
  seccompProfile, appArmorProfile, per-container runAsUser.
- **L3-volumes**: secret + configMap create/ls/rm, all-keys
  mount, projected items, defaultMode, env valueFrom, envFrom,
  read-only mounts, missing-resource errors, PVC persistence.
- **L3-secrets**: create/ls/rm lifecycle, all-keys mount,
  projected items, defaultMode, runtime access, missing errors.
- **L4-networking**: inter-container localhost networking,
  nginx + busybox, HTTP fetch across containers.
- **L5-redis**: redis PING/PONG, SET/GET via raw protocol.
- **L6-gitea**: 3-container app stack (Gitea + MySQL + Nginx)
  with API validation.

```bash
sudo ./test/scripts/verify-kube-L1-basic.sh --base-fs ubuntu
sudo ./test/scripts/verify-kube-L2-spec.sh --base-fs ubuntu
sudo ./test/scripts/verify-kube-L2-probes.sh --base-fs ubuntu
sudo ./test/scripts/verify-kube-L2-security.sh --base-fs ubuntu
sudo ./test/scripts/verify-kube-L3-volumes.sh --base-fs ubuntu
sudo ./test/scripts/verify-kube-L3-secrets.sh --base-fs ubuntu
sudo ./test/scripts/verify-kube-L4-networking.sh --base-fs ubuntu
sudo ./test/scripts/verify-kube-L5-redis-stack.sh --base-fs ubuntu
sudo ./test/scripts/verify-kube-L6-gitea-stack.sh --base-fs ubuntu
```

## Running a full test pass

### Parallel (recommended)

The parallel runner executes all 18 test scripts with maximum concurrency
while respecting resource constraints. It builds sdme, imports the base
rootfs, then launches tests in parallel with a configurable job limit.

```bash
# 1. Unit tests
cargo test

# 2. Integration tests (parallel, builds sdme automatically)
sudo ./test/scripts/run-parallel.sh
sudo ./test/scripts/run-parallel.sh --jobs 4              # limit concurrency
sudo ./test/scripts/run-parallel.sh --skip verify-nixos   # skip slow tests
sudo ./test/scripts/run-parallel.sh --only verify-export --only verify-interrupt
```

**Parallelization groups:**

- **Parallel wave** (16 tests): all tests that use private networking
  or no networking. Runs up to `--jobs` tests concurrently.
- **Host port serial group** (2 tests): `verify-usage.sh` and
  `verify-matrix.sh` bind host ports 8080/5432 and must run one at a
  time. They run as a serial pair occupying one job slot.
- **Kube L3 serial pair**: `verify-kube-L3-secrets.sh` and
  `verify-kube-L3-volumes.sh` share secret/configmap names and run
  serially within one job slot.

Reports are written to `--report-dir` (default: `./test-reports/`) with
a summary linking to individual test reports.

### Sequential

Each script is self-contained and can be run individually. Scripts
source `lib.sh`, which handles root checks, sdme validation, and base
rootfs imports automatically. Scripts clean up their own prefixed
artifacts on exit; the OCI blob cache makes re-imports fast.

```bash
# 1. Unit tests
cargo test

# 2. Build and install
cargo build --release
sudo cp target/release/sdme /usr/local/bin/sdme

# 3. Integration tests (any order; each is self-contained)
sudo ./test/scripts/verify-matrix.sh
sudo ./test/scripts/verify-pods.sh
sudo ./test/scripts/verify-oci.sh
sudo ./test/scripts/verify-security.sh
sudo ./test/scripts/verify-network.sh
sudo ./test/scripts/verify-export.sh
sudo ./test/scripts/verify-interrupt.sh
sudo ./test/scripts/verify-usage.sh
sudo ./test/scripts/verify-nixos.sh   # builds NixOS rootfs externally

# 4. Kube tests
sudo ./test/scripts/verify-kube-L1-basic.sh --base-fs ubuntu
sudo ./test/scripts/verify-kube-L2-spec.sh --base-fs ubuntu
sudo ./test/scripts/verify-kube-L2-probes.sh --base-fs ubuntu
sudo ./test/scripts/verify-kube-L2-security.sh --base-fs ubuntu
sudo ./test/scripts/verify-kube-L3-volumes.sh --base-fs ubuntu
sudo ./test/scripts/verify-kube-L3-secrets.sh --base-fs ubuntu
sudo ./test/scripts/verify-kube-L4-networking.sh --base-fs ubuntu
sudo ./test/scripts/verify-kube-L5-redis-stack.sh --base-fs ubuntu
sudo ./test/scripts/verify-kube-L6-gitea-stack.sh --base-fs ubuntu
```

### Adding new tests

When adding a new `verify-*.sh` script:

1. **Choose a unique prefix** for all artifacts (containers, rootfs, pods,
   secrets). Use `cleanup_prefix "yourprefix-"` in the cleanup trap.
   Ensure no other script's prefix is a substring of yours (e.g. don't
   use `vfy-` since `verify-matrix.sh` used to use it).
2. **Declare port usage** in the `lib.sh` port inventory comment at the
   top of the file.
3. **Add to `run-parallel.sh`**: if the test uses host networking with
   port binding, add it to the `host_port_scripts` serial group.
   Otherwise, add it to `parallel_tests`.

## Test results

See [results.md](results.md) for the latest verified results.
Update that file before each tagged release.
