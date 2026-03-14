# Tests

## Unit tests

sdme has unit tests across 15 modules, all inline in the source files
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
| import       | OCI registry, tarball, directory, disk image     |
| containers   | Create, state, opaque dirs, OCI ports/volumes/env |
| devfd_shim   | LD_PRELOAD shim ELF generation (x86_64, aarch64) |
| mounts       | Bind mount and env var configuration             |
| build        | Buildfile parsing (FROM/RUN/COPY), copy validate |
| security     | Capabilities, seccomp, AppArmor, hardening modes |
| rootfs       | Rootfs listing, removal, os-release, distro      |
| lib          | Utility: sudo_user, resource limits, interrupts  |
| elf          | Shared Arch enum and ELF builder (x86_64, aarch64) |
| systemd      | D-Bus unit management, boot wait, lifecycle      |
| config       | Config loading/saving, defaults, path resolution |
| pod          | Pod creation, netns sharing, state persistence   |
| network      | Network config validation, state serialization   |
| names        | Name generation, collision avoidance             |
| main         | OCI port auto-wiring integration tests           |
| system_check | Dependency and version checks                    |

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
sudo ./test/scripts/verify-matrix.sh --keep                        # keep artifacts
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

Requires the `ubuntu` rootfs imported beforehand:

```bash
sudo sdme fs import ubuntu docker.io/ubuntu:24.04 -v --install-packages=yes
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
sudo ./test/scripts/verify-oci.sh --keep           # keep artifacts
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

Requires the `ubuntu` rootfs. For multi-distro userns tests, also requires
`vfy-*` rootfs from `verify-matrix.sh --keep`:

```bash
# Basic security tests (ubuntu rootfs only)
sudo sdme fs import ubuntu docker.io/ubuntu:24.04 -v --install-packages=yes
sudo ./test/scripts/verify-security.sh

# Full run including multi-distro userns tests
sudo ./test/scripts/verify-matrix.sh --keep
sudo ./test/scripts/verify-security.sh
```

### verify-export.sh

Rootfs export end-to-end validation. Tests all output formats: directory
copy, tarballs (uncompressed, gzip, bzip2, xz, zstd), raw ext4 disk
images (auto-size and explicit `--size`), format override (`-f`), and
error handling for nonexistent rootfs.

Requires the `ubuntu` rootfs imported beforehand:

```bash
sudo sdme fs import ubuntu docker.io/ubuntu:24.04 -v --install-packages=yes
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
sudo ./test/scripts/verify-usage.sh --keep   # keep artifacts
```

### verify-nixos.sh

NixOS end-to-end verification. Builds a NixOS rootfs via `nix-build`,
imports it into sdme, boots a plain NixOS container, then tests an OCI
nginx-unprivileged app on the NixOS base. Requires `nix` with the
daemon running.

```bash
sudo ./test/scripts/verify-nixos.sh
sudo ./test/scripts/verify-nixos.sh --keep   # keep artifacts
```

The `test/scripts/nix/build-rootfs.sh` helper builds the NixOS rootfs
from `test/scripts/nix/container.nix`.

### Kube Tests

Eight-level progression from basic lifecycle to a full multi-service stack.
All require a base-fs imported (e.g. `ubuntu`). Run in order:

| Script                         | Level | Tests |
|--------------------------------|-------|-------|
| `verify-kube-L1-basic.sh`     | L1    | ~6    |
| `verify-kube-L2-spec.sh`      | L2    | ~12   |
| `verify-kube-L2-security.sh`  | L2    | ~17   |
| `verify-kube-L3-volumes.sh`   | L3    | ~39   |
| `verify-kube-L3-secrets.sh`   | L3    | ~16   |
| `verify-kube-L4-networking.sh`| L4    | ~6    |
| `verify-kube-L5-redis.sh`     | L5    | ~6    |
| `verify-kube-L6-gitea.sh`     | L6    | ~15   |

- **L1-basic**: YAML validation, single-container pod, command
  override, kube delete, shared emptyDir, ps metadata.
- **L2-spec**: terminationGracePeriodSeconds, securityContext,
  initContainers, workingDir, resources, readinessProbe.
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
sudo ./test/scripts/verify-kube-L2-security.sh --base-fs ubuntu
sudo ./test/scripts/verify-kube-L3-volumes.sh --base-fs ubuntu
sudo ./test/scripts/verify-kube-L3-secrets.sh --base-fs ubuntu
sudo ./test/scripts/verify-kube-L4-networking.sh --base-fs ubuntu
sudo ./test/scripts/verify-kube-L5-redis.sh --base-fs ubuntu
sudo ./test/scripts/verify-kube-L6-gitea.sh --base-fs ubuntu
```

## Running a full test pass

Before tagging a release, run everything from a clean state:

```bash
# 1. Unit tests
cargo test

# 2. Integration tests (order matters: matrix first, then the rest)
sudo ./test/scripts/verify-matrix.sh --keep
sudo ./test/scripts/verify-pods.sh
sudo ./test/scripts/verify-oci.sh
sudo ./test/scripts/verify-security.sh
sudo ./test/scripts/verify-export.sh
sudo ./test/scripts/verify-usage.sh
sudo ./test/scripts/verify-nixos.sh   # requires nix

# 3. Kube tests (requires ubuntu base-fs from step 2)
sudo ./test/scripts/verify-kube-L1-basic.sh --base-fs ubuntu
sudo ./test/scripts/verify-kube-L2-spec.sh --base-fs ubuntu
sudo ./test/scripts/verify-kube-L2-security.sh --base-fs ubuntu
sudo ./test/scripts/verify-kube-L3-volumes.sh --base-fs ubuntu
sudo ./test/scripts/verify-kube-L3-secrets.sh --base-fs ubuntu
sudo ./test/scripts/verify-kube-L4-networking.sh --base-fs ubuntu
sudo ./test/scripts/verify-kube-L5-redis.sh --base-fs ubuntu
sudo ./test/scripts/verify-kube-L6-gitea.sh --base-fs ubuntu
```

Use `--keep` on verify-matrix.sh so that verify-security.sh can reuse
the imported rootfs for its multi-distro `--userns` tests.

### Clean slate

To remove all test artifacts and start from scratch:

```bash
sudo sdme rm --all -f
sudo sdme fs rm --all -f
```

This removes all containers and imported rootfs. The next integration
test run will re-import everything from OCI registries.

## Test results

See [results.md](results.md) for the latest verified results.
Update that file before each tagged release.
