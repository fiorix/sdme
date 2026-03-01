# sdme: Tests

Last verified: 2026-03-01

System: Linux 6.17.0-14-generic, systemd 257 (257.9-0ubuntu2.1), sdme 0.1.6

## 1. Unit Tests

sdme has 322 unit tests across 14 modules, all inline in the source files
they test. No external test dependencies are required.

### Running unit tests

```bash
cargo test                    # run all tests
cargo test <test_name>        # run a single test
cargo test <module>::         # run tests in a module
cargo test -- --nocapture     # show print output
cargo test -- --list          # list all tests without running
```

### Per-module breakdown

| Module       | Tests | Coverage area                                    |
|--------------|-------|--------------------------------------------------|
| import       | 83    | OCI registry, tarball, directory, disk image     |
| containers   | 32    | Create, state, opaque dirs, name resolution      |
| devfd_shim   | 29    | LD_PRELOAD shim ELF generation (x86_64, aarch64) |
| mounts       | 26    | Bind mount and env var configuration             |
| build        | 23    | Buildfile parsing (FROM/RUN/COPY), copy validate |
| security     | 20    | Capabilities, seccomp, AppArmor, hardening modes |
| rootfs       | 18    | Rootfs listing, removal, os-release, distro      |
| lib          | 16    | Utility: sudo_user, resource limits, interrupts  |
| drop_privs   | 16    | Privilege drop ELF generation (x86_64, aarch64)  |
| systemd      | 15    | D-Bus unit management, boot wait, lifecycle      |
| config       | 14    | Config loading/saving, defaults, path resolution |
| pod          | 11    | Pod creation, netns sharing, state persistence   |
| network      | 11    | Network config validation, state serialization   |
| names        | 5     | Name generation, collision avoidance             |
| system_check | 3     | Dependency and version checks                    |

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
4. `cargo test --locked --verbose` (all 322 unit tests)

Release builds (`.github/workflows/release.yml`, triggered by `v*` tags)
additionally cross-compile musl binaries for x86_64 and aarch64.

## 2. Integration Tests

Integration tests run real containers end-to-end. They require root,
a working systemd-nspawn installation, and network access for importing
rootfs from OCI registries.

All scripts are in the `test/` directory. Set `VERBOSE=1` for detailed
output on any script.

### verify-matrix.sh

Full distro x OCI app verification matrix. Imports 5 distro rootfs from
OCI registries, then tests 4 OCI applications on each distro (20 test
cells, 145 checks total).

```bash
sudo ./test/verify-matrix.sh
sudo ./test/verify-matrix.sh --distro ubuntu --app nginx  # single cell
sudo ./test/verify-matrix.sh --keep                       # keep artifacts
```

Each cell verifies: app import with `--base-fs`, container boot,
`sdme-oci-app.service` active, journal and status accessible, and
app-specific health check (HTTP 200 for nginx, mysqladmin status,
pg_isready, redis-cli ping).

See `./test/verify-matrix.sh --help` for all options.

### verify-pods.sh

Pod networking validation. Tests shared network namespace connectivity,
`--private-network` interaction, and error cases.

Requires the `ubuntu` rootfs imported beforehand:

```bash
sudo sdme fs import ubuntu docker.io/ubuntu:24.04 -v --install-packages=yes
sudo ./test/verify-pods.sh
```

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
sudo ./test/verify-security.sh

# Full run including multi-distro userns tests
sudo ./test/verify-matrix.sh --keep
sudo ./test/verify-security.sh
```

## 3. Results

### Unit tests

Current status: 319 passed, 0 failed, 3 ignored.

### Base OS Import and Boot

| Distro    | Image                            | Import | Boot |
|-----------|----------------------------------|--------|------|
| debian    | docker.io/debian:stable          | PASS   | PASS |
| ubuntu    | docker.io/ubuntu:24.04           | PASS   | PASS |
| fedora    | quay.io/fedora/fedora:41         | PASS   | PASS |
| centos    | quay.io/centos/centos:stream9    | PASS   | PASS |
| almalinux | quay.io/almalinuxorg/almalinux:9 | PASS   | PASS |

Boot tests verify: container create, systemd reaching `running` state,
journalctl access, and systemctl unit listing.

### OCI App Matrix

| App      | Image              | debian | ubuntu | fedora | centos | alma   |
|----------|--------------------|--------|--------|--------|--------|--------|
| nginx    | docker.io/nginx    | PASS   | SKIP*  | PASS   | PASS   | PASS   |
| mysql    | docker.io/mysql    | PASS   | PASS   | PASS   | PASS   | SKIP*  |
| postgres | docker.io/postgres | PASS   | PASS   | PASS   | PASS   | PASS   |
| redis    | docker.io/redis    | PASS   | PASS   | PASS   | PASS   | PASS   |

\* Docker Hub network timeout during blob download (transient).

Each cell verifies: app import with `--base-fs`, container boot,
`sdme-oci-app.service` active, journal and status accessible, and
app-specific health check (HTTP 200 for nginx, mysqladmin status,
pg_isready, redis-cli ping).

### Pod Tests

| Test                                          | Result |
|-----------------------------------------------|--------|
| nspawn pod loopback                           | PASS   |
| --pod + --private-network drop-in             | PASS   |
| --pod + --private-network loopback            | PASS   |
| --pod + --hardened rejected                   | PASS   |
| --pod + --userns rejected                     | PASS   |
| --oci-pod without OCI rootfs rejected         | PASS   |
| --pod=nonexistent rejected                    | PASS   |
| --oci-pod + --hardened not rejected           | PASS   |

- **nspawn pod loopback**: two `--pod` containers share localhost
  via a Python listener/client on port 9999.
- **--pod + --private-network**: `--private-network` is silently
  dropped since the pod's netns provides equivalent loopback-only
  isolation. Verifies drop-in omits `--private-network` and loopback
  connectivity works.
- **--pod + --hardened/--userns rejected**: the kernel blocks
  `setns(CLONE_NEWNET)` from a child user namespace into the pod's
  netns (owned by init userns). Use `--oci-pod` for hardened pods.
- **--oci-pod without OCI rootfs**: error correctly rejected.
- **--pod=nonexistent**: non-existent pod correctly rejected.
- **--oci-pod + --hardened**: combined successfully; the OCI app
  service enters the pod's netns via its inner systemd drop-in
  (`NetworkNamespacePath=`), avoiding the cross-userns restriction.

### Security Hardening Tests

| Test                                    | Result |
|-----------------------------------------|--------|
| CLI: unknown capability rejected        | PASS   |
| CLI: invalid syscall filter rejected    | PASS   |
| CLI: contradictory caps rejected        | PASS   |
| CLI: invalid AppArmor profile rejected  | PASS   |
| CLI: empty syscall filter rejected      | PASS   |
| State: all security fields persisted    | PASS   |
| --drop-capability removes cap           | PASS   |
| --capability adds cap                   | PASS   |
| --no-new-privileges blocks escalation   | PASS   |
| --read-only makes rootfs read-only      | PASS   |
| --system-call-filter state + drop-in    | PASS   |
| --hardened bundle (state check)         | PASS   |
| --hardened with --capability override   | PASS   |
| --apparmor-profile persistence          | PASS   |
| --hardened container boots              | PASS   |
| --hardened runtime enforcement          | PASS   |
| sdme ps shows container                 | PASS   |
| debian boot with --userns              | PASS   |
| ubuntu boot with --userns              | PASS   |
| fedora boot with --userns              | PASS   |
| centos boot with --userns              | PASS   |
| almalinux boot with --userns           | PASS   |
| nginx OCI app with --userns            | PASS   |

- **CLI validation**: verifies that invalid capability names, syscall filter
  syntax, contradictory caps, and bad AppArmor profile names are rejected
  at create time.
- **State persistence**: creates a container with all security flags and
  verifies each KEY=VALUE is written to the state file.
- **Runtime enforcement**: boots containers with individual security flags
  and verifies enforcement from inside (CapBnd bitmask, NoNewPrivs,
  read-only writes, seccomp-blocked mount).
- **--hardened bundle**: verifies the combined effect (userns, private-network,
  no-new-privileges, cap drops) and that explicit `--capability` overrides
  suppress the corresponding hardened drop.
- **AppArmor**: verifies profile name persists in state and the
  `AppArmorProfile=` directive appears in the systemd drop-in.
- **--userns boot**: each distro boots with `--userns`, systemd reaches
  `running` or `degraded` state.
- **--userns OCI app**: nginx imported as OCI app on ubuntu base, container
  created with `--userns`, `sdme-oci-app.service` is active.

### Hardened Boot Matrix

| Distro    | Create | systemd |
|-----------|--------|---------|
| debian    | PASS   | PASS    |
| ubuntu    | PASS   | PASS    |
| fedora    | PASS   | PASS    |
| centos    | PASS   | PASS    |
| almalinux | PASS   | PASS    |

Each distro is created with `--hardened` and verified to reach `running`
or `degraded` state. Hardened enables user namespace isolation,
private network, no-new-privileges, and drops
`CAP_SYS_PTRACE,CAP_NET_RAW,CAP_SYS_RAWIO,CAP_SYS_BOOT`.

### Hardened OCI App Matrix

| App      | Distro    | Boot   | Service |
|----------|-----------|--------|---------|
| nginx    | debian    | PASS   | PASS    |
| nginx    | ubuntu    | SKIP*  | SKIP*   |
| nginx    | fedora    | PASS   | PASS    |
| nginx    | centos    | PASS   | PASS    |
| nginx    | almalinux | PASS   | PASS    |
| mysql    | debian    | PASS   | PASS    |
| mysql    | ubuntu    | PASS   | PASS    |
| mysql    | fedora    | PASS   | PASS    |
| mysql    | centos    | PASS   | PASS    |
| mysql    | almalinux | SKIP*  | SKIP*   |
| postgres | debian    | PASS   | PASS    |
| postgres | ubuntu    | PASS   | PASS    |
| postgres | fedora    | PASS   | PASS    |
| postgres | centos    | PASS   | PASS    |
| postgres | almalinux | PASS   | PASS    |
| redis    | debian    | PASS   | PASS    |
| redis    | ubuntu    | PASS   | PASS    |
| redis    | fedora    | PASS   | PASS    |
| redis    | centos    | PASS   | PASS    |
| redis    | almalinux | PASS   | PASS    |

\* Skipped due to transient Docker Hub network failure during OCI app import.

Each cell verifies: container created with `--hardened`, boots
successfully, and `sdme-oci-app.service` is active. App-specific
health checks (HTTP, CLI) are skipped because `--hardened` enables
private network, blocking host-side connectivity.
