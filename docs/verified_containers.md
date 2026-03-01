# Verified Containers

Last verified: 2026-03-01

System: Linux 6.17.0-14-generic, systemd 257 (257.9-0ubuntu2.1), sdme 0.1.6

## Base OS Import and Boot

| Distro    | Image                          | Import | Boot |
|-----------|--------------------------------|--------|------|
| debian    | docker.io/debian:stable        | PASS   | PASS |
| ubuntu    | docker.io/ubuntu:24.04         | PASS   | PASS |
| fedora    | docker.io/fedora:41            | PASS   | PASS |
| centos    | quay.io/centos/centos:stream9  | PASS   | PASS |
| almalinux | docker.io/almalinux:9          | PASS   | PASS |

Boot tests verify: container create, systemd reaching `running` state,
journalctl access, and systemctl unit listing.

## OCI App Matrix

| App      | Image              | debian | ubuntu | fedora | centos | alma |
|----------|--------------------|--------|--------|--------|--------|------|
| nginx    | docker.io/nginx    | PASS   | PASS   | PASS   | PASS   | PASS |
| mysql    | docker.io/mysql    | PASS   | PASS   | PASS   | PASS   | PASS |
| postgres | docker.io/postgres | PASS   | PASS   | PASS   | PASS   | PASS |
| redis    | docker.io/redis    | PASS   | PASS   | PASS   | PASS   | PASS |

Each cell verifies: app import with `--base-fs`, container boot,
`sdme-oci-app.service` active, journal and status accessible, and
app-specific health check (HTTP 200 for nginx, mysqladmin status,
pg_isready, redis-cli ping).

## Pod Tests

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

## User Namespace Tests

| Test                              | Result  |
|-----------------------------------|---------|
| debian boot with --userns         | PASS    |
| ubuntu boot with --userns         | PASS    |
| fedora boot with --userns         | PASS    |
| centos boot with --userns         | PASS    |
| almalinux boot with --userns      | PASS    |
| nginx OCI app with --userns       | PASS    |

- **distro boot with --userns**: container created with `--userns`, systemd
  reaches `running` or `degraded` state.
- **nginx OCI app with --userns**: nginx imported as OCI app on ubuntu base,
  container created with `--userns`, `sdme-oci-app.service` is active.

## Hardened Boot Matrix

| Distro    | Create  | systemd |
|-----------|---------|---------|
| debian    | PENDING | PENDING |
| ubuntu    | PENDING | PENDING |
| fedora    | PENDING | PENDING |
| centos    | PENDING | PENDING |
| almalinux | PENDING | PENDING |

Each distro is created with `--hardened` and verified to reach `running`
or `degraded` state. Hardened enables user namespace isolation,
private network, no-new-privileges, and drops
`CAP_SYS_PTRACE,CAP_NET_RAW,CAP_SYS_RAWIO,CAP_SYS_BOOT`.

## Hardened OCI App Matrix

| App      | Distro    | Boot    | Service |
|----------|-----------|---------|---------|
| nginx    | debian    | PENDING | PENDING |
| nginx    | ubuntu    | PENDING | PENDING |
| nginx    | fedora    | PENDING | PENDING |
| nginx    | centos    | PENDING | PENDING |
| nginx    | almalinux | PENDING | PENDING |
| mysql    | debian    | PENDING | PENDING |
| mysql    | ubuntu    | PENDING | PENDING |
| mysql    | fedora    | PENDING | PENDING |
| mysql    | centos    | PENDING | PENDING |
| mysql    | almalinux | PENDING | PENDING |
| postgres | debian    | PENDING | PENDING |
| postgres | ubuntu    | PENDING | PENDING |
| postgres | fedora    | PENDING | PENDING |
| postgres | centos    | PENDING | PENDING |
| postgres | almalinux | PENDING | PENDING |
| redis    | debian    | PENDING | PENDING |
| redis    | ubuntu    | PENDING | PENDING |
| redis    | fedora    | PENDING | PENDING |
| redis    | centos    | PENDING | PENDING |
| redis    | almalinux | PENDING | PENDING |

Each cell verifies: container created with `--hardened`, boots
successfully, and `sdme-oci-app.service` is active. App-specific
health checks (HTTP, CLI) are skipped because `--hardened` enables
private network, blocking host-side connectivity.

## Security Hardening Tests

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

## Running the verification

```bash
# Full distro x OCI app matrix (5 distros x 4 apps, 145 checks total)
sudo ./test/verify-matrix.sh
sudo ./test/verify-matrix.sh --distro ubuntu --app nginx  # single cell
sudo ./test/verify-matrix.sh --keep                       # keep artifacts

# Pod tests (requires ubuntu rootfs)
sudo sdme fs import ubuntu docker.io/ubuntu:24.04 -v --install-packages=yes
sudo ./test/verify-pods.sh

# User namespace tests (requires base rootfs from verify-matrix.sh)
sudo ./test/verify-matrix.sh --keep  # import base rootfs first
sudo ./test/verify-userns.sh

# Security hardening tests (requires ubuntu rootfs)
sudo sdme fs import ubuntu docker.io/ubuntu:24.04 -v --install-packages=yes
sudo ./test/verify-security.sh
```

See `test/verify-matrix.sh --help` for all options.
