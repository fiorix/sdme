# Verified Containers

Last verified: 2026-02-28

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

| Test                          | Result |
|-------------------------------|--------|
| nspawn pod loopback           | PASS   |
| --pod + --hardened            | PASS   |
| --oci-pod without OCI rootfs  | PASS   |
| --pod=nonexistent             | PASS   |
| --oci-pod + --hardened        | PASS   |

- **nspawn pod loopback**: two `--pod` containers share localhost
  via a Python listener/client on port 9999.
- **--pod + --hardened**: combined successfully; `--private-network`
  is omitted from nspawn args since the pod's netns provides equivalent
  loopback-only isolation.
- **--oci-pod without OCI rootfs**: error correctly rejected.
- **--pod=nonexistent**: non-existent pod correctly rejected.
- **--oci-pod + --hardened**: combined successfully; `--private-network`
  applies to the nspawn container while the OCI app service enters the
  pod's netns via its systemd drop-in.

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

## Security Hardening Tests

| Test                                    | Result  |
|-----------------------------------------|---------|
| CLI: unknown capability rejected        | PENDING |
| CLI: invalid syscall filter rejected    | PENDING |
| CLI: contradictory caps rejected        | PENDING |
| CLI: invalid AppArmor profile rejected  | PENDING |
| CLI: empty syscall filter rejected      | PENDING |
| State: all security fields persisted    | PENDING |
| --drop-capability removes cap           | PENDING |
| --capability adds cap                   | PENDING |
| --no-new-privileges blocks escalation   | PENDING |
| --read-only makes rootfs read-only      | PENDING |
| --system-call-filter state + drop-in    | PENDING |
| --hardened bundle (state check)         | PENDING |
| --hardened with --capability override   | PENDING |
| --apparmor-profile persistence          | PENDING |
| --hardened container boots              | PENDING |
| --hardened network is private           | PENDING |
| sdme ps shows container                 | PENDING |

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
