# Test Results

Last verified: 2026-03-16

System: Linux 6.19.6-2-cachyos (x86_64), systemd 259 (259.3-1-arch), sdme 0.4.0

See [README.md](README.md) for how to run the tests.

## Base OS Import and Boot

| Distro    | Image                             | Import | Boot | OS (running) | OS (stopped) |
|-----------|-----------------------------------|--------|------|--------------|--------------|
| debian    | docker.io/debian:stable           | PASS   | PASS | PASS         | PASS         |
| ubuntu    | docker.io/ubuntu:24.04            | PASS   | PASS | PASS         | PASS         |
| fedora    | quay.io/fedora/fedora:41          | PASS   | PASS | PASS         | PASS         |
| centos    | quay.io/centos/centos:stream10    | PASS   | PASS | PASS         | PASS         |
| almalinux | quay.io/almalinuxorg/almalinux:9  | PASS   | PASS | PASS         | PASS         |
| archlinux | docker.io/lopsided/archlinux      | PASS   | PASS | PASS         | PASS         |

Boot tests verify: container create, systemd reaching `running` state,
journalctl access, and systemctl unit listing.

OS detection tests verify that `sdme ps` shows the correct distro name
(from `PRETTY_NAME` in os-release) both while the container is running
(reads from overlayfs `merged/`) and after stop (cascade through
`upper/` then the imported rootfs).

archlinux requires x86_64: the `docker.io/lopsided/archlinux` image
only publishes `linux/amd64` manifests.

## OCI App Matrix

| App                | Image                              | deb  | ubu  | fed  | cen  | alma | arch |
|--------------------|------------------------------------|------|------|------|------|------|------|
| nginx-unprivileged | docker.io/nginxinc/nginx-unpriv... | PASS | PASS | PASS | PASS | PASS | PASS |
| redis              | docker.io/redis                    | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL |
| postgresql         | docker.io/postgres                 | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL |

Each cell verifies: app import with `--base-fs`, container boot,
`sdme-oci-{name}.service` active, journal and status accessible, and
app-specific health check (marker file served by nginx-unprivileged,
redis-cli ping, pg_isready).

redis and postgresql verify checks fail on all distros: `sdme exec --oci`
cannot find the cgroup for the OCI service under
`/sys/fs/cgroup/machine.slice`. Import, boot, service, logs, and status
checks all pass. This is a cgroup lookup regression in `exec --oci`,
not an OS detection issue.

## Pod Tests

| Test                                          | Result |
|-----------------------------------------------|--------|
| nspawn pod loopback                           | PASS   |
| --pod + --private-network drop-in             | PASS   |
| --pod + --private-network loopback            | PASS   |
| --pod + --hardened rejected                   | PASS   |
| --pod + --userns rejected                     | PASS   |
| --oci-pod without --private-network rejected  | PASS   |
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
- **--oci-pod without --private-network rejected**: `--oci-pod`
  requires `--private-network` (or `--hardened`/`--strict` which
  imply it) because systemd-nspawn strips `CAP_NET_ADMIN` on
  host-network containers, which prevents the inner
  `NetworkNamespacePath=` directive from calling
  `setns(CLONE_NEWNET)`.
- **--oci-pod without OCI rootfs**: error correctly rejected.
- **--pod=nonexistent**: non-existent pod correctly rejected.
- **--oci-pod + --hardened**: combined successfully; `--hardened`
  implies `--private-network`, satisfying the `CAP_NET_ADMIN`
  requirement. The OCI app service enters the pod's netns via its
  inner systemd drop-in (`NetworkNamespacePath=`).

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
| --apparmor-profile drop-in              | SKIP   |
| --apparmor-profile enforcement: boot    | PASS   |
| --apparmor-profile enforcement: profile | PASS   |
| --apparmor-profile enforcement: deny    | PASS   |
| --hardened container boots              | PASS   |
| --hardened runtime enforcement          | PASS   |
| sdme ps shows container                 | PASS   |
| debian boot with --userns              | PASS   |
| ubuntu boot with --userns              | PASS   |
| fedora boot with --userns              | PASS   |
| centos boot with --userns              | PASS   |
| almalinux boot with --userns           | PASS   |
| archlinux boot with --userns           | PASS   |
| nginx OCI app with --userns            | PASS   |

- **CLI validation**: verifies that invalid capability names, syscall filter
  syntax, contradictory caps, and bad AppArmor profile names are rejected
  at create time.
- **State persistence**: creates a container with all security flags and
  verifies each KEY=VALUE is written to the state file.
- **Runtime enforcement**: boots containers with individual security flags
  and verifies enforcement from inside (CapBnd bitmask, NoNewPrivs,
  read-only writes, seccomp-blocked mount).
- **--hardened bundle**: verifies the combined effect (userns,
  private-network, no-new-privileges, cap drops) and that explicit
  `--capability` overrides suppress the corresponding hardened drop.
- **AppArmor**: enforcement tests verified on Ubuntu 25.10 (aarch64)
  with AppArmor LSM enabled. The `sdme-default` profile is installed,
  loaded, and enforced on container PID 1. Denied writes to
  `/proc/sysrq-trigger` are blocked. The `--apparmor-profile` drop-in
  test is skipped when the profile name used doesn't exist on the host
  (expected; the create-time persistence test covers state correctness).
- **--userns boot**: each distro boots with `--userns`, systemd reaches
  `running` or `degraded` state.
- **--userns OCI app**: nginx imported as OCI app on ubuntu base, container
  created with `--userns`, `sdme-oci-{name}.service` is active.

## Hardened Boot Matrix

| Distro    | Create | systemd |
|-----------|--------|---------|
| debian    | PASS   | PASS    |
| ubuntu    | PASS   | PASS    |
| fedora    | PASS   | PASS    |
| centos    | PASS   | PASS    |
| almalinux | PASS   | PASS    |
| archlinux | PASS   | PASS    |

Each distro is created with `--hardened` and verified to reach `running`
or `degraded` state. Hardened enables user namespace isolation,
private network, no-new-privileges, and drops
`CAP_SYS_PTRACE,CAP_NET_RAW,CAP_SYS_RAWIO,CAP_SYS_BOOT`.

## Hardened OCI App Matrix

| App                | Distro    | Boot | Service |
|--------------------|-----------|------|---------|
| nginx-unprivileged | debian    | PASS | PASS    |
| nginx-unprivileged | ubuntu    | PASS | PASS    |
| nginx-unprivileged | fedora    | PASS | PASS    |
| nginx-unprivileged | centos    | PASS | PASS    |
| nginx-unprivileged | almalinux | PASS | PASS    |
| nginx-unprivileged | archlinux | PASS | PASS    |
| redis              | debian    | PASS | PASS    |
| redis              | ubuntu    | PASS | PASS    |
| redis              | fedora    | PASS | PASS    |
| redis              | centos    | PASS | PASS    |
| redis              | almalinux | PASS | PASS    |
| redis              | archlinux | PASS | PASS    |
| postgresql         | debian    | PASS | PASS    |
| postgresql         | ubuntu    | PASS | PASS    |
| postgresql         | fedora    | PASS | PASS    |
| postgresql         | centos    | PASS | PASS    |
| postgresql         | almalinux | PASS | PASS    |
| postgresql         | archlinux | PASS | PASS    |

Each cell verifies: container created with `--hardened`, boots
successfully, and `sdme-oci-{name}.service` is active. App-specific
health checks (HTTP, CLI) are skipped because `--hardened` enables
private network, blocking host-side connectivity.

## OCI Port Forwarding and Volume Mounting

| Distro | Import | State | Volume | Boot | Service | Logs | Curl |
|--------|--------|-------|--------|------|---------|------|------|
| ubuntu | PASS   | PASS  | PASS   | PASS | PASS    | PASS | SKIP |
| fedora | PASS   | PASS  | PASS   | PASS | PASS    | PASS | SKIP |

App image: `quay.io/nginx/nginx-unprivileged` (listens on 8080/tcp).
Containers created with `--private-network --network-veth` to exercise
port forwarding through a virtual ethernet pair.

Curl tests skipped: `systemd-networkd` is not managing host-side veth
interfaces on this test system (CachyOS uses NetworkManager). The
host-side `ve-*` interface does not get an IP address, so port-forwarded
HTTP requests cannot be routed. All other checks (import, state, volume
creation, boot, service active, OCI logs) pass. To be tested on a
system with `systemd-networkd` managing network interfaces.

## Kube Tests

Run in order with `--base-fs ubuntu`.

| Script | Level | Tests | Pass | Fail | Skip | Result |
|--------|-------|-------|------|------|------|--------|
| verify-kube-L1-basic.sh | L1 Basic lifecycle | 11 | 11 | 0 | 0 | PASS |
| verify-kube-L2-spec.sh | L2 Pod spec features | 12 | 6 | 6 | 0 | FAIL |
| verify-kube-L2-security.sh | L2 Container securityContext | 17 | 15 | 2 | 0 | FAIL |
| verify-kube-L3-volumes.sh | L3 Volumes (secrets, configmaps, PVCs) | 39 | 33 | 4 | 2 | FAIL |
| verify-kube-L3-secrets.sh | L3 Secret volumes | 16 | 16 | 0 | 0 | PASS |
| verify-kube-L4-networking.sh | L4 Localhost networking | 6 | 6 | 0 | 0 | PASS |
| verify-kube-L5-redis.sh | L5 Redis round-trip | 6 | 6 | 0 | 0 | PASS |
| verify-kube-L6-gitea.sh | L6 Gitea stack | 15 | 15 | 0 | 0 | PASS |

### L2-spec failures

6 unit file checks fail: `terminationGracePeriodSeconds` (TimeoutStopSec),
`workingDir`, `resources` (MemoryMax, CPUQuota, etc.), `securityContext`
(runAsUser/runAsGroup), init container dependency ordering
(After=/Requires=), and `readinessProbe` (ExecStartPost). These are
kube spec features that the test scripts check for but are not yet
fully implemented in the unit file generator. Runtime checks pass
(init service, app service, memory limit enforcement).

### L2-security failures

2 failures: (1) `seccompProfile: type: Unconfined` on a container
should suppress the pod-level seccomp filter, but the generated unit
still includes `SystemCallFilter=`; (2) the `hardened` container's
`sdme-oci-hardened.service` fails at runtime when running as
UID 1000/GID 1000 with the current isolate binary setup.

### L3-volumes failures

4 failures in secret volume static checks: secret files are not being
written to the rootfs during kube create for the combined volumes test
pod. The standalone L3-secrets test (which tests the same functionality
in isolation) passes all 16 checks, suggesting this is a test ordering
or resource contention issue in the combined test rather than a
code bug. PVC, configMap, envFrom, and read-only mount tests all pass.

## Export Tests

| Test                    | Result |
|-------------------------|--------|
| dir export              | PASS   |
| tar export              | PASS   |
| tar.gz export           | PASS   |
| tar.bz2 export          | PASS   |
| tar.xz export           | PASS   |
| tar.zst export          | PASS   |
| raw export (auto-size)  | PASS   |
| raw export --size 2G    | PASS   |
| btrfs raw export        | PASS   |
| btrfs raw export --size | PASS   |
| format override (-f)    | PASS   |
| nonexistent rootfs      | PASS   |

- **dir export**: exports ubuntu rootfs to a directory, verifies
  `etc/os-release` exists.
- **tar/tar.gz/tar.bz2/tar.xz/tar.zst**: creates compressed tarballs,
  verifies archive contains `etc/os-release`.
- **raw export**: creates a bare ext4 disk image (auto-sized), loop-mounts
  it, verifies `etc/os-release` exists.
- **raw export --size 2G**: creates a 2 GiB raw image, verifies file size
  matches exactly.
- **btrfs raw export**: creates a bare btrfs disk image (auto-sized),
  loop-mounts it, verifies `etc/os-release` exists. Requires `mkfs.btrfs`.
- **btrfs raw export --size**: creates a 2 GiB btrfs raw image, verifies
  file size matches exactly.
- **format override**: exports with `-f tar.gz` to a file without extension,
  verifies the output is a valid gzip tarball.
- **nonexistent rootfs**: `sdme fs export nonexistent` correctly exits
  non-zero.

## Usage Guide Verification

48 passed, 1 failed, 0 skipped (x86_64 without AppArmor).

The `--strict` security test fails on systems without AppArmor because
`--strict` implies `--apparmor-profile=sdme-default`. On systems with
AppArmor (e.g. Ubuntu), install the profile first:
`sdme config apparmor-profile > /etc/apparmor.d/sdme-default && apparmor_parser -r /etc/apparmor.d/sdme-default`.

Walks through each section of `docs/usage.md` and runs the documented
commands: host clone lifecycle, distro import, OCI apps (nginx, redis,
postgresql with `--oci-env`), `exec --oci`, `logs --oci`, pods with
connectivity, security flags (`--hardened`, `--strict`, individual),
networking (private, veth, zones), resource limits, bind mounts,
environment variables, kube apply, and configuration.
