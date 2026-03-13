# Test Results

Last verified: 2026-03-12

System: Linux 6.19.2-2-cachyos (x86_64), systemd 259 (259.1-1-arch), sdme 0.3.1

See [README.md](README.md) for how to run the tests.

## Unit tests

452 passed, 0 failed, 3 ignored.

## Base OS Import and Boot

| Distro    | Image                             | Import | Boot |
|-----------|-----------------------------------|--------|------|
| debian    | docker.io/debian:stable           | PASS   | PASS |
| ubuntu    | docker.io/ubuntu:24.04            | PASS   | PASS |
| fedora    | quay.io/fedora/fedora:41          | PASS   | PASS |
| centos    | quay.io/centos/centos:stream9     | PASS   | PASS |
| almalinux | quay.io/almalinuxorg/almalinux:9  | PASS   | PASS |
| suse      | docker.io/opensuse/tumbleweed     | PASS   | PASS |
| archlinux | docker.io/archlinux               | PASS   | PASS |

Boot tests verify: container create, systemd reaching `running` state,
journalctl access, and systemctl unit listing.

archlinux requires x86_64: the `docker.io/archlinux` image only
publishes `linux/amd64` manifests.

## OCI App Matrix

| App                | Image                              | deb  | ubu  | fed  | cen  | alma | suse | arch |
|--------------------|------------------------------------|------|------|------|------|------|------|------|
| nginx-unprivileged | docker.io/nginxinc/nginx-unpriv... | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| redis              | docker.io/redis                    | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| postgresql         | docker.io/postgres                 | PASS | PASS | PASS | PASS | PASS | PASS | PASS |

Each cell verifies: app import with `--base-fs`, container boot,
`sdme-oci-app.service` active, journal and status accessible, and
app-specific health check (marker file served by nginx-unprivileged,
redis-cli ping, pg_isready).

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
- **AppArmor**: verifies profile name persists in state file.
  The drop-in check is skipped when the test profile is not loaded
  on the host (the start fails before writing the drop-in).
  Enforcement test installs the `sdme-default` profile
  on the host, boots a container with
  `--apparmor-profile=sdme-default`, verifies PID 1 shows
  `sdme-default (enforce)` in `/proc/1/attr/apparmor/current`,
  and confirms denied writes (e.g. `/proc/sysrq-trigger`) are
  blocked.
- **--userns boot**: each distro boots with `--userns`, systemd reaches
  `running` or `degraded` state. suse skipped (requires rootfs from
  `verify-matrix.sh --keep`; suse userns has a systemd UID/GID shift
  incompatibility).
- **--userns OCI app**: nginx imported as OCI app on ubuntu base, container
  created with `--userns`, `sdme-oci-app.service` is active.

## Hardened Boot Matrix

| Distro    | Create | systemd |
|-----------|--------|---------|
| debian    | PASS   | PASS    |
| ubuntu    | PASS   | PASS    |
| fedora    | PASS   | PASS    |
| centos    | PASS   | PASS    |
| almalinux | PASS   | PASS    |
| suse      | PASS   | PASS    |
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
| nginx-unprivileged | suse      | FAIL | SKIP    |
| nginx-unprivileged | archlinux | PASS | PASS    |
| redis              | debian    | PASS | PASS    |
| redis              | ubuntu    | PASS | PASS    |
| redis              | fedora    | PASS | PASS    |
| redis              | centos    | PASS | PASS    |
| redis              | almalinux | PASS | PASS    |
| redis              | suse      | FAIL | SKIP    |
| redis              | archlinux | PASS | PASS    |
| postgresql         | debian    | PASS | PASS    |
| postgresql         | ubuntu    | PASS | PASS    |
| postgresql         | fedora    | PASS | PASS    |
| postgresql         | centos    | PASS | PASS    |
| postgresql         | almalinux | PASS | PASS    |
| postgresql         | suse      | FAIL | SKIP    |
| postgresql         | archlinux | PASS | PASS    |

Each cell verifies: container created with `--hardened`, boots
successfully, and `sdme-oci-app.service` is active. App-specific
health checks (HTTP, CLI) are skipped because `--hardened` enables
private network, blocking host-side connectivity.

Hardened suse OCI apps fail because the openSUSE Tumbleweed rootfs
has a UID/GID shift incompatibility (`Failed to adjust UID/GID shift
of OS tree`). The suse base OS boots fine with `--hardened` (no OCI
app overlay). This is a systemd version mismatch, not an sdme issue.

## OCI Port Forwarding and Volume Mounting

| Distro | Import | State | Volume | Boot | Curl |
|--------|--------|-------|--------|------|------|
| ubuntu | PASS   | PASS  | PASS   | PASS | PASS |
| fedora | PASS   | PASS  | PASS   | PASS | PASS |

App image: `quay.io/nginx/nginx-unprivileged` (listens on 8080/tcp).
Containers created with `--private-network --network-veth` to exercise
port forwarding through a virtual ethernet pair. `systemd-networkd`
is enabled in the overlayfs upper layer so the container-side `host0`
interface gets configured via DHCP.

Each column covers multiple checks per distro (18 total):
- **Import**: base OS rootfs and nginx-unprivileged OCI app
- **State**: `PORTS` contains `tcp:8080:8080`, `OCI_VOLUMES` is set
- **Volume**: host-side directory at
  `volumes/{name}/usr-share-nginx-html/` exists after create
- **Boot**: container starts, `sdme-oci-app.service` is active
- **Curl**: HTTP 200 on the forwarded port via host-side veth IP,
  response body contains the test HTML marker

The volume path `/usr/share/nginx/html` (nginx document root) is
appended to the rootfs `oci/volumes` file after import, since
nginx-unprivileged declares exposed ports but no volumes. This
exercises the full pipeline: read volumes file, create host dirs,
add bind mounts, serve content.

## Kube Tests

Run in order with `--base-fs ubuntu`.

| Script | Level | Tests | Pass | Fail | Skip | Result |
|--------|-------|-------|------|------|------|--------|
| verify-kube-L1-basic.sh | L1 Basic lifecycle | 11 | 11 | 0 | 0 | PASS |
| verify-kube-L2-spec.sh | L2 Pod spec features | 12 | 12 | 0 | 0 | PASS |
| verify-kube-L3-volumes.sh | L3 Volumes (secrets, configmaps, PVCs) | 31 | 31 | 0 | 0 | PASS |
| verify-kube-L4-networking.sh | L4 Localhost networking | 6 | 6 | 0 | 0 | PASS |
| verify-kube-L5-redis.sh | L5 Redis round-trip | 6 | 6 | 0 | 0 | PASS |
| verify-kube-L6-gitea.sh | L6 Gitea stack | 15 | 15 | 0 | 0 | PASS |


## Usage Guide Verification

44 passed, 0 failed, 0 skipped.

Walks through each section of `docs/usage.md` and runs the documented
commands: host clone lifecycle, distro import, OCI apps (nginx, redis,
postgresql with `--oci-env`), `exec --oci`, `logs --oci`, pods with
connectivity, security flags (`--hardened`, `--strict`, individual),
networking (private, veth, zones), resource limits, bind mounts,
environment variables, and configuration.
