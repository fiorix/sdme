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
| --pod + --private-network     | PASS   |
| --oci-pod without OCI rootfs  | PASS   |
| --pod=nonexistent             | PASS   |
| --oci-pod + --private-network | PASS   |

- **nspawn pod loopback**: two `--pod` containers share localhost
  via a Python listener/client on port 9999.
- **--pod + --private-network**: mutual exclusion correctly rejected.
- **--oci-pod without OCI rootfs**: error correctly rejected.
- **--pod=nonexistent**: non-existent pod correctly rejected.
- **--oci-pod + --private-network**: no mutual exclusion; the error
  is about missing OCI rootfs, not a network conflict.

## Running the verification

```bash
# Full distro x OCI app matrix (5 distros x 4 apps, 145 checks total)
sudo ./scripts/verify-matrix.sh
sudo ./scripts/verify-matrix.sh --distro ubuntu --app nginx  # single cell
sudo ./scripts/verify-matrix.sh --keep                       # keep artifacts

# Pod tests (requires ubuntu rootfs)
sudo sdme fs import ubuntu docker.io/ubuntu:24.04 -v --install-packages=yes
sudo ./scripts/verify-pods.sh
```

See `scripts/verify-matrix.sh --help` for all options.
