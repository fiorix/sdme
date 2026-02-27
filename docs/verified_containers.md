# Verified Containers

Last verified: 2026-02-27

System: Linux 6.17.0-14-generic, systemd 257 (257.9-0ubuntu2.1), sdme 0.1.3

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

| App      | Image              | debian | ubuntu | fedora | centos | almalinux |
|----------|--------------------|--------|--------|--------|--------|-----------|
| nginx    | docker.io/nginx    | PASS   | PASS   | PASS   | PASS   | PASS      |
| mysql    | docker.io/mysql    | PASS   | PASS   | PASS   | PASS   | PASS      |
| postgres | docker.io/postgres | PASS   | PASS   | PASS   | PASS   | PASS      |
| redis    | docker.io/redis    | PASS   | PASS   | PASS   | PASS   | PASS      |

Each cell verifies: app import with `--base-fs`, container boot,
`sdme-oci-app.service` active, journal and status accessible, and
app-specific health check (HTTP 200 for nginx, mysqladmin status,
pg_isready, redis-cli ping).

## Running the verification

```bash
sudo ./scripts/verify-matrix.sh                          # full matrix
sudo ./scripts/verify-matrix.sh --distro ubuntu --app nginx  # single cell
sudo ./scripts/verify-matrix.sh --keep                   # keep artifacts
```

See `scripts/verify-matrix.sh --help` for all options.
