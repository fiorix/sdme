# OCI Container Support in sdme

sdme manages systemd-booted containers: full init, journal, cgroups, the
works. OCI images come from a different world: single-process, no init,
environment-driven configuration. These two paradigms don't naturally fit
together, but there's a useful middle ground.

The idea is simple: use sdme as a glue layer. Import a base OS image
(Ubuntu, Debian, Fedora) that has systemd, then run OCI application images
*inside* that base as regular systemd services. You get the operational model
of systemd (journalctl, systemctl, resource limits) with the packaging model
of OCI (Docker Hub, GHCR, Quay).

This is experimental. It works well for stateless services like nginx. More
complex images like databases work too, but need manual env-var setup. Port
forwarding and volume binding are not wired up yet.

## Two modes of import

When you `sdme fs import` an OCI registry image, sdme classifies it as either
a **base OS image** or an **application image**.

**Base OS images** (ubuntu, debian, fedora, etc.) have no entrypoint, use a
shell as their default command, and expose no ports. sdme extracts the rootfs
and installs systemd if it's missing. The result is a first-class sdme rootfs
you can use with `sdme new -r <name>`.

**Application images** (nginx, mysql, redis, etc.) have an entrypoint, a
non-shell command, or exposed ports. sdme places the application rootfs under
`/oci/root` inside a copy of a base rootfs you specify with `--base-fs`.
A systemd service unit (`sdme-oci-app.service`) is generated that chroots into
`/oci/root` and runs the application's entrypoint.

The `--oci-mode` flag lets you override auto-detection:

| Flag                   | Behavior                                      |
|------------------------|-----------------------------------------------|
| `--oci-mode=auto`      | Auto-detect from image config (default)        |
| `--oci-mode=base`      | Force base OS mode                             |
| `--oci-mode=app`       | Force application mode (requires `--base-fs`)  |

## How it works

When an application image is imported, sdme:

1. Pulls and extracts the OCI image layers (with whiteout handling)
2. Copies the base rootfs (e.g. ubuntu) to the new rootfs directory
3. Moves the OCI application rootfs to `/oci/root/` inside the base
4. Creates essential runtime dirs (`/tmp`, `/run`, etc.) inside `/oci/root`
5. Deploys a devfd shim (`/.sdme-devfd-shim.so`) that intercepts `open()` on
   `/dev/std*` paths to work around ENXIO on journal sockets (see
   [docs/devfd-shim.md](devfd-shim.md))
6. Writes OCI metadata under `/oci/`:
   - `/oci/env`: environment variables from the image config
   - `/oci/ports`: exposed ports (for reference)
   - `/oci/volumes`: declared volumes (for reference)
7. Generates `etc/systemd/system/sdme-oci-app.service` with:
   - `RootDirectory=/oci/root`: chroots into the OCI rootfs
   - `MountAPIVFS=yes`: provides `/proc`, `/sys`, `/dev`
   - `Environment=LD_PRELOAD=/.sdme-devfd-shim.so`: loads the devfd shim
   - `EnvironmentFile=-/oci/env`: loads the image's environment
   - `ExecStart=` built from the image's Entrypoint + Cmd
   - `User=` from the image config (or root)
8. Enables the unit via symlink in `multi-user.target.wants/`

When you create a container from this rootfs (`sdme new -r nginx`), systemd
boots inside the nspawn container, reaches `multi-user.target`, and starts
`sdme-oci-app.service`, which chroots into the OCI rootfs and runs the
application.

## Practical examples

### Step 1: Import a base OS

```bash
sudo sdme fs import ubuntu docker.io/ubuntu:24.04 -v
```

This pulls the Ubuntu 24.04 OCI image, extracts it, and installs systemd
(via apt inside a chroot). The result is a rootfs you can use as a base.

### Step 2: Import and run nginx

```bash
sudo sdme fs import nginx docker.io/nginx --base-fs=ubuntu -v
```

sdme auto-detects nginx as an application image (it has an entrypoint and
exposes port 80). The imported rootfs is a copy of `ubuntu` with the nginx
OCI rootfs placed under `/oci/root/` and a systemd unit generated.

Create and start:

```bash
sudo sdme new -r nginx
```

Once inside the container, verify the service is running:

```bash
systemctl status sdme-oci-app.service
curl -s http://localhost
```

You should see the nginx welcome page. The service runs as:

```
/docker-entrypoint.sh nginx -g 'daemon off;'
```

Exit the container with `logout` or Ctrl+D, then from the host:

```bash
# nginx listens on the host's network namespace
curl -s http://localhost
```

### Step 3: Import and run MySQL

MySQL needs `MYSQL_ROOT_PASSWORD` set at first boot. The OCI image doesn't
bake this in; it's a runtime variable. After importing, you'll add it to the
environment file before starting the container.

```bash
sudo sdme fs import mysql docker.io/mysql --base-fs=ubuntu -v
```

The env file at `/oci/env` contains the image's built-in environment (PATH,
GOSU_VERSION, etc.) but not `MYSQL_ROOT_PASSWORD`. Add it to the rootfs
before creating a container:

```bash
echo 'MYSQL_ROOT_PASSWORD=secret' | sudo tee -a /var/lib/sdme/fs/mysql/oci/env
```

Now create and start:

```bash
sudo sdme new -r mysql
```

Once inside, check the service:

```bash
systemctl status sdme-oci-app.service
journalctl -u sdme-oci-app.service -f
```

Wait for the `ready for connections` log line, then test:

```bash
mysql -u root -psecret -e 'SELECT 1'
```

The mysql client binary lives inside the OCI rootfs at `/oci/root/usr/bin/mysql`,
so you'll need to reference it by full path or run it from within the service's
chroot. From the container:

```bash
chroot /oci/root mysql -u root -psecret -e 'SELECT 1'
```

From the host (container shares the host network):

```bash
mysql -u root -psecret -h 127.0.0.1 -e 'SELECT 1'
```

## OCI pods

OCI pods let multiple OCI app containers share a network namespace, similar
to Kubernetes pods. Containers in the same pod can reach each other via
localhost.

```bash
# Create a pod (loopback-only network namespace)
sudo sdme oci-pod new my-pod

# Run nginx in the pod
sudo sdme fs import nginx-unprivileged quay.io/nginx/nginx-unprivileged --base-fs=ubuntu
sudo sdme new --oci-pod=my-pod -r nginx-unprivileged web

# nginx is reachable on the pod's loopback
sudo nsenter --net=/run/sdme/oci-pods/my-pod curl -s http://localhost:8080
```

A second container created with `--oci-pod=my-pod` shares the same
network namespace: it can reach nginx on `localhost:8080` and vice versa.

Pod management:

```bash
sdme oci-pod ls          # list pods
sdme oci-pod rm my-pod   # remove (fails if containers reference it)
sdme oci-pod rm -f my-pod  # force remove
```

`--oci-pod` is mutually exclusive with `--private-network` and requires an
OCI app rootfs (the rootfs must contain `sdme-oci-app.service`).

## Current limitations

- **Port bindings are not wired up.** The `/oci/ports` file records exposed
  ports, but sdme doesn't configure any forwarding. Since containers share
  the host network by default, services bind directly to the host's
  interfaces. With `--private-network`, you'd need manual iptables rules.

- **Volume bindings are not wired up.** The `/oci/volumes` file records
  declared volumes, but sdme doesn't create `BindPaths=` entries. You can
  manually bind-mount host paths into the container using `--bind`:
  ```bash
  sudo sdme create -r mysql --bind /srv/mysql-data:/oci/root/var/lib/mysql
  ```

- **One OCI service per container.** Each imported rootfs generates a single
  `sdme-oci-app.service`. Running multiple OCI services in one container
  isn't supported by the import flow (but you could manually set it up).

- **Environment variables need manual setup.** Runtime-only variables like
  `MYSQL_ROOT_PASSWORD` must be added to `/oci/env` in the rootfs or the
  container's overlayfs upper layer before first boot.

- **No health checks.** OCI HEALTHCHECK directives are ignored.

- **No restart policy mapping.** OCI restart policies don't map to systemd;
  the generated unit uses systemd defaults. Edit the unit if you need
  `Restart=always` or similar.

