# Running OCI Containers with sdme

## What sdme containers are

sdme creates systemd-booted containers using systemd-nspawn and overlayfs.
Each container runs its own systemd init, journal, and D-Bus, managed as a
regular systemd service on the host. There is no daemon, no container runtime;
just a single binary that talks to systemd over D-Bus.

Containers are overlayfs clones of an imported root filesystem (or your host
system). The base rootfs stays read-only; all writes land on a per-container
upper layer.

## Base OS rootfs: development and infrastructure

Before getting into OCI apps, it helps to understand how sdme handles base
OS root filesystems. Importing a distro rootfs gives you a full Linux
environment with systemd, package managers, and all the tools of that distro.

```bash
sudo sdme fs import ubuntu docker.io/ubuntu:24.04 -v
sudo sdme fs import fedora quay.io/fedora/fedora -v
sudo sdme fs import debian docker.io/debian -v
```

Each import produces a reusable rootfs. Create as many containers as you want
from it; each gets its own overlayfs upper layer.

```bash
sudo sdme new -r ubuntu       # spin up an Ubuntu container
sudo sdme new -r fedora       # spin up a Fedora container
```

### Why this matters

**Build systems.** Need a clean Ubuntu environment to build .deb packages?
Or a Fedora environment for RPMs? Import the rootfs, create a container,
`apt install` or `dnf install` whatever you need, as root, without touching
your host. Destroy the container when you're done; the base rootfs is
untouched.

```bash
sudo sdme new -r ubuntu builder
# inside the container:
apt-get update && apt-get install -y build-essential devscripts
# build your .deb, then exit
```

**Quick experiments.** Test a configuration change, try a new package, run a
service in isolation. Containers boot in seconds and cost almost nothing
(overlayfs means you only store the diff).

## OCI application images

This is where sdme gets interesting. OCI application images (nginx, mysql,
redis, and anything else on Docker Hub, GHCR, or Quay) can run inside sdme
containers as systemd services, with no container runtime dependency.

The idea: import a base OS rootfs that has systemd, then import an OCI app
image on top of it. sdme places the app rootfs under `/oci/root` inside the
base and generates a systemd service (`sdme-oci-app.service`) that chroots
into it and runs the app's entrypoint.

You get the operational model of systemd (journalctl, systemctl, resource
limits, cgroups) with the packaging model of OCI (any registry, any image).

### Two modes of import

When you `sdme fs import` an OCI registry image, sdme classifies it as either
a **base OS image** or an **application image**.

**Base OS images** (ubuntu, debian, fedora, etc.) have no entrypoint, use a
shell as their default command, and expose no ports. sdme extracts the rootfs
and installs systemd if it's missing. The result is a first-class sdme rootfs.

**Application images** (nginx, mysql, redis, etc.) have an entrypoint, a
non-shell command, or exposed ports. sdme places the application rootfs under
`/oci/root` inside a copy of a base rootfs you specify with `--base-fs`.

To avoid passing `--base-fs` every time, set a default:

```bash
sudo sdme config set default_base_fs ubuntu
```

The `--oci-mode` flag lets you override auto-detection:

| Flag                   | Behavior                                      |
|------------------------|-----------------------------------------------|
| `--oci-mode=auto`      | Auto-detect from image config (default)        |
| `--oci-mode=base`      | Force base OS mode                             |
| `--oci-mode=app`       | Force application mode (requires `--base-fs`)  |

### Example: nginx on Ubuntu

Start by importing the base OS, then the app image:

```bash
sudo sdme fs import ubuntu docker.io/ubuntu:24.04 -v
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

You should see the nginx welcome page. Exit the container with `logout` or
Ctrl+D, then from the host:

```bash
# nginx listens on the host's network namespace by default
curl -s http://localhost
```

### Example: MySQL with runtime environment

MySQL needs `MYSQL_ROOT_PASSWORD` set at first boot. The OCI image doesn't
bake this in; it's a runtime variable.

```bash
sudo sdme fs import mysql docker.io/mysql --base-fs=ubuntu -v
```

The env file at `/oci/env` inside the rootfs contains the image's built-in
environment but not `MYSQL_ROOT_PASSWORD`. Add it before creating a container:

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
chroot /oci/root mysql -u root -psecret -e 'SELECT 1'
```

From the host (container shares the host network):

```bash
mysql -u root -psecret -h 127.0.0.1 -e 'SELECT 1'
```

## Pods: composing containers with shared networking

Pods give multiple containers a shared network namespace so they can reach
each other on localhost. The pattern is the same as Kubernetes pods: one
network namespace, multiple processes.

### Two mechanisms

**`--pod` (whole container):** The entire nspawn container (init, services,
everything) runs in the pod's network namespace. Works with any rootfs type.
Mutually exclusive with `--private-network`.

**`--oci-pod` (OCI app process only):** Only the `sdme-oci-app.service`
process enters the pod's network namespace. The container's init and other
services remain in their own namespace. Requires an OCI app rootfs.

Both flags can be combined on the same container. You can even point them at
the same pod (`--pod=X --oci-pod=X`).

### Basic pod example

Two containers sharing localhost:

```bash
sudo sdme pod new my-pod
sudo sdme new --pod=my-pod -r ubuntu db
sudo sdme new --pod=my-pod -r ubuntu app
# db and app can communicate via 127.0.0.1
```

### OCI app pod example

Run nginx in a pod and reach it from the host via the pod's netns:

```bash
sudo sdme fs import ubuntu docker.io/ubuntu:24.04 -v
sudo sdme fs import nginx docker.io/nginx --base-fs=ubuntu -v

sudo sdme pod new web-pod
sudo sdme new --oci-pod=web-pod -r nginx web

# from the host, reach nginx via the pod's netns
sudo nsenter --net=/run/sdme/pods/web-pod/netns curl -s http://localhost
```

### Scaling with pod groups

The composability of `--pod` and `--oci-pod` enables a layered networking
model for larger deployments:

**Groups of containers joined by a pod.** An administrator creates a pod
and assigns multiple containers to it. All containers in the group share
localhost, so services can discover each other by port without any service
mesh or DNS configuration.

```bash
# A database group: primary + replica sharing localhost
sudo sdme pod new db-group
sudo sdme new --pod=db-group -r ubuntu pg-primary
sudo sdme new --pod=db-group -r ubuntu pg-replica
```

**Multiple pod groups running different workloads.** Each pod group is
isolated from the others. You can run completely different sets of OCI apps
in separate pods, each with their own network namespace.

```bash
# Import OCI app images (assumes ubuntu base already imported)
sudo sdme fs import nginx docker.io/nginx --base-fs=ubuntu -v
sudo sdme fs import redis docker.io/redis --base-fs=ubuntu -v
sudo sdme fs import mysql docker.io/mysql --base-fs=ubuntu -v

# Web tier
sudo sdme pod new web-tier
sudo sdme new --oci-pod=web-tier -r nginx frontend
sudo sdme new --oci-pod=web-tier -r nginx api-gateway

# Data tier (separate pod, separate network)
sudo sdme pod new data-tier
sudo sdme new --oci-pod=data-tier -r redis cache
sudo sdme new --oci-pod=data-tier -r mysql db
```

Containers in `web-tier` can reach each other on localhost (nginx on :80,
api-gateway on :8080). Containers in `data-tier` can reach each other on
localhost (redis on :6379, mysql on :3306). The two tiers are network-isolated.

**Combining `--pod` and `--oci-pod`.** When both flags are set on the same
container, the nspawn container itself runs in one pod's netns while the OCI
app process runs in another. This lets you build topologies where the
container-level networking (systemd services, debugging tools) and the
application-level networking (the actual workload) operate in different
network namespaces.

A simpler use case: set both to the same pod. This puts both the container
and the OCI app in the same network namespace, which is equivalent to
`--pod` alone but also wires up the inner `NetworkNamespacePath=` drop-in.

```bash
# Both container and app share the same pod netns
sudo sdme pod new shared-pod
sudo sdme new --pod=shared-pod --oci-pod=shared-pod -r nginx web
```

### Pod management

```bash
sdme pod new my-pod          # create a pod
sdme pod ls                  # list pods
sdme pod rm my-pod           # remove (fails if containers reference it)
sdme pod rm -f my-pod        # force remove
```

## Security

sdme provides opt-in security hardening for containers. The two main flags:

**`--hardened`** enables user namespace isolation, private network,
no-new-privileges, and drops several capabilities:

```bash
sudo sdme new -r nginx --hardened
```

**`--strict`** implies `--hardened` and adds Docker-equivalent capability
drops, seccomp filters, and the `sdme-default` AppArmor profile:

```bash
sudo sdme new -r nginx --strict
```

Individual flags (`--drop-capability`, `--capability`, `--no-new-privileges`,
`--read-only`, `--system-call-filter`, `--apparmor-profile`) are also
available for fine-grained control.

User namespace isolation (`--userns`) works with OCI app containers. It
maps container root to a high unprivileged UID on the host:

```bash
sudo sdme new -r nginx --userns
```

See [security.md](security.md) for a full analysis of sdme's isolation
model and comparisons with Docker and Podman.

## Limitations

- **Port bindings are not wired up.** The `/oci/ports` file records exposed
  ports, but sdme doesn't configure any forwarding. Since containers share
  the host network by default, services bind directly to the host's
  interfaces. With `--private-network`, you'd need manual iptables rules.

- **Volume bindings are not wired up.** The `/oci/volumes` file records
  declared volumes, but sdme doesn't create bind mounts for them. You can
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

## Further reading

- [Architecture and design](architecture.md): internals of how sdme, OCI
  capsules, and pods work under the hood
- [OCI-to-nspawn bridging](hacks.md): how non-root OCI users and
  /dev/stdout compatibility are handled
- [Security](security.md): isolation model, hardening flags, and
  comparison with Docker and Podman
