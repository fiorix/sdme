# Using sdme

sdme is a container manager for Linux built on top of systemd-nspawn and
overlayfs. It produces a single static binary that creates, runs, and
manages containers as regular systemd services. No daemon, no runtime
dependency beyond systemd itself.

From a Linux system with just systemd and sdme, you can create and run
any container and cloud image that exists today. The containers boot a
full systemd init, so you get journalctl, systemctl, cgroups, and
everything else you already know.

## Install

Download a static binary from
[fiorix.github.io/sdme](https://fiorix.github.io/sdme/).

sdme requires root for all operations. It talks to systemd over D-Bus
and manages overlayfs mounts, both of which need elevated privileges.

**On macOS?** See [macos.md](macos.md) for instructions using lima-vm.

## Dependencies

sdme checks for its dependencies at runtime before using them. On most
systemd-based distributions, you only need one extra package.

| Program            | Package             | Used by                        |
|--------------------|---------------------|--------------------------------|
| `systemd` (>= 252) | `systemd`           | All commands (D-Bus)           |
| `systemd-nspawn`   | `systemd-container` | Running containers             |
| `machinectl`       | `systemd-container` | `sdme join`, `sdme exec`       |
| `journalctl`       | `systemd`           | `sdme logs`                    |
| `qemu-nbd`         | `qemu-utils`        | QCOW2 image imports only       |

On Debian and Ubuntu:

```bash
sudo apt install systemd-container
```

For QCOW2 image imports, also install `qemu-utils`.

## Your first container

The simplest thing sdme does is clone your running host system:

```bash
sudo sdme new
```

This creates an overlayfs clone of `/`, boots systemd inside it, and
drops you into a shell. The host rootfs is the read-only lower layer;
all writes go to the container's own upper layer. You can install
packages, change configs, break things. The host is untouched.

By default, host-rootfs containers make `/etc/systemd/system` and
`/var/log` opaque so the host's systemd overrides and log history
don't leak in. Override this with `-o` or change the default:

```bash
sudo sdme config set host_rootfs_opaque_dirs /etc/systemd/system,/var/log
```

### Container lifecycle

Once a container exists, you manage it with familiar patterns:

```bash
sudo sdme ps                     # list containers
sudo sdme join <name>            # enter a running container
sudo sdme join --start <name>    # start if stopped, then enter
sudo sdme exec <name> -- ls /    # run a command inside
sudo sdme logs <name>            # view container journal
sudo sdme stop <name>...         # graceful shutdown
sudo sdme stop --all             # stop all running containers
sudo sdme rm <name>...           # remove container and files
sudo sdme rm --all               # remove all containers
sudo sdme enable <name>...       # auto-start on boot
sudo sdme disable <name>...      # remove auto-start
```

`sdme new` is a shortcut that combines create, start, and join. For
more control, use create and start separately:

```bash
sudo sdme create mybox
sudo sdme start mybox
sudo sdme join mybox
```

## Importing other distros

The host clone is great for quick experiments, but the real power comes
from importing root filesystems from other distributions. Each imported
rootfs becomes a reusable template. You can spin up as many containers
as you want from it; each gets its own overlayfs upper layer.

### From an OCI registry

The easiest way to get a distro rootfs. sdme speaks the OCI Distribution
Spec natively (no Docker or Podman required):

```bash
sudo sdme fs import debian docker.io/debian
sudo sdme fs import ubuntu docker.io/ubuntu:24.04
sudo sdme fs import fedora quay.io/fedora/fedora
```

Then create containers from them:

```bash
sudo sdme new -r debian
sudo sdme new -r ubuntu
sudo sdme new -r fedora
```

### From debootstrap

If you prefer building rootfs locally (on Debian/Ubuntu):

```bash
debootstrap --include=dbus,systemd noble /tmp/ubuntu
sudo sdme fs import ubuntu /tmp/ubuntu
sudo sdme new -r ubuntu
```

### From a cloud image (QCOW2)

sdme can import QCOW2 and raw disk images by mounting them via
`qemu-nbd`, inspecting the partition table, and copying the rootfs:

```bash
sudo sdme fs import cloud-ubuntu some-cloud-image.qcow2
sudo sdme new -r cloud-ubuntu
```

There is no cloud-init support, but the imported rootfs is a fully
bootable systemd container.

### Managing root filesystems

```bash
sudo sdme fs ls                  # list imported rootfs
sudo sdme fs rm ubuntu           # remove a rootfs
```

## OCI applications

Beyond base OS images, sdme can run OCI application images (nginx,
redis, mysql, postgresql, anything on Docker Hub) as systemd services
inside containers. The concept: take a base OS rootfs that has systemd,
place the OCI app rootfs under `/oci/root`, and generate a systemd
service that chroots into it.

You get the OCI packaging model (pull from any registry) with the
systemd operational model (journalctl, systemctl, cgroup limits).

### Quick example: nginx

```bash
# Import a base OS if you haven't already
sudo sdme fs import ubuntu docker.io/ubuntu:24.04 -v --install-packages=yes

# Import nginx as an OCI app on top of ubuntu
sudo sdme fs import nginx docker.io/nginx --base-fs=ubuntu -v

# Create and enter the container
sudo sdme new -r nginx
```

Inside the container:

```bash
systemctl status sdme-oci-app.service
curl -s http://localhost
```

Since containers share the host network by default, you can also reach
nginx from the host directly.

To avoid passing `--base-fs` every time, set a default:

```bash
sudo sdme config set default_base_fs ubuntu
```

### OCI environment variables

Use `--oci-env` on `create` or `new` to set environment variables for
the OCI app service. These are written to the OCI env file
(`/oci/env`) in the container's overlayfs upper layer and read by the
`sdme-oci-app.service` unit via `EnvironmentFile=`.

This is separate from `-e`/`--env`, which sets environment variables
for the container's systemd init (PID 1) via nspawn `--setenv=` flags.

```bash
sudo sdme new -r postgresql --oci-env POSTGRES_PASSWORD=secret
```

### OCI exec and logs

Run a command inside the OCI app root (`/oci/root`) without needing
chroot:

```bash
sudo sdme exec --oci mycontainer redis-cli ping
```

View the OCI app service journal instead of the container unit journal:

```bash
sudo sdme logs --oci mycontainer
sudo sdme logs --oci mycontainer -f    # follow mode
```

See the [OCI integration section](architecture.md#8-oci-integration)
in the architecture doc for internals, including the capsule model,
privilege dropping, and known limitations.

## Pods

Pods give multiple containers a shared network namespace so they can
reach each other on localhost. Same concept as Kubernetes pods: one
network namespace, multiple processes.

### Lifecycle

```bash
sudo sdme pod new my-pod         # create a pod
sudo sdme pod ls                 # list pods
sudo sdme pod rm my-pod          # remove (fails if containers reference it)
sudo sdme pod rm -f my-pod       # force remove
```

A pod creates a network namespace at `/run/sdme/pods/{name}/netns` with
loopback only. State is persisted at `{datadir}/pods/{name}/state`.

### Joining a pod

Containers join a pod at creation time via `--pod` or `--oci-pod`.

**`--pod` (whole container):** The entire nspawn container (init,
services, everything) runs in the pod's network namespace:

```bash
sudo sdme pod new my-pod
sudo sdme create --pod=my-pod -r ubuntu db
sudo sdme create --pod=my-pod -r ubuntu app
sudo sdme start db app
# db and app communicate via 127.0.0.1
```

`--pod` is mutually exclusive with `--private-network`. Incompatible
with `--userns` and `--hardened` because the kernel blocks
`setns(CLONE_NEWNET)` across user namespace boundaries.

**`--oci-pod` (app process only):** Only the
`sdme-oci-app.service` process enters the pod's network namespace.
The container's systemd init and other services remain in their own
namespace:

```bash
sudo sdme pod new web-pod
sudo sdme create --oci-pod=web-pod --hardened -r nginx web
sudo sdme start web
```

Requires `--private-network` (or `--hardened`/`--strict`, which imply
it). Works with `--hardened` because the netns join happens inside the
container's own user namespace.

**Combining both flags:** Both `--pod` and `--oci-pod` can be set on
the same container, pointing to the same or different pods. When set to
different pods, the container-level networking and the application-level
networking operate in separate network namespaces.

```bash
sudo sdme pod new infra-pod
sudo sdme pod new app-pod
sudo sdme create --pod=infra-pod --oci-pod=app-pod -r nginx web
```

### Host access via nsenter

Reach pod services from the host by entering the pod's network
namespace:

```bash
sudo nsenter --net=/run/sdme/pods/my-pod/netns curl -s http://localhost
```

### Multi-service patterns

Multiple containers in a pod communicate over localhost without port
forwarding or bridges:

```bash
sudo sdme pod new monitoring
sudo sdme create --pod=monitoring -r nginx web
sudo sdme create --pod=monitoring -r redis cache
sudo sdme create --pod=monitoring -r prometheus monitor
sudo sdme start web cache monitor
```

All services are reachable from any container in the pod: nginx on :80,
redis on :6379, prometheus on :9090.

**OCI app pod groups.** Group OCI app containers into isolated pod
networks:

```bash
# Web tier
sudo sdme pod new web-tier
sudo sdme create --oci-pod=web-tier --hardened -r nginx frontend
sudo sdme create --oci-pod=web-tier --hardened -r nginx api-gateway

# Data tier (separate pod, separate network)
sudo sdme pod new data-tier
sudo sdme create --oci-pod=data-tier --hardened -r redis cache
sudo sdme create --oci-pod=data-tier --hardened -r mysql db
```

Containers in `web-tier` share localhost. Containers in `data-tier`
share a separate localhost. The two tiers are network-isolated.

## Security

By default, sdme trusts its workloads. For hardening, there are two
convenient flags and a set of fine-grained controls.

**`--hardened`** enables user namespace isolation, private network,
no-new-privileges, and drops several capabilities:

```bash
sudo sdme new -r ubuntu --hardened
```

**`--strict`** implies `--hardened` and adds Docker-equivalent
capability drops, seccomp filters, and AppArmor:

```bash
sudo sdme new -r ubuntu --strict
```

Individual flags are also available:

```bash
sudo sdme create mybox -r ubuntu \
  --userns \
  --private-network \
  --drop-capability CAP_NET_RAW \
  --no-new-privileges \
  --read-only \
  --system-call-filter '~@raw-io'
```

See [architecture.md, Section 14](architecture.md#14-security) for
implementation details and [security.md](security.md) for comparisons
with Docker and Podman.

## Networking

By default, containers share the host's network namespace. Services
bind directly to the host's interfaces, no port mapping needed. This
is equivalent to `docker run --net=host`.

For isolation:

```bash
sudo sdme create mybox --private-network                # loopback only
sudo sdme create mybox --private-network --network-veth  # veth link
sudo sdme create mybox --private-network --port 8080:80  # port forwarding
```

`--hardened` and `--strict` both enable `--private-network`
automatically.

### Network zones

Containers in the same zone can reach each other by name:

```bash
sudo sdme create -r nginx --private-network --network-zone=myzone -p 8080:80 web
sudo sdme create -r ubuntu --private-network --network-zone=myzone client
sudo sdme start web client
sudo sdme exec client -- curl http://web
```

## Resource limits

Containers can have memory and CPU limits applied via cgroups:

```bash
sudo sdme create mybox -r ubuntu --memory 2G --cpus 0.5
sudo sdme set mybox --memory 4G --cpus 2
```

Limits are applied as systemd drop-in files and take effect on the
next container start.

## Bind mounts and environment variables

Custom bind mounts and environment variables are set at creation time:

```bash
sudo sdme create mybox -r ubuntu \
  --bind /srv/data:/data \
  --bind /var/log/app:/var/log/app:ro \
  --env MY_VAR=hello
```

## Building root filesystems

`sdme fs build` takes a Dockerfile-like config and produces a new
rootfs:

```
FROM ubuntu
COPY ./my-app /opt/my-app
RUN apt-get update && apt-get install -y libssl3
RUN systemctl enable my-app.service
```

```bash
sudo sdme fs build my-rootfs build.conf
```

See [architecture.md](architecture.md) for details on how the build
engine works.

## Configuration

sdme stores settings in `~/.config/sdme/sdmerc` (TOML format). Since
sdme runs as root via `sudo`, it checks `$SUDO_USER` and uses that
user's config file if it exists.

```bash
sudo sdme config get                    # show all settings
sudo sdme config set boot_timeout 120   # change a setting
```

| Setting                   | Default                        | Description                     |
|---------------------------|--------------------------------|---------------------------------|
| `interactive`             | `true`                         | Enable interactive prompts      |
| `datadir`                 | `/var/lib/sdme`                | Root data directory             |
| `boot_timeout`            | `60`                           | Seconds to wait for boot        |
| `join_as_sudo_user`       | `true`                         | Join as `$SUDO_USER`           |
| `host_rootfs_opaque_dirs` | `/etc/systemd/system,/var/log` | Default opaque dirs             |
| `default_base_fs`         | (none)                         | Default `--base-fs` for OCI app |

## Building from source

```bash
cargo build --release       # build the binary
cargo test                  # run all tests
make                        # same as cargo build --release
sudo make install           # install to /usr/local (does NOT rebuild)
```

See [test/README.md](../test/README.md) for the test suite and
[test/results.md](../test/results.md) for the latest verified results.

## Further reading

- [Architecture and design](architecture.md): internals, overlayfs
  layout, container lifecycle, the build engine
- [OCI integration](architecture.md#8-oci-integration): capsule model,
  privilege dropping, ports, volumes, limitations
- [Security implementation](architecture.md#14-security): capabilities,
  seccomp, AppArmor, `--hardened`, `--strict`
- [Security comparisons](security.md): isolation model vs Docker and
  Podman
- [OCI-to-nspawn bridging](hacks.md): how sdme handles non-root OCI
  users and /dev/stdout compatibility
- [macOS](macos.md): running sdme on macOS via lima-vm
- [Tests](../test/README.md): test suite, how to run
- [Test results](../test/results.md): latest verified results
