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

Or use the install script:

```bash
curl -fsSL https://fiorix.github.io/sdme/install.sh | sudo sh
```

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
sudo sdme exec <name> -- ls /    # run a command inside
sudo sdme logs <name>            # view container journal
sudo sdme stop <name>            # graceful shutdown
sudo sdme rm <name>              # remove container and files
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
sudo sdme fs import ubuntu docker.io/ubuntu:24.04 -v

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

See [oci.md](oci.md) for more examples, including MySQL with runtime
environment variables, pod networking, and known limitations.

## Pods

Pods give multiple containers a shared network namespace so they can
reach each other on localhost. Same concept as Kubernetes pods: one
network namespace, multiple containers.

```bash
sudo sdme pod new my-pod
sudo sdme new --pod=my-pod -r ubuntu db
sudo sdme new --pod=my-pod -r ubuntu app
# db and app can communicate via 127.0.0.1
```

There is also `--oci-pod` for placing only the OCI app process in
the pod's network namespace while keeping the container's systemd on
its own network. See [oci.md](oci.md) for details.

```bash
sudo sdme pod ls                 # list pods
sudo sdme pod rm my-pod          # remove a pod
```

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

See [security.md](security.md) for a full analysis of the isolation
model and comparisons with Docker and Podman.

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

See [tests.md](tests.md) for the full test matrix and CI details.

## Further reading

- [Architecture and design](architecture.md): internals, overlayfs
  layout, container lifecycle, the build engine
- [OCI containers](oci.md): OCI app examples, pods, limitations
- [Security](security.md): isolation model, hardening flags,
  comparison with Docker and Podman
- [OCI-to-nspawn bridging](hacks.md): how sdme handles non-root OCI
  users and /dev/stdout compatibility
- [macOS](macos.md): running sdme on macOS via lima-vm
- [Tests](tests.md): unit tests, integration tests, results
