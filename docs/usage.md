# Using sdme

## 1. Introduction

sdme is a container manager for Linux. It does not run containers itself.
Instead, it creates overlayfs directories, generates a systemd template unit
(`sdme@.service`), and tells systemd to start it. systemd runs
`systemd-nspawn`, which boots a full init inside the container. sdme talks
to systemd over D-Bus for start, stop, and status operations.

The result is that every sdme container is a regular systemd service. You
manage it with `systemctl`, read its logs with `journalctl`, and apply
resource limits through cgroups. If you already know systemd, you already
know most of how sdme works at runtime.

sdme is a single static binary. There is no daemon. All operations require
root because they involve overlayfs mounts and D-Bus calls to systemd. All
container data lives under `/var/lib/sdme`.

For a deeper look at how the pieces fit together (the overlayfs layering,
the template unit, the D-Bus protocol, the boot-wait logic), see the
[architecture document](architecture.md).

## 2. Installing sdme

### The binary

Download a static binary from
[fiorix.github.io/sdme](https://fiorix.github.io/sdme/). Both x86_64 and
aarch64 are available. Drop it somewhere in your PATH and you are done.

### System requirements

sdme requires root and systemd version 252 or later. It checks the systemd
version at startup and will tell you if yours is too old.

The one package you need is `systemd-container`, which provides
`systemd-nspawn` (the actual container runtime), `machinectl` (used by
`sdme join` and `sdme exec`), and related tooling.

Install it for your distribution:

```bash
# Debian / Ubuntu
sudo apt install systemd-container

# Fedora / CentOS / AlmaLinux
sudo dnf install systemd-container

# Arch Linux (nspawn is included in the base systemd package)
sudo pacman -S systemd

```

If you plan to import QCOW2 cloud images, also install `qemu-utils` (or
your distro's equivalent) for `qemu-nbd`.

**On macOS?** See [macos.md](macos.md) for instructions using lima-vm.

### Building from source

If you prefer to build sdme yourself:

```bash
cargo build --release       # build the binary
cargo test                  # run all tests
make                        # build probe binary + sdme (with embedded probe)
sudo make install           # install to /usr/local (does NOT rebuild)
```

## 3. Cloning your machine

This is the simplest and most powerful thing sdme does. With one command,
you get a full clone of your running system that you can break without
consequences:

```bash
sudo sdme new
```

What happens behind the scenes: sdme creates an overlayfs mount with your
host rootfs (`/`) as the read-only lower layer and a fresh directory as
the writable upper layer. It then tells systemd to start the container,
which boots `systemd-nspawn`, which boots a full systemd init inside. Once
systemd reaches the running state, sdme drops you into a shell.

Every file on your system is visible inside the container, but all writes
go to the upper layer. The host is untouched. You can `apt install`
packages, edit `/etc` files, build software, test configuration changes,
even break systemd units. When you are done, remove the container and
everything is gone.

### What you can do inside

The container is a full Linux system. It has its own systemd, its own
journal, its own process tree. You can:

- Install and remove packages (`apt install`, `dnf install`, etc.)
- Start and stop services (`systemctl start nginx`)
- Edit configuration files and test the results
- Build and run software
- Break things without fear

The host filesystem is always safe underneath the overlayfs lower layer.

### Container lifecycle

Once you have created a container (either through `sdme new` or `sdme
create`), you manage it with these commands:

```bash
sudo sdme ps                     # list containers with status and health
sudo sdme join mybox             # enter a running container's shell
sudo sdme join --start mybox     # start it first if stopped, then enter
sudo sdme exec mybox -- ls /     # run a one-off command inside
sudo sdme logs mybox             # view the container's journal
sudo sdme stop mybox             # graceful shutdown (SIGRTMIN+4, 90s)
sudo sdme stop --term mybox     # terminate (SIGTERM, 30s)
sudo sdme stop --kill mybox     # force-kill all processes (SIGKILL, 15s)
sudo sdme stop --all             # stop all running containers
sudo sdme start mybox            # start a stopped container
sudo sdme start --all            # start all stopped containers
sudo sdme rm mybox               # remove the container and its files
sudo sdme rm --all               # remove all containers
sudo sdme enable mybox           # auto-start on host boot
sudo sdme disable mybox          # remove auto-start
```

The OS column in `sdme ps` shows the distribution name from the
container's os-release file. For running containers it reads the
overlayfs merged view; for stopped containers it falls back to the
upper layer, then the imported rootfs, then the host root. If no
os-release file is found anywhere, it shows "unknown".

`sdme new` is a shortcut that combines create, start, and join. When you
want more control over the process, use them separately:

```bash
sudo sdme create mybox
sudo sdme start mybox
sudo sdme join mybox
```

The `-t`/`--timeout` flag overrides the configured `boot_timeout` (default
60 seconds) for a single invocation. It applies to `new`, `start`, and
`join --start`:

```bash
sudo sdme new -t 120 -r ubuntu          # allow 120s for boot
sudo sdme start -t 30 mybox             # tighter timeout for a fast image
```

To create a container and enable auto-start on boot in one step:

```bash
sudo sdme create mybox --enable
```

### Bind mounts

To share directories between the host and the container, use `-b` (or
`--bind`). The syntax is `host-path:container-path`, with an optional
`:ro` suffix for read-only mounts:

```bash
sudo sdme create mybox -b /srv/data:/data -b /var/log/app:/var/log/app:ro
```

Paths must be absolute and cannot contain `..`. The bind mounts are stored
in the container's state file and applied every time the container starts.

### Environment variables

Set environment variables for the container's init process with `-e` (or
`--env`):

```bash
sudo sdme create mybox -e MY_VAR=hello -e DEBUG=1
```

These are passed to `systemd-nspawn` as `--setenv=` flags and are visible
to all processes inside the container.

### Opaque directories

When you clone the host, certain directories should not inherit content
from the lower layer. For example, you usually do not want the host's
systemd unit overrides or old log files leaking into the container. sdme
handles this with "opaque directories": it sets the
`trusted.overlay.opaque` xattr on them, telling overlayfs to hide the
lower-layer contents.

The defaults are `/etc/systemd/system` and `/var/log`. You can override
them per container with `-o`:

```bash
sudo sdme create mybox -o /etc/systemd/system,/var/log,/tmp
```

Or change the default for all host-rootfs containers:

```bash
sudo sdme config set host_rootfs_opaque_dirs /etc/systemd/system,/var/log
```

### A quick test: running nginx in a host clone

To see the host clone in action, try this:

```bash
sudo sdme new webtest
```

Inside the container:

```bash
apt install -y nginx
systemctl start nginx
curl -s http://localhost
```

Since containers share the host's network by default, you can also reach
nginx from the host:

```bash
curl -s http://localhost
```

When you are done, exit the container and clean up:

```bash
sudo sdme rm webtest
```

The host never had nginx installed.

## 4. Importing root filesystems

The host clone is useful for quick experiments, but the real power comes
from importing root filesystems from other distributions. Each imported
rootfs becomes a reusable template: you can create as many containers as
you want from it, and each one gets its own overlayfs upper layer.

### 4.1 Choosing an import source

sdme auto-detects the source type. Here are the six options and when to
use each:

| Source       | Example                    |
|--------------|----------------------------|
| OCI registry | `docker.io/ubuntu:24.04`   |
| OCI tarball  | `image.oci.tar.xz`        |
| Directory    | `/tmp/ubuntu`              |
| Tarball      | `rootfs.tar.gz`            |
| URL          | `https://...rootfs.tar.xz` |
| QCOW2        | `cloud-image.qcow2`       |

- **OCI registry**: any distro on Docker Hub, Quay, or GHCR.
- **OCI tarball**: local OCI image exported as a tarball
  (detected by `oci-layout` file).
- **Directory**: debootstrap output, custom builds.
- **Tarball**: pre-built archives (auto-detects gz/bz2/xz/zstd).
- **URL**: remote tarballs, cloud image URLs.
- **QCOW2**: cloud disk images (requires `qemu-nbd`).

The OCI registry path is what most people want. sdme speaks the OCI
Distribution Spec natively, so no Docker or Podman is required:

```bash
sudo sdme fs import ubuntu docker.io/ubuntu:24.04
sudo sdme fs import fedora quay.io/fedora/fedora:41
```

If systemd is missing from the imported image, sdme will prompt to install
it (along with packages needed for `machinectl shell`, like `util-linux`
and `pam` on RHEL-family distros).

For a directory-based import (useful with debootstrap on Debian/Ubuntu):

```bash
debootstrap --include=dbus,systemd noble /tmp/ubuntu
sudo sdme fs import ubuntu /tmp/ubuntu
```

For QCOW2 cloud images:

```bash
sudo sdme fs import cloud-ubuntu some-cloud-image.qcow2
```

There is no cloud-init support, but the imported rootfs is a fully bootable
systemd container.

Once imported, create containers from any rootfs with `-r`:

```bash
sudo sdme new -r ubuntu
sudo sdme new -r fedora
```

### 4.2 The distro support matrix

After importing a rootfs, sdme detects the distribution, checks for
systemd, and if systemd is missing, installs it via chroot. The
`--install-packages` flag controls this behavior. Supported distro
families: Debian (apt-get), Fedora (dnf), SUSE (zypper), Arch (pacman).
NixOS rootfs must be built externally (see Section 4.3).

The following matrix is verified in the release process:

```
Base OS       Source                                       Tested
-----------   ------------------------------------------   ------
debian        docker.io/debian:stable                      Yes
ubuntu        docker.io/ubuntu:24.04                       Yes
fedora        quay.io/fedora/fedora:41                     Yes
centos        quay.io/centos/centos:stream10               Yes
almalinux     quay.io/almalinuxorg/almalinux:9             Yes
opensuse      registry.opensuse.org/opensuse/tumbleweed    Yes
archlinux     docker.io/archlinux                          Yes
nixos         external build (see Section 4.3)             Yes
```

The key point: once imported, you can spin up any number of containers from
the same rootfs. Each gets its own overlayfs layer, so they are completely
independent.

### 4.3 NixOS root filesystems

NixOS rootfs must be built externally and imported as a directory.
sdme recognizes pre-built NixOS rootfs by `ID=nixos` in os-release.

The repository includes a helper script and nix expression for building
a NixOS rootfs:

```bash
sudo test/scripts/build-nixos-rootfs.sh mynixos
```

This pulls `docker.io/nixos/nix`, runs `nix-build` inside a chroot to
produce a NixOS system closure, rebuilds a clean rootfs from the
closure, and imports it via `sdme fs import`. No local nix installation
is required.

The default nix expression ([`test/nix/sdme-nixos.nix`](../test/nix/sdme-nixos.nix))
produces a minimal bootable NixOS with:

- systemd, dbus, systemd-networkd
- Common tools: bash, coreutils, util-linux, iproute2, less, procps,
  findutils, grep, sed, curl
- Root autologin on the console
- Empty root password (for `machinectl shell`)
- `systemd-resolved` disabled (the host handles DNS)
- `pam_lastlog2` disabled for `login` and `container-shell` PAM
  services (works around a linkage issue in nspawn containers)
- `nix.nixPath` configured so `nix-env -f '<nixpkgs>' -iA foo` works
  inside the container

To use a custom nix expression or nixpkgs channel:

```bash
sudo test/scripts/build-nixos-rootfs.sh mynixos \
    --nix-file /path/to/my-container.nix \
    --channel nixos-24.11
```

**Network limitation.** `networkd` is enabled but `resolved` is
disabled by default. `--network-veth` and `--network-bridge` get DHCP
via networkd and work out of the box. `--network-zone` also needs
resolved for LLMNR/mDNS inter-container name resolution; add
`services.resolved.enable = true` to your nix expression to enable it.

### 4.4 Managing root filesystems

Listing and removing imported rootfs is straightforward:

```bash
sudo sdme fs ls                  # list imported rootfs with size and distro
sudo sdme fs rm ubuntu           # remove an imported rootfs
```

sdme caches OCI blobs (image layers) to speed up repeated imports. You
can inspect and manage the cache with `sdme fs cache`:

```bash
sudo sdme fs cache info            # show cache location, size, and blob count
sudo sdme fs cache ls              # list cached blobs
sudo sdme fs cache clean           # clean up unreferenced blobs
sudo sdme fs cache clean --all     # remove all cached blobs
```

The cache directory and maximum size are configurable via `oci_cache_dir`
and `oci_cache_max_size` (default: 10G).

### 4.5 Exporting root filesystems

`sdme fs export` exports an imported rootfs or a container's merged
overlayfs view to a directory, tarball, or raw disk image. The output
format is auto-detected from the file extension:

```bash
# Export an imported rootfs
sudo sdme fs export ubuntu /tmp/ubuntu-rootfs             # directory copy
sudo sdme fs export ubuntu /tmp/ubuntu.tar.gz             # gzip tarball
sudo sdme fs export ubuntu /tmp/ubuntu.raw                # ext4 disk image
sudo sdme fs export ubuntu /tmp/ubuntu.raw --size 2G      # explicit size
sudo sdme fs export ubuntu /tmp/ubuntu.raw --filesystem btrfs  # btrfs disk image
sudo sdme fs export ubuntu /tmp/ubuntu.raw --timezone America/New_York  # set timezone

# Export a container's merged view
sudo sdme fs export mybox /tmp/mybox.tar.xz --container
```

Supported tarball formats: `.tar`, `.tar.gz`/`.tgz`, `.tar.bz2`/`.tbz2`,
`.tar.xz`/`.txz`, `.tar.zst`/`.tzst`. Use `--fmt` to override auto-detection
(e.g. `sdme fs export ubuntu /tmp/output --fmt tar.gz`).

Raw disk images are bare ext4 (default) or btrfs filesystems (no partition
table), selectable with `--filesystem`. The default can be changed with
`sdme config set default_export_fs btrfs`. The size
is auto-calculated as `max(256M, content * 1.5 + free_space)` unless
overridden with `--size`. The `--free-space` flag controls how much extra
space is guaranteed in the image (default from config
`default_export_free_space`, initially `256M`). When `--size` is set,
`--free-space` is ignored. Change the default with
`sdme config set default_export_free_space 512M`.
Container exports: running containers are exported from the live
filesystem (with a consistency warning); stopped containers have overlayfs
temporarily mounted.

Use `--timezone` to set the timezone in the exported rootfs (e.g.
`--timezone America/New_York`). This symlinks `/etc/localtime` to the
zoneinfo file and writes `/etc/timezone`, validated against the rootfs
before export begins. Works with all output formats. Not needed for
containers since `systemd-nspawn` copies the host timezone at boot.

For more on how the fs subsystem works internally, see
[architecture.md, Section 6](architecture.md#6-the-fs-subsystem-managing-root-filesystems).

### 4.6 Exporting for VM boot

The `--vm` flag on `sdme fs export` prepares a raw disk image that boots
as a virtual machine. It configures the exported rootfs with a serial
console, fstab entry for the root filesystem, systemd-networkd with DHCP,
DNS resolvers, a hostname, and optionally a root password and SSH public
key. If the rootfs is missing udev (common with container images),
sdme will prompt to install it.

The result is a GPT-partitioned raw disk image with a Linux root
partition (no bootloader), and optionally a swap partition via
`--swap <size>`. You supply your own kernel at boot time via the
hypervisor's `-kernel` flag. This works with cloud-hypervisor and
QEMU.

**Finding a kernel.** Use the host's installed kernel:

```bash
ls /usr/lib/modules/*/vmlinuz       # Arch, Fedora
ls /boot/vmlinuz-*                  # Debian, Ubuntu
```

**Example: Debian**

```bash
# Import (if not already done)
sudo sdme fs import debian docker.io/debian:stable

# Export as a VM image
sudo sdme fs export debian /tmp/debian-vm.raw \
    --vm --hostname debian --root-password test
```

Debian container images don't include udev, so sdme will prompt to install
it during export. Fedora and Arch container images already have
udev.

**Example: Fedora**

```bash
sudo sdme fs import fedora quay.io/fedora/fedora:41

sudo sdme fs export fedora /tmp/fedora-vm.raw \
    --vm --hostname fedora --root-password test
```

**Example: Arch Linux**

```bash
sudo sdme fs import archlinux docker.io/archlinux

sudo sdme fs export archlinux /tmp/archlinux-vm.raw \
    --vm --hostname archlinux --root-password test
```

Arch Linux runs `systemd-firstboot` on first boot, prompting for timezone
and locale. Press Enter at each prompt to skip, then log in normally.

**Booting with cloud-hypervisor:**

```bash
cloud-hypervisor \
    --kernel /path/to/vmlinuz \
    --disk path=/tmp/debian-vm.raw \
    --cmdline "root=/dev/vda1 rw console=ttyS0" \
    --serial tty \
    --console off \
    --cpus boot=2 \
    --memory size=2G
```

**Booting with QEMU:**

```bash
qemu-system-x86_64 \
    -kernel /path/to/vmlinuz \
    -drive file=/tmp/debian-vm.raw,format=raw,if=virtio \
    -append "root=/dev/vda1 rw console=ttyS0" \
    -nographic \
    -m 2G \
    -smp 2 \
    -enable-kvm
```

The `if=virtio` option is required for QEMU so the disk appears as
`/dev/vda`. cloud-hypervisor uses virtio by default. The VM image
contains a GPT partition table, so the root filesystem is on `/dev/vda1`.
Both commands attach the serial console to the terminal. Exit
cloud-hypervisor with Ctrl-A x; exit QEMU with Ctrl-A x.

**Customization options:**

| Flag | Effect |
|------|--------|
| `--dns` | Copy host's `/etc/resolv.conf` into the image |
| `--dns 1.1.1.1 --dns 9.9.9.9` | Write explicit nameservers (omit `--dns` entirely to leave resolv.conf untouched) |
| `--net-ifaces 2` | Configure DHCP on two NICs; `0` to skip network setup |
| `--ssh-key ~/.ssh/id_ed25519.pub` | Add SSH public key to root's authorized_keys |
| `--filesystem btrfs` | Use btrfs instead of ext4 |
| `--size 4G` | Override auto-calculated image size |
| `--free-space 256M` | Extra free space in the image (default: 256M) |
| `--hostname myvm` | Set the VM hostname (default: rootfs name) |
| `--root-password ""` | Passwordless root (empty string) |

**Known limitations:**

- No bootloader. The image has a GPT partition table but must be booted
  with `-kernel` (direct kernel boot).
- `systemd-logind` fails inside the VM (no seat or input devices). This
  is harmless and does not affect serial console login.

## 5. Security, networking, and resource limits

This guide focuses on the concepts and workflows above. For the remaining
topics, the existing documentation covers them well:

**Security.** sdme provides three tiers of hardening. `--userns` enables
user namespace isolation standalone. `--hardened` enables user namespace
isolation, private network, no-new-privileges, and drops several
capabilities. `--strict` adds Docker-equivalent capability drops, seccomp
filters, and AppArmor. Individual flags (`--capability`,
`--drop-capability`, `--no-new-privileges`, `--read-only`,
`--system-call-filter`, `--apparmor-profile`) are also available for
fine-grained control.

```bash
sudo sdme new -r ubuntu --hardened
sudo sdme new -r ubuntu --strict
```

See [security.md](security.md) for the full comparison with Docker and
Podman, and [architecture.md, Section 14](architecture.md#14-security)
for implementation details.

**Networking.** Containers share the host network by default. For
isolation, use `--private-network`, optionally combined with
`--network-veth`, `--network-bridge`, `--network-zone`, or `--port`:

```bash
sudo sdme create mybox --private-network --network-veth --port 8080:80
```

When `--network-veth`, `--network-zone`, or `--network-bridge` is
used, sdme auto-enables `systemd-networkd` in the container so the
container-side interface (`host0`) gets an IP via DHCP.

Network zones let containers in the same zone reach each other.
When using `--network-zone`, sdme automatically leaves
`systemd-resolved` unmasked and configures it with LLMNR/mDNS so
containers can discover each other by hostname within the zone.
For other private-network modes, resolved is masked by default
because the container cannot bind 127.0.0.53 (already owned by the
host):

```bash
sudo sdme create -r nginx --network-zone=myzone -p 8080:80 web
sudo sdme create -r ubuntu --network-zone=myzone client
sudo sdme start web client
```

See [architecture.md, Section 9](architecture.md#9-networking) for details.

**Service masking.** By default, sdme masks `systemd-resolved.service`
in the overlayfs upper layer at container create time. This is
configurable:

```bash
# Change the default for all new containers
sudo sdme config set default_create_masked_services "systemd-resolved.service"

# Mask nothing by default
sudo sdme config set default_create_masked_services ""

# Override per container (comma-separated)
sudo sdme create mybox --masked-services=systemd-resolved.service,systemd-networkd.service

# Mask nothing for this container
sudo sdme create mybox --masked-services=
```

When `--network-zone` is set and `--masked-services` is not explicitly
passed, `systemd-resolved.service` is automatically removed from the
default mask list. NixOS rootfs always skip masking because NixOS
activation replaces `/etc/systemd/system` with an immutable symlink.

Host-rootfs containers additionally mask host-specific `.mount`,
`.swap`, and `.automount` units to prevent them from leaking through
overlayfs. This is separate from `--masked-services` and always applies.

**Resource limits.** Memory and CPU limits are applied via cgroups:

```bash
sudo sdme create mybox -r ubuntu --memory 2G --cpus 0.5
sudo sdme set mybox --memory 4G --cpus 2
```

**Building rootfs.** `sdme fs build` takes a Dockerfile-like config to
produce custom rootfs images. Use `-t` to override the boot timeout for
build steps that start the container (e.g. `sdme fs build -t 180 ...`).
See [architecture.md, Section 7](architecture.md#7-fs-build-building-root-filesystems).

**Configuration.** Settings are stored in `/etc/sdme.conf` (TOML).

```bash
sudo sdme config get                    # show all settings
sudo sdme config set boot_timeout 120   # change a setting
```

The `boot_timeout` config key (default 60 seconds) controls how long sdme
waits for a container to reach the running state. The `-t`/`--timeout`
flag on `new`, `start`, `join --start`, `fs build`, and `kube apply`
overrides this value for a single invocation.

## 6. OCI applications

### 6.1 Base OS vs application images

This is the key conceptual distinction for OCI images in sdme. A "base OS"
image (ubuntu, fedora, debian) contains systemd and can boot as a
standalone container. An "application" image (nginx, redis, postgresql) has
no init system; it expects something else to run it.

sdme auto-detects which mode to use based on the OCI image config: if the
image has no entrypoint, a shell as its default command, and no exposed
ports, it is treated as a base OS rootfs. Everything else is treated as
an application that needs a base OS to run inside. You can override this
with `--oci-mode` (values: `auto`, `base`, `app`), but auto-detection
works correctly in practice.

### 6.2 How OCI apps work

When you import an application image with `--base-fs`, sdme uses a
"capsule" model. It takes your base OS rootfs (which has systemd), copies
it, and places the OCI application's files under
`/oci/apps/{name}/root` inside it. Then it generates a systemd service
unit (`sdme-oci-{name}.service`) that starts the application inside a
chroot (`RootDirectory=/oci/apps/{name}/root`).

The app name is derived from the image. For example,
`docker.io/redis` becomes `redis`, and
`docker.io/nginxinc/nginx-unprivileged` becomes `nginx-unprivileged`.

Here is the full workflow, from importing a base OS to running an OCI app:

```bash
# Step 1: import a base OS (only needed once)
sudo sdme fs import ubuntu docker.io/ubuntu:24.04

# Step 2: import an OCI app on top of that base OS
sudo sdme fs import redis docker.io/redis --base-fs=ubuntu

# Step 3: create and enter the container
sudo sdme new -r redis
```

Inside the container, the app is a regular systemd service:

```bash
systemctl status sdme-oci-redis.service
```

From outside, you can view its logs and run commands in the app's root:

```bash
sudo sdme logs --oci mycontainer
sudo sdme logs --oci mycontainer -f     # follow mode
sudo sdme join --oci mycontainer        # shell inside the app's namespaces
sudo sdme exec --oci mycontainer -- redis-cli ping
```

The `--oci` flag on `logs` shows the OCI app service journal instead of
the container's main journal. On `join` and `exec`, it enters the app's
PID, IPC, and mount namespaces via `nsenter`, so commands like `ps` show
only the app's processes, not the entire container init tree. `join --oci`
defaults to `/bin/sh` when no command is given.

### 6.3 The convenience of this model

Why is this useful? You get the OCI distribution model (pull from any
registry, use any image on Docker Hub, GHCR, or Quay) combined with the
systemd operational model (journalctl, systemctl, cgroup limits, security
hardening). The base OS is yours: you can extend it with monitoring
agents, custom services, log shippers, or anything else via `sdme fs
build`. These extensions run alongside the OCI workload inside the same
container.

Docker and Podman have no equivalent to this. You either run one process
per container or build increasingly complex entrypoint scripts. With sdme,
you have a full systemd environment where the OCI app is just one of
potentially many services.

**Setting a default base OS.** To avoid passing `--base-fs` on every OCI
app import:

```bash
sudo sdme config set default_base_fs ubuntu
```

Now `sudo sdme fs import redis docker.io/redis` will automatically use
ubuntu as the base.

**OCI environment variables.** Use `--oci-env` on `create` or `new` to
set environment variables for the OCI app service:

```bash
sudo sdme new -r postgresql --oci-env POSTGRES_PASSWORD=secret
```

These are written to the app's env file (`/oci/apps/{name}/env`) and
loaded by the systemd service via `EnvironmentFile=`. This is separate
from `-e`/`--env`, which sets environment variables for the container's
systemd init (PID 1) via nspawn `--setenv=` flags. The distinction
matters: `--oci-env` reaches the app, `-e` reaches init.

**Redis 8 locale requirement.** Redis 8+ treats locale configuration
failure as fatal. The OCI image's minimal chroot may lack the locale
expected by the host container. Set `LANG=C.UTF-8` via `--oci-env`
(or `env` in kube YAML) to provide a universally available locale:

```bash
sudo sdme new -r redis --oci-env LANG=C.UTF-8
```

In a Kubernetes Pod YAML:

```yaml
  - name: redis
    image: docker.io/redis:latest
    env:
    - name: LANG
      value: C.UTF-8
```

**OCI ports and volumes.** OCI images declare exposed ports and volumes
in their metadata. sdme reads these at import time and auto-wires them
when you create a container. Ports become `--port` rules (when the
container has a private network), and volumes become bind mounts to
host-side directories under `/var/lib/sdme/volumes/{container}/`. You
can suppress this behavior with `--no-oci-ports` and `--no-oci-volumes`.
Your own `--port` and `--bind` flags always take priority.

### 6.4 Security

OCI apps get additional isolation automatically, beyond what the nspawn
container provides. The `isolate` binary (a static ELF under 2 KiB,
written into the OCI root at import time) creates PID and IPC namespaces,
remounts `/proc` with restricted options, and drops `CAP_SYS_ADMIN` from
the bounding set before exec'ing the workload. The systemd service unit
also applies hardening directives: `NoNewPrivileges=yes`,
`ProtectKernelModules=yes`, `ProtectProc=invisible`, and others.

The net effect is that the OCI application process sees its own PID
namespace, cannot access the container's IPC objects, cannot see other
processes, and has an effective capability set comparable to Docker's
defaults.

For the full details, see [security.md, Part 2](security.md#part-2-oci-workload-security)
and [architecture.md, Section 16](architecture.md#16-oci-integration).

### 6.5 Tested OCI app matrix

The following applications are verified across all supported base OS
distros in the release process:

```
App                  Base OS distros tested
-------------------  ----------------------------------
nginx-unprivileged   all 7 (debian thru archlinux)
redis                all 7
postgresql           all 7
```

OCI port forwarding and volume mounting are additionally tested on ubuntu
and fedora. See [test/results.md](../test/results.md) for the complete
test matrix.

## 7. Pods

A pod is a shared network namespace that multiple containers can join.
This is the same concept as Kubernetes pods: one network, multiple
processes. Containers in the same pod can reach each other on localhost
without any port forwarding or bridge configuration.

### Creating and managing pods

```bash
sudo sdme pod new my-pod         # create a pod
sudo sdme pod ls                 # list pods
sudo sdme pod rm my-pod          # remove (fails if containers reference it)
sudo sdme pod rm -f my-pod       # force remove
```

A pod creates a network namespace at `/run/sdme/pods/{name}/netns` with
only a loopback interface. The namespace persists until the pod is removed.

### 7.1 The `--pod` flag: whole container in the pod's netns

With `--pod`, the entire nspawn container (init, services, everything)
runs in the pod's network namespace:

```bash
sudo sdme pod new my-pod
sudo sdme create --pod=my-pod -r ubuntu db
sudo sdme create --pod=my-pod -r ubuntu app
sudo sdme start db app
```

Both containers share localhost. A service listening on port 5432 in `db`
is reachable from `app` at `127.0.0.1:5432`, and vice versa.

To reach pod services from the host, enter the pod's network namespace:

```bash
sudo nsenter --net=/run/sdme/pods/my-pod/netns curl -s http://localhost
```

**Limitations.** `--pod` is incompatible with `--userns` and `--hardened`.
The reason is specific: the kernel blocks `setns(CLONE_NEWNET)` when the
calling process is in a different user namespace than the one that owns
the target network namespace. Since `--userns` (and `--hardened`, which
implies it) puts the container in a child user namespace, while the pod's
netns was created in the init user namespace, the kernel refuses the
operation. This is not an sdme limitation; it is a kernel security
boundary.

If you need both pod networking and security hardening, use `--oci-pod`
instead (see below).

### 7.2 The `--oci-pod` flag: OCI app only in the pod's netns

With `--oci-pod`, only the `sdme-oci-{name}.service` process enters the
pod's network namespace. The container's systemd init and other services
stay in their own namespace. This works with `--hardened` because the
netns join happens inside the container via a systemd drop-in
(`NetworkNamespacePath=`), not at the nspawn level.

The requirement is that the container must have `--private-network`
(or `--hardened`/`--strict`, which imply it). Without a private network,
systemd-nspawn strips `CAP_NET_ADMIN`, and the inner systemd cannot call
`setns(CLONE_NEWNET)` for the `NetworkNamespacePath=` directive.

```bash
sudo sdme pod new web-pod
sudo sdme create --oci-pod=web-pod --hardened -r nginx web
sudo sdme start web
```

**When to use which.** Use `--pod` when you want the simplest shared
networking and do not need `--userns` or `--hardened`. Use `--oci-pod`
when you need hardened containers that share an application-level network.

Both flags can be set on the same container, pointing to the same or
different pods. When set to different pods, container-level networking
and application-level networking operate in separate network namespaces.

### 7.3 Multi-service patterns

Pods are most useful when you have multiple services that need to
communicate over localhost:

```bash
sudo sdme pod new monitoring
sudo sdme create --pod=monitoring -r nginx web
sudo sdme create --pod=monitoring -r redis cache
sudo sdme start web cache
```

All services are reachable from any container in the pod: nginx on :80,
redis on :6379.

For OCI apps with security hardening:

```bash
sudo sdme pod new web-tier
sudo sdme create --oci-pod=web-tier --hardened -r nginx frontend
sudo sdme create --oci-pod=web-tier --hardened -r redis cache
sudo sdme start frontend cache
```

### 7.4 What's tested

Pod tests verify loopback connectivity between `--pod` containers, correct
rejection of incompatible flag combinations (`--pod` with `--hardened`,
`--pod` with `--userns`, `--oci-pod` without `--private-network`), and
successful `--oci-pod` with `--hardened`. See
[test/results.md](../test/results.md) for details.

For the pod implementation internals, see
[architecture.md, Section 10](architecture.md#10-pods).

## 8. Kubernetes Pod YAML

sdme can create containers from Kubernetes Pod YAML files. Each pod maps
to a single nspawn container where each workload runs as a separate
systemd service (`sdme-oci-{name}.service`) chrooted into its own rootfs.
Multi-container pods share localhost and can communicate the same way they
would in a real Kubernetes cluster.

### 8.1 Preparing a base rootfs

You need a base rootfs with systemd. If you followed section 4, you
already have one. If not:

```bash
sudo sdme fs import ubuntu docker.io/ubuntu:24.04
```

To avoid passing `--base-fs` on every kube command:

```bash
sudo sdme config set default_base_fs ubuntu
```

### 8.2 Running kube pods

Write a Pod YAML file (or use an existing one). Here is a minimal example:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx
spec:
  containers:
  - name: nginx
    image: docker.io/nginx:latest
    ports:
    - containerPort: 80
```

Then apply it:

```bash
sudo sdme kube apply -f nginx-pod.yaml --base-fs ubuntu
sudo sdme kube apply -f nginx-pod.yaml --base-fs ubuntu -t 120   # custom boot timeout
```

This pulls the image, builds a combined rootfs (base OS plus the app
under `/oci/apps/nginx/root`), creates the container, boots it, and drops
you into a shell. Each container in the pod becomes a
`sdme-oci-{name}.service` inside the single nspawn container.

To create without starting:

```bash
sudo sdme kube create -f nginx-pod.yaml --base-fs ubuntu
sudo sdme start nginx
```

To stop and clean up (removes both the container and the kube rootfs):

```bash
sudo sdme kube delete nginx
```

Security flags (`--hardened`, `--strict`, `--userns`, `--drop-capability`,
`--capability`, `--no-new-privileges`, `--read-only`, `--system-call-filter`,
`--apparmor-profile`) are available on both `kube apply` and `kube create`.
These operate at the **nspawn container level** (outer sandbox), while Pod
YAML `securityContext` operates at the **OCI app service level** (inner
systemd units). Both layers are complementary:

```bash
sudo sdme kube apply -f nginx-pod.yaml --base-fs ubuntu --hardened
sudo sdme kube apply -f nginx-pod.yaml --base-fs ubuntu --strict
```

**Supported Pod spec features:**

- `containers[].image`, `name`, `command`, `args`, `env`, `envFrom`,
  `ports`, `volumeMounts`, `workingDir`, `imagePullPolicy`, `resources`
- `startupProbe`, `livenessProbe`, `readinessProbe` with exec,
  httpGet, tcpSocket, and grpc checks (see
  [Kubernetes probe docs](https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/))
- `initContainers[]` (run-to-completion before app containers)
- Volumes: `emptyDir`, `hostPath`, `secret`, `configMap`,
  `persistentVolumeClaim`
- `env[].valueFrom` with `secretKeyRef` and `configMapKeyRef`
- `restartPolicy` (Always, OnFailure, Never)
- `securityContext.runAsUser` / `runAsGroup` / `runAsNonRoot` (pod-level)
- `terminationGracePeriodSeconds`
- Deployments (`kind: Deployment`, apps/v1) are accepted; sdme extracts
  the pod template

**Secrets and configmaps.** Create them before applying a pod that
references them:

```bash
sudo sdme kube secret create db-creds --from-literal user=admin --from-literal password=s3cret
sudo sdme kube configmap create app-config --from-literal log_level=info --from-file config.yaml=./config.yaml

sudo sdme kube secret ls
sudo sdme kube configmap ls
```

Secrets and configmaps can be mounted as volumes or referenced via
`env[].valueFrom` in the pod spec. Values are resolved at container
creation time; changes to secrets or configmaps after creation do not
affect running containers.

**Multi-container pods.** For pods with more than one container, pass
the app name to `--oci` to target a specific service:

```bash
sudo sdme exec --oci nginx mycontainer -- nginx -t
sudo sdme join --oci redis mycontainer
sudo sdme logs --oci redis mycontainer -f
```

Single-container pods auto-select the only app, so `--oci` without a
value is sufficient.

**What's tested.** The kube test suite runs eight progressive levels:
L1 (basic lifecycle), L2-spec (pod spec features: command/args, env,
init containers, restart policy, resources, probes),
L2-security (container securityContext: capabilities, privilege
escalation, seccomp, AppArmor, runAsUser/runAsGroup), L3-volumes
(emptyDir, hostPath, configmaps, envFrom, read-only mounts, PVCs),
L3-secrets (secret volumes, projected items, defaultMode),
L4 (multi-container localhost connectivity), L5 (Redis round-trip), and
L6 (a full Gitea + MySQL + Nginx stack). See
[test/results.md](../test/results.md) for the complete results.

### 8.3 Composing kube pods with pod networking

You can combine `--pod` or `--oci-pod` with kube pods to give multiple
kube containers a shared network namespace:

```bash
sudo sdme pod new infra
sudo sdme kube apply -f frontend.yaml --base-fs ubuntu --pod infra
sudo sdme kube apply -f backend.yaml --base-fs ubuntu --pod infra
```

Both kube containers now share localhost. The frontend can reach the
backend's services directly, and vice versa.

**Note on userns and kube multi-container pods.** The `--pod`/`--userns`
incompatibility (Section 7.1) applies to connecting *separate* nspawn
containers via `--pod`. Kube multi-container pods are different: all OCI
apps run inside a *single* nspawn container as separate systemd services,
sharing localhost automatically. No `setns(CLONE_NEWNET)` is involved, so
`--hardened`, `--strict`, and `--userns` all work fine with multi-container
kube pods.

For the full kube specification reference, see
[architecture.md, Section 17](architecture.md#17-kubernetes-pod-support).

## 9. Further reading

- [Architecture and design](architecture.md): internals, overlayfs
  layout, container lifecycle, the build engine
- [OCI integration](architecture.md#16-oci-integration): the capsule
  model, privilege dropping, ports, volumes, known limitations
- [Security implementation](architecture.md#14-security): capabilities,
  seccomp, AppArmor, `--hardened`, `--strict`
- [Security comparisons](security.md): isolation model vs Docker and
  Podman, OCI workload security, kube security
- [Kubernetes Pod support](architecture.md#17-kubernetes-pod-support):
  full spec reference, supported fields, filesystem layout, service unit
  generation
- [OCI-to-nspawn bridging](architecture.md#16-oci-integration): how sdme
  handles non-root OCI users and /dev/stdout compatibility
- [macOS](macos.md): running sdme on macOS via lima-vm
- [Tests](../test/README.md): test suite, how to run
- [Test results](../test/results.md): latest verified results
