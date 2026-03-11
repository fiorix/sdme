# sdme

Lightweight systemd-nspawn container manager with overlayfs.

sdme is a single static binary that creates, runs, and manages
systemd-booted containers on Linux. Each container gets an overlayfs
copy-on-write layer over a base root filesystem, so the base stays
untouched. No daemon, no runtime dependency beyond systemd. Containers
are regular systemd services with full init, journalctl, systemctl, and
cgroups.

## Install

Download a static binary from
[fiorix.github.io/sdme](https://fiorix.github.io/sdme/).

sdme requires root for all operations and systemd >= 252.

Install the one required dependency:

```bash
# Debian / Ubuntu
sudo apt install systemd-container

# Fedora / CentOS / AlmaLinux
sudo dnf install systemd-container

# Arch Linux
sudo pacman -S systemd    # systemd-nspawn is included

# openSUSE
sudo zypper install systemd-container
```

**On macOS?** See [macos.md](docs/macos.md) for instructions using
lima-vm.

## Dev mode

The simplest thing sdme does is clone your running host system:

```bash
sudo sdme new
```

This creates an overlayfs clone of `/`, boots systemd inside a
container, and drops you into a root shell. Your host filesystem is
untouched -- all changes happen in the overlay. Install packages, change
configs, break things -- then exit and throw it away.

```bash
sudo sdme ps                # list containers and their status
sudo sdme stop <name>       # stop a container
sudo sdme start <name>      # start it again
sudo sdme join <name>       # re-enter a running container
sudo sdme rm <name>         # remove a container
```

## Any distro

Import root filesystems from OCI registries and run containers of any
distribution, regardless of your host:

```bash
sudo sdme fs import debian docker.io/debian
sudo sdme fs import ubuntu docker.io/ubuntu:24.04
sudo sdme fs import fedora quay.io/fedora/fedora
sudo sdme fs import centos quay.io/centos/centos:stream9
sudo sdme fs import almalinux quay.io/almalinuxorg/almalinux:9
sudo sdme fs import suse docker.io/opensuse/tumbleweed
sudo sdme fs import archlinux docker.io/archlinux
```

NixOS rootfs can also be imported, but must be built with systemd and
dbus included (NixOS is declarative, so sdme cannot install packages
into it). See [test/nix/](test/nix/) for a ready-to-use Nix
configuration and build script.

Each imported rootfs becomes a reusable template. Spin up as many
containers as you want from it; each gets its own overlayfs layer:

```bash
sudo sdme new -r ubuntu
sudo sdme new -r fedora
```

You can also import from local directories, tarballs, QCOW2 cloud
images, and debootstrap output. See [usage.md](docs/usage.md) for
details.

## OCI applications

sdme can run any Docker or Podman container image (nginx, redis,
postgresql, anything on Docker Hub or any OCI registry) as a systemd
service inside a booted container. No Docker or Podman required.

```bash
sudo sdme fs import ubuntu docker.io/ubuntu:24.04 -v --install-packages=yes
sudo sdme fs import redis docker.io/redis --base-fs=ubuntu -v
sudo sdme new -r redis
```

Inside the container, the OCI app runs as a managed systemd service:

```bash
systemctl status sdme-oci-app.service
```

This gives you the OCI packaging model (pull from any registry) with
the systemd operational model (journalctl, systemctl, cgroup limits,
security hardening). See
[OCI integration](docs/architecture.md#8-oci-integration) for the
full story.

## Further reading

- [docs/usage.md](docs/usage.md) -- Full user guide: install,
  lifecycle, rootfs management, networking, OCI, pods, and builds
- [docs/architecture.md#oci](docs/architecture.md#8-oci-integration)
  -- OCI container images: capsule model, import modes, ports, volumes
- [docs/security.md](docs/security.md) -- Container isolation and
  security hardening
- [docs/usage.md#pods](docs/usage.md#pods) -- Pods: shared network
  namespaces for multi-container setups
- [docs/architecture.md](docs/architecture.md) -- Architecture and
  design decisions
- [docs/hacks.md](docs/hacks.md) -- Wiring OCI apps into
  systemd-nspawn
- [docs/macos.md](docs/macos.md) -- Running sdme on macOS via lima-vm
- [test/README.md](test/README.md) -- Test suite overview
- [test/results.md](test/results.md) -- Latest test results
- [docs/story.md](docs/story.md) -- The backstory and project stats
