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
- [docs/tests.md](docs/tests.md) -- Test suite overview
- [docs/story.md](docs/story.md) -- The backstory and project stats
