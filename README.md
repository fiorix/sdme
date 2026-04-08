# sdme

sdme is a command line tool for managing systemd-nspawn containers on
Linux. It is distributed as a single static binary or in packages (deb,
rpm, pkg) for x86_64 and aarch64.

sdme configures and orchestrates systemd to run containers. Each
container boots its own systemd init: services start, timers fire,
journald collects logs. It works like a real machine. Containers use
overlayfs copy-on-write layers, so each one gets its own writable
filesystem on top of a shared base image, keeping the original intact.

As part of the toolkit, sdme imports root filesystems from multiple
sources including OCI registries (e.g. Docker images), tarballs,
directories, and QCOW2 images. It also deploys multi-container pods
from Kubernetes Pod YAML manifests.

## Why sdme?

- **Test real scenarios**: systemd units, multi-service setups, distro packaging, upgrade paths. Anything that needs a booted system.
- **Clone your machine**: `sudo sdme new` snapshots your root filesystem and drops you into a shell.
- **Any systemd distro**: Ubuntu, Fedora, Arch, NixOS, openSUSE, CentOS, CachyOS, and more.
- **OCI application images**: run Docker Hub images (nginx, redis, postgres) as systemd services.
- **Kubernetes Pod YAML**: deploy multi-container pods with volumes, secrets, configmaps, and health probes.

## Downloads, tutorials, and documentation

**[fiorix.github.io/sdme](https://fiorix.github.io/sdme/)**
