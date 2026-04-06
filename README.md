# sdme

The systemd machine editor: a command line tool for managing systemd-nspawn booted containers on Linux.

sdme boots Linux containers using systemd-nspawn with overlayfs
copy-on-write layers. Each container runs a real systemd init, so
services, journalctl, systemctl, timers, and everything else work
like a normal system. Changes stay in the container; the base
filesystem is never touched.

It is a single static binary with no daemon. It imports root
filesystems from OCI registries (Ubuntu, Fedora, Arch, NixOS, and
more), tarballs, directories, or QCOW2 images. It runs OCI
application images (nginx, redis, postgres) as systemd services
inside booted containers, and deploys multi-container pods from
Kubernetes Pod YAML manifests.

## Why sdme?

- **Full init**: containers boot systemd. Services start, timers fire, journald collects logs. It works like a real machine.
- **Test real scenarios**: systemd units, multi-service setups, distro packaging, upgrade paths. Anything that needs a booted system.
- **Clone your machine**: `sudo sdme new` snapshots your root filesystem and drops you into a shell.
- **Any systemd distro**: Ubuntu, Fedora, Arch, NixOS, openSUSE, CentOS, CachyOS, and more.
- **OCI images**: run Docker Hub images as systemd services inside a booted system.
- **Kubernetes Pod YAML**: deploy multi-container pods with volumes, secrets, configmaps, and health probes.
- **No daemon**: single static binary, no background service.

## Downloads, tutorials, and documentation

**[fiorix.github.io/sdme](https://fiorix.github.io/sdme/)**
