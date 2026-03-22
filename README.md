# sdme

Run Linux distros as containers on your machine. Each container boots
a real systemd init, so it looks and works like a normal system: services,
journalctl, systemctl, the whole stack. Changes stay in the container;
the base filesystem is never touched.

```
sudo sdme new
```

This uses your root filesystem as a template, creates an overlayfs
snapshot, boots systemd inside it, and drops you into a shell. You can
import other root filesystems (Ubuntu, Fedora, etc.) and use them as
templates to spin up containers from. Changes are written to the
overlayfs upper layer; the template is never modified.

## Why sdme?

sdme containers are full systems, not single processes.

- **Full init**: containers boot systemd. Services start, timers fire, journald collects logs. It looks and works like a real machine.
- **Test real scenarios**: systemd units, multi-service setups, distro packaging, upgrade paths. Anything that needs a booted system.
- **Clone your machine**: `sudo sdme new` gives you your system with your shell, your $HOME, and your configs.
- **Any systemd distro**: Ubuntu, Fedora, Arch, NixOS, openSUSE, CentOS, CachyOS, and more. Import from OCI registries, tarballs, directories, or QCOW2 images.
- **OCI images too**: run nginx, redis, postgres from Docker Hub as systemd services inside a booted system.
- **Kubernetes Pod YAML**: deploy multi-container pods from standard manifests, with volumes, secrets, configmaps, and health probes.
- **No daemon**: single static binary, no background service needed.

## Install

Download the latest release:

```bash
curl -L https://github.com/fiorix/sdme/releases/latest/download/sdme-x86_64-linux -o sdme
chmod +x sdme
sudo mv sdme /usr/local/bin/
```

Install the container runtime for your distro:

```bash
sudo apt install systemd-container   # Debian / Ubuntu
sudo dnf install systemd-container   # Fedora / CentOS
sudo pacman -S systemd               # Arch (included in base)
```

Requires Linux with systemd 252+. Runs as root.

On macOS? See [docs/macos.md](docs/macos.md) for setting up a Linux VM
with lima-vm, then install sdme inside it.

## Quick start

```bash
# Clone your machine
sudo sdme new

# Import and boot Ubuntu
sudo sdme fs import ubuntu docker.io/ubuntu:24.04
sudo sdme new -r ubuntu

# Import and boot Fedora
sudo sdme fs import fedora docker.io/fedora:41
sudo sdme new -r fedora
```

## What you can do

**Manage containers**

- `sdme new`: create, start, and enter a container in one step
- `sdme create` / `start` / `stop` / `rm`: full lifecycle control
- `sdme join`: enter a running container
- `sdme exec`: run a command inside a container
- `sdme ps`: list containers with status and health
- `sdme logs`: view container logs via journalctl
- `sdme enable` / `disable`: auto-start containers on boot

**Import and export filesystems**

- `sdme fs import`: from OCI registries, directories, tarballs, URLs, or QCOW2 images
- `sdme fs export`: to directories, tarballs, or raw disk images (ext4/btrfs)
- `sdme fs build`: build a rootfs from a config file with resumable steps
- `sdme fs ls` / `rm`: list and remove imported filesystems

**Run OCI application images**

Run Docker Hub images (nginx, redis, postgres, etc.) as systemd services
inside a booted container. Port bindings and volumes are wired through
automatically.

**Networking and security**

Private networking, port forwarding, bind mounts, environment variables.
Three security tiers: individual flags, `--hardened`, and `--strict`
(seccomp filters, capability restrictions, AppArmor). User namespace
support included.

**Pods**

Shared network namespaces for multi-container setups. Containers in a pod
communicate over localhost.

**Kubernetes Pod YAML**

`sdme kube apply -f pod.yaml --base-fs ubuntu` creates multi-container
pods from standard Kubernetes manifests.

## Further reading

Every command is documented via `sdme <command> --help`.

- [docs/architecture.md](docs/architecture.md): internals, design, OCI
  bridging, Kubernetes mapping
- [docs/security.md](docs/security.md): container isolation model,
  comparison with other container runtimes
