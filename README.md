# sdme

The systemd machine editor: a single static binary that creates and manages
Linux containers using systemd-nspawn with overlayfs. No daemon, no runtime
dependency beyond systemd. Written in Rust.

sdme is primarily a **development tool**. It makes systemd-nspawn containers
first-class citizens on any Linux machine, letting you spin up almost any
distro that can boot with systemd.

## Quick start

The simplest way to start is to clone your running system. This creates an
overlayfs snapshot of your host, boots systemd inside it, and drops you into
your own shell with your $HOME and configs intact. Install packages, change
configs, break things; the host is untouched.

```
sudo sdme new
```

## Importing any root filesystem

Beyond cloning your host, sdme can import a root filesystem from virtually any
source: OCI registries, local directories, tarballs, URLs, or QCOW2 cloud
images. Each imported rootfs becomes a reusable template. Spin up as many
containers as you want from it, across Debian, Ubuntu, Fedora, CentOS,
AlmaLinux, openSUSE, Arch Linux, CachyOS, and NixOS.

See [importing root filesystems](docs/usage.md#4-importing-root-filesystems).

## Fully featured containers

These containers support all the expected systemd-nspawn capabilities: port
binding, private networking, bind mounts, and complex security configurations.
Run pretty much any systemd-capable distro as a container on any Linux machine.

See [security, networking, and resource limits](docs/usage.md#8-security-networking-and-resource-limits).

---

## Experimental features

Everything below this line is experimental. These features work and are
actively developed, but their interfaces may change.

### OCI application support

sdme can run OCI application images (e.g. nginx, redis, mysql) as systemd
services inside a booted container, with port bindings and volumes wired
through. The OCI application runs in a chroot inside the systemd container.

See [OCI applications](docs/usage.md#5-oci-applications).

### Dual security model and pods

The OCI application has a security model resembling Docker and Podman, while
the systemd container can have different configurations and security
permissions. Containers can be placed in a **pod**, a shared network namespace,
letting you compose a control plane and an application plane separately.

See [pods](docs/usage.md#6-pods).

### Kubernetes pod support

sdme can consume Kube Pod YAML and set up multi-container pods on a systemd
container, with volumes, port bindings, config maps, secrets, and probes.

See [Kubernetes Pod YAML](docs/usage.md#7-kubernetes-pod-yaml).

### Exporting rootfs and containers

Export any imported rootfs or container filesystem as a directory, tarball, or
raw disk image for sharing or producing bootable VM images.

See [docs/usage.md](docs/usage.md) for export details.

## Further reading

- [docs/usage.md](docs/usage.md): install, lifecycle, rootfs management,
  networking, OCI, pods, security, builds
- [docs/architecture.md](docs/architecture.md): internals, design, OCI
  bridging, Kubernetes mapping
