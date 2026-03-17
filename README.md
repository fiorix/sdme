# sdme

The systemd machine editor: a single static binary that creates and manages
Linux containers using systemd-nspawn with overlayfs. No daemon, no runtime
dependency beyond systemd. Written in Rust.

sdme is primarily a **development tool**. It makes systemd-nspawn containers
first-class citizens on any Linux machine, letting you spin up almost any
distro that can boot with systemd.

## Containers from your host filesystem

The simplest way to start is to clone your running system. This creates an
overlayfs snapshot of your host, boots systemd inside it, and drops you into
your own shell with your $HOME and configs intact. Install packages, change
configs, break things; the host is untouched.

```
sudo sdme new
```

Manage containers with:

```
sudo sdme ps              # list containers and their status
sudo sdme join <name>     # re-enter a running container
sudo sdme stop <name>     # stop a container
sudo sdme rm <name>       # remove a container
```

## Importing any root filesystem

Beyond cloning your host, sdme can import a root filesystem from virtually any
source: OCI registries, local directories, tarballs, URLs, or QCOW2 cloud
images. Each imported rootfs becomes a reusable template. Spin up as many
containers as you want from it.

```
sudo sdme fs import ubuntu docker.io/ubuntu:24.04
sudo sdme fs import fedora quay.io/fedora/fedora
sudo sdme fs import archlinux docker.io/archlinux

sudo sdme new -r ubuntu
sudo sdme new -r fedora
sudo sdme new -r archlinux
```

sdme has specific distribution support for Debian, Ubuntu, Fedora, CentOS,
AlmaLinux, openSUSE, Arch Linux, CachyOS, and NixOS. This ensures that the
right packages are present in what we consider a base filesystem for spinning
up a working container.

See [docs/usage.md](docs/usage.md) for the full list of import sources.

## Fully featured containers

These containers are fully featured. They support all the expected
systemd-nspawn capabilities: port binding, private networking, bind mounts,
and complex security configurations. They are useful when you want to install
and run services from the regular distribution repositories or your own
packages, anything you would normally do on a real machine.

The result is that you can run pretty much any systemd-capable distro as a
container on any Linux machine.

See [security, networking, and resource limits](docs/usage.md#8-security-networking-and-resource-limits)
and the [security architecture](docs/architecture.md#15-security) for details.

---

## Experimental features

Everything below this line is experimental. These features work and are
actively developed, but their interfaces may change.

### OCI application support

sdme can query OCI container registries, flatten the root filesystem of any
image, and make it a usable base filesystem.

Because we now support importing from OCI, it is natural to differentiate
between **base filesystem images** like Debian and Fedora, and **application
images** like nginx and MySQL, images that normally bind on ports and share
volumes.

The way this works is by placing the entire OCI application (e.g. the nginx
container) as a chroot inside the systemd container and wiring it all up so
that it looks like a Docker or Podman environment. The application runs as a
systemd service inside a booted container.

```
sudo sdme fs import redis docker.io/redis --base-fs=ubuntu
sudo sdme new -r redis
```

Port bindings and volume bindings are wired to the systemd container itself:

```
sudo sdme logs --oci <name>
sudo sdme exec --oci <name> redis-cli ping
```

See [OCI integration](docs/architecture.md#8-oci-integration) for the full
story.

### Dual security model and pods

Because the systemd container is running the OCI application as a service, you
get two independent layers of configuration.

The OCI application has a security model resembling Docker and Podman, while
the systemd container can have different configurations and security
permissions. This separation gives you fine-grained control over what each
layer can do.

Containers can be placed in a **pod**, a shared network namespace. Pods can
be shared across systemd containers, but the OCI applications themselves can
also be placed in the same or a different pod. This lets you compose a
**control plane** and an **application plane** separately, from both the
network and isolation perspective.

### Kubernetes pod support

The next natural evolution is Kubernetes pod support. sdme can consume Kube Pod
YAML and set up the pod on a systemd container.

Volumes and port bindings are wired through, multiple OCI applications can be
placed in the same systemd container, and the common Kubernetes features are
supported: config maps, secrets, and probes.

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: myapp
spec:
  containers:
  - name: nginx
    image: docker.io/nginx:latest
    ports:
    - containerPort: 80
  - name: redis
    image: docker.io/redis:latest
  - name: mysql
    image: docker.io/mysql:latest
    env:
    - name: MYSQL_ROOT_PASSWORD
      value: secret
```

```
sudo sdme kube apply -f pod.yaml --base-fs ubuntu
```

See [Kubernetes pod support](docs/architecture.md#11-kubernetes-pod-support)
for the full spec.

### Exporting rootfs and containers

Export any imported rootfs or container filesystem as a directory, tarball, or
raw disk image. Copy containers to other machines, share rootfs templates, or
produce bootable VM images for hypervisors like Cloud Hypervisor and QEMU.

```
sudo sdme fs export ubuntu ubuntu.tar.zst
sudo sdme fs export --container <name> container.tar.gz
sudo sdme fs export ubuntu ubuntu.raw --format raw
```

## Further reading

- [docs/usage.md](docs/usage.md): install, lifecycle, rootfs management,
  networking, OCI, pods, security, builds
- [docs/architecture.md](docs/architecture.md): internals, design, OCI
  bridging, Kubernetes mapping
