# sdme

Lightweight systemd-nspawn container manager with overlayfs. A single static
binary that creates and manages Linux containers -- each boots full systemd
over a copy-on-write layer, keeping the base rootfs untouched. No daemon, no
runtime dependency beyond systemd.

## What you can do

### 1. Clone your machine for experimentation

Create an overlayfs clone of your running system, boot systemd inside it, and
land in your own shell with your $HOME and configs. Install packages, change
configs, break things -- the host is untouched.

```bash
sudo sdme new
```

When you are done, manage containers with:

```bash
sudo sdme ps              # list containers and their status
sudo sdme join <name>     # re-enter a running container
sudo sdme stop <name>     # stop a container
sudo sdme rm <name>       # remove a container
```

### 2. Import a root filesystem from virtually any source

Import from OCI registries, local directories, tarballs, URLs, or QCOW2 cloud
images. Each imported rootfs is a reusable template -- spin up as many
containers as you want from it. Supported distros: Debian, Ubuntu, Fedora,
CentOS, AlmaLinux, Arch Linux, CachyOS, openSUSE, and NixOS.

```bash
sudo sdme fs import ubuntu docker.io/ubuntu:24.04
sudo sdme fs import fedora quay.io/fedora/fedora
sudo sdme fs import archlinux docker.io/archlinux

# Create containers from imported rootfs
sudo sdme new -r ubuntu
sudo sdme new -r fedora
sudo sdme new -r archlinux
```

See [docs/usage.md](docs/usage.md) for the full list of import sources.

### 3. Import OCI applications into your nspawn container

Any OCI image (nginx, redis, postgresql, anything on Docker Hub or any
registry) runs as a systemd service inside a booted container. No Docker or
Podman required.

```bash
sudo sdme fs import ubuntu docker.io/ubuntu:24.04 -v --install-packages=yes
sudo sdme fs import redis docker.io/redis --base-fs=ubuntu -v
sudo sdme new -r redis
```

Inside the container, the app is a managed systemd service. From outside, use
`sdme logs` and `sdme exec`:

```bash
sudo sdme logs --oci <name>
sudo sdme exec --oci <name> redis-cli ping
```

See [OCI integration](docs/architecture.md#8-oci-integration) for the full
story.

### 4. Run a Kubernetes pod in your nspawn container

Run Kubernetes Pod YAML directly as nspawn containers. Multi-container pods,
shared volumes, init containers, secrets, and configmaps are all supported.

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

```bash
sudo sdme kube apply -f pod.yaml --base-fs ubuntu
```

See [Kubernetes pod support](docs/architecture.md#11-kubernetes-pod-support)
for the full spec.

## Further reading

- [docs/usage.md](docs/usage.md): install, lifecycle, rootfs management,
  networking, OCI, pods, security, builds
- [docs/architecture.md](docs/architecture.md): internals, design, OCI
  bridging, Kubernetes mapping
