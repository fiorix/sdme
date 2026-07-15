+++
title = "Running Docker and a Registry Inside a Container"
description = "Run a full Docker engine and a private registry inside an sdme container, backed by btrfs storage."
weight = 13
+++

sdme containers run a full systemd init, which is enough to host a nested container engine. This tutorial runs a complete Docker install inside an sdme container: a private registry, an image build, and containers launched from that registry, all without touching the host's Docker (there does not need to be one).

Nested Docker has two requirements the defaults do not cover: a real filesystem for the container root so Docker's storage driver works, and permission to use the `bpf` syscall for the cgroup v2 device controller. sdme's `--storage btrfs` provides the first (see [using a different root filesystem](@/tutorial/different-rootfs.md#storage-backends)); `--system-call-filter` provides the second. See also the [networking](@/tutorial/networking.md) tutorial, which this one builds on.

{% callout(type="warn", title="Why --storage btrfs and --system-call-filter") %}
With `--storage btrfs`, the container's root is a real btrfs subvolume rather than an overlayfs. Docker's `btrfs` storage driver then runs on a genuine filesystem and creates its own nested subvolumes: no overlay-on-overlay problem, and no bind-mount workaround. Every layer, from the container root down to each image layer, is a native btrfs subvolume.

On cgroup v2 the device controller is enforced by an eBPF program. runc calls `bpf()` to install it, and systemd-nspawn's seccomp filter denies that syscall by default, so every `docker run` fails with `bpf_prog_query(BPF_CGROUP_DEVICE) failed: operation not permitted`. Allowing the `bpf` syscall unblocks it. No extra capability is needed: `CAP_SYS_ADMIN` (already in nspawn's default set) covers the operation. `keyctl` and `add_key` are added for images that use the kernel keyring.

`--network-veth` plus `CAP_NET_ADMIN` give the container its own network namespace so Docker's bridge and iptables rules stay isolated from the host.
{% end %}

## Host preparation

The container cannot load kernel modules, so make sure the ones Docker needs are present on the host first. `overlay`, `btrfs`, and `veth` are usually auto-loaded; `br_netfilter` (used by Docker's bridge networking) often is not:

```sh
sudo modprobe br_netfilter
```

`--storage btrfs` needs `btrfs-progs` on the host. If the sdme data directory (`/var/lib/sdme`) is itself on btrfs, containers become native subvolumes; on any other filesystem, sdme transparently creates a loopback btrfs pool for them. Either way, no manual volume setup is required.

## Create the container

Create and enter a container from an imported Ubuntu rootfs (see [using a different root filesystem](@/tutorial/different-rootfs.md) to import one):

```sh
sudo sdme new dockerbox -r ubuntu --storage btrfs \
  --network-veth \
  --capability CAP_NET_ADMIN \
  --system-call-filter bpf \
  --system-call-filter keyctl \
  --system-call-filter add_key
```

`sdme new` creates the container, starts it, and drops you into a root shell inside it. All the commands in the next sections run **inside that shell**. (btrfs storage requires an imported rootfs, so `-r ubuntu` is required here; a host clone cannot use it.)

## Install Docker

```sh
apt-get update
apt-get install -y docker.io
```

Select the `btrfs` storage driver so Docker uses subvolumes on the container's btrfs root, then start the daemon:

```sh
mkdir -p /etc/docker
cat > /etc/docker/daemon.json <<'EOF'
{
  "storage-driver": "btrfs"
}
EOF
systemctl enable --now docker
```

Confirm Docker came up on btrfs:

```sh
docker info | grep -i 'storage driver'
```

You should see `Storage Driver: btrfs`. Now run the canonical first container:

```sh
docker run --rm hello-world
```

`Hello from Docker!` confirms that image pull, the btrfs storage driver, and the cgroup v2 device controller (the `bpf` syscall we allowed) all work, with no extra capability granted.

## Run a private registry

Start a registry as a container, published on port 5000:

```sh
docker run -d --restart=always -p 5000:5000 --name registry registry:2
docker ps
```

## Build, push, and run an image

Build a small image and tag it for the local registry:

```sh
mkdir -p ~/app && cd ~/app
cat > Dockerfile <<'EOF'
FROM alpine:3.20
RUN echo 'built inside sdme' > /msg
CMD ["cat", "/msg"]
EOF
docker build -t localhost:5000/hello:v1 .
```

Push it to the registry, then prove the round trip by deleting the local copy, pulling it back, and running it:

```sh
docker push localhost:5000/hello:v1
docker rmi localhost:5000/hello:v1
docker pull localhost:5000/hello:v1
docker run --rm localhost:5000/hello:v1
```

The final command prints `built inside sdme`, served from the registry running inside the same sdme container.

{% callout(type="tip", title="Pure btrfs, no overlay") %}
The whole chain is native btrfs. Inside the container, `docker info` reports `Storage Driver: btrfs` with `Backing Filesystem: btrfs`. From the host, `sudo btrfs subvolume list` on the sdme btrfs pool shows the container's root subvolume with Docker's image and layer subvolumes (`.../var/lib/docker/btrfs/subvolumes/*`) nested under it. No overlay2, no fuse-overlayfs anywhere.
{% end %}

## Cleanup

Leave the container shell, then remove the container. Its btrfs subvolume (and everything Docker created inside it) is removed with it:

```sh
exit
sudo sdme rm -f dockerbox
```

## Summary

The three requirements for a working Docker engine inside an sdme container:

<pre class="diagram">
Requirement          Flag / setting                  Why
-------------------  ------------------------------  -------------------------
btrfs root           --storage btrfs plus            container root is a real
                     "storage-driver": "btrfs"       fs; no overlay-on-overlay
device controller    --system-call-filter bpf        cgroup v2 devices use eBPF
                     (keyctl, add_key too)           (no extra capability)
isolated networking  --network-veth plus             Docker's bridge/iptables
                     --capability CAP_NET_ADMIN      run in the container netns
</pre>

Podman rootful runs under the same requirements. Rootless container engines are a harder case inside nspawn: storage is solved the same way (a btrfs root gives the kernel's native overlay, no fuse), but nspawn's read-only `/proc/sys` and locked `/proc` submounts block a rootless engine's child user namespace from mounting a fresh `/proc`. For nested engines, prefer the rootful path shown here.

See the [architecture](@/docs/architecture.md) and [security](@/docs/security.md) documentation for how sdme's storage backends, capabilities, and seccomp filtering work.
