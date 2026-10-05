# Nested Workloads

Running containers inside an sdme container works in one topology and is rejected in another. Two things decide it: whether the outer container has a user namespace, and what its root filesystem is.

- A **privileged** outer container is created without `--userns`, `--hardened`, or `--strict`.
- A **user-namespaced** outer container is created with `--userns`, or with `--hardened` or `--strict`, which enable it.

```
Linux host + sdme
|-- Privileged outer container, btrfs root
|   |-- Docker, rootful Podman      supported
|   +-- Inner sdme containers       supported
+-- User-namespaced outer container
    |-- sdme rootfs management      supported (fs import, fs ls, fs rm, prune)
    |-- Inner sdme containers       not supported (rejected at create)
    +-- Docker or Podman            not supported
```

## 1. Support Matrix

```
Outer container   Inner workload            Status         Outer storage
----------------  ------------------------  -------------  -------------
Privileged        Docker, rootful Podman    Supported      btrfs
Privileged        Inner sdme containers     Supported      btrfs
User-namespaced   sdme rootfs management    Supported      Either
User-namespaced   Inner sdme containers     Not supported  None works
User-namespaced   Docker or Podman          Not supported  None works
```

- **Supported**: works, and is an intended use.
- **Not supported**: fails, or sdme rejects it before it can fail.

## 2. Privileged Outer Container

Root in a privileged outer container is host root, limited by nspawn's default capability set and seccomp filter. That is enough for an inner container runtime, with one requirement: the outer container needs a btrfs root (`--storage btrfs`, which takes an imported rootfs). On an overlay root, the inner runtime's writable layer would be an overlay on top of an overlay, which the kernel refuses; an inner sdme container then fails to start with a mount error.

```
Host kernel
+-- Outer nspawn (privileged, btrfs root)
    |-- dockerd + runc (btrfs storage driver)
    |-- podman (rootful)
    +-- Inner nspawn (overlay or btrfs root, with or without --userns)
```

- Docker runs with the btrfs storage driver: image build, registry push and pull, and container execution. Removing the outer container with `sdme rm` also removes the subvolumes Docker created under it.
- Rootful Podman runs under the same requirements. Rootless engines are a harder case inside nspawn; see the closing note of the [Docker tutorial](tutorial/docker-in-container.md).
- Inner sdme containers boot on overlay or btrfs, from the outer container's own root or from an imported rootfs, with or without `--userns`. The outer container needs `systemd-container` installed, and `btrfs-progs` for inner btrfs storage.

Example outer container for Docker:

```sh
sudo sdme new --name dockerbox -r ubuntu --storage btrfs \
  --network-veth \
  --system-call-filter bpf \
  --system-call-filter keyctl \
  --system-call-filter add_key
```

Inside it, configure Docker with `"storage-driver": "btrfs"`. The `bpf` syscall is needed for runc's cgroup v2 device controller; `keyctl` and `add_key` cover images that use the kernel keyring. `--network-veth` gives the container its own network namespace with `CAP_NET_ADMIN` over it, so the engine can create its bridge and container network namespaces with no `--capability` flag; on the host network the engine has no `CAP_NET_ADMIN` and `docker run` fails with `operation not permitted`. The [Docker tutorial](tutorial/docker-in-container.md) walks through the full setup.

Example outer container for inner sdme containers:

```sh
sudo sdme create --name outer -r ubuntu --storage btrfs --started
sudo sdme exec outer -- sh -c \
  'apt-get update && apt-get install -y systemd-container'
sudo sdme cp /usr/local/bin/sdme outer:/usr/local/bin/sdme
sudo sdme exec outer -- sdme create --name inner --started
```

One nested layer is the supported target. Deeper recursion may work, but depends on systemd, cgroup delegation, mount propagation, available capabilities, and resources. It is not an sdme compatibility guarantee.

## 3. User-Namespaced Outer Container: Rootfs Management

Root in a user-namespaced outer container maps to an unprivileged host UID. sdme detects this from a non-identity `/proc/self/uid_map` and avoids the operations that need privilege in the initial user namespace.

Inside such a container, on either storage backend, sdme can manage rootfs: `sdme fs import` of a registry image (including `--install-packages=yes`), `sdme fs ls`, `sdme fs rm`, and `sdme prune`. It cannot create containers; see the next section.

```sh
sudo sdme create --name outer -r ubuntu --storage btrfs --userns --started
sudo sdme exec outer -- tee /usr/local/bin/sdme < /usr/local/bin/sdme >/dev/null
sudo sdme exec outer -- chmod +x /usr/local/bin/sdme
sudo sdme exec outer -- sdme fs import docker.io/ubuntu --name ubuntu \
  --install-packages=yes
```

The binary goes in through `sdme exec` because `sdme cp` refuses to write into a running btrfs container under `--userns`.

`--userns-nested N` reserves N additional 64K UID/GID ranges for the outer container, on either storage backend. It is mapping capacity for workloads that create child user namespaces. sdme's own nested operations do not use the extra ranges, and the flag does not grant capabilities in the initial user namespace.

**Btrfs subvolumes in the nested data root.** Nested sdme does not create btrfs subvolumes: imports are plain directories and inner containers are rejected. If its data root holds subvolumes anyway, sdme inspects them with `stat()` instead of the privileged tree-search ioctls and destroys them with `BTRFS_IOC_SNAP_DESTROY_V2`:

- If the host mount has `user_subvol_rm_allowed`, the subvolume is removed.
- If the destroy is denied, sdme parks the subvolume in a `.trash` directory inside the nested data root and names the mount option to add. Parked subvolumes are destroyed by `sdme prune` run inside the outer container once the option is set, or along with the outer container when it is removed from the host. `sdme prune` on the host does not scan nested data roots.

## 4. User-Namespaced Outer Container: No Inner Containers

Creating a container inside a user-namespaced outer container fails at once, with or without `--userns` on the inner container:

1. Nested sdme detects a non-identity `/proc/self/uid_map`.
2. `--storage auto` (the default) selects overlay. Explicit `--storage btrfs` is rejected: a btrfs superblock cannot be owned by a nested user namespace, so nspawn's mount setup would fail.
3. Nested sdme probes `mknod` on a scratch tmpfs. The kernel requires `CAP_MKNOD` in the initial user namespace and returns `EPERM`.
4. The create is rejected before the container name is claimed, and no state is left behind.

The probe stands in for a boot that cannot succeed. Run directly in that context, `systemd-nspawn` fails to mount sysfs, to set up idmapped mounts with `-U`, or to remount its `/run/host/incoming` export with `--private-network`; through sdme that would surface only as a boot timeout. `sdme kube create` fails with the same error.

Docker and Podman inside a user-namespaced outer container are not supported either. Btrfs solves storage nesting, not the BPF, cgroup, proc, device, and mount privileges those engines may require.

## 5. Summary

Nesting containers takes a privileged outer container on btrfs: it can host Docker, rootful Podman, and inner sdme containers, one layer deep. A user-namespaced outer container can run sdme to manage rootfs, but cannot create containers or host a container engine. `--userns-nested` adds UID/GID mapping capacity and nothing else.

See [Architecture, Storage backends](architecture.md#storage-backends-overlay-and-btrfs), [Architecture, Nested user namespace ranges](architecture.md#nested-user-namespace-ranges), and [Security, User namespace](security.md#user-namespace) for the implementation details.
