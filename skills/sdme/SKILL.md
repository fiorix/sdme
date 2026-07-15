---
name: sdme
description: Operational guidance for using sdme and troubleshooting sdme-managed systemd-nspawn containers. Use when an AI agent needs to help with sdme commands, container lifecycle, rootfs import/build/export, OCI or Kubernetes pod workloads, networking, stop/start failures, systemd-nspawn, machined, machinectl, journalctl, systemctl diagnostics, or repository changes to sdme itself.
---

# sdme

## Operating Model

Treat sdme as a rootful systemd-nspawn and overlayfs manager. It creates containers with writable overlayfs upper layers, boots a full systemd as PID 1 inside each container, and drives host systemd/machined over D-Bus.

Prefer the current binary as source of truth. Run `sdme --help`, `sdme <command> --help`, and `sdme dump-skill` when behavior may have changed. Prefer repository docs and source over memory when editing sdme.

Assume most operational commands require root. Use `sudo sdme ...` for live operations unless the command is explicitly rootless, such as `sdme dump-skill`, `sdme config completions`, and `sdme config apparmor-profile`.

## First Diagnostic Pass

Collect facts before changing state:

```sh
sdme --version
sudo sdme config get
sudo sdme ps
machinectl list --no-pager
systemctl is-active systemd-machined.service
systemctl status systemd-machined.service --no-pager
```

For a specific container, inspect both the host unit and the guest:

```sh
sudo systemctl status sdme@NAME.service --no-pager
sudo journalctl -u sdme@NAME.service -b --no-pager
machinectl status NAME --no-pager
sudo sdme logs NAME -b --no-pager
sudo sdme exec NAME -- systemctl --failed --no-pager
sudo sdme exec NAME -- journalctl -b --no-pager
```

If a command times out or hangs, capture the exact command, stderr, timeout, container name, `sdme ps` state, the host unit journal, and the guest journal tail.

## Lifecycle Commands

Use these commands for normal operation:

```sh
sudo sdme new NAME -r FS
sudo sdme create NAME -r FS
sudo sdme start NAME
sudo sdme join NAME
sudo sdme exec NAME -- COMMAND...
sudo sdme logs NAME
sudo sdme stop NAME
sudo sdme restart NAME
sudo sdme rm NAME
```

Use `sdme ps` as the high-level status view. It summarizes container state, health, rootfs, network, resource limits, OCI app metadata, and pod relationships.

For stopped containers, inspect state files and overlay directories under the configured datadir, normally `/var/lib/sdme`. Do not edit state files manually unless the user is recovering from corruption and understands the risk.

## Stop And Restart Troubleshooting

Know the three stop paths:

- Default graceful stop sends `KillMachine(name, "leader", SIGRTMIN+3)` through machined. For guest systemd, `SIGRTMIN+3` starts `halt.target`; this matches `systemd-nspawn --boot` orderly shutdown behavior and should make nspawn exit cleanly.
- `sdme stop --term NAME` calls `TerminateMachine`. Treat it as an escalation path through machined/nspawn when the direct guest-systemd halt path does not complete.
- `sdme stop --kill NAME` sends SIGKILL to all machine processes through `KillMachine`. Use it only after collecting logs or when the user explicitly wants force.

When default stop is stuck, check whether the guest reaches `halt.target`, `poweroff.target`, or `reboot.target`. A healthy default stop should show the halt path and then the host `sdme@NAME.service` should deactivate. If logs show reboot activity, investigate signal mapping, nspawn behavior, and guest target aliases before changing rootfs state.

Useful references from systemd behavior:

- `SIGRTMIN+3` to systemd means halt (`halt.target`).
- `SIGRTMIN+4` means poweroff (`poweroff.target`).
- `SIGRTMIN+5` means reboot (`reboot.target`).
- `systemd-nspawn --boot` defaults its orderly shutdown signal to `SIGRTMIN+3` when nspawn receives SIGTERM.

## Start And Boot Troubleshooting

For start failures, inspect the host unit first:

```sh
sudo systemctl status sdme@NAME.service --no-pager
sudo journalctl -u sdme@NAME.service -b --no-pager
```

Then check whether machined registered the machine:

```sh
machinectl list --no-pager
machinectl status NAME --no-pager
```

Common causes include missing systemd/dbus in the rootfs, bad `/etc/os-release`, masked or broken essential services, networking setup failures, overlayfs permission problems, restrictive umask during create, missing bind mount sources, and unsupported user namespace or idmapped mount behavior on the host filesystem.

For guest boot failures, use `sdme logs NAME -b --no-pager` and, when the guest is reachable, `sdme exec NAME -- systemctl --failed --no-pager`.

## Exec, Join, And Logs

Use `sdme join` for interactive login-like sessions. It prefers `machinectl shell` and may fall back to namespace entry when needed.

Use `sdme exec` for non-interactive commands and scripts. It uses `systemd-run --machine=NAME --pipe --wait --quiet --collect`, so stdout/stderr are suitable for shell pipelines.

Use `sdme logs` for container journals. The default `sdme logs NAME` reads the host unit journal (`journalctl -u sdme@NAME.service`). The `--oci` form reads an OCI app service journal from inside the container and detects the NixOS `journalctl` path when possible.

## Rootfs And OCI Workflows

Use `sdme fs import` for root filesystems from OCI registries, tarballs, directories, and disk images. Use `--install-packages=yes` when an imported distro rootfs needs packages such as systemd or dbus installed for boot.

Use `sdme fs build` for repeatable rootfs customization from `FROM`, `RUN`, and `COPY` directives.

Use `sdme fs export` to write a container or rootfs out as a directory, tarball, or disk image. Use `--vm` for a bootable raw image.

For OCI application images, remember that sdme runs the app as a systemd service inside a full rootfs. App images generally need a base OS rootfs via `--base-fs` or `default_base_fs`.

Inspect OCI app metadata under the rootfs `oci/apps/` directory when debugging env, ports, or volumes. The app filesystem is `oci/apps/{name}/root/`. The entrypoint (ExecStart) lives in the generated unit `/etc/systemd/system/sdme-oci-{name}.service`, not under `oci/apps/`.

## Storage Backends

A container's writable root uses one of two backends, chosen with `--storage` (default `overlay`). Overlay is the original model: an immutable lower rootfs and a per-container `upper`/`merged`. Btrfs gives each container a copy-on-write subvolume snapshot instead, which enables nested containers (a real upperdir is available), preserves suid and xattrs under `--userns` via native idmapped mounts, and supports a per-container disk cap. Only imported rootfs can use btrfs; host-rootfs containers (`sdme new` with no `--fs`) always stay on overlay.

On a datadir that is already btrfs, subvolumes live under `{datadir}/btrfs/` (Mode A). Otherwise sdme keeps them in a loopback pool image `{datadir}/btrfs-pool.img` mounted at `{datadir}/pool/` (Mode B); its container subvolumes are `{datadir}/pool/containers/{name}` and bases are `{datadir}/pool/fs/{name}`. For stopped btrfs containers, inspect the subvolume directly instead of an overlay `upper`. `--storage btrfs` needs `btrfs-progs`, and `--disk` (a btrfs qgroup cap, shown in `sdme ps` as used/limit) additionally needs btrfs simple quotas from btrfs-progs and kernel 6.7 or newer.

Running a container engine (Docker or Podman) inside a btrfs container needs the `bpf` syscall allowed in seccomp so runc can program the cgroup v2 device controller: `--system-call-filter bpf` (plus `keyctl add_key` for images that use the kernel keyring). `--system-call-filter` accepts bare syscall names and `~name` denies, not only `@group` sets; no `CAP_BPF` is needed because the retained `CAP_SYS_ADMIN` covers the operation. Add `--capability CAP_NET_ADMIN --network-veth` for the engine's own bridge and iptables, load `br_netfilter` on the host, and point the engine at its `btrfs` storage driver so image layers become nested subvolumes. `sdme rm` deletes those nested subvolumes recursively. See the docker-in-container tutorial.

## Networking Checks

By default, sdme containers use the host network namespace. Port publishing requires a private network plus an interface (`--network-veth`, `--network-bridge`, or `--network-zone`); `--private-network` alone gives only loopback and cannot forward ports.

For networked containers, inspect:

```sh
sudo sdme ps
sudo sdme exec NAME -- ip addr
sudo sdme exec NAME -- resolvectl status
sudo sdme exec NAME -- systemctl status systemd-networkd systemd-resolved --no-pager
```

For zones and pod networks, verify pod membership, bridge/veth names, DHCP leases, and whether `systemd-resolved` is intentionally masked or unmasked for that mode.

## Pods And Kubernetes

Use `sdme kube apply` to run Kubernetes Pod YAML, and `sdme pod` to manage pod lifecycle and networking. Pods and OCI workloads ultimately run as sdme containers, so the lifecycle, stop/start, and logs diagnostics above apply directly.

For Kubernetes-specific failures, check Pod YAML parsing, probe readiness (`probe-ready` files under `/oci/apps/{name}/`), and `sdme kube secret`/`sdme kube configmap` data used for env references and projected volumes.

## Repository Work

When changing sdme itself, start from the existing docs and source map instead of duplicating that material in the prompt or this skill:

- `README.md`: project overview, install path, and user-facing positioning.
- `site/content/docs/architecture.md`: main design and implementation map.
- `site/content/docs/security.md`: security model and hardening trade-offs.
- `site/content/tutorial/*.md`: user workflows and examples.
- `test/README.md`: live and end-to-end validation notes.
- `Cargo.toml`: crate metadata, binaries, features, and dependencies.

Find code by responsibility:

- `src/main.rs`: CLI definitions, long help text, and command dispatch.
- `src/lib.rs`: module index plus shared state and utility helpers.
- `src/containers/`: create, list, manage, stop, exec, and join behavior.
- `src/systemd/`: D-Bus helpers and generated nspawn/systemd units.
- `src/import/`, `src/export/`, `src/rootfs/`: rootfs import/build/export flows.
- `src/kube/`, `src/pod.rs`, `src/network.rs`: Kubernetes pod support, pod networking, and network flags.
- `src/security.rs`, `src/userns.rs`, `src/mounts.rs`: hardening, user namespaces, binds, and env handling.

Read the relevant source and existing tests before editing. Tests usually live beside implementation in module test files or `#[cfg(test)]` modules. Keep CLI help, site docs, and this skill in sync when behavior changes.

Run focused tests for the changed area, then prefer the full baseline when feasible:

```sh
cargo test
cargo fmt --check
git diff --check
```

For behavior tied to live systemd-nspawn or machined, add unit tests for pure logic and perform live validation only when a suitable disposable container is available. Never force-remove user containers or reset the worktree without explicit permission.
