# sdme: Container Isolation and Security

**Alexandre Fiori, March 2026**

This document compares sdme's isolation model with Docker and Podman.
For sdme's security implementation details (capabilities, seccomp,
AppArmor, `--hardened`, `--strict`), see
[architecture.md, Section 14](architecture.md#14-security).

## 1. Security Philosophy: Full Init as a Benefit

sdme's security model is different from Docker and Podman by design. The
full systemd init environment inside every container is not a compromise;
it is the primary value proposition.

### Familiar systems

sdme containers are the Linux you know. They run systemd, journald, and
D-Bus. You manage services with `systemctl`, read logs with `journalctl`,
and configure the system with the tools you already use. There is no
container-specific runtime to learn, no custom logging driver, no
proprietary health check mechanism.

### Your rootfs, your rules

Even OCI applications imported with `sdme fs import` run on the rootfs of
your choice. You pick your Debian, your CentOS, your Fedora. The OCI app
is confined inside that environment as a systemd service
(`sdme-oci-app.service`), not as a standalone process.

### Extensible containers

`sdme fs build` lets you extend any base rootfs: install monitoring agents,
add custom services, configure systemd units. These services run alongside
the OCI workload but outside it, in the same container. Docker and Podman
have no equivalent: you either run one process per container or build
increasingly complex entrypoint scripts and agents around the container,
not in it. This sidecar functionality for your rootfs + OCI is key.

### OCI packaging, systemd management

You still get the OCI packaging and distribution model. Pull images from
any OCI registry, layer applications on base rootfs images. But at runtime,
the container is managed by systemd, the most widely available service
management framework on Linux.

### Pod isolation with OCI flexibility

`--oci-pod` confines the network namespace of the OCI application process
while keeping the container's systemd, journal, and D-Bus on their own
network. This gives you pod semantics for application networking without
sacrificing the container's management plane.

### The security trade-off

The trade-off is explicit: `CAP_SYS_ADMIN` and the `@mount` syscall group
cannot be dropped because systemd needs them. With `--strict`, this is
scoped to a user namespace; `CAP_SYS_ADMIN` does not grant host-level
privileges. Every other restriction matches or exceeds Docker defaults.

For environments that cannot accept `CAP_SYS_ADMIN` under any
circumstances, Docker or Podman is the right choice. For environments
that value operational familiarity, extensibility, and the full power
of systemd, sdme with `--strict` provides strong isolation while
preserving these benefits.

## 2. Design Philosophy and Scope

sdme, Docker, and Podman take fundamentally different approaches to container
security.

**sdme** delegates baseline isolation to systemd-nspawn and provides opt-in
hardening layers: `--hardened` as a one-flag defense-in-depth bundle, plus
fine-grained controls for capabilities, seccomp, AppArmor, privilege
escalation, and read-only rootfs. It is designed for single-tenant machines
running full systemd inside containers. It requires root for all operations
and has no persistent daemon.

**Docker** applies defense-in-depth by default: reduced capabilities, a
restrictive seccomp profile, a default AppArmor profile, and optional user
namespace remapping. It is daemon-based (containerd) and designed for
application containers that typically run a single process.

**Podman** provides similar defense-in-depth with rootless execution by
default, SELinux integration on Fedora/RHEL, and a daemonless architecture.
It is designed for OCI-compatible workflows and Docker CLI compatibility.

The key philosophical difference: Docker and Podman apply security layers by
default and require explicit opt-out. sdme provides the layers but requires
explicit opt-in (or `--hardened` for a sensible bundle). Out of the box,
sdme trusts its workloads; Docker and Podman do not.

## 3. Namespace Isolation

Every container runtime uses Linux namespaces for isolation. The table below
compares which namespaces each runtime enables and how.

```
+-----------------------+----------------------------+----------------------------+----------------------------+
| Namespace             | sdme (nspawn)              | Docker (runc, rootful)     | Podman (crun, rootless)    |
+-----------------------+----------------------------+----------------------------+----------------------------+
| PID                   | Always                     | Always                     | Always                     |
| IPC                   | Always                     | Always                     | Always                     |
| UTS                   | Always                     | Always                     | Always                     |
| Mount                 | Always                     | Always                     | Always                     |
| Network               | Optional (host default)    | Yes (bridge default)       | Yes (slirp4netns/pasta)    |
| User                  | Optional                   | Optional                   | Yes (default)              |
| Cgroup                | Partial (Delegate=yes)     | Yes                        | Yes                        |
+-----------------------+----------------------------+----------------------------+----------------------------+
```

### Always-on namespaces

All three runtimes always create PID, IPC, UTS, and mount namespaces. In
sdme, PID 1 inside the container is the container's systemd init, not the
host's. Processes inside cannot see or signal host processes, IPC objects are
isolated, the container has its own hostname, and the mount table is
independent (built from an overlayfs mount on top of the rootfs).

### Network namespace

sdme shares the host's network namespace by default for simplicity: no port
mapping, no bridge configuration, containers just work on the host's network
stack. This is equivalent to `docker run --net=host`.

Docker creates a private bridge network by default, providing network
isolation out of the box. Podman rootless uses slirp4netns or pasta for
unprivileged network namespace setup.

sdme provides network isolation via `--private-network` (or `--hardened`,
which enables it automatically). With `--private-network`, the container
gets its own network namespace with only a loopback interface. Connectivity
options (`--network-veth`, `--network-bridge`, `--network-zone`, `--port`)
build on top of that.

### User namespace

Without `--userns`, UID 0 inside the container is UID 0 on the host. A
container escape gives the attacker full root access. This is the default
for both sdme and rootful Docker.

With `--userns` (or `--hardened`), sdme passes `--private-users=pick
--private-users-ownership=auto` to nspawn. Container root maps to a high
unprivileged UID on the host (524288+ range, deterministically hashed from
the machine name). An escape lands in an unprivileged context. On kernel
6.6+, overlayfs supports idmapped mounts, making this zero-overhead (files
stay UID 0 on disk). On older kernels, `auto` falls back to recursive chown
on first boot.

Podman rootless gets user namespace remapping by default; the entire
container runtime runs as an unprivileged user.

### Cgroup namespace

sdme uses `Delegate=yes` in the systemd template unit. The container's
systemd gets its own cgroup subtree (`machine.slice/sdme@<name>.service`)
but can see the host cgroup hierarchy structure. Docker and Podman provide
full cgroup namespace isolation.

## 4. Capability Bounding Set

Capabilities determine what privileged operations a container's root user
can perform.

Docker retains roughly 14 capabilities, the minimum needed for typical
application containers. Notably, `CAP_SYS_ADMIN` is excluded. Podman uses
the same default set as Docker.

Docker doesn't need `CAP_SYS_ADMIN` because Docker containers don't run a
full init system. This is a fundamental consequence of the different design:
sdme runs full systemd (requiring broad capabilities), while Docker runs
single-purpose application processes (requiring minimal capabilities).

sdme (via nspawn) retains 26 capabilities by default, including
`CAP_SYS_ADMIN`. See
[architecture.md, Section 14](architecture.md#14-security) for the full
capability list and sdme's `--drop-capability`/`--capability` controls.

## 5. Seccomp Filtering

All three runtimes apply seccomp system call filters. The baseline
restrictiveness differs because of their different design goals.

Docker's OCI default seccomp profile is more restrictive, blocking roughly
44 syscalls with a more conservative allowlist. Podman uses the same OCI
default profile. The most significant difference: Docker blocks `mount()`
and related syscalls, while nspawn must allow `@mount` because systemd
needs them during boot.

This means a compromised process inside sdme has access to more kernel
surface than inside Docker. This is an inherent trade-off of running a
full init system.

See [architecture.md, Section 14](architecture.md#14-security) for
nspawn's baseline filter details and sdme's `--system-call-filter` controls.

## 6. Mandatory Access Control (MAC)

**Docker** ships a default AppArmor profile (`docker-default`) that
restricts mount operations, `/proc`/`/sys` writes, and cross-container
ptrace.

**Podman** has strong SELinux integration with `svirt` type enforcement
labels on Fedora/RHEL. AppArmor is used where available (Debian/Ubuntu).

**sdme** ships a default AppArmor profile (`sdme-default`) that is more
permissive than Docker's `docker-default` because sdme containers run a
full init system. Docker blocks mount operations entirely; sdme must allow
them for systemd to set up `/proc`, `/sys`, and tmpfs mounts during boot.

**SELinux is not supported.** sdme has no SELinux integration and does
not provide MAC confinement on SELinux-only systems (Fedora, RHEL).
During rootfs import (`sdme fs import`), `security.selinux` extended
attributes are explicitly skipped because they do not transfer
meaningfully between filesystems and would cause label conflicts on
the host. Docker and Podman provide MAC confinement out of the box on
both AppArmor and SELinux systems.

See [architecture.md, Section 14](architecture.md#14-security) for the
`sdme-default` profile details and installation instructions.

## 7. Privilege Escalation Prevention

**Docker**: `no_new_privs` enabled by default. Setuid binaries inside the
container cannot escalate privileges.

**Podman**: enabled by default.

**sdme**: off by default because interactive containers typically want
`sudo`/`su` to work. Enabled by `--no-new-privileges`, `--hardened`,
or `--strict`.

All three provide read-only rootfs as an opt-in flag (`--read-only`).

See [architecture.md, Section 14](architecture.md#14-security) for
sdme's `--no-new-privileges` and `--read-only` implementation details.

## 8. Network Isolation Deep Dive

### Default mode (host networking)

By default, sdme containers share the host's network namespace. This is
equivalent to `docker run --net=host`. No network isolation exists: the
container can bind to any port, see all host interfaces, and communicate
with any network the host can reach.

This is the simplest mode and sufficient for most development use cases.
The trade-off is explicit: zero network isolation in exchange for zero
configuration.

### Private network mode

`--private-network` gives the container its own network namespace with
only a loopback interface (no external connectivity). This is the foundation
for all other network options.

```
sdme create mybox --private-network
sdme create mybox --private-network --network-veth
sdme create mybox --private-network --network-zone=myzone
sdme create mybox --private-network --port=8080:80
```

When `--private-network` is active:

- The container gets `CAP_NET_ADMIN` (safe, since it only affects the
  isolated namespace).
- systemd-nspawn creates the network namespace and optionally sets up
  veth pairs, bridges, or zones.
- Port forwarding (`--port`) maps host ports to container ports through
  nspawn's built-in NAT.

This is closest to Docker's default networking model.

`--hardened` enables `--private-network` automatically.

### Pod networking

Pods give multiple containers a shared network namespace (see
[architecture.md, Section 10](architecture.md#10-pods) for implementation
details and lifecycle management).

Two mechanisms for joining a pod:

**`--pod` (whole-container):** The entire nspawn container runs in the pod's
network namespace via `--network-namespace-path=`. All processes, including
the container's systemd init, share the pod's network stack. This is the
general-purpose option.

**`--oci-pod` (OCI app process only):** The pod's netns is bind-mounted into
the container at `/run/sdme/oci-pod-netns`, and a systemd drop-in sets
`NetworkNamespacePath=` on the OCI app service. Only the application process
enters the pod's netns; the container's init and other services keep their
own network namespace. This is for OCI app containers that need pod
networking for their application but want systemd's own networking (e.g.
journal remote, D-Bus) to remain independent.

**Comparison with Podman pods.** Podman uses an "infra container" (a pause
process) to hold the pod's network namespace. Podman pods support full
external connectivity through slirp4netns/pasta or CNI/Netavark plugins.
sdme pods are loopback-only by default with no built-in external
connectivity mechanism.

**Comparison with Docker Compose.** Docker Compose creates shared bridge
networks, not true pod semantics. Containers in a Compose service
communicate via DNS names over a bridge, not via localhost. sdme pods are
closer to Kubernetes pod semantics: shared localhost, shared ports.

### Pod isolation properties

The pod netns is created with only a loopback interface and no routes.
Containers in the pod can communicate via `127.0.0.1` but have no external
connectivity unless a veth or bridge is added to the netns externally.

When a container joins a pod with `--pod`, it does **not** use
`--private-network`. This means `CAP_NET_ADMIN` is **not** granted.
The container's root cannot add interfaces, modify routes, or change iptables
rules in the shared netns. `CAP_SYS_ADMIN` is present (required for systemd)
but the container's PID namespace prevents access to the host's network
namespace references through `/proc`.

## 9. Attack Surface

### Process-level surface

sdme containers run a full systemd init system: PID 1 is systemd, with
journald, logind, dbus-daemon, and any enabled services. A typical container
has ~10 processes at idle. Docker containers typically run a single
application process (PID 1).

More processes means more potential targets for exploitation, but also means
familiar operational tooling: `systemctl`, `journalctl`, `loginctl`.

### Filesystem surface

Without `--userns`, UID 0 inside the container is UID 0 on the host. The
overlayfs upper layer files are owned by real host UIDs. With `--userns`,
container root maps to a high UID, so files are owned by that UID on the
host (or stay UID 0 on disk with idmapped mounts on kernel 6.6+).

Custom bind mounts (`-b`/`--bind`) expose host directories directly into
the container. A read-write bind mount gives container root full access to
those host files. Use `:ro` for read-only mounts when the container does
not need write access.

### Network surface

In default mode (host networking), the container shares the host's full
network stack. A compromised container process can:

- Bind to any host port
- Connect to any host-accessible network
- Sniff traffic on host interfaces (via `CAP_NET_RAW`)
- Access host-local services on `127.0.0.1`

With `--private-network`, `--hardened`, or `--pod`, the container is limited
to its own network namespace.

### Daemon surface

sdme has no persistent daemon. There is no equivalent of Docker's
`containerd` socket, which is a well-known privilege escalation vector
(access to the Docker socket is effectively root access). sdme communicates
with systemd over the system D-Bus, which is already present and secured
by its own policy.

## 10. Hardening Tiers: Comparison with Docker/Podman

sdme provides two convenience flags (`--hardened` and `--strict`) that
bundle multiple security layers. See
[architecture.md, Section 14](architecture.md#14-security) for full
details on what each flag enables and its effects on host-rootfs
containers.

### How `--hardened` compares to Docker/Podman defaults

`--hardened` covers user namespace isolation, network isolation,
`no_new_privs`, and capability reduction. The remaining gaps versus
Docker/Podman defaults are:

- **No default MAC confinement.** Docker ships a default AppArmor profile.
  sdme supports `--apparmor-profile` but `--hardened` does not set one.
- **Less restrictive seccomp baseline.** nspawn's allowlist permits
  `@mount` and more syscall groups than Docker's OCI default profile.
- **More capabilities retained.** Even after `--hardened` drops 4
  capabilities, 22 remain (including `CAP_SYS_ADMIN`), compared to
  Docker's ~14.

These gaps are inherent to running a full init system inside the container.
For maximum restriction, use `--strict`.

### `--strict` vs Docker defaults

```
+-----------------------------+---------------------------+---------------------------+
| Mechanism                   | sdme --strict             | Docker default            |
+-----------------------------+---------------------------+---------------------------+
| User namespace              | Yes                       | Optional                  |
| Network namespace           | Yes (loopback only)       | Yes (bridge)              |
| no_new_privs                | Yes                       | Yes                       |
| Retained caps               | ~14 (Docker - NET_RAW)    | ~14                       |
| Seccomp                     | nspawn baseline + 4 deny  | OCI default (~44 blocked) |
| AppArmor                    | sdme-default              | docker-default            |
| CAP_SYS_ADMIN               | Yes (for systemd)         | No                        |
| Init in container           | Full systemd              | Single process            |
+-----------------------------+---------------------------+---------------------------+
```

The one remaining difference is `CAP_SYS_ADMIN` and the `@mount` syscall
group, both required for the full init model. sdme's security philosophy
is that this is an acceptable trade-off for the operational benefits it
provides (see Section 1).

## 11. Isolation Summary Table

```
+-----------------------+----------------------------+----------------------------+----------------------------+
| Mechanism             | sdme (nspawn)              | Docker (runc, rootful)     | Podman (crun, rootless)    |
+-----------------------+----------------------------+----------------------------+----------------------------+
| PID namespace         | Yes                        | Yes                        | Yes                        |
| IPC namespace         | Yes                        | Yes                        | Yes                        |
| UTS namespace         | Yes                        | Yes                        | Yes                        |
| Mount namespace       | Yes                        | Yes                        | Yes                        |
| Network namespace     | Optional (host default)    | Yes (bridge default)       | Yes (slirp4netns/pasta)    |
| User namespace        | Optional (--strict: yes)   | Optional                   | Yes (default)              |
| Cgroup namespace      | Partial (Delegate=yes)     | Yes                        | Yes                        |
| Capabilities          | ~26 (--strict: ~15)        | ~14, no SYS_ADMIN          | Same as Docker             |
| Seccomp               | nspawn + optional filters  | OCI default (~44 blocked)  | Same as Docker             |
| AppArmor              | sdme-default (--strict)    | Default profile            | Where available            |
| SELinux               | None                       | svirt labels               | Strong integration         |
| no_new_privs          | Optional (--strict: yes)   | Yes (default)              | Yes (default)              |
| Read-only rootfs      | Optional                   | Optional                   | Optional                   |
| Rootless              | No (root-only)             | Optional                   | Default                    |
| Daemon                | None                       | containerd socket          | None                       |
| Init in container     | Full systemd (always)      | Optional (--init)          | Optional (--init)          |
+-----------------------+----------------------------+----------------------------+----------------------------+
```

Each "Optional" cell means the feature is available but not on by default.
For sdme, `--strict` enables all security layers simultaneously. Individual
flags: `--private-network` or `--hardened` for network namespace, `--userns`
or `--hardened` for user namespace, `--no-new-privileges` or `--hardened`
for no_new_privs, `--read-only` for read-only rootfs, `--apparmor-profile`
for AppArmor, and `--system-call-filter` for additional seccomp rules.

## 12. When to Use What

**sdme** is appropriate when:

- You want a full systemd environment (service management, journald, cgroups).
- You want disposable containers that boot quickly, with no daemon.
- You are comfortable with root-level operation.
- You use `--strict` for Docker-equivalent security, or `--hardened` for
  defense-in-depth.
- You want to extend containers with custom services alongside OCI workloads.

**Docker or Podman** is appropriate when:

- You need defense-in-depth out of the box for untrusted workloads.
- You need rootless execution (especially Podman).
- You need OCI-compatible image building and distribution workflows.
- You cannot accept `CAP_SYS_ADMIN` in any form.
- You operate in a multi-tenant environment.
- Compliance requirements specify specific isolation standards.

**Podman specifically** when:

- Rootless is a hard requirement.
- SELinux integration is needed.
- You want a daemonless runtime with Docker-compatible CLI.
- You need Kubernetes-style pod semantics with full external connectivity.
