# sdme: Container Isolation and Security

**Alexandre Fiori, March 2026**

## 1. Design Philosophy and Scope

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

## 2. Namespace Isolation

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

Podman rootless gets user namespace remapping by default — the entire
container runtime runs as an unprivileged user.

### Cgroup namespace

sdme uses `Delegate=yes` in the systemd template unit. The container's
systemd gets its own cgroup subtree (`machine.slice/sdme@<name>.service`)
but can see the host cgroup hierarchy structure. Docker and Podman provide
full cgroup namespace isolation.

## 3. Capability Bounding Set

Capabilities determine what privileged operations a container's root user
can perform.

### nspawn defaults (sdme)

nspawn retains 26 capabilities by default:

```
CAP_AUDIT_CONTROL       CAP_AUDIT_WRITE         CAP_CHOWN
CAP_DAC_OVERRIDE        CAP_DAC_READ_SEARCH     CAP_FOWNER
CAP_FSETID              CAP_IPC_OWNER           CAP_KILL
CAP_LEASE               CAP_LINUX_IMMUTABLE     CAP_MKNOD
CAP_NET_BIND_SERVICE    CAP_NET_BROADCAST       CAP_NET_RAW
CAP_SETFCAP             CAP_SETGID              CAP_SETPCAP
CAP_SETUID              CAP_SYS_ADMIN           CAP_SYS_BOOT
CAP_SYS_CHROOT          CAP_SYS_NICE            CAP_SYS_PTRACE
CAP_SYS_RESOURCE        CAP_SYS_TTY_CONFIG
```

`CAP_NET_ADMIN` is added only when `--private-network` is active, since
it is safe to grant when the container has its own network namespace
(changes only affect the isolated namespace, not the host).

`CAP_SYS_ADMIN` is the most significant capability in this set. It is
required for systemd to function inside the container: mounting filesystems,
configuring cgroups, managing namespaces for its own services. This cannot
be dropped without breaking the systemd-inside-nspawn model.

Notable exclusions: `CAP_SYS_MODULE` (no kernel module loading),
`CAP_SYS_RAWIO` (no raw I/O port access), `CAP_SYS_TIME` (no system clock
modification), `CAP_BPF` (no BPF program loading), `CAP_SYSLOG`, and
`CAP_IPC_LOCK`.

### Docker and Podman defaults

Docker retains roughly 14 capabilities — the minimum needed for typical
application containers. Notably, `CAP_SYS_ADMIN` is excluded. Podman uses
the same default set as Docker.

Docker doesn't need `CAP_SYS_ADMIN` because Docker containers don't run a
full init system. This is a fundamental consequence of the different design:
sdme runs full systemd (requiring broad capabilities), while Docker runs
single-purpose application processes (requiring minimal capabilities).

### sdme's capability controls

sdme provides fine-grained capability management:

- `--drop-capability CAP_X` — drop individual capabilities from nspawn's
  default set. Accepts names with or without the `CAP_` prefix.
- `--capability CAP_X` — add capabilities not in the default set (e.g.
  `CAP_NET_ADMIN` for containers with `--private-network`).
- `--hardened` drops `CAP_SYS_PTRACE`, `CAP_NET_RAW`, `CAP_SYS_RAWIO`,
  and `CAP_SYS_BOOT` (configurable via `hardened_drop_caps` in the config),
  reducing from 26 to 22 retained capabilities.

Both `--drop-capability` and `--capability` are repeatable and validated
against a known set of Linux capabilities. Specifying the same capability
in both is rejected as contradictory.

## 4. Seccomp Filtering

All three runtimes apply seccomp system call filters. The baseline
restrictiveness differs because of their different design goals.

### nspawn (sdme baseline)

nspawn applies a built-in allowlist-based seccomp filter. Syscalls not on
the allowlist are blocked with `EPERM` (for known syscalls) or `ENOSYS`
(for unknown ones).

Allowed by default: `@basic-io`, `@file-system`, `@io-event`, `@ipc`,
`@mount`, `@network-io`, `@process`, `@resources`, `@setuid`, `@signal`,
`@sync`, `@timer`, and about 50 individual syscalls.

Blocked unconditionally: `kexec_load`, `kexec_file_load`,
`perf_event_open`, `fanotify_init`, `open_by_handle_at`, `quotactl`,
the `@swap` group, and the `@cpu-emulation` group.

Capability-gated: `@clock` requires `CAP_SYS_TIME`, `@module` requires
`CAP_SYS_MODULE`, `@raw-io` requires `CAP_SYS_RAWIO`. Since none of these
capabilities are in the default bounding set, these syscall groups are
effectively blocked.

### Docker and Podman

Docker's OCI default seccomp profile is more restrictive, blocking roughly
44 syscalls with a more conservative allowlist. Podman uses the same OCI
default profile. The most significant difference: Docker blocks `mount()`
and related syscalls, while nspawn must allow `@mount` because systemd
needs them during boot.

This means a compromised process inside sdme has access to more kernel
surface than inside Docker. This is an inherent trade-off of running a
full init system.

### sdme's additional seccomp controls

`--system-call-filter` layers additional seccomp filters on top of nspawn's
baseline. It uses systemd's group syntax:

- `@group` — allow a syscall group
- `~@group` — deny a syscall group

```
sdme create mybox --system-call-filter ~@raw-io
sdme create mybox --system-call-filter ~@cpu-emulation
```

The flag is repeatable. Note that `~@mount` breaks systemd inside the
container — the same reason nspawn allows it in the first place.

## 5. Mandatory Access Control (MAC)

**sdme** ships a default AppArmor profile (`sdme-default`) designed for
systemd-nspawn system containers. The profile allows the operations
required for systemd boot (mount, pivot_root, signal, unix sockets) while
denying dangerous host-level access (raw device I/O, `/proc` sysctl writes,
kernel module paths). It is applied via `AppArmorProfile=` in the systemd
service unit drop-in.

The profile is automatically applied by `--strict`. It can also be used
standalone:

```
sdme create mybox --apparmor-profile sdme-default
```

The `sdme-default` profile is more permissive than Docker's `docker-default`
because sdme containers run a full init system. Docker blocks mount
operations entirely; sdme must allow them for systemd to set up `/proc`,
`/sys`, and tmpfs mounts during boot.

To install the profile:

```
sdme config apparmor-profile > /etc/apparmor.d/sdme-default
apparmor_parser -r /etc/apparmor.d/sdme-default
```

The deb and rpm packages install and load the profile automatically.

**Docker** ships a default AppArmor profile (`docker-default`) that
restricts mount operations, `/proc`/`/sys` writes, and cross-container
ptrace.

**Podman** has strong SELinux integration with `svirt` type enforcement
labels on Fedora/RHEL. AppArmor is used where available (Debian/Ubuntu).

On SELinux-only systems (Fedora, RHEL), sdme has no MAC confinement.
Docker and Podman provide MAC confinement out of the box on both AppArmor
and SELinux systems. No SELinux support is provided by sdme.

## 6. Privilege Escalation Prevention

### no_new_privs

**sdme**: off by default. `--no-new-privileges` (or `--hardened`) passes
`--no-new-privileges=yes` to nspawn. Off by default because interactive
containers typically want `sudo`/`su` to work — `no_new_privs` blocks
privilege escalation via setuid binaries and file capabilities.

**Docker**: enabled by default. Setuid binaries inside the container cannot
escalate privileges.

**Podman**: enabled by default.

### Read-only rootfs

**sdme**: `--read-only` makes the overlayfs merged view read-only.
Applications needing writable areas use bind mounts (`-b`).

**Docker**: `--read-only` flag, same concept.

**Podman**: `--read-only` flag, same concept.

All three provide read-only rootfs as an opt-in flag.

## 7. Network Isolation Deep Dive

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

## 8. Attack Surface

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

## 9. The `--hardened` Flag

`--hardened` is sdme's one-flag defense-in-depth bundle. It enables multiple
security layers at once:

- **User namespace isolation** (`--private-users=pick
  --private-users-ownership=auto`) — container root maps to a high
  unprivileged UID on the host.
- **Private network namespace** (`--private-network`) — the container gets
  its own network namespace with loopback only.
- **`--no-new-privileges=yes`** — blocks privilege escalation via setuid
  binaries and file capabilities.
- **Drops capabilities**: `CAP_SYS_PTRACE`, `CAP_NET_RAW`,
  `CAP_SYS_RAWIO`, `CAP_SYS_BOOT` — reducing from 26 to 22 retained
  capabilities.

```
sdme create mybox --hardened
sdme new mybox --hardened
```

**When cloning the host rootfs** (no `-r` flag), `--hardened` has several
visible effects because the container inherits the host's installed
binaries and enabled services:

- **No internet.** `--private-network` gives the container only a
  loopback interface. Host services that assume network access (sshd,
  NTP, avahi, etc.) will fail or retry indefinitely.
- **`sudo`/`su` silently fail.** `--no-new-privileges` prevents setuid
  escalation. The binaries exist and appear normal, but the kernel
  blocks the privilege transition.
- **`ping` and raw-socket tools fail.** `CAP_NET_RAW` is dropped.
- **`strace`/`gdb` fail.** `CAP_SYS_PTRACE` is dropped.

`sdme new` prints notes about `--private-network` and
`--no-new-privileges` when cloning the host rootfs. For imported rootfs
(e.g. `-r ubuntu`), these effects are less surprising because the rootfs
was built for container use.

For a host-rootfs container where these side effects matter, apply
individual flags instead:

```
sdme create mybox --userns --drop-capability CAP_SYS_RAWIO
```

### Composable with fine-grained flags

`--hardened` sets a baseline that individual flags can override or extend:

```
sdme create mybox --hardened --capability CAP_NET_RAW    # re-enable a dropped cap
sdme create mybox --hardened --system-call-filter ~@raw-io  # add seccomp filter
sdme create mybox --hardened --apparmor-profile myprofile   # add MAC confinement
sdme create mybox --hardened --read-only                    # read-only rootfs
```

### Configurable

The capabilities dropped by `--hardened` are controlled by the
`hardened_drop_caps` config key:

```
sdme config set hardened_drop_caps CAP_SYS_PTRACE,CAP_NET_RAW
```

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

## 10. The `--strict` Flag

`--strict` closes the gaps between `--hardened` and Docker/Podman defaults.
It implies `--hardened` and adds:

- **Aggressive capability drops**: retains only the ~14 capabilities Docker
  grants (AUDIT_WRITE, CHOWN, DAC_OVERRIDE, FOWNER, FSETID, KILL, MKNOD,
  NET_BIND_SERVICE, SETFCAP, SETGID, SETPCAP, SETUID, SYS_CHROOT) plus
  `CAP_SYS_ADMIN` (required for systemd init). Also drops `CAP_NET_RAW`
  (carried over from `--hardened`, stricter than Docker). Drops 27
  capabilities total.
- **Seccomp filters**: denies `@cpu-emulation`, `@debug`, `@obsolete`,
  and `@raw-io` syscall groups on top of nspawn's baseline filter.
- **AppArmor profile**: applies the `sdme-default` profile, which confines
  `/proc`/`/sys` writes and raw device access at the MAC level.

```
sdme create mybox --strict
sdme new mybox --strict
```

**When cloning the host rootfs**, `--strict` compounds the effects of
`--hardened` (above) with additional restrictions:

- **`systemd-networkd` and `NetworkManager` fail.**
  `CAP_NET_ADMIN` is dropped.
- **`systemd-timesyncd` cannot set the clock.** `CAP_SYS_TIME` is
  dropped.
- **Logging to `/dev/kmsg` is denied.** `CAP_SYSLOG` is dropped.
- **Nice/priority adjustments fail.** `CAP_SYS_NICE` is dropped.
- **AppArmor profile must be installed first.** The `sdme-default`
  profile is checked at `start` time; if it is not loaded, the
  container fails to start with instructions for installation.

For host-rootfs use, `--hardened` with selective additions is often
more practical than `--strict`:

```
sdme create mybox --hardened --system-call-filter ~@raw-io
```

`--strict` is best suited for imported rootfs images where the service
set is known and controlled.

### Why `CAP_SYS_ADMIN` is retained

`CAP_SYS_ADMIN` is required for systemd to function inside the container.
It needs to mount filesystems, configure cgroups, and manage namespaces
for its own services. This cannot be dropped without breaking the
systemd-inside-nspawn model.

With user namespace isolation (enabled by `--strict`), `CAP_SYS_ADMIN`
is scoped to the user namespace. It does not grant host-level SYS_ADMIN.
A process that escapes the container lands in an unprivileged context on
the host.

### Composable with fine-grained flags

Like `--hardened`, `--strict` sets a baseline that individual flags can
override:

```
sdme create mybox --strict --capability CAP_NET_RAW   # re-enable a dropped cap
sdme create mybox --strict --read-only                 # add read-only rootfs
sdme create mybox --strict --apparmor-profile custom   # use a custom profile
```

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
provides (see Section 12).

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

## 12. Security Philosophy: Full Init as a Benefit

sdme's security model is different from Docker and Podman by design. The
full systemd init environment inside every container is not a compromise —
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
have no equivalent — you either run one process per container or build
increasingly complex entrypoint scripts and agents around the container,
not in it. This sidecar functionality for your rootfs + OCI is key.

### OCI packaging, systemd management

You still get the OCI packaging and distribution model. Pull images from
any OCI registry, layer applications on base rootfs images. But at runtime,
the container is managed by systemd — the most widely available service
management framework on Linux.

### Pod isolation with OCI flexibility

`--oci-pod` confines the network namespace of the OCI application process
while keeping the container's systemd, journal, and D-Bus on their own
network. This gives you pod semantics for application networking without
sacrificing the container's management plane.

### The security trade-off

The trade-off is explicit: `CAP_SYS_ADMIN` and the `@mount` syscall group
cannot be dropped because systemd needs them. With `--strict`, this is
scoped to a user namespace — `CAP_SYS_ADMIN` does not grant host-level
privileges. Every other restriction matches or exceeds Docker defaults.

For environments that cannot accept `CAP_SYS_ADMIN` under any
circumstances, Docker or Podman is the right choice. For environments
that value operational familiarity, extensibility, and the full power
of systemd, sdme with `--strict` provides strong isolation while
preserving these benefits.

## 13. When to Use What

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

