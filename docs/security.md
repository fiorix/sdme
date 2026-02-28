# sdme: Container Isolation and Security

**Alexandre Fiori, February 2026**

## 1. Design Philosophy and Scope

sdme delegates all container isolation to systemd-nspawn. It does not add
security layers on top: no custom seccomp profiles, no AppArmor or SELinux
policy. What nspawn provides is what you get.

This is a deliberate choice. sdme is a single-binary tool for spinning up
disposable containers on a single-tenant machine. Out of the box, its
isolation model works well for developer workstations and trusted workloads.
Running truly isolated untrusted workloads is possible but requires specific
hardening (private networking, pod netns, resource limits, and optionally
external MAC profiles) compared to Docker and Podman, which apply several
of these layers by default.

Docker and Podman use defense-in-depth: namespaces + reduced capabilities +
a strict seccomp profile + MAC confinement (AppArmor or SELinux) + optional
user namespace remapping. sdme's model is simpler: kernel namespace isolation
from nspawn, nspawn's default capability bounding set, and nspawn's built-in
seccomp filter. The hardening section (Section 8) covers how to close the
gap when stronger isolation is needed.

If your threat model requires protection against a malicious root inside the
container (a container escape scenario), sdme needs additional hardening
beyond its defaults. Docker with user namespace remapping and Podman rootless
provide this out of the box. With sdme, you can enable user namespace
isolation via `--userns` (see Section 8), but it is not on by default,
so the remaining layers (network isolation, MAC confinement, resource limits)
become more important. See Section 8 for specific recommendations.

## 2. What systemd-nspawn Provides

sdme runs containers with `systemd-nspawn --boot`, letting nspawn handle
namespace creation, capability bounding, and seccomp filtering. Here is what
nspawn provides by default (systemd >= 252).

### Always-on namespaces

Every nspawn container gets its own:

- **PID namespace** -- processes inside cannot see or signal host processes.
  PID 1 inside the container is the container's systemd init, not the host's.
- **IPC namespace** -- System V IPC objects and POSIX message queues are
  isolated. Containers cannot interfere with each other's shared memory.
- **UTS namespace** -- the container has its own hostname (set to the
  machine name). Changes to hostname inside the container are invisible to
  the host.
- **Mount namespace** -- the container has its own mount table. sdme builds
  this from an overlayfs mount on top of the rootfs.

### Conditional namespaces

- **Network namespace** -- only with `--private-network` or
  `--network-namespace-path=`. Without either flag, containers share the
  host's network namespace (same interfaces, same ports, no isolation).
  sdme defaults to host networking.
- **User namespace** -- only with `--private-users`. sdme supports this via
  `--userns` on `create`/`new`, which passes `--private-users=pick
  --private-users-ownership=auto`. Without `--userns`, UID 0 inside the
  container is UID 0 on the host.
- **Cgroup namespace** -- partial isolation via `Delegate=yes` in the
  template unit. The container's systemd gets its own cgroup subtree
  (`machine.slice/sdme@<name>.service`) but can see the host cgroup hierarchy
  structure.

### Capability bounding set

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
required for systemd to function inside the container (mounting filesystems,
configuring cgroups, managing namespaces for its own services). Docker drops
`CAP_SYS_ADMIN` by default, but Docker containers do not run a full init
system.

Capabilities not retained include: `CAP_SYS_MODULE` (no kernel module
loading), `CAP_SYS_RAWIO` (no raw I/O port access), `CAP_SYS_TIME` (no
system clock modification), `CAP_BPF` (no BPF program loading),
`CAP_SYSLOG`, and `CAP_IPC_LOCK`.

### Seccomp filter

nspawn applies a built-in allowlist-based seccomp filter (defined in
`nspawn-seccomp.c`). Syscalls not on the allowlist are blocked with `EPERM`
(for known syscalls) or `ENOSYS` (for unknown ones).

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

This filter is less restrictive than Docker's OCI default profile (which
blocks roughly 44 syscalls and uses a more conservative allowlist) but
provides a meaningful baseline. The key difference is that nspawn's filter
allows `@mount` syscalls (required for systemd's own mount management),
while Docker blocks them.

### What nspawn does NOT provide by default

- **No AppArmor profile.** Docker ships a default AppArmor profile that
  restricts mount operations, write access to `/proc` and `/sys`, and
  prevents `ptrace` across containers. nspawn applies no MAC confinement
  unless the administrator configures it externally.
- **No SELinux labels.** Docker and Podman assign `svirt` labels to
  containers, providing type enforcement even if a container escapes its
  namespaces. nspawn does not label containers.
- **No user namespace remapping by default.** `--private-users` is available
  and sdme exposes it via `--userns`. Without `--userns`, UID 0 inside the
  container maps directly to UID 0 on the host.
- **No `no_new_privs`.** This flag is off by default in nspawn (`--no-new-
  privileges=false`). Setuid binaries inside the container function normally,
  meaning a process can gain privileges through `execve()` of a setuid binary.
  Docker sets `no_new_privs` by default.
- **No read-only root enforcement.** The overlayfs merged view is writable.
  Docker supports `--read-only` to make the root filesystem read-only.

## 3. Isolation Comparison

This table maps every major isolation mechanism across sdme, Docker (rootful,
default configuration), and Podman (rootless, default configuration).

```
+-----------------------+----------------------------+----------------------------+----------------------------+
| Mechanism             | sdme (nspawn)              | Docker (runc, rootful)     | Podman (crun, rootless)    |
+-----------------------+----------------------------+----------------------------+----------------------------+
| PID namespace         | Yes                        | Yes                        | Yes                        |
| IPC namespace         | Yes                        | Yes                        | Yes                        |
| UTS namespace         | Yes                        | Yes                        | Yes                        |
| Mount namespace       | Yes                        | Yes                        | Yes                        |
| Network namespace     | Optional (host default)    | Yes (bridge default)       | Yes (slirp4netns/pasta)    |
| User namespace        | Optional (--userns)        | Optional                   | Yes (default)              |
| Cgroup namespace      | Partial (Delegate=yes)     | Yes                        | Yes                        |
| Capabilities          | ~26 incl. SYS_ADMIN        | ~14, no SYS_ADMIN          | Same as Docker             |
| Seccomp               | nspawn allowlist           | OCI default (~44 blocked)  | Same as Docker             |
| AppArmor              | None                       | Default profile            | Where available            |
| SELinux               | None                       | svirt labels               | Strong integration         |
| no_new_privs          | No                         | Yes                        | Yes                        |
| Read-only rootfs      | No                         | Optional                   | Optional                   |
| Rootless              | No (root-only)             | Optional                   | Default                    |
| Daemon                | None                       | containerd socket          | None                       |
| Init in container     | Full systemd (always)      | Optional (--init)          | Optional (--init)          |
+-----------------------+----------------------------+----------------------------+----------------------------+
```

### Key differences explained

**Network namespace.** sdme shares the host network by default for
simplicity: no port mapping, no bridge configuration, containers just work
on the host's network stack. Docker creates a private bridge network by
default, providing network isolation out of the box. Podman rootless uses
slirp4netns or pasta for unprivileged network namespace setup.

**User namespace.** Without `--userns`, UID 0 inside the container is UID 0
on the host. A container escape gives the attacker full root access. With
`--userns`, container root maps to a high UID on the host (524288+ range),
so an escape lands in an unprivileged context. On kernel 6.6+, overlayfs
supports idmapped mounts, so `--userns` has zero overhead and files on the
upper layer stay UID 0 on disk. Podman rootless runs the entire container
runtime as an unprivileged user, providing similar protection by default.

**Capabilities.** Docker retains roughly 14 capabilities (the minimum needed
for typical application containers). nspawn retains 26, including
`CAP_SYS_ADMIN`, because full systemd inside the container requires it for
mount management, cgroup delegation, and namespace operations. This is not
something sdme can change without breaking the systemd-inside-nspawn model.

**Seccomp.** Docker's OCI default profile is more restrictive, particularly
around mount-related syscalls. nspawn must allow `mount()` and related
syscalls because systemd needs them during boot. The practical difference
is that a compromised process inside an sdme container has more syscalls
available than inside a Docker container.

**MAC confinement.** Docker's default AppArmor profile and Podman's SELinux
integration provide a second layer of defense: even if a process escapes its
namespaces, MAC policy restricts what it can access on the host. sdme has no
MAC layer. This is the most significant gap for security-sensitive
deployments.

**Rootless operation.** sdme requires root because overlayfs with
`trusted.*` xattrs, bind mounts, and nspawn itself all require root
privileges. Podman's rootless mode is a fundamentally different security
posture: the container runtime itself is unprivileged.

## 4. Network Namespace Deep Dive

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

### Pod networking

Pods give multiple containers a shared network namespace. The implementation
uses raw syscalls:

```
  1. unshare(CLONE_NEWNET)    -- create new network namespace
  2. ioctl(SIOCSIFFLAGS)      -- bring up loopback
  3. bind-mount /proc/self/ns/net to /run/sdme/pods/<name>/netns
  4. setns() to restore original netns
```

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

The OCI app process (running as a non-root UID via `drop_privs`) has zero
effective capabilities.

Contrast with Podman rootless: `CAP_SYS_ADMIN` inside a user-namespace-
remapped container is meaningless against host resources because the user
namespace maps it to an unprivileged UID on the host. In sdme, `CAP_SYS_ADMIN`
is real root `CAP_SYS_ADMIN`, constrained only by namespace boundaries and
the seccomp filter.

## 5. Intentional Trade-offs vs. Genuine Gaps

### Intentional trade-offs (by design)

**Root-only execution.** Overlayfs with `trusted.*` xattrs, bind mounts,
and systemd-nspawn all require root. Rootless overlayfs exists (with
user xattrs) but systemd-nspawn itself requires root for most of its
functionality. This is a fundamental architectural constraint, not a
missing feature.

**Host network sharing by default.** Simplicity for development containers.
No port mapping to remember, no bridge to configure. The user opts into
network isolation explicitly.

**User namespace isolation opt-in.** `--userns` is available but off by
default. On kernel 6.6+, `--private-users=pick --private-users-ownership=auto`
uses idmapped mounts with zero overhead and full systemd compatibility.
On older kernels, `auto` falls back to recursive chown, which is slower
but still functional.

**Full systemd in container.** This is the entire point of sdme: a real
systemd environment with journald, service management, and cgroup control.
This requires `CAP_SYS_ADMIN`, which in turn means a larger capability set
than application-only containers need.

### Genuine gaps relative to Docker/Podman defaults

**`CAP_SYS_ADMIN` retained.** Docker drops it by default. In an sdme
container, a root process has `CAP_SYS_ADMIN`, which gives it mount, cgroup,
and namespace manipulation capabilities. These are constrained by the PID
and mount namespaces, but `CAP_SYS_ADMIN` remains the most dangerous
capability to grant.

**No MAC confinement.** Neither AppArmor nor SELinux profiles are applied.
A process that escapes namespace isolation has no MAC layer to contain it.

**No `no_new_privs`.** Setuid binaries inside the container function
normally. A process running as a non-root user can escalate to root via
a setuid binary (e.g. `sudo`, `su`, `passwd`). This is by design for
interactive containers (you want `sudo` to work) but is a gap for
hardened deployments.

**Weaker seccomp profile.** nspawn's allowlist permits mount-related
syscalls that Docker blocks. A compromised process has access to more kernel
attack surface.

## 6. Attack Surface

### Process-level surface

sdme containers run a full systemd init system: PID 1 is systemd, with
journald, logind, dbus-daemon, and any enabled services. A typical container
has 10-20 processes at idle. Docker containers typically run a single
application process (PID 1).

More processes means more potential targets for exploitation, but also means
familiar operational tooling: `systemctl`, `journalctl`, `loginctl`.

The capability bounding set (26 capabilities including `CAP_SYS_ADMIN`)
gives container processes significant kernel interaction surface. Docker's
14-capability set is deliberately minimal.

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

With `--private-network` or `--pod`, the container is limited to its own
network namespace. Network-level attacks are confined to that namespace
(loopback only in a pod, or whatever connectivity is configured via veth/
bridge/zone).

### Host daemon exposure

sdme has no persistent daemon. There is no equivalent of Docker's
`containerd` socket, which is a well-known privilege escalation vector
(access to the Docker socket is effectively root access). sdme communicates
with systemd over the system D-Bus, which is already present and secured
by its own policy.

## 7. When to Use What

**sdme** is appropriate when:

- You want a full systemd environment (service management, journald, cgroups).
- You want disposable, ephemeral containers that boot in seconds.
- You want to avoid installing a container runtime daemon.
- You are comfortable with root-level operation.
- You are running trusted workloads, or you have applied the hardening
  measures in Section 8 (private networking, pod netns, resource limits).

**Docker or Podman** is appropriate when:

- You need defense-in-depth out of the box for untrusted workloads.
- You need rootless execution (especially Podman).
- You need OCI-compatible image building and distribution workflows.
- You need MAC confinement (AppArmor or SELinux).
- You operate in a multi-tenant environment.
- Compliance requirements specify specific isolation standards.

**Podman specifically** when:

- Rootless is a hard requirement.
- SELinux integration is needed.
- You want a daemonless runtime with Docker-compatible CLI.
- You need Kubernetes-style pod semantics with full external connectivity.

## 8. Hardening Recommendations

If you want to tighten isolation beyond sdme's defaults:

**Use `--userns`.** This enables user namespace isolation so that container
root maps to a high unprivileged UID on the host. A container escape no
longer gives the attacker host root access. On kernel 6.6+, overlayfs
supports idmapped mounts, making this zero-overhead. On older kernels,
`--private-users-ownership=auto` falls back to recursive chown on first
boot.

**Use `--private-network`.** This is the single most impactful change.
It gives the container its own network namespace, eliminating the largest
attack surface (shared host networking). Use `--port` for specific port
forwarding or `--network-zone` for controlled inter-container networking.

**Use `--pod` for inter-container communication.** Pods provide shared
localhost networking between containers without exposing any of them to the
host network. This is the recommended pattern for multi-container setups
(e.g. database + application).

**Apply resource limits.** Use `--memory`, `--cpus`, and `--cpu-weight`
to prevent a container from exhausting host resources. Without limits, a
container can consume all available memory and CPU.

**Keep systemd updated.** nspawn's seccomp filter and capability handling
evolve with systemd releases. Running a current systemd version ensures you
get the latest security fixes and improvements.

**Consider custom AppArmor or SELinux profiles.** While sdme does not ship
MAC profiles, you can apply them to the `sdme@.service` template unit.
For example, an AppArmor profile on the nspawn process would restrict what
the container can access even if it escapes namespace isolation. This
requires writing and maintaining the profile yourself.

**Use read-only bind mounts.** When sharing host directories with a
container (`-b`/`--bind`), append `:ro` unless the container genuinely
needs write access: `-b /data:/data:ro`.

## 9. Input Sanitization

sdme runs as root and handles untrusted input from the network (OCI
registries, URL downloads) and from the filesystem (tarballs, disk images).
The input sanitization measures (path traversal prevention, digest
validation, download size caps, umask enforcement, permission hardening)
are documented in [architecture.md, Section 14](architecture.md#14-security).
