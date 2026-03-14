# sdme: Container Isolation and Security

**Alexandre Fiori, March 2026**

This document covers sdme's security model across three layers:
nspawn container isolation (Part 1), OCI workload isolation inside
containers (Part 2), and Kubernetes compatibility security (Part 3).
For sdme's security implementation details (capabilities, seccomp,
AppArmor, `--hardened`, `--strict`), see
[architecture.md, Section 15](architecture.md#15-security).

---

# Part 1: nspawn Container Security

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
(`sdme-oci-{name}.service`), not as a standalone process. See Part 2 for
details on how OCI workloads are isolated within the container.

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
Namespace  sdme (nspawn)            Docker (rootful)     Podman (rootless)
---------  -----------------------  -------------------  --------------------
PID        Always                   Always               Always
IPC        Always                   Always               Always
UTS        Always                   Always               Always
Mount      Always                   Always               Always
Network    Optional (host default)  Yes (bridge)         Yes (slirp4/pasta)
User       Optional                 Optional             Yes (default)
Cgroup     Partial (Delegate=yes)   Yes                  Yes
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
[architecture.md, Section 15](architecture.md#15-security) for the full
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

See [architecture.md, Section 15](architecture.md#15-security) for
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

See [architecture.md, Section 15](architecture.md#15-security) for the
`sdme-default` profile details and installation instructions.

## 7. Privilege Escalation Prevention

**Docker**: `no_new_privs` enabled by default. Setuid binaries inside the
container cannot escalate privileges.

**Podman**: enabled by default.

**sdme**: off by default because interactive containers typically want
`sudo`/`su` to work. Enabled by `--no-new-privileges`, `--hardened`,
or `--strict`.

All three provide read-only rootfs as an opt-in flag (`--read-only`).

See [architecture.md, Section 15](architecture.md#15-security) for
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

## 10. Hardening Tiers

sdme provides two convenience flags (`--hardened` and `--strict`) that
bundle multiple security layers. See
[architecture.md, Section 15](architecture.md#15-security) for full
details on what each flag enables and its effects on host-rootfs
containers.

### sdme hardening tiers

```
Mechanism            Default   --hardened   --strict
-------------------  --------  -----------  ----------
User namespace       No        Yes          Yes
Private network      No        Yes          Yes
no_new_privs         No        Yes          Yes
Caps retained        26        23           14
Seccomp (extra)      None      None         4 deny groups
AppArmor             None      None         sdme-default
Read-only rootfs     No        No           No
```

### How `--hardened` compares to Docker/Podman defaults

`--hardened` covers user namespace isolation, network isolation,
`no_new_privs`, and capability reduction. It drops 4 capabilities
(3 from the active set; `CAP_SYS_RAWIO` is preventive since nspawn
does not grant it by default), leaving 23 retained. The remaining
gaps versus Docker/Podman defaults are:

- **No default MAC confinement.** Docker ships a default AppArmor profile.
  sdme supports `--apparmor-profile` but `--hardened` does not set one.
- **Less restrictive seccomp baseline.** nspawn's allowlist permits
  `@mount` and more syscall groups than Docker's OCI default profile.
- **More capabilities retained.** Even after `--hardened` drops 4
  capabilities, 23 remain (including `CAP_SYS_ADMIN`), compared to
  Docker's ~14.

These gaps are inherent to running a full init system inside the container.
For maximum restriction, use `--strict`.

### `--strict` vs Docker defaults

```
Mechanism              sdme --strict             Docker default
---------------------  ------------------------  ----------------------
User namespace         Yes                       Optional
Network namespace      Yes (loopback only)       Yes (bridge)
no_new_privs           Yes                       Yes
Retained caps          14 (Docker's set, minus   ~14
                       NET_RAW, plus SYS_ADMIN)
Seccomp                nspawn baseline + 4 deny  OCI default (~44 deny)
AppArmor               sdme-default              docker-default
CAP_SYS_ADMIN          Yes (for systemd)         No
Init in container      Full systemd              Single process
```

The one remaining difference is `CAP_SYS_ADMIN` and the `@mount` syscall
group, both required for the full init model. sdme's security philosophy
is that this is an acceptable trade-off for the operational benefits it
provides (see Section 1).

## 11. Isolation Summary

```
Mechanism          sdme             Docker           Podman
-----------------  ---------------  ---------------  ---------------
PID namespace      Yes              Yes              Yes
IPC namespace      Yes              Yes              Yes
UTS namespace      Yes              Yes              Yes
Mount namespace    Yes              Yes              Yes
Network ns         Optional         Yes (bridge)     Yes (slirp4pasta)
User ns            Optional         Optional         Yes (default)
Cgroup ns          Partial          Yes              Yes
Capabilities       26 default       ~14              ~14
Seccomp            nspawn baseline  OCI default      OCI default
AppArmor           Optional         Default profile  Where available
SELinux            None             svirt labels     Strong
no_new_privs       Optional         Yes (default)    Yes (default)
Read-only rootfs   Optional         Optional         Optional
Rootless           No (root-only)   Optional         Default
Daemon             None             containerd       None
Init in container  Full systemd     Optional --init  Optional --init
```

Each "Optional" cell means the feature is available but not on by
default. For sdme, `--strict` enables all security layers
simultaneously. Individual flags: `--private-network` or `--hardened`
for network namespace, `--userns` or `--hardened` for user namespace,
`--no-new-privileges` or `--hardened` for no_new_privs, `--read-only`
for read-only rootfs, `--apparmor-profile` for AppArmor, and
`--system-call-filter` for additional seccomp rules.

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

---

# Part 2: OCI Workload Security

## 13. OCI App Isolation Architecture

OCI applications run inside nspawn containers as systemd services
(`sdme-oci-{name}.service`) with `RootDirectory=/oci/apps/{name}/root`.
The isolation is layered:

```
nspawn container
  systemd, D-Bus, journald
  sdme-oci-{name}.service
    RootDirectory chroot (/oci/apps/{name}/root)
      isolate binary
        PID namespace (unshare CLONE_NEWPID)
        IPC namespace (unshare CLONE_NEWIPC)
        /proc remount (MS_NOSUID|MS_NODEV|MS_NOEXEC)
        drop CAP_SYS_ADMIN from bounding set
        drop privileges (setgroups/setgid/setuid for non-root)
          application process
```

The `isolate` binary is a static ELF (under 2 KiB, no libc, raw
syscalls) written to `/.sdme-isolate` inside the OCI root at import
time. It is used for ALL OCI apps, both root and non-root:

- **All apps**: PID namespace, IPC namespace, /proc remount,
  `CAP_SYS_ADMIN` drop
- **Non-root apps**: additionally drops privileges via
  `setgroups`/`setgid`/`setuid`

See [architecture.md, Section 8](architecture.md#8-oci-integration)
and [architecture.md, Section 8](architecture.md#8-oci-integration) for
full details on the isolate binary.

## 14. Systemd Hardening Directives

The following directives are always applied to OCI app service units.
These are not optional and do not depend on `--hardened` or `--strict`.

```
Directive                  Effect
-------------------------  ----------------------------------
CapabilityBoundingSet      15 caps (see below)
NoNewPrivileges=yes        Block setuid/file-cap escalation
ProtectKernelModules=yes   Deny /usr/lib/modules access
ProtectKernelLogs=yes      Deny /dev/kmsg and /proc/kmsg
ProtectControlGroups=yes   Read-only /sys/fs/cgroup
ProtectClock=yes           Block clock_settime, adjtimex
RestrictSUIDSGID=yes       Block setuid/setgid bit creation
LockPersonality=yes        Lock execution domain
ProtectProc=invisible      Hide other users' processes
ProcSubset=pid             Expose only /proc/pid/ entries
```

The 15 capabilities in the bounding set are Docker's 14 plus
`CAP_SYS_ADMIN`:

```
CAP_AUDIT_WRITE      CAP_CHOWN            CAP_DAC_OVERRIDE
CAP_FOWNER           CAP_FSETID           CAP_KILL
CAP_MKNOD            CAP_NET_BIND_SERVICE CAP_NET_RAW
CAP_SETFCAP          CAP_SETGID           CAP_SETPCAP
CAP_SETUID           CAP_SYS_ADMIN        CAP_SYS_CHROOT
```

`CAP_SYS_ADMIN` is kept in the bounding set because `isolate` needs it
for `unshare()` and `mount()`. The `isolate` binary drops it via
`prctl(PR_CAPBSET_DROP)` before exec'ing the workload. The application
effectively runs with Docker's 14 caps (or zero effective caps for
non-root users).

Source: `src/security.rs` (`OCI_DEFAULT_CAPS`)

## 15. Effective Workload Isolation

After all layers (nspawn + RootDirectory + isolate + systemd directives),
the application process sees:

- **Own PID namespace**: PID 1 is isolate's child; cannot see sibling
  services or the container's systemd
- **Own IPC namespace**: cannot access the container's IPC objects
  (shared memory, semaphores, message queues)
- **Shared network namespace**: shares the nspawn container's network
  (or a pod's netns if `--pod`/`--oci-pod` is configured)
- **Shared user namespace**: shares the nspawn container's user
  namespace (remapped if `--userns` is active)
- **Chrooted filesystem**: confined to `/oci/apps/{name}/root`; cannot
  see the container's filesystem or other OCI apps
- **CAP_SYS_ADMIN dropped**: cannot mount, unshare, or manipulate
  namespaces
- **NoNewPrivileges active**: cannot escalate via setuid binaries or
  file capabilities
- **/proc filtered**: sees only its own PID subtree
  (`ProtectProc=invisible`, `ProcSubset=pid`)

## 16. OCI Workload Comparison with Docker/Podman

```
Mechanism              sdme OCI app       Docker         Podman
---------------------  -----------------  -------------  -------------
PID namespace          Yes (isolate)      Yes            Yes
IPC namespace          Yes (isolate)      Yes            Yes
Network namespace      Shared w/nspawn    Yes            Yes
User namespace         Shared w/nspawn    Optional       Yes (default)
Filesystem isolation   RootDirectory      pivot_root     pivot_root
Capabilities           14 effective       ~14            ~14
CAP_SYS_ADMIN          Dropped by isolate No             No
no_new_privs           Yes                Yes            Yes
Seccomp                nspawn baseline    OCI default    OCI default
/proc visibility       PID subset only    Default        Default
Kernel protection      Multiple dirs      Default        Default
```

### Key differences

- sdme OCI apps get comparable workload isolation to Docker; the
  capability set is effectively the same after `isolate` drops
  `CAP_SYS_ADMIN`.
- The seccomp baseline is still nspawn's (less restrictive than
  Docker's OCI default), but the application cannot leverage most
  allowed syscalls due to capability restrictions.
- PID/IPC isolation comes from `isolate` (not from the container
  runtime), which creates namespaces via `unshare()` before exec.
- Network isolation depends on the nspawn container's configuration
  (host, private, or pod).
- `/proc` visibility is more restricted in sdme: `ProtectProc=invisible`
  and `ProcSubset=pid` hide other processes and non-PID /proc entries,
  while Docker exposes the full /proc by default.

---

# Part 3: Kube Security

## 17. Kube Security Model Overview

Kube pods are a single nspawn container with multiple OCI app services.
All apps get the same hardening from Part 2 (isolate binary, systemd
directives). All apps share the nspawn container's network namespace
and can communicate via localhost. Each app gets its own PID/IPC
namespace and `RootDirectory` chroot via `isolate`.

The security model is additive: nspawn container isolation (Part 1)
plus OCI workload isolation (Part 2) plus kube-specific features
(this section).

## 18. Pod-Level Security Context

Kubernetes `securityContext` fields supported at the pod level:

```
Field           Supported  Enforcement
--------------  ---------  --------------------------------
runAsUser       Yes        Passed to isolate as uid argument
runAsGroup      Yes        Passed to isolate as gid argument
runAsNonRoot    Yes        Validated at create time (fails
                           if runAsUser is 0 or unset)
```

Per-container `securityContext` is not supported; only pod-level.
The `runAsUser`/`runAsGroup` values are passed to the `isolate` binary,
which performs the privilege drop via raw syscalls (`setgroups`,
`setgid`, `setuid`) before exec'ing the workload.

## 19. Secrets and ConfigMaps

Security properties of the kube secret and configmap stores:

**Secrets:**
- Stored at `{datadir}/secrets/{name}/data/` on the host
- Directory permissions: 0700 (root-only access)
- File permissions: 0600 (root-only read/write)
- Not encrypted at rest

**ConfigMaps:**
- Stored at `{datadir}/configmaps/{name}/data/` on the host
- Directory permissions: 0755
- File permissions: 0644

**Key validation** (both secrets and configmaps):
- No empty keys
- No `/` or `..` in key names
- No keys starting with `.`

**Environment variable resolution:**
- `valueFrom` with `secretKeyRef` and `configMapKeyRef` are resolved
  at container creation time
- Values are baked into the environment file, not injected at runtime
- Changing a secret or configmap after creation does not affect running
  containers

Source: `src/kube/store.rs` (shared CRUD), `src/kube/secret.rs`
(0700/0600 permissions), `src/kube/configmap.rs` (0755/0644
permissions)

## 20. Kube vs OCI Differences

```
Feature               sdme OCI         sdme kube
--------------------  ---------------  -----------------
Apps per container    1                1 or more
Init containers      No               Yes
Volume sharing        No               Yes (emptyDir)
Security context      OCI User field   runAsUser/Group
Secrets/ConfigMaps    No               Yes
Resource limits       Via sdme set     Via K8s spec
Restart policy        systemd default  K8s mapping
Pod networking        Per-container    --pod / --oci-pod
```

## 21. Kube Limitations

- No `securityContext.privileged` support
- Seccomp `Localhost` profile type not supported (custom BPF profiles cannot be loaded via systemd's `SystemCallFilter`)
- No network policies
- No service accounts or RBAC
- Liveness probes parsed but not enforced at runtime
- No startup probes
- Secrets not encrypted at rest
