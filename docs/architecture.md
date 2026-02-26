# sdme: Architecture and Design

**Alexandre Fiori, February 2026**

## 1. Introduction

sdme is a container manager for Linux. It runs on top of systemd-nspawn and
overlayfs, both already present on any modern systemd-based distribution.

No daemon, no runtime dependency beyond systemd itself. A single static binary
that manages overlayfs layering and drives systemd over D-Bus.

The project started as an experiment inspired by virtme-ng: what if you could
clone your running host system into an isolated container with a single command?
Overlayfs makes this nearly free: mount the host rootfs as a read-only lower
layer, give the container its own upper layer for writes, and you have a
full-featured Linux environment that shares the host's binaries but can't damage
the host's files. That was the seed.

From there it grew: importing rootfs from other distros, pulling OCI images from
Docker Hub, building custom root filesystems, managing container lifecycle
through D-Bus. Each piece turned out to be surprisingly tractable when you let
claude (and systemd) do the heavy lifting.

sdme is not an attempt to replace Podman, Docker, or any other container runtime.
Podman in particular has excellent systemd integration through Quadlet
(podman-systemd).
It is today's mature, full-featured approach to systemd-native container
management. sdme is a different thing entirely. It boots full systemd inside
nspawn containers, manages overlayfs layering directly, and bridges the OCI
ecosystem, all without a daemon and without pulling in a container runtime.

You get the operational model of systemd (journalctl, systemctl, resource
limits) with the packaging model of OCI (Docker Hub, GHCR, Quay).

The name stands for *Systemd Machine Editor*, and its pronunciation is left as
an exercise for the reader.

## 2. Dev Mode: Cloning Your Host

The foundational mode of sdme is what you get when you run `sdme new` with no
flags. It creates a container that is an overlayfs clone of your running host
system: same kernel, same binaries, same libraries, but with its own writable
layer so changes stay isolated.

```
  +------------------------------------------------------+
  |                    HOST SYSTEM                       |
  |  +--------+  +--------+  +------------------+        |
  |  | kernel |  | systemd|  | root filesystem  |        |
  |  |        |  |  D-Bus |  |       (/)        |        |
  |  +--------+  +----+---+  +--------+---------+        |
  |                   |               | overlayfs        |
  |        +----------+---------------+ (lower)          |
  |        |                          |                  |
  |  +-----+----------------+  +-----+----------------+  |
  |  |  container A         |  |  container B         |  |
  |  |  +----------------+  |  |  +----------------+  |  |
  |  |  |  systemd       |  |  |  |  systemd       |  |  |
  |  |  |  D-Bus         |  |  |  |  D-Bus         |  |  |
  |  |  +----------------+  |  |  +----------------+  |  |
  |  |  upper/ work/        |  |  upper/ work/        |  |
  |  |  merged/             |  |  merged/             |  |
  |  +----------------------+  +----------------------+  |
  +------------------------------------------------------+

  Note: /etc/systemd/system and /var/log are opaque
  by default -- the container sees empty directories
  there, not the host's units and logs.
```

Looks like this:

```
$ sudo sdme new
creating 'jerinhouma'
starting 'jerinhouma'
joining 'jerinhouma'
host rootfs container: joining as user 'fiorix' with opaque dirs /etc/systemd/system, /var/log
Connected to machine jerinhouma. Press ^] three times within 1s to exit session.
jerinhouma ~ $ systemctl status
● jerinhouma
    State: running
    Units: 185 loaded (incl. loaded aliases)
     Jobs: 0 queued
   Failed: 0 units
    Since: Thu 2026-02-26 01:15:38 GMT; 7s ago
  systemd: 257.9-0ubuntu2.1
...
```

Each container boots its own systemd instance inside the nspawn namespace. The
host's systemd manages the container as a service unit; the container's systemd
manages everything inside. Both talk to their own D-Bus, both write to their own
journal, but the container's writes land on the overlayfs upper layer and never
touch the host - well, except that they are stored on the host. This matters,
and the details are explained in Section 13.

**User identity preservation.** When sdme is run via `sudo` and the container
is a host-rootfs clone (no `-r` flag), it reads `$SUDO_USER` and joins the
container as that user rather than root. This is a convenience for landing on
your own machine as your own user: your own `$HOME`, dotfiles, shell, etc.
The behaviour is controlled by the `join_as_sudo_user` config setting (enabled
by default) and can be disabled with `sdme config set join_as_sudo_user no`.

**Opaque directories** are the key to making host clones usable. Without them,
the container would inherit the host's systemd units and try to start all the
same services. By default, sdme marks `/etc/systemd/system` and `/var/log` as
overlayfs-opaque (via the `trusted.overlay.opaque` xattr), making the container
see empty directories there. The host's units and logs are hidden; the container
starts clean.

**DNS** requires special treatment because containers share the host's network
namespace by default. The host's `systemd-resolved` already owns `127.0.0.53`,
so the container's copy would fail to bind. For imported rootfs, sdme masks
`systemd-resolved` directly in the rootfs during `sdme fs import`. For
host-rootfs containers (no `-r`), the mask goes in the overlayfs upper layer
during `create`. Either way, the mask is a symlink to `/dev/null` in
`/etc/systemd/system/`. This causes the container's NSS `resolve` module to
return UNAVAIL, falling through to the `dns` module which reads
`/etc/resolv.conf`. A placeholder regular file is written there so
`systemd-nspawn --resolv-conf=auto` can populate it at boot.

## 3. The Catalogue

Everything sdme knows lives under `/var/lib/sdme` (the default `datadir`,
configurable via `sdme config set datadir <path>`):

```
  /var/lib/sdme/
  |-- state/
  |   |-- container-a          # KEY=VALUE metadata
  |   +-- container-b
  |-- containers/
  |   |-- container-a/
  |   |   |-- upper/           # CoW writes
  |   |   |-- work/            # overlayfs workdir
  |   |   |-- merged/          # mount point
  |   |   +-- shared/          # host <-> container exchange
  |   +-- container-b/
  |       +-- ...
  +-- fs/
      |-- ubuntu/              # imported rootfs
      |-- fedora/
      |-- nginx/               # OCI app rootfs
      +-- .ubuntu.meta         # distro metadata
```

**State files** are flat KEY=VALUE text files under `state/`. They record
everything about a container: name, rootfs, creation timestamp, resource limits,
network configuration, bind mounts, environment variables, opaque directories.
The format is intentionally simple: readable with `cat`, parseable with `grep`,
editable with `sed` in an emergency. The `State` type in the code uses a
`BTreeMap<String, String>` for deterministic key ordering.

**Transactional operations** follow a staging pattern throughout sdme. Rootfs
imports write to a `.{name}.importing` staging directory, then do an atomic
`rename()` to the final path on success. If the import fails or is interrupted,
the staging directory is cleaned up, and if it's left behind (power failure,
OOM kill), the next import detects it and offers to clean up with `--force`.

**Health detection** in `sdme ps` checks that a container's expected directories
actually exist and that its rootfs (if specified) is present. A container whose
rootfs has been removed shows as `broken`. OS detection reads
`/etc/os-release` from the rootfs to show distro names in the listing.

**Conflict detection** checks three places before accepting a name: the sdme
state directory, `/var/lib/machines/` (systemd's own machine directory), and the
list of currently registered machines via D-Bus. This prevents collisions with
both sdme containers and any other nspawn machines on the system.

## 4. Container Lifecycle

```
  create --> start --> join/exec --> stop --> rm
    |           |                     |       |
    |     install/update         graceful: KillMachine SIGRTMIN+4
    |     template unit          --term:   TerminateMachine
    |     StartUnit (D-Bus)      --kill:   KillMachine SIGKILL
    |     wait for boot
    |
    +-- mkdir upper/ work/ merged/ shared/
    +-- mask systemd-resolved (host-rootfs only; imported rootfs patched at import)
    +-- write /etc/resolv.conf placeholder
    +-- set opaque dirs (xattr)
    +-- write state file
```

**create** builds the overlayfs directory structure, sets up DNS, applies opaque
directories, validates the umask (a restrictive umask would make overlayfs files
inaccessible to non-root services like dbus-daemon), and writes the state file.
It does not start the container.

**start** installs (or updates) a systemd template unit and per-container
drop-in, then calls `StartUnit` over D-Bus. After the unit starts, sdme waits
for the container to reach the `running` state by subscribing to `machined`
D-Bus signals and polling the machine state. The boot timeout defaults to 60
seconds and is configurable.

**join** and **exec** spawn `machinectl shell` as a child process and forward
its exit status. This was a deliberate choice: machinectl handles the namespace
entry, PAM session setup, and environment correctly, and reimplementing that
logic in Rust would buy nothing. Spawning (rather than exec'ing) keeps sdme
alive so it can inspect the exit code and clean up on failure (particularly
important for `sdme new`, which removes the container if the join fails). The
balance struck is: use D-Bus where it gives us programmatic control (start,
stop, status queries), shell out where the existing tool already does the job
well (interactive shell sessions, running commands).

**stop** has three tiers: graceful (default) sends `SIGRTMIN+4` to the container
leader via `KillMachine` (90s timeout), `--term` calls `TerminateMachine` which
sends SIGTERM to the nspawn process (30s timeout), and `--kill` sends SIGKILL to
all processes via `KillMachine` (15s timeout). Multiple containers can be stopped
in one invocation.

**rm** stops the container if running, removes the state file, and deletes the
container's directories. The `make_removable()` helper recursively fixes
permissions before deletion, since containers can create files owned by arbitrary UIDs
with restrictive modes, and `remove_dir_all()` would fail without this.

**Boot failure cleanup** differs between `sdme new` and `sdme start`. If
`sdme new` fails to boot or join the container (or is interrupted with Ctrl+C),
it removes the just-created container entirely (the user never asked for a
stopped container, they asked for a running one). If `sdme start` fails, it
stops the container but preserves it on disk for debugging.

## 5. Container Names

When you don't specify a name, sdme generates one from a wordlist of 200
Tupi-Guarani words and variations. The choice is an easter egg, a nod to the
indigenous languages of Brazil - our roots!

Name generation shuffles the wordlist (Fisher-Yates, seeded from
`/dev/urandom`), checks each candidate against the three-way conflict detection
(state files, `/var/lib/machines/`, registered machines), and returns the first
unused name. If all 200 base words are taken, it falls back to vowel mutations:
consonants stay fixed while vowels are randomly substituted, producing names
that sound like plausible Tupi-Guarani words but don't appear in the original
list. Up to 200 mutation attempts before giving up. Sorry folks yet I digress,
cuz thinking like MF-DOOM makes me handle of these tech things just like chess.

## 6. The fs Subsystem: Managing Root Filesystems

The `fs` subsystem manages the catalogue of root filesystems that containers
are built from. Each rootfs is a plain directory under `/var/lib/sdme/fs/`
containing a complete Linux filesystem tree. Containers reference them by name.

### Import sources

`sdme fs import` auto-detects the source type by probing in order:

- **URL** -- `http://` or `https://` prefix. Downloads the file, then extracts
  as a tarball.
- **OCI registry** -- looks like a domain with a path
  (e.g. `docker.io/ubuntu:24.04`, `quay.io/fedora/fedora`). Pulled via the
  OCI Distribution Spec.
- **Directory** -- path is a directory. Copied with `copy_tree()` preserving
  ownership, permissions, xattrs, and special files.
- **QCOW2 image** -- magic bytes `QFI\xfb` at the start of the file. Mounted
  read-only via `qemu-nbd`, then copied with `copy_tree()`.
- **Raw disk image** -- MBR/GPT signature or `.raw`/`.img` extension. Same
  `qemu-nbd` path as QCOW2.
- **Tarball** -- default fallback for any other file. Extracted with native
  Rust crates; compression is detected from magic bytes, not the file name.

### The hard parts

**Permissions and ownership** must be preserved exactly. A rootfs contains files
owned by dozens of system UIDs (root, messagebus, systemd-network, nobody, etc.)
with specific modes. The `copy_tree()` function uses `lchown()` for ownership,
`chmod()` for permissions, and `utimensat()` with nanosecond precision for
timestamps. All operations use `l`-prefixed variants (lstat, lchown, lgetxattr)
to avoid following symlinks.

**Extended attributes** carry security and filesystem metadata. `copy_xattrs()`
lists and copies all xattrs except `security.selinux` (which doesn't transfer
meaningfully between filesystems). The overlayfs `trusted.overlay.opaque` xattr
is preserved when present.

**Special files** (block devices, character devices, FIFOs, and Unix sockets)
are recreated with `mknod()` and `mkfifo()` using the original mode and device
numbers. This matters for rootfs that include `/dev/null`, `/dev/zero`, and
friends.

**Compression auto-detection** uses magic bytes rather than file extensions.
The first few bytes of a file reveal its compression format:

| Magic bytes         | Format |
|---------------------|--------|
| `1f 8b`             | gzip   |
| `BZh`               | bzip2  |
| `fd 37 7a 58 5a 00` | xz     |
| `28 b5 2f fd`       | zstd   |

This means `sdme fs import ubuntu rootfs.tar.zst` works even if the file is
named `rootfs.tar`, because the content, not the name, determines the decompressor.

**Systemd detection** runs after import. If the rootfs doesn't contain systemd
and dbus (both required for nspawn containers), sdme can install them
automatically: it detects the distro family from `/etc/os-release` and runs the
appropriate package manager (`apt`, `dnf`) in a chroot. The `--install-packages`
flag controls this: `auto` prompts interactively, `yes` always installs, `no`
refuses if systemd is absent.

**Rootfs patching** runs after systemd detection. Even when systemd is present,
sdme patches the rootfs for nspawn compatibility: `systemd-resolved` is masked
(containers share the host's network namespace and cannot bind 127.0.0.53),
`systemd-logind` is unmasked if masked (some OCI images like CentOS/AlmaLinux
mask it, but `machinectl shell` requires logind), and missing packages needed by
`machinectl shell` (e.g. `util-linux` and `pam` on RHEL-family, which provide
`/etc/pam.d/login`) are installed via chroot. These patches are applied directly
to the rootfs so all containers created from it inherit a working environment
without overlayfs-level fixups.

**Staging areas and atomic operations** ensure that a failed import doesn't
leave a half-written rootfs. The staging directory `.{name}.importing` is
renamed to the final location only on complete success. If sdme finds a leftover
staging directory on the next run, it reports it and the `--force` flag cleans
it up.

**Cooperative Ctrl+C** runs throughout the import pipeline. A global
`INTERRUPTED` flag is set by a POSIX signal handler (installed with
`sigaction`, deliberately without `SA_RESTART` so blocking reads return
`EINTR`). The import loop checks this flag between operations, allowing clean
cancellation of multi-gigabyte downloads and extractions.

## 7. fs build: Building Root Filesystems

`sdme fs build` takes a Dockerfile-like config and produces a new rootfs:

```
FROM ubuntu
COPY ./my-app /opt/my-app
RUN apt-get update && apt-get install -y libssl3
RUN systemctl enable my-app.service
```

The build engine creates a staging container from the FROM rootfs, then
processes operations sequentially. The key insight is that COPY and RUN have
different requirements:

- **COPY** writes directly to the overlayfs upper layer while the container is
  stopped. This is a filesystem operation; no running container needed.
- **RUN** executes a command inside the container via `machinectl shell`. The
  container must be running.

The engine starts and stops the container as needed: if it encounters a RUN
after a COPY, it starts the container; if it encounters a COPY after a RUN, it
stops it first. This means a config with alternating COPY and RUN operations
will start and stop the container multiple times, but in practice most configs
group their COPYs at the top and RUNs at the bottom.

**Path sanitisation** rejects COPY destinations under directories that systemd
mounts tmpfs over at boot (`/tmp`, `/run`, `/dev/shm`). Files written to the
overlayfs upper layer in these locations would be hidden by the tmpfs mount when
the container starts, a silent data loss that's hard to debug. Destinations
under overlayfs-opaque directories are also rejected. Errors include the config
file path and line number for easy debugging.

After all operations complete, the engine mounts the overlayfs manually (the
container is stopped), copies the merged view to a staging rootfs directory, and
does an atomic rename to the final location. The staging container is cleaned up
regardless of success or failure.

## 8. OCI Integration

> *The goal isn't to replace Docker or Podman. It's to give systemd-nspawn users
> a way to tap into the OCI ecosystem without leaving the systemd operational
> model.*

### Learning the spec

OCI registry pulling implements the OCI Distribution Spec directly, no shelling
out. The flow is: parse the image reference, probe the registry for auth
requirements, obtain a bearer token if needed, fetch the manifest (resolving
manifest lists by architecture), then download and extract layers in order.

Layer extraction handles OCI whiteout markers: `.wh.<name>` deletes a file from
the previous layer, `.wh..wh..opq` clears an entire directory. Tar paths are
sanitised (leading `/` is stripped and `..` components are rejected) to prevent
path traversal escaping the destination directory.

### Two modes: base OS and application

When importing an OCI image, sdme classifies it as either a **base OS image** or
an **application image** based on the image config: presence of an entrypoint,
non-shell default command, or exposed ports indicate an application.

**Base OS import** (ubuntu, debian, fedora) is straightforward: extract the
rootfs and install systemd if missing. The result is a first-class sdme rootfs.

**Application import** produces what sdme calls a *capsule*: a copy of a base
OS rootfs with the OCI application rootfs placed under `/oci/root` and a
generated systemd service unit that chroots into it.

```
  +------------------------------------------------------+
  |                     HOST SYSTEM                      |
  |         kernel . systemd . D-Bus . machined          |
  |                        |                             |
  |           sdme@name.service (nspawn)                 |
  |      +------------------+----------------------+     |
  |      |          CAPSULE (container)            |     |
  |      |                                         |     |
  |      |  systemd . D-Bus . journald             |     |
  |      |                                         |     |
  |      |  +-----------------------------------+  |     |
  |      |  |  sdme-oci-app.service             |  |     |
  |      |  |  RootDirectory=/oci/root          |  |     |
  |      |  |                                   |  |     |
  |      |  |  +-----------------------------+  |  |     |
  |      |  |  |     OCI process             |  |  |     |
  |      |  |  |   (nginx, mysql, ...)       |  |  |     |
  |      |  |  +-----------------------------+  |  |     |
  |      |  +-----------------------------------+  |     |
  |      |                                         |     |
  |      |  /oci/env     -- environment vars       |     |
  |      |  /oci/ports   -- exposed ports          |     |
  |      |  /oci/volumes -- declared volumes       |     |
  |      +-----------------------------------------+     |
  +------------------------------------------------------+
```

The generated `sdme-oci-app.service` unit uses `RootDirectory=/oci/root` to
chroot the process, `MountAPIVFS=yes` to provide `/proc`, `/sys`, `/dev`, and
`EnvironmentFile=-/oci/env` to load the image's environment variables. The unit
is enabled via symlink in `multi-user.target.wants/` so it starts automatically
when the container boots.

The capsule model means OCI applications get the full systemd operational model
for free: `journalctl -u sdme-oci-app` for logs, `systemctl restart` for
restarts, cgroup resource limits from the host. The application doesn't know or
care that it's inside an nspawn container; it sees a chroot with API
filesystems, exactly what it expects.

### Future direction

At this point this is all very exploratory. This journey is 1% complete.

**Important caveat.** OCI capsules (application images) currently have significant
gaps. Bind mounts (`-b`) and environment variables (`-e`) set on the container
operate at the nspawn level, not inside the `RootDirectory=/oci/root` chroot
where the application actually runs.

OCI-declared volumes are saved to `/oci/volumes` as metadata only and are not
mounted. OCI-declared ports are saved to `/oci/ports` but are not automatically
forwarded; the user must manually pass `--port` when creating the container.

In short: the plumbing between the outer nspawn container and the inner chroot
is incomplete. This is a known limitation and the TODOs live in the generated
`sdme-oci-app.service` unit file.

## 9. Networking

By default, containers share the host's network namespace: same interfaces, same
addresses, same ports. This is the simplest mode and what you get with `sdme new`
out of the box.

For isolation, `--private-network` gives the container its own network namespace
with no connectivity. The remaining network flags build on top of it and all
imply `--private-network` automatically:

- `--private-network`: isolated network namespace, no connectivity
- `--network-veth`: creates a virtual ethernet link between host and container
- `--network-bridge <name>`: connects the container's veth to a host bridge
- `--network-zone <name>`: joins a named zone for inter-container networking
- `--port / -p <HOST:CONTAINER[/PROTO]>`: forwards a port (TCP by default, repeatable)

These flags are available on both `sdme create` and `sdme new`. They compose
freely: you can combine `--network-zone` with `--port`, or use `--network-bridge`
with `--network-veth`. Port forwarding requires a private network namespace
because systemd-nspawn's `--port` flag only works when host and container have
separate network stacks.

Under the hood, each flag translates directly to a systemd-nspawn argument.
The network configuration is persisted in the container's state file
(`PRIVATE_NETWORK`, `NETWORK_VETH`, `NETWORK_BRIDGE`, `NETWORK_ZONE`, `PORTS`)
and written into the per-container nspawn drop-in at start time.

Bridge and zone names are validated (alphanumeric, hyphens, underscores). Port
specs are validated for format (`HOST:CONTAINER[/PROTO]`) and range (1-65535).

## 10. Resource Limits

sdme exposes three cgroup-based resource controls:

| Flag                      | systemd property | Example                                 |
|---------------------------|------------------|-----------------------------------------|
| `--memory <size>`         | `MemoryMax=`     | `--memory 2G`                           |
| `--cpus <count>`          | `CPUQuota=`      | `--cpus 0.5` (50%), `--cpus 2` (200%)   |
| `--cpu-weight <1-10000>`  | `CPUWeight=`     | `--cpu-weight 100`                      |

These flags are available on `sdme create`, `sdme new`, and `sdme set`. They
are applied via a systemd drop-in file (`limits.conf`) installed alongside the
container's service unit. A `daemon-reload` is triggered when the drop-in changes.

`sdme set` replaces all limits at once: flags not specified are removed. If the
container is running, sdme prints a note that a restart is needed for the new
limits to take effect.

Memory values accept K/M/G/T suffixes. CPU count is a positive float where `1`
means one full core and `0.5` means half a core (converted to systemd's
`CPUQuota=` percentage internally). CPU weight is an integer from 1 to 10000,
controlling relative scheduling priority when CPUs are contended.

## 11. Bind Mounts and Environment Variables

Custom bind mounts and environment variables are set at creation time with
`-b`/`--bind` and `-e`/`--env`, available on both `sdme create` and `sdme new`.

**Bind mounts** use the format `HOST:CONTAINER[:ro]`. Read-write is the default;
append `:ro` for read-only. Both paths must be absolute with no `..` components,
and the host path must exist at creation time. At start time, each bind becomes
a `--bind=` or `--bind-ro=` argument to systemd-nspawn.

**Environment variables** use the format `KEY=VALUE`. Keys must be alphanumeric
or underscore (no leading digit). At start time, each variable becomes a
`--setenv=KEY=VALUE` argument to systemd-nspawn.

Both are stored in the container's state file (`BINDS=` and `ENVS=`,
pipe-separated) and reconstituted into nspawn arguments on every start.

## 12. Configuration

sdme stores its settings in a TOML file at `~/.config/sdme/sdmerc`:

| Setting                    | Default                        | Description                                                            |
|----------------------------|--------------------------------|------------------------------------------------------------------------|
| `interactive`              | `true`                         | Enable interactive prompts                                             |
| `datadir`                  | `/var/lib/sdme`                | Root directory for all container and rootfs data                       |
| `boot_timeout`             | `60`                           | Seconds to wait for container boot before giving up                    |
| `join_as_sudo_user`        | `true`                         | Join host-rootfs containers as `$SUDO_USER` instead of root            |
| `host_rootfs_opaque_dirs`  | `/etc/systemd/system,/var/log` | Default opaque dirs for host-rootfs containers (empty string disables) |

Settings are read with `sdme config get` and written with `sdme config set <key> <value>`.

**Sudo interplay.** Since sdme runs as root via `sudo`, the config file lookup
checks whether `$SUDO_USER` is set to a non-root user. If so, and if that user's
`~/.config/sdme/sdmerc` exists, it is used instead of root's config. This means
the invoking user's preferences are respected without requiring the config to live
under `/root`. An explicit `-c`/`--config` flag overrides all resolution logic.

Config files are written with mode `0600` and directories with mode `0700`.

## 13. Security

sdme runs as root and handles untrusted input: tarballs from the internet, OCI
images from public registries, QCOW2 disk images from unknown sources. Several
hardening measures are in place:

**Path traversal prevention.** OCI layer tar paths are sanitised before
extraction: `..` components are rejected and leading `/` is stripped. Whiteout
marker handling verifies (via `canonicalize()`) that the target path stays
within the destination directory before deleting anything.

**Digest validation.** OCI blob digests (`sha256:abc123...`) are validated for
safe characters (alphanumeric and hex only) and correct length (64 chars for
SHA-256, 128 for SHA-512) before being used to construct filesystem paths. A
malicious manifest cannot use the digest field for directory traversal.

**Download size cap.** URL downloads are capped at 50 GiB (`MAX_DOWNLOAD_SIZE`),
checked during streaming. A malicious or misbehaving server cannot fill the disk
by sending an unbounded response.

**Rootfs name validation.** The `-r`/`--fs` parameter (on `create` and `new`)
is validated with `validate_name()` (alphanumeric, hyphens, no leading/trailing
hyphens, no `..`) before being used to construct filesystem paths.

**Opaque directory validation.** Paths must be absolute, contain no `..`
components, no empty strings, no duplicates. Normalised before storage.

**Permission hardening.** Config files are written with mode `0o600`, config
directories with `0o700`. Overlayfs work directories get mode `0o700`.

**Umask enforcement.** Container creation refuses to proceed if the process
umask strips read or execute from "other" (`umask & 005 != 0`). A restrictive
umask would make overlayfs upper-layer files inaccessible to non-root services
like dbus-daemon, preventing container boot. This actually happened during
development when setting umask to 007 before the `sdme create` command, would
result in `sdme start` mysteriously misbehaving.

If you find a way to escape a container, traverse a path, or corrupt the host
filesystem through sdme, please open an issue.

## 14. Reliability

Multi-step operations in sdme are designed to fail cleanly rather than leave
broken state behind.

**Transactional imports** use a staging directory (`.{name}.importing`) that is
atomically renamed on success. Partial imports are either cleaned up immediately
or detected and reported on the next run.

**Cooperative interrupt handling** uses a global `AtomicBool` flag set by a
POSIX `SIGINT` handler. The handler is installed without `SA_RESTART`, so
blocking system calls (file reads, network I/O) return `EINTR` immediately.
Import loops, boot-wait loops, and build operations check the flag between
steps, allowing Ctrl+C to cancel cleanly at any point. The handler also
restores the default `SIGINT` disposition after the first press, so a second
Ctrl+C force-kills the process. This covers cases where Rust's stdlib retries
`poll()`/`connect()` on EINTR, preventing cooperative cancellation during
blocked DNS resolution or TCP connection attempts.

**Boot failure cleanup** differs by intent: `sdme new` removes the container on
boot or join failure (the user wanted a running container, not a broken one),
while `sdme start` (from previous `sdme create`) preserves it for debugging.

**Health checks** in `sdme ps` detect containers with missing directories or
missing rootfs and report them as `broken` rather than crashing or silently
hiding them.

**Build failure cleanup** removes the staging container and any partial rootfs
on error, regardless of which build step failed.

If you find a way to leave sdme's state inconsistent (a container that can't be
listed, removed, or recovered), please open an issue.
