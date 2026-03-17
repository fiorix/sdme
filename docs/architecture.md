# sdme: Architecture and Design

**Alexandre Fiori, February 2026**

## 1. Introduction

sdme is a container manager for Linux. It runs on top of systemd-nspawn
and overlayfs, both already present on any modern systemd-based
distribution.

No daemon, no runtime dependency beyond systemd itself. A single static
binary that manages overlayfs layering and drives systemd over D-Bus.

The project started as an experiment inspired by virtme-ng: what if you
could clone your running host system into an isolated container with a
single command? Overlayfs makes this nearly free: mount the host rootfs
as a read-only lower layer, give the container its own upper layer for
writes, and you have a full-featured Linux environment that shares the
host's binaries but can't damage the host's files. That was the seed.

From there it grew: importing rootfs from other distros, pulling OCI
images from Docker Hub, building custom root filesystems, managing
container lifecycle through D-Bus. Each piece turned out to be
surprisingly tractable when you let claude (and systemd) do the heavy
lifting.

sdme is not an attempt to replace Podman, Docker, or any other container
runtime. Podman in particular has excellent systemd integration through
Quadlet (podman-systemd). It is today's mature, full-featured approach
to systemd-native container management. sdme is a different thing
entirely. It boots full systemd inside nspawn containers, manages
overlayfs layering directly, and bridges the OCI ecosystem, all without
a daemon and without pulling in a container runtime.

You get the operational model of systemd (journalctl, systemctl,
resource limits) with the packaging model of OCI (Docker Hub, GHCR,
Quay).

The name stands for *Systemd Machine Editor*, and its pronunciation is
left as an exercise for the reader.

## 2. Dev Mode: Cloning Your Host

The foundational mode of sdme is what you get when you run `sdme new`
with no flags. It creates a container that is an overlayfs clone of your
running host system: same kernel, same binaries, same libraries, but
with its own writable layer so changes stay isolated.

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
  by default: the container sees empty directories
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

Each container boots its own systemd instance inside the nspawn
namespace. The host's systemd manages the container as a service unit;
the container's systemd manages everything inside. Both talk to their
own D-Bus, both write to their own journal, but the container's writes
land on the overlayfs upper layer and never touch the host - well,
except that they are stored on the host. This matters, and the details
are explained in Section 15.

**User identity preservation.** When sdme is run via `sudo` and the
container is a host-rootfs clone (no `-r` flag), it reads `$SUDO_USER`
and joins the container as that user rather than root. This is a
convenience for landing on your own machine as your own user: your own
`$HOME`, dotfiles, shell, etc. The behaviour is controlled by the
`join_as_sudo_user` config setting (enabled by default) and can be
disabled with `sdme config set join_as_sudo_user no`.

**Opaque directories** are the key to making host clones usable.
Without them, the container would inherit the host's systemd units and
try to start all the same services. By default, sdme marks
`/etc/systemd/system` and `/var/log` as overlayfs-opaque (via the
`trusted.overlay.opaque` xattr), making the container see empty
directories there. The host's units and logs are hidden; the container
starts clean.

**DNS** requires special treatment because containers share the host's
network namespace by default. The host's `systemd-resolved` already
owns `127.0.0.53`, so the container's copy would fail to bind. For
imported rootfs, sdme masks `systemd-resolved` directly in the rootfs
during `sdme fs import`. For host-rootfs containers (no `-r`), the mask
goes in the overlayfs upper layer during `create`. Either way, the mask
is a symlink to `/dev/null` in `/etc/systemd/system/`. This causes the
container's NSS `resolve` module to return UNAVAIL, falling through to
the `dns` module which reads `/etc/resolv.conf`. A placeholder regular
file is written there so `systemd-nspawn --resolv-conf=auto` can
populate it at boot.

## 3. The Catalogue

Everything sdme knows lives under `/var/lib/sdme` (the default
`datadir`, configurable via `sdme config set datadir <path>`):

```
  /var/lib/sdme/
  |-- state/
  |   |-- container-a          # KEY=VALUE metadata
  |   +-- container-b
  |-- containers/
  |   |-- container-a/
  |   |   |-- upper/           # CoW writes
  |   |   |-- work/            # overlayfs workdir
  |   |   +-- merged/          # mount point
  |   +-- container-b/
  |       +-- ...
  |-- fs/
  |   |-- ubuntu/              # imported rootfs
  |   |-- fedora/
  |   |-- nginx/               # OCI app rootfs
  |   +-- .ubuntu.meta         # distro metadata
  |-- volumes/
  |   +-- my-container/
  |       |-- var-lib-mysql/   # OCI-declared volume data
  |       +-- data/
  +-- pods/
      +-- my-pod/
          +-- state            # KEY=VALUE pod state (CREATED=...)
```

Pod runtime state (volatile, recreated after reboot):

```
  /run/sdme/pods/
  +-- my-pod/
      +-- netns                # bind-mount of the pod's netns fd
```

**State files** are flat KEY=VALUE text files under `state/`. They
record everything about a container: name, rootfs, creation timestamp,
resource limits, network configuration, bind mounts, environment
variables, opaque directories, and pod membership (`POD` and/or
`OCI_POD`). The format is intentionally simple: readable with `cat`,
parseable with `grep`, editable with `sed` in an emergency. The `State`
type in the code uses a `BTreeMap<String, String>` for deterministic
key ordering.

**Transactional operations** follow a staging pattern throughout sdme.
Rootfs imports write to a `.{name}.importing` staging directory, then
do an atomic `rename()` to the final path on success. If the import
fails or is interrupted, the staging directory is cleaned up, and if
it's left behind (power failure, OOM kill), the next import detects it
and offers to clean up with `--force`.

**Health detection** in `sdme ps` checks that a container's expected
directories actually exist and that its rootfs (if specified) is
present. A container whose rootfs has been removed shows as `broken`.
OS detection uses a 5-step cascade to resolve the distro name shown
in the listing:

1. **merged/**: the overlayfs merged view (available when the
   container is running; reflects both the base rootfs and any
   upper-layer changes such as a distro upgrade).
2. **upper/**: the overlayfs upper layer alone (works when the
   container is stopped, since merged is not mounted).
3. **{datadir}/fs/{rootfs}/**: the imported rootfs on disk (for
   containers created with `-r`; useful when upper has no
   os-release of its own).
4. **/**: the host root filesystem (for host-rootfs containers
   that have no imported rootfs).
5. **"unknown"**: returned when none of the above paths contain
   an os-release file.

This cascade ensures that `sdme ps` always shows a meaningful OS
column regardless of whether the container is running, stopped, or
based on the host rootfs.

**Conflict detection** checks three places before accepting a name: the
sdme state directory, `/var/lib/machines/` (systemd's own machine
directory), and the list of currently registered machines via D-Bus.
This prevents collisions with both sdme containers and any other nspawn
machines on the system.

## 4. Container Lifecycle

```
  create --> start --> join/exec --> stop --> rm
    |           |                     |       |
    |     install/update         graceful: KillMachine SIGRTMIN+4
    |     template unit          --term:   TerminateMachine
    |     StartUnit (D-Bus)      --kill:   KillMachine SIGKILL
    |     wait for boot
    |
    +-- mkdir upper/ work/ merged/
    +-- mask systemd-resolved (host-rootfs only; imported rootfs patched at import)
    +-- write /etc/resolv.conf placeholder
    +-- set opaque dirs (xattr)
    +-- write state file
```

**create** builds the overlayfs directory structure, sets up DNS,
applies opaque directories, validates the umask (a restrictive umask
would make overlayfs files inaccessible to non-root services like
dbus-daemon), and writes the state file. It does not start the
container.

**start** installs (or updates) a systemd template unit and
per-container drop-in, then calls `StartUnit` over D-Bus. After the
unit starts, sdme waits for the container to reach the `running` state
by subscribing to `machined` D-Bus signals and polling the machine
state. The boot timeout defaults to 60 seconds and is configurable.

**join** and **exec** spawn `machinectl shell` as a child process and
forward its exit status. This was a deliberate choice: machinectl
handles the namespace entry, PAM session setup, and environment
correctly, and reimplementing that logic in Rust would buy nothing.
Spawning (rather than exec'ing) keeps sdme alive so it can inspect the
exit code and clean up on failure (particularly important for `sdme
new`, which removes the container if the join fails). The balance struck
is: use D-Bus where it gives us programmatic control (start, stop,
status queries), shell out where the existing tool already does the job
well (interactive shell sessions, running commands).

**stop** has three tiers: graceful (default) sends `SIGRTMIN+4` to the
container leader via `KillMachine` (90s timeout), `--term` calls
`TerminateMachine` which sends SIGTERM to the nspawn process (30s
timeout), and `--kill` sends SIGKILL to all processes via `KillMachine`
(15s timeout). Multiple containers can be stopped in one invocation.

**rm** stops the container if running, removes the state file, and
deletes the container's directories via `safe_remove_dir()`. This
function guards against stale bind mounts that can survive a host
crash or unclean shutdown:

1. `make_removable()` recursively fixes directory permissions to
   ensure owner read/write/execute (`0o700`), since containers can
   create files owned by arbitrary UIDs with restrictive modes.
2. `find_mounts_under()` reads `/proc/self/mountinfo` to discover
   any filesystems still mounted under the directory. Mount paths
   in mountinfo use kernel octal escapes (`\040` for space, etc.);
   `decode_mountinfo_path()` decodes them before comparison.
3. If mounts are found, they are sorted deepest-first by path
   length and unmounted with `umount -R`.
4. A second check verifies all mounts are gone. If any remain,
   `safe_remove_dir()` refuses to delete the directory and returns
   an error, preventing accidental removal of host filesystem
   contents that were visible through a stale bind mount.

**Boot failure cleanup** differs between `sdme new` and `sdme start`.
If `sdme new` fails to boot or join the container (or is interrupted
with Ctrl+C), it removes the just-created container entirely (the user
never asked for a stopped container, they asked for a running one). If
`sdme start` fails, it stops the container but preserves it on disk for
debugging.

## 5. Container Names

When you don't specify a name, sdme generates one from a wordlist of
200 Tupi-Guarani words and variations. The choice is an easter egg, a
nod to the indigenous languages of Brazil - our roots!

Name generation shuffles the wordlist (Fisher-Yates, seeded from
`/dev/urandom`), checks each candidate against the three-way conflict
detection (state files, `/var/lib/machines/`, registered machines), and
returns the first unused name. If all 200 base words are taken, it
falls back to vowel mutations: consonants stay fixed while vowels are
randomly substituted, producing names that sound like plausible
Tupi-Guarani words but don't appear in the original list. Up to 200
mutation attempts before giving up.

## 6. The fs Subsystem: Managing Root Filesystems

The `fs` subsystem manages the catalogue of root filesystems that
containers are built from. Each rootfs is a plain directory under
`/var/lib/sdme/fs/` containing a complete Linux filesystem tree.
Containers reference them by name.

### Import sources

`sdme fs import` auto-detects the source type by probing in order:

- **URL**: `http://` or `https://` prefix. Downloads the file, then
  extracts as a tarball.
- **OCI registry**: looks like a domain with a path
  (e.g. `docker.io/ubuntu:24.04`, `quay.io/fedora/fedora`). Pulled via
  the OCI Distribution Spec.
- **Directory**: path is a directory. Copied with `copy_tree()`
  preserving ownership, permissions, xattrs, and special files.
- **QCOW2 image**: magic bytes `QFI\xfb` at the start of the file.
  Mounted read-only via `qemu-nbd`, then copied with `copy_tree()`.
- **Raw disk image**: MBR/GPT signature or `.raw`/`.img` extension.
  Same `qemu-nbd` path as QCOW2.
- **Tarball**: default fallback for any other file. Extracted with
  native Rust crates; compression is detected from magic bytes, not the
  file name.

### The hard parts

**Permissions and ownership** must be preserved exactly. A rootfs
contains files owned by dozens of system UIDs (root, messagebus,
systemd-network, nobody, etc.) with specific modes. The `copy_tree()`
function uses `lchown()` for ownership, `chmod()` for permissions, and
`utimensat()` with nanosecond precision for timestamps. All operations
use `l`-prefixed variants (lstat, lchown, lgetxattr) to avoid following
symlinks.

**Extended attributes** carry security and filesystem metadata.
`copy_xattrs()` lists and copies all xattrs except `security.selinux`
(which doesn't transfer meaningfully between filesystems). The overlayfs
`trusted.overlay.opaque` xattr is preserved when present.

**Special files** (block devices, character devices, FIFOs, and Unix
sockets) are recreated with `mknod()` and `mkfifo()` using the original
mode and device numbers. This matters for rootfs that include
`/dev/null`, `/dev/zero`, and friends.

**Compression auto-detection** uses magic bytes rather than file
extensions. The first few bytes of a file reveal its compression format:

| Magic bytes            | Format |
|------------------------|--------|
| `1f 8b`                | gzip   |
| `BZh`                  | bzip2  |
| `fd 37 7a 58 5a 00`   | xz     |
| `28 b5 2f fd`          | zstd   |

This means `sdme fs import ubuntu rootfs.tar.zst` works even if the
file is named `rootfs.tar`, because the content, not the name,
determines the decompressor.

**Systemd detection** runs after import. If the rootfs doesn't contain
systemd and dbus (both required for nspawn containers), sdme can install
them automatically: it detects the distro family from `/etc/os-release`
and runs the appropriate package manager (`apt`, `dnf`) in a chroot.
The `--install-packages` flag controls this: `auto` prompts
interactively, `yes` always installs, `no` refuses if systemd is
absent.

**Rootfs patching** runs after systemd detection. Even when systemd is
present, sdme patches the rootfs for nspawn compatibility:
`systemd-resolved` is masked (containers share the host's network
namespace and cannot bind 127.0.0.53), `systemd-logind` is unmasked if
masked (some OCI images like CentOS/AlmaLinux mask it, but
`machinectl shell` requires logind), and missing packages needed by
`machinectl shell` (e.g. `util-linux` and `pam` on RHEL-family, which
provide `/etc/pam.d/login`) are installed via chroot. These patches are
applied directly to the rootfs so all containers created from it inherit
a working environment without overlayfs-level fixups.

**Staging areas and atomic operations** ensure that a failed import
doesn't leave a half-written rootfs. The staging directory
`.{name}.importing` is renamed to the final location only on complete
success. If sdme finds a leftover staging directory on the next run, it
reports it and the `--force` flag cleans it up.

**Cooperative Ctrl+C** runs throughout the import pipeline. A global
`INTERRUPTED` flag is set by a POSIX signal handler (installed with
`sigaction`, deliberately without `SA_RESTART` so blocking reads return
`EINTR`). The import loop checks this flag between operations, allowing
clean cancellation of multi-gigabyte downloads and extractions.

## 7. fs build: Building Root Filesystems

`sdme fs build` takes a Dockerfile-like config and produces a new
rootfs:

```
FROM ubuntu
COPY ./my-app /opt/my-app
RUN apt-get update && apt-get install -y libssl3
RUN systemctl enable my-app.service
```

The build engine creates a staging container from the FROM rootfs, then
processes operations sequentially. The key insight is that COPY and RUN
have different requirements:

- **COPY** writes directly to the overlayfs upper layer while the
  container is stopped. This is a filesystem operation; no running
  container needed.
- **RUN** executes a command inside the container via
  `machinectl shell`. The container must be running.

The engine starts and stops the container as needed: if it encounters a
RUN after a COPY, it starts the container; if it encounters a COPY
after a RUN, it stops it first. This means a config with alternating
COPY and RUN operations will start and stop the container multiple
times, but in practice most configs group their COPYs at the top and
RUNs at the bottom.

**Path sanitisation** rejects COPY destinations under directories that
systemd mounts tmpfs over at boot (`/tmp`, `/run`, `/dev/shm`). Files
written to the overlayfs upper layer in these locations would be hidden
by the tmpfs mount when the container starts, a silent data loss that's
hard to debug. Destinations under overlayfs-opaque directories are also
rejected. Errors include the config file path and line number for easy
debugging.

After all operations complete, the engine mounts the overlayfs manually
(the container is stopped), copies the merged view to a staging rootfs
directory, and does an atomic rename to the final location. The staging
container is cleaned up regardless of success or failure.

## 7b. fs export: Exporting Root Filesystems

`sdme fs export` is the inverse of import: it takes an imported rootfs
(or a container's merged overlayfs view) and writes it to a directory,
tarball, or raw disk image (ext4 or btrfs). The implementation lives in
`src/export.rs`.

### Format detection

The output format is determined by file extension, following the same
convention as import's compression detection but using extensions
instead of magic bytes (since we are creating, not reading):

| Extension                  | Format              |
|----------------------------|---------------------|
| `.tar`                     | uncompressed tar    |
| `.tar.gz`, `.tgz`         | gzip tar            |
| `.tar.bz2`, `.tbz2`       | bzip2 tar           |
| `.tar.xz`, `.txz`         | xz tar              |
| `.tar.zst`, `.tzst`       | zstandard tar       |
| `.img`, `.raw`            | bare ext4 raw image (default; `--filesystem btrfs` for btrfs) |
| anything else              | directory copy      |

The `-f` flag overrides detection. Format names match the extension
without the dot: `dir`, `tar`, `tar.gz`, `tar.bz2`, `tar.xz`,
`tar.zst`, `raw`.

### Directory export

Delegates to `copy_tree()` (the same function used by import), so
ownership, permissions, xattrs, and special files are preserved. The
destination must not already exist.

### Tarball export

Creates a tar archive using the Rust `tar` crate. Each entry preserves
uid/gid, permissions, and symlink targets. Compression uses the same
Rust crates as import decompression (flate2, bzip2, xz2, zstd) but on
the write side. Symlinks are stored as symlink entries (not followed).
Block/char devices, FIFOs, and sockets are stored as header-only
entries.

### Raw disk image export

Creates a sparse file, formats it with `mkfs.ext4` (default) or
`mkfs.btrfs` (`--filesystem btrfs`), loop-mounts it, copies the tree,
and unmounts. The mount point is a temporary directory under `/tmp`. If
the copy fails, the image file is cleaned up. For ext4, the `lost+found`
directory created by mkfs is removed before copying; btrfs does not
create one.

Size auto-calculation: `max(256 MiB, content_size * 1.5)`. The 1.5x
multiplier accounts for filesystem metadata overhead. The `--size` flag
overrides this with a human-readable value (e.g. `2G`, `500M`).

### Container export

When `--container` is passed, the export reads the container's merged
overlayfs view instead of an imported rootfs. If the container is
running, it reads directly from `merged/` with a consistency warning.
If stopped, it temporarily mounts overlayfs (lower=rootfs,
upper=container upper, work=container work) for the duration of the
export, then unmounts.

## 8. OCI Integration

> *The goal isn't to replace Docker or Podman. It's to give systemd-nspawn users
> a way to tap into the OCI ecosystem without leaving the systemd operational
> model.*

### Learning the spec

OCI registry pulling implements the OCI Distribution Spec directly, no
shelling out. The flow is: parse the image reference, probe the registry
for auth requirements, obtain a bearer token if needed, fetch the
manifest (resolving manifest lists by architecture), then download and
extract layers in order.

Layer extraction handles OCI whiteout markers: `.wh.<name>` deletes a
file from the previous layer, `.wh..wh..opq` clears an entire
directory. Tar paths are sanitised (leading `/` is stripped and `..`
components are rejected) to prevent path traversal escaping the
destination directory.

### Two modes: base OS and application

When importing an OCI image, sdme classifies it as either a **base OS
image** or an **application image** based on the image config:

| Classification    | Criteria                              |
|-------------------|---------------------------------------|
| Base OS image     | No entrypoint, shell default, no ports |
| Application image | Has entrypoint, non-shell cmd, or ports |

- **Base OS image**: extracted as a first-class sdme rootfs.
- **Application image**: placed under `/oci/apps/{name}/root`
  inside a base rootfs.

Application images require a base rootfs specified with `--base-fs`:

```bash
sudo sdme fs import ubuntu docker.io/ubuntu:24.04 -v --install-packages=yes
sudo sdme fs import nginx docker.io/nginx --base-fs=ubuntu -v
```

Set a default to avoid repeating `--base-fs`:

```bash
sudo sdme config set default_base_fs ubuntu
```

The `--oci-mode` flag overrides auto-detection:

| Flag              | Behavior                                     |
|-------------------|----------------------------------------------|
| `--oci-mode=auto` | Auto-detect from image config (default)       |
| `--oci-mode=base` | Force base OS mode                            |
| `--oci-mode=app`  | Force application mode (requires `--base-fs`) |

**Base OS import** (debian, ubuntu, fedora) is straightforward: extract
the rootfs and install systemd if missing. The result is a first-class
sdme rootfs.

**Application import** produces what sdme calls a *capsule*: a copy of
a base OS rootfs with the OCI application rootfs placed under
`/oci/apps/{name}/root` and a generated systemd service unit
(`sdme-oci-{name}.service`) that chroots into it. The app name is
derived from the last path component of the registry repository
(underscores replaced with hyphens) for registry images, or the rootfs
name for non-registry imports. Stored as `OCI_APP={name}` in the
container state file at create time.

```
  +------------------------------------------------------------+
  |                       HOST SYSTEM                          |
  |           kernel . systemd . D-Bus . machined              |
  |                          |                                 |
  |             sdme@name.service (nspawn)                     |
  |      +----------------------------------------------+      |
  |      |           CAPSULE (container)                |      |
  |      |                                              |      |
  |      |  systemd . D-Bus . journald                  |      |
  |      |                                              |      |
  |      |  +----------------------------------------+  |      |
  |      |  |  sdme-oci-{name}.service               |  |      |
  |      |  |  RootDirectory=/oci/apps/{name}/root   |  |      |
  |      |  |                                        |  |      |
  |      |  |  +----------------------------------+  |  |      |
  |      |  |  |      OCI process                 |  |  |      |
  |      |  |  |    (nginx, mysql, ...)           |  |  |      |
  |      |  |  +----------------------------------+  |  |      |
  |      |  +----------------------------------------+  |      |
  |      |                                              |      |
  |      |  /oci/apps/{name}/env      (env vars)        |      |
  |      |  /oci/apps/{name}/ports    (ports)           |      |
  |      |  /oci/apps/{name}/volumes  (volumes)         |      |
  |      +----------------------------------------------+      |
  +------------------------------------------------------------+
```

The generated `sdme-oci-{name}.service` unit uses
`RootDirectory=/oci/apps/{name}/root` to chroot the process,
`MountAPIVFS=yes` to provide `/proc`, `/sys`, `/dev`, and
`EnvironmentFile=-/oci/apps/{name}/env` to
load the image's environment variables. The unit is enabled via symlink
in `multi-user.target.wants/` so it starts automatically when the
container boots.

The capsule model means OCI applications get the full systemd
operational model for free: `journalctl -u sdme-oci-{name}` for logs,
`systemctl restart` for restarts, cgroup resource limits from the host.
The application doesn't know or care that it's inside an nspawn
container; it sees a chroot with API filesystems, exactly what it
expects.

### Privilege dropping for non-root OCI users

Many OCI application images declare a non-root `User` in their config
(e.g. `nginx` runs as UID 101). systemd's `User=` directive resolves
usernames via NSS **before** entering the `RootDirectory=` chroot, so
users that only exist inside the OCI rootfs cause exit code 217/USER.
This is a known upstream limitation (see
[systemd#12498](https://github.com/systemd/systemd/issues/12498),
[systemd#19781](https://github.com/systemd/systemd/issues/19781)).

sdme solves this with a generated static ELF binary (`isolate`,
under 2 KiB) that creates PID/IPC namespaces, remounts /proc, drops
`CAP_SYS_ADMIN`, optionally drops privileges (`setgroups`/`setgid`/
`setuid`), changes the working directory, and exec's the target, all
via raw syscalls with no libc or NSS dependency. The binary is written
to `/.sdme-isolate` inside the OCI root at import time (mode `0o111`,
owned by root). The generated unit becomes:

```ini
ExecStart=/.sdme-isolate <uid> <gid> <workdir> <entrypoint> [args...]
```

No `User=` or `WorkingDirectory=` directives are needed; the binary
handles both. For root users, uid and gid are 0; the binary still
creates PID/IPC namespaces for proper container isolation.

The OCI `User` field is resolved at import time against `etc/passwd`
and `etc/group` inside the OCI rootfs, supporting named users, numeric
UIDs, explicit groups, and `uid:gid` pairs.

### The isolate binary

systemd's execution pipeline for a service unit with `RootDirectory=` runs
in this order:

1. NSS lookup of `User=` against the host filesystem
2. `RootDirectory=` chroot
3. `execve()` of the service binary

For OCI containers, steps 1 and 2 should be reversed: the user exists in
the OCI rootfs, not on the host. This is a known upstream limitation:

- [systemd#12498](https://github.com/systemd/systemd/issues/12498):
  `RootDirectory` with `User` not working. Fixed the ordering for some
  chroot operations, but NSS lookup still happens pre-chroot.
- [systemd#19781](https://github.com/systemd/systemd/issues/19781):
  RFE: allow exec units as uid without passwd entry. Open; upstream
  position is to use NSS registration (nss-systemd, machined) instead.
- [systemd#14806](https://github.com/systemd/systemd/issues/14806):
  Support uid/gids from target rootfs with `--root`. Fixed for `tmpfiles`
  via `fgetpwent`, but not for service execution.

sdme generates a static ELF binary (`isolate`) that creates PID/IPC
namespaces, remounts /proc, drops `CAP_SYS_ADMIN`, optionally drops
privileges, and execs the target, all via raw syscalls with no libc
dependency and no NSS. The binary is invoked as:

```
/.sdme-isolate <uid> <gid> <workdir> <command> [args...]
```

The syscall sequence:

1. `unshare(CLONE_NEWPID | CLONE_NEWIPC)`: create new PID and IPC namespaces
2. `fork()`: enter the new PID namespace (child becomes PID 1)
3. `mount("proc", "/proc", "proc", ...)`: remount /proc for the new namespace
4. `prctl(PR_CAPBSET_DROP, CAP_SYS_ADMIN)`: drop CAP_SYS_ADMIN from bounding set
5. `setgroups(0, NULL)`: clear supplementary groups (skipped if uid==0)
6. `setgid(gid)`: set group ID (skipped if uid==0)
7. `setuid(uid)`: set user ID (skipped if uid==0)
8. `chdir(workdir)`: change to the application's working directory
9. `execve(command, args, envp)`: replace the process with the application

Each syscall is checked for errors. On failure, a diagnostic message is
written to stderr and the process exits with code 1. For root users
(uid==0, gid==0), steps 5-7 are skipped but namespace isolation still
applies.

**User resolution.** The OCI `User` field is resolved at import time
against `etc/passwd` and `etc/group` inside the OCI rootfs:

| Format            | Behavior                                            |
|-------------------|-----------------------------------------------------|
| `""`, `"root"`    | Root; uid=0 gid=0 (namespace isolation only)        |
| `"name"`          | Resolved via `etc/passwd` in OCI rootfs             |
| `"uid"`           | Used directly; primary GID from passwd if found     |
| `"name:group"`    | User from `etc/passwd`, group from `etc/group`      |
| `"uid:gid"`       | Both used directly                                  |

**Security model.** The privilege-dropping sequence is designed to be
irreversible:

- `setgroups(0, NULL)` clears all supplementary groups before any
  uid/gid change.
- `setgid(gid)` before `setuid(uid)`: correct order, since `setgid`
  requires root and must happen first.
- `setuid(uid)` for non-zero UIDs is irreversible (the kernel clears
  all capabilities).
- Binary permissions (`0o111`, execute-only): non-root users cannot read,
  write, or delete the file.
- Binary ownership (root:root): only root can modify or remove it.
- Parent directory (`/` inside the chroot) is owned by root, so non-root
  cannot unlink files from it.
- No SUID/SGID bit: the binary runs with the caller's privileges (root,
  since no `User=` in the unit).
- No file capabilities: no `security.capability` xattr is set.
- The `atoi` implementation rejects values exceeding `u32::MAX` to
  prevent wrap-around to UID 0.

After `execve`, the new process inherits the dropped uid/gid and cannot
regain root.

### /dev/std* shim for journal socket compatibility

OCI images commonly symlink log files to `/dev/stdout` or
`/dev/stderr` (e.g. `/var/log/nginx/error.log -> /dev/stderr ->
/proc/self/fd/2`). Under Docker, fds 1/2 are pipes, so `open()` on
`/proc/self/fd/N` succeeds. Under systemd, fds 1/2 are journal
sockets, and the kernel rejects `open()` on socket-backed
`/proc/self/fd/N` with ENXIO.

sdme solves this with a generated LD_PRELOAD shared library
(`devfd_shim`, approximately 4 KiB) that intercepts
`open()`/`openat()` at the libc symbol level. When the path matches
`/dev/stdin`, `/dev/stdout`, `/dev/stderr`, `/dev/fd/{0,1,2}`, or
`/proc/self/fd/{0,1,2}`, the interceptor returns `dup(N)` instead of
calling the real `open`. All other paths fall through to the real
syscall.

The shim is written to `/.sdme-devfd-shim.so` inside the OCI root at
import time, and the generated unit includes
`Environment=LD_PRELOAD=/.sdme-devfd-shim.so`. This applies to all OCI
containers (both root and non-root users).

### The /dev/std* shim

OCI images commonly create symlinks from log files to the standard
file descriptors:

```
/var/log/nginx/error.log -> /dev/stderr -> /proc/self/fd/2
```

When the application opens its log file, the kernel follows the symlink
chain to `/proc/self/fd/N` and calls `open()` on the underlying file
descriptor.

Under Docker, fds 1/2 are pipes. The kernel allows `open()` on
pipe-backed `/proc/self/fd/N`, and the call succeeds.

Under systemd, fds 1/2 are journal sockets. The kernel rejects `open()`
on socket-backed `/proc/self/fd/N` with ENXIO ("No such device or
address"). This is a kernel limitation, not a systemd one.

The distinction matters: `write()` on a socket fd works fine. Only
`open()` on `/proc/self/fd/N` fails. Applications that write directly
to fd 1 or fd 2 have no problem. Applications that open a path that
resolves to `/proc/self/fd/N` (like nginx opening its log symlinks) fail
with ENXIO.

**Alternatives considered.** eBPF cannot solve this. `bpf_override_return`
can inject error codes, but it cannot fabricate file descriptors.
Returning a valid fd from `open()` requires allocating a kernel
`struct file` and installing it in the process's fd table. No eBPF hook
is capable of this. Removing the symlinks works but means log output goes
to files inside the chroot instead of the journal. Since the whole point
of running under systemd is journal integration, losing log output to
files defeats the purpose.

sdme generates an LD_PRELOAD shared library that intercepts `open()`,
`openat()`, `open64()`, and `openat64()` at the libc symbol level. When
the path matches a standard fd path, the interceptor returns `dup(N)`
instead of calling the real `open()`. All other paths fall through to the
real `openat` syscall.

Intercepted paths:

| Path               | Result   |
|--------------------|----------|
| `/dev/stdin`       | `dup(0)` |
| `/dev/stdout`      | `dup(1)` |
| `/dev/stderr`      | `dup(2)` |
| `/dev/fd/0`        | `dup(0)` |
| `/dev/fd/1`        | `dup(1)` |
| `/dev/fd/2`        | `dup(2)` |
| `/proc/self/fd/0`  | `dup(0)` |
| `/proc/self/fd/1`  | `dup(1)` |
| `/proc/self/fd/2`  | `dup(2)` |

**Why dup() instead of returning the raw fd.** Returning the raw fd
number (0, 1, or 2) would work for simple cases, but callers expect
`open()` to return a new, independently closeable fd. If we returned fd 2
directly and the caller later called `close()`, stderr would be closed
for the entire process. `dup()` gives the caller their own fd that they
can close without affecting the original.

**Path matching.** The interceptor uses 8-byte loads and integer
comparisons organized as a prefix tree. No string function calls:

1. Load the first 8 bytes as a 64-bit integer.
2. Compare against `/dev/std` (8 bytes). On match, check for `in\0`,
   `out\0`, `err\0` at offset 8.
3. Compare against `/dev/fd/` (8 bytes). On match, check for `0\0`,
   `1\0`, `2\0` at offset 8.
4. Compare against `/proc/se` (8 bytes). On match, check for
   `lf/fd/0\0`, `lf/fd/1\0`, `lf/fd/2\0` at offset 8.
5. No match: call the real `openat` syscall.

**ENXIO fallback.** If the real `openat` syscall returns `-ENXIO`, the
interceptor resolves one level of symlink via `readlinkat` and retries
the path matching against the resolved target. This handles cases like
nginx opening `/var/log/nginx/error.log`, which is a symlink to
`/dev/stderr`. Without this fallback, only direct opens of `/dev/std*`
paths would be intercepted.

On error (from `dup` or a non-ENXIO `openat` failure), the shim sets
`errno` via `__errno_location()` (imported through the GOT, resolved by
the dynamic linker at load time) and returns `-1` per C convention.

The `open()` entry point rewrites its arguments to match the `openat()`
calling convention (inserting `AT_FDCWD` as the directory fd) and jumps
to the `openat` entry point. `open64` and `openat64` are aliases since
they are identical on 64-bit Linux.

### Deployment

Both binaries are deployed during `sdme fs import` of an OCI application
image (one imported with `--base-fs`):

1. The OCI image config's `User` field is parsed.
2. The `devfd_shim` shared library is written to `/.sdme-devfd-shim.so`
   inside the OCI root (mode `0o444`, readable for mmap).
3. The `isolate` binary is written to `/.sdme-isolate` (mode `0o111`,
   execute-only). If the user is non-root, the name is resolved against
   `etc/passwd` and `etc/group` inside the OCI rootfs.
4. A systemd service unit (`sdme-oci-{name}.service`) is generated with
   both binaries wired in.

Generated unit (non-root user):

```ini
[Service]
Type=exec
RootDirectory=/oci/apps/nginx/root
MountAPIVFS=yes
Environment=LD_PRELOAD=/.sdme-devfd-shim.so
EnvironmentFile=-/oci/apps/nginx/env
ExecStart=/.sdme-isolate 101 101 / /docker-entrypoint.sh nginx -g 'daemon off;'
```

`LD_PRELOAD` loads the devfd shim into the application's address space.
`ExecStart` invokes the isolate binary, which creates PID/IPC namespaces,
drops privileges to uid/gid, and then exec's the actual entrypoint.

Generated unit (root user):

```ini
[Service]
Type=exec
RootDirectory=/oci/apps/nginx/root
MountAPIVFS=yes
Environment=LD_PRELOAD=/.sdme-devfd-shim.so
EnvironmentFile=-/oci/apps/nginx/env
ExecStart=/.sdme-isolate 0 0 / /docker-entrypoint.sh nginx -g 'daemon off;'
```

For root users, the isolate binary still runs to provide namespace
isolation, but privilege dropping is skipped.

### Implementation notes

Both binaries are generated at import time for the host architecture:

| Binary       | x86_64            | aarch64          | Size    |
|--------------|-------------------|------------------|---------|
| `isolate`    | `syscall`, rax=nr | `svc #0`, x8=nr  | < 2 KiB |
| `devfd_shim` | `syscall`, rax=nr | `svc #0`, x8=nr  | ~ 4 KiB |

Both are generated entirely in Rust with no assembler, no external tools,
and no libc. Each architecture module contains its own `Asm` struct with
a label/fixup system tailored to the ISA: x86_64 uses rel8/rel32 fixups
for variable-length instructions; aarch64 uses BCond/Branch26 fixups for
fixed 4-byte instructions.

**ELF structure.** `isolate` is a minimal ET_EXEC static ELF64 with:

- ELF header + 1 program header (PT_LOAD RX)
- Machine code (namespace creation + privilege drop + exec syscall sequence)
- String constants (error messages, read from code-relative addresses)
- No section headers, no dynamic section, no symbol table

`devfd_shim` is a minimal ET_DYN shared library with:

- ELF header + 3 program headers (PT_LOAD RX, PT_LOAD RW, PT_DYNAMIC)
- Machine code (the interceptor logic)
- SysV hash table for symbol lookup by the dynamic linker
- Dynamic symbol table: exported symbols (`open`, `openat`, `open64`,
  `openat64`) and imported symbols (`__errno_location`)
- RELA relocations pointing the dynamic linker at GOT slots
- GOT entries (filled by the dynamic linker at load time)
- Dynamic section (DT_HASH, DT_STRTAB, DT_SYMTAB, etc.)
- No section headers (not needed at runtime)

**Module layout:**

| File                         | Purpose                             |
|------------------------------|-------------------------------------|
| `src/elf.rs`                 | Shared `Arch` enum + ELF builder    |
| `src/isolate/mod.rs`         | Public API: `generate(Arch)`        |
| `src/isolate/x86_64.rs`     | x86_64 emitter (PID/IPC ns + privs) |
| `src/isolate/aarch64.rs`    | AArch64 emitter (PID/IPC ns + privs)|
| `src/devfd_shim/mod.rs`     | Public API: `generate(Arch)`        |
| `src/devfd_shim/elf.rs`     | ET_DYN ELF builder (SysV hash)      |
| `src/devfd_shim/x86_64.rs`  | x86_64 emitter                      |
| `src/devfd_shim/aarch64.rs` | AArch64 emitter                     |

Both architecture modules use the same pattern: an `Asm` struct that emits
machine code bytes, a label system for forward references, and a fixup pass
that patches relative offsets once all labels are defined. The `elf` module
in each crate assembles the ELF headers, program headers, and metadata
tables around the emitted code.

### OCI plumbing: ports and volumes

OCI images declare exposed ports and volumes in their image config.
sdme reads these from `/oci/apps/{name}/ports` and `/oci/apps/{name}/volumes` in the rootfs
and auto-wires them at container creation time.

**Port forwarding.** When the container uses a private network namespace
(`--private-network`, `--hardened`, or `--strict`), sdme reads
`/oci/apps/{name}/ports` and adds `--port` rules mapping each declared port to the
same host port. User `--port` flags take priority; matching ports are
skipped. On host-network containers, no forwarding is needed (services
bind directly to the host), so sdme prints an informational message
instead. Suppressed with `--no-oci-ports`.

**Volume mounts.** For each volume declared in `/oci/apps/{name}/volumes`, sdme
creates a host-side directory at
`{datadir}/volumes/{container}/{volume-name}` and adds a bind mount
mapping it to `/oci/apps/{name}/root{volume-path}` inside the container. Volume
data survives container removal (sdme prints the path but does not
delete it). User `--bind` flags take priority: if the user binds to the
same container path, the auto-mount is skipped. Suppressed with
`--no-oci-volumes`.

**Remaining caveat.** User-specified bind mounts (`-b`) and environment
variables (`-e`) on the container operate at the nspawn level, not
inside the `RootDirectory=/oci/apps/{name}/root` chroot where the OCI application
runs. OCI-declared volumes and ports are handled correctly because sdme
maps volumes into the `/oci/apps/{name}/root` subtree and ports operate at the
network namespace level.

### Environment variables

OCI image environment variables are stored in `/oci/apps/{name}/env` inside the
rootfs (loaded via `EnvironmentFile=-/oci/apps/{name}/env` in the generated unit).
Additional variables (e.g. `MYSQL_ROOT_PASSWORD`) can be set at creation time
with `--oci-env`:

```bash
sudo sdme new -r mysql --oci-env MYSQL_ROOT_PASSWORD=secret
```

The `--oci-env` flag appends to the existing env file from the OCI image,
so image-defined variables are preserved unless explicitly overridden.

### Limitations

- **One OCI service per container.** Each rootfs generates a single
  `sdme-oci-{name}.service`.
- **No health checks.** OCI HEALTHCHECK directives are ignored.
### OCI namespace entry: cgroup discovery

`sdme exec --oci` and `sdme join --oci` need to find the host PID of
the OCI app process so they can call `nsenter`. The PID is discovered
from the app's cgroup: `find_oci_service_cgroup()` searches for the
`sdme-oci-{name}.service` cgroup directory under
`/sys/fs/cgroup/machine.slice/`.

Three cgroup root patterns are tried, because systemd versions lay out
the container's cgroup differently:

1. **`{name}.scope`**: systemd 259+ registers the machine scope
   directly under the container name.
2. **`sdme@{name}.service`**: older systemd versions (< 257) use
   the template unit name as the cgroup path.
3. **`machine-{escaped}.scope`**: systemd 257-258 use a
   `machine-` prefix with hyphens escaped as `\x2d`.

Within each root, three inner path candidates are searched:
`init.scope/system.slice`, `payload/system.slice`, and
`system.slice`. The function retries for up to 3 seconds (30 × 100 ms)
because the cgroup directory may not appear on the filesystem
immediately after systemd reports the unit as active.

### OCI capability filtering for hardened containers

When `--drop-capability` is used on a container that has OCI apps,
`create()` writes a `hardening.conf` systemd drop-in into the
overlayfs upper layer at
`/etc/systemd/system/sdme-oci-{name}.service.d/hardening.conf`. The
drop-in resets and re-sets `CapabilityBoundingSet`, filtering the
dropped capabilities out of `OCI_DEFAULT_CAPS`. `CAP_SYS_ADMIN` is
always preserved because the isolate binary needs it for
`unshare()`/`mount()`.

Without this drop-in, the inner OCI service would inherit the full
default capability set, which can conflict with the container-level
capability restrictions and cause boot failures (systemd refuses to
start a service whose bounding set includes capabilities the container
does not have).

### Future direction

At this point this is all very exploratory. This journey is 1% complete.

## 9. Networking

By default, containers share the host's network namespace: same
interfaces, same addresses, same ports. This is the simplest mode and
what you get with `sdme new` out of the box.

For isolation, `--private-network` gives the container its own network
namespace with no connectivity. The remaining network flags build on
top of it and all imply `--private-network` automatically:

- `--private-network`: isolated network namespace, no connectivity
- `--network-veth`: creates a virtual ethernet link between host and
  container
- `--network-bridge <name>`: connects the container's veth to a host
  bridge
- `--network-zone <name>`: joins a named zone for inter-container
  networking
- `--port / -p <[PROTO:]HOST[:CONTAINER]>`: forwards a port (TCP by
  default, repeatable)

These flags are available on both `sdme create` and `sdme new`. They
compose freely: you can combine `--network-zone` with `--port`, or use
`--network-bridge` with `--network-veth`. Port forwarding requires a
private network namespace because systemd-nspawn's `--port` flag only
works when host and container have separate network stacks.

Under the hood, each flag translates directly to a systemd-nspawn
argument. The network configuration is persisted in the container's
state file (`PRIVATE_NETWORK`, `NETWORK_VETH`, `NETWORK_BRIDGE`,
`NETWORK_ZONE`, `PORTS`) and written into the per-container nspawn
drop-in at start time.

Bridge and zone names are validated (alphanumeric, hyphens,
underscores). Port specs are validated for format
(`[PROTO:]HOST[:CONTAINER]`) and range (1-65535).

## 10. Pods

Pods give multiple containers a shared network namespace so they can
reach each other on localhost. The pattern is the same as Kubernetes
pods: one network namespace, multiple containers.

There are two mechanisms for joining a pod, serving different use cases:

**`--pod` (whole-container):** The entire nspawn container runs in the
pod's network namespace. All processes (init, services, everything)
share the pod's network stack. This is the general-purpose option for
any container type.

**`--oci-pod` (OCI app only):** The pod's netns is bind-mounted into
the container and only the OCI app service process enters it via a
systemd `NetworkNamespacePath=` drop-in. The container's init and other
services remain in their own network namespace. This is for OCI app
containers that need pod networking for their application process but
want systemd's own networking to remain independent. Requires an OCI
app rootfs.

Both flags can be combined on the same container (e.g.
`--pod=X --oci-pod=Y` with different pods).

```
  --pod (whole container in pod netns):

  +------------------------------------------------------+
  |                     HOST SYSTEM                      |
  |         kernel . systemd . D-Bus . machined          |
  |                                                      |
  |   /run/sdme/pods/my-pod/netns  (netns bind-mount)    |
  |          |                                           |
  |          |  +-- loopback only (127.0.0.1) --+        |
  |          |  |                               |        |
  |    +-----+----------+   +------------------+--+      |
  |    | container A     |   | container B        |      |
  |    | (db :5432)      |   | (app :8080)        |      |
  |    | nspawn --network|   | nspawn --network   |      |
  |    |  -namespace-    |   |  -namespace-       |      |
  |    |  path=pod-netns |   |  path=pod-netns    |      |
  |    +-----------------+   +--------------------+      |
  +------------------------------------------------------+

  Both containers see 127.0.0.1:5432 (db) and
  127.0.0.1:8080 (app) because they share the netns.
```

### Lifecycle

`sdme pod new <name>` creates the pod:

1. Validates the name (same rules as container names).
2. Calls `unshare(CLONE_NEWNET)` to create a new network namespace.
3. Brings up the loopback interface (`ioctl SIOCSIFFLAGS IFF_UP`).
4. Bind-mounts `/proc/self/ns/net` to
   `/run/sdme/pods/<name>/netns`.
5. Restores the original network namespace via `setns()`.
6. Writes a persistent state file at
   `{datadir}/pods/<name>/state`.

The runtime bind-mount under `/run` is volatile and disappears on
reboot. When a container referencing a pod is started,
`ensure_runtime()` checks whether the bind-mount still exists and
recreates the netns if needed.

`sdme pod ls` lists all pods with their active/inactive status.

`sdme pod rm <name>` unmounts the netns, removes the runtime directory,
and deletes the persistent state directory. Removal is refused if any
container still references the pod via `POD` or `OCI_POD` keys
(override with `--force`).

### Container integration

**`--pod=<name>`** on `sdme create` or `sdme new`:

- Works with any container type (host-rootfs or imported rootfs).
- Incompatible with `--userns` and `--hardened`: the kernel blocks
  `setns(CLONE_NEWNET)` from a child user namespace into the pod's
  netns (owned by the init userns). Use `--oci-pod` for hardened pods.
- Compatible with `--private-network` (without userns): the pod's
  netns already provides equivalent isolation (loopback only), so
  `--private-network` is automatically omitted from the nspawn
  invocation when a pod is used.
- Stores `POD=<name>` in the container's state file.
- At start time, the nspawn drop-in includes
  `--network-namespace-path=/run/sdme/pods/<name>/netns`, which makes
  the entire container (including init and all services) run inside
  the pod's network namespace.

**`--oci-pod=<name>`** on `sdme create` or `sdme new`:

- Requires an OCI app rootfs (an `sdme-oci-{name}.service` unit must exist in the
  rootfs).
- Stores `OCI_POD=<name>` in the container's state file.
- At create time, writes a systemd drop-in inside the overlayfs upper
  layer at
  `upper/etc/systemd/system/sdme-oci-{name}.service.d/oci-pod-netns.conf`
  with `NetworkNamespacePath=/run/sdme/oci-pod-netns`.
- At start time, the nspawn drop-in includes
  `--bind-ro=/run/sdme/pods/<name>/netns:/run/sdme/oci-pod-netns`,
  which makes the pod's netns available inside the container. The
  inner drop-in makes only the OCI app service process enter the
  pod's netns.

`sdme ps` shows a POD column when any container has a `--pod`
assignment, an OCI-POD column when any container has an `--oci-pod`
assignment, a USERNS column when any container has `--userns` enabled,
and a BINDS column when any container has bind mounts configured.

### Isolation properties

The pod netns contains only a loopback interface with no routes.
Containers in the pod can communicate via localhost but have no external
connectivity unless a veth or bridge is added to the netns externally.

Inside the container, systemd-nspawn's default capability set drops
`CAP_NET_ADMIN`, so the container's root cannot add interfaces or
change routes in the shared netns. `CAP_SYS_ADMIN` is present
(required by systemd inside nspawn) but the container's PID namespace
prevents access to host process netns references. The OCI app process
itself (running as a non-root UID) has zero effective capabilities.

## 11. Kubernetes Pod Support

sdme can run Kubernetes Pod YAML files as nspawn containers. Each pod maps
to a single container where each workload runs as a separate systemd
service chrooted into its own rootfs under `/oci/apps/{name}/root`. For
usage examples and CLI reference, see
[usage.md, Section 7](usage.md#7-kubernetes-pod-yaml).

### Pipeline

1. **Parse & Validate**: reads the YAML, validates container names, volume
   references, etc. Accepts `kind: Pod` (v1) and `kind: Deployment`
   (apps/v1; extracts pod template).
2. **Pull Images**: downloads each container's OCI image from the registry.
3. **Build Combined Rootfs**: copies the base rootfs, then places each
   container's OCI rootfs under `/oci/apps/{name}/root` with a generated
   systemd service unit.
4. **Generate Volume Mounts**: if the pod has volume mounts, generates a
   `sdme-kube-volumes.service` oneshot unit that bind-mounts
   `/oci/volumes/{name}` into each app's root directory; app services
   depend on this unit via `After=`/`Requires=`.
5. **Create Container**: creates an sdme container using the combined
   rootfs (hostPath volumes become nspawn `--bind=` mounts; emptyDir
   volumes live inside the rootfs).
6. **Start & Boot**: boots the container; the volume mount service runs
   first, then all app services start.

### Supported Pod spec fields

| Field                            | Description                        |
|----------------------------------|------------------------------------|
| `containers[].image`             | OCI image reference                |
| `containers[].name`              | Container name (service name)      |
| `containers[].command`           | Override ENTRYPOINT                |
| `containers[].args`              | Override CMD                       |
| `containers[].env`               | Per-container env vars             |
| `containers[].env[].valueFrom`   | secretKeyRef or configMapKeyRef    |
| `containers[].ports`             | Port forwarding (private network)  |
| `containers[].volumeMounts`      | Bind volumes into app rootfs       |
| `containers[].workingDir`        | Override working directory         |
| `containers[].imagePullPolicy`   | Always, IfNotPresent, or Never     |
| `containers[].resources`         | Memory/CPU limits and weights      |
| `containers[].startupProbe`      | exec, httpGet, tcpSocket, grpc     |
| `containers[].livenessProbe`     | exec, httpGet, tcpSocket, grpc     |
| `containers[].readinessProbe`    | exec, httpGet, tcpSocket, grpc     |
| `initContainers[]`               | Run-to-completion before app start |
| `volumes` (emptyDir)             | Shared directory between apps      |
| `volumes` (hostPath)             | Mount host directory into the pod  |
| `volumes` (secret)               | From sdme kube secret              |
| `volumes` (configMap)            | From sdme kube configmap           |
| `volumes` (persistentVolumeClaim)| Host dir at {datadir}/volumes/     |
| `restartPolicy`                  | Maps to systemd Restart=           |
| `terminationGracePeriodSeconds`  | Shutdown timeout                   |
| `securityContext.runAsUser`       | Pod-level UID for all containers   |
| `securityContext.runAsGroup`      | Pod-level GID for all containers   |
| `securityContext.runAsNonRoot`    | Validates runAsUser is non-zero    |

Secret and configMap volumes support `items` for projected key
paths and `defaultMode` for file permissions.

### Filesystem layout

```
/oci/
|-- apps/
|   |-- nginx/
|   |   |-- root/           # nginx OCI rootfs
|   |   |-- env             # environment variables
|   |   |-- ports           # exposed ports
|   |   +-- volumes         # declared volumes
|   +-- redis/
|       |-- root/           # redis OCI rootfs
|       |-- env
|       |-- ports
|       +-- volumes
+-- volumes/
    +-- cache-vol/          # emptyDir shared volume

/oci/
+-- .sdme-kube-probe               # probe binary (when probes defined)

/etc/systemd/system/
|-- sdme-oci-nginx.service
|-- sdme-oci-redis.service
|-- sdme-kube-volumes.service    # oneshot: bind-mounts volumes
|-- sdme-probe-liveness-nginx.timer
|-- sdme-probe-liveness-nginx.service
+-- multi-user.target.wants/
    |-- sdme-oci-nginx.service -> ...
    |-- sdme-oci-redis.service -> ...
    |-- sdme-kube-volumes.service -> ...
    +-- sdme-probe-liveness-nginx.timer -> ...
```

### Generated service units

Each container gets a systemd service `sdme-oci-{name}.service`:

```ini
[Unit]
Description=OCI app: nginx (docker.io/nginx:latest)
After=network.target
After=sdme-kube-volumes.service
Requires=sdme-kube-volumes.service

[Service]
Type=exec
RootDirectory=/oci/apps/nginx/root
MountAPIVFS=yes
Environment=LD_PRELOAD=/.sdme-devfd-shim.so
EnvironmentFile=-/oci/apps/nginx/env
ExecStart=/.sdme-isolate 0 0 / /docker-entrypoint.sh nginx -g 'daemon off;'
Restart=always
CapabilityBoundingSet=CAP_AUDIT_WRITE CAP_CHOWN CAP_DAC_OVERRIDE ...
NoNewPrivileges=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
RestrictSUIDSGID=yes
LockPersonality=yes
ProtectProc=invisible
ProcSubset=pid

[Install]
WantedBy=multi-user.target
```

The `After=`/`Requires=` lines are only present when the pod has volume
mounts.

When shared volumes exist, a `sdme-kube-volumes.service` oneshot unit is
also generated:

```ini
[Unit]
Description=Kube volume mounts
DefaultDependencies=no
After=local-fs.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/mount --bind /oci/volumes/shared-data /oci/apps/nginx/root/usr/share/nginx/html
ExecStart=/bin/mount --bind /oci/volumes/shared-data /oci/apps/content-gen/root/data

[Install]
WantedBy=multi-user.target
```

This runs `mount --bind` in the container's PID 1 mount namespace before
app services start, so all services see the same shared directories.
Read-only mounts get an additional `remount,ro,bind` line.

### Probes

Startup, liveness, and readiness probes are implemented via an embedded
`sdme-kube-probe` binary deployed at `/oci/.sdme-kube-probe` inside the
container rootfs. The binary is built separately (`cargo build --features
probe --bin sdme-kube-probe`) and embedded into sdme via `include_bytes!()`
at compile time.

All three probe types use systemd timer + oneshot service pairs. No
shell scripts are generated and no external tools are required (wget,
bash, etc.).

Four probe mechanisms are supported:

- **exec**: runs a command inside the app rootfs via `chroot` + `Command`
  (std only, no external deps)
- **httpGet**: raw HTTP/1.0 GET via `TcpStream`, checks for 2xx/3xx
  status (std only)
- **tcpSocket**: `TcpStream::connect_timeout()` (std only)
- **grpc**: gRPC Health Checking Protocol via tonic (optional `probe`
  feature)

Standard Kubernetes probe parameters are supported:
`initialDelaySeconds`, `periodSeconds`, `timeoutSeconds`,
`failureThreshold`, `successThreshold`.

**Probe lifecycle.** When a startup probe exists, it gates liveness
and readiness probes: the liveness/readiness service units include
`ConditionPathExists=/run/sdme-probe-startup-{name}.done`, so they
silently skip until the startup probe writes its done file.

On success, the startup probe writes
`/run/sdme-probe-startup-{name}.done`; the readiness probe writes
`ready` to `/oci/apps/{name}/probe-ready` (readable from the host
via the overlayfs merged dir, shown in `sdme ps`). On failure
threshold, startup/liveness probes restart the app service via
`systemctl restart`; readiness probes write `not-ready`.

The probe binary always exits 0 so systemd does not mark the
oneshot service as failed. Failure counting is managed internally
via counter files in `/run/`.

**Generated units.** For an app named `nginx` with a liveness probe:

```
sdme-probe-liveness-nginx.timer     # fires periodically
sdme-probe-liveness-nginx.service   # runs /oci/.sdme-kube-probe
```

The timer binds to the main service (`BindsTo=sdme-oci-nginx.service`)
and stops automatically when the app stops.

### State management

Kube pods are tracked with additional state fields:

- `KUBE=yes`: marks this as a kube pod
- `KUBE_CONTAINERS=nginx,redis,...`: list of container names
- `KUBE_YAML_HASH={sha256}`: hash of the source YAML (for future update
  detection)
- `HAS_PROBES=yes`: set when the pod has any probe definitions

`sdme ps` shows kube pods with a KUBE column, e.g.: `kube:nginx,redis`

### Limitations

- No idempotent re-apply: `kube apply` on an existing pod fails; delete
  first, then re-apply
- No per-container securityContext (only pod-level `runAsUser`/`runAsGroup`)

## 12. Resource Limits

sdme exposes three cgroup-based resource controls:

| Flag                     | systemd property | Example             |
|--------------------------|------------------|---------------------|
| `--memory <size>`        | `MemoryMax=`     | `--memory 2G`       |
| `--cpus <count>`         | `CPUQuota=`      | `--cpus 0.5` (50%) |
| `--cpu-weight <1-10000>` | `CPUWeight=`     | `--cpu-weight 100`  |

These flags are available on `sdme create`, `sdme new`, and `sdme set`.
They are applied via a systemd drop-in file (`limits.conf`) installed
alongside the container's service unit. A `daemon-reload` is triggered
when the drop-in changes.

`sdme set` replaces all limits at once: flags not specified are removed.
If the container is running, sdme prints a note that a restart is needed
for the new limits to take effect.

Memory values accept K/M/G/T suffixes. CPU count is a positive float
where `1` means one full core and `0.5` means half a core (converted to
systemd's `CPUQuota=` percentage internally). CPU weight is an integer
from 1 to 10000, controlling relative scheduling priority when CPUs are
contended.

## 13. Bind Mounts and Environment Variables

Custom bind mounts and environment variables are set at creation time
with `-b`/`--bind` and `-e`/`--env`, available on both `sdme create`
and `sdme new`.

**Bind mounts** use the format `HOST:CONTAINER[:ro]`. Read-write is the
default; append `:ro` for read-only. Both paths must be absolute with
no `..` components, and the host path must exist at creation time. At
start time, each bind becomes a `--bind=` or `--bind-ro=` argument to
systemd-nspawn.

**Environment variables** use the format `KEY=VALUE`. Keys must be
alphanumeric or underscore (no leading digit). At start time, each
variable becomes a `--setenv=KEY=VALUE` argument to systemd-nspawn.

Both are stored in the container's state file (`BINDS=` and `ENVS=`,
pipe-separated) and reconstituted into nspawn arguments on every start.

## 14. Configuration

sdme stores its settings in a TOML file at `/etc/sdme.conf`:

| Setting                   | Default                          |
|---------------------------|----------------------------------|
| `interactive`             | `true`                           |
| `datadir`                 | `/var/lib/sdme`                  |
| `boot_timeout`            | `60`                             |
| `join_as_sudo_user`       | `true`                           |
| `host_rootfs_opaque_dirs` | `/etc/systemd/system,/var/log`   |
| `hardened_drop_caps`      | `CAP_SYS_PTRACE,CAP_NET_RAW,...` |
| `default_base_fs`         | (empty)                          |
| `default_export_fs`       | `ext4`                           |
| `tasks_max`               | `16384`                          |
| `docker_user`             | (empty)                          |
| `docker_token`            | (empty)                          |
| `oci_cache_dir`           | (empty = `{datadir}/cache/oci`)  |
| `oci_cache_max_size`      | `10G`                            |
| `http_timeout`            | `30`                             |
| `http_body_timeout`       | `300`                            |
| `max_download_size`       | `50G`                            |

- `interactive`: enable interactive prompts.
- `datadir`: root directory for all container and rootfs data.
- `boot_timeout`: seconds to wait for container boot.
- `join_as_sudo_user`: join host-rootfs containers as
  `$SUDO_USER` instead of root.
- `host_rootfs_opaque_dirs`: default opaque dirs for host-rootfs
  containers (empty string disables).
- `hardened_drop_caps`: capabilities dropped by `--hardened`.
- `default_base_fs`: default base rootfs for OCI app images.
- `default_export_fs`: filesystem type for raw disk image export
  (`ext4` or `btrfs`).
- `tasks_max`: maximum tasks (processes/threads) per container
  in the systemd template unit.
- `docker_user`: Docker Hub username for authenticated pulls.
- `docker_token`: Docker Hub personal access token.
- `oci_cache_dir`: OCI blob cache directory.
- `oci_cache_max_size`: max cache size (`0` disables).
- `http_timeout`: HTTP connect/resolve timeout in seconds for
  downloads and OCI registry pulls.
- `http_body_timeout`: HTTP body receive timeout in seconds.
- `max_download_size`: maximum download size for imports and
  OCI pulls (e.g. `50G`; `0` = unlimited).

Settings are read with `sdme config get` and written with
`sdme config set <key> <value>`.

Config files are written with mode `0600`.

## 15. Security

This section documents sdme's security implementation: capabilities,
seccomp, AppArmor, the `--hardened` and `--strict` flags, and input
sanitization. For comparisons with Docker and Podman, see
[docs/security.md](security.md).

### Capability bounding set

systemd-nspawn retains 26 capabilities by default:

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
required for systemd to function inside the container: mounting
filesystems, configuring cgroups, managing namespaces for its own
services. This cannot be dropped without breaking the
systemd-inside-nspawn model.

Notable exclusions: `CAP_SYS_MODULE` (no kernel module loading),
`CAP_SYS_RAWIO` (no raw I/O port access), `CAP_SYS_TIME` (no system
clock modification), `CAP_BPF` (no BPF program loading),
`CAP_SYSLOG`, and `CAP_IPC_LOCK`.

sdme provides fine-grained capability management:

- `--drop-capability CAP_X`: drop individual capabilities from nspawn's
  default set. Accepts names with or without the `CAP_` prefix.
- `--capability CAP_X`: add capabilities not in the default set (e.g.
  `CAP_NET_ADMIN` for containers with `--private-network`).

Both flags are repeatable and validated against a known set of Linux
capabilities. Specifying the same capability in both is rejected as
contradictory.

### Seccomp filtering

nspawn applies a built-in allowlist-based seccomp filter. Syscalls not
on the allowlist are blocked with `EPERM` (for known syscalls) or
`ENOSYS` (for unknown ones).

Allowed by default: `@basic-io`, `@file-system`, `@io-event`, `@ipc`,
`@mount`, `@network-io`, `@process`, `@resources`, `@setuid`, `@signal`,
`@sync`, `@timer`, and about 50 individual syscalls.

Blocked unconditionally: `kexec_load`, `kexec_file_load`,
`perf_event_open`, `fanotify_init`, `open_by_handle_at`, `quotactl`,
the `@swap` group, and the `@cpu-emulation` group.

Capability-gated: `@clock` requires `CAP_SYS_TIME`, `@module` requires
`CAP_SYS_MODULE`, `@raw-io` requires `CAP_SYS_RAWIO`. Since none of
these capabilities are in the default bounding set, these syscall groups
are effectively blocked.

`--system-call-filter` layers additional seccomp filters on top of
nspawn's baseline. It uses systemd's group syntax:

- `@group`: allow a syscall group
- `~@group`: deny a syscall group

```
sdme create mybox --system-call-filter ~@raw-io
sdme create mybox --system-call-filter ~@cpu-emulation
```

The flag is repeatable. Note that `~@mount` breaks systemd inside the
container, the same reason nspawn allows it in the first place.

### Mandatory access control

sdme ships a default AppArmor profile (`sdme-default`) designed for
systemd-nspawn system containers. The profile allows the operations
required for systemd boot (mount, pivot_root, signal, unix sockets)
while denying dangerous host-level access (raw device I/O, `/proc`
sysctl writes, kernel module paths). It is applied via
`AppArmorProfile=` in the systemd service unit drop-in.

The profile is automatically applied by `--strict`. It can also be used
standalone:

```
sdme create mybox --apparmor-profile sdme-default
```

To install the profile:

```
sdme config apparmor-profile > /etc/apparmor.d/sdme-default
apparmor_parser -r /etc/apparmor.d/sdme-default
```

The deb and rpm packages install and load the profile automatically.

**SELinux is not supported.** sdme has no SELinux integration. During
rootfs import (`sdme fs import`), `security.selinux` extended
attributes are explicitly skipped because they do not transfer
meaningfully between filesystems.

### Privilege escalation prevention

**`--no-new-privileges`** passes `--no-new-privileges=yes` to nspawn.
Off by default because interactive containers typically want `sudo`/`su`
to work; `no_new_privs` blocks privilege escalation via setuid binaries
and file capabilities. Enabled by `--hardened` and `--strict`.

**`--read-only`** makes the overlayfs merged view read-only.
Applications needing writable areas use bind mounts (`-b`).

### The `--hardened` flag

`--hardened` is sdme's one-flag defense-in-depth bundle. It enables
multiple security layers at once:

- **User namespace isolation** (`--private-users=pick
  --private-users-ownership=auto`): container root maps to a high
  unprivileged UID on the host.
- **Private network namespace** (`--private-network`): the container
  gets its own network namespace with loopback only.
- **`--no-new-privileges=yes`**: blocks privilege escalation via setuid
  binaries and file capabilities.
- **Drops capabilities**: `CAP_SYS_PTRACE`, `CAP_NET_RAW`,
  `CAP_SYS_RAWIO`, `CAP_SYS_BOOT`, dropping 4 capabilities (3 from
  the active set; `CAP_SYS_RAWIO` is preventive since nspawn does not
  grant it by default), leaving 23 retained capabilities.

```
sdme create mybox --hardened
sdme new mybox --hardened
```

**When cloning the host rootfs** (no `-r` flag), `--hardened` has
several visible effects because the container inherits the host's
installed binaries and enabled services:

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

**Composable with fine-grained flags.** `--hardened` sets a baseline
that individual flags can override or extend:

```
sdme create mybox --hardened --capability CAP_NET_RAW       # re-enable a dropped cap
sdme create mybox --hardened --system-call-filter ~@raw-io  # add seccomp filter
sdme create mybox --hardened --apparmor-profile myprofile   # add MAC confinement
sdme create mybox --hardened --read-only                    # read-only rootfs
```

**Configurable.** The capabilities dropped by `--hardened` are
controlled by the `hardened_drop_caps` config key:

```
sdme config set hardened_drop_caps CAP_SYS_PTRACE,CAP_NET_RAW
```

### The `--strict` flag

`--strict` closes the gaps between `--hardened` and Docker/Podman
defaults. It implies `--hardened` and adds:

- **Aggressive capability drops**: retains only the ~14 capabilities
  Docker grants (AUDIT_WRITE, CHOWN, DAC_OVERRIDE, FOWNER, FSETID,
  KILL, MKNOD, NET_BIND_SERVICE, SETFCAP, SETGID, SETPCAP, SETUID,
  SYS_CHROOT) plus `CAP_SYS_ADMIN` (required for systemd init). Also
  drops `CAP_NET_RAW` (carried over from `--hardened`, stricter than
  Docker). Drops 27 capabilities total.
- **Seccomp filters**: denies `@cpu-emulation`, `@debug`, `@obsolete`,
  and `@raw-io` syscall groups on top of nspawn's baseline filter.
- **AppArmor profile**: applies the `sdme-default` profile, which
  confines `/proc`/`/sys` writes and raw device access at the MAC level.

```
sdme create mybox --strict
sdme new mybox --strict
```

**When cloning the host rootfs**, `--strict` compounds the effects of
`--hardened` with additional restrictions:

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

**Why `CAP_SYS_ADMIN` is retained.** `CAP_SYS_ADMIN` is required for
systemd to function inside the container. It needs to mount filesystems,
configure cgroups, and manage namespaces for its own services. With user
namespace isolation (enabled by `--strict`), `CAP_SYS_ADMIN` is scoped
to the user namespace. It does not grant host-level SYS_ADMIN. A process
that escapes the container lands in an unprivileged context on the host.

**Composable with fine-grained flags.** Like `--hardened`, `--strict`
sets a baseline that individual flags can override:

```
sdme create mybox --strict --capability CAP_NET_RAW   # re-enable a dropped cap
sdme create mybox --strict --read-only                # add read-only rootfs
sdme create mybox --strict --apparmor-profile custom  # use a custom profile
```

### Input sanitization

sdme runs as root and handles untrusted input: tarballs from the
internet, OCI images from public registries, QCOW2 disk images from
unknown sources. Several hardening measures are in place:

**Path traversal prevention.** OCI layer tar paths are sanitised before
extraction: `..` components are rejected and leading `/` is stripped.
Whiteout marker handling verifies (via `canonicalize()`) that the target
path stays within the destination directory before deleting anything.

**Digest validation.** OCI blob digests (`sha256:abc123...`) are
validated for safe characters (alphanumeric and hex only) and correct
length (64 chars for SHA-256, 128 for SHA-512) before being used to
construct filesystem paths. A malicious manifest cannot use the digest
field for directory traversal.

**Download size cap.** URL downloads are capped at 50 GiB
(`MAX_DOWNLOAD_SIZE`), checked during streaming. A malicious or
misbehaving server cannot fill the disk by sending an unbounded
response.

**Rootfs name validation.** The `-r`/`--fs` parameter (on `create` and
`new`) is validated with `validate_name()` (alphanumeric, hyphens, no
leading/trailing hyphens, no `..`) before being used to construct
filesystem paths.

**Opaque directory validation.** Paths must be absolute, contain no
`..` components, no empty strings, no duplicates. Normalised before
storage.

**Permission hardening.** Config files are written with mode `0o600`,
config directories with `0o700`. Overlayfs work directories get mode
`0o700`.

**Umask enforcement.** Container creation refuses to proceed if the
process umask strips read or execute from "other"
(`umask & 005 != 0`). A restrictive umask would make overlayfs
upper-layer files inaccessible to non-root services like dbus-daemon,
preventing container boot. This actually happened during development
when setting umask to 007 before the `sdme create` command, would
result in `sdme start` mysteriously misbehaving.

If you find a way to escape a container, traverse a path, or corrupt
the host filesystem through sdme, please open an issue.

## 16. Reliability

Multi-step operations in sdme are designed to fail cleanly rather than
leave broken state behind.

**Transactional imports** use a staging directory
(`.{name}.importing`) that is atomically renamed on success. Partial
imports are either cleaned up immediately or detected and reported on
the next run.

**Cooperative interrupt handling** uses a global `AtomicBool` flag set
by a POSIX `SIGINT` handler. The handler is installed without
`SA_RESTART`, so blocking system calls (file reads, network I/O) return
`EINTR` immediately. Import loops, boot-wait loops, and build
operations check the flag between steps, allowing Ctrl+C to cancel
cleanly at any point. The handler also restores the default `SIGINT`
disposition after the first press, so a second Ctrl+C force-kills the
process. This covers cases where Rust's stdlib retries
`poll()`/`connect()` on EINTR, preventing cooperative cancellation
during blocked DNS resolution or TCP connection attempts.

**Boot failure cleanup** differs by intent: `sdme new` removes the
container on boot or join failure (the user wanted a running container,
not a broken one), while `sdme start` (from previous `sdme create`)
preserves it for debugging.

**Health checks** in `sdme ps` detect containers with missing
directories or missing rootfs and report them as `broken` rather than
crashing or silently hiding them.

**Build failure cleanup** removes the staging container and any partial
rootfs on error, regardless of which build step failed.

If you find a way to leave sdme's state inconsistent (a container that
can't be listed, removed, or recovered), please open an issue.
