# Wiring OCI into systemd-nspawn

**Alexandre Fiori, March 2026**

## 1. The Problem

OCI container images are built for Docker's execution model. Two assumptions
in that model break under systemd-nspawn:

1. **User resolution happens pre-chroot.** Docker resolves the image's `User`
   field inside the container filesystem. systemd's `User=` directive resolves
   via NSS on the host filesystem, before entering `RootDirectory=`. Users
   that exist only inside the OCI rootfs (e.g. `nginx`, UID 101) cause
   exit code 217/USER.

2. **Standard file descriptors are pipes, not sockets.** Docker connects
   fds 0/1/2 to pipes (or ptys). systemd connects them to journal sockets.
   OCI images commonly symlink log files to `/dev/stdout` or `/dev/stderr`
   (e.g. nginx). When the application opens the symlink chain through
   `/proc/self/fd/N`, the kernel rejects `open()` on socket-backed fds
   with ENXIO.

sdme solves both with generated static binaries deployed at import time:
a privilege-dropping ELF (`drop_privs`, under 1 KiB) and an LD_PRELOAD
shared library (`devfd_shim`, approximately 4 KiB). Neither has a libc
dependency; both use raw syscalls and are generated entirely in Rust.

## 2. Privilege Dropping

### The systemd limitation

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

### The solution

sdme generates a static ELF binary (`drop_privs`) that performs privilege
dropping via raw syscalls, with no libc dependency and no NSS. The binary
is invoked as:

```
/.sdme-drop-privs <uid> <gid> <workdir> <command> [args...]
```

The syscall sequence:

1. `setgroups(0, NULL)`: clear supplementary groups
2. `setgid(gid)`: set group ID (must happen before setuid)
3. `setuid(uid)`: set user ID (irreversible for non-zero UIDs)
4. `chdir(workdir)`: change to the application's working directory
5. `execve(command, args, envp)`: replace the process with the application

Each syscall is checked for errors. On failure, a diagnostic message is
written to stderr and the process exits with code 1.

### User resolution

The OCI `User` field is resolved at import time against `etc/passwd` and
`etc/group` inside the OCI rootfs:

| Format            | Behavior                                            |
|-------------------|-----------------------------------------------------|
| `""`, `"root"`    | Root; uses standard `User=root` unit                |
| `"name"`          | Resolved via `etc/passwd` in OCI rootfs             |
| `"uid"`           | Used directly; primary GID from passwd if found     |
| `"name:group"`    | User from `etc/passwd`, group from `etc/group`      |
| `"uid:gid"`       | Both used directly                                  |

### Security model

The privilege-dropping sequence is designed to be irreversible:

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

## 3. The /dev/std* Shim

### The journal socket problem

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

### Alternatives considered

**eBPF** cannot solve this. `bpf_override_return` can inject error codes,
but it cannot fabricate file descriptors. Returning a valid fd from
`open()` requires allocating a kernel `struct file` and installing it in
the process's fd table. No eBPF hook is capable of this.

**Removing the symlinks** works but means log output goes to files inside
the chroot instead of the journal. Since the whole point of running under
systemd is journal integration, losing log output to files defeats the
purpose.

### The solution

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

### Why dup() instead of returning the raw fd

Returning the raw fd number (0, 1, or 2) would work for simple cases, but
callers expect `open()` to return a new, independently closeable fd. If we
returned fd 2 directly and the caller later called `close()`, stderr would
be closed for the entire process. `dup()` gives the caller their own fd
that they can close without affecting the original.

### Path matching

The interceptor uses 8-byte loads and integer comparisons organized as a
prefix tree. No string function calls:

1. Load the first 8 bytes as a 64-bit integer.
2. Compare against `/dev/std` (8 bytes). On match, check for `in\0`,
   `out\0`, `err\0` at offset 8.
3. Compare against `/dev/fd/` (8 bytes). On match, check for `0\0`,
   `1\0`, `2\0` at offset 8.
4. Compare against `/proc/se` (8 bytes). On match, check for
   `lf/fd/0\0`, `lf/fd/1\0`, `lf/fd/2\0` at offset 8.
5. No match: call the real `openat` syscall.

### ENXIO fallback

If the real `openat` syscall returns `-ENXIO`, the interceptor resolves
one level of symlink via `readlinkat` and retries the path matching against
the resolved target. This handles cases like nginx opening
`/var/log/nginx/error.log`, which is a symlink to `/dev/stderr`. Without
this fallback, only direct opens of `/dev/std*` paths would be intercepted.

On error (from `dup` or a non-ENXIO `openat` failure), the shim sets
`errno` via `__errno_location()` (imported through the GOT, resolved by
the dynamic linker at load time) and returns `-1` per C convention.

The `open()` entry point rewrites its arguments to match the `openat()`
calling convention (inserting `AT_FDCWD` as the directory fd) and jumps
to the `openat` entry point. `open64` and `openat64` are aliases since
they are identical on 64-bit Linux.

## 4. Integration

Both binaries are deployed during `sdme fs import` of an OCI application
image (one imported with `--base-fs`):

1. The OCI image config's `User` field is parsed.
2. The `devfd_shim` shared library is written to `/.sdme-devfd-shim.so`
   inside the OCI root (mode `0o444`, readable for mmap).
3. If the user is non-root, the name is resolved against `etc/passwd` and
   `etc/group` inside the OCI rootfs, and the `drop_privs` binary is
   written to `/.sdme-drop-privs` (mode `0o111`, execute-only).
4. A systemd service unit (`sdme-oci-app.service`) is generated with
   both binaries wired in.

### Generated unit (non-root user)

Both the privilege dropper and the devfd shim appear in the same unit:

```ini
[Service]
Type=exec
RootDirectory=/oci/root
MountAPIVFS=yes
Environment=LD_PRELOAD=/.sdme-devfd-shim.so
EnvironmentFile=-/oci/env
ExecStart=/.sdme-drop-privs 101 101 / /docker-entrypoint.sh nginx -g 'daemon off;'
```

`LD_PRELOAD` loads the devfd shim into the application's address space.
`ExecStart` invokes the privilege dropper, which sets uid/gid and then
exec's the actual entrypoint.

### Generated unit (root user)

For root users, `drop_privs` is not needed. The devfd shim still applies:

```ini
[Service]
Type=exec
RootDirectory=/oci/root
MountAPIVFS=yes
Environment=LD_PRELOAD=/.sdme-devfd-shim.so
ExecStart=/docker-entrypoint.sh nginx -g 'daemon off;'
WorkingDirectory=/
EnvironmentFile=-/oci/env
User=root
```

## 5. Implementation Notes

### Architecture support

Both binaries are generated at import time for the host architecture:

| Binary       | x86_64            | aarch64          | Size    |
|--------------|-------------------|------------------|---------|
| `drop_privs` | `syscall`, rax=nr | `svc #0`, x8=nr  | < 1 KiB |
| `devfd_shim` | `syscall`, rax=nr | `svc #0`, x8=nr  | ~ 4 KiB |

Both are generated entirely in Rust with no assembler, no external tools,
and no libc. Each architecture module contains its own `Asm` struct with
a label/fixup system tailored to the ISA: x86_64 uses rel8/rel32 fixups
for variable-length instructions; aarch64 uses BCond/Branch26 fixups for
fixed 4-byte instructions.

### ELF structure

`drop_privs` is a minimal ET_EXEC static ELF64 with:

- ELF header + 1 program header (PT_LOAD RX)
- Machine code (the syscall sequence)
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

### Module layout

| File                         | Purpose                                 |
|------------------------------|-----------------------------------------|
| `src/drop_privs/mod.rs`     | Public API: `generate(Arch) -> Vec<u8>` |
| `src/drop_privs/elf.rs`     | ET_EXEC ELF builder                     |
| `src/drop_privs/x86_64.rs`  | x86_64 machine code emitter             |
| `src/drop_privs/aarch64.rs` | AArch64 machine code emitter            |
| `src/devfd_shim/mod.rs`     | Public API: `generate(Arch) -> Vec<u8>` |
| `src/devfd_shim/elf.rs`     | ET_DYN ELF builder with SysV hash table |
| `src/devfd_shim/x86_64.rs`  | x86_64 machine code emitter             |
| `src/devfd_shim/aarch64.rs` | AArch64 machine code emitter            |

Both architecture modules use the same pattern: an `Asm` struct that emits
machine code bytes, a label system for forward references, and a fixup pass
that patches relative offsets once all labels are defined. The `elf` module
in each crate assembles the ELF headers, program headers, and metadata
tables around the emitted code.
