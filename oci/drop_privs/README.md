# drop_privs — Tiny Static ELF Generator for Privilege Dropping

## The Problem

OCI application containers in sdme run as systemd services inside a chroot.
The generated unit looks like this:

```ini
[Service]
Type=exec
RootDirectory=/oci/root
ExecStart=/entrypoint args...
User=101
```

systemd resolves `User=101` via NSS (Name Service Switch) **before** applying
`RootDirectory=`. The NSS lookup happens against the **host's** `/etc/passwd`,
not the chroot's. If UID 101 only exists inside the chroot (e.g. the `nginx`
user created during the OCI image build), systemd fails the unit with:

```
Failed to determine user credentials: No such process
```

This is a fundamental ordering problem in systemd: credential resolution
happens before filesystem isolation. There is no combination of `User=`,
`Group=`, `DynamicUser=`, or `SupplementaryGroups=` that solves this — the
UID must be resolvable on the host at unit start time.

## The Solution

A tiny static binary placed inside the chroot at `/.sdme-drop-privs` that
drops privileges and then exec's the real entrypoint:

```ini
[Service]
Type=exec
RootDirectory=/oci/root
ExecStart=/.sdme-drop-privs 101 101 /app /entrypoint args...
```

The service starts as root (no `User=` directive). The drop_privs binary runs
first, calls `setgid`/`setuid` to switch to the target UID/GID, changes to
the working directory, and then exec's the real program. Since NSS is never
consulted, the UID only needs to exist in the chroot's `/etc/passwd` for the
application — not for the privilege drop itself.

## Why a Custom Binary

The binary runs inside an arbitrary OCI chroot. We cannot depend on:

- **libc** — the chroot may use musl, glibc, or have no libc at all
  (e.g. distroless images, scratch-based Go images)
- **a shell** — no `/bin/sh`, no `su`, no `runuser`
- **any userspace tools** — the chroot contains only what the OCI image provides

The binary must be **fully static with zero runtime dependencies**. It talks
directly to the kernel via syscalls — no dynamic linker, no libc, no
interpreter.

## Approach: ELF Generator

Instead of cross-compiling a C or Rust program with a static libc, we take a
more direct approach: a Rust program that **emits raw ELF64 binaries** with
hand-crafted machine code. The generator:

1. Constructs a minimal ELF64 header (64 bytes) + one program header (56 bytes)
2. Emits the machine code for the syscall sequence directly
3. Outputs a complete, ready-to-run static executable

No linker. No libc. No runtime. The resulting binaries are **~500 bytes**
each — smaller than most error messages.

## Binary Behavior

```
Usage: .sdme-drop-privs <uid> <gid> <workdir> <program> [args...]
```

The binary performs this exact syscall sequence:

| Step | Syscall                  | Purpose                          |
|------|--------------------------|----------------------------------|
| 1    | Validate argc >= 5       | Ensure all required args present |
| 2    | `atoi(argv[1])` → uid    | Parse target UID from ASCII      |
| 3    | `atoi(argv[2])` → gid    | Parse target GID from ASCII      |
| 4    | `setgroups(0, NULL)`     | Drop all supplementary groups    |
| 5    | `setgid(gid)`            | Set group ID                     |
| 6    | `setuid(uid)`            | Set user ID (must be last)       |
| 7    | `chdir(argv[3])`         | Change to working directory      |
| 8    | `execve(argv[4], ...)`   | Replace process with real program|

On any error: writes a short diagnostic to stderr and exits with code 1.

The ordering matters: `setgroups` must come before `setgid`/`setuid` (once
you drop root, you can no longer modify supplementary groups), and `setuid`
must come last (once UID is non-root, you can no longer call `setgid`).

## Target Architectures

| Architecture | Syscall ABI                                         |
|--------------|-----------------------------------------------------|
| x86_64       | `rax`=nr, `rdi/rsi/rdx/r10/r8/r9`=args, `syscall`  |
| aarch64      | `x8`=nr, `x0-x5`=args, `svc #0`                     |

### Syscall Numbers

| Syscall    | x86_64 | aarch64 |
|------------|--------|---------|
| write      | 1      | 64      |
| execve     | 59     | 221     |
| exit       | 60     | 93      |
| chdir      | 80     | 49      |
| setuid     | 105    | 146     |
| setgid     | 106    | 144     |
| setgroups  | 116    | 159     |

## ELF Structure

Each generated binary has this layout:

```
Offset  Size   Content
0x00    64B    ELF64 header (e_type=ET_EXEC, static, no interpreter)
0x40    56B    PT_LOAD program header (maps entire file RX at 0x400000)
0x78    ~400B  Machine code + string data (entry point)
              x86_64: 401B code → 521B total
              aarch64: 432B code → 552B total
```

No section headers — the kernel doesn't need them to load and execute the
binary. No `.text`, `.data`, `.bss` sections. Just a program header that says
"map this file into memory and jump to offset 0x78."

## Error Handling

The binary includes rudimentary error checking:

- **argc < 5**: writes usage message to stderr, exits 1
- **atoi bad input**: non-digit character encountered or u32 overflow, exits 1
- **syscall failure**: any syscall returning negative writes the syscall name
  (e.g. "setuid", "execve") to stderr, exits 1

No errno decoding, no formatted output — just enough to diagnose which step
failed. Errors are visible in `journalctl -u <unit>`.

## Project Structure

```
oci/drop_privs/
├── Cargo.toml
├── README.md
└── src/
    ├── main.rs        # Generator CLI: emits ELF binaries to files
    ├── elf.rs         # Minimal ELF64 header builder
    ├── x86_64.rs      # x86_64 machine code emitter
    └── aarch64.rs     # aarch64 machine code emitter
```

No external dependencies. Pure `std` Rust.

## Integration with sdme

The generated ELF binaries are embedded into the sdme binary at compile time
via `include_bytes!()`. During OCI app image import (`src/import/mod.rs`),
sdme writes the architecture-appropriate binary to `/.sdme-drop-privs` in the
OCI rootfs and generates the unit with the wrapper in `ExecStart=` instead of
using `User=`.

## Build

```bash
cd oci/drop_privs
cargo run                # generates sdme-drop-privs.x86_64 and sdme-drop-privs.aarch64
```

To verify:

```bash
$ file sdme-drop-privs.*
sdme-drop-privs.aarch64: ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), statically linked, no section header
sdme-drop-privs.x86_64:  ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, no section header

$ wc -c sdme-drop-privs.*
552 sdme-drop-privs.aarch64
521 sdme-drop-privs.x86_64
```

## Testing

The binary can be tested directly:

```bash
# Usage error (too few args)
$ ./sdme-drop-privs.aarch64
usage: drop_privs <uid> <gid> <dir> <cmd> [args...]

# Bad number
$ ./sdme-drop-privs.aarch64 abc 1000 /tmp /bin/true
bad number

# Permission error (not root)
$ ./sdme-drop-privs.aarch64 1000 1000 /tmp /bin/true
setgroups

# Full privilege drop (as root)
$ sudo ./sdme-drop-privs.aarch64 65534 65534 /tmp /usr/bin/id
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)

# Working directory change
$ sudo ./sdme-drop-privs.aarch64 65534 65534 /var /usr/bin/pwd
/var

# Argument passthrough
$ sudo ./sdme-drop-privs.aarch64 65534 65534 / /usr/bin/echo hello world
hello world
```

Inside an sdme container (the actual use case):

```bash
# Copy binary into container overlay and exec
$ sudo cp sdme-drop-privs.aarch64 /var/lib/sdme/containers/mycontainer/upper/.sdme-drop-privs
$ sudo sdme exec mycontainer /.sdme-drop-privs 100 101 / /usr/bin/id
uid=100(messagebus) gid=101(messagebus) groups=101(messagebus)
```
