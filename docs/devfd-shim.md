# devfd_shim: LD_PRELOAD Shim for /dev/std* in OCI Containers

## The Problem

OCI application images commonly create symlinks from log files to the standard
file descriptors:

```
/var/log/nginx/error.log -> /dev/stderr -> /proc/self/fd/2
/var/log/nginx/access.log -> /dev/stdout -> /proc/self/fd/1
```

When the application opens its log file, the kernel follows the symlink chain
to `/proc/self/fd/N` and calls `open()` on the underlying file descriptor.

Under Docker, file descriptors 1 and 2 are pipes (or ptys). The kernel allows
`open()` on `/proc/self/fd/N` when N is a pipe, and the call succeeds.

Under systemd service management, file descriptors 1 and 2 are journal sockets.
The kernel does not allow `open()` on `/proc/self/fd/N` when N is a socket. The
call fails with `ENXIO` ("No such device or address"). This is a kernel
limitation, not a systemd one.

The distinction matters: `write()` on a socket fd works fine. Only `open()` on
`/proc/self/fd/N` fails. Applications that write directly to fd 1 or fd 2 have
no problem. Applications that open a path that resolves to `/proc/self/fd/N`
(like nginx opening its log symlinks) fail with ENXIO.

### Why not eBPF?

eBPF cannot solve this. `bpf_override_return` can inject error codes, but it
cannot fabricate file descriptors. Returning a valid fd from `open()` requires
allocating a kernel `struct file` and installing it in the process's fd table.
No eBPF hook is capable of this.

### Why not remove the symlinks?

An earlier version of sdme removed the symlinks and replaced them with regular
files. This works, but means log output goes to files inside the chroot instead
of the journal. Since the whole point of running under systemd is journal
integration, losing log output to files defeats the purpose.

## The Solution

sdme generates a tiny LD_PRELOAD shared library (`.so`) that intercepts
`open()`, `openat()`, `open64()`, and `openat64()` at the libc symbol level.
When the path matches one of the standard file descriptor paths, the
interceptor returns `dup(N)` for the appropriate fd instead of calling the
real `open()`. All other paths fall through to the real `openat` syscall.

The intercepted paths are:

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

The `dup()` call returns a new file descriptor that refers to the same
underlying kernel object (the journal socket). Since `write()` on a socket fd
works, the application can write its log output through the dup'd fd, and it
flows to the journal.

### Why dup() instead of just returning the fd number?

Returning the raw fd number (0, 1, or 2) would work for simple cases, but
callers expect `open()` to return a new, independently closeable fd. If we
returned fd 2 directly and the caller later called `close()` on it, stderr
would be closed for the entire process. `dup()` gives the caller their own fd
that they can close without affecting the original.

### Architecture support

The shared library is generated at import time matching the host architecture:

| Architecture | Syscall ABI                   | Binary Size |
|--------------|-------------------------------|-------------|
| x86_64       | `syscall` instruction, rax=nr | ~4 KiB      |
| aarch64      | `svc #0` instruction, x8=nr   | ~4 KiB      |

The binaries are generated purely in Rust (no assembler, no external tools,
no libc) by the `src/devfd_shim/` module.

### Path matching strategy

The interceptor uses 8-byte loads and integer comparisons organized as a prefix
tree for fast matching with zero string function calls:

1. Load the first 8 bytes of the path as a 64-bit integer
2. Compare against `/dev/std` (8 bytes). On match, load 4 bytes at offset 8
   and check for `in\0`, `out\0`, `err\0`
3. Compare against `/dev/fd/` (8 bytes). On match, load 2 bytes at offset 8
   and check for `0\0`, `1\0`, `2\0`
4. Compare against `/proc/se` (8 bytes). On match, load 8 bytes at offset 8
   and check for `lf/fd/0\0`, `lf/fd/1\0`, `lf/fd/2\0`
5. No match: call the real `openat` syscall with the original arguments

If the real `openat` syscall returns `-ENXIO`, the interceptor resolves one
level of symlink via the `readlinkat` syscall and retries the same path matching
against the resolved target. This handles cases like nginx opening
`/var/log/nginx/error.log`, which is a symlink to `/dev/stderr`. Without this
fallback, only direct opens of `/dev/std*` paths would be intercepted.

On error (from `dup` or a non-ENXIO `openat` failure), the shim sets `errno`
properly via `__errno_location()` (imported through the GOT and resolved by the
dynamic linker at load time) and returns `-1` per C convention.

The `open()` entry point rewrites its arguments to match the `openat()` calling
convention (inserting `AT_FDCWD` as the directory fd) and jumps to the `openat`
entry point. `open64` and `openat64` are aliases (same symbol offsets) since
they are identical on 64-bit Linux.

## Integration with sdme

During `sdme fs import` of any OCI application image (with `--base-fs`):

1. The shim `.so` is written to `/.sdme-devfd-shim.so` inside the OCI root
   (mode `0o444`, readable for mmap)
2. The generated systemd unit includes `Environment=LD_PRELOAD=/.sdme-devfd-shim.so`

The shim is deployed for all OCI containers, regardless of whether the
application runs as root or a non-root user. The path `/.sdme-devfd-shim.so`
is relative to the `RootDirectory=/oci/root` chroot.

### Generated unit (non-root user)

```ini
[Service]
Type=exec
RootDirectory=/oci/root
MountAPIVFS=yes
Environment=LD_PRELOAD=/.sdme-devfd-shim.so
EnvironmentFile=-/oci/env
ExecStart=/.sdme-drop-privs 101 101 / /docker-entrypoint.sh nginx -g 'daemon off;'
```

### Generated unit (root user)

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

## ELF structure

The generated `.so` is a minimal ET_DYN ELF64 shared library containing:

- ELF header (64 bytes)
- 3 program headers: PT_LOAD RX (code + metadata), PT_LOAD RW (GOT +
  dynamic section on next page), PT_DYNAMIC
- Machine code (the interceptor logic)
- SysV hash table (`.hash`) for symbol lookup by the dynamic linker
- Dynamic symbol table (`.dynsym`): STN_UNDEF + exported symbols (`open`,
  `openat`, `open64`, `openat64`) + imported symbols (`__errno_location`)
- Dynamic string table (`.dynstr`)
- RELA relocations (`.rela.dyn`): one `R_*_GLOB_DAT` entry per imported
  symbol, pointing the dynamic linker at the corresponding GOT slot
- GOT entries (one per import, zeroed; filled by the dynamic linker at
  load time)
- Dynamic section: DT_HASH, DT_STRTAB, DT_SYMTAB, DT_STRSZ, DT_SYMENT,
  DT_RELA, DT_RELASZ, DT_RELAENT, DT_NULL
- No section headers (not needed at runtime)

The RX segment contains the ELF header, program headers, machine code, hash
table, dynsym, dynstr, and RELA relocations. The RW segment (next page)
contains the GOT entries and the dynamic section. Total file size is
approximately 4 KiB.

## Implementation

The module structure follows the same pattern as `drop_privs`:

| File                        | Purpose                                  |
|-----------------------------|------------------------------------------|
| `src/devfd_shim/mod.rs`     | Public API: `generate(Arch) -> Vec<u8>`  |
| `src/devfd_shim/elf.rs`     | ET_DYN ELF builder with SysV hash table  |
| `src/devfd_shim/x86_64.rs`  | x86_64 machine code emitter              |
| `src/devfd_shim/aarch64.rs` | AArch64 machine code emitter             |

Both architecture modules use their own `Asm` struct with a label/fixup system
tailored to the ISA (x86_64 uses rel8/rel32 fixups for variable-length
instructions; aarch64 uses BCond/Branch26 fixups for fixed 4-byte instructions).
The `elf::Symbol` type is shared across both.
