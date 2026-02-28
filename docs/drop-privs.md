# drop_privs: Privilege Dropping for OCI Application Images

## The Problem

systemd's `User=` directive in service units resolves usernames to UIDs via NSS (Name Service Switch) **before** entering the `RootDirectory=` chroot. This means when an OCI image declares a user like `nginx` (UID 101), systemd tries to look it up in the **host's** `/etc/passwd`, where that user typically doesn't exist. The result is exit code **217/USER**.

This is a known limitation in systemd's execution model. The resolution order is:

1. NSS lookup of `User=` against host filesystem
2. `RootDirectory=` chroot
3. `execve()` of the service binary

Steps 1 and 2 should be reversed for container use cases, but this would require fundamental changes to systemd's execution pipeline.

### Upstream Issues

- [systemd#12498](https://github.com/systemd/systemd/issues/12498): `RootDirectory` with `User` not working. Fixed the ordering for some chroot operations, but NSS lookup still happens pre-chroot.
- [systemd#19781](https://github.com/systemd/systemd/issues/19781): RFE: allow exec units as uid without passwd entry. Open; upstream position is to use NSS registration (nss-systemd, machined) instead.
- [systemd#14806](https://github.com/systemd/systemd/issues/14806): Support uid/gids from target rootfs with `--root`. Fixed for `tmpfiles` via `fgetpwent`, but not for service execution.

## The Solution

sdme generates a tiny static ELF binary (`drop_privs`) that performs privilege dropping via raw syscalls, with no libc dependency and no NSS. The binary is under 1 KiB and supports x86_64 and aarch64.

### How It Works

The binary is invoked as:

```
/.sdme-drop-privs <uid> <gid> <workdir> <command> [args...]
```

It performs the following syscall sequence:

1. **`setgroups(0, NULL)`**: clear supplementary groups
2. **`setgid(gid)`**: set group ID (must happen before setuid)
3. **`setuid(uid)`**: set user ID (irreversible for non-zero UIDs)
4. **`chdir(workdir)`**: change to the application's working directory
5. **`execve(command, args, envp)`**: replace the process with the application

Each syscall is checked for errors. On failure, a diagnostic message is written to stderr and the process exits with code 1. The `atoi` implementation includes overflow protection to prevent wrap-around to UID 0.

### Architecture Support

The ELF binary is generated at import time matching the host architecture:

| Architecture | Syscall ABI | Binary Size |
|---|---|---|
| x86_64 | `syscall` instruction, rax=nr | < 1 KiB |
| aarch64 | `svc #0` instruction, x8=nr | < 1 KiB |

The binaries are generated purely in Rust (no assembler, no external tools) by the `src/drop_privs/` module.

## Integration with sdme

During `sdme fs import` of an OCI application image (with `--base-fs`):

1. The OCI image config's `User` field is parsed
2. If the user is non-root, the name is resolved against `etc/passwd` and `etc/group` inside the OCI rootfs
3. The `drop_privs` binary is written to `/.sdme-drop-privs` inside the OCI root (mode `0o111`)
4. The systemd unit uses `ExecStart=/.sdme-drop-privs <uid> <gid> <workdir> <command>` instead of `User=` and `WorkingDirectory=`

For root users, the standard `User=root` and `WorkingDirectory=` directives are used (no `drop_privs` needed).

### Generated Unit (non-root user)

```ini
[Service]
Type=exec
RootDirectory=/oci/root
MountAPIVFS=yes
EnvironmentFile=-/oci/env
ExecStart=/.sdme-drop-privs 101 101 / /docker-entrypoint.sh nginx -g 'daemon off;'
```

### Generated Unit (root user)

```ini
[Service]
Type=exec
RootDirectory=/oci/root
MountAPIVFS=yes
ExecStart=/docker-entrypoint.sh nginx -g 'daemon off;'
WorkingDirectory=/
EnvironmentFile=-/oci/env
User=root
```

## Security Model

The privilege-dropping sequence is designed to be irreversible:

- **`setgroups(0, NULL)`** clears all supplementary groups before any uid/gid change
- **`setgid(gid)` before `setuid(uid)`**: correct order; `setgid` requires root, so it must happen first
- **`setuid(uid)`** for non-zero UIDs is irreversible (the kernel clears all capabilities)
- **Binary permissions** (`0o111`, execute-only): non-root users cannot read, write, or delete the file
- **Binary ownership** (root:root): only root can modify or remove it
- **Parent directory**: `/` inside the chroot is owned by root, so non-root cannot unlink files from it
- **No SUID/SGID bit**: the binary runs with the caller's privileges (root, since no `User=` in the unit)
- **No file capabilities**: no `security.capability` xattr is set
- **Overflow protection**: the `atoi` implementation rejects values exceeding `u32::MAX` to prevent wrap-around to UID 0
- After `execve`, the new process inherits the dropped uid/gid and cannot regain root

### User Resolution

The OCI `User` field supports several formats:

| Format | Behavior |
|---|---|
| `""`, `"root"`, `"0"` | Root; uses standard `User=root` |
| `"name"` | Resolved via `etc/passwd` in OCI rootfs |
| `"uid"` | Used directly; primary GID from `etc/passwd` if found, else gid=uid |
| `"name:group"` | User from `etc/passwd`, group from `etc/group` |
| `"uid:gid"` | Both used directly |
