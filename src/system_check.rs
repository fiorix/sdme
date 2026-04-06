//! Runtime dependency and version checks.
//!
//! Verifies that the host has a compatible systemd version and that
//! required external programs (systemd-nspawn, machinectl, etc.) are
//! available in PATH.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::systemd;

/// Parse the major version number from a systemd version string.
///
/// Extracts leading digits: `"255-1ubuntu1"` returns `255`.
pub fn parse_systemd_version(version: &str) -> Result<u32> {
    let digits: String = version.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        bail!("cannot parse systemd version: {version:?}");
    }
    digits
        .parse::<u32>()
        .map_err(|e| anyhow::anyhow!("cannot parse systemd version: {e}"))
}

/// Check that systemd is >= min_version.
/// Reads the "Version" property from org.freedesktop.systemd1.Manager via D-Bus.
pub fn check_systemd_version(min_version: u32) -> Result<()> {
    let version_str = systemd::systemd_version()?;
    let version = parse_systemd_version(&version_str)?;
    if version < min_version {
        bail!("systemd {min_version} or later is required (found {version})");
    }
    Ok(())
}

/// Find a program in PATH, returning its full path.
///
/// Checks that the candidate is a regular file and has at least one
/// execute bit set (user, group, or other).
pub fn find_program(name: &str) -> Result<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let path_var = std::env::var("PATH").unwrap_or_default();
    for dir in path_var.split(':') {
        let candidate = PathBuf::from(dir).join(name);
        if let Ok(meta) = std::fs::metadata(&candidate) {
            if meta.is_file() && (meta.permissions().mode() & 0o111 != 0) {
                return Ok(candidate);
            }
        }
    }
    bail!("{name} not found in PATH")
}

/// Check that all required external programs are available.
///
/// `programs` is a slice of `(binary_name, package_hint)` pairs.
/// With `verbose`, prints the resolved path for each program.
pub fn check_dependencies(programs: &[(&str, &str)], verbose: bool) -> Result<()> {
    for (name, hint) in programs {
        match find_program(name) {
            Ok(path) => {
                if verbose {
                    eprintln!("found {name}: {}", path.display());
                }
            }
            Err(_) => {
                bail!("{name} not found; install it with: {hint}");
            }
        }
    }
    Ok(())
}

// Linux mount API syscall numbers (stable ABI, same on x86_64 and aarch64).
const SYS_OPEN_TREE: libc::c_long = 428;
const SYS_MOUNT_SETATTR: libc::c_long = 442;

const OPEN_TREE_CLONE: libc::c_uint = 1;
const OPEN_TREE_CLOEXEC: libc::c_uint = libc::O_CLOEXEC as libc::c_uint;
const AT_RECURSIVE: libc::c_uint = 0x8000;
const MOUNT_ATTR_IDMAP: u64 = 0x0010_0000;

/// Argument struct for `mount_setattr(2)`, matching the kernel's `struct mount_attr`.
#[repr(C)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

/// Clone a mount tree via `open_tree(2)`.
///
/// Returns a file descriptor for the cloned mount, or an OS error.
unsafe fn sys_open_tree(dfd: libc::c_int, path: *const libc::c_char, flags: libc::c_uint) -> i64 {
    libc::syscall(SYS_OPEN_TREE, dfd, path, flags)
}

/// Apply mount attributes via `mount_setattr(2)`.
unsafe fn sys_mount_setattr(
    dfd: libc::c_int,
    path: *const libc::c_char,
    flags: libc::c_uint,
    attr: *const MountAttr,
    size: libc::size_t,
) -> i64 {
    libc::syscall(SYS_MOUNT_SETATTR, dfd, path, flags, attr, size)
}

/// Probe whether the kernel supports idmapped mounts on overlayfs.
///
/// Creates a temporary overlayfs mount under `datadir`, then attempts
/// the same `open_tree(OPEN_TREE_CLONE)` + `mount_setattr(MOUNT_ATTR_IDMAP)`
/// sequence that systemd-nspawn uses internally for `--private-users-ownership=auto`.
/// This tells us whether nspawn will use fast idmapped mounts or fall back
/// to slow recursive chown.
///
/// Must be called as root. The temporary mount and directories are cleaned
/// up before returning.
pub fn probe_idmap_on_overlayfs(datadir: &Path) -> Result<()> {
    let pid = std::process::id();
    let probe_dir = datadir.join(format!(".idmap-probe-{pid}"));

    // Set up temporary overlayfs directories.
    let lower = probe_dir.join("lower");
    let upper = probe_dir.join("upper");
    let work = probe_dir.join("work");
    let merged = probe_dir.join("merged");
    for d in [&lower, &upper, &work, &merged] {
        std::fs::create_dir_all(d).with_context(|| format!("failed to create {}", d.display()))?;
    }

    // Mount a minimal overlayfs.
    let opts = format!(
        "lowerdir={},upperdir={},workdir={}",
        lower.display(),
        upper.display(),
        work.display()
    );
    let result = mount_overlay(&merged, &opts);
    let cleanup = || {
        let _ = umount(&merged);
        let _ = std::fs::remove_dir_all(&probe_dir);
    };

    if let Err(e) = result {
        cleanup();
        return Err(e).context("failed to mount probe overlayfs");
    }

    // Create a child process with a new user namespace to get a userns fd.
    // The child blocks on a pipe until we're done probing.
    let result = probe_idmap_on_mount(&merged);
    cleanup();
    result
}

/// Run the idmap probe on an already-mounted path.
///
/// Forks a child with CLONE_NEWUSER, writes a UID/GID map for it, then
/// uses the child's user namespace fd to attempt mount_setattr(MOUNT_ATTR_IDMAP).
fn probe_idmap_on_mount(mount_path: &Path) -> Result<()> {
    // Two pipes for synchronization:
    // - ready_pipe: child writes after unshare(CLONE_NEWUSER), parent reads to wait
    // - done_pipe:  parent closes to signal child to exit
    let mut ready_fds = [0i32; 2];
    let mut done_fds = [0i32; 2];
    if unsafe { libc::pipe(ready_fds.as_mut_ptr()) } != 0 {
        bail!("pipe() failed: {}", std::io::Error::last_os_error());
    }
    if unsafe { libc::pipe(done_fds.as_mut_ptr()) } != 0 {
        unsafe {
            libc::close(ready_fds[0]);
            libc::close(ready_fds[1]);
        }
        bail!("pipe() failed: {}", std::io::Error::last_os_error());
    }

    let child_pid = unsafe { libc::fork() };
    if child_pid < 0 {
        unsafe {
            libc::close(ready_fds[0]);
            libc::close(ready_fds[1]);
            libc::close(done_fds[0]);
            libc::close(done_fds[1]);
        }
        bail!("fork() failed: {}", std::io::Error::last_os_error());
    }

    if child_pid == 0 {
        // Child: close parent ends, enter new user namespace, signal, wait.
        unsafe {
            libc::close(ready_fds[0]); // parent reads this
            libc::close(done_fds[1]); // parent writes this

            if libc::unshare(libc::CLONE_NEWUSER) != 0 {
                libc::_exit(1);
            }

            // Signal parent that unshare is done.
            let _ = libc::write(ready_fds[1], [1u8].as_ptr().cast(), 1);
            libc::close(ready_fds[1]);

            // Block until parent signals done.
            let mut buf = [0u8; 1];
            let _ = libc::read(done_fds[0], buf.as_mut_ptr().cast(), 1);
            libc::close(done_fds[0]);
            libc::_exit(0);
        }
    }

    // Parent: close child ends.
    unsafe {
        libc::close(ready_fds[1]); // child writes this
        libc::close(done_fds[0]); // child reads this
    }

    // Wait for child to finish unshare(CLONE_NEWUSER).
    let mut buf = [0u8; 1];
    let n = unsafe { libc::read(ready_fds[0], buf.as_mut_ptr().cast(), 1) };
    unsafe { libc::close(ready_fds[0]) };
    if n <= 0 {
        // Child exited before signaling (unshare failed).
        unsafe {
            libc::close(done_fds[1]);
            libc::waitpid(child_pid, std::ptr::null_mut(), 0);
        }
        bail!("child failed to create user namespace (unshare returned non-zero)");
    }

    let result = (|| -> Result<()> {
        // Write uid_map and gid_map for the child.
        // Map container UID 0 to host UID 524288 (same range nspawn uses).
        write_id_map(child_pid, "uid_map", "0 524288 65536")?;
        write_id_map(child_pid, "gid_map", "0 524288 65536")?;

        // Open the child's user namespace.
        let userns_path = format!("/proc/{child_pid}/ns/user");
        let userns_fd = unsafe {
            libc::open(
                std::ffi::CString::new(userns_path.as_str())?.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC,
            )
        };
        if userns_fd < 0 {
            bail!(
                "failed to open {userns_path}: {}",
                std::io::Error::last_os_error()
            );
        }

        let result = do_idmap_probe(mount_path, userns_fd);
        unsafe { libc::close(userns_fd) };
        result
    })();

    // Signal child to exit and reap it.
    unsafe {
        libc::close(done_fds[1]);
        libc::waitpid(child_pid, std::ptr::null_mut(), 0);
    }

    result
}

/// Write a UID or GID map to /proc/{pid}/{file}.
///
/// Must write "deny" to setgroups first for unprivileged user namespaces
/// (required by the kernel before writing gid_map).
fn write_id_map(pid: i32, file: &str, content: &str) -> Result<()> {
    if file == "gid_map" {
        let setgroups_path = format!("/proc/{pid}/setgroups");
        std::fs::write(&setgroups_path, "deny")
            .with_context(|| format!("failed to write {setgroups_path}"))?;
    }
    let path = format!("/proc/{pid}/{file}");
    std::fs::write(&path, content).with_context(|| format!("failed to write {path}"))
}

/// Attempt `open_tree(OPEN_TREE_CLONE)` + `mount_setattr(MOUNT_ATTR_IDMAP)`.
///
/// This replicates what nspawn does in `remount_idmap()`. If both syscalls
/// succeed, the kernel supports idmapped mounts on this filesystem.
fn do_idmap_probe(mount_path: &Path, userns_fd: i32) -> Result<()> {
    let c_path = std::ffi::CString::new(mount_path.as_os_str().as_encoded_bytes())
        .context("mount path contains null byte")?;

    let tree_fd = unsafe {
        sys_open_tree(
            libc::AT_FDCWD,
            c_path.as_ptr(),
            OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC,
        )
    };
    if tree_fd < 0 {
        let err = std::io::Error::last_os_error();
        bail!("open_tree(OPEN_TREE_CLONE) failed: {err}");
    }
    let tree_fd = tree_fd as i32;

    let attr = MountAttr {
        attr_set: MOUNT_ATTR_IDMAP,
        attr_clr: 0,
        propagation: 0,
        userns_fd: userns_fd as u64,
    };
    let empty = std::ffi::CString::new("").unwrap();
    // Match nspawn's remount_idmap_fd exactly: AT_EMPTY_PATH without
    // AT_RECURSIVE. nspawn does not use AT_RECURSIVE for the idmap probe.
    let ret = unsafe {
        sys_mount_setattr(
            tree_fd,
            empty.as_ptr(),
            libc::AT_EMPTY_PATH as libc::c_uint,
            &attr,
            std::mem::size_of::<MountAttr>(),
        )
    };
    unsafe { libc::close(tree_fd) };

    if ret < 0 {
        let err = std::io::Error::last_os_error();
        bail!("mount_setattr(MOUNT_ATTR_IDMAP) failed: {err}");
    }

    Ok(())
}

/// Mount an overlayfs at the given path.
pub(crate) fn mount_overlay(target: &Path, opts: &str) -> Result<()> {
    let c_target = std::ffi::CString::new(target.as_os_str().as_encoded_bytes())
        .context("target path contains null byte")?;
    let c_fstype = std::ffi::CString::new("overlay").unwrap();
    let c_source = std::ffi::CString::new("overlay").unwrap();
    let c_opts = std::ffi::CString::new(opts.as_bytes()).context("opts contains null byte")?;
    let ret = unsafe {
        libc::mount(
            c_source.as_ptr(),
            c_target.as_ptr(),
            c_fstype.as_ptr(),
            0,
            c_opts.as_ptr().cast(),
        )
    };
    if ret != 0 {
        bail!(
            "mount overlayfs on {}: {}",
            target.display(),
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

/// Unmount a filesystem.
pub(crate) fn umount(target: &Path) -> Result<()> {
    let c_target = std::ffi::CString::new(target.as_os_str().as_encoded_bytes())
        .context("target path contains null byte")?;
    let ret = unsafe { libc::umount(c_target.as_ptr()) };
    if ret != 0 {
        bail!(
            "umount {}: {}",
            target.display(),
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_systemd_version_plain() {
        assert_eq!(parse_systemd_version("259").unwrap(), 259);
    }

    #[test]
    fn test_parse_systemd_version_with_suffix() {
        assert_eq!(parse_systemd_version("255-1ubuntu1").unwrap(), 255);
    }

    #[test]
    fn test_parse_systemd_version_empty() {
        assert!(parse_systemd_version("").is_err());
    }

    #[test]
    fn test_mount_attr_size() {
        // The kernel expects exactly 32 bytes for struct mount_attr.
        assert_eq!(std::mem::size_of::<MountAttr>(), 32);
    }
}
