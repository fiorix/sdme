//! Advisory file locking for resource protection across all mutating operations.
//!
//! Uses `flock(2)` to prevent concurrent operations from conflicting.
//! Shared (read) locks allow concurrent readers (build, export, create,
//! start) while exclusive (write) locks protect mutating operations
//! (import, remove, kube delete, pod create/remove, secret/configmap
//! create/remove).
//!
//! # Lock ordering
//!
//! When multiple locks are needed, acquire in this order to prevent
//! deadlocks:
//!
//! ```text
//! fs → containers → pods → secrets → configmaps
//! ```
//!
//! Within the same kind, acquire SHARED before EXCLUSIVE on different
//! names.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::path::Path;

use anyhow::{bail, Context, Result};

/// An advisory file lock held via `flock(2)`.
///
/// The lock is released automatically when this value is dropped (the
/// file descriptor is closed, which releases the flock). On process
/// crash or SIGKILL the kernel releases the lock.
#[derive(Debug)]
pub struct ResourceLock {
    _file: File,
}

/// Acquire a shared (read) lock on a resource.
///
/// Multiple shared locks can coexist. Returns `Err` if an exclusive
/// lock is already held.
pub fn lock_shared(datadir: &Path, kind: &str, name: &str) -> Result<ResourceLock> {
    do_lock(datadir, kind, name, libc::LOCK_SH)
}

/// Acquire an exclusive (write) lock on a resource.
///
/// No other locks (shared or exclusive) can coexist. Returns `Err` if
/// any lock is already held.
pub fn lock_exclusive(datadir: &Path, kind: &str, name: &str) -> Result<ResourceLock> {
    do_lock(datadir, kind, name, libc::LOCK_EX)
}

fn do_lock(datadir: &Path, kind: &str, name: &str, operation: libc::c_int) -> Result<ResourceLock> {
    let lock_dir = datadir.join("locks").join(kind);
    fs::create_dir_all(&lock_dir)
        .with_context(|| format!("failed to create lock directory {}", lock_dir.display()))?;

    let lock_path = lock_dir.join(format!("{name}.lock"));
    let mut file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(&lock_path)
        .with_context(|| format!("failed to open lock file {}", lock_path.display()))?;

    let ret = unsafe { libc::flock(file.as_raw_fd(), operation | libc::LOCK_NB) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::WouldBlock {
            // Read the PID from the lock file for diagnostics.
            let mut content = String::new();
            let _ = file.read_to_string(&mut content);
            let holder = content.trim();
            let action = if operation == libc::LOCK_EX {
                "lock"
            } else {
                "read-lock"
            };
            if holder.is_empty() {
                bail!("cannot {action} {kind}/{name}: locked by another process");
            } else {
                bail!("cannot {action} {kind}/{name}: locked by pid {holder}");
            }
        }
        return Err(err).with_context(|| format!("flock failed on {}", lock_path.display()));
    }

    // Write our PID for diagnostics (best-effort).
    let _ = file.set_len(0);
    let _ = file.write_all(format!("{}", std::process::id()).as_bytes());
    let _ = file.flush();

    Ok(ResourceLock { _file: file })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDataDir;

    fn tmp() -> TempDataDir {
        TempDataDir::new("lock")
    }

    #[test]
    fn test_shared_shared_ok() {
        let tmp = tmp();
        let _lock1 = lock_shared(tmp.path(), "fs", "ubuntu").unwrap();
        let _lock2 = lock_shared(tmp.path(), "fs", "ubuntu").unwrap();
        // Both shared locks coexist.
    }

    #[test]
    fn test_exclusive_blocks_shared() {
        let tmp = tmp();
        let _lock1 = lock_exclusive(tmp.path(), "fs", "ubuntu").unwrap();
        let err = lock_shared(tmp.path(), "fs", "ubuntu").unwrap_err();
        assert!(
            err.to_string().contains("locked"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_shared_blocks_exclusive() {
        let tmp = tmp();
        let _lock1 = lock_shared(tmp.path(), "fs", "ubuntu").unwrap();
        let err = lock_exclusive(tmp.path(), "fs", "ubuntu").unwrap_err();
        assert!(
            err.to_string().contains("locked"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_lock_released_on_drop() {
        let tmp = tmp();
        {
            let _lock1 = lock_exclusive(tmp.path(), "fs", "ubuntu").unwrap();
        }
        // After drop, re-acquire should succeed.
        let _lock2 = lock_exclusive(tmp.path(), "fs", "ubuntu").unwrap();
    }

    #[test]
    fn test_different_resources_independent() {
        let tmp = tmp();
        let _lock1 = lock_exclusive(tmp.path(), "fs", "ubuntu").unwrap();
        let _lock2 = lock_exclusive(tmp.path(), "fs", "debian").unwrap();
        // Different resources don't conflict.
    }

    #[test]
    fn test_different_kinds_independent() {
        let tmp = tmp();
        let _lock1 = lock_exclusive(tmp.path(), "fs", "test").unwrap();
        let _lock2 = lock_exclusive(tmp.path(), "containers", "test").unwrap();
        // Different kinds don't conflict.
    }

    #[test]
    fn test_lock_file_contains_pid() {
        let tmp = tmp();
        let _lock = lock_exclusive(tmp.path(), "fs", "pidtest").unwrap();
        let content = fs::read_to_string(tmp.path().join("locks/fs/pidtest.lock")).unwrap();
        let pid: u32 = content.trim().parse().unwrap();
        assert_eq!(pid, std::process::id());
    }
}
