//! Shared filesystem copy utilities.
//!
//! Provides recursive directory copying that preserves ownership, permissions,
//! timestamps, extended attributes, and special file types (symlinks, devices,
//! fifos, sockets). Used by both the import and build modules.

use std::ffi::CString;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs as unix_fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::check_interrupted;

/// Recursively copy all entries from `src_dir` to `dst_dir`.
pub(crate) fn copy_tree(src_dir: &Path, dst_dir: &Path, verbose: bool) -> Result<()> {
    let entries = fs::read_dir(src_dir)
        .with_context(|| format!("failed to read directory {}", src_dir.display()))?;

    for entry in entries {
        check_interrupted()?;
        let entry =
            entry.with_context(|| format!("failed to read entry in {}", src_dir.display()))?;
        let src_path = entry.path();
        let file_name = entry.file_name();
        let dst_path = dst_dir.join(&file_name);

        copy_entry(&src_path, &dst_path, verbose)
            .with_context(|| format!("failed to copy {}", src_path.display()))?;
    }

    Ok(())
}

/// Copy a single filesystem entry (file, dir, symlink, device, fifo, socket).
pub(crate) fn copy_entry(src: &Path, dst: &Path, verbose: bool) -> Result<()> {
    let stat = lstat_entry(src)?;
    let mode = stat.st_mode & libc::S_IFMT;

    match mode {
        libc::S_IFDIR => {
            fs::create_dir(dst)
                .with_context(|| format!("failed to create directory {}", dst.display()))?;
            copy_metadata_from_stat(dst, &stat)?;
            copy_xattrs(src, dst)?;
            copy_tree(src, dst, verbose)?;
        }
        libc::S_IFREG => {
            fs::copy(src, dst).with_context(|| format!("failed to copy file {}", src.display()))?;
            copy_metadata_from_stat(dst, &stat)?;
            copy_xattrs(src, dst)?;
        }
        libc::S_IFLNK => {
            let target = fs::read_link(src)
                .with_context(|| format!("failed to read symlink {}", src.display()))?;
            unix_fs::symlink(&target, dst)
                .with_context(|| format!("failed to create symlink {}", dst.display()))?;
            lchown(dst, stat.st_uid, stat.st_gid)?;
            // Timestamps for symlinks.
            let c_path = path_to_cstring(dst)?;
            let times = [
                libc::timespec {
                    tv_sec: stat.st_atime,
                    tv_nsec: stat.st_atime_nsec,
                },
                libc::timespec {
                    tv_sec: stat.st_mtime,
                    tv_nsec: stat.st_mtime_nsec,
                },
            ];
            let ret = unsafe {
                libc::utimensat(
                    libc::AT_FDCWD,
                    c_path.as_ptr(),
                    times.as_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if ret != 0 {
                let err = std::io::Error::last_os_error();
                // ENOTSUP on some filesystems for symlink timestamps; not fatal.
                if err.raw_os_error() != Some(libc::ENOTSUP) {
                    return Err(err)
                        .with_context(|| format!("utimensat failed for {}", dst.display()));
                }
            }
            copy_xattrs(src, dst)?;
        }
        libc::S_IFBLK | libc::S_IFCHR => {
            let c_path = path_to_cstring(dst)?;
            let ret = unsafe { libc::mknod(c_path.as_ptr(), stat.st_mode, stat.st_rdev) };
            if ret != 0 {
                return Err(std::io::Error::last_os_error())
                    .with_context(|| format!("mknod failed for {}", dst.display()));
            }
            copy_metadata_from_stat(dst, &stat)?;
            copy_xattrs(src, dst)?;
        }
        libc::S_IFIFO => {
            let c_path = path_to_cstring(dst)?;
            let ret = unsafe { libc::mkfifo(c_path.as_ptr(), stat.st_mode & 0o7777) };
            if ret != 0 {
                return Err(std::io::Error::last_os_error())
                    .with_context(|| format!("mkfifo failed for {}", dst.display()));
            }
            copy_metadata_from_stat(dst, &stat)?;
            copy_xattrs(src, dst)?;
        }
        libc::S_IFSOCK => {
            let c_path = path_to_cstring(dst)?;
            let ret = unsafe {
                libc::mknod(c_path.as_ptr(), libc::S_IFSOCK | (stat.st_mode & 0o7777), 0)
            };
            if ret != 0 {
                return Err(std::io::Error::last_os_error())
                    .with_context(|| format!("mknod (socket) failed for {}", dst.display()));
            }
            copy_metadata_from_stat(dst, &stat)?;
            copy_xattrs(src, dst)?;
        }
        _ => {
            eprintln!(
                "warning: skipping unknown file type {:o} for {}",
                mode,
                src.display()
            );
        }
    }

    Ok(())
}

/// Apply ownership, permissions, and timestamps from a stat result to `dst`.
pub(crate) fn copy_metadata_from_stat(dst: &Path, stat: &libc::stat) -> Result<()> {
    let c_path = path_to_cstring(dst)?;

    // Ownership.
    let ret = unsafe { libc::lchown(c_path.as_ptr(), stat.st_uid, stat.st_gid) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("lchown failed for {}", dst.display()));
    }

    // Permission bits (skip for symlinks; chmod doesn't apply to them).
    let file_type = stat.st_mode & libc::S_IFMT;
    if file_type != libc::S_IFLNK {
        let ret = unsafe { libc::chmod(c_path.as_ptr(), stat.st_mode & 0o7777) };
        if ret != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("chmod failed for {}", dst.display()));
        }
    }

    // Timestamps with nanosecond precision.
    let times = [
        libc::timespec {
            tv_sec: stat.st_atime,
            tv_nsec: stat.st_atime_nsec,
        },
        libc::timespec {
            tv_sec: stat.st_mtime,
            tv_nsec: stat.st_mtime_nsec,
        },
    ];
    let ret = unsafe {
        libc::utimensat(
            libc::AT_FDCWD,
            c_path.as_ptr(),
            times.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::ENOTSUP) {
            return Err(err).with_context(|| format!("utimensat failed for {}", dst.display()));
        }
    }

    Ok(())
}

/// Copy ownership, permissions, and timestamps from `src` to `dst`.
pub(crate) fn copy_metadata(src: &Path, dst: &Path) -> Result<()> {
    let stat = lstat_entry(src)?;
    copy_metadata_from_stat(dst, &stat)
}

/// Copy extended attributes from `src` to `dst`, skipping security.selinux.
pub(crate) fn copy_xattrs(src: &Path, dst: &Path) -> Result<()> {
    let c_src = path_to_cstring(src)?;
    let c_dst = path_to_cstring(dst)?;

    // Get the size of the xattr name list.
    let size = unsafe { libc::llistxattr(c_src.as_ptr(), std::ptr::null_mut(), 0) };
    if size < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOTSUP) || err.raw_os_error() == Some(libc::ENODATA) {
            return Ok(());
        }
        return Err(err).with_context(|| format!("llistxattr failed for {}", src.display()));
    }
    if size == 0 {
        return Ok(());
    }

    let mut names_buf = vec![0u8; size as usize];
    let size = unsafe {
        libc::llistxattr(
            c_src.as_ptr(),
            names_buf.as_mut_ptr() as *mut libc::c_char,
            names_buf.len(),
        )
    };
    if size < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("llistxattr failed for {}", src.display()));
    }

    // Parse null-terminated name list.
    let names_buf = &names_buf[..size as usize];
    for name_bytes in names_buf.split(|&b| b == 0) {
        if name_bytes.is_empty() {
            continue;
        }

        // Skip security.selinux.
        if name_bytes.starts_with(b"security.selinux") {
            continue;
        }

        let c_name =
            CString::new(name_bytes).with_context(|| "xattr name contains interior null byte")?;

        // Get xattr value size.
        let val_size =
            unsafe { libc::lgetxattr(c_src.as_ptr(), c_name.as_ptr(), std::ptr::null_mut(), 0) };
        if val_size < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENODATA) {
                continue;
            }
            return Err(err).with_context(|| {
                format!(
                    "lgetxattr failed for {} attr {}",
                    src.display(),
                    c_name.to_string_lossy()
                )
            });
        }

        let mut val_buf = vec![0u8; val_size as usize];
        let val_size = unsafe {
            libc::lgetxattr(
                c_src.as_ptr(),
                c_name.as_ptr(),
                val_buf.as_mut_ptr() as *mut libc::c_void,
                val_buf.len(),
            )
        };
        if val_size < 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| {
                format!(
                    "lgetxattr failed for {} attr {}",
                    src.display(),
                    c_name.to_string_lossy()
                )
            });
        }

        let ret = unsafe {
            libc::lsetxattr(
                c_dst.as_ptr(),
                c_name.as_ptr(),
                val_buf.as_ptr() as *const libc::c_void,
                val_size as usize,
                0,
            )
        };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOTSUP) {
                return Ok(());
            }
            return Err(err).with_context(|| {
                format!(
                    "lsetxattr failed for {} attr {}",
                    dst.display(),
                    c_name.to_string_lossy()
                )
            });
        }
    }

    Ok(())
}

/// Recursively restore directory permissions so `remove_dir_all` can succeed.
pub(crate) fn make_removable(path: &Path) -> std::io::Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if meta.is_dir() {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode();
        if mode & 0o700 != 0o700 {
            fs::set_permissions(path, fs::Permissions::from_mode(mode | 0o700))?;
        }
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                let _ = make_removable(&entry.path());
            }
        }
    }
    Ok(())
}

/// Safely remove a directory tree, refusing to proceed if stale bind
/// mounts are detected underneath it.
///
/// During rootfs import, `ChrootGuard` bind-mounts `/dev`, `/proc`, `/sys`
/// from the host into the rootfs for chroot package installation. If cleanup
/// is interrupted (SIGKILL, power loss), these mounts persist. A plain
/// `remove_dir_all` on such a directory would traverse the bind mounts and
/// **delete files from the host filesystem** (e.g. `/dev/null`).
///
/// This function:
/// 1. Restores directory permissions so deletion can succeed
/// 2. Reads `/proc/self/mountinfo` to find mounts under `dir`
/// 3. Runs `umount -R` on each stale mount point
/// 4. Refuses to proceed if any mount could not be removed
pub(crate) fn safe_remove_dir(dir: &Path) -> anyhow::Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    let _ = make_removable(dir);
    unmount_stale_mounts(dir)?;
    fs::remove_dir_all(dir).with_context(|| format!("failed to remove {}", dir.display()))?;
    Ok(())
}

/// Find and remove stale bind mounts under a directory.
///
/// Returns `Ok(())` if no mounts remain. Returns `Err` if mounts could
/// not be removed, preventing the caller from accidentally deleting
/// host filesystem contents through a stale bind mount.
fn unmount_stale_mounts(dir: &Path) -> anyhow::Result<()> {
    let mounts = find_mounts_under(dir)?;
    if mounts.is_empty() {
        return Ok(());
    }

    eprintln!(
        "warning: found {} stale mount(s) under {}, unmounting",
        mounts.len(),
        dir.display()
    );

    // Unmount deepest first (mounts are sorted by path length, longest first).
    for mount_point in &mounts {
        let _ = std::process::Command::new("umount")
            .arg("-R")
            .arg(mount_point)
            .status();
    }

    // Verify all mounts are gone.
    let remaining = find_mounts_under(dir)?;
    if !remaining.is_empty() {
        let paths: Vec<String> = remaining.iter().map(|p| p.display().to_string()).collect();
        bail!(
            "refusing to remove {}: stale mounts could not be unmounted: {}",
            dir.display(),
            paths.join(", ")
        );
    }

    Ok(())
}

/// Read `/proc/self/mountinfo` and return mount points under `dir`,
/// sorted deepest-first for safe unmounting.
fn find_mounts_under(dir: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mountinfo = fs::read_to_string("/proc/self/mountinfo")
        .context("failed to read /proc/self/mountinfo")?;

    let dir_str = format!("{}/", dir.display());

    let mut mounts: Vec<PathBuf> = mountinfo
        .lines()
        .filter_map(|line| {
            // mountinfo format: id parent major:minor root mount_point options ...
            let mut fields = line.split_whitespace();
            let mount_point = fields.nth(4)?;
            // Match mounts strictly under dir (not dir itself).
            if mount_point.starts_with(&dir_str) {
                Some(PathBuf::from(mount_point))
            } else {
                None
            }
        })
        .collect();

    // Sort by path length descending (deepest first) for unmounting.
    mounts.sort_by_key(|b| std::cmp::Reverse(b.as_os_str().len()));
    Ok(mounts)
}

/// Call lstat on a path and return the raw stat result.
pub(crate) fn lstat_entry(path: &Path) -> Result<libc::stat> {
    let c_path = path_to_cstring(path)?;
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::lstat(c_path.as_ptr(), &mut stat) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("lstat failed for {}", path.display()));
    }
    Ok(stat)
}

/// Sanitize a destination path: strip leading `/` and reject `..` components
/// to prevent path traversal that could escape a target directory.
pub(crate) fn sanitize_dest_path(path: &Path) -> Result<PathBuf> {
    use std::path::Component;
    let mut clean = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                bail!("refusing path with '..' component: {}", path.display());
            }
            Component::RootDir | Component::Prefix(_) => {
                // Strip leading '/' and Windows prefixes.
            }
            Component::CurDir => {
                // Skip '.' components.
            }
            Component::Normal(c) => {
                clean.push(c);
            }
        }
    }
    Ok(clean)
}

/// Convert a path to a CString for use with libc functions.
pub(crate) fn path_to_cstring(path: &Path) -> Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .with_context(|| format!("path contains null byte: {}", path.display()))
}

/// Change ownership of a path without following symlinks.
pub(crate) fn lchown(path: &Path, uid: u32, gid: u32) -> Result<()> {
    let c_path = path_to_cstring(path)?;
    let ret = unsafe { libc::lchown(c_path.as_ptr(), uid, gid) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("lchown failed for {}", path.display()));
    }
    Ok(())
}
