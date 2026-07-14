//! Shared filesystem copy utilities.
//!
//! Provides recursive directory copying that preserves ownership, permissions,
//! timestamps, extended attributes, and special file types (symlinks, devices,
//! fifos, sockets). Used by both the import and build modules.

use std::collections::HashMap;
use std::ffi::CString;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs as unix_fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::check_interrupted;

/// Maps `(st_dev, st_ino)` to the first destination path for hard link preservation.
pub(crate) type HardLinkMap = HashMap<(u64, u64), PathBuf>;

/// Recursively copy all entries from `src_dir` to `dst_dir`.
pub(crate) fn copy_tree(src_dir: &Path, dst_dir: &Path, verbose: bool) -> Result<()> {
    let mut hardlinks = HardLinkMap::new();
    copy_tree_inner(src_dir, dst_dir, verbose, &mut hardlinks, false)
}

/// Like [`copy_tree`], but symlink-safe for writing into a tree that may hold
/// untrusted pre-existing entries (a btrfs container subvolume holding the base
/// image). Before writing each destination entry, an existing symlink there is
/// removed so the write cannot be redirected through it (in the worst case onto
/// the host, since sdme runs as root and is not chrooted). Existing real
/// directories are merged into rather than failed on. Use for `sdme cp` writes
/// into a btrfs container; the overlay backend writes into a fresh upper layer
/// and must use plain [`copy_tree`] (unchanged behavior).
pub(crate) fn copy_tree_shadowed(src_dir: &Path, dst_dir: &Path, verbose: bool) -> Result<()> {
    let mut hardlinks = HardLinkMap::new();
    copy_tree_inner(src_dir, dst_dir, verbose, &mut hardlinks, true)
}

fn copy_tree_inner(
    src_dir: &Path,
    dst_dir: &Path,
    verbose: bool,
    hardlinks: &mut HardLinkMap,
    shadow: bool,
) -> Result<()> {
    let entries = fs::read_dir(src_dir)
        .with_context(|| format!("failed to read directory {}", src_dir.display()))?;

    for entry in entries {
        check_interrupted()?;
        let entry =
            entry.with_context(|| format!("failed to read entry in {}", src_dir.display()))?;
        let src_path = entry.path();
        let file_name = entry.file_name();
        let dst_path = dst_dir.join(&file_name);

        copy_entry_inner(&src_path, &dst_path, verbose, hardlinks, shadow)
            .with_context(|| format!("failed to copy {}", src_path.display()))?;
    }

    Ok(())
}

/// Copy a single filesystem entry (file, dir, symlink, device, fifo, socket).
pub(crate) fn copy_entry(src: &Path, dst: &Path, verbose: bool) -> Result<()> {
    let mut hardlinks = HardLinkMap::new();
    copy_entry_inner(src, dst, verbose, &mut hardlinks, false)
}

/// Symlink-safe variant of [`copy_entry`]; see [`copy_tree_shadowed`].
pub(crate) fn copy_entry_shadowed(src: &Path, dst: &Path, verbose: bool) -> Result<()> {
    let mut hardlinks = HardLinkMap::new();
    copy_entry_inner(src, dst, verbose, &mut hardlinks, true)
}

fn copy_entry_inner(
    src: &Path,
    dst: &Path,
    verbose: bool,
    hardlinks: &mut HardLinkMap,
    shadow: bool,
) -> Result<()> {
    // When writing into a tree that may hold untrusted base-image symlinks,
    // replace any pre-existing symlink at `dst` with the real entry so the
    // write (and every recursive child write) cannot be redirected outside the
    // tree. Without this, `fs::copy` opens the destination without O_NOFOLLOW
    // and would follow a base-image symlink child onto the host.
    if shadow {
        shadow_symlink(dst)?;
    }

    let stat = lstat_entry(src)?;
    let mode = stat.st_mode & libc::S_IFMT;

    match mode {
        libc::S_IFDIR => {
            // In shadow mode an existing real directory (from the base image) is
            // merged into rather than failed on; a symlink there was already
            // removed above. Otherwise a fresh directory is expected.
            if !(shadow && dst.is_dir()) {
                fs::create_dir(dst)
                    .with_context(|| format!("failed to create directory {}", dst.display()))?;
            }
            copy_metadata_from_stat(dst, &stat)?;
            copy_xattrs(src, dst)?;
            copy_tree_inner(src, dst, verbose, hardlinks, shadow)?;
        }
        libc::S_IFREG => {
            if stat.st_nlink > 1 {
                let key = (stat.st_dev, stat.st_ino);
                if let Some(existing) = hardlinks.get(&key) {
                    fs::hard_link(existing, dst).with_context(|| {
                        format!(
                            "failed to hard link {} -> {}",
                            dst.display(),
                            existing.display()
                        )
                    })?;
                    return Ok(());
                }
                hardlinks.insert(key, dst.to_path_buf());
            }
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

/// Read extended attributes from `path`, skipping security.selinux
/// (labels are policy-specific and must be derived from the active
/// policy via restorecon/autorelabel, not carried from the source).
pub(crate) fn read_xattrs(path: &Path) -> Result<Vec<(CString, Vec<u8>)>> {
    let c_path = path_to_cstring(path)?;

    // Get the size of the xattr name list.
    let size = unsafe { libc::llistxattr(c_path.as_ptr(), std::ptr::null_mut(), 0) };
    if size < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOTSUP) || err.raw_os_error() == Some(libc::ENODATA) {
            return Ok(Vec::new());
        }
        return Err(err).with_context(|| format!("llistxattr failed for {}", path.display()));
    }
    if size == 0 {
        return Ok(Vec::new());
    }

    let mut names_buf = vec![0u8; size as usize];
    let size = unsafe {
        libc::llistxattr(
            c_path.as_ptr(),
            names_buf.as_mut_ptr() as *mut libc::c_char,
            names_buf.len(),
        )
    };
    if size < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("llistxattr failed for {}", path.display()));
    }

    let mut result = Vec::new();
    let names_buf = &names_buf[..size as usize];
    for name_bytes in names_buf.split(|&b| b == 0) {
        if name_bytes.is_empty() {
            continue;
        }

        // Skip security.selinux: labels reference the source policy's
        // types/roles which may not exist on the destination system.
        // Correct labeling requires restorecon against the active policy.
        if name_bytes.starts_with(b"security.selinux") {
            continue;
        }

        let c_name =
            CString::new(name_bytes).with_context(|| "xattr name contains interior null byte")?;

        // Get xattr value size.
        let val_size =
            unsafe { libc::lgetxattr(c_path.as_ptr(), c_name.as_ptr(), std::ptr::null_mut(), 0) };
        if val_size < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENODATA) {
                continue;
            }
            return Err(err).with_context(|| {
                format!(
                    "lgetxattr failed for {} attr {}",
                    path.display(),
                    c_name.to_string_lossy()
                )
            });
        }

        let mut val_buf = vec![0u8; val_size as usize];
        let val_size = unsafe {
            libc::lgetxattr(
                c_path.as_ptr(),
                c_name.as_ptr(),
                val_buf.as_mut_ptr() as *mut libc::c_void,
                val_buf.len(),
            )
        };
        if val_size < 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| {
                format!(
                    "lgetxattr failed for {} attr {}",
                    path.display(),
                    c_name.to_string_lossy()
                )
            });
        }
        val_buf.truncate(val_size as usize);
        result.push((c_name, val_buf));
    }

    Ok(result)
}

/// Copy extended attributes from `src` to `dst`, skipping security.selinux
/// (see `read_xattrs` for rationale).
pub(crate) fn copy_xattrs(src: &Path, dst: &Path) -> Result<()> {
    let xattrs = read_xattrs(src)?;
    if xattrs.is_empty() {
        return Ok(());
    }

    let c_dst = path_to_cstring(dst)?;
    for (c_name, val_buf) in &xattrs {
        let ret = unsafe {
            libc::lsetxattr(
                c_dst.as_ptr(),
                c_name.as_ptr(),
                val_buf.as_ptr() as *const libc::c_void,
                val_buf.len(),
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
    let mounts = crate::submounts::find_mounts_under(dir)?;
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
    let remaining = crate::submounts::find_mounts_under(dir)?;
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

/// Reject a write whose path, resolved component by component under `root`,
/// would traverse a symlink already present in the tree.
///
/// The overlay backend writes into a fresh, empty upper layer, so an
/// image-supplied symlink in the base rootfs (e.g. `/var/lib` -> `/etc`, a
/// merged-usr `/bin` -> `usr/bin`, or an absolute symlink that resolves onto
/// the host) can never redirect the write. The btrfs backend writes directly
/// into the container's subvolume, which already holds the base tree, so such
/// a symlink ancestor could redirect `create_dir_all`/`write` outside the
/// subvolume, in the worst case onto the host filesystem. This walks each
/// existing component of `rel` under `root` and bails if any is a symlink, so
/// only real directories are ever descended into.
pub(crate) fn reject_symlinked_path(root: &Path, rel: &str) -> Result<()> {
    let mut cur = root.to_path_buf();
    for part in rel.split('/').filter(|s| !s.is_empty()) {
        cur.push(part);
        if let Ok(m) = fs::symlink_metadata(&cur) {
            if m.file_type().is_symlink() {
                bail!(
                    "refusing to write through symlink {} in the container root; a \
                     malformed or hostile base image could redirect the write outside \
                     the container (use the symlink's real target path instead)",
                    cur.display()
                );
            }
        }
    }
    Ok(())
}

/// Remove a leaf path if it is a symlink, so a subsequent write creates a real
/// file in place rather than following the base image's symlink (e.g. a Debian
/// `/etc/resolv.conf` -> systemd stub, or an absolute symlink that would escape
/// onto the host). Mirrors how the overlay upper layer shadows a lower-layer
/// symlink with a real file. Intended for the btrfs backend, whose writes land
/// in the base tree itself.
pub(crate) fn shadow_symlink(path: &Path) -> Result<()> {
    if let Ok(m) = fs::symlink_metadata(path) {
        if m.file_type().is_symlink() {
            fs::remove_file(path)
                .with_context(|| format!("failed to replace symlink {}", path.display()))?;
        }
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn test_copy_tree_preserves_hard_links() {
        let src = crate::testutil::TempDataDir::new("copy-hl-src");
        let dst = crate::testutil::TempDataDir::new("copy-hl-dst");
        let out = dst.path().join("out");
        fs::create_dir(&out).unwrap();

        // Create file `a` and hard link `b`.
        fs::write(src.path().join("a"), "hardlink-test").unwrap();
        fs::hard_link(src.path().join("a"), src.path().join("b")).unwrap();

        copy_tree(src.path(), &out, false).unwrap();

        let ino_a = fs::metadata(out.join("a")).unwrap().ino();
        let ino_b = fs::metadata(out.join("b")).unwrap().ino();
        assert_eq!(ino_a, ino_b, "hard links should share the same inode");
        assert_eq!(fs::metadata(out.join("a")).unwrap().nlink(), 2);
    }

    #[test]
    fn test_copy_tree_hardlinks_across_subdirs() {
        let src = crate::testutil::TempDataDir::new("copy-hl-cross-src");
        let dst = crate::testutil::TempDataDir::new("copy-hl-cross-dst");
        let out = dst.path().join("out");
        fs::create_dir(&out).unwrap();

        fs::create_dir(src.path().join("dir1")).unwrap();
        fs::create_dir(src.path().join("dir2")).unwrap();
        fs::write(src.path().join("dir1/a"), "cross-dir-hl").unwrap();
        fs::hard_link(src.path().join("dir1/a"), src.path().join("dir2/b")).unwrap();

        copy_tree(src.path(), &out, false).unwrap();

        let ino_a = fs::metadata(out.join("dir1/a")).unwrap().ino();
        let ino_b = fs::metadata(out.join("dir2/b")).unwrap().ino();
        assert_eq!(ino_a, ino_b, "cross-dir hard links should share inode");
    }

    #[test]
    fn test_reject_symlinked_path_real_dirs_ok() {
        // A path whose every existing component is a real directory passes,
        // and components that do not exist yet are fine (create_dir_all makes
        // them real dirs).
        let tmp = crate::testutil::TempDataDir::new("reject-ok");
        fs::create_dir_all(tmp.path().join("usr/local/bin")).unwrap();
        reject_symlinked_path(tmp.path(), "usr/local/bin/tool").unwrap();
        reject_symlinked_path(tmp.path(), "etc/does/not/exist/yet").unwrap();
    }

    #[test]
    fn test_reject_symlinked_path_ancestor_symlink_bails() {
        // A merged-usr style symlink ancestor (/bin -> usr/bin) is rejected so a
        // write can never be redirected through it.
        let tmp = crate::testutil::TempDataDir::new("reject-sym");
        fs::create_dir_all(tmp.path().join("usr/bin")).unwrap();
        unix_fs::symlink("usr/bin", tmp.path().join("bin")).unwrap();
        let err = reject_symlinked_path(tmp.path(), "bin/tool").unwrap_err();
        assert!(
            err.to_string().contains("symlink"),
            "expected symlink rejection, got: {err}"
        );
    }

    #[test]
    fn test_reject_symlinked_path_absolute_symlink_escape_bails() {
        // An absolute symlink (data -> /) that would resolve onto the host is
        // rejected before any component beneath it is touched.
        let tmp = crate::testutil::TempDataDir::new("reject-abs");
        unix_fs::symlink("/", tmp.path().join("data")).unwrap();
        let err = reject_symlinked_path(tmp.path(), "data/etc/passwd").unwrap_err();
        assert!(err.to_string().contains("symlink"), "got: {err}");
    }

    #[test]
    fn test_copy_tree_shadowed_merges_and_shadows_nested() {
        // Merges into an existing real directory and shadows a nested symlink
        // child (an absolute symlink that must never be followed), while a plain
        // copy_tree would follow it and write through onto the escape target.
        let tmp = crate::testutil::TempDataDir::new("shadowed-merge");
        let dst = tmp.path().join("dst");
        fs::create_dir_all(dst.join("sub")).unwrap();
        let escape = tmp.path().join("escape");
        unix_fs::symlink(&escape, dst.join("sub/link")).unwrap();

        let src = tmp.path().join("src");
        fs::create_dir_all(src.join("sub")).unwrap();
        fs::write(src.join("sub/link"), "real").unwrap(); // collides with the symlink
        fs::write(src.join("new"), "added").unwrap();

        copy_tree_shadowed(&src, &dst, false).unwrap();

        // The colliding entry is now a real file in dst, not a followed symlink.
        let landed = dst.join("sub/link");
        assert!(landed.symlink_metadata().unwrap().file_type().is_file());
        assert_eq!(fs::read_to_string(&landed).unwrap(), "real");
        // New sibling merged in; existing dir preserved; escape target untouched.
        assert_eq!(fs::read_to_string(dst.join("new")).unwrap(), "added");
        assert!(
            !escape.exists(),
            "shadowed copy followed a symlink and escaped"
        );
    }

    #[test]
    fn test_copy_tree_shadowed_symlink_dir_ancestor() {
        // A nested directory child that exists as a symlink in the destination
        // is shadowed (replaced by a real dir) before descending, so files
        // written beneath it stay inside dst.
        let tmp = crate::testutil::TempDataDir::new("shadowed-dir");
        let dst = tmp.path().join("dst");
        fs::create_dir_all(&dst).unwrap();
        let escape_dir = tmp.path().join("escape-dir");
        fs::create_dir_all(&escape_dir).unwrap();
        unix_fs::symlink(&escape_dir, dst.join("d")).unwrap(); // d -> outside dst

        let src = tmp.path().join("src");
        fs::create_dir_all(src.join("d")).unwrap();
        fs::write(src.join("d/f"), "x").unwrap();

        copy_tree_shadowed(&src, &dst, false).unwrap();

        assert!(dst
            .join("d")
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_dir());
        assert_eq!(fs::read_to_string(dst.join("d/f")).unwrap(), "x");
        assert!(
            !escape_dir.join("f").exists(),
            "descent followed a symlinked directory and escaped"
        );
    }

    #[test]
    fn test_shadow_symlink_removes_symlink_only() {
        let tmp = crate::testutil::TempDataDir::new("shadow");
        // A symlink leaf is removed so a later write creates a real file.
        let link = tmp.path().join("resolv.conf");
        unix_fs::symlink("../run/systemd/resolve/stub-resolv.conf", &link).unwrap();
        shadow_symlink(&link).unwrap();
        assert!(
            link.symlink_metadata().is_err(),
            "symlink should have been removed"
        );
        // A real file is left untouched.
        let real = tmp.path().join("real");
        fs::write(&real, "keep").unwrap();
        shadow_symlink(&real).unwrap();
        assert_eq!(fs::read_to_string(&real).unwrap(), "keep");
        // A missing path is a no-op.
        shadow_symlink(&tmp.path().join("missing")).unwrap();
    }

    #[test]
    fn test_copy_entry_standalone_no_tracking() {
        let src = crate::testutil::TempDataDir::new("copy-entry-standalone-src");
        let dst = crate::testutil::TempDataDir::new("copy-entry-standalone-dst");

        // Create a file with nlink > 1.
        fs::write(src.path().join("a"), "standalone").unwrap();
        fs::hard_link(src.path().join("a"), src.path().join("b")).unwrap();

        // copy_entry on a single file succeeds (data copy, no tracking).
        copy_entry(&src.path().join("a"), &dst.path().join("a-copy"), false).unwrap();
        assert_eq!(
            fs::read_to_string(dst.path().join("a-copy")).unwrap(),
            "standalone"
        );
    }
}
