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

mod contained;
pub(crate) use contained::copy_contained;

/// Maps `(st_dev, st_ino)` to the first destination path for hard link preservation.
pub(crate) type HardLinkMap = HashMap<(u64, u64), PathBuf>;

/// Recursively copy all entries from `src_dir` to `dst_dir`.
pub(crate) fn copy_tree(src_dir: &Path, dst_dir: &Path, verbose: bool) -> Result<()> {
    let mut hardlinks = HardLinkMap::new();
    copy_tree_inner(src_dir, dst_dir, verbose, &mut hardlinks)
}

fn copy_tree_inner(
    src_dir: &Path,
    dst_dir: &Path,
    verbose: bool,
    hardlinks: &mut HardLinkMap,
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

        copy_entry_inner(&src_path, &dst_path, verbose, hardlinks)
            .with_context(|| format!("failed to copy {}", src_path.display()))?;
    }

    Ok(())
}

/// Copy a single filesystem entry (file, dir, symlink, device, fifo, socket).
pub(crate) fn copy_entry(src: &Path, dst: &Path, verbose: bool) -> Result<()> {
    let mut hardlinks = HardLinkMap::new();
    copy_entry_inner(src, dst, verbose, &mut hardlinks)
}

fn copy_entry_inner(
    src: &Path,
    dst: &Path,
    verbose: bool,
    hardlinks: &mut HardLinkMap,
) -> Result<()> {
    let stat = lstat_entry(src)?;
    let mode = stat.st_mode & libc::S_IFMT;

    match mode {
        libc::S_IFDIR => {
            // A fresh directory is expected.
            fs::create_dir(dst)
                .with_context(|| format!("failed to create directory {}", dst.display()))?;
            copy_metadata_from_stat(dst, &stat)?;
            copy_xattrs(src, dst)?;
            copy_tree_inner(src, dst, verbose, hardlinks)?;
        }
        libc::S_IFREG => {
            if stat.st_nlink > 1 {
                let key = (stat.st_dev, stat.st_ino);
                if let Some(existing) = hardlinks.get(&key) {
                    // link(2) refuses to replace an existing destination, so
                    // remove a non-directory destination first: re-copying
                    // over a populated tree must behave like the fs::copy
                    // branch, which truncates an existing destination file. A
                    // directory is left alone and fails the link below.
                    if let Ok(m) = fs::symlink_metadata(dst) {
                        if !m.is_dir() {
                            fs::remove_file(dst)
                                .with_context(|| format!("failed to replace {}", dst.display()))?;
                        }
                    }
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
/// Writes into a container or rootfs destination land in a tree whose content
/// sdme does not control: an imported rootfs, a btrfs subvolume holding the
/// base image, or an overlay upper populated by a container run or an earlier
/// copy can all hold symlinks (e.g. `/var/lib` -> `/etc`, a merged-usr
/// `/bin` -> `usr/bin`, or an absolute symlink that resolves onto the host).
/// Such a symlink ancestor could redirect `create_dir_all`/`write` outside
/// the tree, in the worst case onto the host filesystem. This walks each
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
/// file in place rather than following the tree's symlink (e.g. a Debian
/// `/etc/resolv.conf` -> systemd stub, or an absolute symlink that would escape
/// onto the host). Mirrors how the overlay upper layer shadows a lower-layer
/// symlink with a real file. Intended for writes into trees whose content sdme
/// does not control (imported rootfs, container subvolume or populated upper).
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
    fn test_copy_contained_merges_and_shadows_nested() {
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

        copy_contained(&dst, Path::new(""), &src).unwrap();

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
    fn test_copy_contained_shadows_nested_directory_symlink() {
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

        copy_contained(&dst, Path::new(""), &src).unwrap();

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
    fn test_copy_tree_hardlink_overwrites_existing_destination() {
        // Re-copying a hardlinked pair over a destination that already has
        // real files at those names must replace them (the fs::copy branch
        // truncates; the hardlink branch must not fail with EEXIST).
        let src = crate::testutil::TempDataDir::new("copy-hl-over-src");
        let dst = crate::testutil::TempDataDir::new("copy-hl-over-dst");
        let out = dst.path().join("out");
        fs::create_dir(&out).unwrap();

        fs::write(src.path().join("a"), "new-content").unwrap();
        fs::hard_link(src.path().join("a"), src.path().join("b")).unwrap();
        fs::write(out.join("a"), "old-content").unwrap();
        fs::write(out.join("b"), "old-content").unwrap();

        copy_tree(src.path(), &out, false).unwrap();

        assert_eq!(fs::read_to_string(out.join("a")).unwrap(), "new-content");
        let ino_a = fs::metadata(out.join("a")).unwrap().ino();
        let ino_b = fs::metadata(out.join("b")).unwrap().ino();
        assert_eq!(ino_a, ino_b, "replaced files should share the same inode");
        assert_eq!(fs::metadata(out.join("a")).unwrap().nlink(), 2);
    }

    #[test]
    fn test_copy_tree_hardlink_destination_directory_errors() {
        // A directory at the link name is not removed; the link fails instead
        // of silently replacing the directory.
        let src = crate::testutil::TempDataDir::new("copy-hl-dir-src");
        let dst = crate::testutil::TempDataDir::new("copy-hl-dir-dst");
        let out = dst.path().join("out");
        fs::create_dir(&out).unwrap();

        fs::write(src.path().join("a"), "content").unwrap();
        fs::hard_link(src.path().join("a"), src.path().join("b")).unwrap();
        fs::create_dir(out.join("b")).unwrap();

        let err = copy_tree(src.path(), &out, false).unwrap_err();
        // Depending on read_dir order this fails in the fs::copy branch
        // (EISDIR) or the hard link branch; either way it must error.
        let msg = format!("{err:#}");
        assert!(
            msg.contains("hard link") || msg.contains("Is a directory"),
            "unexpected error: {msg}"
        );
        assert!(
            out.join("b").symlink_metadata().unwrap().is_dir(),
            "destination directory must not be removed"
        );
    }

    #[test]
    fn test_copy_contained_unlinks_hardlinked_destination() {
        // A destination file hardlinked to an outside file shares its inode:
        // truncating it in place would write the new content through the
        // other link. Contained copies must replace the destination inode.
        let tmp = crate::testutil::TempDataDir::new("shadow-hl-dest");
        let src = tmp.path().join("source");
        let outside = tmp.path().join("outside");
        let root = tmp.path().join("root");
        fs::create_dir(&root).unwrap();
        fs::write(&src, b"replacement").unwrap();
        fs::write(&outside, b"outside original").unwrap();
        fs::hard_link(&outside, root.join("target")).unwrap();

        copy_contained(&root, Path::new("target"), &src).unwrap();

        assert_eq!(fs::read(root.join("target")).unwrap(), b"replacement");
        assert_eq!(
            fs::read(&outside).unwrap(),
            b"outside original",
            "write went through a destination hard link and escaped"
        );
        assert_eq!(
            fs::metadata(&outside).unwrap().nlink(),
            1,
            "destination should be a fresh inode, unlinked from the outside file"
        );
    }

    // --- contained engine tests ---

    #[test]
    fn test_copy_contained_ordinary_copies() {
        // Controls: ordinary file (with parent creation), directory tree
        // merge into an existing real directory, source symlink recreation,
        // and hard link preservation all work through the contained engine.
        let tmp = crate::testutil::TempDataDir::new("contained-ordinary");
        let root = tmp.path().join("root");
        fs::create_dir_all(root.join("etc")).unwrap();

        let src = tmp.path().join("src");
        fs::create_dir_all(src.join("d/sub")).unwrap();
        fs::write(src.join("d/a"), "aaa").unwrap();
        fs::write(src.join("d/sub/b"), "bbb").unwrap();
        unix_fs::symlink("a", src.join("d/link")).unwrap();
        fs::write(src.join("d/h1"), "shared").unwrap();
        fs::hard_link(src.join("d/h1"), src.join("d/h2")).unwrap();

        // File to a new path, creating parents.
        let f = tmp.path().join("conf");
        fs::write(&f, "k=v").unwrap();
        copy_contained(&root, Path::new("etc/app.conf"), &f).unwrap();
        assert_eq!(
            fs::read_to_string(root.join("etc/app.conf")).unwrap(),
            "k=v"
        );

        // Directory tree merged into an existing directory.
        fs::create_dir_all(root.join("d")).unwrap();
        fs::write(root.join("d/existing"), "old").unwrap();
        copy_contained(&root, Path::new("d"), &src.join("d")).unwrap();
        assert_eq!(fs::read_to_string(root.join("d/a")).unwrap(), "aaa");
        assert_eq!(fs::read_to_string(root.join("d/sub/b")).unwrap(), "bbb");
        assert_eq!(fs::read_to_string(root.join("d/existing")).unwrap(), "old");
        assert_eq!(
            fs::read_link(root.join("d/link"))
                .unwrap()
                .to_str()
                .unwrap(),
            "a",
            "source symlink must be recreated as a symlink"
        );
        let ino1 = fs::metadata(root.join("d/h1")).unwrap().ino();
        let ino2 = fs::metadata(root.join("d/h2")).unwrap().ino();
        assert_eq!(ino1, ino2, "hard links must share an inode");
        assert_eq!(fs::read_to_string(root.join("d/h2")).unwrap(), "shared");
    }

    #[test]
    fn test_copy_contained_contents_into_root() {
        // An empty relative path (e.g. COPY . /) copies the source
        // directory's contents into the root itself.
        let tmp = crate::testutil::TempDataDir::new("contained-root");
        let root = tmp.path().join("root");
        fs::create_dir_all(&root).unwrap();
        let src = tmp.path().join("src");
        fs::create_dir_all(src.join("sub")).unwrap();
        fs::write(src.join("sub/x"), "x").unwrap();

        copy_contained(&root, Path::new(""), &src).unwrap();
        assert_eq!(fs::read_to_string(root.join("sub/x")).unwrap(), "x");
    }

    #[test]
    fn test_copy_contained_rejects_ancestor_symlink() {
        let tmp = crate::testutil::TempDataDir::new("contained-ancestor");
        let root = tmp.path().join("root");
        fs::create_dir_all(&root).unwrap();
        let outside = tmp.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("victim"), "original").unwrap();
        unix_fs::symlink(&outside, root.join("etc")).unwrap();

        let src = tmp.path().join("payload");
        fs::write(&src, "attacker").unwrap();
        let err = copy_contained(&root, Path::new("etc/victim"), &src).unwrap_err();
        assert!(format!("{err:#}").contains("symlink"), "got: {err:#}");
        assert_eq!(
            fs::read_to_string(outside.join("victim")).unwrap(),
            "original"
        );
        assert_eq!(fs::read_dir(&outside).unwrap().count(), 1);
    }

    #[test]
    fn test_copy_contained_shadows_leaf_symlink() {
        let tmp = crate::testutil::TempDataDir::new("contained-leaf");
        let root = tmp.path().join("root");
        fs::create_dir_all(&root).unwrap();
        let outside = tmp.path().join("outside");
        unix_fs::symlink(&outside, root.join("f")).unwrap();

        let src = tmp.path().join("payload");
        fs::write(&src, "data").unwrap();
        copy_contained(&root, Path::new("f"), &src).unwrap();

        assert!(root
            .join("f")
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_file());
        assert_eq!(fs::read_to_string(root.join("f")).unwrap(), "data");
        assert!(!outside.exists(), "write escaped through the leaf symlink");
    }

    #[test]
    fn test_copy_contained_leaf_swap_churn_never_escapes() {
        // A concurrent process swaps the destination leaf between a symlink
        // to an outside path and nothing, in a loop, while copies land. The
        // outside path must never be created or written; copies either
        // succeed or fail, never escape.
        let tmp = crate::testutil::TempDataDir::new("contained-leaf-churn");
        let root = tmp.path().join("root");
        fs::create_dir_all(root.join("d")).unwrap();
        let outside = tmp.path().join("outside");
        let src = tmp.path().join("payload");
        fs::write(&src, "data").unwrap();

        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let handle = {
            let stop = stop.clone();
            let leaf = root.join("d/f");
            let outside = outside.clone();
            std::thread::spawn(move || {
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    let _ = fs::remove_file(&leaf);
                    let _ = unix_fs::symlink(&outside, &leaf);
                }
            })
        };

        for _ in 0..200 {
            // Success or rejection are both fine; escaping is not.
            let _ = copy_contained(&root, Path::new("d/f"), &src);
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        handle.join().unwrap();

        assert!(
            !outside.exists(),
            "a copy escaped through a concurrently swapped leaf"
        );
        // After the churn stops, an ordinary copy succeeds.
        copy_contained(&root, Path::new("d/f"), &src).unwrap();
        assert_eq!(fs::read_to_string(root.join("d/f")).unwrap(), "data");
    }

    #[test]
    fn test_copy_contained_ancestor_swap_churn_never_escapes() {
        // A concurrent process swaps an ancestor directory for a symlink to
        // an outside directory and back, in a loop. Copies may land in the
        // (renamed, still in-tree) real directory or be rejected; the
        // outside directory must never gain an entry.
        let tmp = crate::testutil::TempDataDir::new("contained-anc-churn");
        let root = tmp.path().join("root");
        fs::create_dir_all(root.join("x")).unwrap();
        let outside = tmp.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        let src = tmp.path().join("payload");
        fs::write(&src, "data").unwrap();

        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let handle = {
            let stop = stop.clone();
            let x = root.join("x");
            let x_saved = root.join("x.saved");
            let outside = outside.clone();
            std::thread::spawn(move || {
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    // Swap the real dir aside and plant a symlink; then undo.
                    // Every step can lose the race; that is the point.
                    if fs::rename(&x, &x_saved).is_ok() {
                        if unix_fs::symlink(&outside, &x).is_ok() {
                            let _ = fs::remove_file(&x);
                        }
                        let _ = fs::rename(&x_saved, &x);
                    }
                }
            })
        };

        for i in 0..200 {
            let rel = format!("x/f{i}");
            let _ = copy_contained(&root, Path::new(&rel), &src);
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        handle.join().unwrap();

        // Undo any in-flight swap so the assertions see a stable tree.
        let _ = fs::remove_file(root.join("x"));
        let _ = fs::rename(root.join("x.saved"), root.join("x"));
        assert!(
            fs::read_dir(&outside).unwrap().next().is_none(),
            "a copy escaped through a concurrently swapped ancestor"
        );
        // After the churn stops, an ordinary copy succeeds.
        copy_contained(&root, Path::new("x/final"), &src).unwrap();
        assert_eq!(fs::read_to_string(root.join("x/final")).unwrap(), "data");
    }

    #[test]
    fn test_copy_contained_hardlink_over_symlink() {
        // Hard link preservation must not re-create a shadowed symlink: the
        // first copied name for an inode shadows the symlink, and the second
        // name links to the real file, regardless of read_dir order.
        let tmp = crate::testutil::TempDataDir::new("shadow-hl");
        let dst = tmp.path().join("dst");
        fs::create_dir_all(&dst).unwrap();
        let escape = tmp.path().join("escape");
        unix_fs::symlink(&escape, dst.join("a")).unwrap();

        let src = tmp.path().join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("a"), "payload").unwrap();
        fs::hard_link(src.join("a"), src.join("b")).unwrap();

        copy_contained(&dst, Path::new(""), &src).unwrap();

        assert!(dst
            .join("a")
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_file());
        let ino_a = fs::metadata(dst.join("a")).unwrap().ino();
        let ino_b = fs::metadata(dst.join("b")).unwrap().ino();
        assert_eq!(ino_a, ino_b, "hard links should share the same inode");
        assert_eq!(fs::read_to_string(dst.join("a")).unwrap(), "payload");
        assert!(
            !escape.exists(),
            "hard link creation followed a symlink and escaped"
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
