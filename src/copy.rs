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
    copy_tree_inner(src_dir, dst_dir, verbose, &mut hardlinks)
}

/// Like [`copy_tree`], but safe for writing into a tree that may hold
/// untrusted pre-existing entries (an imported rootfs, a btrfs container
/// subvolume holding the base image, an overlay upper populated by a
/// container run or an earlier copy), including under concurrent mutation of
/// that tree. Implemented by the fd-relative contained engine below: no
/// operation beneath `dst_dir` ever resolves a symlink present in (or swapped
/// into) the tree. Existing real directories are merged into; a symlink leaf
/// is unlinked and recreated. `dst_dir` itself must already exist and is now
/// rejected if it is a symlink (previously it was followed).
// Retained for API compatibility with callers on other branches; production
// destinations go through copy_contained, which also contains the ancestors.
#[allow(dead_code)]
pub(crate) fn copy_tree_shadowed(src_dir: &Path, dst_dir: &Path, _verbose: bool) -> Result<()> {
    let c = path_to_cstring(dst_dir)?;
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::ELOOP) {
            return Err(refuse_symlink(dst_dir));
        }
        return Err(e).with_context(|| format!("failed to open directory {}", dst_dir.display()));
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    copy_children_at(&fd, dst_dir, src_dir, &mut FdHardLinkMap::new())
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

/// Contained variant of [`copy_entry`]; see [`copy_tree_shadowed`]. `dst` is
/// interpreted as `parent + leaf name`; the parent is resolved once (it is
/// the caller's trusted anchor), and the leaf is handled fd-relative beneath
/// it, safe against concurrent swaps of the leaf.
// Retained for API compatibility with callers on other branches; production
// destinations go through copy_contained, which also contains the ancestors.
#[allow(dead_code)]
pub(crate) fn copy_entry_shadowed(src: &Path, dst: &Path, _verbose: bool) -> Result<()> {
    let parent = dst.parent().unwrap_or(Path::new("/"));
    let name = dst
        .file_name()
        .with_context(|| format!("invalid destination {}", dst.display()))?;
    copy_contained(parent, Path::new(name), src)
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

// --- fd-relative contained copy engine ---
//
// Writing into a destination tree that a container or another process can
// mutate concurrently (a running container's live root via merged/ or
// /proc/<pid>/root, an imported rootfs, a populated overlay upper) cannot be
// made safe by checking a path and then writing to it: any component can be
// swapped for a symlink between the check and the write, and sdme runs as
// root without chroot. This engine instead pins the write root with an open
// directory fd, resolves every component beneath it fd-relative with
// O_NOFOLLOW, writes through the returned fds, applies metadata with
// fd-relative calls, and recreates hard links with linkat(AT_EMPTY_PATH)
// from the pinned first copy, so no operation ever resolves a symlink that
// is present in, or swapped into, the destination tree.
//
// Policy matches the path-based guard above: a symlink among the
// destination's ancestors is rejected, a symlink (or a multiply-linked
// regular file) at the destination leaf is unlinked and recreated, existing
// real directories are merged into, and source symlinks are recreated as
// symlinks.

use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};

/// Maximum attempts to create or shadow a destination leaf while a
/// concurrent process keeps swapping it; exceeding this fails the copy
/// rather than spinning.
const LEAF_SWAP_RETRIES: u32 = 8;

/// Maps `(st_dev, st_ino)` to an open fd of the first destination copy, so a
/// second name is linkat(AT_EMPTY_PATH)'d from the pinned inode instead of
/// re-resolving its path.
type FdHardLinkMap = HashMap<(u64, u64), OwnedFd>;

fn cstring(name: &std::ffi::OsStr) -> Result<CString> {
    CString::new(name.as_bytes()).with_context(|| "name contains null byte")
}

fn refuse_symlink(display: &Path) -> anyhow::Error {
    anyhow::anyhow!(
        "refusing to write through symlink {} in the destination; a malformed or \
         hostile image could redirect the write outside the destination (use the \
         symlink's real target path instead)",
        display.display()
    )
}

/// Open the write root as a directory fd. The anchor is sdme-controlled
/// (the fs/ tree, a container's upper/ or merged/ view, /proc/<pid>/root)
/// and resolved once; everything beneath it is fd-relative.
fn open_dest_root(path: &Path) -> Result<OwnedFd> {
    let c = path_to_cstring(path)?;
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("failed to open destination root {}", path.display()));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Open a directory beneath `parent`, never following a symlink.
fn open_dir_nofollow(parent: &OwnedFd, name: &CString) -> std::io::Result<OwnedFd> {
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn unlink_at(parent: &OwnedFd, name: &CString, display: &Path) -> Result<()> {
    let ret = unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("failed to remove destination leaf {}", display.display()));
    }
    Ok(())
}

fn mkdir_at(parent: &OwnedFd, name: &CString, display: &Path) -> Result<()> {
    let ret = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o777) };
    if ret != 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EEXIST) {
            return Err(e)
                .with_context(|| format!("failed to create directory {}", display.display()));
        }
    }
    Ok(())
}

fn fstatat_nofollow(parent: &OwnedFd, name: &CString) -> std::io::Result<libc::stat> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    let ret = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            &mut stat,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(stat)
}

/// Stat `name` beneath `parent` without following; classifies the ENOTDIR
/// that O_DIRECTORY|O_NOFOLLOW returns for a symlink-to-directory.
fn classify_not_dir(parent: &OwnedFd, name: &CString, display: &Path) -> anyhow::Error {
    match fstatat_nofollow(parent, name) {
        Ok(st) if st.st_mode & libc::S_IFMT == libc::S_IFLNK => refuse_symlink(display),
        _ => anyhow::anyhow!(
            "destination component is not a directory: {}",
            display.display()
        ),
    }
}

/// Open ancestor directory `name` beneath `parent`, creating it if missing.
/// A symlink there is rejected, never raced: it could redirect the write
/// outside the destination, and removing an ancestor under a concurrent
/// writer cannot be done safely.
fn ensure_dir_at(parent: &OwnedFd, name: &std::ffi::OsStr, display: &Path) -> Result<OwnedFd> {
    let c = cstring(name)?;
    match open_dir_nofollow(parent, &c) {
        Ok(fd) => Ok(fd),
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => Err(refuse_symlink(display)),
        Err(e) if e.raw_os_error() == Some(libc::ENOTDIR) => {
            Err(classify_not_dir(parent, &c, display))
        }
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
            mkdir_at(parent, &c, display)?;
            // Open whatever is there now; a symlink planted in the race is
            // rejected rather than followed.
            match open_dir_nofollow(parent, &c) {
                Ok(fd) => Ok(fd),
                Err(e) if e.raw_os_error() == Some(libc::ELOOP) => Err(refuse_symlink(display)),
                Err(e) if e.raw_os_error() == Some(libc::ENOTDIR) => {
                    Err(classify_not_dir(parent, &c, display))
                }
                Err(e) => Err(e)
                    .with_context(|| format!("failed to open directory {}", display.display())),
            }
        }
        Err(e) => Err(e).with_context(|| format!("failed to open directory {}", display.display())),
    }
}

/// Open or create the leaf directory for a directory copy: merge into an
/// existing real directory, atomically shadow a symlink leaf, create a
/// missing one. Retries bound the race against a concurrent process that
/// keeps re-planting the leaf.
fn open_leaf_dir_at(parent: &OwnedFd, name: &std::ffi::OsStr, display: &Path) -> Result<OwnedFd> {
    let c = cstring(name)?;
    for _ in 0..LEAF_SWAP_RETRIES {
        match open_dir_nofollow(parent, &c) {
            Ok(fd) => return Ok(fd),
            Err(e)
                if e.raw_os_error() == Some(libc::ELOOP)
                    || e.raw_os_error() == Some(libc::ENOTDIR) =>
            {
                // A symlink leaf is shadowed (replaced by a real directory),
                // never followed; a real non-directory leaf is an error.
                match fstatat_nofollow(parent, &c) {
                    Ok(st) if st.st_mode & libc::S_IFMT == libc::S_IFLNK => {
                        unlink_at(parent, &c, display)?;
                        mkdir_at(parent, &c, display)?;
                    }
                    _ => bail!("destination is not a directory: {}", display.display()),
                }
            }
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
                mkdir_at(parent, &c, display)?;
            }
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("failed to open directory {}", display.display()))
            }
        }
    }
    bail!(
        "destination {} keeps changing under concurrent mutation; aborting",
        display.display()
    )
}

/// Open the leaf file `name` for writing, creating or truncating it. A
/// symlink leaf is unlinked first (shadowed); an existing regular file with
/// other hard links is unlinked first so truncating cannot write through a
/// shared inode (possibly outside the destination). Never follows a symlink,
/// even one swapped in concurrently.
fn create_file_at(parent: &OwnedFd, name: &std::ffi::OsStr, display: &Path) -> Result<OwnedFd> {
    let c = cstring(name)?;
    for _ in 0..LEAF_SWAP_RETRIES {
        match fstatat_nofollow(parent, &c) {
            Ok(st) => {
                let ft = st.st_mode & libc::S_IFMT;
                if ft == libc::S_IFLNK || (ft == libc::S_IFREG && st.st_nlink > 1) {
                    unlink_at(parent, &c, display)?;
                    continue;
                }
                // Other existing types (directory, device, ...): let the
                // open below fail with its natural error.
            }
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {}
            Err(e) => {
                return Err(e).with_context(|| format!("failed to stat {}", display.display()))
            }
        }
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                c.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o666,
            )
        };
        if fd >= 0 {
            return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
        }
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::ELOOP) {
            // Lost the race to a symlink; loop to shadow it.
            continue;
        }
        return Err(e).with_context(|| format!("failed to create {}", display.display()));
    }
    bail!(
        "destination {} keeps changing under concurrent mutation; aborting",
        display.display()
    )
}

/// Apply ownership, permissions, and timestamps from a stat result to an
/// open fd.
fn copy_metadata_to_fd(fd: RawFd, stat: &libc::stat, display: &Path) -> Result<()> {
    let ret = unsafe { libc::fchown(fd, stat.st_uid, stat.st_gid) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("fchown failed for {}", display.display()));
    }
    let ret = unsafe { libc::fchmod(fd, stat.st_mode & 0o7777) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("fchmod failed for {}", display.display()));
    }
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
    let ret = unsafe { libc::futimens(fd, times.as_ptr()) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::ENOTSUP) {
            return Err(err).with_context(|| format!("futimens failed for {}", display.display()));
        }
    }
    Ok(())
}

/// Apply ownership and timestamps to an unopenable leaf (symlink, device,
/// fifo, socket) beneath a directory fd, never following it. Permission
/// bits are set at creation by mknodat/mkfifoat; fchmodat2 fixes umask
/// masking without following where the kernel supports it.
fn copy_metadata_to_leaf_at(
    parent: &OwnedFd,
    name: &CString,
    stat: &libc::stat,
    display: &Path,
) -> Result<()> {
    let ret = unsafe {
        libc::fchownat(
            parent.as_raw_fd(),
            name.as_ptr(),
            stat.st_uid,
            stat.st_gid,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("fchownat failed for {}", display.display()));
    }
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
            parent.as_raw_fd(),
            name.as_ptr(),
            times.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::ENOTSUP) {
            return Err(err).with_context(|| format!("utimensat failed for {}", display.display()));
        }
    }
    if stat.st_mode & libc::S_IFMT != libc::S_IFLNK {
        // fchmodat2 syscall number (452 on x86_64 and aarch64, the
        // architectures sdme ships); libc 0.2.184 does not export it.
        const SYS_FCHMODAT2: libc::c_long = 452;
        let ret = unsafe {
            libc::syscall(
                SYS_FCHMODAT2,
                parent.as_raw_fd(),
                name.as_ptr(),
                stat.st_mode & 0o7777,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::ENOSYS) | Some(libc::ENOTSUP) => {
                    eprintln!(
                        "warning: cannot chmod {} without following symlinks \
                         (kernel lacks fchmodat2); mode may be umask-masked",
                        display.display()
                    );
                }
                _ => {
                    return Err(err)
                        .with_context(|| format!("fchmodat2 failed for {}", display.display()))
                }
            }
        }
    }
    Ok(())
}

/// Copy extended attributes from `src` to an open fd, skipping
/// security.selinux (see `read_xattrs` for rationale).
fn copy_xattrs_to_fd(src: &Path, fd: RawFd, display: &Path) -> Result<()> {
    let xattrs = read_xattrs(src)?;
    for (c_name, val_buf) in &xattrs {
        let ret = unsafe {
            libc::fsetxattr(
                fd,
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
                    "fsetxattr failed for {} attr {}",
                    display.display(),
                    c_name.to_string_lossy()
                )
            });
        }
    }
    Ok(())
}

/// Copy metadata and xattrs to an unopenable leaf beneath a directory fd
/// via an O_PATH handle (which fsetxattr accepts), verifying it is still the
/// entry type just created before touching it.
fn finish_leaf_at(
    parent: &OwnedFd,
    name: &CString,
    src: &Path,
    stat: &libc::stat,
    display: &Path,
) -> Result<()> {
    copy_metadata_to_leaf_at(parent, name, stat, display)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("failed to open {}", display.display()));
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::fstat(fd.as_raw_fd(), &mut st) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("fstat failed for {}", display.display()));
    }
    if st.st_mode & libc::S_IFMT != stat.st_mode & libc::S_IFMT {
        bail!(
            "destination {} changed type during the copy; aborting",
            display.display()
        );
    }
    copy_xattrs_to_fd(src, fd.as_raw_fd(), display)
}

/// Copy one source entry to leaf `name` beneath `parent`, contained.
fn copy_entry_at(
    parent: &OwnedFd,
    name: &std::ffi::OsStr,
    display: &Path,
    src: &Path,
    links: &mut FdHardLinkMap,
) -> Result<()> {
    let stat = lstat_entry(src)?;
    let mode = stat.st_mode & libc::S_IFMT;
    let c_name = cstring(name)?;

    match mode {
        libc::S_IFDIR => {
            let fd = open_leaf_dir_at(parent, name, display)?;
            copy_metadata_to_fd(fd.as_raw_fd(), &stat, display)?;
            copy_xattrs_to_fd(src, fd.as_raw_fd(), display)?;
            copy_children_at(&fd, display, src, links)?;
        }
        libc::S_IFREG => {
            if stat.st_nlink > 1 {
                let key = (stat.st_dev, stat.st_ino);
                if let Some(first) = links.get(&key) {
                    // Link the pinned inode of the first copy; an existing
                    // non-directory leaf is removed first (a directory fails).
                    match fstatat_nofollow(parent, &c_name) {
                        Ok(st) => {
                            if st.st_mode & libc::S_IFMT == libc::S_IFDIR {
                                bail!(
                                    "cannot replace directory {} with a hard link",
                                    display.display()
                                );
                            }
                            unlink_at(parent, &c_name, display)?;
                        }
                        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {}
                        Err(e) => {
                            return Err(e)
                                .with_context(|| format!("failed to stat {}", display.display()))
                        }
                    }
                    let empty = c"";
                    let ret = unsafe {
                        libc::linkat(
                            first.as_raw_fd(),
                            empty.as_ptr(),
                            parent.as_raw_fd(),
                            c_name.as_ptr(),
                            libc::AT_EMPTY_PATH,
                        )
                    };
                    if ret != 0 {
                        return Err(std::io::Error::last_os_error())
                            .with_context(|| format!("failed to hard link {}", display.display()));
                    }
                    return Ok(());
                }
            }
            let fd = create_file_at(parent, name, display)?;
            let mut src_file = fs::File::open(src)
                .with_context(|| format!("failed to open source {}", src.display()))?;
            // The File owns a duplicate fd; the original stays open for
            // metadata and the hardlink map.
            let mut dst_file: fs::File = fd
                .try_clone()
                .map(fs::File::from)
                .with_context(|| format!("failed to clone fd for {}", display.display()))?;
            std::io::copy(&mut src_file, &mut dst_file)
                .with_context(|| format!("failed to write {}", display.display()))?;
            drop(dst_file);
            copy_metadata_to_fd(fd.as_raw_fd(), &stat, display)?;
            copy_xattrs_to_fd(src, fd.as_raw_fd(), display)?;
            if stat.st_nlink > 1 {
                links.insert((stat.st_dev, stat.st_ino), fd);
            }
        }
        libc::S_IFLNK => {
            let target = fs::read_link(src)
                .with_context(|| format!("failed to read symlink {}", src.display()))?;
            let c_target = path_to_cstring(&target)?;
            // Shadow an existing symlink leaf; anything else existing fails
            // the symlinkat with EEXIST, matching previous behavior.
            for _ in 0..LEAF_SWAP_RETRIES {
                let ret = unsafe {
                    libc::symlinkat(c_target.as_ptr(), parent.as_raw_fd(), c_name.as_ptr())
                };
                if ret == 0 {
                    break;
                }
                let e = std::io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::EEXIST) {
                    match fstatat_nofollow(parent, &c_name) {
                        Ok(st) if st.st_mode & libc::S_IFMT == libc::S_IFLNK => {
                            unlink_at(parent, &c_name, display)?;
                            continue;
                        }
                        _ => {
                            return Err(e).with_context(|| {
                                format!("failed to create symlink {}", display.display())
                            })
                        }
                    }
                }
                return Err(e)
                    .with_context(|| format!("failed to create symlink {}", display.display()));
            }
            finish_leaf_at(parent, &c_name, src, &stat, display)?;
        }
        libc::S_IFBLK | libc::S_IFCHR | libc::S_IFIFO | libc::S_IFSOCK => {
            // Shadow an existing symlink leaf; an existing real node fails
            // the creation with EEXIST, matching previous behavior.
            if let Ok(st) = fstatat_nofollow(parent, &c_name) {
                if st.st_mode & libc::S_IFMT == libc::S_IFLNK {
                    unlink_at(parent, &c_name, display)?;
                }
            }
            let ret = if mode == libc::S_IFIFO {
                unsafe {
                    libc::mkfifoat(parent.as_raw_fd(), c_name.as_ptr(), stat.st_mode & 0o7777)
                }
            } else {
                let dev = if mode == libc::S_IFSOCK {
                    0
                } else {
                    stat.st_rdev
                };
                unsafe { libc::mknodat(parent.as_raw_fd(), c_name.as_ptr(), stat.st_mode, dev) }
            };
            if ret != 0 {
                return Err(std::io::Error::last_os_error())
                    .with_context(|| format!("mknodat failed for {}", display.display()));
            }
            finish_leaf_at(parent, &c_name, src, &stat, display)?;
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

/// Copy all children of `src_dir` beneath the open destination directory.
fn copy_children_at(
    dir_fd: &OwnedFd,
    dir_display: &Path,
    src_dir: &Path,
    links: &mut FdHardLinkMap,
) -> Result<()> {
    let entries = fs::read_dir(src_dir)
        .with_context(|| format!("failed to read directory {}", src_dir.display()))?;
    for entry in entries {
        check_interrupted()?;
        let entry =
            entry.with_context(|| format!("failed to read entry in {}", src_dir.display()))?;
        let name = entry.file_name();
        copy_entry_at(
            dir_fd,
            &name,
            &dir_display.join(&name),
            &entry.path(),
            links,
        )
        .with_context(|| format!("failed to copy {}", entry.path().display()))?;
    }
    Ok(())
}

/// Copy `src` to `rel` beneath `root`, safe against concurrent mutation of
/// the destination tree (a running container's live root, an imported
/// rootfs, a populated overlay upper). Every component of `rel` is resolved
/// fd-relative with O_NOFOLLOW beneath an fd pinning `root`; a symlink among
/// the ancestors is rejected, a symlink or multiply-linked file at the leaf
/// is unlinked and recreated, and existing real directories are merged into.
pub(crate) fn copy_contained(root: &Path, rel: &Path, src: &Path) -> Result<()> {
    let mut parts = Vec::new();
    for comp in rel.components() {
        match comp {
            std::path::Component::Normal(c) => parts.push(c),
            std::path::Component::CurDir => {}
            _ => bail!("refusing unsafe destination component in {}", rel.display()),
        }
    }
    let root_fd = open_dest_root(root)?;
    let mut links = FdHardLinkMap::new();
    let mut display = root.to_path_buf();
    if parts.is_empty() {
        // Copy the source directory's contents into the root itself.
        if !src.is_dir() {
            bail!(
                "cannot copy {} onto destination root {}",
                src.display(),
                root.display()
            );
        }
        return copy_children_at(&root_fd, &display, src, &mut links);
    }
    let (leaf, ancestors) = parts.split_last().unwrap();
    let mut dir_fd = root_fd;
    for anc in ancestors {
        display = display.join(anc);
        dir_fd = ensure_dir_at(&dir_fd, anc, &display)?;
    }
    display = display.join(leaf);
    copy_entry_at(&dir_fd, leaf, &display, src, &mut links)
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
    fn test_copy_entry_shadowed_unlinks_hardlinked_destination() {
        // A destination file hardlinked to an outside file shares its inode:
        // truncating it in place would write the new content through the
        // other link. Shadowed copies must unlink such a destination first.
        let tmp = crate::testutil::TempDataDir::new("shadow-hl-dest");
        let src = tmp.path().join("source");
        let outside = tmp.path().join("outside");
        let root = tmp.path().join("root");
        fs::create_dir(&root).unwrap();
        fs::write(&src, b"replacement").unwrap();
        fs::write(&outside, b"outside original").unwrap();
        fs::hard_link(&outside, root.join("target")).unwrap();

        copy_entry_shadowed(&src, &root.join("target"), false).unwrap();

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
    fn test_copy_tree_shadowed_hardlink_over_symlink() {
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

        copy_tree_shadowed(&src, &dst, false).unwrap();

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
