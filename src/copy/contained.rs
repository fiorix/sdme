//! Destination traversal and inode publication for copies into mutable rootfs trees.

use std::collections::HashMap;
use std::ffi::CString;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use super::{lstat_entry, path_to_cstring, read_xattrs};
use crate::check_interrupted;

/// Maximum attempts to create or shadow a destination leaf while a
/// concurrent process keeps swapping it; exceeding this fails the copy
/// rather than spinning.
const LEAF_SWAP_RETRIES: u32 = 8;

#[cfg(test)]
thread_local! {
    static BEFORE_FILE_CREATE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    static AFTER_DIR_OPEN: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    static AFTER_FILE_CREATE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    static BEFORE_PUBLICATION: std::cell::RefCell<Option<Box<dyn FnMut()>>> = const { std::cell::RefCell::new(None) };
    static AFTER_PUBLICATION: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    static BEFORE_LEAF_METADATA: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

type InodeKey = (u64, u64);

struct LinkTarget {
    source: PathBuf,
    destination: PathBuf,
}

struct DirectoryAtime {
    inode: InodeKey,
    atime: libc::timespec,
}

/// Index selected aliases so each group can publish from one pinned inode and
/// release it immediately. External-only aliases do not need retained state.
/// Save directory atimes before inventory reads can change them. Source paths
/// are inventory, never handles for destination writes/metadata.
struct HardLinkPlan {
    pending: HashMap<InodeKey, Vec<LinkTarget>>,
    completed: HashMap<PathBuf, InodeKey>,
    directory_atimes: HashMap<PathBuf, DirectoryAtime>,
    anchor_display: PathBuf,
}

impl HardLinkPlan {
    fn new(source: &Path, destination: &Path, anchor_display: &Path) -> Result<Self> {
        let mut plan = Self {
            pending: HashMap::new(),
            completed: HashMap::new(),
            directory_atimes: HashMap::new(),
            anchor_display: anchor_display.to_path_buf(),
        };
        if destination.as_os_str().is_empty() {
            plan.scan_children(source, destination)?;
        } else {
            plan.scan(source, destination)?;
        }
        plan.pending.retain(|_, aliases| aliases.len() > 1);
        Ok(plan)
    }

    fn scan(&mut self, source: &Path, destination: &Path) -> Result<()> {
        check_interrupted()?;
        let stat = lstat_entry(source)?;
        match stat.st_mode & libc::S_IFMT {
            libc::S_IFDIR => {
                self.directory_atimes.insert(
                    source.to_path_buf(),
                    DirectoryAtime {
                        inode: (stat.st_dev, stat.st_ino),
                        atime: libc::timespec {
                            tv_sec: stat.st_atime,
                            tv_nsec: stat.st_atime_nsec,
                        },
                    },
                );
                self.scan_children(source, destination)?;
            }
            libc::S_IFREG if stat.st_nlink > 1 => {
                self.pending
                    .entry((stat.st_dev, stat.st_ino))
                    .or_default()
                    .push(LinkTarget {
                        source: source.to_path_buf(),
                        destination: destination.to_path_buf(),
                    });
            }
            _ => {}
        }
        Ok(())
    }

    fn scan_children(&mut self, source: &Path, destination: &Path) -> Result<()> {
        check_interrupted()?;
        let entries = fs::read_dir(source).with_context(|| {
            format!("failed to inventory source directory {}", source.display())
        })?;
        for entry in entries {
            let entry =
                entry.with_context(|| format!("failed to inventory {}", source.display()))?;
            self.scan(&entry.path(), &destination.join(entry.file_name()))?;
        }
        Ok(())
    }

    fn source_stat(&mut self, source: &Path) -> Result<libc::stat> {
        let mut stat = lstat_entry(source)?;
        if let Some(saved) = self.directory_atimes.remove(source) {
            if stat.st_mode & libc::S_IFMT != libc::S_IFDIR
                || (stat.st_dev, stat.st_ino) != saved.inode
            {
                bail!(
                    "source directory {} changed during the copy",
                    source.display()
                );
            }
            // Only atime predates inventory; retain freshly read metadata for
            // every other field and never apply saved atime to a new inode.
            stat.st_atime = saved.atime.tv_sec;
            stat.st_atime_nsec = saved.atime.tv_nsec;
        }
        Ok(stat)
    }

    fn is_completed(&self, source: &Path, stat: &libc::stat) -> Result<bool> {
        let Some(key) = self.completed.get(source) else {
            return Ok(false);
        };
        verify_source_inode(source, stat, *key)?;
        Ok(true)
    }

    fn publish_aliases(
        &mut self,
        source: &Path,
        stat: &libc::stat,
        fd: RawFd,
        anchor: &OwnedFd,
    ) -> Result<()> {
        let key = (stat.st_dev, stat.st_ino);
        let Some(aliases) = self.pending.remove(&key) else {
            return Ok(());
        };
        for alias in aliases {
            check_interrupted()?;
            if alias.source != source {
                verify_source_inode(&alias.source, &lstat_entry(&alias.source)?, key)?;
                let name = alias
                    .destination
                    .file_name()
                    .context("invalid hardlink destination")?;
                let mut parent = anchor
                    .try_clone()
                    .context("failed to pin hardlink destination anchor")?;
                let mut display = self.anchor_display.clone();
                if let Some(ancestors) = alias.destination.parent() {
                    for component in ancestors.components() {
                        let std::path::Component::Normal(component) = component else {
                            bail!(
                                "invalid hardlink destination {}",
                                alias.destination.display()
                            );
                        };
                        display.push(component);
                        // These ancestors are source directories inside the selected
                        // copy, so use the same merge/shadow policy as their visit.
                        parent = open_leaf_dir_at(&parent, component, &display)?;
                    }
                }
                display.push(name);
                let name = cstring(name)?;
                publish_at(&parent, &name, &display, false, || {
                    link_fd_at(fd, &parent, &name)
                })?;
            }
            self.completed.insert(alias.source, key);
        }
        Ok(())
    }
}

fn verify_source_inode(source: &Path, stat: &libc::stat, expected: InodeKey) -> Result<()> {
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG || (stat.st_dev, stat.st_ino) != expected {
        bail!(
            "source hardlink {} changed during the copy",
            source.display()
        );
    }
    Ok(())
}

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
/// existing real directory, replace a symlink leaf, or create a
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

/// Keep writes and metadata on an inode with no destination name until complete.
fn create_file_at(parent: &OwnedFd, display: &Path) -> Result<OwnedFd> {
    #[cfg(test)]
    BEFORE_FILE_CREATE.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook();
        }
    });
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            c".".as_ptr(),
            libc::O_WRONLY | libc::O_TMPFILE | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| format!(
            "cannot create an anonymous inode for {}; destination filesystem must support O_TMPFILE",
            display.display()
        ));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Publish only completed inodes. Replacements unlink a name without opening it.
/// No content or metadata operation may follow publication, even through an fd:
/// the container can immediately link the published inode elsewhere.
fn publish_at(
    parent: &OwnedFd,
    name: &CString,
    display: &Path,
    symlinks_only: bool,
    mut link: impl FnMut() -> std::io::Result<()>,
) -> Result<()> {
    for _ in 0..LEAF_SWAP_RETRIES {
        check_interrupted()?;
        #[cfg(test)]
        BEFORE_PUBLICATION.with(|hook| {
            if let Some(hook) = hook.borrow_mut().as_mut() {
                hook();
            }
        });
        match link() {
            Ok(()) => {
                #[cfg(test)]
                AFTER_PUBLICATION.with(|hook| {
                    if let Some(hook) = hook.borrow_mut().take() {
                        hook();
                    }
                });
                return Ok(());
            }
            Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {
                match fstatat_nofollow(parent, name) {
                    Ok(st) if st.st_mode & libc::S_IFMT == libc::S_IFDIR => {
                        bail!("cannot replace destination directory {}", display.display());
                    }
                    Ok(st) if symlinks_only && st.st_mode & libc::S_IFMT != libc::S_IFLNK => {
                        return Err(e).with_context(|| {
                            format!("destination already exists: {}", display.display())
                        });
                    }
                    Ok(_) => {
                        let ret = unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) };
                        if ret != 0 {
                            let err = std::io::Error::last_os_error();
                            if err.kind() != std::io::ErrorKind::NotFound {
                                return Err(err).with_context(|| {
                                    format!("failed to replace {}", display.display())
                                });
                            }
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => {
                        return Err(e)
                            .with_context(|| format!("failed to stat {}", display.display()))
                    }
                }
            }
            Err(e) => {
                return Err(e).with_context(|| format!("failed to publish {}", display.display()))
            }
        }
    }
    bail!(
        "destination {} keeps changing under concurrent mutation; aborting",
        display.display()
    )
}

fn link_fd_at(fd: RawFd, parent: &OwnedFd, name: &CString) -> std::io::Result<()> {
    // The procfs magic link pins the inode and permits unprivileged O_TMPFILE
    // publication without CAP_DAC_READ_SEARCH. It never resolves a destination
    // name, including when the inode's first published name has been replaced.
    let path = CString::new(format!("/proc/self/fd/{fd}")).expect("fd is numeric");
    let ret = unsafe {
        libc::linkat(
            libc::AT_FDCWD,
            path.as_ptr(),
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::AT_SYMLINK_FOLLOW,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// A directory outside the mutable root, on the same mount as the destination.
/// Its parent belongs to sdme's trusted anchor, not to the container. Mode 0700
/// alone would not protect staging inside a container from container root.
struct Staging {
    path: PathBuf,
    fd: OwnedFd,
}

impl Staging {
    fn new(root: &Path, destination: &OwnedFd) -> Result<Self> {
        let parent = root
            .parent()
            .context("destination root has no trusted staging parent")?;
        let parent = if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        };
        let parent_fd = open_dest_root(parent)?;
        if mount_identity(&parent_fd)? != mount_identity(destination)? {
            bail!("special-node copy requires protected staging on the destination mount; no such staging is available outside {}", root.display());
        }
        let mut template =
            path_to_cstring(&parent.join(".sdme-copy-XXXXXX"))?.into_bytes_with_nul();
        let ptr = unsafe { libc::mkdtemp(template.as_mut_ptr().cast()) };
        if ptr.is_null() {
            return Err(std::io::Error::last_os_error())
                .context("cannot create protected staging outside the destination root");
        }
        let path = PathBuf::from(std::ffi::OsStr::from_bytes(&template[..template.len() - 1]));
        let fd = match open_dest_root(&path) {
            Ok(fd) => fd,
            Err(e) => {
                let _ = fs::remove_dir(&path);
                return Err(e);
            }
        };
        Ok(Self { path, fd })
    }

    fn node_path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}/node", self.fd.as_raw_fd()))
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        if let Err(e) = fs::remove_dir_all(&self.path) {
            eprintln!(
                "warning: failed to remove copy staging {}: {e}",
                self.path.display()
            );
        }
    }
}

// Both matter: bind mounts can share st_dev, while distinct Btrfs subvolumes
// can share a mount ID. linkat cannot cross either boundary.
fn mount_identity(fd: &OwnedFd) -> Result<(u64, u32, u32)> {
    let mut st: libc::statx = unsafe { std::mem::zeroed() };
    let ret = unsafe {
        libc::statx(
            fd.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH,
            libc::STATX_MNT_ID | libc::STATX_BASIC_STATS,
            &mut st,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error())
            .context("cannot establish mount identity for protected staging");
    }
    if st.stx_mask & libc::STATX_MNT_ID == 0 {
        bail!("kernel does not report mount identity required for protected staging");
    }
    Ok((st.stx_mnt_id, st.stx_dev_major, st.stx_dev_minor))
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

/// Finish an inode while its only name is in protected staging. Path-based
/// metadata calls are safe here because neither parent nor leaf is mutable by
/// the destination writer. lsetxattr supports special nodes without opening
/// devices or relying on fsetxattr accepting O_PATH descriptors.
fn finish_staged_leaf(stage: &Staging, src: &Path, stat: &libc::stat) -> Result<()> {
    #[cfg(test)]
    BEFORE_LEAF_METADATA.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook();
        }
    });
    let path = stage.node_path();
    super::copy_metadata_from_stat(&path, stat)?;
    let c_path = path_to_cstring(&path)?;
    for (name, value) in read_xattrs(src)? {
        let ret = unsafe {
            libc::lsetxattr(
                c_path.as_ptr(),
                name.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                0,
            )
        };
        if ret != 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| {
                format!(
                    "failed to preserve xattr {} on staged inode",
                    name.to_string_lossy()
                )
            });
        }
    }
    Ok(())
}

/// Copy one source entry to leaf `name` beneath `parent`, contained.
fn copy_entry_at(
    parent: &OwnedFd,
    name: &std::ffi::OsStr,
    display: &Path,
    src: &Path,
    links: &mut HardLinkPlan,
    root: &Path,
    anchor: &OwnedFd,
) -> Result<()> {
    let stat = links.source_stat(src)?;
    if links.is_completed(src, &stat)? {
        return Ok(());
    }
    let mode = stat.st_mode & libc::S_IFMT;
    let c_name = cstring(name)?;

    match mode {
        libc::S_IFDIR => {
            let fd = open_leaf_dir_at(parent, name, display)?;
            #[cfg(test)]
            AFTER_DIR_OPEN.with(|hook| {
                if let Some(hook) = hook.borrow_mut().take() {
                    hook();
                }
            });
            copy_metadata_to_fd(fd.as_raw_fd(), &stat, display)?;
            copy_xattrs_to_fd(src, fd.as_raw_fd(), display)?;
            copy_children_at(&fd, display, src, links, root, anchor)?;
        }
        libc::S_IFREG => {
            let mut dst_file = fs::File::from(create_file_at(parent, display)?);
            #[cfg(test)]
            AFTER_FILE_CREATE.with(|hook| {
                if let Some(hook) = hook.borrow_mut().take() {
                    hook();
                }
            });
            let mut src_file = fs::File::open(src)
                .with_context(|| format!("failed to open source {}", src.display()))?;
            std::io::copy(&mut src_file, &mut dst_file)
                .with_context(|| format!("failed to write {}", display.display()))?;
            drop(src_file);
            copy_metadata_to_fd(dst_file.as_raw_fd(), &stat, display)?;
            copy_xattrs_to_fd(src, dst_file.as_raw_fd(), display)?;
            publish_at(parent, &c_name, display, false, || {
                link_fd_at(dst_file.as_raw_fd(), parent, &c_name)
            })?;
            links.publish_aliases(src, &stat, dst_file.as_raw_fd(), anchor)?;
        }
        libc::S_IFLNK | libc::S_IFBLK | libc::S_IFCHR | libc::S_IFIFO | libc::S_IFSOCK => {
            let stage = Staging::new(root, parent).with_context(|| {
                format!(
                    "cannot safely copy special node {} to {}",
                    src.display(),
                    display.display()
                )
            })?;
            let ret = if mode == libc::S_IFLNK {
                let target = fs::read_link(src)
                    .with_context(|| format!("failed to read symlink {}", src.display()))?;
                let target = path_to_cstring(&target)?;
                unsafe { libc::symlinkat(target.as_ptr(), stage.fd.as_raw_fd(), c"node".as_ptr()) }
            } else {
                unsafe {
                    libc::mknodat(
                        stage.fd.as_raw_fd(),
                        c"node".as_ptr(),
                        stat.st_mode,
                        stat.st_rdev,
                    )
                }
            };
            if ret != 0 {
                return Err(std::io::Error::last_os_error())
                    .with_context(|| format!("failed to stage {}", src.display()));
            }
            finish_staged_leaf(&stage, src, &stat)?;
            publish_at(parent, &c_name, display, true, || {
                let ret = unsafe {
                    libc::linkat(
                        stage.fd.as_raw_fd(),
                        c"node".as_ptr(),
                        parent.as_raw_fd(),
                        c_name.as_ptr(),
                        0,
                    )
                };
                if ret != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            })?;
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
    links: &mut HardLinkPlan,
    root: &Path,
    anchor: &OwnedFd,
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
            root,
            anchor,
        )
        .with_context(|| format!("failed to copy {}", entry.path().display()))?;
    }
    Ok(())
}

/// Copy `src` to `rel` beneath `root`, safe against concurrent mutation of
/// the destination tree (a running container's live root, an imported
/// rootfs, a populated overlay upper). Every component of `rel` is resolved
/// fd-relative with O_NOFOLLOW beneath an fd pinning `root`; a symlink among
/// the ancestors is rejected, regular-file leaves are replaced with completed
/// anonymous inodes, and real directories are merged into. Symlinks and special
/// nodes require protected staging outside `root` on the destination mount;
/// unavailable staging is an explicit error. The anchor and its parent must be
/// trusted host paths, outside the destination writer's control. Regular-file
/// copying requires O_TMPFILE support. Selected source hardlinks are inventoried
/// and published group by group, with descriptor use bounded by traversal depth
/// rather than group count. Source reads are not contained or snapshotted here.
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
        let mut links = HardLinkPlan::new(src, Path::new(""), &display)?;
        return copy_children_at(&root_fd, &display, src, &mut links, root, &root_fd);
    }
    let (leaf, ancestors) = parts.split_last().unwrap();
    let mut dir_fd = root_fd;
    for anc in ancestors {
        display = display.join(anc);
        dir_fd = ensure_dir_at(&dir_fd, anc, &display)?;
    }
    let mut links = HardLinkPlan::new(src, Path::new(leaf), &display)?;
    display = display.join(leaf);
    copy_entry_at(&dir_fd, leaf, &display, src, &mut links, root, &dir_fd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    #[test]
    fn test_contained_regression_hardlink_swap_preserves_outside() {
        let tmp = crate::testutil::TempDataDir::new("coordinator-hl-race");
        let root = tmp.path().join("root");
        fs::create_dir(&root).unwrap();
        let outside = tmp.path().join("outside");
        fs::write(&outside, b"sentinel").unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o640)).unwrap();
        let before = fs::metadata(&outside).unwrap();
        let src = tmp.path().join("src");
        fs::write(&src, b"payload").unwrap();
        let target = root.join("target");
        fs::write(&target, b"innocent").unwrap();
        let outside_copy = outside.clone();
        BEFORE_FILE_CREATE.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                fs::remove_file(&target).unwrap();
                fs::hard_link(&outside_copy, &target).unwrap();
            }))
        });
        let result = copy_contained(&root, Path::new("target"), &src);
        result.unwrap();
        assert_metadata_eq(&before, &fs::metadata(&outside).unwrap());
        assert_eq!(fs::read(&outside).unwrap(), b"sentinel");
        assert_eq!(fs::read(root.join("target")).unwrap(), b"payload");
    }

    #[test]
    fn test_contained_regression_existing_fifo_is_not_written() {
        let tmp = crate::testutil::TempDataDir::new("coordinator-fifo");
        let root = tmp.path().join("root");
        fs::create_dir(&root).unwrap();
        let target = root.join("target");
        let c = cstring(target.as_os_str()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let raw = unsafe {
            libc::open(
                c.as_ptr(),
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        assert!(raw >= 0);
        let reader = unsafe { OwnedFd::from_raw_fd(raw) };
        let src = tmp.path().join("src");
        fs::write(&src, b"payload").unwrap();
        let result = copy_contained(&root, Path::new("target"), &src);
        result.unwrap();
        assert!(fs::symlink_metadata(&target).unwrap().is_file());
        assert_eq!(fs::read(&target).unwrap(), b"payload");
        let mut buf = [0u8; 32];
        let count = unsafe { libc::read(reader.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        assert!(count <= 0, "copied {count} bytes into the existing FIFO");
    }

    #[test]
    fn test_contained_regression_special_leaf_substitution_preserves_outside_metadata() {
        let tmp = crate::testutil::TempDataDir::new("coordinator-special-race");
        let root = tmp.path().join("root");
        fs::create_dir(&root).unwrap();
        let outside = tmp.path().join("outside");
        fs::write(&outside, b"sentinel").unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o640)).unwrap();
        let before = fs::metadata(&outside).unwrap();
        let src = tmp.path().join("src");
        let csrc = cstring(src.as_os_str()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(csrc.as_ptr(), 0o600) }, 0);
        let target = root.join("target");
        std::os::unix::fs::symlink("old-target", &target).unwrap();
        let sentinel = outside.clone();
        BEFORE_LEAF_METADATA.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                fs::remove_file(&target).unwrap();
                fs::hard_link(&sentinel, &target).unwrap();
            }))
        });
        let result = copy_contained(&root, Path::new("target"), &src);
        assert!(result.is_err());
        assert_metadata_eq(&before, &fs::metadata(&outside).unwrap());
        assert_eq!(fs::read(&outside).unwrap(), b"sentinel");
    }

    #[test]
    fn test_contained_regression_o_path_fsetxattr_returns_ebadf() {
        let tmp = crate::testutil::TempDataDir::new("coordinator-opath");
        let file = tmp.path().join("file");
        fs::write(&file, b"data").unwrap();
        let c = cstring(file.as_os_str()).unwrap();
        let raw = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        assert!(raw >= 0);
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let key = CString::new("user.test").unwrap();
        assert_eq!(
            unsafe { libc::fsetxattr(fd.as_raw_fd(), key.as_ptr(), b"x".as_ptr().cast(), 1, 0) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EBADF)
        );
    }

    fn assert_metadata_eq(before: &fs::Metadata, after: &fs::Metadata) {
        // Link/unlink operations necessarily change ctime and link count.
        assert_eq!(
            (
                after.mode(),
                after.uid(),
                after.gid(),
                after.atime(),
                after.atime_nsec(),
                after.mtime(),
                after.mtime_nsec()
            ),
            (
                before.mode(),
                before.uid(),
                before.gid(),
                before.atime(),
                before.atime_nsec(),
                before.mtime(),
                before.mtime_nsec()
            )
        );
    }

    fn set_xattr(path: &Path, value: &[u8]) {
        let path = path_to_cstring(path).unwrap();
        assert_eq!(
            unsafe {
                libc::lsetxattr(
                    path.as_ptr(),
                    c"user.copy-test".as_ptr(),
                    value.as_ptr().cast(),
                    value.len(),
                    0,
                )
            },
            0
        );
    }

    fn make_fifo(path: &Path, mode: u32) {
        let path = path_to_cstring(path).unwrap();
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), mode) }, 0);
    }

    fn set_times(path: &Path) {
        let path = path_to_cstring(path).unwrap();
        let times = [
            libc::timespec {
                tv_sec: 12345678,
                tv_nsec: 123456789,
            },
            libc::timespec {
                tv_sec: 87654321,
                tv_nsec: 987654321,
            },
        ];
        assert_eq!(
            unsafe {
                libc::utimensat(
                    libc::AT_FDCWD,
                    path.as_ptr(),
                    times.as_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            },
            0
        );
    }

    #[test]
    fn test_regular_inode_is_private_until_complete() {
        let tmp = crate::testutil::TempDataDir::new("copy-private-inode");
        let root = tmp.path().join("root");
        fs::create_dir(&root).unwrap();
        let src = tmp.path().join("src");
        fs::write(&src, b"completed payload").unwrap();
        fs::set_permissions(&src, fs::Permissions::from_mode(0o751)).unwrap();
        set_times(&src);
        set_xattr(&src, b"required xattr");
        let expected = fs::metadata(&src).unwrap();
        let target = root.join("target");
        let unpublished = target.clone();
        AFTER_FILE_CREATE.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                assert!(
                    !unpublished.exists(),
                    "the writable inode must have no destination name"
                );
            }))
        });
        let published = target.clone();
        let expected_xattrs = read_xattrs(&src).unwrap();
        AFTER_PUBLICATION.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                assert_metadata_eq(&expected, &fs::metadata(&published).unwrap());
                assert_eq!(read_xattrs(&published).unwrap(), expected_xattrs);
                assert_eq!(fs::read(&published).unwrap(), b"completed payload");
                // No subsequent chmod/write/xattr is allowed to undo a live writer.
                fs::write(&published, b"live writer").unwrap();
                fs::set_permissions(&published, fs::Permissions::from_mode(0o640)).unwrap();
                set_xattr(&published, b"live xattr");
            }))
        });
        copy_contained(&root, Path::new("target"), &src).unwrap();
        assert_eq!(fs::metadata(&target).unwrap().mode() & 0o777, 0o640);
        assert_eq!(fs::read(&target).unwrap(), b"live writer");
        assert_eq!(read_xattrs(&target).unwrap()[0].1, b"live xattr");
    }

    #[test]
    fn test_special_same_type_substitution_preserves_outside_metadata() {
        let tmp = crate::testutil::TempDataDir::new("copy-same-type");
        let root = tmp.path().join("root");
        fs::create_dir(&root).unwrap();
        let src = tmp.path().join("src");
        make_fifo(&src, 0o600);
        let outside = tmp.path().join("outside");
        make_fifo(&outside, 0o640);
        set_times(&outside);
        let before = fs::symlink_metadata(&outside).unwrap();
        let target = root.join("target");
        std::os::unix::fs::symlink("old", &target).unwrap();
        let sentinel = outside.clone();
        BEFORE_LEAF_METADATA.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                fs::remove_file(&target).unwrap();
                fs::hard_link(&sentinel, &target).unwrap();
            }))
        });
        assert!(copy_contained(&root, Path::new("target"), &src).is_err());
        assert_metadata_eq(&before, &fs::symlink_metadata(&outside).unwrap());
    }

    #[test]
    fn test_special_metadata_is_complete_before_publication() {
        let tmp = crate::testutil::TempDataDir::new("copy-special-control");
        let root = tmp.path().join("root");
        fs::create_dir(&root).unwrap();
        for (name, kind) in [
            ("fifo", libc::S_IFIFO),
            ("socket", libc::S_IFSOCK),
            ("symlink", libc::S_IFLNK),
        ] {
            let src = tmp.path().join(name);
            if kind == libc::S_IFLNK {
                std::os::unix::fs::symlink("missing-target", &src).unwrap();
            } else {
                let c_src = path_to_cstring(&src).unwrap();
                assert_eq!(unsafe { libc::mknod(c_src.as_ptr(), kind | 0o751, 0) }, 0);
                fs::set_permissions(&src, fs::Permissions::from_mode(0o751)).unwrap();
            }
            set_times(&src);
            let expected = fs::symlink_metadata(&src).unwrap();
            let target = root.join(name);
            let published = target.clone();
            AFTER_PUBLICATION.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move || {
                    assert_metadata_eq(&expected, &fs::symlink_metadata(&published).unwrap());
                }))
            });
            copy_contained(&root, Path::new(name), &src).unwrap();
            assert_eq!(
                fs::symlink_metadata(&target).unwrap().mode() & libc::S_IFMT,
                kind
            );
            if kind == libc::S_IFLNK {
                assert_eq!(fs::read_link(&target).unwrap(), Path::new("missing-target"));
            }
        }
        assert!(!fs::read_dir(tmp.path()).unwrap().any(|entry| entry
            .unwrap()
            .file_name()
            .as_bytes()
            .starts_with(b".sdme-copy-")));
    }

    #[test]
    fn test_staged_xattrs_use_supported_path_calls_and_report_errors() {
        let tmp = crate::testutil::TempDataDir::new("copy-staged-xattrs");
        let root = tmp.path().join("root");
        fs::create_dir(&root).unwrap();
        let src = tmp.path().join("src");
        fs::write(&src, b"data").unwrap();
        set_xattr(&src, b"required value");
        let parent = open_dest_root(&root).unwrap();
        let stage = Staging::new(&root, &parent).unwrap();
        fs::write(stage.node_path(), b"").unwrap();
        finish_staged_leaf(&stage, &src, &lstat_entry(&src).unwrap()).unwrap();
        assert_eq!(
            read_xattrs(&stage.node_path()).unwrap(),
            read_xattrs(&src).unwrap()
        );
        fs::remove_file(stage.node_path()).unwrap();
        make_fifo(&stage.node_path(), 0o600);
        // Linux rejects user.* xattrs on FIFOs. Required xattrs must not vanish
        // behind a successful copy result when the destination rejects them.
        let err = finish_staged_leaf(&stage, &src, &lstat_entry(&stage.node_path()).unwrap())
            .unwrap_err();
        assert!(format!("{err:#}").contains("preserve xattr"));
    }

    #[test]
    fn test_symlink_publication_exhaustion_is_an_error() {
        let tmp = crate::testutil::TempDataDir::new("copy-symlink-exhaustion");
        let root = tmp.path().join("root");
        fs::create_dir(&root).unwrap();
        let src = tmp.path().join("src");
        std::os::unix::fs::symlink("wanted", &src).unwrap();
        let outside = tmp.path().join("outside");
        fs::write(&outside, b"sentinel").unwrap();
        set_times(&outside);
        let before = fs::metadata(&outside).unwrap();
        let attempts = std::rc::Rc::new(std::cell::Cell::new(0));
        let count = attempts.clone();
        let target = root.join("target");
        let sentinel = outside.clone();
        BEFORE_PUBLICATION.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                count.set(count.get() + 1);
                std::os::unix::fs::symlink(&sentinel, &target).unwrap();
            }))
        });
        let result = copy_contained(&root, Path::new("target"), &src);
        BEFORE_PUBLICATION.with(|hook| hook.borrow_mut().take());
        let err = result.unwrap_err();
        assert!(format!("{err:#}").contains("keeps changing"));
        assert_eq!(attempts.get(), LEAF_SWAP_RETRIES);
        assert_metadata_eq(&before, &fs::metadata(&outside).unwrap());
        assert_eq!(fs::read(&outside).unwrap(), b"sentinel");
        copy_contained(&root, Path::new("target"), &src).unwrap();
        assert_eq!(
            fs::read_link(root.join("target")).unwrap(),
            Path::new("wanted")
        );
    }

    #[test]
    fn test_live_root_alias_keeps_regular_copies_and_refuses_unavailable_staging() {
        let tmp = crate::testutil::TempDataDir::new("copy-live-root-alias");
        let root = tmp.path().join("root");
        fs::create_dir(&root).unwrap();
        let root_fd = open_dest_root(&root).unwrap();
        // A procfs root anchor has no writable same-mount host parent, as with
        // /proc/pid/root. This exercises refusal without a privileged mount.
        let alias = PathBuf::from(format!("/proc/self/fd/{}", root_fd.as_raw_fd()));
        let src = tmp.path().join("src");
        fs::write(&src, b"live payload").unwrap();
        copy_contained(&alias, Path::new("target"), &src).unwrap();
        assert_eq!(fs::read(root.join("target")).unwrap(), b"live payload");
        for kind in [libc::S_IFIFO, libc::S_IFSOCK, libc::S_IFLNK] {
            fs::remove_file(&src).unwrap();
            if kind == libc::S_IFLNK {
                std::os::unix::fs::symlink("missing", &src).unwrap();
            } else {
                let path = path_to_cstring(&src).unwrap();
                assert_eq!(unsafe { libc::mknod(path.as_ptr(), kind | 0o600, 0) }, 0);
            }
            let err = copy_contained(&alias, Path::new("target"), &src).unwrap_err();
            assert!(format!("{err:#}").contains("protected staging"), "{err:#}");
            assert_eq!(fs::read(root.join("target")).unwrap(), b"live payload");
        }
    }
    #[test]
    fn test_publication_substitution_never_receives_metadata() {
        let tmp = crate::testutil::TempDataDir::new("copy-after-publish");
        let root = tmp.path().join("root");
        fs::create_dir(&root).unwrap();
        let outside = tmp.path().join("outside");
        fs::write(&outside, b"sentinel").unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o640)).unwrap();
        set_xattr(&outside, b"outside xattr");
        for kind in [libc::S_IFREG, libc::S_IFIFO, libc::S_IFLNK] {
            set_times(&outside);
            let before = fs::metadata(&outside).unwrap();
            let src = tmp.path().join(format!("src-{kind}"));
            if kind == libc::S_IFREG {
                fs::write(&src, b"payload").unwrap();
                set_xattr(&src, b"new xattr");
            } else if kind == libc::S_IFIFO {
                make_fifo(&src, 0o600);
            } else {
                std::os::unix::fs::symlink("missing", &src).unwrap();
            }
            let name = format!("target-{kind}");
            let target = root.join(&name);
            let sentinel = outside.clone();
            AFTER_PUBLICATION.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move || {
                    fs::remove_file(&target).unwrap();
                    fs::hard_link(&sentinel, &target).unwrap();
                }))
            });
            copy_contained(&root, Path::new(&name), &src).unwrap();
            assert_metadata_eq(&before, &fs::metadata(&outside).unwrap());
            assert_eq!(read_xattrs(&outside).unwrap()[0].1, b"outside xattr");
            assert_eq!(fs::read(&outside).unwrap(), b"sentinel");
        }
    }

    #[test]
    fn test_hardlink_group_does_not_resolve_replaced_first_name() {
        let tmp = crate::testutil::TempDataDir::new("copy-hardlink-group");
        let root = tmp.path().join("root");
        fs::create_dir(&root).unwrap();
        let src = tmp.path().join("src");
        fs::create_dir(&src).unwrap();
        fs::write(src.join("first"), b"payload").unwrap();
        fs::hard_link(src.join("first"), src.join("second")).unwrap();
        let outside = tmp.path().join("outside");
        fs::write(&outside, b"sentinel").unwrap();
        set_times(&outside);
        let before = fs::metadata(&outside).unwrap();
        let destination = root.join("destination");
        let copied = destination.clone();
        let sentinel = outside.clone();
        let replaced = std::rc::Rc::new(std::cell::RefCell::new(None));
        let first_name = replaced.clone();
        AFTER_PUBLICATION.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                let first = fs::read_dir(&copied).unwrap().next().unwrap().unwrap();
                *first_name.borrow_mut() = Some(first.file_name());
                fs::rename(first.path(), copied.join("saved")).unwrap();
                fs::hard_link(&sentinel, first.path()).unwrap();
            }))
        });
        copy_contained(&root, Path::new("destination"), &src).unwrap();
        let other = if replaced.borrow().as_deref() == Some(std::ffi::OsStr::new("first")) {
            "second"
        } else {
            "first"
        };
        assert_metadata_eq(&before, &fs::metadata(&outside).unwrap());
        assert_eq!(fs::read(destination.join(other)).unwrap(), b"payload");
        assert_eq!(
            fs::metadata(destination.join(other)).unwrap().ino(),
            fs::metadata(destination.join("saved")).unwrap().ino()
        );
        assert_eq!(fs::read(&outside).unwrap(), b"sentinel");
    }

    #[test]
    fn test_failed_source_read_preserves_existing_destination() {
        let tmp = crate::testutil::TempDataDir::new("copy-source-failure");
        let root = tmp.path().join("root");
        fs::create_dir(&root).unwrap();
        let src = tmp.path().join("src");
        fs::write(&src, b"payload").unwrap();
        let target = root.join("target");
        fs::write(&target, b"original").unwrap();
        set_xattr(&target, b"original xattr");
        let before = fs::metadata(&target).unwrap();
        let disappearing = src.clone();
        AFTER_FILE_CREATE.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                fs::remove_file(&disappearing).unwrap();
            }))
        });
        assert!(copy_contained(&root, Path::new("target"), &src).is_err());
        assert_metadata_eq(&before, &fs::metadata(&target).unwrap());
        assert_eq!(fs::read(&target).unwrap(), b"original");
        assert_eq!(read_xattrs(&target).unwrap()[0].1, b"original xattr");
    }

    #[test]
    fn test_directory_swap_pins_metadata_and_recursive_descent() {
        let tmp = crate::testutil::TempDataDir::new("copy-dir-pin");
        let root = tmp.path().join("root");
        fs::create_dir_all(root.join("dir")).unwrap();
        let src = tmp.path().join("src");
        fs::create_dir(&src).unwrap();
        fs::write(src.join("child"), b"payload").unwrap();
        fs::set_permissions(&src, fs::Permissions::from_mode(0o751)).unwrap();
        set_xattr(&src, b"source xattr");
        let outside = tmp.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("child"), b"sentinel").unwrap();
        set_times(&outside);
        set_xattr(&outside, b"outside xattr");
        let before = fs::metadata(&outside).unwrap();
        let dir = root.join("dir");
        let saved = root.join("saved");
        let sentinel = outside.clone();
        AFTER_DIR_OPEN.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                fs::rename(&dir, &saved).unwrap();
                std::os::unix::fs::symlink(&sentinel, &dir).unwrap();
            }))
        });
        copy_contained(&root, Path::new("dir"), &src).unwrap();
        assert_metadata_eq(&before, &fs::metadata(&outside).unwrap());
        assert_eq!(read_xattrs(&outside).unwrap()[0].1, b"outside xattr");
        assert_eq!(fs::read(outside.join("child")).unwrap(), b"sentinel");
        assert_eq!(fs::read(root.join("saved/child")).unwrap(), b"payload");
        assert_eq!(
            fs::metadata(root.join("saved")).unwrap().mode() & 0o777,
            0o751
        );
        assert_eq!(
            read_xattrs(&root.join("saved")).unwrap()[0].1,
            b"source xattr"
        );
    }
    fn directory_atime_copy(nested: bool) {
        let tmp = crate::testutil::TempDataDir::new("copy-directory-atime");
        let src = tmp.path().join("source");
        let directories: &[&str] = if nested {
            &[
                "",
                "empty",
                "branch",
                "branch/nested",
                "branch/nested/empty",
            ]
        } else {
            &["", "empty"]
        };
        for directory in directories {
            fs::create_dir_all(src.join(directory)).unwrap();
        }
        for (i, relative) in ["destination", ""].iter().enumerate() {
            let root = tmp.path().join(format!("root-{i}"));
            fs::create_dir(&root).unwrap();
            let expected: Vec<_> = directories
                .iter()
                .map(|directory| {
                    let source = src.join(directory);
                    set_times(&source);
                    fs::metadata(&source).unwrap()
                })
                .collect();
            copy_contained(&root, Path::new(relative), &src).unwrap();
            for (directory, before) in directories.iter().zip(&expected) {
                if relative.is_empty() && directory.is_empty() {
                    // Contents-only copying does not apply source-root metadata.
                    continue;
                }
                let destination = root.join(relative).join(directory);
                let after = fs::metadata(&destination).unwrap();
                assert_eq!(
                    (after.atime(), after.atime_nsec()),
                    (before.atime(), before.atime_nsec()),
                    "directory atime changed during inventory: {}",
                    destination.display()
                );
                if directory.ends_with("empty") {
                    // Child creation may change nonempty directory mtimes.
                    assert_eq!(
                        (after.mtime(), after.mtime_nsec()),
                        (before.mtime(), before.mtime_nsec())
                    );
                }
            }
        }
    }

    #[test]
    fn test_directory_atime_before_inventory_empty() {
        directory_atime_copy(false);
    }

    #[test]
    fn test_directory_atime_before_inventory_nested() {
        directory_atime_copy(true);
    }

    #[test]
    fn test_directory_atime_inventory_rejects_source_replacement() {
        for replacement in ["directory", "file", "symlink"] {
            let tmp = crate::testutil::TempDataDir::new("copy-directory-atime-change");
            let src = tmp.path().join("source");
            fs::create_dir_all(src.join("child")).unwrap();
            set_times(&src.join("child"));
            let root = tmp.path().join("root");
            let destination = root.join("destination/child");
            fs::create_dir_all(&destination).unwrap();
            fs::write(destination.join("sentinel"), b"preserved").unwrap();
            set_times(&destination);
            let before = fs::metadata(&destination).unwrap();
            let child = src.join("child");
            let saved = tmp.path().join("saved-source-child");
            AFTER_DIR_OPEN.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move || {
                    // Keep the inventoried inode alive to exclude inode reuse.
                    fs::rename(&child, &saved).unwrap();
                    match replacement {
                        "directory" => fs::create_dir(&child).unwrap(),
                        "file" => fs::write(&child, b"replacement").unwrap(),
                        "symlink" => std::os::unix::fs::symlink(&saved, &child).unwrap(),
                        _ => unreachable!(),
                    }
                }))
            });
            let err = copy_contained(&root, Path::new("destination"), &src).unwrap_err();
            let message = format!("{err:#}");
            assert!(message.contains("source directory"), "{message}");
            assert!(message.contains("changed during the copy"), "{message}");
            assert_metadata_eq(&before, &fs::metadata(&destination).unwrap());
            assert_eq!(
                fs::read(destination.join("sentinel")).unwrap(),
                b"preserved"
            );
        }
    }

    fn bounded_descriptor_copy(test_name: &str, in_tree_groups: bool) {
        const CHILD_CASE: &str = "SDME_TEST_COPY_FD_CASE";
        if std::env::var(CHILD_CASE).as_deref() != Ok(test_name) {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", test_name, "--nocapture", "--test-threads=1"])
                .env(CHILD_CASE, test_name)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "bounded-descriptor child failed:\n{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }

        // Limit only the fresh child process; parallel tests retain their limits.
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) },
            0
        );
        assert!(limit.rlim_cur >= 64);
        limit.rlim_cur = 64;
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);

        let tmp = crate::testutil::TempDataDir::new("copy-fd-budget");
        let root = tmp.path().join("root");
        let src = tmp.path().join("source");
        let outside = tmp.path().join("source-links-outside");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&src).unwrap();
        fs::create_dir(&outside).unwrap();
        let prefixes: &[&str] = if in_tree_groups {
            &["first", "second", "third/nested"]
        } else {
            &[""]
        };
        for prefix in prefixes {
            fs::create_dir_all(src.join(prefix)).unwrap();
        }
        let mut expected = Vec::new();
        for i in 0..192 {
            let name = format!("file-{i:04}");
            let first = src.join(prefixes[0]).join(&name);
            fs::write(&first, b"payload").unwrap();
            fs::set_permissions(&first, fs::Permissions::from_mode(0o640)).unwrap();
            set_times(&first);
            set_xattr(&first, b"required xattr");
            fs::hard_link(&first, outside.join(&name)).unwrap();
            for prefix in &prefixes[1..] {
                fs::hard_link(&first, src.join(prefix).join(&name)).unwrap();
            }
            expected.push(fs::metadata(&first).unwrap());
        }
        // A procfd root preserves the live regular-copy contract without
        // introducing any requirement for protected special-node staging.
        let root_fd = open_dest_root(&root).unwrap();
        let alias = PathBuf::from(format!("/proc/self/fd/{}", root_fd.as_raw_fd()));
        let peak = std::rc::Rc::new(std::cell::Cell::new(0));
        let observed = peak.clone();
        BEFORE_PUBLICATION.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                let count = fs::read_dir("/proc/self/fd").unwrap().count();
                observed.set(observed.get().max(count));
            }))
        });
        let result = copy_contained(&alias, Path::new("destination"), &src);
        BEFORE_PUBLICATION.with(|hook| hook.borrow_mut().take());
        assert!(
            result.is_ok(),
            "all selected files must copy with 64 descriptors: {result:#?}"
        );
        assert!(
            peak.get() < 32,
            "unexpected descriptor growth: peak {}",
            peak.get()
        );
        for (i, before) in expected.iter().enumerate() {
            let name = format!("file-{i:04}");
            let first = root.join("destination").join(prefixes[0]).join(&name);
            let first_meta = fs::metadata(&first).unwrap();
            assert_ne!(
                (first_meta.dev(), first_meta.ino()),
                (before.dev(), before.ino())
            );
            for prefix in prefixes {
                let destination = root.join("destination").join(prefix).join(&name);
                let copied = fs::metadata(&destination).unwrap();
                assert_metadata_eq(before, &copied);
                assert_eq!(copied.ino(), first_meta.ino(), "hardlink group {i}");
                assert_eq!(copied.nlink(), prefixes.len() as u64);
                assert_eq!(read_xattrs(&destination).unwrap()[0].1, b"required xattr");
            }
            // Read only after checking all aliases' atimes.
            assert_eq!(fs::read(&first).unwrap(), b"payload");
            assert_eq!(fs::read(outside.join(&name)).unwrap(), b"payload");
        }
        println!(
            "192 groups, {} selected names, peak {} descriptors with RLIMIT_NOFILE=64",
            192 * prefixes.len(),
            peak.get()
        );
    }

    #[test]
    fn test_bounded_descriptors_external_only_links() {
        bounded_descriptor_copy(
            "copy::contained::tests::test_bounded_descriptors_external_only_links",
            false,
        );
    }

    #[test]
    fn test_bounded_descriptors_many_in_tree_groups() {
        bounded_descriptor_copy(
            "copy::contained::tests::test_bounded_descriptors_many_in_tree_groups",
            true,
        );
    }
    #[test]
    fn test_grouped_alias_parent_swap_preserves_outside() {
        let tmp = crate::testutil::TempDataDir::new("copy-alias-parent");
        let root = tmp.path().join("root");
        let src = tmp.path().join("source");
        let outside = tmp.path().join("outside");
        fs::create_dir(&root).unwrap();
        fs::create_dir_all(src.join("left")).unwrap();
        fs::create_dir(src.join("right")).unwrap();
        fs::write(src.join("left/file"), b"payload").unwrap();
        fs::hard_link(src.join("left/file"), src.join("right/file")).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("file"), b"sentinel").unwrap();
        set_times(&outside);
        set_xattr(&outside, b"outside directory");
        let before = fs::metadata(&outside).unwrap();
        let before_file = fs::metadata(outside.join("file")).unwrap();
        let destination = root.join("destination");
        let copied = destination.clone();
        let sentinel = outside.clone();
        AFTER_PUBLICATION.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                let other = if copied.join("left/file").exists() {
                    "right"
                } else {
                    "left"
                };
                std::os::unix::fs::symlink(&sentinel, copied.join(other)).unwrap();
            }))
        });
        copy_contained(&root, Path::new("destination"), &src).unwrap();
        assert_metadata_eq(&before, &fs::metadata(&outside).unwrap());
        assert_metadata_eq(&before_file, &fs::metadata(outside.join("file")).unwrap());
        assert_eq!(read_xattrs(&outside).unwrap()[0].1, b"outside directory");
        assert_eq!(fs::read(outside.join("file")).unwrap(), b"sentinel");
        assert_eq!(fs::read(destination.join("left/file")).unwrap(), b"payload");
        assert_eq!(
            fs::metadata(destination.join("left/file")).unwrap().ino(),
            fs::metadata(destination.join("right/file")).unwrap().ino()
        );
    }

    #[test]
    fn test_grouped_alias_source_change_is_reported_before_publication() {
        let tmp = crate::testutil::TempDataDir::new("copy-alias-source-change");
        let root = tmp.path().join("root");
        let src = tmp.path().join("source");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&src).unwrap();
        fs::write(src.join("first"), b"payload").unwrap();
        fs::hard_link(src.join("first"), src.join("second")).unwrap();
        let outside = tmp.path().join("outside");
        fs::write(&outside, b"sentinel").unwrap();
        set_times(&outside);
        set_xattr(&outside, b"outside xattr");
        let before = fs::metadata(&outside).unwrap();
        let destination = root.join("destination");
        let changing = src.clone();
        let sentinel = outside.clone();
        AFTER_PUBLICATION.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                let first = fs::read_dir(&destination).unwrap().next().unwrap().unwrap();
                let other = if first.file_name() == "first" {
                    "second"
                } else {
                    "first"
                };
                fs::remove_file(changing.join(other)).unwrap();
                fs::write(changing.join(other), b"changed source").unwrap();
                fs::hard_link(&sentinel, destination.join(other)).unwrap();
            }))
        });
        let err = copy_contained(&root, Path::new("destination"), &src).unwrap_err();
        assert!(
            format!("{err:#}").contains("changed during the copy"),
            "{err:#}"
        );
        assert_metadata_eq(&before, &fs::metadata(&outside).unwrap());
        assert_eq!(read_xattrs(&outside).unwrap()[0].1, b"outside xattr");
        assert_eq!(fs::read(&outside).unwrap(), b"sentinel");
    }

    #[test]
    fn test_hardlink_inventory_for_directory_contents_controls() {
        let tmp = crate::testutil::TempDataDir::new("copy-group-contents");
        let src = tmp.path().join("source");
        fs::create_dir(&src).unwrap();
        fs::write(src.join("a"), b"payload").unwrap();
        fs::create_dir(src.join("nested")).unwrap();
        fs::hard_link(src.join("a"), src.join("nested/b")).unwrap();
        let source_alias = tmp.path().join("source-alias");
        std::os::unix::fs::symlink(&src, &source_alias).unwrap();
        for (i, source) in [&src, &source_alias].iter().enumerate() {
            let root = tmp.path().join(format!("root-{i}"));
            fs::create_dir(&root).unwrap();
            copy_contained(&root, Path::new(""), source).unwrap();
            assert_eq!(fs::read(root.join("nested/b")).unwrap(), b"payload");
            assert_eq!(
                fs::metadata(root.join("a")).unwrap().ino(),
                fs::metadata(root.join("nested/b")).unwrap().ino()
            );
            let dot_root = tmp.path().join(format!("dot-root-{i}"));
            fs::create_dir(&dot_root).unwrap();
            copy_contained(&dot_root, Path::new("."), source).unwrap();
            assert_eq!(
                fs::metadata(dot_root.join("a")).unwrap().ino(),
                fs::metadata(dot_root.join("nested/b")).unwrap().ino()
            );
        }
    }
}
