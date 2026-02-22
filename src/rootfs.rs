//! Internal API for managing root filesystems used as overlayfs lower layers.
//!
//! Provides functions for importing, listing, and removing root filesystems
//! stored under `{datadir}/rootfs/{name}/`. Each rootfs is a complete
//! directory tree that containers reference via their state file.

use std::collections::HashMap;
use std::ffi::CString;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs as unix_fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::{State, validate_name};
use crate::system_check;

/// An entry returned by [`list`].
pub struct RootfsEntry {
    pub name: String,
    pub distro: String,
}

/// Parse an `os-release` file into a key-value map.
///
/// Reads `{rootfs}/etc/os-release`, falling back to
/// `{rootfs}/usr/lib/os-release` per the freedesktop spec.
/// Returns an empty map if neither file exists.
fn parse_os_release(rootfs: &Path) -> HashMap<String, String> {
    let primary = rootfs.join("etc/os-release");
    let fallback = rootfs.join("usr/lib/os-release");

    let content = match fs::read_to_string(&primary) {
        Ok(c) => c,
        Err(_) => match fs::read_to_string(&fallback) {
            Ok(c) => c,
            Err(_) => return HashMap::new(),
        },
    };

    let mut map = HashMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let value = value.trim();
            // Strip surrounding double quotes if present.
            let value = if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
                &value[1..value.len() - 1]
            } else {
                value
            };
            map.insert(key.trim().to_string(), value.to_string());
        }
    }
    map
}

/// Detect the distro name from `os-release` inside a rootfs.
///
/// Returns `PRETTY_NAME` if present, else `NAME`, else an empty string.
fn detect_distro(rootfs: &Path) -> String {
    let map = parse_os_release(rootfs);
    if let Some(v) = map.get("PRETTY_NAME") {
        return v.clone();
    }
    if let Some(v) = map.get("NAME") {
        return v.clone();
    }
    String::new()
}

/// List all imported root filesystems under `{datadir}/rootfs/`.
///
/// Returns entries sorted by name. If no rootfs directory exists,
/// returns an empty vec (not an error).
pub fn list(datadir: &Path) -> Result<Vec<RootfsEntry>> {
    let rootfs_dir = datadir.join("rootfs");
    if !rootfs_dir.exists() {
        return Ok(Vec::new());
    }

    let mut entries = Vec::new();
    for entry in fs::read_dir(&rootfs_dir)
        .with_context(|| format!("failed to read {}", rootfs_dir.display()))?
    {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();

        // Skip hidden entries (staging dirs like .foo.importing, meta files).
        if name.starts_with('.') {
            continue;
        }

        if !entry.file_type()?.is_dir() {
            continue;
        }

        // Try sidecar metadata first; fall back to live detection.
        let meta_path = rootfs_dir.join(format!(".{name}.meta"));
        let distro = if meta_path.exists() {
            State::read_from(&meta_path)
                .ok()
                .and_then(|s| s.get("DISTRO").map(|v| v.to_string()))
                .unwrap_or_default()
        } else {
            detect_distro(&entry.path())
        };

        entries.push(RootfsEntry { name, distro });
    }

    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(entries)
}

/// Classifies the source argument for rootfs import.
#[derive(Debug)]
enum SourceKind {
    Directory(PathBuf),
    Tarball(PathBuf),
    Url(String),
}

/// Detect whether the source is a URL, directory, tarball file, or invalid.
fn detect_source_kind(source: &str) -> Result<SourceKind> {
    if source.starts_with("http://") || source.starts_with("https://") {
        return Ok(SourceKind::Url(source.to_string()));
    }

    let path = Path::new(source);
    if path.is_dir() {
        return Ok(SourceKind::Directory(path.to_path_buf()));
    }
    if path.is_file() {
        return Ok(SourceKind::Tarball(path.to_path_buf()));
    }
    if !path.exists() {
        bail!("source path does not exist: {source}");
    }
    bail!("source path is not a file or directory: {source}");
}

/// Extract a tarball into the staging directory using the `tar` CLI.
fn import_tarball(tarball: &Path, staging_dir: &Path, verbose: bool) -> Result<()> {
    let tar_bin = system_check::find_program("tar")
        .context("tar is required for tarball import; install it with: apt install tar")?;

    fs::create_dir_all(staging_dir)
        .with_context(|| format!("failed to create staging dir {}", staging_dir.display()))?;

    if verbose {
        eprintln!("extracting {} -> {}", tarball.display(), staging_dir.display());
    }

    let output = Command::new(&tar_bin)
        .args(["xf", &tarball.to_string_lossy(), "-C", &staging_dir.to_string_lossy()])
        .output()
        .with_context(|| format!("failed to run {}", tar_bin.display()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("tar extraction failed: {}", stderr.trim());
    }

    Ok(())
}

/// Download a URL to a local file, streaming to constant memory.
fn download_file(url: &str, dest: &Path, verbose: bool) -> Result<()> {
    if verbose {
        eprintln!("downloading {url}");
    }

    let response = ureq::get(url)
        .call()
        .with_context(|| format!("failed to download {url}"))?;

    let mut reader = response.into_body().into_reader();
    let mut file = fs::File::create(dest)
        .with_context(|| format!("failed to create {}", dest.display()))?;

    let bytes = std::io::copy(&mut reader, &mut file)
        .with_context(|| format!("failed to write download to {}", dest.display()))?;

    if verbose {
        eprintln!("downloaded {} bytes to {}", bytes, dest.display());
    }

    Ok(())
}

/// Download a URL to a temp file and extract it as a tarball.
fn import_url(url: &str, staging_dir: &Path, rootfs_dir: &Path, name: &str, verbose: bool) -> Result<()> {
    let temp_file = rootfs_dir.join(format!(".{name}.download"));

    let result = (|| -> Result<()> {
        download_file(url, &temp_file, verbose)?;
        import_tarball(&temp_file, staging_dir, verbose)
    })();

    // Clean up temp file on both success and failure.
    let _ = fs::remove_file(&temp_file);

    result
}

/// Import a root filesystem from a directory, tarball, or URL.
///
/// The source can be:
/// - A local directory (e.g. debootstrap output)
/// - A tarball file (.tar, .tar.gz, .tar.bz2, .tar.xz)
/// - An HTTP/HTTPS URL pointing to a tarball
///
/// The import is transactional: files are copied/extracted into a staging
/// directory and atomically renamed into place on success.
pub fn import(datadir: &Path, source: &str, name: &str, verbose: bool, force: bool) -> Result<()> {
    validate_name(name)?;

    let kind = detect_source_kind(source)?;

    let rootfs_dir = datadir.join("rootfs");
    let final_dir = rootfs_dir.join(name);
    if final_dir.exists() {
        if !force {
            bail!("rootfs already exists: {name}; re-run with -f to replace it");
        }
        if verbose {
            eprintln!("removing existing rootfs '{name}' (forced)");
        }
        let _ = make_removable(&final_dir);
        fs::remove_dir_all(&final_dir)
            .with_context(|| format!("failed to remove existing rootfs {}", final_dir.display()))?;
        let meta_path = rootfs_dir.join(format!(".{name}.meta"));
        let _ = fs::remove_file(meta_path);
    }

    let staging_name = format!(".{name}.importing");
    let staging_dir = rootfs_dir.join(&staging_name);

    // Clean up any leftover staging dir from a previous failed attempt.
    cleanup_staging(&staging_dir, force, verbose)?;

    fs::create_dir_all(&rootfs_dir)
        .with_context(|| format!("failed to create {}", rootfs_dir.display()))?;

    let result = match kind {
        SourceKind::Directory(ref dir) => do_import(dir, &staging_dir, verbose),
        SourceKind::Tarball(ref path) => import_tarball(path, &staging_dir, verbose),
        SourceKind::Url(ref url) => import_url(url, &staging_dir, &rootfs_dir, name, verbose),
    };

    match result {
        Ok(()) => {
            fs::rename(&staging_dir, &final_dir).with_context(|| {
                format!(
                    "failed to rename {} to {}",
                    staging_dir.display(),
                    final_dir.display()
                )
            })?;

            // Write distro metadata sidecar.
            let distro = detect_distro(&final_dir);
            let mut meta = State::new();
            meta.set("DISTRO", &distro);
            let meta_path = rootfs_dir.join(format!(".{name}.meta"));
            meta.write_to(&meta_path)?;

            if verbose {
                eprintln!("imported rootfs '{name}' from {source}");
            }
            Ok(())
        }
        Err(e) => {
            let _ = make_removable(&staging_dir);
            let _ = fs::remove_dir_all(&staging_dir);
            Err(e)
        }
    }
}

/// Remove a leftover staging directory from a previous failed import.
///
/// When `force` is true, attempts to fix permissions and remove the directory.
/// When `force` is false and the directory exists, returns an error telling
/// the user to retry with `-f`.
fn cleanup_staging(staging_dir: &Path, force: bool, verbose: bool) -> Result<()> {
    if !staging_dir.exists() {
        return Ok(());
    }
    if !force {
        bail!(
            "staging directory already exists: {}\n\
             a previous import may have failed; re-run with -f to remove it and try again",
            staging_dir.display()
        );
    }
    if verbose {
        eprintln!("removing leftover staging directory: {}", staging_dir.display());
    }
    let _ = make_removable(staging_dir);
    fs::remove_dir_all(staging_dir)
        .with_context(|| format!("failed to remove staging directory {}", staging_dir.display()))?;
    Ok(())
}

fn do_import(source: &Path, staging: &Path, verbose: bool) -> Result<()> {
    // Create the staging directory and copy the root directory's metadata.
    fs::create_dir(staging)
        .with_context(|| format!("failed to create staging dir {}", staging.display()))?;
    copy_metadata(source, staging)
        .with_context(|| format!("failed to copy metadata for {}", source.display()))?;
    copy_xattrs(source, staging)?;

    if verbose {
        eprintln!("copying {} -> {}", source.display(), staging.display());
    }

    copy_tree(source, staging, verbose)
}

fn copy_tree(src_dir: &Path, dst_dir: &Path, verbose: bool) -> Result<()> {
    let entries = fs::read_dir(src_dir)
        .with_context(|| format!("failed to read directory {}", src_dir.display()))?;

    for entry in entries {
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

fn copy_entry(src: &Path, dst: &Path, verbose: bool) -> Result<()> {
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
            fs::copy(src, dst)
                .with_context(|| format!("failed to copy file {}", src.display()))?;
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
                // ENOTSUP on some filesystems for symlink timestamps — not fatal.
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
            let ret =
                unsafe { libc::mknod(c_path.as_ptr(), libc::S_IFSOCK | (stat.st_mode & 0o7777), 0) };
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

fn copy_metadata_from_stat(dst: &Path, stat: &libc::stat) -> Result<()> {
    let c_path = path_to_cstring(dst)?;

    // Ownership.
    let ret = unsafe { libc::lchown(c_path.as_ptr(), stat.st_uid, stat.st_gid) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("lchown failed for {}", dst.display()));
    }

    // Permission bits (skip for symlinks — chmod doesn't apply to them).
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

fn copy_metadata(src: &Path, dst: &Path) -> Result<()> {
    let stat = lstat_entry(src)?;
    copy_metadata_from_stat(dst, &stat)
}

fn copy_xattrs(src: &Path, dst: &Path) -> Result<()> {
    let c_src = path_to_cstring(src)?;
    let c_dst = path_to_cstring(dst)?;

    // Get the size of the xattr name list.
    let size = unsafe { libc::llistxattr(c_src.as_ptr(), std::ptr::null_mut(), 0) };
    if size < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOTSUP) || err.raw_os_error() == Some(libc::ENODATA)
        {
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

        let c_name = CString::new(name_bytes)
            .with_context(|| "xattr name contains interior null byte")?;

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

/// Remove an imported root filesystem.
///
/// Validates the name, checks that no container references it, then removes
/// the rootfs directory and its `.meta` sidecar.
///
/// To prevent a TOCTOU race where `sdme create --rootfs <name>` could
/// reference the rootfs between the usage check and the deletion, we
/// first rename the rootfs directory to a staging name (atomic on the same
/// filesystem), then verify no container was created referencing it. If a
/// reference appeared, we rename it back and bail.
pub fn remove(datadir: &Path, name: &str, verbose: bool) -> Result<()> {
    validate_name(name)?;

    let rootfs_path = datadir.join("rootfs").join(name);
    if !rootfs_path.exists() {
        bail!("rootfs not found: {name}");
    }

    // Check that no container is using this rootfs (first pass).
    check_rootfs_in_use(datadir, name)?;

    // Atomically rename the rootfs to a staging name so that any concurrent
    // `sdme create --rootfs <name>` will fail with "rootfs not found" instead
    // of creating a container with a dangling reference.
    let removing_path = datadir.join("rootfs").join(format!(".{name}.removing"));
    fs::rename(&rootfs_path, &removing_path).with_context(|| {
        format!(
            "failed to rename {} to {}",
            rootfs_path.display(),
            removing_path.display()
        )
    })?;

    // Re-check after rename: if a container was created between the first check
    // and the rename, we need to restore the rootfs.
    if let Err(e) = check_rootfs_in_use(datadir, name) {
        // Restore the rootfs directory.
        let _ = fs::rename(&removing_path, &rootfs_path);
        return Err(e);
    }

    make_removable(&removing_path)?;
    fs::remove_dir_all(&removing_path)
        .with_context(|| format!("failed to remove {}", removing_path.display()))?;

    let meta_path = datadir.join("rootfs").join(format!(".{name}.meta"));
    let _ = fs::remove_file(meta_path);

    if verbose {
        eprintln!("removed rootfs '{name}'");
    }

    Ok(())
}

fn check_rootfs_in_use(datadir: &Path, name: &str) -> Result<()> {
    let state_dir = datadir.join("state");
    if !state_dir.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(&state_dir)
        .with_context(|| format!("failed to read {}", state_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if let Ok(state) = State::read_from(&path) {
            if state.get("ROOTFS") == Some(name) {
                let container = match state.get("NAME") {
                    Some(n) => n.to_string(),
                    None => entry
                        .file_name()
                        .to_str()
                        .unwrap_or("unknown")
                        .to_string(),
                };
                bail!("rootfs '{name}' is in use by container '{container}'");
            }
        }
    }
    Ok(())
}

/// Recursively restore directory permissions so `remove_dir_all` can succeed.
fn make_removable(path: &Path) -> std::io::Result<()> {
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

fn lstat_entry(path: &Path) -> Result<libc::stat> {
    let c_path = path_to_cstring(path)?;
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::lstat(c_path.as_ptr(), &mut stat) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("lstat failed for {}", path.display()));
    }
    Ok(stat)
}

fn path_to_cstring(path: &Path) -> Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .with_context(|| format!("path contains null byte: {}", path.display()))
}

fn lchown(path: &Path, uid: u32, gid: u32) -> Result<()> {
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
    use std::os::unix::fs::PermissionsExt;

    struct TempDataDir {
        dir: std::path::PathBuf,
    }

    impl TempDataDir {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "sdme-test-rootfs-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            Self { dir }
        }

        fn path(&self) -> &Path {
            &self.dir
        }
    }

    impl Drop for TempDataDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    struct TempSourceDir {
        dir: std::path::PathBuf,
    }

    impl TempSourceDir {
        fn new(suffix: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "sdme-test-rootfs-src-{}-{:?}-{suffix}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            Self { dir }
        }

        fn path(&self) -> &Path {
            &self.dir
        }
    }

    impl Drop for TempSourceDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn test_import_basic_directory() {
        let tmp = TempDataDir::new();
        let src = TempSourceDir::new("basic");

        // Create source structure.
        fs::write(src.path().join("hello.txt"), "hello world\n").unwrap();
        fs::create_dir(src.path().join("subdir")).unwrap();
        fs::write(src.path().join("subdir/nested.txt"), "nested\n").unwrap();

        import(tmp.path(), src.path().to_str().unwrap(), "test", false, false).unwrap();

        let rootfs = tmp.path().join("rootfs/test");
        assert!(rootfs.is_dir());
        assert_eq!(
            fs::read_to_string(rootfs.join("hello.txt")).unwrap(),
            "hello world\n"
        );
        assert!(rootfs.join("subdir").is_dir());
        assert_eq!(
            fs::read_to_string(rootfs.join("subdir/nested.txt")).unwrap(),
            "nested\n"
        );
    }

    #[test]
    fn test_import_preserves_permissions() {
        let tmp = TempDataDir::new();
        let src = TempSourceDir::new("perms");

        let file_path = src.path().join("script.sh");
        fs::write(&file_path, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&file_path, fs::Permissions::from_mode(0o755)).unwrap();

        let ro_path = src.path().join("readonly.txt");
        fs::write(&ro_path, "data\n").unwrap();
        fs::set_permissions(&ro_path, fs::Permissions::from_mode(0o644)).unwrap();

        let suid_path = src.path().join("suid");
        fs::write(&suid_path, "suid\n").unwrap();
        fs::set_permissions(&suid_path, fs::Permissions::from_mode(0o4755)).unwrap();

        import(tmp.path(), src.path().to_str().unwrap(), "perms", false, false).unwrap();

        let rootfs = tmp.path().join("rootfs/perms");
        let meta = fs::metadata(rootfs.join("script.sh")).unwrap();
        assert_eq!(meta.permissions().mode() & 0o7777, 0o755);

        let meta = fs::metadata(rootfs.join("readonly.txt")).unwrap();
        assert_eq!(meta.permissions().mode() & 0o7777, 0o644);

        let meta = fs::metadata(rootfs.join("suid")).unwrap();
        // SUID bit preserved when running as root; silently cleared otherwise.
        let suid_mode = meta.permissions().mode() & 0o7777;
        assert!(suid_mode == 0o4755 || suid_mode == 0o755);
    }

    #[test]
    fn test_import_preserves_symlinks() {
        let tmp = TempDataDir::new();
        let src = TempSourceDir::new("symlinks");

        fs::write(src.path().join("target.txt"), "target\n").unwrap();
        unix_fs::symlink("target.txt", src.path().join("link.txt")).unwrap();
        // Dangling symlink.
        unix_fs::symlink("/nonexistent", src.path().join("dangling")).unwrap();

        import(tmp.path(), src.path().to_str().unwrap(), "sym", false, false).unwrap();

        let rootfs = tmp.path().join("rootfs/sym");
        let link_target = fs::read_link(rootfs.join("link.txt")).unwrap();
        assert_eq!(link_target.to_str().unwrap(), "target.txt");

        let dangling_target = fs::read_link(rootfs.join("dangling")).unwrap();
        assert_eq!(dangling_target.to_str().unwrap(), "/nonexistent");
    }

    #[test]
    fn test_import_duplicate_name() {
        let tmp = TempDataDir::new();
        let src = TempSourceDir::new("dup");

        import(tmp.path(), src.path().to_str().unwrap(), "dup", false, false).unwrap();
        let err = import(tmp.path(), src.path().to_str().unwrap(), "dup", false, false).unwrap_err();
        assert!(
            err.to_string().contains("already exists"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_import_invalid_name() {
        let tmp = TempDataDir::new();
        let src = TempSourceDir::new("invalid");

        let err = import(tmp.path(), src.path().to_str().unwrap(), "INVALID", false, false).unwrap_err();
        assert!(
            err.to_string().contains("lowercase"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_import_source_not_directory() {
        let tmp = TempDataDir::new();
        let file_path = std::env::temp_dir().join(format!(
            "sdme-test-rootfs-notdir-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        fs::write(&file_path, "not a dir").unwrap();

        // A regular file is now treated as a tarball, so expect a tar error.
        let err = import(tmp.path(), file_path.to_str().unwrap(), "test", false, false).unwrap_err();
        assert!(
            err.to_string().contains("tar"),
            "unexpected error: {err}"
        );

        let _ = fs::remove_file(&file_path);
    }

    #[test]
    fn test_import_source_not_found() {
        let tmp = TempDataDir::new();
        let missing = Path::new("/tmp/sdme-test-definitely-nonexistent");

        let err = import(tmp.path(), missing.to_str().unwrap(), "test", false, false).unwrap_err();
        assert!(
            err.to_string().contains("does not exist"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_import_cleanup_on_failure() {
        let tmp = TempDataDir::new();
        let src = TempSourceDir::new("cleanup");

        // Create a subdirectory that can't be read.
        let unreadable = src.path().join("secret");
        fs::create_dir(&unreadable).unwrap();
        fs::write(unreadable.join("file.txt"), "data").unwrap();
        fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o000)).unwrap();

        let result = import(tmp.path(), src.path().to_str().unwrap(), "fail", false, false);
        assert!(result.is_err());

        // Staging dir should be cleaned up.
        let staging = tmp.path().join("rootfs/.fail.importing");
        assert!(!staging.exists(), "staging dir was not cleaned up");

        // Final dir should not exist.
        let final_dir = tmp.path().join("rootfs/fail");
        assert!(!final_dir.exists(), "final dir should not exist");

        // Restore permissions so TempSourceDir can clean up.
        fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn test_import_preserves_empty_directories() {
        let tmp = TempDataDir::new();
        let src = TempSourceDir::new("emptydir");

        fs::create_dir(src.path().join("empty")).unwrap();
        fs::create_dir(src.path().join("also-empty")).unwrap();

        import(tmp.path(), src.path().to_str().unwrap(), "empty", false, false).unwrap();

        let rootfs = tmp.path().join("rootfs/empty");
        assert!(rootfs.join("empty").is_dir());
        assert!(rootfs.join("also-empty").is_dir());
        assert_eq!(fs::read_dir(rootfs.join("empty")).unwrap().count(), 0);
        assert_eq!(fs::read_dir(rootfs.join("also-empty")).unwrap().count(), 0);
    }

    #[test]
    fn test_import_preserves_timestamps() {
        let tmp = TempDataDir::new();
        let src = TempSourceDir::new("timestamps");

        let file_path = src.path().join("file.txt");
        fs::write(&file_path, "data\n").unwrap();

        // Set a specific mtime.
        let times = [
            libc::timespec {
                tv_sec: 1000000000,
                tv_nsec: 0,
            },
            libc::timespec {
                tv_sec: 1000000000,
                tv_nsec: 0,
            },
        ];
        let c_path = path_to_cstring(&file_path).unwrap();
        unsafe {
            libc::utimensat(
                libc::AT_FDCWD,
                c_path.as_ptr(),
                times.as_ptr(),
                0,
            );
        }

        import(tmp.path(), src.path().to_str().unwrap(), "ts", false, false).unwrap();

        let dst_stat = lstat_entry(&tmp.path().join("rootfs/ts/file.txt")).unwrap();
        assert_eq!(dst_stat.st_mtime, 1000000000);
    }

    #[test]
    #[ignore] // Requires CAP_MKNOD (root).
    fn test_import_preserves_devices() {
        let tmp = TempDataDir::new();
        let src = TempSourceDir::new("devices");

        // Create a character device (null-like).
        let dev_path = src.path().join("null");
        let c_path = path_to_cstring(&dev_path).unwrap();
        let dev = libc::makedev(1, 3);
        let ret = unsafe { libc::mknod(c_path.as_ptr(), libc::S_IFCHR | 0o666, dev) };
        assert_eq!(ret, 0, "mknod failed (need root)");

        import(tmp.path(), src.path().to_str().unwrap(), "dev", false, false).unwrap();

        let dst_stat = lstat_entry(&tmp.path().join("rootfs/dev/null")).unwrap();
        assert_eq!(dst_stat.st_mode & libc::S_IFMT, libc::S_IFCHR);
        assert_eq!(dst_stat.st_rdev, dev);
    }

    #[test]
    fn test_import_stores_distro_metadata() {
        let tmp = TempDataDir::new();
        let src = TempSourceDir::new("distro");

        fs::create_dir_all(src.path().join("etc")).unwrap();
        fs::write(
            src.path().join("etc/os-release"),
            "PRETTY_NAME=\"Ubuntu 24.04.4 LTS\"\nNAME=\"Ubuntu\"\n",
        )
        .unwrap();

        import(tmp.path(), src.path().to_str().unwrap(), "distro", false, false).unwrap();

        let meta_path = tmp.path().join("rootfs/.distro.meta");
        assert!(meta_path.exists(), ".meta sidecar should exist");
        let state = State::read_from(&meta_path).unwrap();
        assert_eq!(state.get("DISTRO").unwrap(), "Ubuntu 24.04.4 LTS");
    }

    #[test]
    fn test_import_no_os_release() {
        let tmp = TempDataDir::new();
        let src = TempSourceDir::new("no-os-release");

        fs::write(src.path().join("hello.txt"), "hi\n").unwrap();

        import(tmp.path(), src.path().to_str().unwrap(), "noos", false, false).unwrap();

        let meta_path = tmp.path().join("rootfs/.noos.meta");
        assert!(meta_path.exists(), ".meta sidecar should exist");
        let state = State::read_from(&meta_path).unwrap();
        assert_eq!(state.get("DISTRO").unwrap(), "");
    }

    #[test]
    fn test_parse_os_release_quoted() {
        let tmp = TempSourceDir::new("quoted");

        fs::create_dir_all(tmp.path().join("etc")).unwrap();
        fs::write(
            tmp.path().join("etc/os-release"),
            "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nNAME=\"Debian GNU/Linux\"\nID=debian\n",
        )
        .unwrap();

        let map = parse_os_release(tmp.path());
        assert_eq!(
            map.get("PRETTY_NAME").unwrap(),
            "Debian GNU/Linux 12 (bookworm)"
        );
        assert_eq!(map.get("NAME").unwrap(), "Debian GNU/Linux");
        assert_eq!(map.get("ID").unwrap(), "debian");
    }

    #[test]
    fn test_parse_os_release_fallback_path() {
        let tmp = TempSourceDir::new("fallback");

        // No etc/os-release, but usr/lib/os-release exists.
        fs::create_dir_all(tmp.path().join("usr/lib")).unwrap();
        fs::write(
            tmp.path().join("usr/lib/os-release"),
            "PRETTY_NAME=\"Arch Linux\"\n",
        )
        .unwrap();

        let map = parse_os_release(tmp.path());
        assert_eq!(map.get("PRETTY_NAME").unwrap(), "Arch Linux");
    }

    #[test]
    fn test_list_empty() {
        let tmp = TempDataDir::new();
        let entries = list(tmp.path()).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_list_entries() {
        let tmp = TempDataDir::new();

        // Import two rootfs with different distros.
        let src_a = TempSourceDir::new("list-a");
        fs::create_dir_all(src_a.path().join("etc")).unwrap();
        fs::write(
            src_a.path().join("etc/os-release"),
            "PRETTY_NAME=\"Ubuntu 24.04 LTS\"\n",
        )
        .unwrap();

        let src_b = TempSourceDir::new("list-b");
        fs::create_dir_all(src_b.path().join("etc")).unwrap();
        fs::write(
            src_b.path().join("etc/os-release"),
            "PRETTY_NAME=\"Debian 12\"\n",
        )
        .unwrap();

        import(tmp.path(), src_a.path().to_str().unwrap(), "ubuntu", false, false).unwrap();
        import(tmp.path(), src_b.path().to_str().unwrap(), "debian", false, false).unwrap();

        let entries = list(tmp.path()).unwrap();
        assert_eq!(entries.len(), 2);
        // Sorted by name.
        assert_eq!(entries[0].name, "debian");
        assert_eq!(entries[0].distro, "Debian 12");
        assert_eq!(entries[1].name, "ubuntu");
        assert_eq!(entries[1].distro, "Ubuntu 24.04 LTS");
    }

    #[test]
    fn test_list_skips_staging_dirs() {
        let tmp = TempDataDir::new();

        // Import a real rootfs.
        let src = TempSourceDir::new("staging");
        import(tmp.path(), src.path().to_str().unwrap(), "real", false, false).unwrap();

        // Create a fake staging dir that should be skipped.
        fs::create_dir_all(tmp.path().join("rootfs/.fake.importing")).unwrap();

        let entries = list(tmp.path()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "real");
    }

    #[test]
    #[ignore] // Requires CAP_CHOWN (root).
    fn test_import_preserves_ownership() {
        let tmp = TempDataDir::new();
        let src = TempSourceDir::new("ownership");

        let file_path = src.path().join("owned.txt");
        fs::write(&file_path, "data\n").unwrap();
        let c_path = path_to_cstring(&file_path).unwrap();
        unsafe {
            libc::chown(c_path.as_ptr(), 1000, 1000);
        }

        import(tmp.path(), src.path().to_str().unwrap(), "own", false, false).unwrap();

        let dst_stat = lstat_entry(&tmp.path().join("rootfs/own/owned.txt")).unwrap();
        assert_eq!(dst_stat.st_uid, 1000);
        assert_eq!(dst_stat.st_gid, 1000);
    }

    #[test]
    fn test_remove_basic() {
        let tmp = TempDataDir::new();
        let src = TempSourceDir::new("rm-basic");
        fs::write(src.path().join("file.txt"), "data\n").unwrap();

        import(tmp.path(), src.path().to_str().unwrap(), "rmme", false, false).unwrap();
        assert!(tmp.path().join("rootfs/rmme").is_dir());
        assert!(tmp.path().join("rootfs/.rmme.meta").exists());

        remove(tmp.path(), "rmme", false).unwrap();
        assert!(!tmp.path().join("rootfs/rmme").exists());
        assert!(!tmp.path().join("rootfs/.rmme.meta").exists());
    }

    #[test]
    fn test_remove_not_found() {
        let tmp = TempDataDir::new();
        let err = remove(tmp.path(), "nonexistent", false).unwrap_err();
        assert!(
            err.to_string().contains("not found"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_remove_in_use() {
        let tmp = TempDataDir::new();
        let src = TempSourceDir::new("rm-inuse");
        import(tmp.path(), src.path().to_str().unwrap(), "inuse", false, false).unwrap();

        // Create a container state file that references this rootfs.
        let state_dir = tmp.path().join("state");
        fs::create_dir_all(&state_dir).unwrap();
        let mut state = State::new();
        state.set("NAME", "mycontainer");
        state.set("ROOTFS", "inuse");
        state.write_to(&state_dir.join("mycontainer")).unwrap();

        let err = remove(tmp.path(), "inuse", false).unwrap_err();
        assert!(
            err.to_string().contains("in use"),
            "unexpected error: {err}"
        );
        // Rootfs should still exist.
        assert!(tmp.path().join("rootfs/inuse").is_dir());
    }

    #[test]
    fn test_remove_multiple() {
        let tmp = TempDataDir::new();
        let src_a = TempSourceDir::new("rm-multi-a");
        let src_b = TempSourceDir::new("rm-multi-b");

        import(tmp.path(), src_a.path().to_str().unwrap(), "alpha", false, false).unwrap();
        import(tmp.path(), src_b.path().to_str().unwrap(), "beta", false, false).unwrap();
        assert_eq!(list(tmp.path()).unwrap().len(), 2);

        remove(tmp.path(), "alpha", false).unwrap();
        remove(tmp.path(), "beta", false).unwrap();

        assert!(list(tmp.path()).unwrap().is_empty());
        assert!(!tmp.path().join("rootfs/alpha").exists());
        assert!(!tmp.path().join("rootfs/beta").exists());
    }

    #[test]
    fn test_detect_source_kind_url() {
        match detect_source_kind("https://example.com/rootfs.tar.gz").unwrap() {
            SourceKind::Url(u) => assert_eq!(u, "https://example.com/rootfs.tar.gz"),
            _ => panic!("expected Url"),
        }
        match detect_source_kind("http://example.com/rootfs.tar").unwrap() {
            SourceKind::Url(u) => assert_eq!(u, "http://example.com/rootfs.tar"),
            _ => panic!("expected Url"),
        }
    }

    #[test]
    fn test_detect_source_kind_directory() {
        let src = TempSourceDir::new("detect-dir");
        match detect_source_kind(src.path().to_str().unwrap()).unwrap() {
            SourceKind::Directory(p) => assert_eq!(p, src.path()),
            _ => panic!("expected Directory"),
        }
    }

    #[test]
    fn test_detect_source_kind_file() {
        let file_path = std::env::temp_dir().join(format!(
            "sdme-test-detect-file-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        fs::write(&file_path, "data").unwrap();
        match detect_source_kind(file_path.to_str().unwrap()).unwrap() {
            SourceKind::Tarball(p) => assert_eq!(p, file_path),
            _ => panic!("expected Tarball"),
        }
        let _ = fs::remove_file(&file_path);
    }

    #[test]
    fn test_detect_source_kind_not_found() {
        let err = detect_source_kind("/tmp/sdme-test-definitely-nonexistent").unwrap_err();
        assert!(
            err.to_string().contains("does not exist"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_import_tarball_basic() {
        let tmp = TempDataDir::new();
        let src = TempSourceDir::new("tarball-gz");

        // Create source files.
        fs::write(src.path().join("hello.txt"), "hello world\n").unwrap();
        fs::create_dir(src.path().join("subdir")).unwrap();
        fs::write(src.path().join("subdir/nested.txt"), "nested\n").unwrap();

        // Create a tarball from the source directory.
        let tarball = std::env::temp_dir().join(format!(
            "sdme-test-tarball-{}-{:?}.tar.gz",
            std::process::id(),
            std::thread::current().id()
        ));
        let output = Command::new("tar")
            .args(["czf", tarball.to_str().unwrap(), "-C", src.path().to_str().unwrap(), "."])
            .output()
            .unwrap();
        assert!(output.status.success(), "tar create failed");

        import(tmp.path(), tarball.to_str().unwrap(), "tgz", false, false).unwrap();

        let rootfs = tmp.path().join("rootfs/tgz");
        assert!(rootfs.is_dir());
        assert_eq!(
            fs::read_to_string(rootfs.join("hello.txt")).unwrap(),
            "hello world\n"
        );
        assert!(rootfs.join("subdir").is_dir());
        assert_eq!(
            fs::read_to_string(rootfs.join("subdir/nested.txt")).unwrap(),
            "nested\n"
        );

        let _ = fs::remove_file(&tarball);
    }

    #[test]
    fn test_import_tarball_uncompressed() {
        let tmp = TempDataDir::new();
        let src = TempSourceDir::new("tarball-plain");

        fs::write(src.path().join("file.txt"), "content\n").unwrap();

        let tarball = std::env::temp_dir().join(format!(
            "sdme-test-tarball-plain-{}-{:?}.tar",
            std::process::id(),
            std::thread::current().id()
        ));
        let output = Command::new("tar")
            .args(["cf", tarball.to_str().unwrap(), "-C", src.path().to_str().unwrap(), "."])
            .output()
            .unwrap();
        assert!(output.status.success(), "tar create failed");

        import(tmp.path(), tarball.to_str().unwrap(), "plain", false, false).unwrap();

        let rootfs = tmp.path().join("rootfs/plain");
        assert_eq!(
            fs::read_to_string(rootfs.join("file.txt")).unwrap(),
            "content\n"
        );

        let _ = fs::remove_file(&tarball);
    }

    #[test]
    fn test_import_tarball_invalid_file() {
        let tmp = TempDataDir::new();
        let file_path = std::env::temp_dir().join(format!(
            "sdme-test-bad-tarball-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        fs::write(&file_path, "this is not a tarball").unwrap();

        let err = import(tmp.path(), file_path.to_str().unwrap(), "bad", false, false).unwrap_err();
        assert!(
            err.to_string().contains("tar"),
            "unexpected error: {err}"
        );

        // Staging dir should be cleaned up.
        assert!(!tmp.path().join("rootfs/.bad.importing").exists());

        let _ = fs::remove_file(&file_path);
    }
}
