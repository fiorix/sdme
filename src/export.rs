//! Rootfs export: directory copy, tarball creation, raw disk image.
//!
//! Exports an imported rootfs or a container's merged overlayfs view
//! to a directory, compressed tarball, or bare ext4/btrfs raw disk image.

use std::fs::{self, File};
use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::{check_interrupted, containers, copy, system_check, systemd, validate_name, State};

/// Filesystem type for raw disk image export.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum RawFs {
    #[default]
    Ext4,
    Btrfs,
}

impl std::fmt::Display for RawFs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RawFs::Ext4 => write!(f, "ext4"),
            RawFs::Btrfs => write!(f, "btrfs"),
        }
    }
}

/// Output format for rootfs export.
#[derive(Debug, Clone, PartialEq)]
pub enum ExportFormat {
    /// Plain directory copy.
    Dir,
    /// Uncompressed tar archive.
    Tar,
    /// Gzip-compressed tar archive.
    TarGz,
    /// Bzip2-compressed tar archive.
    TarBz2,
    /// XZ-compressed tar archive.
    TarXz,
    /// Zstandard-compressed tar archive.
    TarZst,
    /// Bare filesystem in a raw disk image (no partition table).
    Raw(RawFs),
}

/// Detect the export format from the output path extension, with an
/// optional override string.
pub fn detect_format(output: &str, format_override: Option<&str>) -> Result<ExportFormat> {
    if let Some(fmt) = format_override {
        return match fmt {
            "dir" => Ok(ExportFormat::Dir),
            "tar" => Ok(ExportFormat::Tar),
            "tar.gz" => Ok(ExportFormat::TarGz),
            "tar.bz2" => Ok(ExportFormat::TarBz2),
            "tar.xz" => Ok(ExportFormat::TarXz),
            "tar.zst" => Ok(ExportFormat::TarZst),
            "raw" => Ok(ExportFormat::Raw(RawFs::Ext4)),
            _ => bail!("unknown format '{fmt}': expected dir, tar, tar.gz, tar.bz2, tar.xz, tar.zst, or raw"),
        };
    }

    let lower = output.to_ascii_lowercase();
    if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") {
        Ok(ExportFormat::TarGz)
    } else if lower.ends_with(".tar.bz2") || lower.ends_with(".tbz2") {
        Ok(ExportFormat::TarBz2)
    } else if lower.ends_with(".tar.xz") || lower.ends_with(".txz") {
        Ok(ExportFormat::TarXz)
    } else if lower.ends_with(".tar.zst") || lower.ends_with(".tzst") {
        Ok(ExportFormat::TarZst)
    } else if lower.ends_with(".tar") {
        Ok(ExportFormat::Tar)
    } else if lower.ends_with(".img") || lower.ends_with(".raw") {
        Ok(ExportFormat::Raw(RawFs::Ext4))
    } else {
        Ok(ExportFormat::Dir)
    }
}

/// Export an imported rootfs to the given output path.
pub fn export_rootfs(
    datadir: &Path,
    name: &str,
    output: &Path,
    format: &ExportFormat,
    size: Option<&str>,
    verbose: bool,
) -> Result<()> {
    validate_name(name).context("invalid rootfs name")?;
    let rootfs_dir = datadir.join("fs").join(name);
    if !rootfs_dir.is_dir() {
        bail!("rootfs not found: {name}");
    }
    export_from_dir(&rootfs_dir, output, format, size, verbose)
}

/// Export a container's merged rootfs to the given output path.
///
/// If the container is running, exports directly from the live `merged/`
/// directory (with a warning about consistency). If stopped, temporarily
/// mounts overlayfs for the export.
pub fn export_container(
    datadir: &Path,
    name: &str,
    output: &Path,
    format: &ExportFormat,
    size: Option<&str>,
    verbose: bool,
) -> Result<()> {
    validate_name(name)?;
    containers::ensure_exists(datadir, name)?;

    let container_dir = datadir.join("containers").join(name);
    let merged_dir = container_dir.join("merged");

    let running = systemd::is_active(name)?;
    if running {
        eprintln!(
            "warning: container '{name}' is running; filesystem is live and \
             consistency is not guaranteed"
        );
        export_from_dir(&merged_dir, output, format, size, verbose)
    } else {
        // Read state to find the rootfs.
        let state_file = datadir.join("state").join(name);
        let state = State::read_from(&state_file)?;
        let rootfs_name = state.rootfs();
        let rootfs_dir = containers::resolve_rootfs(
            datadir,
            if rootfs_name.is_empty() {
                None
            } else {
                Some(rootfs_name)
            },
        )?;

        mount_overlay(&rootfs_dir, &container_dir)?;
        let result = export_from_dir(&merged_dir, output, format, size, verbose);
        unmount_overlay(&container_dir);
        result
    }
}

/// Core dispatcher: export from a source directory to the output in the
/// requested format.
fn export_from_dir(
    src: &Path,
    output: &Path,
    format: &ExportFormat,
    size: Option<&str>,
    verbose: bool,
) -> Result<()> {
    match format {
        ExportFormat::Dir => export_to_dir(src, output, verbose),
        ExportFormat::Tar
        | ExportFormat::TarGz
        | ExportFormat::TarBz2
        | ExportFormat::TarXz
        | ExportFormat::TarZst => export_to_tar(src, output, format, verbose),
        ExportFormat::Raw(fs_type) => export_to_raw(src, output, *fs_type, size, verbose),
    }
}

/// Export by copying the source directory tree to the destination.
fn export_to_dir(src: &Path, dst: &Path, verbose: bool) -> Result<()> {
    if dst.exists() {
        bail!("destination already exists: {}", dst.display());
    }
    fs::create_dir_all(dst).with_context(|| format!("failed to create {}", dst.display()))?;
    copy::copy_metadata(src, dst)?;
    copy::copy_xattrs(src, dst)?;
    copy::copy_tree(src, dst, verbose)
        .with_context(|| format!("failed to copy {} to {}", src.display(), dst.display()))
}

/// Export by creating a tar archive, optionally compressed.
fn export_to_tar(src: &Path, output: &Path, format: &ExportFormat, verbose: bool) -> Result<()> {
    if output.exists() {
        bail!("destination already exists: {}", output.display());
    }
    if verbose {
        eprintln!("creating tarball: {}", output.display());
    }

    match format {
        ExportFormat::Tar => {
            let file = File::create(output)
                .with_context(|| format!("failed to create {}", output.display()))?;
            let mut builder = tar::Builder::new(file);
            builder.follow_symlinks(false);
            append_dir_recursive(&mut builder, src, src, verbose)?;
            builder.finish()?;
        }
        ExportFormat::TarGz => {
            let file = File::create(output)
                .with_context(|| format!("failed to create {}", output.display()))?;
            let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
            let mut builder = tar::Builder::new(encoder);
            builder.follow_symlinks(false);
            append_dir_recursive(&mut builder, src, src, verbose)?;
            let encoder = builder.into_inner()?;
            encoder.finish()?;
        }
        ExportFormat::TarBz2 => {
            let file = File::create(output)
                .with_context(|| format!("failed to create {}", output.display()))?;
            let encoder = bzip2::write::BzEncoder::new(file, bzip2::Compression::default());
            let mut builder = tar::Builder::new(encoder);
            builder.follow_symlinks(false);
            append_dir_recursive(&mut builder, src, src, verbose)?;
            let encoder = builder.into_inner()?;
            encoder.finish()?;
        }
        ExportFormat::TarXz => {
            let file = File::create(output)
                .with_context(|| format!("failed to create {}", output.display()))?;
            let encoder = xz2::write::XzEncoder::new(file, 6);
            let mut builder = tar::Builder::new(encoder);
            builder.follow_symlinks(false);
            append_dir_recursive(&mut builder, src, src, verbose)?;
            let encoder = builder.into_inner()?;
            encoder.finish()?;
        }
        ExportFormat::TarZst => {
            let file = File::create(output)
                .with_context(|| format!("failed to create {}", output.display()))?;
            let encoder = zstd::stream::write::Encoder::new(file, 0)?;
            let mut builder = tar::Builder::new(encoder);
            builder.follow_symlinks(false);
            append_dir_recursive(&mut builder, src, src, verbose)?;
            let encoder = builder.into_inner()?;
            encoder.finish()?;
        }
        _ => unreachable!(),
    }

    Ok(())
}

/// Recursively append directory entries to a tar builder, preserving
/// ownership, permissions, and special file types.
fn append_dir_recursive<W: std::io::Write>(
    builder: &mut tar::Builder<W>,
    root: &Path,
    dir: &Path,
    verbose: bool,
) -> Result<()> {
    let entries =
        fs::read_dir(dir).with_context(|| format!("failed to read directory {}", dir.display()))?;

    for entry in entries {
        check_interrupted()?;
        let entry = entry.with_context(|| format!("failed to read entry in {}", dir.display()))?;
        let path = entry.path();
        let rel = path
            .strip_prefix(root)
            .with_context(|| format!("failed to strip prefix from {}", path.display()))?;

        if verbose {
            eprintln!("  {}", rel.display());
        }

        let meta = fs::symlink_metadata(&path)
            .with_context(|| format!("failed to stat {}", path.display()))?;

        let mut header = tar::Header::new_gnu();
        header.set_metadata_in_mode(&meta, tar::HeaderMode::Deterministic);
        // Restore actual uid/gid (Deterministic mode zeros them).
        header.set_uid(meta_uid(&meta));
        header.set_gid(meta_gid(&meta));

        if meta.is_dir() {
            builder.append_data(&mut header, rel, &[] as &[u8])?;
            append_dir_recursive(builder, root, &path, verbose)?;
        } else if meta.is_symlink() {
            let target = fs::read_link(&path)
                .with_context(|| format!("failed to read symlink {}", path.display()))?;
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            builder.append_link(&mut header, rel, &target)?;
        } else if meta.is_file() {
            let file =
                File::open(&path).with_context(|| format!("failed to open {}", path.display()))?;
            builder.append_data(&mut header, rel, file)?;
        } else {
            // Block/char devices, fifos, sockets — append header only.
            header.set_size(0);
            builder.append_data(&mut header, rel, &[] as &[u8])?;
        }
    }
    Ok(())
}

/// Extract uid from metadata (Unix-specific).
fn meta_uid(meta: &fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    meta.uid() as u64
}

/// Extract gid from metadata (Unix-specific).
fn meta_gid(meta: &fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    meta.gid() as u64
}

/// Export by creating a raw disk image with the specified filesystem.
fn export_to_raw(
    src: &Path,
    output: &Path,
    fs_type: RawFs,
    size: Option<&str>,
    verbose: bool,
) -> Result<()> {
    if output.exists() {
        bail!("destination already exists: {}", output.display());
    }

    let (mkfs_bin, mkfs_pkg) = match fs_type {
        RawFs::Ext4 => ("mkfs.ext4", "e2fsprogs"),
        RawFs::Btrfs => ("mkfs.btrfs", "btrfs-progs"),
    };
    system_check::check_dependencies(&[(mkfs_bin, mkfs_pkg)], verbose)?;

    // Calculate or parse image size.
    let image_size = match size {
        Some(s) => crate::parse_size(s)?,
        None => {
            let total = dir_size(src)?;
            // At least 256 MiB, otherwise 150% of content for filesystem
            // metadata overhead.
            let min_size = 256 * 1024 * 1024;
            let padded = (total as f64 * 1.5) as u64;
            std::cmp::max(min_size, padded)
        }
    };

    if verbose {
        eprintln!(
            "creating {fs_type} raw image: {} ({} bytes)",
            output.display(),
            image_size
        );
    }

    // Create sparse file.
    let file =
        File::create(output).with_context(|| format!("failed to create {}", output.display()))?;
    file.set_len(image_size)
        .with_context(|| format!("failed to set file size for {}", output.display()))?;
    drop(file);

    // Format the image.
    let (mkfs_args, mkfs_err): (&[&str], &str) = match fs_type {
        RawFs::Ext4 => (&["-q", "-F"], "mkfs.ext4 failed"),
        RawFs::Btrfs => (&["-q", "-f"], "mkfs.btrfs failed"),
    };
    let status = std::process::Command::new(mkfs_bin)
        .args(mkfs_args)
        .arg(output)
        .status()
        .with_context(|| format!("failed to run {mkfs_bin}"))?;
    if !status.success() {
        let _ = fs::remove_file(output);
        bail!("{mkfs_err}");
    }

    // Mount, copy, unmount.
    let mount_dir = std::env::temp_dir().join(format!("sdme-export-mount-{}", std::process::id()));
    fs::create_dir_all(&mount_dir)
        .with_context(|| format!("failed to create mount point {}", mount_dir.display()))?;

    let mount_status = std::process::Command::new("mount")
        .args(["-o", "loop"])
        .arg(output)
        .arg(&mount_dir)
        .status()
        .context("failed to run mount")?;

    if !mount_status.success() {
        let _ = fs::remove_dir(&mount_dir);
        let _ = fs::remove_file(output);
        bail!("failed to mount raw image");
    }

    // Remove lost+found created by mkfs.ext4 (btrfs doesn't create one).
    if fs_type == RawFs::Ext4 {
        let lost_found = mount_dir.join("lost+found");
        if lost_found.exists() {
            let _ = fs::remove_dir(&lost_found);
        }
    }

    let copy_result = (|| -> Result<()> {
        copy::copy_metadata(src, &mount_dir)?;
        copy::copy_tree(src, &mount_dir, verbose)
    })();

    // Always unmount.
    let _ = std::process::Command::new("umount")
        .arg(&mount_dir)
        .status();
    let _ = fs::remove_dir(&mount_dir);

    if let Err(e) = copy_result {
        let _ = fs::remove_file(output);
        return Err(e).context("failed to copy to raw image");
    }

    Ok(())
}

/// Recursively walk a directory tree summing regular file sizes.
fn dir_size(path: &Path) -> Result<u64> {
    let mut total: u64 = 0;
    let entries = fs::read_dir(path)
        .with_context(|| format!("failed to read directory {}", path.display()))?;
    for entry in entries {
        check_interrupted()?;
        let entry = entry.with_context(|| format!("failed to read entry in {}", path.display()))?;
        let meta = entry
            .metadata()
            .with_context(|| format!("failed to stat {}", entry.path().display()))?;
        if meta.is_dir() {
            total += dir_size(&entry.path())?;
        } else {
            total += meta.len();
        }
    }
    Ok(total)
}

/// Mount overlayfs on a stopped container's `merged/` directory.
fn mount_overlay(rootfs_dir: &Path, container_dir: &Path) -> Result<()> {
    let upper_dir = container_dir.join("upper");
    let work_dir = container_dir.join("work");
    let merged_dir = container_dir.join("merged");

    let mount_opts = format!(
        "lowerdir={},upperdir={},workdir={}",
        rootfs_dir.display(),
        upper_dir.display(),
        work_dir.display()
    );

    let status = std::process::Command::new("mount")
        .args(["-t", "overlay", "overlay", "-o", &mount_opts])
        .arg(&merged_dir)
        .status()
        .context("failed to run mount")?;

    if !status.success() {
        bail!("failed to mount overlayfs for export");
    }
    Ok(())
}

/// Unmount overlayfs from a container's `merged/` directory.
fn unmount_overlay(container_dir: &Path) {
    let merged_dir = container_dir.join("merged");
    let _ = std::process::Command::new("umount")
        .arg(&merged_dir)
        .status();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    /// Acquire the interrupt lock and clear the INTERRUPTED flag.
    /// Returns a guard that holds the lock, preventing other tests from
    /// setting INTERRUPTED while our test is running.
    fn lock_and_clear_interrupted() -> std::sync::MutexGuard<'static, ()> {
        let guard = crate::import::tests::INTERRUPT_LOCK.lock().unwrap();
        crate::INTERRUPTED.store(false, Ordering::Relaxed);
        guard
    }

    // --- detect_format tests ---

    #[test]
    fn test_detect_format_from_extension() {
        assert_eq!(detect_format("foo.tar", None).unwrap(), ExportFormat::Tar);
        assert_eq!(
            detect_format("foo.tar.gz", None).unwrap(),
            ExportFormat::TarGz
        );
        assert_eq!(detect_format("foo.tgz", None).unwrap(), ExportFormat::TarGz);
        assert_eq!(
            detect_format("foo.tar.bz2", None).unwrap(),
            ExportFormat::TarBz2
        );
        assert_eq!(
            detect_format("foo.tbz2", None).unwrap(),
            ExportFormat::TarBz2
        );
        assert_eq!(
            detect_format("foo.tar.xz", None).unwrap(),
            ExportFormat::TarXz
        );
        assert_eq!(detect_format("foo.txz", None).unwrap(), ExportFormat::TarXz);
        assert_eq!(
            detect_format("foo.tar.zst", None).unwrap(),
            ExportFormat::TarZst
        );
        assert_eq!(
            detect_format("foo.tzst", None).unwrap(),
            ExportFormat::TarZst
        );
        assert_eq!(
            detect_format("foo.img", None).unwrap(),
            ExportFormat::Raw(RawFs::Ext4)
        );
        assert_eq!(
            detect_format("foo.raw", None).unwrap(),
            ExportFormat::Raw(RawFs::Ext4)
        );
        assert_eq!(detect_format("foo", None).unwrap(), ExportFormat::Dir);
        assert_eq!(
            detect_format("/tmp/mydir", None).unwrap(),
            ExportFormat::Dir
        );
    }

    #[test]
    fn test_detect_format_override() {
        assert_eq!(
            detect_format("foo.tar", Some("dir")).unwrap(),
            ExportFormat::Dir
        );
        assert_eq!(
            detect_format("foo", Some("tar.gz")).unwrap(),
            ExportFormat::TarGz
        );
        assert_eq!(
            detect_format("foo", Some("raw")).unwrap(),
            ExportFormat::Raw(RawFs::Ext4)
        );
    }

    #[test]
    fn test_detect_format_unknown_override() {
        assert!(detect_format("foo", Some("zip")).is_err());
    }

    #[test]
    fn test_detect_format_case_insensitive() {
        assert_eq!(
            detect_format("FOO.TAR.GZ", None).unwrap(),
            ExportFormat::TarGz
        );
        assert_eq!(
            detect_format("FOO.IMG", None).unwrap(),
            ExportFormat::Raw(RawFs::Ext4)
        );
    }

    // --- dir_size tests ---

    #[test]
    fn test_dir_size_empty() {
        let tmp = crate::testutil::TempDataDir::new("export-dirsize-empty");
        assert_eq!(dir_size(tmp.path()).unwrap(), 0);
    }

    #[test]
    fn test_dir_size_with_files() {
        let _guard = lock_and_clear_interrupted();
        let tmp = crate::testutil::TempDataDir::new("export-dirsize-files");
        fs::write(tmp.path().join("a"), "hello").unwrap(); // 5 bytes
        fs::create_dir(tmp.path().join("sub")).unwrap();
        fs::write(tmp.path().join("sub/b"), "world!").unwrap(); // 6 bytes
        assert_eq!(dir_size(tmp.path()).unwrap(), 11);
    }

    // --- export_to_dir tests ---

    #[test]
    fn test_export_to_dir_creates_copy() {
        let _guard = lock_and_clear_interrupted();
        let src = crate::testutil::TempDataDir::new("export-dir-src");
        fs::write(src.path().join("hello.txt"), "hi").unwrap();
        fs::create_dir(src.path().join("sub")).unwrap();
        fs::write(src.path().join("sub/nested.txt"), "nested").unwrap();

        let dst_parent = crate::testutil::TempDataDir::new("export-dir-dst");
        let dst = dst_parent.path().join("output");

        export_to_dir(src.path(), &dst, false).unwrap();

        assert!(dst.join("hello.txt").is_file());
        assert_eq!(fs::read_to_string(dst.join("hello.txt")).unwrap(), "hi");
        assert!(dst.join("sub/nested.txt").is_file());
    }

    #[test]
    fn test_export_to_dir_rejects_existing() {
        let src = crate::testutil::TempDataDir::new("export-dir-exist-src");
        let dst = crate::testutil::TempDataDir::new("export-dir-exist-dst");

        let err = export_to_dir(src.path(), dst.path(), false).unwrap_err();
        assert!(err.to_string().contains("already exists"), "got: {err}");
    }

    // --- export_to_tar tests ---

    #[test]
    fn test_export_to_tar_uncompressed() {
        let _guard = lock_and_clear_interrupted();
        let src = crate::testutil::TempDataDir::new("export-tar-src");
        fs::write(src.path().join("file.txt"), "content").unwrap();

        let dst = crate::testutil::TempDataDir::new("export-tar-dst");
        let tarball = dst.path().join("out.tar");

        export_to_tar(src.path(), &tarball, &ExportFormat::Tar, false).unwrap();
        assert!(tarball.exists());
        assert!(fs::metadata(&tarball).unwrap().len() > 0);

        // Verify contents by reading the tarball.
        let file = File::open(&tarball).unwrap();
        let mut archive = tar::Archive::new(file);
        let entries: Vec<String> = archive
            .entries()
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path().unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(entries.contains(&"file.txt".to_string()));
    }

    #[test]
    fn test_export_to_tar_gz() {
        let _guard = lock_and_clear_interrupted();
        let src = crate::testutil::TempDataDir::new("export-targz-src");
        fs::write(src.path().join("data"), "compressed").unwrap();

        let dst = crate::testutil::TempDataDir::new("export-targz-dst");
        let tarball = dst.path().join("out.tar.gz");

        export_to_tar(src.path(), &tarball, &ExportFormat::TarGz, false).unwrap();
        assert!(tarball.exists());

        // Verify by decompressing and reading.
        let file = File::open(&tarball).unwrap();
        let decoder = flate2::read::GzDecoder::new(file);
        let mut archive = tar::Archive::new(decoder);
        let entries: Vec<String> = archive
            .entries()
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path().unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(entries.contains(&"data".to_string()));
    }

    #[test]
    fn test_export_to_tar_rejects_existing() {
        let src = crate::testutil::TempDataDir::new("export-tar-exist-src");
        let dst = crate::testutil::TempDataDir::new("export-tar-exist-dst");
        let tarball = dst.path().join("out.tar");
        fs::write(&tarball, "existing").unwrap();

        let err = export_to_tar(src.path(), &tarball, &ExportFormat::Tar, false).unwrap_err();
        assert!(err.to_string().contains("already exists"), "got: {err}");
    }

    // --- export_rootfs tests ---

    #[test]
    fn test_export_rootfs_not_found() {
        let tmp = crate::testutil::TempDataDir::new("export-rootfs-notfound");
        fs::create_dir_all(tmp.path().join("fs")).unwrap();
        let output = tmp.path().join("out");

        let err = export_rootfs(
            tmp.path(),
            "nonexistent",
            &output,
            &ExportFormat::Dir,
            None,
            false,
        )
        .unwrap_err();
        assert!(err.to_string().contains("rootfs not found"), "got: {err}");
    }

    #[test]
    fn test_export_rootfs_invalid_name() {
        let tmp = crate::testutil::TempDataDir::new("export-rootfs-badname");
        let output = tmp.path().join("out");

        let err = export_rootfs(
            tmp.path(),
            "../escape",
            &output,
            &ExportFormat::Dir,
            None,
            false,
        )
        .unwrap_err();
        assert!(err.to_string().contains("name"), "got: {err}");
    }

    #[test]
    fn test_export_rootfs_to_dir() {
        let _guard = lock_and_clear_interrupted();
        let tmp = crate::testutil::TempDataDir::new("export-rootfs-dir");
        let rootfs_dir = tmp.path().join("fs/myfs");
        fs::create_dir_all(&rootfs_dir).unwrap();
        fs::write(rootfs_dir.join("hello"), "world").unwrap();

        let output = tmp.path().join("exported");
        export_rootfs(tmp.path(), "myfs", &output, &ExportFormat::Dir, None, false).unwrap();

        assert!(output.join("hello").is_file());
        assert_eq!(fs::read_to_string(output.join("hello")).unwrap(), "world");
    }
}
