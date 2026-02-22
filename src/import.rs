//! Rootfs import logic: directory copy, tarball extraction, URL download, OCI image, and QCOW2 support.
//!
//! This module handles all import sources for `sdme rootfs import`:
//! - Local directories (recursive copy preserving permissions, ownership, xattrs)
//! - Tarball files (.tar, .tar.gz, .tar.bz2, .tar.xz, .tar.zst)
//! - HTTP/HTTPS URLs pointing to tarballs
//! - OCI container image archives (.oci.tar, .oci.tar.xz, etc.)
//! - QCOW2 disk images (via qemu-nbd, auto-detected by magic bytes)

use std::ffi::CString;
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs as unix_fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use anyhow::{bail, Context, Result};
use serde::Deserialize;

use crate::{State, validate_name};

// --- Source detection ---

/// Classifies the source argument for rootfs import.
#[derive(Debug)]
enum SourceKind {
    Directory(PathBuf),
    Tarball(PathBuf),
    QcowImage(PathBuf),
    Url(String),
}

/// QCOW2 magic bytes: "QFI\xfb".
const QCOW2_MAGIC: [u8; 4] = [0x51, 0x46, 0x49, 0xfb];

/// Check if a file is a QCOW2 image by reading its magic bytes.
fn is_qcow2(path: &Path) -> bool {
    let Ok(mut file) = File::open(path) else {
        return false;
    };
    let mut magic = [0u8; 4];
    if file.read_exact(&mut magic).is_ok() {
        return magic == QCOW2_MAGIC;
    }
    false
}

/// Detect whether the source is a URL, directory, qcow2 image, tarball file, or invalid.
fn detect_source_kind(source: &str) -> Result<SourceKind> {
    if source.starts_with("http://") || source.starts_with("https://") {
        return Ok(SourceKind::Url(source.to_string()));
    }

    let path = Path::new(source);
    if path.is_dir() {
        return Ok(SourceKind::Directory(path.to_path_buf()));
    }
    if path.is_file() {
        if is_qcow2(path) {
            return Ok(SourceKind::QcowImage(path.to_path_buf()));
        }
        return Ok(SourceKind::Tarball(path.to_path_buf()));
    }
    if !path.exists() {
        bail!("source path does not exist: {source}");
    }
    bail!("source path is not a file or directory: {source}");
}

// --- Compression ---

enum Compression {
    None,
    Gzip,
    Bzip2,
    Xz,
    Zstd,
}

/// Detect the compression format of a file by reading its magic bytes.
fn detect_compression(path: &Path) -> Result<Compression> {
    let mut file =
        File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut magic = [0u8; 6];
    let n = file
        .read(&mut magic)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let magic = &magic[..n];

    detect_compression_magic(magic)
}

/// Detect compression from magic bytes.
fn detect_compression_magic(magic: &[u8]) -> Result<Compression> {
    if magic.starts_with(&[0x1f, 0x8b]) {
        Ok(Compression::Gzip)
    } else if magic.starts_with(b"BZh") {
        Ok(Compression::Bzip2)
    } else if magic.starts_with(&[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]) {
        Ok(Compression::Xz)
    } else if magic.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        Ok(Compression::Zstd)
    } else {
        Ok(Compression::None)
    }
}

// --- Tarball extraction ---

/// Unpack a tar archive from a reader into a destination directory.
fn unpack_tar<R: Read>(reader: R, dest: &Path) -> Result<()> {
    let mut archive = tar::Archive::new(reader);
    archive.set_preserve_permissions(true);
    archive.set_preserve_ownerships(true);
    archive.set_unpack_xattrs(true);
    archive
        .unpack(dest)
        .with_context(|| format!("failed to extract tarball to {}", dest.display()))?;
    Ok(())
}

/// Extract a tarball into the staging directory using native Rust crates.
///
/// After extraction, checks if the result is an OCI image layout and
/// processes it accordingly.
fn import_tarball(tarball: &Path, staging_dir: &Path, verbose: bool) -> Result<()> {
    let compression = detect_compression(tarball)?;

    fs::create_dir_all(staging_dir)
        .with_context(|| format!("failed to create staging dir {}", staging_dir.display()))?;

    if verbose {
        eprintln!(
            "extracting {} -> {}",
            tarball.display(),
            staging_dir.display()
        );
    }

    let file =
        File::open(tarball).with_context(|| format!("failed to open {}", tarball.display()))?;

    match compression {
        Compression::Gzip => unpack_tar(flate2::read::GzDecoder::new(file), staging_dir),
        Compression::Bzip2 => unpack_tar(bzip2::read::BzDecoder::new(file), staging_dir),
        Compression::Xz => unpack_tar(xz2::read::XzDecoder::new(file), staging_dir),
        Compression::Zstd => unpack_tar(zstd::stream::read::Decoder::new(file)?, staging_dir),
        Compression::None => unpack_tar(file, staging_dir),
    }?;

    // Check if the extracted content is an OCI image layout.
    if is_oci_layout(staging_dir) {
        if verbose {
            eprintln!("detected OCI image layout");
        }
        let mut oci_name = staging_dir
            .file_name()
            .unwrap()
            .to_os_string();
        oci_name.push(".oci");
        let oci_dir = staging_dir.with_file_name(oci_name);
        fs::rename(staging_dir, &oci_dir)?;
        let result = import_oci_layout(&oci_dir, staging_dir, verbose);
        let _ = make_removable(&oci_dir);
        let _ = fs::remove_dir_all(&oci_dir);
        return result;
    }

    Ok(())
}

// --- OCI image support ---

#[derive(Deserialize)]
struct OciLayout {
    #[serde(rename = "imageLayoutVersion")]
    image_layout_version: String,
}

#[derive(Deserialize)]
struct OciIndex {
    manifests: Vec<OciDescriptor>,
}

#[derive(Deserialize)]
struct OciDescriptor {
    digest: String,
    #[serde(rename = "mediaType")]
    #[allow(dead_code)]
    media_type: Option<String>,
}

#[derive(Deserialize)]
struct OciManifest {
    layers: Vec<OciDescriptor>,
}

/// Check if a directory contains an OCI image layout (has an `oci-layout` file).
fn is_oci_layout(dir: &Path) -> bool {
    dir.join("oci-layout").is_file()
}

/// Read and deserialize a JSON file.
fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let content =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_str(&content)
        .with_context(|| format!("failed to parse JSON from {}", path.display()))
}

/// Resolve a blob path from an OCI digest like `sha256:abc123`.
fn resolve_blob(oci_dir: &Path, digest: &str) -> Result<PathBuf> {
    let (algo, hash) = digest
        .split_once(':')
        .with_context(|| format!("invalid OCI digest format: {digest}"))?;
    let blob_path = oci_dir.join("blobs").join(algo).join(hash);
    if !blob_path.exists() {
        bail!("OCI blob not found: {}", blob_path.display());
    }
    Ok(blob_path)
}

/// Import an OCI image layout by reading the manifest chain and extracting layers.
fn import_oci_layout(oci_dir: &Path, staging_dir: &Path, verbose: bool) -> Result<()> {
    // Validate oci-layout version.
    let layout: OciLayout = read_json(&oci_dir.join("oci-layout"))?;
    if layout.image_layout_version != "1.0.0" {
        bail!(
            "unsupported OCI image layout version: {}",
            layout.image_layout_version
        );
    }

    // Read index.json to find the manifest.
    let index: OciIndex = read_json(&oci_dir.join("index.json"))?;
    if index.manifests.is_empty() {
        bail!("OCI index.json contains no manifests");
    }

    let manifest_blob = resolve_blob(oci_dir, &index.manifests[0].digest)?;

    // The index may point to an image manifest or a manifest index.
    // Use serde_json::Value to check which one it is.
    let manifest_value: serde_json::Value = read_json(&manifest_blob)?;

    let manifest: OciManifest = if manifest_value.get("layers").is_some() {
        // Direct image manifest.
        serde_json::from_value(manifest_value)
            .context("failed to parse OCI image manifest")?
    } else if manifest_value.get("manifests").is_some() {
        // Manifest index — follow one level of indirection.
        let sub_index: OciIndex = serde_json::from_value(manifest_value)
            .context("failed to parse OCI manifest index")?;
        if sub_index.manifests.is_empty() {
            bail!("OCI manifest index contains no manifests");
        }
        let sub_blob = resolve_blob(oci_dir, &sub_index.manifests[0].digest)?;
        read_json(&sub_blob)?
    } else {
        bail!("OCI manifest has neither 'layers' nor 'manifests' field");
    };

    if manifest.layers.is_empty() {
        bail!("OCI manifest contains no layers");
    }

    fs::create_dir_all(staging_dir)
        .with_context(|| format!("failed to create staging dir {}", staging_dir.display()))?;

    // Extract layers in order.
    for (i, layer) in manifest.layers.iter().enumerate() {
        let blob_path = resolve_blob(oci_dir, &layer.digest)?;
        if verbose {
            eprintln!(
                "extracting layer {}/{}: {}",
                i + 1,
                manifest.layers.len(),
                layer.digest
            );
        }

        // Detect compression from magic bytes of the blob.
        let mut blob_file = File::open(&blob_path)
            .with_context(|| format!("failed to open blob {}", blob_path.display()))?;
        let mut magic = [0u8; 6];
        let n = blob_file.read(&mut magic)?;
        // Seek back to the start.
        drop(blob_file);
        let blob_file = File::open(&blob_path)?;

        let compression = detect_compression_magic(&magic[..n])?;
        match compression {
            Compression::Gzip => {
                unpack_oci_layer(flate2::read::GzDecoder::new(blob_file), staging_dir)?
            }
            Compression::Bzip2 => {
                unpack_oci_layer(bzip2::read::BzDecoder::new(blob_file), staging_dir)?
            }
            Compression::Xz => {
                unpack_oci_layer(xz2::read::XzDecoder::new(blob_file), staging_dir)?
            }
            Compression::Zstd => {
                unpack_oci_layer(zstd::stream::read::Decoder::new(blob_file)?, staging_dir)?
            }
            Compression::None => unpack_oci_layer(blob_file, staging_dir)?,
        }
    }

    Ok(())
}

/// Unpack an OCI layer tar archive, handling OCI whiteout markers.
///
/// OCI whiteouts:
/// - `.wh..wh..opq` in a directory means "clear existing contents of this directory"
/// - `.wh.<name>` means "delete <name> from the destination"
fn unpack_oci_layer<R: Read>(reader: R, dest: &Path) -> Result<()> {
    let mut archive = tar::Archive::new(reader);
    archive.set_preserve_permissions(true);
    archive.set_preserve_ownerships(true);
    archive.set_unpack_xattrs(true);

    for entry in archive.entries().context("failed to read tar entries")? {
        let mut entry = entry.context("failed to read tar entry")?;
        let path = entry.path().context("failed to read entry path")?.into_owned();

        let file_name = match path.file_name() {
            Some(name) => name.to_string_lossy().into_owned(),
            None => {
                // Root directory entry — just ensure it exists.
                entry.unpack_in(dest).with_context(|| {
                    format!("failed to unpack entry {}", path.display())
                })?;
                continue;
            }
        };

        if file_name == ".wh..wh..opq" {
            // Opaque whiteout: clear existing contents of the parent directory.
            let parent = path.parent().unwrap_or(Path::new(""));
            let abs_parent = dest.join(parent);
            if abs_parent.is_dir() {
                for child in fs::read_dir(&abs_parent)
                    .with_context(|| format!("failed to read dir {}", abs_parent.display()))?
                {
                    let child = child?;
                    let child_path = child.path();
                    if child.file_type()?.is_dir() {
                        let _ = make_removable(&child_path);
                        fs::remove_dir_all(&child_path).ok();
                    } else {
                        fs::remove_file(&child_path).ok();
                    }
                }
            }
            continue;
        }

        if let Some(target_name) = file_name.strip_prefix(".wh.") {
            // Regular whiteout: delete the target file/dir.
            let parent = path.parent().unwrap_or(Path::new(""));
            let target = dest.join(parent).join(target_name);
            if target.is_dir() {
                let _ = make_removable(&target);
                fs::remove_dir_all(&target).ok();
            } else if target.exists() || target.symlink_metadata().is_ok() {
                fs::remove_file(&target).ok();
            }
            continue;
        }

        // Normal entry — unpack into destination.
        entry
            .unpack_in(dest)
            .with_context(|| format!("failed to unpack entry {}", path.display()))?;
    }

    Ok(())
}

// --- Directory copy ---

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

// --- URL download ---

/// Download a URL to a local file, streaming to constant memory.
fn download_file(url: &str, dest: &Path, verbose: bool) -> Result<()> {
    if verbose {
        eprintln!("downloading {url}");
    }

    let response = ureq::get(url)
        .call()
        .with_context(|| format!("failed to download {url}"))?;

    let mut reader = response.into_body().into_reader();
    let mut file =
        fs::File::create(dest).with_context(|| format!("failed to create {}", dest.display()))?;

    let bytes = std::io::copy(&mut reader, &mut file)
        .with_context(|| format!("failed to write download to {}", dest.display()))?;

    if verbose {
        eprintln!("downloaded {} bytes to {}", bytes, dest.display());
    }

    Ok(())
}

/// Download a URL to a temp file and extract it as a tarball.
fn import_url(
    url: &str,
    staging_dir: &Path,
    rootfs_dir: &Path,
    name: &str,
    verbose: bool,
) -> Result<()> {
    let temp_file = rootfs_dir.join(format!(".{name}.download"));

    let result = (|| -> Result<()> {
        download_file(url, &temp_file, verbose)?;
        import_tarball(&temp_file, staging_dir, verbose)
    })();

    // Clean up temp file on both success and failure.
    let _ = fs::remove_file(&temp_file);

    result
}

// --- QCOW2 import ---

/// Import a QCOW2 disk image by mounting it via qemu-nbd and copying the filesystem tree.
///
/// Steps:
/// 1. Load the `nbd` kernel module
/// 2. Find a free `/dev/nbdN` device
/// 3. Connect the qcow2 image via `qemu-nbd`
/// 4. Discover and mount the root partition
/// 5. Copy the mounted tree to the staging directory
/// 6. Clean up (unmount, disconnect)
fn import_qcow2(image: &Path, staging_dir: &Path, verbose: bool) -> Result<()> {
    crate::system_check::check_dependencies(
        &[("qemu-nbd", "apt install qemu-utils")],
        verbose,
    )?;

    if verbose {
        eprintln!("importing qcow2 image: {}", image.display());
    }

    // Load the nbd kernel module.
    let status = Command::new("modprobe")
        .args(["nbd", "max_part=16"])
        .status()
        .context("failed to run modprobe nbd")?;
    if !status.success() {
        bail!("modprobe nbd failed (is the nbd kernel module available?)");
    }

    // Find a free /dev/nbdN device.
    let nbd_dev = find_free_nbd_device()?;
    if verbose {
        eprintln!("using nbd device: {}", nbd_dev.display());
    }

    // Connect the image. Everything after this point must disconnect on cleanup.
    let status = Command::new("qemu-nbd")
        .args(["--read-only", "--connect"])
        .arg(&nbd_dev)
        .arg(image)
        .status()
        .context("failed to run qemu-nbd")?;
    if !status.success() {
        bail!("qemu-nbd --connect failed for {}", image.display());
    }

    // Use a closure so we can clean up the nbd connection on any error.
    let result = (|| -> Result<()> {
        // Wait for the kernel to scan partitions.
        let status = Command::new("partprobe")
            .arg(&nbd_dev)
            .status();
        // partprobe is optional; if missing, the kernel usually scans automatically.
        if let Ok(s) = status {
            if !s.success() && verbose {
                eprintln!("partprobe failed (non-fatal)");
            }
        }

        // Small delay for partition devices to appear.
        std::thread::sleep(std::time::Duration::from_millis(500));

        // Find the root partition device.
        let part_dev = find_root_partition(&nbd_dev, verbose)?;
        if verbose {
            eprintln!("mounting partition: {}", part_dev.display());
        }

        // Create a temporary mount point.
        let mount_dir = staging_dir.with_file_name(
            format!(
                ".{}.qcow2-mount",
                staging_dir.file_name().unwrap().to_string_lossy()
            ),
        );
        fs::create_dir_all(&mount_dir)
            .with_context(|| format!("failed to create mount point {}", mount_dir.display()))?;

        // Mount the partition read-only.
        let status = Command::new("mount")
            .args(["-o", "ro"])
            .arg(&part_dev)
            .arg(&mount_dir)
            .status()
            .context("failed to run mount")?;
        if !status.success() {
            let _ = fs::remove_dir(&mount_dir);
            bail!("mount failed for {}", part_dev.display());
        }

        // Copy the tree; unmount on any error.
        let copy_result = do_import(&mount_dir, staging_dir, verbose);

        // Always unmount.
        let umount_status = Command::new("umount")
            .arg(&mount_dir)
            .status();
        let _ = fs::remove_dir(&mount_dir);
        if let Ok(s) = umount_status {
            if !s.success() && verbose {
                eprintln!("warning: umount {} failed", mount_dir.display());
            }
        }

        copy_result
    })();

    // Always disconnect the nbd device.
    let disconnect_status = Command::new("qemu-nbd")
        .args(["--disconnect"])
        .arg(&nbd_dev)
        .status();
    if let Ok(s) = disconnect_status {
        if !s.success() && verbose {
            eprintln!("warning: qemu-nbd --disconnect {} failed", nbd_dev.display());
        }
    }

    result
}

/// Find a free `/dev/nbdN` device by checking which ones have zero size.
fn find_free_nbd_device() -> Result<PathBuf> {
    for i in 0..16 {
        let dev = PathBuf::from(format!("/dev/nbd{i}"));
        if !dev.exists() {
            continue;
        }
        let size_path = PathBuf::from(format!("/sys/block/nbd{i}/size"));
        if let Ok(content) = fs::read_to_string(&size_path) {
            if content.trim() == "0" {
                return Ok(dev);
            }
        }
    }
    bail!("no free nbd device found (all /dev/nbd0..15 are in use)")
}

/// Find the root partition on an nbd device.
///
/// Looks for partition devices (`/dev/nbdNpM`) and picks the largest one,
/// which is typically the root filesystem. If no partitions are found,
/// tries the whole device (for unpartitioned disk images).
fn find_root_partition(nbd_dev: &Path, verbose: bool) -> Result<PathBuf> {
    let dev_name = nbd_dev
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();

    // Look for partition devices in /sys/block/nbdN/.
    let sys_dir = PathBuf::from(format!("/sys/block/{dev_name}"));
    let mut partitions: Vec<(PathBuf, u64)> = Vec::new();

    if let Ok(entries) = fs::read_dir(&sys_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.starts_with(&format!("{dev_name}p")) {
                continue;
            }
            let size_path = entry.path().join("size");
            if let Ok(content) = fs::read_to_string(&size_path) {
                if let Ok(size) = content.trim().parse::<u64>() {
                    if size > 0 {
                        let part_dev = PathBuf::from(format!("/dev/{name}"));
                        if verbose {
                            eprintln!(
                                "found partition: {} ({} sectors)",
                                part_dev.display(),
                                size
                            );
                        }
                        partitions.push((part_dev, size));
                    }
                }
            }
        }
    }

    if partitions.is_empty() {
        // No partitions found — try the whole device (unpartitioned image).
        if verbose {
            eprintln!("no partitions found, trying whole device");
        }
        return Ok(nbd_dev.to_path_buf());
    }

    // Pick the largest partition (usually the root filesystem).
    partitions.sort_by(|a, b| b.1.cmp(&a.1));
    Ok(partitions[0].0.clone())
}

// --- Shared helpers ---

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
        eprintln!(
            "removing leftover staging directory: {}",
            staging_dir.display()
        );
    }
    let _ = make_removable(staging_dir);
    fs::remove_dir_all(staging_dir)
        .with_context(|| format!("failed to remove staging directory {}", staging_dir.display()))?;
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

// --- Public entry point ---

/// Import a root filesystem from a directory, tarball, URL, OCI image, or QCOW2 disk image.
///
/// The source can be:
/// - A local directory (e.g. debootstrap output)
/// - A tarball file (.tar, .tar.gz, .tar.bz2, .tar.xz, .tar.zst)
/// - An HTTP/HTTPS URL pointing to a tarball
/// - An OCI container image archive (.oci.tar, .oci.tar.xz, etc.)
/// - A QCOW2 disk image (auto-detected by magic bytes; requires qemu-nbd)
///
/// OCI images are auto-detected after tarball extraction by checking for
/// an `oci-layout` file. The manifest chain is walked and filesystem layers
/// are extracted in order, with whiteout markers handled.
///
/// QCOW2 images are detected by their magic bytes (`QFI\xfb`). The image
/// is mounted read-only via qemu-nbd, the largest partition is selected as
/// the root filesystem, and its contents are copied to the staging directory.
///
/// The import is transactional: files are copied/extracted into a staging
/// directory and atomically renamed into place on success.
pub fn run(datadir: &Path, source: &str, name: &str, verbose: bool, force: bool) -> Result<()> {
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
        SourceKind::QcowImage(ref path) => import_qcow2(path, &staging_dir, verbose),
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
            let distro = crate::rootfs::detect_distro(&final_dir);
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

// --- Tests ---

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
                "sdme-test-import-{}-{:?}",
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
                "sdme-test-import-src-{}-{:?}-{suffix}",
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

        run(
            tmp.path(),
            src.path().to_str().unwrap(),
            "test",
            false,
            false,
        )
        .unwrap();

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

        run(
            tmp.path(),
            src.path().to_str().unwrap(),
            "perms",
            false,
            false,
        )
        .unwrap();

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

        run(
            tmp.path(),
            src.path().to_str().unwrap(),
            "sym",
            false,
            false,
        )
        .unwrap();

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

        run(
            tmp.path(),
            src.path().to_str().unwrap(),
            "dup",
            false,
            false,
        )
        .unwrap();
        let err = run(
            tmp.path(),
            src.path().to_str().unwrap(),
            "dup",
            false,
            false,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("already exists"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_import_invalid_name() {
        let tmp = TempDataDir::new();
        let src = TempSourceDir::new("invalid");

        let err = run(
            tmp.path(),
            src.path().to_str().unwrap(),
            "INVALID",
            false,
            false,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("lowercase"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_import_source_not_directory() {
        let tmp = TempDataDir::new();
        let file_path = std::env::temp_dir().join(format!(
            "sdme-test-import-notdir-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        fs::write(&file_path, "not a dir").unwrap();

        // A regular file is now treated as a tarball, so expect an extraction error.
        let err = run(
            tmp.path(),
            file_path.to_str().unwrap(),
            "test",
            false,
            false,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("extract"),
            "unexpected error: {err}"
        );

        let _ = fs::remove_file(&file_path);
    }

    #[test]
    fn test_import_source_not_found() {
        let tmp = TempDataDir::new();
        let missing = Path::new("/tmp/sdme-test-definitely-nonexistent");

        let err = run(
            tmp.path(),
            missing.to_str().unwrap(),
            "test",
            false,
            false,
        )
        .unwrap_err();
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

        let result = run(
            tmp.path(),
            src.path().to_str().unwrap(),
            "fail",
            false,
            false,
        );
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

        run(
            tmp.path(),
            src.path().to_str().unwrap(),
            "empty",
            false,
            false,
        )
        .unwrap();

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

        run(
            tmp.path(),
            src.path().to_str().unwrap(),
            "ts",
            false,
            false,
        )
        .unwrap();

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

        run(
            tmp.path(),
            src.path().to_str().unwrap(),
            "dev",
            false,
            false,
        )
        .unwrap();

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

        run(
            tmp.path(),
            src.path().to_str().unwrap(),
            "distro",
            false,
            false,
        )
        .unwrap();

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

        run(
            tmp.path(),
            src.path().to_str().unwrap(),
            "noos",
            false,
            false,
        )
        .unwrap();

        let meta_path = tmp.path().join("rootfs/.noos.meta");
        assert!(meta_path.exists(), ".meta sidecar should exist");
        let state = State::read_from(&meta_path).unwrap();
        assert_eq!(state.get("DISTRO").unwrap(), "");
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
    fn test_detect_source_kind_qcow2() {
        let file_path = std::env::temp_dir().join(format!(
            "sdme-test-detect-qcow2-{}-{:?}.qcow2",
            std::process::id(),
            std::thread::current().id()
        ));
        // Write a file with QCOW2 magic bytes.
        let mut data = vec![0u8; 512];
        data[0..4].copy_from_slice(&QCOW2_MAGIC);
        fs::write(&file_path, &data).unwrap();
        match detect_source_kind(file_path.to_str().unwrap()).unwrap() {
            SourceKind::QcowImage(p) => assert_eq!(p, file_path),
            other => panic!("expected QcowImage, got {other:?}"),
        }
        let _ = fs::remove_file(&file_path);
    }

    #[test]
    fn test_is_qcow2_true() {
        let file_path = std::env::temp_dir().join(format!(
            "sdme-test-is-qcow2-true-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let mut data = vec![0u8; 512];
        data[0..4].copy_from_slice(&QCOW2_MAGIC);
        fs::write(&file_path, &data).unwrap();
        assert!(is_qcow2(&file_path));
        let _ = fs::remove_file(&file_path);
    }

    #[test]
    fn test_is_qcow2_false() {
        let file_path = std::env::temp_dir().join(format!(
            "sdme-test-is-qcow2-false-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        fs::write(&file_path, "not a qcow2 file").unwrap();
        assert!(!is_qcow2(&file_path));
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

        // Create a gzipped tarball using tar::Builder.
        let tarball = std::env::temp_dir().join(format!(
            "sdme-test-tarball-{}-{:?}.tar.gz",
            std::process::id(),
            std::thread::current().id()
        ));
        let file = File::create(&tarball).unwrap();
        let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        let mut builder = tar::Builder::new(encoder);
        builder.append_dir_all(".", src.path()).unwrap();
        let encoder = builder.into_inner().unwrap();
        encoder.finish().unwrap();

        run(
            tmp.path(),
            tarball.to_str().unwrap(),
            "tgz",
            false,
            false,
        )
        .unwrap();

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

        // Create an uncompressed tarball using tar::Builder.
        let tarball = std::env::temp_dir().join(format!(
            "sdme-test-tarball-plain-{}-{:?}.tar",
            std::process::id(),
            std::thread::current().id()
        ));
        let file = File::create(&tarball).unwrap();
        let mut builder = tar::Builder::new(file);
        builder.append_dir_all(".", src.path()).unwrap();
        builder.finish().unwrap();

        run(
            tmp.path(),
            tarball.to_str().unwrap(),
            "plain",
            false,
            false,
        )
        .unwrap();

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

        let err = run(
            tmp.path(),
            file_path.to_str().unwrap(),
            "bad",
            false,
            false,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("extract"),
            "unexpected error: {err}"
        );

        // Staging dir should be cleaned up.
        assert!(!tmp.path().join("rootfs/.bad.importing").exists());

        let _ = fs::remove_file(&file_path);
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

        run(
            tmp.path(),
            src.path().to_str().unwrap(),
            "own",
            false,
            false,
        )
        .unwrap();

        let dst_stat = lstat_entry(&tmp.path().join("rootfs/own/owned.txt")).unwrap();
        assert_eq!(dst_stat.st_uid, 1000);
        assert_eq!(dst_stat.st_gid, 1000);
    }

    // --- OCI tests ---

    /// Helper to build an OCI image tarball programmatically.
    ///
    /// Constructs a valid OCI image layout with the given layers, each
    /// specified as a list of (path, content) pairs for regular files.
    /// Returns the path to the gzipped tarball.
    fn build_oci_tarball(
        name: &str,
        layers: &[Vec<(&str, &[u8])>],
        use_manifest_index: bool,
    ) -> PathBuf {
        use sha2::{Digest, Sha256};


        let work_dir = std::env::temp_dir().join(format!(
            "sdme-test-oci-build-{}-{:?}-{name}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&work_dir);
        fs::create_dir_all(work_dir.join("blobs/sha256")).unwrap();

        // Write oci-layout.
        fs::write(
            work_dir.join("oci-layout"),
            r#"{"imageLayoutVersion":"1.0.0"}"#,
        )
        .unwrap();

        // Build layer blobs.
        let mut layer_descriptors = Vec::new();
        for layer_files in layers {
            let mut layer_tar = Vec::new();
            {
                let encoder =
                    flate2::write::GzEncoder::new(&mut layer_tar, flate2::Compression::default());
                let mut builder = tar::Builder::new(encoder);
                for (path, content) in layer_files {
                    let mut header = tar::Header::new_ustar();
                    header.set_path(path).unwrap();
                    header.set_size(content.len() as u64);
                    header.set_mode(0o644);
                    header.set_uid(unsafe { libc::getuid() } as u64);
                    header.set_gid(unsafe { libc::getgid() } as u64);
                    header.set_cksum();
                    builder.append(&header, *content).unwrap();
                }
                let encoder = builder.into_inner().unwrap();
                encoder.finish().unwrap();
            }

            let hash = {
                let mut hasher = Sha256::new();
                hasher.update(&layer_tar);
                format!("{:x}", hasher.finalize())
            };

            fs::write(work_dir.join("blobs/sha256").join(&hash), &layer_tar).unwrap();
            layer_descriptors.push(serde_json::json!({
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": format!("sha256:{hash}"),
                "size": layer_tar.len()
            }));
        }

        // Build config blob (minimal).
        let config_json = b"{}";
        let config_hash = {
            let mut hasher = Sha256::new();
            hasher.update(config_json);
            format!("{:x}", hasher.finalize())
        };
        fs::write(
            work_dir.join("blobs/sha256").join(&config_hash),
            config_json,
        )
        .unwrap();

        // Build image manifest.
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": format!("sha256:{config_hash}"),
                "size": config_json.len()
            },
            "layers": layer_descriptors
        });
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        let manifest_hash = {
            let mut hasher = Sha256::new();
            hasher.update(&manifest_bytes);
            format!("{:x}", hasher.finalize())
        };
        fs::write(
            work_dir.join("blobs/sha256").join(&manifest_hash),
            &manifest_bytes,
        )
        .unwrap();

        // Build index.json.
        let index = if use_manifest_index {
            // Wrap in a manifest index (one level of indirection).
            let manifest_index = serde_json::json!({
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": [{
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": format!("sha256:{manifest_hash}"),
                    "size": manifest_bytes.len()
                }]
            });
            let mi_bytes = serde_json::to_vec(&manifest_index).unwrap();
            let mi_hash = {
                let mut hasher = Sha256::new();
                hasher.update(&mi_bytes);
                format!("{:x}", hasher.finalize())
            };
            fs::write(work_dir.join("blobs/sha256").join(&mi_hash), &mi_bytes).unwrap();

            serde_json::json!({
                "schemaVersion": 2,
                "manifests": [{
                    "mediaType": "application/vnd.oci.image.index.v1+json",
                    "digest": format!("sha256:{mi_hash}"),
                    "size": mi_bytes.len()
                }]
            })
        } else {
            serde_json::json!({
                "schemaVersion": 2,
                "manifests": [{
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": format!("sha256:{manifest_hash}"),
                    "size": manifest_bytes.len()
                }]
            })
        };
        fs::write(
            work_dir.join("index.json"),
            serde_json::to_vec_pretty(&index).unwrap(),
        )
        .unwrap();

        // Pack everything into a gzipped tarball.
        let tarball_path = std::env::temp_dir().join(format!(
            "sdme-test-oci-{}-{:?}-{name}.tar.gz",
            std::process::id(),
            std::thread::current().id()
        ));
        let file = File::create(&tarball_path).unwrap();
        let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        let mut builder = tar::Builder::new(encoder);
        builder.append_dir_all(".", &work_dir).unwrap();
        let encoder = builder.into_inner().unwrap();
        encoder.finish().unwrap();

        let _ = fs::remove_dir_all(&work_dir);
        tarball_path
    }

    /// Helper to build an OCI layer tarball with whiteout markers.
    fn build_oci_tarball_with_whiteouts(
        name: &str,
        base_files: Vec<(&str, &[u8])>,
        whiteout_entries: Vec<&str>,
    ) -> PathBuf {
        use sha2::{Digest, Sha256};


        let work_dir = std::env::temp_dir().join(format!(
            "sdme-test-oci-wh-build-{}-{:?}-{name}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&work_dir);
        fs::create_dir_all(work_dir.join("blobs/sha256")).unwrap();

        fs::write(
            work_dir.join("oci-layout"),
            r#"{"imageLayoutVersion":"1.0.0"}"#,
        )
        .unwrap();

        let mut layer_descriptors = Vec::new();

        // Base layer with files.
        {
            let mut layer_tar = Vec::new();
            {
                let encoder =
                    flate2::write::GzEncoder::new(&mut layer_tar, flate2::Compression::default());
                let mut builder = tar::Builder::new(encoder);
                for (path, content) in &base_files {
                    let mut header = tar::Header::new_ustar();
                    header.set_path(path).unwrap();
                    header.set_size(content.len() as u64);
                    header.set_mode(0o644);
                    header.set_uid(unsafe { libc::getuid() } as u64);
                    header.set_gid(unsafe { libc::getgid() } as u64);
                    header.set_cksum();
                    builder.append(&header, *content).unwrap();
                }
                let encoder = builder.into_inner().unwrap();
                encoder.finish().unwrap();
            }
            let hash = {
                let mut hasher = Sha256::new();
                hasher.update(&layer_tar);
                format!("{:x}", hasher.finalize())
            };
            fs::write(work_dir.join("blobs/sha256").join(&hash), &layer_tar).unwrap();
            layer_descriptors.push(serde_json::json!({
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": format!("sha256:{hash}"),
                "size": layer_tar.len()
            }));
        }

        // Whiteout layer.
        {
            let mut layer_tar = Vec::new();
            {
                let encoder =
                    flate2::write::GzEncoder::new(&mut layer_tar, flate2::Compression::default());
                let mut builder = tar::Builder::new(encoder);
                for entry_path in &whiteout_entries {
                    let mut header = tar::Header::new_ustar();
                    header.set_path(entry_path).unwrap();
                    header.set_size(0);
                    header.set_mode(0o644);
                    header.set_uid(unsafe { libc::getuid() } as u64);
                    header.set_gid(unsafe { libc::getgid() } as u64);
                    header.set_cksum();
                    builder.append(&header, &b""[..]).unwrap();
                }
                let encoder = builder.into_inner().unwrap();
                encoder.finish().unwrap();
            }
            let hash = {
                let mut hasher = Sha256::new();
                hasher.update(&layer_tar);
                format!("{:x}", hasher.finalize())
            };
            fs::write(work_dir.join("blobs/sha256").join(&hash), &layer_tar).unwrap();
            layer_descriptors.push(serde_json::json!({
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": format!("sha256:{hash}"),
                "size": layer_tar.len()
            }));
        }

        // Config + manifest + index (same pattern as build_oci_tarball).
        let config_json = b"{}";
        let config_hash = {
            let mut hasher = Sha256::new();
            hasher.update(config_json);
            format!("{:x}", hasher.finalize())
        };
        fs::write(
            work_dir.join("blobs/sha256").join(&config_hash),
            config_json,
        )
        .unwrap();

        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": format!("sha256:{config_hash}"),
                "size": config_json.len()
            },
            "layers": layer_descriptors
        });
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        let manifest_hash = {
            let mut hasher = Sha256::new();
            hasher.update(&manifest_bytes);
            format!("{:x}", hasher.finalize())
        };
        fs::write(
            work_dir.join("blobs/sha256").join(&manifest_hash),
            &manifest_bytes,
        )
        .unwrap();

        let index = serde_json::json!({
            "schemaVersion": 2,
            "manifests": [{
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": format!("sha256:{manifest_hash}"),
                "size": manifest_bytes.len()
            }]
        });
        fs::write(
            work_dir.join("index.json"),
            serde_json::to_vec_pretty(&index).unwrap(),
        )
        .unwrap();

        let tarball_path = std::env::temp_dir().join(format!(
            "sdme-test-oci-wh-{}-{:?}-{name}.tar.gz",
            std::process::id(),
            std::thread::current().id()
        ));
        let file = File::create(&tarball_path).unwrap();
        let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        let mut builder = tar::Builder::new(encoder);
        builder.append_dir_all(".", &work_dir).unwrap();
        let encoder = builder.into_inner().unwrap();
        encoder.finish().unwrap();

        let _ = fs::remove_dir_all(&work_dir);
        tarball_path
    }

    #[test]
    fn test_is_oci_layout() {
        let dir = std::env::temp_dir().join(format!(
            "sdme-test-oci-detect-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        // No oci-layout file.
        assert!(!is_oci_layout(&dir));

        // Create oci-layout file.
        fs::write(dir.join("oci-layout"), r#"{"imageLayoutVersion":"1.0.0"}"#).unwrap();
        assert!(is_oci_layout(&dir));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_import_oci_basic() {
        let tmp = TempDataDir::new();
        let tarball = build_oci_tarball(
            "basic",
            &[vec![
                ("etc/os-release", b"PRETTY_NAME=\"TestOS 1.0\"\n"),
                ("hello.txt", b"hello from OCI\n"),
            ]],
            false,
        );

        run(
            tmp.path(),
            tarball.to_str().unwrap(),
            "ocibasic",
            false,
            false,
        )
        .unwrap();

        let rootfs = tmp.path().join("rootfs/ocibasic");
        assert!(rootfs.is_dir());
        assert_eq!(
            fs::read_to_string(rootfs.join("hello.txt")).unwrap(),
            "hello from OCI\n"
        );
        assert_eq!(
            fs::read_to_string(rootfs.join("etc/os-release")).unwrap(),
            "PRETTY_NAME=\"TestOS 1.0\"\n"
        );

        let _ = fs::remove_file(&tarball);
    }

    #[test]
    fn test_import_oci_multilayer() {
        let tmp = TempDataDir::new();
        let tarball = build_oci_tarball(
            "multi",
            &[
                vec![
                    ("base.txt", b"from layer 1\n"),
                    ("shared.txt", b"layer 1 version\n"),
                ],
                vec![
                    ("overlay.txt", b"from layer 2\n"),
                    ("shared.txt", b"layer 2 version\n"),
                ],
            ],
            false,
        );

        run(
            tmp.path(),
            tarball.to_str().unwrap(),
            "ocimulti",
            false,
            false,
        )
        .unwrap();

        let rootfs = tmp.path().join("rootfs/ocimulti");
        assert_eq!(
            fs::read_to_string(rootfs.join("base.txt")).unwrap(),
            "from layer 1\n"
        );
        assert_eq!(
            fs::read_to_string(rootfs.join("overlay.txt")).unwrap(),
            "from layer 2\n"
        );
        // Layer 2 should overwrite layer 1's version.
        assert_eq!(
            fs::read_to_string(rootfs.join("shared.txt")).unwrap(),
            "layer 2 version\n"
        );

        let _ = fs::remove_file(&tarball);
    }

    #[test]
    fn test_import_oci_whiteout() {
        let tmp = TempDataDir::new();
        let tarball = build_oci_tarball_with_whiteouts(
            "whiteout",
            vec![
                ("keep.txt", b"keep me\n"),
                ("delete-me.txt", b"delete me\n"),
                ("subdir/also-delete.txt", b"also delete\n"),
                ("subdir/keep-this.txt", b"keep this\n"),
            ],
            vec![".wh.delete-me.txt", "subdir/.wh.also-delete.txt"],
        );

        run(
            tmp.path(),
            tarball.to_str().unwrap(),
            "ociwhiteout",
            false,
            false,
        )
        .unwrap();

        let rootfs = tmp.path().join("rootfs/ociwhiteout");
        assert_eq!(
            fs::read_to_string(rootfs.join("keep.txt")).unwrap(),
            "keep me\n"
        );
        assert!(
            !rootfs.join("delete-me.txt").exists(),
            "whiteout should have deleted delete-me.txt"
        );
        assert!(
            !rootfs.join("subdir/also-delete.txt").exists(),
            "whiteout should have deleted subdir/also-delete.txt"
        );
        assert_eq!(
            fs::read_to_string(rootfs.join("subdir/keep-this.txt")).unwrap(),
            "keep this\n"
        );

        let _ = fs::remove_file(&tarball);
    }

    #[test]
    fn test_import_oci_manifest_index() {
        let tmp = TempDataDir::new();
        let tarball = build_oci_tarball(
            "index",
            &[vec![("from-index.txt", b"via manifest index\n")]],
            true, // Use manifest index indirection.
        );

        run(
            tmp.path(),
            tarball.to_str().unwrap(),
            "ociindex",
            false,
            false,
        )
        .unwrap();

        let rootfs = tmp.path().join("rootfs/ociindex");
        assert_eq!(
            fs::read_to_string(rootfs.join("from-index.txt")).unwrap(),
            "via manifest index\n"
        );

        let _ = fs::remove_file(&tarball);
    }
}
