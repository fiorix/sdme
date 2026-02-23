//! Rootfs import logic: directory copy, tarball extraction, URL download, OCI image, and QCOW2 support.
//!
//! NOTE: Internally the code uses "rootfs" (variables, structs, module name),
//! but the CLI command is "fs" and the on-disk path is {datadir}/fs/.
//!
//! This module handles all import sources for `sdme fs import`:
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

use crate::rootfs::DistroFamily;
use crate::{State, validate_name, check_interrupted};

/// Controls whether systemd packages are installed during rootfs import.
#[derive(Debug, Clone, Copy, PartialEq, clap::ValueEnum)]
pub enum InstallPackages {
    /// Prompt the user if on an interactive terminal; refuse otherwise.
    Auto,
    /// Install systemd packages via chroot if missing.
    Yes,
    /// Refuse to import if systemd is missing (unless --force).
    No,
}

// --- Source detection ---

/// Classifies the source argument for rootfs import.
#[derive(Debug)]
enum SourceKind {
    Directory(PathBuf),
    Tarball(PathBuf),
    QcowImage(PathBuf),
    RawImage(PathBuf),
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

/// Represents the meaningful file types for downloaded files.
/// OCI is not applicable here — it is detected *after* tarball extraction.
#[derive(Debug, PartialEq)]
enum DownloadedFileKind {
    Tarball,
    QcowImage,
    RawImage,
}

/// Detect file kind from the HTTP Content-Type header (tier 1).
/// Returns `None` for unknown or overly generic types like `application/octet-stream`.
fn detect_kind_from_content_type(ct: &str) -> Option<DownloadedFileKind> {
    match ct {
        "application/x-tar"
        | "application/gzip"
        | "application/x-gzip"
        | "application/x-bzip2"
        | "application/x-xz"
        | "application/zstd"
        | "application/x-zstd"
        | "application/x-compressed-tar" => Some(DownloadedFileKind::Tarball),
        "application/x-qemu-disk" => Some(DownloadedFileKind::QcowImage),
        "application/x-raw-disk-image" => Some(DownloadedFileKind::RawImage),
        _ => None,
    }
}

/// Detect file kind from URL path extension (tier 2).
/// Strips query string and fragment before inspecting extensions.
fn detect_kind_from_url(url: &str) -> Option<DownloadedFileKind> {
    // Strip query string and fragment.
    let path = url.split('?').next().unwrap_or(url);
    let path = path.split('#').next().unwrap_or(path);

    // Extract the filename from the last path segment.
    let filename = path.rsplit('/').next().unwrap_or(path).to_lowercase();

    if filename.ends_with(".qcow2") {
        return Some(DownloadedFileKind::QcowImage);
    }

    // Raw disk images, including compressed variants.
    let raw_extensions = [
        ".raw", ".raw.gz", ".raw.bz2", ".raw.xz", ".raw.zst",
        ".img", ".img.gz", ".img.bz2", ".img.xz", ".img.zst",
    ];
    for ext in &raw_extensions {
        if filename.ends_with(ext) {
            return Some(DownloadedFileKind::RawImage);
        }
    }

    let tarball_extensions = [
        ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz", ".tar.zst", ".tzst",
    ];
    for ext in &tarball_extensions {
        if filename.ends_with(ext) {
            return Some(DownloadedFileKind::Tarball);
        }
    }

    // Bare compression extensions — common for compressed tarballs named like `rootfs.gz`.
    let compression_extensions = [".gz", ".bz2", ".xz", ".zst"];
    for ext in &compression_extensions {
        if filename.ends_with(ext) {
            return Some(DownloadedFileKind::Tarball);
        }
    }

    None
}

/// Check if a file looks like a raw disk image by reading the MBR boot signature
/// (bytes 0x55, 0xAA at offset 510) or GPT magic ("EFI PART" at offset 512).
fn is_raw_disk_image(path: &Path) -> bool {
    let Ok(mut file) = File::open(path) else {
        return false;
    };
    let mut buf = [0u8; 520];
    let n = file.read(&mut buf).unwrap_or(0);
    if n < 512 {
        return false;
    }
    // MBR signature at offset 510-511.
    if buf[510] == 0x55 && buf[511] == 0xAA {
        return true;
    }
    // GPT magic "EFI PART" at offset 512 (start of LBA 1).
    if n >= 520 && &buf[512..520] == b"EFI PART" {
        return true;
    }
    false
}

/// Detect file kind from magic bytes (tier 3, fallback).
/// Checks for QCOW2 magic, then raw disk image signatures; defaults to Tarball.
fn detect_kind_from_magic(path: &Path) -> DownloadedFileKind {
    if is_qcow2(path) {
        DownloadedFileKind::QcowImage
    } else if is_raw_disk_image(path) {
        DownloadedFileKind::RawImage
    } else {
        DownloadedFileKind::Tarball
    }
}

/// Raw disk image extensions (uncompressed and compressed variants).
const RAW_IMAGE_EXTENSIONS: &[&str] = &[
    ".raw", ".raw.gz", ".raw.bz2", ".raw.xz", ".raw.zst",
    ".img", ".img.gz", ".img.bz2", ".img.xz", ".img.zst",
];

/// Check if a filename has a raw disk image extension.
fn has_raw_image_extension(filename: &str) -> bool {
    let lower = filename.to_lowercase();
    RAW_IMAGE_EXTENSIONS.iter().any(|ext| lower.ends_with(ext))
}

/// Detect whether the source is a URL, directory, qcow2 image, raw image, tarball file, or invalid.
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
        // Detect raw images by extension (magic byte detection doesn't work for
        // compressed raw images, and uncompressed raw images share boot sector
        // signatures with many file types).
        if has_raw_image_extension(source) {
            return Ok(SourceKind::RawImage(path.to_path_buf()));
        }
        // Fall back to magic-byte detection for raw images without a known extension.
        if is_raw_disk_image(path) {
            return Ok(SourceKind::RawImage(path.to_path_buf()));
        }
        return Ok(SourceKind::Tarball(path.to_path_buf()));
    }
    if !path.exists() {
        bail!("source path does not exist: {source}");
    }
    bail!("source path is not a file or directory: {source}");
}

// --- Compression ---

#[derive(Debug)]
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
    for entry in archive.entries().with_context(|| {
        format!("failed to extract tarball to {}", dest.display())
    })? {
        check_interrupted()?;
        let mut entry = entry.with_context(|| {
            format!("failed to extract tarball to {}", dest.display())
        })?;
        entry.unpack_in(dest).with_context(|| {
            format!("failed to extract tarball to {}", dest.display())
        })?;
    }
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
        check_interrupted()?;
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
        check_interrupted()?;
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

/// Resolve the proxy URI from environment variables.
///
/// Checks (in order): `https_proxy`, `HTTPS_PROXY`, `http_proxy`, `HTTP_PROXY`,
/// `all_proxy`, `ALL_PROXY`. Returns the first non-empty value found.
fn proxy_from_env() -> Option<String> {
    for var in [
        "https_proxy",
        "HTTPS_PROXY",
        "http_proxy",
        "HTTP_PROXY",
        "all_proxy",
        "ALL_PROXY",
    ] {
        if let Ok(val) = std::env::var(var) {
            if !val.is_empty() {
                return Some(val);
            }
        }
    }
    None
}

/// Build a ureq agent, configuring proxy from environment if available.
fn build_http_agent(verbose: bool) -> Result<ureq::Agent> {
    let mut config = ureq::Agent::config_builder();
    if let Some(proxy_uri) = proxy_from_env() {
        if verbose {
            eprintln!("using proxy: {proxy_uri}");
        }
        let proxy = ureq::Proxy::new(&proxy_uri)
            .with_context(|| format!("invalid proxy URI: {proxy_uri}"))?;
        config = config.proxy(Some(proxy));
    } else if verbose {
        eprintln!("no proxy configured");
    }
    Ok(config.build().into())
}

/// Download a URL to a local file, streaming to constant memory.
/// Returns the Content-Type mime type from the response, if present.
fn download_file(url: &str, dest: &Path, verbose: bool) -> Result<Option<String>> {
    if verbose {
        eprintln!("downloading {url}");
    }

    let agent = build_http_agent(verbose)?;
    let response = agent
        .get(url)
        .call()
        .with_context(|| format!("failed to download {url}"))?;

    let content_type = response.body().mime_type().map(|s| s.to_string());
    let mut reader = response.into_body().into_reader();
    let mut file =
        fs::File::create(dest).with_context(|| format!("failed to create {}", dest.display()))?;

    let mut buf = [0u8; 65536];
    let mut total: u64 = 0;
    loop {
        check_interrupted()?;
        let n = reader
            .read(&mut buf)
            .with_context(|| format!("failed to read from {url}"))?;
        if n == 0 {
            break;
        }
        std::io::Write::write_all(&mut file, &buf[..n])
            .with_context(|| format!("failed to write download to {}", dest.display()))?;
        total += n as u64;
    }

    if verbose {
        eprintln!("downloaded {} bytes to {}", total, dest.display());
    }

    Ok(content_type)
}

/// Download a URL to a temp file and import it using 3-tier file type detection:
/// 1. Content-Type header (highest priority)
/// 2. URL filename extension
/// 3. Magic bytes (fallback)
fn import_url(
    url: &str,
    staging_dir: &Path,
    rootfs_dir: &Path,
    name: &str,
    verbose: bool,
) -> Result<()> {
    let temp_file = rootfs_dir.join(format!(".{name}.download"));

    let result = (|| -> Result<()> {
        let content_type = download_file(url, &temp_file, verbose)?;

        // Tier 1: Content-Type header.
        let kind = content_type
            .as_deref()
            .and_then(detect_kind_from_content_type);

        // Tier 2: URL filename extension.
        let kind = kind.or_else(|| detect_kind_from_url(url));

        // Tier 3: Magic bytes (fallback).
        let kind = kind.unwrap_or_else(|| detect_kind_from_magic(&temp_file));

        if verbose {
            eprintln!(
                "detected file type: {:?} (content-type: {:?})",
                kind, content_type
            );
        }

        match kind {
            DownloadedFileKind::QcowImage => import_qcow2(&temp_file, staging_dir, verbose),
            DownloadedFileKind::RawImage => import_raw(&temp_file, staging_dir, verbose),
            DownloadedFileKind::Tarball => import_tarball(&temp_file, staging_dir, verbose),
        }
    })();

    // Clean up temp file on both success and failure.
    let _ = fs::remove_file(&temp_file);

    result
}

// --- QCOW2 import ---

/// RAII guard for an NBD device connection. Disconnects on drop.
struct NbdGuard {
    device: PathBuf,
    active: bool,
}

impl NbdGuard {
    fn new() -> Self {
        Self {
            device: PathBuf::new(),
            active: false,
        }
    }

    fn set_active(&mut self, device: PathBuf) {
        self.device = device;
        self.active = true;
    }

    fn disconnect(&mut self) {
        if self.active {
            let _ = Command::new("qemu-nbd")
                .args(["--disconnect"])
                .arg(&self.device)
                .status();
            self.active = false;
        }
    }
}

impl Drop for NbdGuard {
    fn drop(&mut self) {
        self.disconnect();
    }
}

/// RAII guard for a mount point. Unmounts and removes the directory on drop.
struct MountGuard {
    path: PathBuf,
    mounted: bool,
}

impl MountGuard {
    fn new() -> Self {
        Self {
            path: PathBuf::new(),
            mounted: false,
        }
    }

    fn set_mounted(&mut self, path: PathBuf) {
        self.path = path;
        self.mounted = true;
    }

    fn unmount(&mut self) {
        if self.mounted {
            let _ = Command::new("umount").arg(&self.path).status();
            let _ = fs::remove_dir(&self.path);
            self.mounted = false;
        }
    }
}

impl Drop for MountGuard {
    fn drop(&mut self) {
        self.unmount();
    }
}

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

    if !verbose {
        eprintln!("warning: qcow2 imports can be slow; use -v to see progress");
    } else {
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

    let mut nbd_guard = NbdGuard::new();
    let mut mount_guard = MountGuard::new();

    // Connect the image. The guard ensures disconnect on any exit path.
    let status = Command::new("qemu-nbd")
        .args(["--read-only", "--connect"])
        .arg(&nbd_dev)
        .arg(image)
        .status()
        .context("failed to run qemu-nbd")?;
    if !status.success() {
        bail!("qemu-nbd --connect failed for {}", image.display());
    }
    nbd_guard.set_active(nbd_dev.clone());

    check_interrupted()?;

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

    check_interrupted()?;

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
    mount_guard.set_mounted(mount_dir);

    // Copy the tree. Guards handle cleanup on error or interruption.
    let result = do_import(&mount_guard.path, staging_dir, verbose);

    // Explicit cleanup in order (mount before nbd disconnect).
    mount_guard.unmount();
    nbd_guard.disconnect();

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

/// Find the root partition on a block device (nbd or loop).
///
/// Looks for partition devices (`/dev/{dev}pM`) and picks the largest one,
/// which is typically the root filesystem. If no partitions are found,
/// tries the whole device (for unpartitioned disk images).
fn find_root_partition(block_dev: &Path, verbose: bool) -> Result<PathBuf> {
    let dev_name = block_dev
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
        return Ok(block_dev.to_path_buf());
    }

    // Pick the largest partition (usually the root filesystem).
    partitions.sort_by(|a, b| b.1.cmp(&a.1));
    Ok(partitions[0].0.clone())
}

// --- Raw disk image import ---

/// RAII guard for a loop device. Detaches on drop.
struct LoopGuard {
    device: PathBuf,
    active: bool,
}

impl LoopGuard {
    fn new() -> Self {
        Self {
            device: PathBuf::new(),
            active: false,
        }
    }

    fn set_active(&mut self, device: PathBuf) {
        self.device = device;
        self.active = true;
    }

    fn detach(&mut self) {
        if self.active {
            let _ = Command::new("losetup")
                .args(["--detach"])
                .arg(&self.device)
                .status();
            self.active = false;
        }
    }
}

impl Drop for LoopGuard {
    fn drop(&mut self) {
        self.detach();
    }
}

/// Decompress a file in-place if it is compressed, returning the path to the
/// uncompressed file. For uncompressed files, returns the original path unchanged.
/// For compressed files, decompresses to a `.decompressed` sibling file and returns
/// that path.
fn decompress_if_needed(path: &Path, verbose: bool) -> Result<PathBuf> {
    let compression = detect_compression(path)?;
    match compression {
        Compression::None => Ok(path.to_path_buf()),
        _ => {
            let decompressed = path.with_extension("decompressed");
            if verbose {
                eprintln!(
                    "decompressing {} ({:?})",
                    path.display(),
                    compression,
                );
            }
            let input = File::open(path)
                .with_context(|| format!("failed to open {}", path.display()))?;
            let mut output = File::create(&decompressed)
                .with_context(|| format!("failed to create {}", decompressed.display()))?;

            let mut reader: Box<dyn std::io::Read> = match compression {
                Compression::Gzip => {
                    Box::new(flate2::read::GzDecoder::new(input))
                }
                Compression::Bzip2 => {
                    Box::new(bzip2::read::BzDecoder::new(input))
                }
                Compression::Xz => {
                    Box::new(xz2::read::XzDecoder::new(input))
                }
                Compression::Zstd => {
                    Box::new(
                        zstd::stream::read::Decoder::new(input)
                            .context("failed to create zstd decoder")?,
                    )
                }
                Compression::None => unreachable!(),
            };

            let mut buf = [0u8; 65536];
            loop {
                check_interrupted()?;
                let n = reader.read(&mut buf)
                    .context("failed to read during decompression")?;
                if n == 0 {
                    break;
                }
                std::io::Write::write_all(&mut output, &buf[..n])
                    .context("failed to write during decompression")?;
            }

            if verbose {
                let meta = fs::metadata(&decompressed)?;
                eprintln!("decompressed to {} ({} bytes)", decompressed.display(), meta.len());
            }
            Ok(decompressed)
        }
    }
}

/// Import a raw disk image by mounting it via a loop device and copying the filesystem tree.
///
/// Steps:
/// 1. Decompress the image if compressed
/// 2. Attach via `losetup --partscan --read-only --find --show`
/// 3. Discover and mount the root partition
/// 4. Copy the mounted tree to the staging directory
/// 5. Clean up (unmount, detach loop, remove temp files)
fn import_raw(image: &Path, staging_dir: &Path, verbose: bool) -> Result<()> {
    if !verbose {
        eprintln!("warning: raw image imports can be slow; use -v to see progress");
    } else {
        eprintln!("importing raw disk image: {}", image.display());
    }

    // Decompress if needed.
    let decompressed = decompress_if_needed(image, verbose)?;
    let cleanup_decompressed = decompressed != image;

    let result = (|| -> Result<()> {
        // Attach the image as a loop device.
        let output = Command::new("losetup")
            .args(["--partscan", "--read-only", "--find", "--show"])
            .arg(&decompressed)
            .output()
            .context("failed to run losetup")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("losetup failed: {stderr}");
        }
        let loop_dev = PathBuf::from(
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        );

        let mut loop_guard = LoopGuard::new();
        loop_guard.set_active(loop_dev.clone());

        if verbose {
            eprintln!("attached loop device: {}", loop_dev.display());
        }

        check_interrupted()?;

        // Small delay for partition devices to appear.
        std::thread::sleep(std::time::Duration::from_millis(500));

        check_interrupted()?;

        // Find the root partition device.
        let part_dev = find_root_partition(&loop_dev, verbose)?;
        if verbose {
            eprintln!("mounting partition: {}", part_dev.display());
        }

        // Create a temporary mount point.
        let mut mount_guard = MountGuard::new();
        let mount_dir = staging_dir.with_file_name(format!(
            ".{}.raw-mount",
            staging_dir.file_name().unwrap().to_string_lossy()
        ));
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
        mount_guard.set_mounted(mount_dir);

        // Copy the tree. Guards handle cleanup on error or interruption.
        let result = do_import(&mount_guard.path, staging_dir, verbose);

        // Explicit cleanup in order (unmount before loop detach).
        mount_guard.unmount();
        loop_guard.detach();

        result
    })();

    // Clean up decompressed temp file.
    if cleanup_decompressed {
        let _ = fs::remove_file(&decompressed);
    }

    result
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

// --- Systemd detection and package installation ---

/// Check whether systemd is present inside a rootfs.
fn has_systemd(rootfs: &Path, family: &DistroFamily) -> bool {
    let common_paths = [
        "usr/bin/systemd",
        "usr/lib/systemd/systemd",
        "lib/systemd/systemd",
    ];
    for p in &common_paths {
        if rootfs.join(p).exists() {
            return true;
        }
    }

    if *family == DistroFamily::NixOS {
        if rootfs.join("run/current-system/sw/bin/systemd").exists() {
            return true;
        }
        // Scan nix store for systemd binary.
        let store = rootfs.join("nix/store");
        if let Ok(entries) = fs::read_dir(&store) {
            for entry in entries.flatten() {
                if entry.path().join("bin/systemd").exists() {
                    return true;
                }
            }
        }
    }

    false
}

/// RAII guard for bind mounts into a chroot environment.
///
/// Manages `/proc`, `/sys`, `/dev`, `/dev/pts` bind mounts and
/// `/etc/resolv.conf` for DNS resolution during package installation.
struct ChrootGuard {
    rootfs: PathBuf,
    mounts: Vec<PathBuf>,
    resolv_backup: Option<PathBuf>,
}

impl ChrootGuard {
    /// Set up bind mounts and resolv.conf for chroot package installation.
    fn setup(rootfs: &Path) -> Result<Self> {
        let mut guard = Self {
            rootfs: rootfs.to_path_buf(),
            mounts: Vec::new(),
            resolv_backup: None,
        };

        let bind_targets = ["proc", "sys", "dev"];
        for target in &bind_targets {
            let mount_point = rootfs.join(target);
            fs::create_dir_all(&mount_point).with_context(|| {
                format!("failed to create mount point {}", mount_point.display())
            })?;
            let source = PathBuf::from("/").join(target);
            let status = Command::new("mount")
                .args(["--bind"])
                .arg(&source)
                .arg(&mount_point)
                .status()
                .with_context(|| format!("failed to bind mount {}", source.display()))?;
            if !status.success() {
                bail!("bind mount failed: {} -> {}", source.display(), mount_point.display());
            }
            guard.mounts.push(mount_point);
        }

        // Bind mount /dev/pts separately.
        let devpts = rootfs.join("dev/pts");
        fs::create_dir_all(&devpts)?;
        let status = Command::new("mount")
            .args(["--bind", "/dev/pts"])
            .arg(&devpts)
            .status()
            .context("failed to bind mount /dev/pts")?;
        if !status.success() {
            bail!("bind mount failed: /dev/pts -> {}", devpts.display());
        }
        guard.mounts.push(devpts);

        // Copy host resolv.conf for DNS resolution.
        let resolv = rootfs.join("etc/resolv.conf");
        let resolv_bak = rootfs.join("etc/resolv.conf.sdme-bak");
        if resolv.exists() || resolv.symlink_metadata().is_ok() {
            // Back up existing (could be a symlink in some distros).
            let _ = fs::rename(&resolv, &resolv_bak);
            guard.resolv_backup = Some(resolv_bak);
        }
        if let Err(e) = fs::copy("/etc/resolv.conf", &resolv) {
            eprintln!("warning: could not copy /etc/resolv.conf to chroot: {e}");
        }

        Ok(guard)
    }

    fn cleanup(&mut self) {
        // Unmount in reverse order.
        for mount_point in self.mounts.drain(..).rev() {
            let _ = Command::new("umount")
                .arg(&mount_point)
                .status();
        }

        // Restore original resolv.conf.
        let resolv = self.rootfs.join("etc/resolv.conf");
        if let Some(ref backup) = self.resolv_backup {
            let _ = fs::remove_file(&resolv);
            let _ = fs::rename(backup, &resolv);
            self.resolv_backup = None;
        } else {
            // We created it; remove it.
            let _ = fs::remove_file(&resolv);
        }
    }
}

impl Drop for ChrootGuard {
    fn drop(&mut self) {
        self.cleanup();
    }
}

/// Return the shell commands that would be run to install systemd packages.
fn install_commands(family: &DistroFamily) -> Vec<&'static str> {
    match family {
        DistroFamily::Debian => vec![
            "apt-get update",
            "DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC apt-get -y install tzdata",
            "apt-get install -y dbus systemd; apt-get autoremove -y -f && apt-get clean",
        ],
        DistroFamily::Fedora => vec![
            "dnf install -y systemd util-linux pam; dnf clean all",
        ],
        _ => vec![],
    }
}

/// Install systemd packages into a rootfs via chroot.
fn install_systemd_packages(rootfs: &Path, family: &DistroFamily, verbose: bool) -> Result<()> {
    let commands = install_commands(family);
    if commands.is_empty() {
        bail!("no package installation commands available for distro family {:?}", family);
    }

    if verbose {
        eprintln!("setting up chroot environment for package installation");
    }

    let mut chroot_guard = ChrootGuard::setup(rootfs)?;

    let result = (|| -> Result<()> {
        for cmd_str in &commands {
            check_interrupted()?;
            if verbose {
                eprintln!("chroot: {cmd_str}");
            }
            let status = Command::new("chroot")
                .arg(rootfs)
                .args(["/bin/sh", "-c", cmd_str])
                .status()
                .with_context(|| format!("failed to run chroot command: {cmd_str}"))?;
            if !status.success() {
                bail!("chroot command failed (exit {}): {cmd_str}",
                    status.code().unwrap_or(-1));
            }
        }
        Ok(())
    })();

    // Explicit cleanup before returning the result so errors propagate cleanly.
    chroot_guard.cleanup();

    result
}

/// Prompt the user interactively to install systemd packages.
///
/// Returns true if the user accepts, false otherwise.
fn prompt_install_systemd(family: &DistroFamily, distro_name: &str) -> bool {
    let commands = install_commands(family);
    eprintln!("warning: systemd not found in rootfs (detected: {distro_name})");
    eprintln!("Install systemd packages via chroot? The following commands will run:");
    for cmd in &commands {
        eprintln!("  {cmd}");
    }
    eprint!("\nProceed? [y/N]: ");
    let _ = std::io::Write::flush(&mut std::io::stderr());

    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_err() {
        return false;
    }
    matches!(input.trim(), "y" | "Y")
}

/// Check if stdin is an interactive terminal.
fn is_interactive_terminal() -> bool {
    unsafe { libc::isatty(libc::STDIN_FILENO) != 0 }
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
pub fn run(
    datadir: &Path,
    source: &str,
    name: &str,
    verbose: bool,
    force: bool,
    install_packages: InstallPackages,
) -> Result<()> {
    validate_name(name)?;

    let kind = detect_source_kind(source)?;

    let rootfs_dir = datadir.join("fs");
    let final_dir = rootfs_dir.join(name);
    if final_dir.exists() {
        if !force {
            bail!("fs already exists: {name}; re-run with -f to replace it");
        }
        if verbose {
            eprintln!("removing existing fs '{name}' (forced)");
        }
        let _ = make_removable(&final_dir);
        fs::remove_dir_all(&final_dir)
            .with_context(|| format!("failed to remove existing fs {}", final_dir.display()))?;
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
        SourceKind::RawImage(ref path) => import_raw(path, &staging_dir, verbose),
        SourceKind::Url(ref url) => import_url(url, &staging_dir, &rootfs_dir, name, verbose),
    };

    if let Err(e) = result {
        let _ = make_removable(&staging_dir);
        let _ = fs::remove_dir_all(&staging_dir);
        return Err(e);
    }

    // --- Systemd detection and optional package installation ---
    // At this point, staging_dir contains the imported rootfs.

    let family = crate::rootfs::detect_distro_family(&staging_dir);
    let distro_name = crate::rootfs::detect_distro(&staging_dir);

    if verbose {
        eprintln!(
            "detected distro: {} (family: {:?})",
            if distro_name.is_empty() { "unknown" } else { &distro_name },
            family,
        );
    }

    if !has_systemd(&staging_dir, &family) {
        let install_result = (|| -> Result<()> {
            match install_packages {
                InstallPackages::Yes => {
                    if family == DistroFamily::Unknown || family == DistroFamily::NixOS {
                        if force {
                            eprintln!(
                                "warning: cannot install systemd for {:?} distro; \
                                 importing anyway (forced)",
                                family
                            );
                            return Ok(());
                        }
                        bail!(
                            "systemd not found and cannot install packages for {:?} distro",
                            family
                        );
                    }
                    install_systemd_packages(&staging_dir, &family, verbose)?;
                }
                InstallPackages::Auto => {
                    if family == DistroFamily::Unknown || family == DistroFamily::NixOS {
                        if force {
                            eprintln!(
                                "warning: systemd not found in rootfs; \
                                 importing anyway (forced)"
                            );
                            return Ok(());
                        }
                        bail!(
                            "systemd not found in rootfs and distro family is {:?}; \
                             cannot install packages automatically\n\
                             re-run with -f to import anyway",
                            family
                        );
                    }
                    if is_interactive_terminal() {
                        if prompt_install_systemd(&family, &distro_name) {
                            install_systemd_packages(&staging_dir, &family, verbose)?;
                        } else {
                            bail!("systemd not found in rootfs; import aborted by user");
                        }
                    } else {
                        if force {
                            eprintln!(
                                "warning: systemd not found in rootfs; \
                                 importing anyway (forced)"
                            );
                            return Ok(());
                        }
                        bail!(
                            "systemd not found in rootfs and running non-interactively; \
                             re-run with --install-packages=yes or -f to override"
                        );
                    }
                }
                InstallPackages::No => {
                    if force {
                        eprintln!(
                            "warning: systemd not found in rootfs; importing anyway (forced)"
                        );
                        return Ok(());
                    }
                    bail!(
                        "systemd not found in rootfs; \
                         re-run with --install-packages=yes or -f to override"
                    );
                }
            }
            Ok(())
        })();

        if let Err(e) = install_result {
            let _ = make_removable(&staging_dir);
            let _ = fs::remove_dir_all(&staging_dir);
            return Err(e);
        }

        // Verify systemd is present after installation.
        if !has_systemd(&staging_dir, &family) && !force {
            let _ = make_removable(&staging_dir);
            let _ = fs::remove_dir_all(&staging_dir);
            bail!("systemd still not found after package installation");
        }
    }

    // --- Atomic rename to final location ---

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
        eprintln!("imported fs '{name}' from {source}");
    }
    Ok(())
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// Mutex that serializes all tests touching the global INTERRUPTED flag
    /// so they don't poison concurrent tests that call check_interrupted().
    static INTERRUPT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Helper to run import in tests, bypassing systemd checks.
    fn test_run(
        datadir: &Path,
        source: &str,
        name: &str,
        verbose: bool,
        force: bool,
    ) -> Result<()> {
        // Acquire the interrupt lock to prevent concurrent InterruptGuard
        // tests from poisoning check_interrupted() calls inside run().
        let _lock = INTERRUPT_LOCK.lock().unwrap();
        run(datadir, source, name, verbose, force, InstallPackages::No)
    }

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

        test_run(
            tmp.path(),
            src.path().to_str().unwrap(),
            "test",
            false,
            true,
        )
        .unwrap();

        let rootfs = tmp.path().join("fs/test");
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

        test_run(
            tmp.path(),
            src.path().to_str().unwrap(),
            "perms",
            false,
            true,
        )
        .unwrap();

        let rootfs = tmp.path().join("fs/perms");
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

        test_run(
            tmp.path(),
            src.path().to_str().unwrap(),
            "sym",
            false,
            true,
        )
        .unwrap();

        let rootfs = tmp.path().join("fs/sym");
        let link_target = fs::read_link(rootfs.join("link.txt")).unwrap();
        assert_eq!(link_target.to_str().unwrap(), "target.txt");

        let dangling_target = fs::read_link(rootfs.join("dangling")).unwrap();
        assert_eq!(dangling_target.to_str().unwrap(), "/nonexistent");
    }

    #[test]
    fn test_import_duplicate_name() {
        let tmp = TempDataDir::new();
        let src = TempSourceDir::new("dup");

        test_run(
            tmp.path(),
            src.path().to_str().unwrap(),
            "dup",
            false,
            true,
        )
        .unwrap();
        let err = test_run(
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

        let err = test_run(
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
        let err = test_run(
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

        let err = test_run(
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

        let result = test_run(
            tmp.path(),
            src.path().to_str().unwrap(),
            "fail",
            false,
            false,
        );
        assert!(result.is_err());

        // Staging dir should be cleaned up.
        let staging = tmp.path().join("fs/.fail.importing");
        assert!(!staging.exists(), "staging dir was not cleaned up");

        // Final dir should not exist.
        let final_dir = tmp.path().join("fs/fail");
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

        test_run(
            tmp.path(),
            src.path().to_str().unwrap(),
            "empty",
            false,
            true,
        )
        .unwrap();

        let rootfs = tmp.path().join("fs/empty");
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

        test_run(
            tmp.path(),
            src.path().to_str().unwrap(),
            "ts",
            false,
            true,
        )
        .unwrap();

        let dst_stat = lstat_entry(&tmp.path().join("fs/ts/file.txt")).unwrap();
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

        test_run(
            tmp.path(),
            src.path().to_str().unwrap(),
            "dev",
            false,
            true,
        )
        .unwrap();

        let dst_stat = lstat_entry(&tmp.path().join("fs/dev/null")).unwrap();
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

        test_run(
            tmp.path(),
            src.path().to_str().unwrap(),
            "distro",
            false,
            true,
        )
        .unwrap();

        let meta_path = tmp.path().join("fs/.distro.meta");
        assert!(meta_path.exists(), ".meta sidecar should exist");
        let state = State::read_from(&meta_path).unwrap();
        assert_eq!(state.get("DISTRO").unwrap(), "Ubuntu 24.04.4 LTS");
    }

    #[test]
    fn test_import_no_os_release() {
        let tmp = TempDataDir::new();
        let src = TempSourceDir::new("no-os-release");

        fs::write(src.path().join("hello.txt"), "hi\n").unwrap();

        test_run(
            tmp.path(),
            src.path().to_str().unwrap(),
            "noos",
            false,
            true,
        )
        .unwrap();

        let meta_path = tmp.path().join("fs/.noos.meta");
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

        test_run(
            tmp.path(),
            tarball.to_str().unwrap(),
            "tgz",
            false,
            true,
        )
        .unwrap();

        let rootfs = tmp.path().join("fs/tgz");
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

        test_run(
            tmp.path(),
            tarball.to_str().unwrap(),
            "plain",
            false,
            true,
        )
        .unwrap();

        let rootfs = tmp.path().join("fs/plain");
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

        let err = test_run(
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
        assert!(!tmp.path().join("fs/.bad.importing").exists());

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

        test_run(
            tmp.path(),
            src.path().to_str().unwrap(),
            "own",
            false,
            true,
        )
        .unwrap();

        let dst_stat = lstat_entry(&tmp.path().join("fs/own/owned.txt")).unwrap();
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

        test_run(
            tmp.path(),
            tarball.to_str().unwrap(),
            "ocibasic",
            false,
            true,
        )
        .unwrap();

        let rootfs = tmp.path().join("fs/ocibasic");
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

        test_run(
            tmp.path(),
            tarball.to_str().unwrap(),
            "ocimulti",
            false,
            true,
        )
        .unwrap();

        let rootfs = tmp.path().join("fs/ocimulti");
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

        test_run(
            tmp.path(),
            tarball.to_str().unwrap(),
            "ociwhiteout",
            false,
            true,
        )
        .unwrap();

        let rootfs = tmp.path().join("fs/ociwhiteout");
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

        test_run(
            tmp.path(),
            tarball.to_str().unwrap(),
            "ociindex",
            false,
            true,
        )
        .unwrap();

        let rootfs = tmp.path().join("fs/ociindex");
        assert_eq!(
            fs::read_to_string(rootfs.join("from-index.txt")).unwrap(),
            "via manifest index\n"
        );

        let _ = fs::remove_file(&tarball);
    }

    // --- Interrupt tests ---

    /// RAII guard that acquires INTERRUPT_LOCK, sets INTERRUPTED to true,
    /// and resets it on drop.
    struct InterruptGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl InterruptGuard {
        fn new() -> Self {
            use std::sync::atomic::Ordering;
            let lock = INTERRUPT_LOCK.lock().unwrap();
            crate::INTERRUPTED.store(true, Ordering::Relaxed);
            Self { _lock: lock }
        }
    }

    impl Drop for InterruptGuard {
        fn drop(&mut self) {
            use std::sync::atomic::Ordering;
            crate::INTERRUPTED.store(false, Ordering::Relaxed);
        }
    }

    #[test]
    fn test_check_interrupted() {
        let _lock = INTERRUPT_LOCK.lock().unwrap();

        // Not interrupted — should be Ok.
        assert!(crate::check_interrupted().is_ok());

        // Set interrupted — should bail.
        {
            use std::sync::atomic::Ordering;
            crate::INTERRUPTED.store(true, Ordering::Relaxed);
        }
        let err = crate::check_interrupted().unwrap_err();
        assert!(
            err.to_string().contains("interrupted"),
            "unexpected error: {err}"
        );

        // Reset for other tests.
        {
            use std::sync::atomic::Ordering;
            crate::INTERRUPTED.store(false, Ordering::Relaxed);
        }
    }

    #[test]
    fn test_copy_tree_interrupted() {
        let _guard = InterruptGuard::new();
        let src = TempSourceDir::new("int-copy-src");
        fs::write(src.path().join("file.txt"), "data").unwrap();

        let dst = std::env::temp_dir().join(format!(
            "sdme-test-int-copy-dst-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dst);
        fs::create_dir_all(&dst).unwrap();

        let err = copy_tree(src.path(), &dst, false).unwrap_err();
        assert!(
            err.to_string().contains("interrupted"),
            "unexpected error: {err}"
        );

        let _ = fs::remove_dir_all(&dst);
    }

    #[test]
    fn test_unpack_tar_interrupted() {
        let _guard = InterruptGuard::new();
        let src = TempSourceDir::new("int-tar-src");
        fs::write(src.path().join("file.txt"), "data").unwrap();

        // Build a small tarball.
        let tarball_path = std::env::temp_dir().join(format!(
            "sdme-test-int-tar-{}-{:?}.tar",
            std::process::id(),
            std::thread::current().id()
        ));
        let file = File::create(&tarball_path).unwrap();
        let mut builder = tar::Builder::new(file);
        builder.append_dir_all(".", src.path()).unwrap();
        builder.finish().unwrap();

        let dest = std::env::temp_dir().join(format!(
            "sdme-test-int-tar-dst-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dest);
        fs::create_dir_all(&dest).unwrap();

        let file = File::open(&tarball_path).unwrap();
        let err = unpack_tar(file, &dest).unwrap_err();
        assert!(
            err.to_string().contains("interrupted"),
            "unexpected error: {err}"
        );

        let _ = fs::remove_dir_all(&dest);
        let _ = fs::remove_file(&tarball_path);
    }

    #[test]
    fn test_detect_kind_from_content_type() {
        // Known tarball types.
        assert_eq!(
            detect_kind_from_content_type("application/x-tar"),
            Some(DownloadedFileKind::Tarball)
        );
        assert_eq!(
            detect_kind_from_content_type("application/gzip"),
            Some(DownloadedFileKind::Tarball)
        );
        assert_eq!(
            detect_kind_from_content_type("application/x-gzip"),
            Some(DownloadedFileKind::Tarball)
        );
        assert_eq!(
            detect_kind_from_content_type("application/x-bzip2"),
            Some(DownloadedFileKind::Tarball)
        );
        assert_eq!(
            detect_kind_from_content_type("application/x-xz"),
            Some(DownloadedFileKind::Tarball)
        );
        assert_eq!(
            detect_kind_from_content_type("application/zstd"),
            Some(DownloadedFileKind::Tarball)
        );
        assert_eq!(
            detect_kind_from_content_type("application/x-zstd"),
            Some(DownloadedFileKind::Tarball)
        );
        assert_eq!(
            detect_kind_from_content_type("application/x-compressed-tar"),
            Some(DownloadedFileKind::Tarball)
        );

        // QCOW2 type.
        assert_eq!(
            detect_kind_from_content_type("application/x-qemu-disk"),
            Some(DownloadedFileKind::QcowImage)
        );

        // Raw disk image type.
        assert_eq!(
            detect_kind_from_content_type("application/x-raw-disk-image"),
            Some(DownloadedFileKind::RawImage)
        );

        // Generic/unknown types return None.
        assert_eq!(detect_kind_from_content_type("application/octet-stream"), None);
        assert_eq!(detect_kind_from_content_type("text/html"), None);
        assert_eq!(detect_kind_from_content_type(""), None);
    }

    #[test]
    fn test_detect_kind_from_url() {
        // Tarball URLs.
        assert_eq!(
            detect_kind_from_url("https://example.com/rootfs.tar"),
            Some(DownloadedFileKind::Tarball)
        );
        assert_eq!(
            detect_kind_from_url("https://example.com/rootfs.tar.gz"),
            Some(DownloadedFileKind::Tarball)
        );
        assert_eq!(
            detect_kind_from_url("https://example.com/rootfs.tgz"),
            Some(DownloadedFileKind::Tarball)
        );
        assert_eq!(
            detect_kind_from_url("https://example.com/rootfs.tar.bz2"),
            Some(DownloadedFileKind::Tarball)
        );
        assert_eq!(
            detect_kind_from_url("https://example.com/rootfs.tbz2"),
            Some(DownloadedFileKind::Tarball)
        );
        assert_eq!(
            detect_kind_from_url("https://example.com/rootfs.tar.xz"),
            Some(DownloadedFileKind::Tarball)
        );
        assert_eq!(
            detect_kind_from_url("https://example.com/rootfs.txz"),
            Some(DownloadedFileKind::Tarball)
        );
        assert_eq!(
            detect_kind_from_url("https://example.com/rootfs.tar.zst"),
            Some(DownloadedFileKind::Tarball)
        );
        assert_eq!(
            detect_kind_from_url("https://example.com/rootfs.tzst"),
            Some(DownloadedFileKind::Tarball)
        );

        // Bare compression extensions.
        assert_eq!(
            detect_kind_from_url("https://example.com/rootfs.gz"),
            Some(DownloadedFileKind::Tarball)
        );
        assert_eq!(
            detect_kind_from_url("https://example.com/rootfs.xz"),
            Some(DownloadedFileKind::Tarball)
        );

        // QCOW2 URLs.
        assert_eq!(
            detect_kind_from_url("https://example.com/disk.qcow2"),
            Some(DownloadedFileKind::QcowImage)
        );

        // Raw disk image URLs.
        assert_eq!(
            detect_kind_from_url("https://example.com/disk.raw"),
            Some(DownloadedFileKind::RawImage)
        );
        assert_eq!(
            detect_kind_from_url("https://example.com/disk.img"),
            Some(DownloadedFileKind::RawImage)
        );

        // Compressed raw disk image URLs.
        assert_eq!(
            detect_kind_from_url("https://example.com/disk.raw.xz"),
            Some(DownloadedFileKind::RawImage)
        );
        assert_eq!(
            detect_kind_from_url("https://example.com/disk.raw.gz"),
            Some(DownloadedFileKind::RawImage)
        );
        assert_eq!(
            detect_kind_from_url("https://example.com/disk.img.zst"),
            Some(DownloadedFileKind::RawImage)
        );

        // URLs with query strings and fragments.
        assert_eq!(
            detect_kind_from_url("https://example.com/rootfs.tar.gz?token=abc"),
            Some(DownloadedFileKind::Tarball)
        );
        assert_eq!(
            detect_kind_from_url("https://example.com/disk.qcow2#section"),
            Some(DownloadedFileKind::QcowImage)
        );
        assert_eq!(
            detect_kind_from_url("https://example.com/disk.raw?token=abc"),
            Some(DownloadedFileKind::RawImage)
        );

        // Case insensitivity.
        assert_eq!(
            detect_kind_from_url("https://example.com/ROOTFS.TAR.GZ"),
            Some(DownloadedFileKind::Tarball)
        );
        assert_eq!(
            detect_kind_from_url("https://example.com/DISK.QCOW2"),
            Some(DownloadedFileKind::QcowImage)
        );
        assert_eq!(
            detect_kind_from_url("https://example.com/DISK.RAW"),
            Some(DownloadedFileKind::RawImage)
        );

        // Unknown extensions.
        assert_eq!(detect_kind_from_url("https://example.com/file.zip"), None);
        assert_eq!(detect_kind_from_url("https://example.com/file"), None);
        assert_eq!(
            detect_kind_from_url("https://example.com/download"),
            None
        );
    }

    #[test]
    fn test_detect_kind_from_magic_tarball() {
        let path = std::env::temp_dir().join(format!(
            "sdme-test-magic-tar-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        // Write non-QCOW2 content — should be detected as tarball.
        fs::write(&path, b"not a qcow2 file").unwrap();
        assert_eq!(detect_kind_from_magic(&path), DownloadedFileKind::Tarball);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_detect_kind_from_magic_qcow2() {
        let path = std::env::temp_dir().join(format!(
            "sdme-test-magic-qcow2-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        // Write QCOW2 magic bytes followed by some padding.
        let mut data = vec![0x51, 0x46, 0x49, 0xfb];
        data.extend_from_slice(&[0u8; 64]);
        fs::write(&path, &data).unwrap();
        assert_eq!(
            detect_kind_from_magic(&path),
            DownloadedFileKind::QcowImage
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_detect_kind_from_magic_raw_mbr() {
        let path = std::env::temp_dir().join(format!(
            "sdme-test-magic-raw-mbr-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        // Write a fake MBR: 512 bytes with boot signature 0x55AA at offset 510-511.
        let mut data = vec![0u8; 512];
        data[510] = 0x55;
        data[511] = 0xAA;
        fs::write(&path, &data).unwrap();
        assert_eq!(
            detect_kind_from_magic(&path),
            DownloadedFileKind::RawImage
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_detect_kind_from_magic_raw_gpt() {
        let path = std::env::temp_dir().join(format!(
            "sdme-test-magic-raw-gpt-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        // Write a fake GPT: 520 bytes with "EFI PART" at offset 512.
        let mut data = vec![0u8; 520];
        data[512..520].copy_from_slice(b"EFI PART");
        fs::write(&path, &data).unwrap();
        assert_eq!(
            detect_kind_from_magic(&path),
            DownloadedFileKind::RawImage
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_is_raw_disk_image_false() {
        let path = std::env::temp_dir().join(format!(
            "sdme-test-not-raw-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        // Write a small non-disk-image file.
        fs::write(&path, b"just some text data").unwrap();
        assert!(!is_raw_disk_image(&path));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_has_raw_image_extension() {
        assert!(has_raw_image_extension("disk.raw"));
        assert!(has_raw_image_extension("disk.img"));
        assert!(has_raw_image_extension("disk.raw.xz"));
        assert!(has_raw_image_extension("disk.raw.gz"));
        assert!(has_raw_image_extension("disk.raw.bz2"));
        assert!(has_raw_image_extension("disk.raw.zst"));
        assert!(has_raw_image_extension("disk.img.xz"));
        assert!(has_raw_image_extension("/path/to/DISK.RAW"));
        assert!(!has_raw_image_extension("disk.qcow2"));
        assert!(!has_raw_image_extension("disk.tar.gz"));
        assert!(!has_raw_image_extension("disk.txt"));
    }

    #[test]
    fn test_detect_source_kind_raw_image() {
        let path = std::env::temp_dir().join(format!(
            "sdme-test-src-{}-{:?}.raw",
            std::process::id(),
            std::thread::current().id()
        ));
        fs::write(&path, b"fake raw data").unwrap();
        let kind = detect_source_kind(path.to_str().unwrap()).unwrap();
        assert!(
            matches!(kind, SourceKind::RawImage(_)),
            "expected RawImage, got {kind:?}"
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_detect_source_kind_raw_image_compressed() {
        let path = std::env::temp_dir().join(format!(
            "sdme-test-src-{}-{:?}.raw.xz",
            std::process::id(),
            std::thread::current().id()
        ));
        fs::write(&path, b"fake compressed raw data").unwrap();
        let kind = detect_source_kind(path.to_str().unwrap()).unwrap();
        assert!(
            matches!(kind, SourceKind::RawImage(_)),
            "expected RawImage, got {kind:?}"
        );
        let _ = fs::remove_file(&path);
    }
}
