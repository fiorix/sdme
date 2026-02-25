//! Rootfs import logic: directory copy, tarball extraction, URL download, OCI image, registry pull, and QCOW2 support.
//!
//! NOTE: Internally the code uses "rootfs" (variables, structs, module name),
//! but the CLI command is "fs" and the on-disk path is {datadir}/fs/.
//!
//! This module handles all import sources for `sdme fs import`:
//! - Local directories (recursive copy preserving permissions, ownership, xattrs)
//! - Tarball files (.tar, .tar.gz, .tar.bz2, .tar.xz, .tar.zst)
//! - HTTP/HTTPS URLs pointing to tarballs
//! - OCI container image archives (.oci.tar, .oci.tar.xz, etc.)
//! - OCI registry images (e.g. quay.io/repo:tag, pulled via OCI Distribution Spec)
//! - QCOW2 disk images (via qemu-nbd, auto-detected by magic bytes)

mod dir;
mod img;
mod oci;
mod registry;
mod tar;

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use anyhow::{bail, Context, Result};

use crate::copy::make_removable;
use crate::rootfs::DistroFamily;
use crate::{State, validate_name, check_interrupted};

use std::process::Command;

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
    RegistryImage(registry::ImageReference),
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
    for ext in RAW_IMAGE_EXTENSIONS {
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

    if let Some(image_ref) = registry::ImageReference::parse(source) {
        return Ok(SourceKind::RegistryImage(image_ref));
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
pub(super) enum Compression {
    None,
    Gzip,
    Bzip2,
    Xz,
    Zstd,
}

/// Detect the compression format of a file by reading its magic bytes.
pub(super) fn detect_compression(path: &Path) -> Result<Compression> {
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
pub(super) fn detect_compression_magic(magic: &[u8]) -> Result<Compression> {
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

/// Get a decompression reader wrapping the given reader.
pub(super) fn get_decoder(
    reader: impl Read + 'static,
    compression: &Compression,
) -> Result<Box<dyn Read>> {
    match compression {
        Compression::Gzip => Ok(Box::new(flate2::read::GzDecoder::new(reader))),
        Compression::Bzip2 => Ok(Box::new(bzip2::read::BzDecoder::new(reader))),
        Compression::Xz => Ok(Box::new(xz2::read::XzDecoder::new(reader))),
        Compression::Zstd => {
            let decoder = zstd::stream::read::Decoder::new(reader)
                .context("failed to create zstd decoder")?;
            Ok(Box::new(decoder))
        }
        Compression::None => Ok(Box::new(reader)),
    }
}

// --- URL download ---

/// Resolve the proxy URI from environment variables.
///
/// Checks (in order): `https_proxy`, `HTTPS_PROXY`, `http_proxy`, `HTTP_PROXY`,
/// `all_proxy`, `ALL_PROXY`. Returns the first non-empty value found.
pub(super) fn proxy_from_env() -> Option<String> {
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
///
/// Note on interrupt handling: the `ctrlc` crate installs signal handlers with
/// `SA_RESTART`, which means a blocked `read()` syscall is automatically restarted
/// after SIGINT rather than returning `EINTR`. If the remote server stalls during a
/// download, Ctrl+C will set `INTERRUPTED` but the read loop won't cycle to check it
/// until the `read()` returns. This is a pre-existing limitation shared with
/// `download_file()` and is inherent to the `SA_RESTART` signal handling model.
/// For metadata requests (auth, manifests), this is mitigated by response size limits
/// (`read_to_string`). For blob downloads, stalled connections will eventually hit
/// TCP keepalive timeouts (typically 2+ hours on Linux).
pub(super) fn build_http_agent(verbose: bool) -> Result<ureq::Agent> {
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

/// Maximum download size (50 GiB) to prevent disk exhaustion from malicious servers.
pub(super) const MAX_DOWNLOAD_SIZE: u64 = 50 * 1024 * 1024 * 1024;

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
        if total > MAX_DOWNLOAD_SIZE {
            bail!(
                "download from {url} exceeds maximum size of {} bytes",
                MAX_DOWNLOAD_SIZE
            );
        }
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
            DownloadedFileKind::QcowImage => img::import_qcow2(&temp_file, staging_dir, verbose),
            DownloadedFileKind::RawImage => img::import_raw(&temp_file, staging_dir, verbose),
            DownloadedFileKind::Tarball => tar::import_tarball(&temp_file, staging_dir, verbose),
        }
    })();

    // Clean up temp file on both success and failure.
    let _ = fs::remove_file(&temp_file);

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
        SourceKind::Directory(ref path) => dir::do_import(path, &staging_dir, verbose),
        SourceKind::Tarball(ref path) => tar::import_tarball(path, &staging_dir, verbose),
        SourceKind::QcowImage(ref path) => img::import_qcow2(path, &staging_dir, verbose),
        SourceKind::RawImage(ref path) => img::import_raw(path, &staging_dir, verbose),
        SourceKind::Url(ref url) => import_url(url, &staging_dir, &rootfs_dir, name, verbose),
        SourceKind::RegistryImage(ref img) => {
            registry::import_registry_image(img, &staging_dir, &rootfs_dir, verbose)
        }
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
                    if !verbose && is_interactive_terminal() {
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
pub(crate) mod tests {
    use super::*;
    use std::os::unix::fs as unix_fs;
    use std::os::unix::fs::PermissionsExt;

    use crate::copy::{copy_tree, lstat_entry, path_to_cstring};

    /// Mutex that serializes all tests touching the global INTERRUPTED flag
    /// so they don't poison concurrent tests that call check_interrupted().
    pub(crate) static INTERRUPT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Helper to run import in tests, bypassing systemd checks.
    pub(crate) fn test_run(
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

    use crate::testutil::TempDataDir;

    pub(crate) fn tmp() -> TempDataDir {
        TempDataDir::new("import")
    }

    pub(crate) struct TempSourceDir {
        dir: std::path::PathBuf,
    }

    impl TempSourceDir {
        pub(crate) fn new(suffix: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "sdme-test-import-src-{}-{:?}-{suffix}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            Self { dir }
        }

        pub(crate) fn path(&self) -> &Path {
            &self.dir
        }
    }

    impl Drop for TempSourceDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    /// RAII guard that acquires INTERRUPT_LOCK, sets INTERRUPTED to true,
    /// and resets it on drop.
    pub(crate) struct InterruptGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl InterruptGuard {
        pub(crate) fn new() -> Self {
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
    fn test_import_basic_directory() {
        let tmp = tmp();
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
        let tmp = tmp();
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
        let tmp = tmp();
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
        let tmp = tmp();
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
        let tmp = tmp();
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
        let tmp = tmp();
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
        let tmp = tmp();
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
        let tmp = tmp();
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
        let tmp = tmp();
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
        let tmp = tmp();
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
        let tmp = tmp();
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
        let tmp = tmp();
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
        let tmp = tmp();
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
    fn test_detect_source_kind_registry() {
        match detect_source_kind("quay.io/centos/centos:stream10").unwrap() {
            SourceKind::RegistryImage(img) => {
                assert_eq!(img.registry, "quay.io");
                assert_eq!(img.repository, "centos/centos");
                assert_eq!(img.reference, "stream10");
            }
            other => panic!("expected RegistryImage, got {other:?}"),
        }
    }

    #[test]
    fn test_detect_source_kind_registry_default_tag() {
        match detect_source_kind("ghcr.io/org/repo").unwrap() {
            SourceKind::RegistryImage(img) => {
                assert_eq!(img.registry, "ghcr.io");
                assert_eq!(img.repository, "org/repo");
                assert_eq!(img.reference, "latest");
            }
            other => panic!("expected RegistryImage, got {other:?}"),
        }
    }

    #[test]
    #[ignore] // Requires CAP_CHOWN (root).
    fn test_import_preserves_ownership() {
        let tmp = tmp();
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

    // --- Interrupt tests ---

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
