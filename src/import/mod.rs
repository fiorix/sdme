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
mod tar;

use anyhow::{bail, Context, Result};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use std::collections::HashMap;

use crate::config::DistroCommands;
use crate::rootfs::DistroFamily;
use crate::{check_interrupted, validate_name, State};

use std::process::Command;
use std::time::Duration;

/// Join command arguments into a shell-safe string.
///
/// Arguments containing spaces, quotes, or shell metacharacters are
/// single-quoted. Single quotes within arguments are escaped as `'\''`.
pub(crate) fn shell_join(args: &[String]) -> String {
    args.iter()
        .map(|arg| {
            if arg.is_empty() {
                "''".to_string()
            } else if arg
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-_./=:@".contains(c))
            {
                arg.clone()
            } else {
                format!("'{}'", arg.replace('\'', "'\\''"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

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

/// Controls how OCI registry images are classified during import.
#[derive(Debug, Clone, Copy, PartialEq, clap::ValueEnum)]
pub enum OciMode {
    /// Auto-detect from image config (entrypoint, cmd, exposed ports).
    Auto,
    /// Treat as base OS image (run systemd detection, ignore exposed ports).
    Base,
    /// Treat as application image (requires --base-fs, generates service unit).
    App,
}

/// Options for rootfs import.
pub struct ImportOptions<'a> {
    /// Import source (path, URL, or OCI registry reference).
    pub source: &'a str,
    /// Name for the imported rootfs.
    pub name: &'a str,
    /// Enable verbose output.
    pub verbose: bool,
    /// Overwrite an existing rootfs with the same name.
    pub force: bool,
    /// Allow interactive prompts (e.g. package installation confirmation).
    pub interactive: bool,
    /// Whether to install systemd packages if missing.
    pub install_packages: InstallPackages,
    /// How to classify OCI registry images (auto, base, or app).
    pub oci_mode: OciMode,
    /// Base rootfs name for OCI app imports.
    pub base_fs: Option<&'a str>,
    /// Docker Hub credentials `(user, token)` for authenticated pulls.
    pub docker_credentials: Option<(&'a str, &'a str)>,
    /// OCI blob cache for registry downloads.
    pub cache: &'a crate::oci::cache::BlobCache,
    /// HTTP configuration for downloads and OCI pulls.
    pub http: crate::config::HttpConfig,
    /// Optional path to a user NixOS configuration file for nix-build imports.
    pub nix_config: Option<&'a Path>,
    /// Optional path to a custom NixOS configuration template that replaces
    /// the embedded DEFAULT_NIXOS_CONFIG. `nix_config` still merges on top.
    pub nix_config_template: &'a str,
    /// Nixpkgs channel for NixOS rootfs builds (e.g. "nixos-unstable").
    pub nixpkgs_channel: &'a str,
    /// Automatically clean up stale transactions before importing.
    pub auto_gc: bool,
    /// Per-distro chroot command overrides from config.
    pub distros: &'a HashMap<String, DistroCommands>,
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
    RegistryImage(crate::oci::registry::ImageReference),
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
/// OCI is not applicable here; it is detected *after* tarball extraction.
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

    // Bare compression extensions, common for compressed tarballs named like `rootfs.gz`.
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
    ".raw", ".raw.gz", ".raw.bz2", ".raw.xz", ".raw.zst", ".img", ".img.gz", ".img.bz2", ".img.xz",
    ".img.zst",
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

    if let Some(image_ref) = crate::oci::registry::ImageReference::parse(source) {
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

/// Detect compression from a file's magic bytes and return a decompression reader.
///
/// Opens the file, reads the first 6 bytes to detect compression, then reopens
/// the file and wraps it in the appropriate decoder. This avoids seeking (which
/// not all readers support) by using a cheap reopen.
pub(crate) fn open_decoder(path: &Path) -> Result<Box<dyn Read>> {
    let mut file =
        File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut magic = [0u8; 6];
    let n = file.read(&mut magic)?;
    drop(file);
    let file = File::open(path)?;
    let compression = detect_compression_magic(&magic[..n])?;
    get_decoder(file, &compression)
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

/// Redact credentials from a proxy URI for safe logging.
///
/// Replaces the userinfo portion (between `://` and `@`) with `***`.
/// If no credentials are present, returns the URI unchanged.
fn redact_proxy_credentials(uri: &str) -> String {
    if let Some(scheme_end) = uri.find("://") {
        let after_scheme = &uri[scheme_end + 3..];
        if let Some(at_pos) = after_scheme.find('@') {
            return format!(
                "{}://***@{}",
                &uri[..scheme_end],
                &after_scheme[at_pos + 1..]
            );
        }
    }
    uri.to_string()
}

/// Resolve the proxy URI from environment variables.
///
/// Checks (in order): `https_proxy`, `HTTPS_PROXY`, `http_proxy`, `HTTP_PROXY`,
/// `all_proxy`, `ALL_PROXY`. Returns the first non-empty value found.
pub(crate) fn proxy_from_env() -> Option<String> {
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

/// Build a ureq agent with shared config: user-agent, timeouts, and proxy from environment.
///
/// Note on interrupt handling: the SIGINT handler does NOT set `SA_RESTART`, so
/// blocked `read()` syscalls return `EINTR` immediately on Ctrl+C. The download
/// loops in `download_file()` and `download_blob()` call `check_interrupted()` on
/// each iteration, which will catch the flag set by the signal handler.
fn build_agent(
    verbose: bool,
    connect_timeout: u64,
    body_timeout: u64,
    http_status_as_error: bool,
    redirect_auth_same_host: bool,
) -> Result<ureq::Agent> {
    let mut config = ureq::Agent::config_builder()
        .http_status_as_error(http_status_as_error)
        .user_agent("sdme/0.1")
        .timeout_connect(Some(Duration::from_secs(connect_timeout)))
        .timeout_resolve(Some(Duration::from_secs(connect_timeout)))
        .timeout_recv_response(Some(Duration::from_secs(connect_timeout * 2)))
        .timeout_recv_body(Some(Duration::from_secs(body_timeout)));
    if redirect_auth_same_host {
        config = config.redirect_auth_headers(ureq::config::RedirectAuthHeaders::SameHost);
    }
    if let Some(proxy_uri) = proxy_from_env() {
        let redacted = redact_proxy_credentials(&proxy_uri);
        if verbose {
            eprintln!("using proxy: {redacted}");
        }
        let proxy = ureq::Proxy::new(&proxy_uri)
            .with_context(|| format!("invalid proxy URI: {redacted}"))?;
        config = config.proxy(Some(proxy));
    } else if verbose {
        eprintln!("no proxy configured");
    }
    Ok(config.build().into())
}

/// Build a ureq agent, configuring proxy from environment if available.
pub(crate) fn build_http_agent(
    verbose: bool,
    connect_timeout: u64,
    body_timeout: u64,
) -> Result<ureq::Agent> {
    build_agent(verbose, connect_timeout, body_timeout, true, true)
}

/// Build a ureq agent that does not convert non-2xx status codes to errors.
///
/// Same proxy/timeout configuration as [`build_http_agent`], but with
/// `http_status_as_error(false)` so callers can inspect non-2xx responses.
pub(crate) fn build_http_agent_no_error(
    connect_timeout: u64,
    body_timeout: u64,
) -> Result<ureq::Agent> {
    build_agent(false, connect_timeout, body_timeout, false, false)
}

/// Download a URL to a local file, streaming to constant memory.
/// Returns the Content-Type mime type from the response, if present.
fn download_file(
    url: &str,
    dest: &Path,
    verbose: bool,
    http: &crate::config::HttpConfig,
) -> Result<Option<String>> {
    if verbose {
        eprintln!("downloading {url}");
    }

    let agent = build_http_agent(verbose, http.connect_timeout, http.body_timeout)?;
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
        if http.max_download_size > 0 && total > http.max_download_size {
            bail!(
                "download from {url} exceeds maximum size of {} bytes",
                http.max_download_size
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
    http: &crate::config::HttpConfig,
) -> Result<()> {
    let temp_file = rootfs_dir.join(format!(".{name}.download-txn-{}", std::process::id()));

    let result = (|| -> Result<()> {
        let content_type = download_file(url, &temp_file, verbose, http)?;

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

// --- Systemd detection and package installation ---

/// What systemd components are present in a rootfs.
struct SystemdPresence {
    /// systemd binary found.
    has_systemd: bool,
    /// dbus daemon found (dbus-daemon or dbus-broker).
    has_dbus: bool,
}

impl SystemdPresence {
    /// Returns true if both systemd and dbus are present.
    fn is_bootable(&self) -> bool {
        self.has_systemd && self.has_dbus
    }

    /// Describes which components are missing, for error messages.
    fn missing(&self) -> &'static str {
        match (self.has_systemd, self.has_dbus) {
            (false, false) => "systemd and dbus",
            (true, false) => "dbus",
            (false, true) => "systemd",
            (true, true) => "nothing",
        }
    }
}

/// Detect systemd and dbus presence inside a rootfs.
fn detect_systemd_presence(rootfs: &Path) -> SystemdPresence {
    let has_systemd = [
        "usr/bin/systemd",
        "usr/lib/systemd/systemd",
        "lib/systemd/systemd",
    ]
    .iter()
    .any(|p| rootfs.join(p).exists())
        || detect_systemd_nixos(rootfs);

    let has_dbus = [
        "usr/bin/dbus-daemon",
        "usr/bin/dbus-broker",
        "usr/lib/dbus-1/dbus-daemon-launch-helper",
        "usr/lib/dbus-daemon-launch-helper",
    ]
    .iter()
    .any(|p| rootfs.join(p).exists())
        || detect_dbus_nixos(rootfs);

    SystemdPresence {
        has_systemd,
        has_dbus,
    }
}

/// Check for systemd in NixOS-specific paths.
///
/// After a nix-build, `/sbin/init` is symlinked to the NixOS toplevel init
/// in the nix store. This is the most reliable indicator that systemd is
/// present because the NixOS system closure always includes systemd.
/// Falls back to scanning the nix store for `lib/systemd/systemd` (the
/// standard NixOS path) or `bin/systemd`.
fn detect_systemd_nixos(rootfs: &Path) -> bool {
    // Booted NixOS system profile.
    if rootfs.join("run/current-system/sw/bin/systemd").exists() {
        return true;
    }
    // /sbin/init created by nix-build; follows symlink into nix store.
    for init in &["sbin/init", "usr/sbin/init"] {
        let p = rootfs.join(init);
        if p.exists() || p.is_symlink() {
            return true;
        }
    }
    scan_nix_store(rootfs, "lib/systemd/systemd") || scan_nix_store(rootfs, "bin/systemd")
}

/// Check for dbus in NixOS-specific paths.
///
/// NixOS system closures with `services.dbus.enable = true` always include
/// dbus. Checks the booted profile first, then scans the nix store.
fn detect_dbus_nixos(rootfs: &Path) -> bool {
    if rootfs
        .join("run/current-system/sw/bin/dbus-daemon")
        .exists()
    {
        return true;
    }
    scan_nix_store(rootfs, "bin/dbus-daemon") || scan_nix_store(rootfs, "bin/dbus-broker")
}

/// Scan the nix store for a binary matching the given suffix.
pub(crate) fn scan_nix_store(rootfs: &Path, suffix: &str) -> bool {
    let store = rootfs.join("nix/store");
    if let Ok(entries) = fs::read_dir(&store) {
        for entry in entries.flatten() {
            if entry.path().join(suffix).exists() {
                return true;
            }
        }
    }
    false
}

/// Collect proxy-related environment variables for forwarding to chroot commands.
///
/// Returns all set, non-empty proxy variables. These are explicitly passed to
/// chroot commands so that package managers (apt-get, dnf) can reach
/// repositories through a proxy.
fn proxy_env_vars() -> Vec<(String, String)> {
    let names = [
        "https_proxy",
        "HTTPS_PROXY",
        "http_proxy",
        "HTTP_PROXY",
        "all_proxy",
        "ALL_PROXY",
        "no_proxy",
        "NO_PROXY",
    ];
    names
        .iter()
        .filter_map(|&name| {
            std::env::var(name)
                .ok()
                .filter(|v| !v.is_empty())
                .map(|val| (name.to_string(), val))
        })
        .collect()
}

/// RAII guard for bind mounts into a chroot environment.
///
/// Manages `/proc`, `/sys`, `/dev`, `/dev/pts` bind mounts and
/// `/etc/resolv.conf` for DNS resolution during package installation.
pub(crate) struct ChrootGuard {
    rootfs: PathBuf,
    mounts: Vec<PathBuf>,
    resolv_backup: Option<PathBuf>,
}

impl ChrootGuard {
    /// Set up bind mounts and resolv.conf for chroot package installation.
    pub(crate) fn setup(rootfs: &Path, verbose: bool) -> Result<Self> {
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
            crate::check_interrupted()?;
            if !status.success() {
                bail!(
                    "bind mount failed: {} -> {}",
                    source.display(),
                    mount_point.display()
                );
            }
            // Prevent mount events inside the chroot from propagating back
            // to the host. Without this, package managers that trigger udev
            // or systemd inside the chroot can remount the host's /dev.
            let status = Command::new("mount")
                .args(["--make-rslave"])
                .arg(&mount_point)
                .status()
                .with_context(|| format!("failed to make rslave: {}", mount_point.display()))?;
            crate::check_interrupted()?;
            if !status.success() {
                bail!("make-rslave failed: {}", mount_point.display());
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
        crate::check_interrupted()?;
        if !status.success() {
            bail!("bind mount failed: /dev/pts -> {}", devpts.display());
        }
        let status = Command::new("mount")
            .args(["--make-rslave"])
            .arg(&devpts)
            .status()
            .context("failed to make rslave: /dev/pts")?;
        crate::check_interrupted()?;
        if !status.success() {
            bail!("make-rslave failed: {}", devpts.display());
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

        if verbose {
            match fs::read_to_string("/etc/resolv.conf") {
                Ok(content) => {
                    eprintln!("chroot: host /etc/resolv.conf:");
                    for line in content.lines() {
                        if line.starts_with("nameserver") || line.starts_with("search") {
                            eprintln!("  {line}");
                        }
                    }
                }
                Err(e) => eprintln!("chroot: could not read host /etc/resolv.conf: {e}"),
            }
        }

        Ok(guard)
    }

    pub(crate) fn cleanup(&mut self) {
        // Unmount in reverse order. Use -R (recursive) because package
        // managers inside the chroot may create submounts (e.g. /dev/shm,
        // /dev/mqueue) that prevent a plain umount from succeeding.
        for mount_point in self.mounts.drain(..).rev() {
            match Command::new("umount").arg("-R").arg(&mount_point).status() {
                Ok(s) if !s.success() => {
                    eprintln!("warning: failed to unmount {}", mount_point.display());
                }
                Err(e) => {
                    eprintln!("warning: failed to unmount {}: {e}", mount_point.display());
                }
                _ => {}
            }
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

/// Run a sequence of shell commands inside a rootfs via chroot.
///
/// Each command is executed as `/bin/sh -c <cmd>` inside the rootfs. Proxy
/// environment variables are logged when verbose. The parent environment is
/// inherited by the chroot process, so proxy vars set in the parent are
/// automatically available to package managers (apt-get, dnf).
/// The function checks for interrupts between commands and bails on failure.
pub(crate) fn run_chroot_commands(rootfs: &Path, commands: &[String], verbose: bool) -> Result<()> {
    if verbose {
        let proxy_vars = proxy_env_vars();
        if proxy_vars.is_empty() {
            eprintln!("chroot: no proxy environment variables set");
        } else {
            eprintln!("chroot: proxy environment:");
            for (k, v) in &proxy_vars {
                let display = if k == "no_proxy" || k == "NO_PROXY" {
                    v.clone()
                } else {
                    redact_proxy_credentials(v)
                };
                eprintln!("  {k}={display}");
            }
        }
    }

    for cmd_str in commands {
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
            bail!(
                "chroot command failed (exit {}): {cmd_str}",
                status.code().unwrap_or(-1)
            );
        }
    }
    Ok(())
}

/// Apt option to disable the privilege-dropping sandbox.
///
/// By default apt drops privileges to the `_apt` user for network operations.
/// In a chroot the sandboxed user may lack network access (e.g. on IPv6-only
/// networks where the `_apt` user cannot reach the proxy). Since we are
/// already running as root in a throwaway chroot, disabling the sandbox is safe.
pub(crate) const APT_NO_SANDBOX: &str = r#"-o APT::Sandbox::User="""#;

/// Embedded NixOS container configuration for nix-build imports.
///
/// Produces a bootable NixOS system closure with systemd, dbus, and a minimal
/// set of tools. Supports an optional user config via NixOS `imports`.
///
/// **Limitation**: `networkd` is enabled but `resolved` is disabled by default.
/// Containers using `--network-veth` or `--network-bridge` get DHCP via networkd
/// and work out of the box. However, `--network-zone` also needs resolved for
/// LLMNR/mDNS inter-container name resolution. To enable it, pass a
/// `--nix-config` file containing `{ services.resolved.enable = true; }`.
const DEFAULT_NIXOS_CONFIG: &str = r#"{ pkgs ? import <nixpkgs> {} }:
let
  userConfig = /tmp/sdme-nixos-extra.nix;
  hasUserConfig = builtins.pathExists userConfig;
  nixos = import "${pkgs.path}/nixos" {
    configuration = { config, lib, pkgs, ... }: {
      imports = lib.optionals hasUserConfig [ userConfig ];
      boot.isContainer = true;
      services.dbus.enable = true;
      users.users.root.initialHashedPassword = "";
      networking.useNetworkd = true;
      environment.systemPackages = with pkgs; [
        bashInteractive coreutils util-linux iproute2
        less procps findutils gnugrep gnused curl
      ];
      fileSystems."/" = { device = "none"; fsType = "tmpfs"; };
      boot.loader.grub.enable = false;
      services.resolved.enable = false;
      services.getty.autologinUser = "root";
      # Disable pam_lastlog2 for machinectl shell (container-shell PAM service)
      # and login: the module has linkage issues in nspawn containers.
      security.pam.services.login.rules.session.lastlog.enable = lib.mkForce false;
      security.pam.services.container-shell.rules.session.lastlog.enable = lib.mkForce false;
      system.stateVersion = lib.trivial.release;
      nix.nixPath = [ "nixpkgs=${pkgs.path}" ];
    };
  };
in nixos.config.system.build.toplevel
"#;

/// Built-in import prehook commands for each distro family.
///
/// These install systemd, dbus, pam/login, set timezone, and clean cache.
/// Package managers are idempotent, so re-running when some packages are
/// already present is safe.
pub fn builtin_import_prehook(family: &DistroFamily) -> Vec<String> {
    let s = APT_NO_SANDBOX;
    match family {
        DistroFamily::Debian => vec![
            format!("apt-get {s} update"),
            format!("DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC apt-get {s} -y install tzdata"),
            format!("apt-get {s} install -y dbus systemd systemd-resolved login"),
            "apt-get autoremove -y -f".into(),
            "apt-get clean".into(),
            "rm -rf /var/lib/apt/lists/*".into(),
        ],
        DistroFamily::Fedora => vec![
            "dnf install -y systemd dbus util-linux pam".into(),
            "dnf clean all".into(),
        ],
        DistroFamily::Arch => vec![
            "pacman -Sy --noconfirm systemd dbus util-linux pam".into(),
            "pacman -Scc --noconfirm".into(),
        ],
        DistroFamily::Suse => vec![
            "zypper --non-interactive install systemd dbus-1 util-linux pam libcap-progs".into(),
            "zypper clean --all".into(),
            "setcap -r /usr/bin/newuidmap 2>/dev/null || true".into(),
            "setcap -r /usr/bin/newgidmap 2>/dev/null || true".into(),
        ],
        _ => vec![],
    }
}

/// Built-in Nix import commands (not configurable via hooks).
fn builtin_nix_commands(nixpkgs_channel: &str) -> Vec<String> {
    let channel = if nixpkgs_channel.is_empty() {
        "nixos-unstable"
    } else {
        nixpkgs_channel
    };
    vec![format!(
        "export PATH=/root/.nix-profile/bin:/nix/var/nix/profiles/default/bin:$PATH && \
         export NIX_REMOTE= && \
         export NIX_PATH='nixpkgs=https://github.com/NixOS/nixpkgs/archive/refs/heads/{channel}.tar.gz' && \
         TOPLEVEL=$(nix-build /tmp/sdme-nixos.nix --no-out-link --option sandbox false --option filter-syscalls false) && \
         mkdir -p /sbin && \
         ln -sf \"$TOPLEVEL/init\" /sbin/init && \
         nix-store -qR \"$TOPLEVEL\" > /tmp/sdme-nix-closure.txt"
    )]
}

/// Resolve import prehook commands: config override → built-in default.
///
/// Nix stays hardcoded (nix-build flow, not configurable via hooks).
fn resolve_import_prehook(
    family: &DistroFamily,
    distros: &HashMap<String, DistroCommands>,
    nixpkgs_channel: &str,
) -> Vec<String> {
    if *family == DistroFamily::Nix {
        return builtin_nix_commands(nixpkgs_channel);
    }
    if let Some(cfg) = distros.get(family.config_key()) {
        if let Some(cmds) = &cfg.import_prehook {
            return cmds.clone();
        }
    }
    builtin_import_prehook(family)
}

/// Install systemd packages into a rootfs via chroot.
fn install_systemd_packages(
    rootfs: &Path,
    family: &DistroFamily,
    nixpkgs_channel: &str,
    nix_config: Option<&Path>,
    nix_config_template: &str,
    distros: &HashMap<String, DistroCommands>,
    verbose: bool,
) -> Result<()> {
    let commands = resolve_import_prehook(family, distros, nixpkgs_channel);
    if commands.is_empty() {
        bail!(
            "no package installation commands available for distro family {:?}",
            family
        );
    }

    // For Nix family: write NixOS configuration and optional user config
    // into the rootfs before entering the chroot.
    if *family == DistroFamily::Nix {
        let tmp_dir = rootfs.join("tmp");
        fs::create_dir_all(&tmp_dir)
            .with_context(|| format!("failed to create {}", tmp_dir.display()))?;
        if nix_config_template.is_empty() {
            fs::write(tmp_dir.join("sdme-nixos.nix"), DEFAULT_NIXOS_CONFIG)
                .context("failed to write embedded sdme-nixos.nix")?;
        } else {
            fs::copy(nix_config_template, tmp_dir.join("sdme-nixos.nix")).with_context(|| {
                format!(
                    "failed to copy nix config template from {}",
                    nix_config_template
                )
            })?;
        }
        if let Some(config_path) = nix_config {
            fs::copy(config_path, tmp_dir.join("sdme-nixos-extra.nix")).with_context(|| {
                format!("failed to copy nix config from {}", config_path.display())
            })?;
        }
        if verbose {
            let source = if nix_config_template.is_empty() {
                "embedded"
            } else {
                nix_config_template
            };
            eprintln!(
                "wrote nix build config ({source}) to {}/tmp/sdme-nixos.nix",
                rootfs.display()
            );
        }
    }

    if verbose {
        eprintln!("setting up chroot environment for package installation");
    }

    let mut chroot_guard = ChrootGuard::setup(rootfs, verbose)?;
    let result = run_chroot_commands(rootfs, &commands, verbose);
    chroot_guard.cleanup();
    result?;

    // For Nix family: rebuild rootfs from the NixOS closure only,
    // discarding leftover non-NixOS files from the OCI base image.
    if *family == DistroFamily::Nix {
        rebuild_nix_rootfs(rootfs, verbose)?;
    }

    Ok(())
}

/// Rebuild a rootfs from the NixOS closure, discarding everything else.
///
/// After `nix-build` produces a NixOS system closure inside the OCI base image
/// (e.g. `docker.io/nixos/nix` which is Alpine-based), the rootfs contains both
/// the NixOS closure in `/nix/store` and the leftover base image files. The
/// leftover files interfere with NixOS boot/activation.
///
/// This function reads the closure list written by the chroot step, creates a
/// clean rootfs with only the NixOS store paths and skeleton directories, then
/// atomically replaces the old rootfs.
fn rebuild_nix_rootfs(rootfs: &Path, verbose: bool) -> Result<()> {
    if verbose {
        eprintln!("rebuilding rootfs from NixOS closure");
    }

    // Read the closure list written by the chroot nix-build step.
    let closure_file = rootfs.join("tmp/sdme-nix-closure.txt");
    let closure_text = fs::read_to_string(&closure_file)
        .with_context(|| format!("failed to read {}", closure_file.display()))?;
    let store_paths: Vec<&str> = closure_text.lines().filter(|l| !l.is_empty()).collect();
    if store_paths.is_empty() {
        bail!("nix closure list is empty");
    }

    // Read the /sbin/init symlink to get the TOPLEVEL path.
    let init_link = rootfs.join("sbin/init");
    let toplevel_init = fs::read_link(&init_link)
        .with_context(|| format!("failed to read symlink {}", init_link.display()))?;

    if verbose {
        eprintln!(
            "  {} store paths, toplevel init: {}",
            store_paths.len(),
            toplevel_init.display()
        );
    }

    // Create a clean rootfs directory alongside the current one.
    let clean_dir = rootfs.with_extension("rebuilding");
    if clean_dir.exists() {
        crate::copy::safe_remove_dir(&clean_dir)?;
    }

    // Create skeleton directories.
    for dir in &[
        "nix/store",
        "bin",
        "sbin",
        "etc",
        "root",
        "run",
        "tmp",
        "var/log",
        "var/lib",
        "proc",
        "sys",
        "dev",
    ] {
        fs::create_dir_all(clean_dir.join(dir))
            .with_context(|| format!("failed to create skeleton dir {}", dir))?;
    }

    // Move each closure store path from old rootfs to clean rootfs.
    for store_path in &store_paths {
        // store_path is absolute, e.g. "/nix/store/abc-foo"
        let rel = store_path.strip_prefix('/').unwrap_or(store_path);
        let src = rootfs.join(rel);
        let dst = clean_dir.join(rel);
        if src.exists() {
            fs::rename(&src, &dst).with_context(|| {
                format!("failed to move {} to {}", src.display(), dst.display())
            })?;
        } else if verbose {
            eprintln!("  warning: store path not found: {}", src.display());
        }
    }

    // Create /sbin/init symlink.
    std::os::unix::fs::symlink(&toplevel_init, clean_dir.join("sbin/init"))
        .context("failed to create /sbin/init symlink")?;

    // Set /tmp permissions.
    fs::set_permissions(
        clean_dir.join("tmp"),
        std::os::unix::fs::PermissionsExt::from_mode(0o1777),
    )
    .context("failed to chmod /tmp")?;

    // Write os-release so sdme detects the rootfs as NixOS.
    fs::write(
        clean_dir.join("etc/os-release"),
        "NAME=\"NixOS\"\nID=nixos\nPRETTY_NAME=\"NixOS (sdme)\"\n",
    )
    .context("failed to write os-release")?;

    // Replace old rootfs with clean one.
    if verbose {
        eprintln!("replacing old rootfs with clean NixOS rootfs");
    }
    crate::copy::safe_remove_dir(rootfs)?;
    fs::rename(&clean_dir, rootfs).with_context(|| {
        format!(
            "failed to rename {} to {}",
            clean_dir.display(),
            rootfs.display()
        )
    })?;

    if verbose {
        eprintln!("NixOS rootfs rebuild complete");
    }

    Ok(())
}

/// Patch systemd services in an imported rootfs for nspawn compatibility.
///
/// - Masks systemd-resolved: when containers share the host's network namespace,
///   the container's resolved cannot bind 127.0.0.53. Masking it makes NSS fall
///   through to the "dns" module, which reads /etc/resolv.conf.
///
/// - Unmasks systemd-logind: some OCI images (CentOS, AlmaLinux) mask logind
///   because Docker/Podman don't need it. sdme requires logind for machinectl
///   shell (join/exec).
///
/// - Installs missing packages required by machinectl shell: some minimal OCI
///   images lack /etc/pam.d/login (needed for PAM session setup). Runs the
///   import prehook (which includes pam/login packages) since package managers
///   are idempotent.
fn patch_rootfs_services(
    rootfs: &Path,
    family: &DistroFamily,
    distros: &HashMap<String, DistroCommands>,
    verbose: bool,
) -> Result<()> {
    let unit_dir = rootfs.join("etc/systemd/system");
    fs::create_dir_all(&unit_dir)
        .with_context(|| format!("failed to create {}", unit_dir.display()))?;

    // Masking of systemd-resolved is handled at container create time
    // (see containers.rs) rather than at import time. This allows per-container
    // control via --masked-services and automatic unmasking for --network-zone.
    // Remove any pre-existing mask (e.g. from package postinst scripts during
    // chroot installation) so it doesn't leak through overlayfs and interfere
    // with zone containers that need resolved for inter-container DNS.
    let resolved = unit_dir.join("systemd-resolved.service");
    if let Ok(target) = fs::read_link(&resolved) {
        if target == Path::new("/dev/null") {
            fs::remove_file(&resolved).with_context(|| {
                format!("failed to remove resolved mask at {}", resolved.display())
            })?;
            if verbose {
                eprintln!("removed pre-existing systemd-resolved mask from rootfs");
            }
        }
    }

    // Unmask systemd-logind if it points to /dev/null.
    let logind = unit_dir.join("systemd-logind.service");
    if let Ok(target) = fs::read_link(&logind) {
        if target == Path::new("/dev/null") {
            fs::remove_file(&logind)
                .with_context(|| format!("failed to remove logind mask at {}", logind.display()))?;
            if verbose {
                eprintln!("unmasked systemd-logind in rootfs");
            }
        }
    }

    // Ensure /etc/pam.d/login exists (required by machinectl shell).
    // Run the import prehook which now includes pam/login packages.
    // Package managers are idempotent so re-installing is safe.
    let pam_login = rootfs.join("etc/pam.d/login");
    if !pam_login.exists() {
        let commands = resolve_import_prehook(family, distros, "");
        if !commands.is_empty() {
            eprintln!("installing packages for machinectl shell support");
            let mut chroot_guard = ChrootGuard::setup(rootfs, verbose)?;
            let result = run_chroot_commands(rootfs, &commands, verbose);
            chroot_guard.cleanup();
            result?;
        } else if verbose {
            eprintln!(
                "warning: /etc/pam.d/login missing but no fix commands for {:?}",
                family
            );
        }
    }

    Ok(())
}

/// Prompt the user interactively to install systemd packages.
///
/// Returns `Ok(true)` if the user accepts, `Ok(false)` if declined,
/// or `Err` if interrupted by a signal.
fn prompt_install_systemd(
    presence: &SystemdPresence,
    family: &DistroFamily,
    distro_name: &str,
    nixpkgs_channel: &str,
    distros: &HashMap<String, DistroCommands>,
) -> Result<bool> {
    let commands = resolve_import_prehook(family, distros, nixpkgs_channel);
    let missing = presence.missing();
    eprintln!("warning: {missing} not found in rootfs (detected: {distro_name})");
    eprintln!("Install packages via chroot? The following commands will run:");
    for cmd in &commands {
        eprintln!("  {cmd}");
    }
    crate::confirm_default_yes("\nProceed? [Y/n]: ")
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
pub fn run(datadir: &Path, opts: &ImportOptions) -> Result<()> {
    let ImportOptions {
        source,
        name,
        verbose,
        force,
        interactive,
        install_packages,
        oci_mode,
        base_fs,
        docker_credentials,
        cache,
        ref http,
        nix_config,
        nix_config_template,
        nixpkgs_channel,
        auto_gc,
        distros,
    } = *opts;

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
        crate::copy::safe_remove_dir(&final_dir)?;
        let meta_path = rootfs_dir.join(format!(".{name}.meta"));
        let _ = fs::remove_file(meta_path);
        let env_path = rootfs_dir.join(format!(".{name}.env"));
        let _ = fs::remove_file(env_path);
    }

    fs::create_dir_all(&rootfs_dir)
        .with_context(|| format!("failed to create {}", rootfs_dir.display()))?;

    let mut txn = crate::txn::Txn::new(
        &rootfs_dir,
        name,
        crate::txn::TxnKind::Import,
        auto_gc,
        verbose,
    );
    txn.prepare()?;
    let staging_dir = txn.path().to_path_buf();

    let mut oci_config = None;
    let result = match kind {
        SourceKind::Directory(ref path) => dir::do_import(path, &staging_dir, verbose),
        SourceKind::Tarball(ref path) => tar::import_tarball(path, &staging_dir, verbose),
        SourceKind::QcowImage(ref path) => img::import_qcow2(path, &staging_dir, verbose),
        SourceKind::RawImage(ref path) => img::import_raw(path, &staging_dir, verbose),
        SourceKind::Url(ref url) => import_url(url, &staging_dir, &rootfs_dir, name, verbose, http),
        SourceKind::RegistryImage(ref img) => {
            match crate::oci::registry::import_registry_image(
                img,
                &staging_dir,
                docker_credentials,
                cache,
                verbose,
                http,
            ) {
                Ok(config) => {
                    oci_config = config;
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
    };

    result?;

    // --- OCI application image handling ---
    // If this was a registry pull, check if it's an application image.
    let skip_systemd_check = if let Some(ref cc) = oci_config {
        let is_base = match oci_mode {
            OciMode::Base => true,
            OciMode::App => false,
            OciMode::Auto => cc.is_base_os_image(),
        };

        eprintln!(
            "OCI image: {}",
            if is_base { "base OS" } else { "application" }
        );
        if oci_mode == OciMode::Auto {
            eprintln!("  (auto-detected; override with --oci-mode=base or --oci-mode=app)");
        }

        if is_base {
            if base_fs.is_some() && verbose {
                eprintln!("note: --base-fs ignored for base OS image");
            }
            false
        } else {
            match base_fs {
                Some(base_name) => {
                    let app_name = crate::oci::derive_app_name(source, name);
                    let setup_result = crate::oci::app::setup_app_image(
                        datadir,
                        &staging_dir,
                        &crate::oci::app::AppImageOptions {
                            rootfs_dir: &rootfs_dir,
                            name,
                            base_name,
                            app_name: &app_name,
                            config: cc,
                            image_ref: source,
                            verbose,
                        },
                    );
                    setup_result?;
                    true // skip systemd detection; base already has it
                }
                None => {
                    if force {
                        eprintln!(
                            "warning: image appears to be an application container; \
                             importing raw rootfs (forced)"
                        );
                        false
                    } else {
                        let ep_str = cc
                            .entrypoint
                            .as_ref()
                            .map(|v| shell_join(v))
                            .unwrap_or_else(|| "(none)".to_string());
                        let cmd_str = cc
                            .cmd
                            .as_ref()
                            .map(|v| shell_join(v))
                            .unwrap_or_else(|| "(none)".to_string());
                        bail!(
                            "image appears to be an application container \
                             (Entrypoint: {ep_str}, Cmd: {cmd_str}); \
                             specify --base-fs=<rootfs> to use a systemd-capable base, \
                             set a default with: sdme config set default_base_fs <rootfs>, \
                             or -f to import the raw rootfs"
                        );
                    }
                }
            }
        }
    } else {
        if oci_mode != OciMode::Auto && verbose {
            eprintln!("note: --oci-mode ignored for non-registry source");
        }
        false
    };

    // --- Systemd detection and optional package installation ---
    // At this point, staging_dir contains the imported rootfs.

    let family = crate::rootfs::detect_distro_family(&staging_dir);
    let distro_name = crate::rootfs::detect_distro(&staging_dir);

    if verbose {
        eprintln!(
            "detected distro: {} (family: {:?})",
            if distro_name.is_empty() {
                "unknown"
            } else {
                &distro_name
            },
            family,
        );
    }

    let mut presence = detect_systemd_presence(&staging_dir);

    if verbose {
        eprintln!(
            "systemd components: systemd={}, dbus={}",
            if presence.has_systemd {
                "found"
            } else {
                "missing"
            },
            if presence.has_dbus {
                "found"
            } else {
                "missing"
            },
        );
    }

    if !skip_systemd_check && !presence.is_bootable() {
        let missing = presence.missing();
        let install_result = (|| -> Result<()> {
            match install_packages {
                InstallPackages::Yes => {
                    if family == DistroFamily::Unknown {
                        if force {
                            eprintln!(
                                "warning: {missing} not found in rootfs; \
                                 importing anyway (forced)",
                            );
                            return Ok(());
                        }
                        bail!(
                            "{missing} not found and cannot install packages for {:?} distro",
                            family
                        );
                    }
                    install_systemd_packages(
                        &staging_dir,
                        &family,
                        nixpkgs_channel,
                        nix_config,
                        nix_config_template,
                        distros,
                        verbose,
                    )?;
                }
                InstallPackages::Auto => {
                    if family == DistroFamily::Unknown {
                        if force {
                            eprintln!(
                                "warning: {missing} not found in rootfs; \
                                 importing anyway (forced)"
                            );
                            return Ok(());
                        }
                        bail!(
                            "{missing} not found in rootfs and distro family is {:?}; \
                             cannot install packages automatically\n\
                             re-run with -f to import anyway",
                            family
                        );
                    }
                    if interactive {
                        if prompt_install_systemd(
                            &presence,
                            &family,
                            &distro_name,
                            nixpkgs_channel,
                            distros,
                        )? {
                            install_systemd_packages(
                                &staging_dir,
                                &family,
                                nixpkgs_channel,
                                nix_config,
                                nix_config_template,
                                distros,
                                verbose,
                            )?;
                        } else {
                            bail!("{missing} not found in rootfs; import aborted by user");
                        }
                    } else if force {
                        eprintln!(
                            "warning: {missing} not found in rootfs; \
                             importing anyway (forced)"
                        );
                        return Ok(());
                    } else {
                        bail!(
                            "{missing} not found in rootfs and running non-interactively; \
                             re-run with --install-packages=yes or -f to override"
                        );
                    }
                }
                InstallPackages::No => {
                    if force {
                        eprintln!(
                            "warning: {missing} not found in rootfs; importing anyway (forced)"
                        );
                        return Ok(());
                    }
                    bail!(
                        "{missing} not found in rootfs; \
                         re-run with --install-packages=yes or -f to override"
                    );
                }
            }
            Ok(())
        })();

        install_result?;

        // Re-scan after installation.
        presence = detect_systemd_presence(&staging_dir);
        if !presence.is_bootable() && !force {
            bail!(
                "{} still not found after package installation",
                presence.missing()
            );
        }
    }

    // Patch systemd services for nspawn compatibility (mask resolved,
    // unmask logind, install missing machinectl shell dependencies).
    // Skip for NixOS (Nix-built) rootfs: NixOS manages /etc via activation
    // and the config already disables resolved.
    if !skip_systemd_check && presence.has_systemd && family != DistroFamily::Nix {
        if let Err(e) = patch_rootfs_services(&staging_dir, &family, distros, verbose) {
            eprintln!("warning: rootfs service patching failed: {e}");
        }
    }

    // --- Atomic rename to final location ---

    txn.commit(&final_dir)?;

    // Write distro and OCI config metadata sidecar.
    let distro = crate::rootfs::detect_distro(&final_dir);
    let mut meta = State::new();
    meta.set("DISTRO", &distro);

    if let Some(ref cc) = oci_config {
        if let Some(ref ep) = cc.entrypoint {
            if !ep.is_empty() {
                meta.set("OCI_ENTRYPOINT", shell_join(ep));
            }
        }
        if let Some(ref cmd) = cc.cmd {
            if !cmd.is_empty() {
                meta.set("OCI_CMD", shell_join(cmd));
            }
        }
        if let Some(ref wd) = cc.working_dir {
            if !wd.is_empty() {
                meta.set("OCI_WORKDIR", wd);
            }
        }
        if let Some(ref user) = cc.user {
            if !user.is_empty() {
                meta.set("OCI_USER", user);
            }
        }
        if let Some(ref env) = cc.env {
            if !env.is_empty() {
                // Store env vars as newline-separated KEY=VALUE pairs.
                // The State format uses first `=` as delimiter, so multi-line
                // values aren't directly supported. Use a separate file.
                let env_path = rootfs_dir.join(format!(".{name}.env"));
                let content = env.join("\n") + "\n";
                crate::atomic_write(&env_path, content.as_bytes())
                    .with_context(|| format!("failed to write {}", env_path.display()))?;
            }
        }
        if let Some(ref ports) = cc.exposed_ports {
            if !ports.is_empty() {
                meta.set("OCI_PORTS", crate::oci::sorted_keys_joined(ports, ","));
            }
        }
        if let Some(ref vols) = cc.volumes {
            if !vols.is_empty() {
                meta.set("OCI_VOLUMES", crate::oci::sorted_keys_joined(vols, ","));
            }
        }
        if let Some(ref sig) = cc.stop_signal {
            if !sig.is_empty() {
                meta.set("OCI_STOP_SIGNAL", sig);
            }
        }
    }

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
        let cfg = crate::config::Config {
            oci_cache_max_size: "0".to_string(),
            ..crate::config::Config::default()
        };
        let cache = crate::oci::cache::BlobCache::from_config(&cfg).unwrap();
        run(
            datadir,
            &ImportOptions {
                source,
                name,
                verbose,
                force,
                interactive: false,
                install_packages: InstallPackages::No,
                oci_mode: OciMode::Auto,
                base_fs: None,
                docker_credentials: None,
                cache: &cache,
                http: crate::config::HttpConfig {
                    connect_timeout: cfg.http_timeout,
                    body_timeout: cfg.http_body_timeout,
                    max_download_size: 0,
                },
                nix_config: None,
                nix_config_template: "",
                nixpkgs_channel: "",
                auto_gc: true,
                distros: &HashMap::new(),
            },
        )
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
    fn test_derive_app_name_registry() {
        assert_eq!(
            crate::oci::derive_app_name("docker.io/nginx:latest", "fallback"),
            "nginx"
        );
        assert_eq!(
            crate::oci::derive_app_name("docker.io/oliver006/redis_exporter:latest", "fb"),
            "redis-exporter"
        );
        assert_eq!(
            crate::oci::derive_app_name("quay.io/centos/centos:stream10", "fb"),
            "centos"
        );
    }

    #[test]
    fn test_derive_app_name_non_registry() {
        assert_eq!(crate::oci::derive_app_name("/path/to/dir", "myfs"), "myfs");
        assert_eq!(
            crate::oci::derive_app_name("some-tarball.tar.gz", "myfs"),
            "myfs"
        );
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

        test_run(tmp.path(), src.path().to_str().unwrap(), "sym", false, true).unwrap();

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

        test_run(tmp.path(), src.path().to_str().unwrap(), "dup", false, true).unwrap();
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

        let err =
            test_run(tmp.path(), missing.to_str().unwrap(), "test", false, false).unwrap_err();
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
            libc::utimensat(libc::AT_FDCWD, c_path.as_ptr(), times.as_ptr(), 0);
        }

        test_run(tmp.path(), src.path().to_str().unwrap(), "ts", false, true).unwrap();

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

        test_run(tmp.path(), src.path().to_str().unwrap(), "dev", false, true).unwrap();

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

        test_run(tmp.path(), src.path().to_str().unwrap(), "own", false, true).unwrap();

        let dst_stat = lstat_entry(&tmp.path().join("fs/own/owned.txt")).unwrap();
        assert_eq!(dst_stat.st_uid, 1000);
        assert_eq!(dst_stat.st_gid, 1000);
    }

    // --- Interrupt tests ---

    #[test]
    fn test_check_interrupted() {
        let _lock = INTERRUPT_LOCK.lock().unwrap();

        // Not interrupted; should be Ok.
        assert!(crate::check_interrupted().is_ok());

        // Set interrupted; should bail.
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
        assert_eq!(
            detect_kind_from_content_type("application/octet-stream"),
            None
        );
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
        assert_eq!(detect_kind_from_url("https://example.com/download"), None);
    }

    #[test]
    fn test_detect_kind_from_magic_tarball() {
        let path = std::env::temp_dir().join(format!(
            "sdme-test-magic-tar-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        // Write non-QCOW2 content; should be detected as tarball.
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
        assert_eq!(detect_kind_from_magic(&path), DownloadedFileKind::QcowImage);
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
        assert_eq!(detect_kind_from_magic(&path), DownloadedFileKind::RawImage);
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
        assert_eq!(detect_kind_from_magic(&path), DownloadedFileKind::RawImage);
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

    #[test]
    fn test_import_oci_tarball_with_config() {
        let tmp = tmp();
        let _lock = INTERRUPT_LOCK.lock().unwrap();

        let config_json = serde_json::to_vec(&serde_json::json!({
            "config": {
                "Entrypoint": ["/usr/bin/myapp"],
                "Cmd": ["--serve"],
                "ExposedPorts": {"8080/tcp": {}}
            }
        }))
        .unwrap();

        let tarball = crate::oci::layout::tests::build_oci_tarball_with_config(
            "withcfg",
            &[vec![("app.bin", b"#!/bin/sh\necho hi\n")]],
            &config_json,
        );

        // Import through run(): this goes through the OCI tarball path,
        // not the registry path, so oci_config won't be set. The import
        // should succeed and extract the layer contents.
        let cfg = crate::config::Config {
            oci_cache_max_size: "0".to_string(),
            ..crate::config::Config::default()
        };
        let cache = crate::oci::cache::BlobCache::from_config(&cfg).unwrap();
        run(
            tmp.path(),
            &ImportOptions {
                source: tarball.to_str().unwrap(),
                name: "ocicfg",
                verbose: false,
                force: true,
                interactive: false,
                install_packages: InstallPackages::No,
                oci_mode: OciMode::Auto,
                base_fs: None,
                docker_credentials: None,
                cache: &cache,
                http: crate::config::HttpConfig {
                    connect_timeout: cfg.http_timeout,
                    body_timeout: cfg.http_body_timeout,
                    max_download_size: 0,
                },
                nix_config: None,
                nix_config_template: "",
                nixpkgs_channel: "",
                auto_gc: true,
                distros: &HashMap::new(),
            },
        )
        .unwrap();

        let rootfs = tmp.path().join("fs/ocicfg");
        assert!(rootfs.is_dir());
        assert_eq!(
            fs::read_to_string(rootfs.join("app.bin")).unwrap(),
            "#!/bin/sh\necho hi\n"
        );

        let _ = fs::remove_file(&tarball);
    }
}
