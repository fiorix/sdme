//! Rootfs export: directory copy, tarball creation, raw disk image.
//!
//! Exports an imported rootfs or a container's merged overlayfs view
//! to a directory, compressed tarball, or bare ext4/btrfs raw disk image.

mod dir;
mod raw;
mod tar;
mod vm;

#[cfg(test)]
mod tests;

pub use vm::{builtin_export_prehook, builtin_export_vm_prehook};

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::config::DistroCommands;
use crate::import::InstallPackages;
use crate::lock;
use crate::txn::{Txn, TxnKind};
use crate::{containers, storage, systemd, validate_name, State};

/// Options for preparing a raw disk image for VM boot.
pub struct VmOptions {
    /// Hostname written to `/etc/hostname` inside the image.
    pub hostname: String,
    /// DNS nameservers for `/etc/resolv.conf`.
    /// `None` = don't touch, `Some(empty)` = copy host's, `Some(values)` = write those.
    pub nameservers: Option<Vec<String>>,
    /// Number of network interfaces to configure via `systemd-networkd`.
    pub net_ifaces: u32,
    /// SHA-512 crypt hash for the root password in `/etc/shadow`.
    pub root_password: Option<String>,
    /// SSH public key installed as root's `authorized_keys`.
    pub ssh_key: Option<String>,
    /// Swap partition size in bytes (`0` = no swap).
    pub swap_size: u64,
    /// Whether to run the VM prehook (distro-specific preparation) via chroot.
    pub install_packages: InstallPackages,
    /// Allow interactive prompts during package installation.
    pub interactive: bool,
    /// Per-distro chroot command overrides from config.
    pub distros: HashMap<String, DistroCommands>,
}

/// Filesystem type for raw disk image export.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum RawFs {
    /// ext4 filesystem (default).
    #[default]
    Ext4,
    /// Btrfs filesystem.
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

/// Grouped options for rootfs/container export.
pub struct ExportOptions<'a> {
    /// Output format (directory, tarball, or raw disk image).
    pub format: &'a ExportFormat,
    /// Explicit image size (overrides auto-calculation when set).
    pub size: Option<&'a str>,
    /// Extra free space added to auto-calculated image size, in bytes.
    pub free_space: u64,
    /// VM-specific options; `None` for non-VM exports.
    pub vm_opts: Option<&'a VmOptions>,
    /// Enable verbose output.
    pub verbose: bool,
    /// Overwrite the output path if it already exists.
    pub force: bool,
    /// Timezone to set in the exported rootfs (e.g. "America/New_York").
    pub timezone: Option<&'a str>,
}

/// Summary returned after a successful export.
#[derive(Debug)]
pub struct ExportResult {
    /// Total size of the output file or directory in bytes.
    pub output_size: u64,
    /// Free space in the image (raw exports only).
    pub free_space: Option<u64>,
    /// Number of partitions (raw exports only; 0 = bare, 1 = GPT with root).
    pub partitions: Option<u32>,
}

impl ExportResult {
    /// Format the result as a human-readable summary line (without the path).
    pub fn summary(&self) -> String {
        let size = format_human_size(self.output_size);
        match (self.free_space, self.partitions) {
            (Some(free), Some(parts)) => {
                let free = format_human_size(free);
                let label = if parts == 1 {
                    "partition"
                } else {
                    "partitions"
                };
                format!("{size}, {free} free, {parts} {label}")
            }
            _ => size,
        }
    }
}

/// Source for an export operation.
pub enum ExportSource {
    /// Export a container's merged overlayfs view.
    Container(String),
    /// Export an imported rootfs from the catalogue.
    Rootfs(String),
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

/// Unified export entry point.
///
/// Handles source validation, flock locking, overlay mounting for stopped
/// containers, timezone validation, and delegation to the format-specific
/// export function.
pub fn export(
    datadir: &Path,
    source: &ExportSource,
    output: &Path,
    opts: &ExportOptions,
    auto_gc: bool,
) -> Result<ExportResult> {
    match source {
        ExportSource::Rootfs(name) => {
            validate_name(name).context("invalid rootfs name")?;
            let rootfs_dir = datadir.join("fs").join(name);
            if !rootfs_dir.is_dir() {
                bail!("rootfs not found: {name}");
            }
            let _lock = lock::lock_shared(datadir, "fs", name)
                .with_context(|| format!("cannot lock rootfs '{name}' for export"))?;
            if let Some(tz) = opts.timezone {
                validate_timezone(&rootfs_dir, tz)?;
            }
            export_from_dir(&rootfs_dir, output, opts)
        }
        ExportSource::Container(name) => {
            validate_name(name)?;
            containers::ensure_exists(datadir, name)?;
            let _lock = lock::lock_shared(datadir, "containers", name)
                .with_context(|| format!("cannot lock container '{name}' for export"))?;

            let container_dir = datadir.join("containers").join(name);
            let merged_dir = container_dir.join("merged");

            // Read the backend up front so both the running and stopped paths
            // can dispatch on it.
            let state_file = datadir.join("state").join(name);
            let state = State::read_from(&state_file)?;
            let backend = storage::Backend::from_state(&state);
            let rootfs_name = state.rootfs();

            let running = systemd::is_active(name)?;

            // btrfs exports directly from the container's subvolume in either
            // state: there is no overlay mount and no stale-mount txn marker to
            // manage, and the subvolume is host-accessible whether or not the
            // container is running. A running export carries the same
            // live-filesystem inconsistency caveat as an overlay merged/ export.
            if backend == storage::Backend::Btrfs {
                if running {
                    eprintln!(
                        "warning: container '{name}' is running; filesystem is live and \
                         consistency is not guaranteed"
                    );
                }
                let root =
                    containers::open_root_ro(datadir, name, backend, Path::new("/"), opts.verbose)?;
                if let Some(tz) = opts.timezone {
                    validate_timezone(root.root(), tz)?;
                }
                return export_from_dir(root.root(), output, opts);
            }

            // Overlay backend.
            if running {
                eprintln!(
                    "warning: container '{name}' is running; filesystem is live and \
                     consistency is not guaranteed"
                );
                if let Some(tz) = opts.timezone {
                    validate_timezone(&merged_dir, tz)?;
                }
                export_from_dir(&merged_dir, output, opts)
            } else {
                let rootfs_dir = containers::resolve_rootfs(
                    datadir,
                    if rootfs_name.is_empty() {
                        None
                    } else {
                        Some(rootfs_name)
                    },
                )?;

                // Lock the rootfs to prevent deletion during export.
                let _rootfs_lock = if !rootfs_name.is_empty() {
                    Some(
                        lock::lock_shared(datadir, "fs", rootfs_name).with_context(|| {
                            format!("cannot lock rootfs '{rootfs_name}' for export")
                        })?,
                    )
                } else {
                    None
                };

                // Create a txn marker so fs gc can detect stale overlay mounts.
                let fs_dir = datadir.join("fs");
                let mut txn = Txn::new(&fs_dir, name, TxnKind::Export, auto_gc, opts.verbose);
                txn.prepare()?;

                // Validate timezone against the lower-layer rootfs before mounting.
                if let Some(tz) = opts.timezone {
                    validate_timezone(&rootfs_dir, tz)?;
                }

                containers::mount_overlay_ro(&rootfs_dir, &container_dir)?;
                let _guard = containers::OverlayGuard {
                    container_dir: container_dir.clone(),
                };

                let result = export_from_dir(&merged_dir, output, opts);
                // OverlayGuard unmounts on drop, then txn staging dir cleaned.
                drop(_guard);
                txn.done();
                result
            }
        }
    }
}

pub(super) fn format_human_size(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    const TIB: u64 = 1024 * GIB;
    if bytes >= TIB {
        format!("{:.1}T", bytes as f64 / TIB as f64)
    } else if bytes >= GIB {
        format!("{:.1}G", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1}M", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1}K", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes}B")
    }
}

/// Detect the export format from the output path extension, with an
/// optional override string.
///
/// # Examples
///
/// ```
/// # use sdme::export::{detect_format, ExportFormat, RawFs};
/// assert_eq!(detect_format("out.tar.gz", None).unwrap(), ExportFormat::TarGz);
/// assert_eq!(detect_format("out.img", None).unwrap(), ExportFormat::Raw(RawFs::Ext4));
/// assert_eq!(detect_format("anything", Some("tar")).unwrap(), ExportFormat::Tar);
/// ```
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

/// Validate timezone string format: no empty, no null bytes, no leading `/`,
/// no `..` path components, no whitespace or control characters.
pub(super) fn validate_timezone_format(tz: &str) -> Result<()> {
    if tz.is_empty() {
        bail!("timezone cannot be empty");
    }
    if tz.contains('\0') {
        bail!("timezone contains null byte");
    }
    if tz.starts_with('/') {
        bail!("timezone must not start with '/'");
    }
    if tz.split('/').any(|c| c == "..") {
        bail!("timezone must not contain '..' components");
    }
    if tz.chars().any(|c| c.is_whitespace() || c.is_control()) {
        bail!("timezone must not contain whitespace or control characters");
    }
    Ok(())
}

/// Validate that the timezone zoneinfo file exists in the given rootfs.
pub(super) fn validate_timezone_in_rootfs(rootfs: &Path, tz: &str) -> Result<()> {
    let zi = rootfs.join("usr/share/zoneinfo").join(tz);
    if !zi.exists() {
        bail!(
            "timezone '{tz}' not found in rootfs (expected {})",
            zi.display()
        );
    }
    Ok(())
}

/// Validate timezone format and existence in the rootfs.
pub(super) fn validate_timezone(rootfs: &Path, tz: &str) -> Result<()> {
    validate_timezone_format(tz)?;
    validate_timezone_in_rootfs(rootfs, tz)
}

/// Write timezone into a writable rootfs directory: symlink `/etc/localtime`
/// and write `/etc/timezone`.
pub(super) fn set_timezone(root: &Path, tz: &str) -> Result<()> {
    let etc = root.join("etc");
    fs::create_dir_all(&etc).with_context(|| format!("failed to create {}", etc.display()))?;

    let localtime = etc.join("localtime");
    // Remove existing file or symlink.
    if localtime.symlink_metadata().is_ok() {
        fs::remove_file(&localtime)
            .with_context(|| format!("failed to remove {}", localtime.display()))?;
    }
    let target = format!("../usr/share/zoneinfo/{tz}");
    std::os::unix::fs::symlink(&target, &localtime)
        .with_context(|| format!("failed to symlink {} -> {}", localtime.display(), target))?;

    let tz_file = etc.join("timezone");
    fs::write(&tz_file, format!("{tz}\n"))
        .with_context(|| format!("failed to write {}", tz_file.display()))?;

    Ok(())
}

/// Export an imported rootfs to the given output path.
pub fn export_rootfs(
    datadir: &Path,
    name: &str,
    output: &Path,
    opts: &ExportOptions,
) -> Result<ExportResult> {
    validate_name(name).context("invalid rootfs name")?;
    let rootfs_dir = datadir.join("fs").join(name);
    if !rootfs_dir.is_dir() {
        bail!("rootfs not found: {name}");
    }
    if let Some(tz) = opts.timezone {
        validate_timezone(&rootfs_dir, tz)?;
    }
    export_from_dir(&rootfs_dir, output, opts)
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
    opts: &ExportOptions,
) -> Result<ExportResult> {
    validate_name(name)?;
    containers::ensure_exists(datadir, name)?;

    let container_dir = datadir.join("containers").join(name);
    let merged_dir = container_dir.join("merged");

    // Read the backend up front so both the running and stopped paths dispatch
    // on it.
    let state_file = datadir.join("state").join(name);
    let state = State::read_from(&state_file)?;
    let backend = storage::Backend::from_state(&state);
    let rootfs_name = state.rootfs();

    let running = systemd::is_active(name)?;

    // btrfs exports directly from the container's subvolume in either state
    // (no overlay mount; the subvolume is host-accessible while running too).
    if backend == storage::Backend::Btrfs {
        if running {
            eprintln!(
                "warning: container '{name}' is running; filesystem is live and \
                 consistency is not guaranteed"
            );
        }
        let root = containers::open_root_ro(datadir, name, backend, Path::new("/"), opts.verbose)?;
        if let Some(tz) = opts.timezone {
            validate_timezone(root.root(), tz)?;
        }
        return export_from_dir(root.root(), output, opts);
    }

    // Overlay backend.
    if running {
        eprintln!(
            "warning: container '{name}' is running; filesystem is live and \
             consistency is not guaranteed"
        );
        if let Some(tz) = opts.timezone {
            validate_timezone(&merged_dir, tz)?;
        }
        export_from_dir(&merged_dir, output, opts)
    } else {
        let rootfs_dir = containers::resolve_rootfs(
            datadir,
            if rootfs_name.is_empty() {
                None
            } else {
                Some(rootfs_name)
            },
        )?;

        // Validate timezone against the lower-layer rootfs before mounting.
        if let Some(tz) = opts.timezone {
            validate_timezone(&rootfs_dir, tz)?;
        }

        containers::mount_overlay_ro(&rootfs_dir, &container_dir)?;
        let result = export_from_dir(&merged_dir, output, opts);
        containers::unmount_overlay(&container_dir);
        result
    }
}

/// Core dispatcher: export from a source directory to the output in the
/// requested format.
fn export_from_dir(src: &Path, output: &Path, opts: &ExportOptions) -> Result<ExportResult> {
    match opts.format {
        ExportFormat::Dir => {
            dir::export_to_dir(src, output, opts.verbose, opts.force)?;
            if let Some(tz) = opts.timezone {
                set_timezone(output, tz)?;
            }
            let output_size = raw::dir_size(output)?;
            Ok(ExportResult {
                output_size,
                free_space: None,
                partitions: None,
            })
        }
        ExportFormat::Tar
        | ExportFormat::TarGz
        | ExportFormat::TarBz2
        | ExportFormat::TarXz
        | ExportFormat::TarZst => {
            tar::export_to_tar(src, output, opts)?;
            let output_size = fs::metadata(output)
                .with_context(|| format!("failed to stat {}", output.display()))?
                .len();
            Ok(ExportResult {
                output_size,
                free_space: None,
                partitions: None,
            })
        }
        ExportFormat::Raw(fs_type) => raw::export_to_raw(src, output, *fs_type, opts),
    }
}
