//! Internal API for container filesystem, state, and runtime management.
//!
//! Each container gets an overlayfs directory tree (`upper/work/merged`)
//! under the configured data directory and a KEY=VALUE state file that tracks
//! its metadata. All mutating operations follow a transaction-style pattern:
//! work is performed step-by-step and, on failure, partially-created artifacts
//! are cleaned up before the error is returned. New implementations and changes
//! should conform to this pattern.

mod create;
mod exec;
mod list;
mod manage;

#[cfg(test)]
mod tests;

// Re-export all public items for backwards compatibility.
pub use create::{create, validate_opaque_dirs, CreateOptions};
pub use exec::{exec, exec_oci, join};
pub use list::{list, ContainerInfo, KubeInfo};
pub use manage::{remove, set_limits, stop, StopMode};

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};

use crate::validate_name;

/// Read the current process umask. There is no "get umask" syscall, so
/// we set it to 0, read the old value, and restore it immediately.
pub(super) fn get_umask() -> u32 {
    let old = unsafe { libc::umask(0) };
    unsafe { libc::umask(old) };
    old as u32
}

/// Resolve a rootfs name to its on-disk path; `None` means host rootfs.
// NOTE: "rootfs" is the internal name; the CLI command is "fs" and the
// on-disk path is {datadir}/fs/.
pub fn resolve_rootfs(datadir: &Path, rootfs: Option<&str>) -> Result<PathBuf> {
    match rootfs {
        None => Ok(PathBuf::from("/")),
        Some(name) => {
            validate_name(name).context("invalid rootfs name")?;
            let path = datadir.join("fs").join(name);
            if !path.exists() {
                bail!("fs not found: {}", path.display());
            }
            Ok(path)
        }
    }
}

/// Return the volume storage directory for a container.
pub fn volumes_dir(datadir: &Path, name: &str) -> PathBuf {
    datadir.join("volumes").join(name)
}

/// Resolve a (possibly abbreviated) container name to the full name.
///
/// Exact matches take priority. If `input` is not an exact match, all
/// container names that start with `input` are collected. A single match
/// is returned; zero or multiple matches produce an error.
pub fn resolve_name(datadir: &Path, input: &str) -> Result<String> {
    if input.is_empty() {
        bail!("container name must not be empty");
    }
    let state_dir = datadir.join("state");
    if !state_dir.is_dir() {
        bail!("no container found matching '{input}'");
    }
    let mut names: Vec<String> = Vec::new();
    for entry in fs::read_dir(&state_dir)
        .with_context(|| format!("failed to read {}", state_dir.display()))?
    {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            if let Some(name) = entry.file_name().to_str() {
                names.push(name.to_string());
            }
        }
    }
    // Exact match; return immediately.
    if names.iter().any(|n| n == input) {
        return Ok(input.to_string());
    }
    let mut matches: Vec<&String> = names.iter().filter(|n| n.starts_with(input)).collect();
    match matches.len() {
        0 => bail!("no container found matching '{input}'"),
        1 => Ok(matches.remove(0).clone()),
        _ => {
            matches.sort();
            let list = matches
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            bail!("ambiguous name '{input}', could match: {list}");
        }
    }
}

/// Mount overlayfs on a stopped container's `merged/` directory (read-write).
pub(crate) fn mount_overlay(rootfs_dir: &Path, container_dir: &Path) -> Result<()> {
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
    crate::check_interrupted()?;

    if !status.success() {
        bail!("failed to mount overlayfs");
    }

    // Per-submount overlayfs for host-rootfs containers.
    if rootfs_dir == Path::new("/") {
        mount_submount_overlays(&merged_dir, container_dir, false)?;
    }

    Ok(())
}

/// Mount a read-only overlay view of a container's merged filesystem.
///
/// Uses multi-lower lowerdir (upper:rootfs); no upperdir/workdir needed.
/// The resulting mount is inherently read-only and correctly handles
/// whiteouts and opaque dirs from the upper layer.
pub(crate) fn mount_overlay_ro(rootfs_dir: &Path, container_dir: &Path) -> Result<()> {
    let upper_dir = container_dir.join("upper");
    let merged_dir = container_dir.join("merged");

    let mount_opts = format!("lowerdir={}:{}", upper_dir.display(), rootfs_dir.display());

    let status = std::process::Command::new("mount")
        .args(["-t", "overlay", "overlay", "-o", &mount_opts])
        .arg(&merged_dir)
        .status()
        .context("failed to run mount")?;
    crate::check_interrupted()?;

    if !status.success() {
        bail!("failed to mount read-only overlayfs");
    }

    // Per-submount read-only overlays for host-rootfs containers.
    if rootfs_dir == Path::new("/") {
        mount_submount_overlays(&merged_dir, container_dir, true)?;
    }

    Ok(())
}

/// Mount per-submount overlayfs layers for host-rootfs containers.
///
/// For each real-filesystem submount under `/` (e.g. `/home` on a separate
/// btrfs subvolume), mounts a per-submount overlay on the corresponding
/// path inside `merged/`.
fn mount_submount_overlays(merged_dir: &Path, container_dir: &Path, read_only: bool) -> Result<()> {
    let submounts = crate::submounts::host_submounts()?;
    if submounts.is_empty() {
        return Ok(());
    }
    crate::submounts::ensure_submount_dirs(container_dir, &submounts)?;
    for rel in &submounts {
        let sub_upper = container_dir.join("submounts").join(rel).join("upper");
        let sub_merged = merged_dir.join(rel);
        let sub_opts = if read_only {
            format!("lowerdir={}:/{rel}", sub_upper.display())
        } else {
            let sub_work = container_dir.join("submounts").join(rel).join("work");
            format!(
                "lowerdir=/{rel},upperdir={},workdir={}",
                sub_upper.display(),
                sub_work.display()
            )
        };
        let status = std::process::Command::new("mount")
            .args(["-t", "overlay", "overlay", "-o", &sub_opts])
            .arg(&sub_merged)
            .status();
        match status {
            Ok(s) if !s.success() => {
                eprintln!("warning: failed to mount submount overlay for /{rel}");
            }
            Err(e) => {
                eprintln!("warning: failed to run mount for submount /{rel}: {e}");
            }
            _ => {}
        }
    }
    Ok(())
}

/// RAII guard that unmounts overlayfs on drop.
pub(crate) struct OverlayGuard {
    pub container_dir: PathBuf,
}

impl Drop for OverlayGuard {
    fn drop(&mut self) {
        unmount_overlay(&self.container_dir);
    }
}

/// Unmount overlayfs from a container's `merged/` directory.
///
/// Unmounts any nested submount overlays (deepest-first) before
/// unmounting the root overlay.
pub(crate) fn unmount_overlay(container_dir: &Path) {
    let merged_dir = container_dir.join("merged");
    // Unmount any nested mounts (submount overlays) deepest-first.
    if let Ok(nested) = crate::submounts::find_mounts_under(&merged_dir) {
        for mount_point in &nested {
            let _ = std::process::Command::new("umount")
                .arg(mount_point)
                .status();
        }
    }
    let _ = std::process::Command::new("umount")
        .arg(&merged_dir)
        .status();
}

/// Verify that a container's state file and directory exist.
pub fn ensure_exists(datadir: &Path, name: &str) -> Result<()> {
    let state_file = datadir.join("state").join(name);
    if !state_file.exists() {
        bail!("container does not exist: {name}");
    }
    let container_dir = datadir.join("containers").join(name);
    if !container_dir.exists() {
        bail!("container '{name}' state file exists but directory is missing");
    }
    Ok(())
}

/// Fix directory permissions on containers created before the 0o755 fix.
///
/// Called from `systemd::start()` before writing the env file so that
/// old containers work without requiring manual intervention or recreation.
pub fn ensure_permissions(datadir: &Path, name: &str) -> Result<()> {
    let container_dir = datadir.join("containers").join(name);
    for (sub, mode) in &[("upper", 0o755), ("merged", 0o755)] {
        let dir = container_dir.join(sub);
        if dir.exists() {
            set_dir_permissions(&dir, *mode)?;
        }
    }
    Ok(())
}

pub(super) fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs()
}

pub(super) fn set_dir_permissions(path: &Path, mode: u32) -> Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("failed to set permissions on {}", path.display()))
}
