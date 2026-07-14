//! btrfs storage location: mode detection and the Mode B loopback pool.
//!
//! The btrfs backend keeps base and per-container subvolumes under a single
//! btrfs filesystem. Two host modes are supported:
//!
//! - **Mode A**: the datadir already sits on btrfs. Subvolumes live in
//!   `{datadir}/btrfs/` directly, with no loop device or pool image.
//! - **Mode B**: the datadir is on some other filesystem (ext4, xfs, ...). A
//!   single sparse loopback image `{datadir}/btrfs-pool.img` holds a btrfs
//!   filesystem, mounted at `{datadir}/pool/` via a generated systemd `.mount`
//!   unit. Subvolumes live under that mount point.
//!
//! In both modes [`root`] returns the directory under which `fs/{name}` (base)
//! and `containers/{name}` (per-container) subvolumes are created. That path is
//! deliberately distinct from the overlay bookkeeping tree
//! (`{datadir}/containers/{name}`, `{datadir}/fs/{name}`), so overlay and btrfs
//! containers never collide on disk.

use std::ffi::CString;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::{check_interrupted, system_check};

/// btrfs superblock magic reported by `statfs(2)` `f_type`. See
/// `<linux/magic.h>` `BTRFS_SUPER_MAGIC`.
const BTRFS_SUPER_MAGIC: i64 = 0x9123_683E;

/// Default virtual size of the Mode B pool image. The file is sparse, so this
/// costs almost nothing on disk until containers actually write; the btrfs
/// filesystem can be grown later with [`grow`].
pub const DEFAULT_POOL_SIZE: &str = "20G";

/// Basename of the Mode B loopback pool image under the datadir.
const POOL_IMAGE: &str = "btrfs-pool.img";
/// Mode B mount point (a subdirectory of the datadir).
const POOL_MOUNT_DIR: &str = "pool";
/// Mode A subvolume root directory name under a btrfs datadir.
const BTRFS_SUBDIR: &str = "btrfs";

/// Returns `true` if `path` resides on a btrfs filesystem (Mode A).
pub fn is_btrfs(path: &Path) -> Result<bool> {
    let c = CString::new(path.as_os_str().as_bytes()).context("path contains interior NUL")?;
    // SAFETY: `buf` is written by statfs before we read it; `c` outlives the call.
    let mut buf: libc::statfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statfs(c.as_ptr(), &mut buf) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("statfs {}", path.display()));
    }
    Ok(buf.f_type as i64 == BTRFS_SUPER_MAGIC)
}

/// The Mode B image and mount-point paths for a datadir. Pure path derivation;
/// says nothing about whether the pool exists or is mounted.
fn mode_b_paths(datadir: &Path) -> (PathBuf, PathBuf) {
    (datadir.join(POOL_IMAGE), datadir.join(POOL_MOUNT_DIR))
}

/// The directory under which btrfs base and container subvolumes live, without
/// guaranteeing it is mounted. Callers that need a mounted, usable location
/// must go through [`ensure_ready`]. Mode A: `{datadir}/btrfs`; Mode B:
/// `{datadir}/pool`.
pub fn root(datadir: &Path) -> Result<PathBuf> {
    if is_btrfs(datadir)? {
        Ok(datadir.join(BTRFS_SUBDIR))
    } else {
        Ok(datadir.join(POOL_MOUNT_DIR))
    }
}

/// Ensure the btrfs subvolume location exists and is mounted, returning it.
///
/// Mode A creates `{datadir}/btrfs`. Mode B creates the sparse pool image (if
/// absent), formats it btrfs, installs a systemd `.mount` unit, and mounts it.
/// Idempotent: safe to call before every btrfs operation.
pub fn ensure_ready(datadir: &Path, pool_size: &str, verbose: bool) -> Result<PathBuf> {
    system_check::check_dependencies(&[("btrfs", "btrfs-progs")], verbose)?;

    if is_btrfs(datadir)? {
        let dir = datadir.join(BTRFS_SUBDIR);
        fs::create_dir_all(&dir).with_context(|| format!("failed to create {}", dir.display()))?;
        if verbose {
            eprintln!("btrfs storage (mode A, native): {}", dir.display());
        }
        return Ok(dir);
    }

    // Mode B: loopback pool image.
    system_check::check_dependencies(&[("mkfs.btrfs", "btrfs-progs")], verbose)?;
    let (image, mount_dir) = mode_b_paths(datadir);
    fs::create_dir_all(&mount_dir)
        .with_context(|| format!("failed to create {}", mount_dir.display()))?;

    if !image.exists() {
        create_image(&image, pool_size, verbose)?;
    }
    if !is_mounted(&mount_dir)? {
        mount_pool(&image, &mount_dir, verbose)?;
    }
    if verbose {
        eprintln!("btrfs storage (mode B, pool): {}", mount_dir.display());
    }
    Ok(mount_dir)
}

/// Ensure an *existing* pool is mounted, returning the subvolume root. Unlike
/// [`ensure_ready`], this never creates the pool image; it errors if a Mode B
/// pool does not yet exist. Use for operations on existing containers
/// (rm/cp/export/diff), where the pool must already have been created.
pub fn ensure_mounted(datadir: &Path, verbose: bool) -> Result<PathBuf> {
    if is_btrfs(datadir)? {
        return Ok(datadir.join(BTRFS_SUBDIR));
    }
    let (image, mount_dir) = mode_b_paths(datadir);
    if !image.exists() {
        bail!("btrfs pool image not found: {}", image.display());
    }
    if !is_mounted(&mount_dir)? {
        mount_pool(&image, &mount_dir, verbose)?;
    }
    Ok(mount_dir)
}

/// Grow the Mode B pool image by `extra` bytes and expand the btrfs filesystem
/// online. No-op in Mode A (the datadir filesystem is grown by the operator).
pub fn grow(datadir: &Path, extra: u64, verbose: bool) -> Result<()> {
    if is_btrfs(datadir)? {
        bail!("datadir is native btrfs; grow the underlying filesystem directly");
    }
    let (image, mount_dir) = mode_b_paths(datadir);
    let cur = fs::metadata(&image)
        .with_context(|| format!("failed to stat {}", image.display()))?
        .len();
    let new_len = cur.saturating_add(extra);
    fs::OpenOptions::new()
        .write(true)
        .open(&image)
        .with_context(|| format!("failed to open {}", image.display()))?
        .set_len(new_len)
        .with_context(|| format!("failed to grow {}", image.display()))?;
    // Refresh the loop device capacity, then grow the filesystem online.
    run(
        "losetup",
        &["-c"],
        &[loop_device_for(&mount_dir)?.as_os_str()],
        verbose,
    )?;
    run(
        "btrfs",
        &["filesystem", "resize", "max"],
        &[mount_dir.as_os_str()],
        verbose,
    )?;
    Ok(())
}

/// Create a sparse pool image of `size` and format it btrfs.
fn create_image(image: &Path, size: &str, verbose: bool) -> Result<()> {
    let bytes =
        crate::parse_size(size).with_context(|| format!("invalid btrfs pool size: {size:?}"))?;
    if verbose {
        eprintln!(
            "creating btrfs pool image {} ({bytes} bytes, sparse)",
            image.display()
        );
    }
    let f =
        fs::File::create(image).with_context(|| format!("failed to create {}", image.display()))?;
    f.set_len(bytes)
        .with_context(|| format!("failed to size {}", image.display()))?;
    drop(f);
    let st = Command::new("mkfs.btrfs")
        .args(["-q", "-f"])
        .arg(image)
        .status()
        .context("failed to run mkfs.btrfs")?;
    check_interrupted()?;
    if !st.success() {
        let _ = fs::remove_file(image);
        bail!("mkfs.btrfs failed on {}", image.display());
    }
    Ok(())
}

/// Returns `true` if `dir` is itself a mount point (its device differs from its
/// parent's). Dependency-free alternative to the `mountpoint` binary.
fn is_mounted(dir: &Path) -> Result<bool> {
    let Some(parent) = dir.parent() else {
        return Ok(false);
    };
    let d = fs::metadata(dir)
        .with_context(|| format!("failed to stat {}", dir.display()))?
        .dev();
    let p = fs::metadata(parent)
        .with_context(|| format!("failed to stat {}", parent.display()))?
        .dev();
    Ok(d != p)
}

/// Mount the pool image at `mount_dir` via a generated systemd `.mount` unit,
/// so the mount is tracked by systemd and can be ordered before container
/// units (via `RequiresMountsFor`) and re-established after a host reboot.
fn mount_pool(image: &Path, mount_dir: &Path, verbose: bool) -> Result<()> {
    let unit = ensure_mount_unit(image, mount_dir, verbose)?;
    let st = Command::new("systemctl")
        .arg("start")
        .arg(&unit)
        .status()
        .context("failed to run systemctl start")?;
    check_interrupted()?;
    if !st.success() {
        bail!("failed to start pool mount unit {unit}");
    }
    if !is_mounted(mount_dir)? {
        bail!(
            "pool mount unit {unit} started but {} is not mounted",
            mount_dir.display()
        );
    }
    Ok(())
}

/// Compute the systemd unit name for a mount at `mount_dir`
/// (e.g. `var-lib-sdme-pool.mount`) via `systemd-escape`.
pub fn mount_unit_name(mount_dir: &Path) -> Result<String> {
    let out = Command::new("systemd-escape")
        .args(["-p", "--suffix=mount"])
        .arg(mount_dir)
        .output()
        .context("failed to run systemd-escape")?;
    if !out.status.success() {
        bail!("systemd-escape failed for {}", mount_dir.display());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Install (write + daemon-reload if changed) the pool `.mount` unit and return
/// its name.
fn ensure_mount_unit(image: &Path, mount_dir: &Path, verbose: bool) -> Result<String> {
    let unit = mount_unit_name(mount_dir)?;
    let unit_path = Path::new("/etc/systemd/system").join(&unit);
    // Options: loop attaches the image; noatime avoids metadata churn. Direct
    // I/O on the loop device (to avoid double page-cache buffering under memory
    // pressure) is a documented follow-up; util-linux `-o loop` does not expose
    // it directly.
    let content = format!(
        "[Unit]\n\
         Description=sdme btrfs storage pool\n\
         DefaultDependencies=no\n\
         Conflicts=umount.target\n\
         Before=umount.target\n\
         \n\
         [Mount]\n\
         What={}\n\
         Where={}\n\
         Type=btrfs\n\
         Options=loop,noatime\n",
        image.display(),
        mount_dir.display(),
    );
    let changed = match fs::read_to_string(&unit_path) {
        Ok(existing) if existing == content => false,
        _ => {
            fs::write(&unit_path, &content)
                .with_context(|| format!("failed to write {}", unit_path.display()))?;
            true
        }
    };
    if changed {
        if verbose {
            eprintln!("installed pool mount unit: {}", unit_path.display());
        }
        crate::systemd::dbus::daemon_reload()?;
    }
    Ok(unit)
}

/// Find the loop device backing a mounted pool by scanning `/proc/self/mountinfo`
/// for `mount_dir` and reading its source device.
fn loop_device_for(mount_dir: &Path) -> Result<PathBuf> {
    let target = mount_dir
        .to_str()
        .context("mount dir path is not valid UTF-8")?;
    let mountinfo = fs::read_to_string("/proc/self/mountinfo")
        .context("failed to read /proc/self/mountinfo")?;
    for line in mountinfo.lines() {
        // Fields: ... mount_point ... - fstype source super_opts
        let mut parts = line.split(" - ");
        let (Some(pre), Some(post)) = (parts.next(), parts.next()) else {
            continue;
        };
        let mount_point = pre.split_whitespace().nth(4);
        if mount_point != Some(target) {
            continue;
        }
        if let Some(source) = post.split_whitespace().nth(1) {
            return Ok(PathBuf::from(source));
        }
    }
    bail!("could not find loop device for {}", mount_dir.display())
}

/// Run a command with a mix of string args and OsStr args, failing on non-zero.
fn run(bin: &str, args: &[&str], os_args: &[&std::ffi::OsStr], verbose: bool) -> Result<()> {
    let mut cmd = Command::new(bin);
    cmd.args(args);
    for a in os_args {
        cmd.arg(a);
    }
    if verbose {
        eprintln!("running: {bin} {args:?}");
    }
    let st = cmd
        .status()
        .with_context(|| format!("failed to run {bin}"))?;
    check_interrupted()?;
    if !st.success() {
        bail!("{bin} failed");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_pool_size_parses() {
        // The default must be a valid size string the rest of the code can parse.
        assert_eq!(
            crate::parse_size(DEFAULT_POOL_SIZE).unwrap(),
            20 * 1024 * 1024 * 1024
        );
    }

    #[test]
    fn mode_b_paths_are_under_datadir() {
        let (image, mount) = mode_b_paths(Path::new("/var/lib/sdme"));
        assert_eq!(image, Path::new("/var/lib/sdme/btrfs-pool.img"));
        assert_eq!(mount, Path::new("/var/lib/sdme/pool"));
    }
}
