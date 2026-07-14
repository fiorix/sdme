//! btrfs subvolume operations for the btrfs storage backend.
//!
//! A btrfs container's root is a copy-on-write subvolume snapshot of an
//! immutable base subvolume. Both live under the pool root resolved by
//! [`super::pool`]:
//!
//! - base (immutable) subvolumes: `{pool_root}/fs/{base}`
//! - per-container subvolumes:    `{pool_root}/containers/{name}`
//!
//! The base subvolume is materialized once from an existing rootfs directory
//! (via the shared [`crate::copy`] engine, which preserves hardlinks, device
//! nodes, suid bits, and xattrs); every container is then an O(1) `btrfs
//! subvolume snapshot` of it. On a native-btrfs datadir (Mode A) or inside the
//! loopback pool (Mode B), the snapshot shares the base's blocks, so N
//! containers cost roughly one base plus their divergence.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};

use super::pool;
use crate::{check_interrupted, copy};

/// Subdirectory under the pool root holding base (immutable) subvolumes.
const FS_SUBDIR: &str = "fs";
/// Subdirectory under the pool root holding per-container subvolumes.
const CONTAINERS_SUBDIR: &str = "containers";

/// Path of the base subvolume for rootfs `base` under `pool_root`.
pub fn base_subvol(pool_root: &Path, base: &str) -> PathBuf {
    pool_root.join(FS_SUBDIR).join(base)
}

/// Path of the per-container subvolume for `name` under `pool_root`. This is
/// what `systemd-nspawn --directory=` points at for a btrfs container.
pub fn container_root(pool_root: &Path, name: &str) -> PathBuf {
    pool_root.join(CONTAINERS_SUBDIR).join(name)
}

/// Provision a container's root by snapshotting the base subvolume.
///
/// Ensures the pool is ready (creating/mounting it in Mode B), materializes the
/// base subvolume from `base_src` if it does not exist yet, then takes a
/// writable CoW snapshot as the container root and returns its path.
pub fn provision(
    datadir: &Path,
    name: &str,
    base_name: &str,
    base_src: &Path,
    pool_size: &str,
    verbose: bool,
) -> Result<PathBuf> {
    let pool_root = pool::ensure_ready(datadir, pool_size, verbose)?;
    ensure_base(&pool_root, base_name, base_src, verbose)?;

    let base = base_subvol(&pool_root, base_name);
    let dst = container_root(&pool_root, name);
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    if dst.exists() {
        bail!("container subvolume already exists: {}", dst.display());
    }
    snapshot(&base, &dst, false, verbose)?;
    Ok(dst)
}

/// Remove a container's subvolume. No-op if it does not exist. Requires the
/// pool to already exist (errors otherwise, via [`pool::ensure_mounted`]).
pub fn teardown(datadir: &Path, name: &str, verbose: bool) -> Result<()> {
    let pool_root = pool::ensure_mounted(datadir, verbose)?;
    delete_subvol(&container_root(&pool_root, name), verbose)
}

/// Ensure the base subvolume for `base_name` exists, materializing it from
/// `src_dir` if absent. Idempotent and race-safe: population happens in a
/// temporary subvolume that is atomically renamed into place, so a concurrent
/// creator either wins the rename or finds the finished base.
pub fn ensure_base(
    pool_root: &Path,
    base_name: &str,
    src_dir: &Path,
    verbose: bool,
) -> Result<PathBuf> {
    let dst = base_subvol(pool_root, base_name);
    if is_subvolume(&dst) {
        return Ok(dst);
    }
    let fs_dir = pool_root.join(FS_SUBDIR);
    fs::create_dir_all(&fs_dir)
        .with_context(|| format!("failed to create {}", fs_dir.display()))?;

    let tmp = fs_dir.join(format!(".{base_name}.tmp-{}", std::process::id()));
    if tmp.exists() {
        let _ = delete_subvol(&tmp, verbose);
    }
    create_subvol(&tmp, verbose)?;

    let populate = (|| -> Result<()> {
        copy::copy_metadata(src_dir, &tmp)?;
        copy::copy_tree(src_dir, &tmp, verbose)?;
        Ok(())
    })();
    if let Err(e) = populate {
        let _ = delete_subvol(&tmp, verbose);
        return Err(e).context("failed to populate base subvolume");
    }

    match fs::rename(&tmp, &dst) {
        Ok(()) => Ok(dst),
        // Lost the race: another creator finished the same base first.
        Err(_) if is_subvolume(&dst) => {
            let _ = delete_subvol(&tmp, verbose);
            Ok(dst)
        }
        Err(e) => {
            let _ = delete_subvol(&tmp, verbose);
            Err(e).with_context(|| format!("failed to commit base subvolume {}", dst.display()))
        }
    }
}

/// Returns `true` if `path` is a btrfs subvolume. `btrfs subvolume show` exits
/// non-zero for a plain directory or a missing path.
pub fn is_subvolume(path: &Path) -> bool {
    Command::new("btrfs")
        .args(["subvolume", "show"])
        .arg(path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Create an empty subvolume at `path`.
pub fn create_subvol(path: &Path, verbose: bool) -> Result<()> {
    if verbose {
        eprintln!("btrfs subvolume create {}", path.display());
    }
    let mut cmd = Command::new("btrfs");
    cmd.args(["subvolume", "create"]).arg(path);
    run(&mut cmd, "btrfs subvolume create")
}

/// Snapshot `src` to `dst`. `readonly` takes a `-r` (read-only) snapshot.
pub fn snapshot(src: &Path, dst: &Path, readonly: bool, verbose: bool) -> Result<()> {
    if verbose {
        eprintln!(
            "btrfs subvolume snapshot{} {} {}",
            if readonly { " -r" } else { "" },
            src.display(),
            dst.display()
        );
    }
    let mut cmd = Command::new("btrfs");
    cmd.args(["subvolume", "snapshot"]);
    if readonly {
        cmd.arg("-r");
    }
    cmd.arg(src).arg(dst);
    run(&mut cmd, "btrfs subvolume snapshot")
}

/// Delete the subvolume at `path`. No-op if the path does not exist.
pub fn delete_subvol(path: &Path, verbose: bool) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    if verbose {
        eprintln!("btrfs subvolume delete {}", path.display());
    }
    let mut cmd = Command::new("btrfs");
    cmd.args(["subvolume", "delete"]).arg(path);
    run(&mut cmd, "btrfs subvolume delete")
}

/// Run a `btrfs` subcommand, mapping a non-zero exit to an error and honoring
/// interrupt requests.
fn run(cmd: &mut Command, what: &str) -> Result<()> {
    let st = cmd
        .status()
        .with_context(|| format!("failed to run {what}"))?;
    check_interrupted()?;
    if !st.success() {
        bail!("{what} failed");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subvol_paths() {
        let pool = Path::new("/var/lib/sdme/pool");
        assert_eq!(
            base_subvol(pool, "debian"),
            Path::new("/var/lib/sdme/pool/fs/debian")
        );
        assert_eq!(
            container_root(pool, "web"),
            Path::new("/var/lib/sdme/pool/containers/web")
        );
    }
}
