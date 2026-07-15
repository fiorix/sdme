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
//! (via the shared `crate::copy` engine, which preserves hardlinks, device
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
    ensure_base(datadir, &pool_root, base_name, base_src, verbose)?;

    let base = base_subvol(&pool_root, base_name);
    let dst = container_root(&pool_root, name);
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    if dst.exists() {
        // A leftover from a crashed create, or an rm whose teardown failed. The
        // state file is claimed atomically (O_CREAT|O_EXCL) before do_create, so
        // no live container can own this path; reclaim it rather than bail and
        // block name reuse.
        if verbose {
            eprintln!("reclaiming stale container subvolume {}", dst.display());
        }
        delete_subvol(&dst, verbose)?;
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
    datadir: &Path,
    pool_root: &Path,
    base_name: &str,
    src_dir: &Path,
    verbose: bool,
) -> Result<PathBuf> {
    let dst = base_subvol(pool_root, base_name);
    if is_subvolume(&dst) {
        return Ok(dst);
    }

    // Serialize base materialization: without this, N concurrent first-time
    // creates from the same rootfs each copy_tree the whole base (wasted work,
    // and spurious ENOSPC in a fixed-size pool). Blocking so peers queue and
    // then take the double-check below. "storage" kind keeps btrfs pool locks
    // together, acquired after the shared fs lock create already holds.
    let _base_lock =
        crate::lock::lock_exclusive_blocking(datadir, "storage", &format!("base-{base_name}"))?;
    if is_subvolume(&dst) {
        return Ok(dst);
    }

    let fs_dir = pool_root.join(FS_SUBDIR);
    fs::create_dir_all(&fs_dir)
        .with_context(|| format!("failed to create {}", fs_dir.display()))?;
    // Reclaim base temp subvolumes leaked by creators that died mid-copy.
    sweep_stale_temps(&fs_dir, verbose);

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

/// Invalidate the cached base subvolume for `base_name`, so a later container
/// re-materializes it from the current rootfs. Call after the imported rootfs
/// at `{datadir}/fs/{base_name}` is removed (`fs rm`) or replaced (`import -f`);
/// otherwise a stale base would keep seeding new containers with the old
/// content.
///
/// No-op when no pool exists (overlay-only host, or a Mode B pool never
/// created). Safe even while container snapshots of the base exist: btrfs
/// snapshots are independent of their source after creation, so deleting the
/// base only frees its own metadata, not the snapshots' shared blocks. Callers
/// hold the exclusive `fs` lock, which excludes concurrent base materialization
/// (creates take the shared `fs` lock).
pub fn invalidate_base(datadir: &Path, base_name: &str, verbose: bool) -> Result<()> {
    if !pool::exists(datadir)? {
        return Ok(());
    }
    let pool_root = pool::ensure_mounted(datadir, verbose)?;
    let base = base_subvol(&pool_root, base_name);
    if is_subvolume(&base) {
        if verbose {
            eprintln!("invalidating stale btrfs base subvolume {}", base.display());
        }
        delete_subvol(&base, verbose)?;
    }
    Ok(())
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

/// Apply a disk cap to a container subvolume via its btrfs qgroup, as a limit
/// on referenced bytes (`max_rfer`). Simple quotas (squota) are enabled lazily,
/// after the base was already snapshotted, so blocks shared with the base
/// predate quota accounting and do NOT count toward the cap: the limit bounds
/// the data the container writes after creation (its own footprint), and
/// [`qgroup_usage`] reports usage on the same basis. Quotas must already be
/// enabled on the pool ([`super::pool::ensure_quota_enabled`]). Given a
/// subvolume path with no explicit qgroup id, btrfs limits that subvolume's
/// level-0 qgroup.
pub fn set_disk_limit(subvol: &Path, bytes: u64, verbose: bool) -> Result<()> {
    if verbose {
        eprintln!("btrfs qgroup limit {bytes} {}", subvol.display());
    }
    let mut cmd = Command::new("btrfs");
    cmd.args(["qgroup", "limit"])
        .arg(bytes.to_string())
        .arg(subvol);
    run(&mut cmd, "btrfs qgroup limit")
}

/// Remove any disk cap from a container subvolume (`btrfs qgroup limit none`).
pub fn clear_disk_limit(subvol: &Path, verbose: bool) -> Result<()> {
    if verbose {
        eprintln!("btrfs qgroup limit none {}", subvol.display());
    }
    let mut cmd = Command::new("btrfs");
    cmd.args(["qgroup", "limit", "none"]).arg(subvol);
    run(&mut cmd, "btrfs qgroup limit none")
}

/// Referenced (used) bytes for a container subvolume's btrfs qgroup, or `None`
/// if quotas are off, the subvolume is missing, or the pool is not mounted.
///
/// Best-effort by design: `sdme ps` calls this per btrfs container and must not
/// fail when a pool is offline, so every error path yields `None`.
pub fn qgroup_usage(pool_root: &Path, subvol: &Path) -> Option<u64> {
    let id = subvol_id(subvol)?;
    let out = Command::new("btrfs")
        .args(["qgroup", "show", "--raw"])
        .arg(pool_root)
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    parse_qgroup_referenced(&String::from_utf8_lossy(&out.stdout), id)
}

/// Read a subvolume's numeric id from `btrfs subvolume show`.
fn subvol_id(subvol: &Path) -> Option<u64> {
    let out = Command::new("btrfs")
        .args(["subvolume", "show"])
        .arg(subvol)
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    parse_subvol_id(&String::from_utf8_lossy(&out.stdout))
}

/// Extract the numeric `Subvolume ID:` field from `btrfs subvolume show` output.
fn parse_subvol_id(text: &str) -> Option<u64> {
    for line in text.lines() {
        if let Some(rest) = line.trim().strip_prefix("Subvolume ID:") {
            return rest.trim().parse().ok();
        }
    }
    None
}

/// Find the Referenced (used) bytes for qgroup `0/<id>` in the output of
/// `btrfs qgroup show --raw`. Columns are: qgroupid, referenced, exclusive.
fn parse_qgroup_referenced(text: &str, id: u64) -> Option<u64> {
    let target = format!("0/{id}");
    for line in text.lines() {
        let mut cols = line.split_whitespace();
        if cols.next() == Some(target.as_str()) {
            return cols.next().and_then(|r| r.parse().ok());
        }
    }
    None
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

/// Reclaim base temp subvolumes (`.{base}.tmp-{pid}`) left behind by creators
/// that died mid-`copy_tree`. Best-effort; called under the base lock so it
/// never races a live creator, and it skips temps whose PID is still alive.
fn sweep_stale_temps(fs_dir: &Path, verbose: bool) {
    let Ok(entries) = fs::read_dir(fs_dir) else {
        return;
    };
    let self_pid = std::process::id();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some((_, pid_str)) = name
            .strip_prefix('.')
            .and_then(|rest| rest.rsplit_once(".tmp-"))
        else {
            continue;
        };
        let Ok(pid) = pid_str.parse::<u32>() else {
            continue;
        };
        // Skip our own temp and any whose creating process is still running.
        if pid == self_pid || Path::new(&format!("/proc/{pid}")).exists() {
            continue;
        }
        let path = entry.path();
        if is_subvolume(&path) {
            if verbose {
                eprintln!("reclaiming stale base temp subvolume {}", path.display());
            }
            let _ = delete_subvol(&path, verbose);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_subvol_id_reads_id() {
        let out = "containers/web\n\
                   \tName: \t\t\tweb\n\
                   \tUUID: \t\t\t1234\n\
                   \tSubvolume ID: \t\t264\n\
                   \tGeneration: \t\t7\n";
        assert_eq!(parse_subvol_id(out), Some(264));
        assert_eq!(parse_subvol_id("no id here\n"), None);
    }

    #[test]
    fn parse_qgroup_referenced_matches_level0() {
        let out = "Qgroupid    Referenced    Exclusive \n\
                   --------    ----------    --------- \n\
                   0/5                  0            0 \n\
                   0/256         16384000     16384000 \n\
                   0/264        252305408    252305408 \n";
        assert_eq!(parse_qgroup_referenced(out, 264), Some(252305408));
        assert_eq!(parse_qgroup_referenced(out, 256), Some(16384000));
        // A missing qgroup (no such subvolume) yields None, not a header match.
        assert_eq!(parse_qgroup_referenced(out, 999), None);
    }

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
