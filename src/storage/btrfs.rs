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

use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};

use super::pool;
use crate::{check_interrupted, copy};

/// Subdirectory under the pool root holding base (immutable) subvolumes.
pub(crate) const FS_SUBDIR: &str = "fs";
/// Subdirectory under the pool root holding per-container subvolumes.
pub(crate) const CONTAINERS_SUBDIR: &str = "containers";

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
    if subvolume_exists(&dst) {
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
    if subvolume_exists(&tmp) {
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

/// Inode number of every btrfs subvolume root (`BTRFS_FIRST_FREE_OBJECTID`).
/// The filesystem tree root shares it, but sdme only ever probes paths it
/// created itself under the pool, never the filesystem root.
const SUBVOL_ROOT_INO: u64 = 256;

/// Returns `true` if `path` is a btrfs subvolume root.
///
/// Detection is ioctl-free: a subvolume root is a directory with inode number
/// 256 on a btrfs filesystem (statfs magic). This works in nested
/// (user-namespaced) contexts, where `btrfs subvolume show` fails with EPERM:
/// its tree-search ioctls require CAP_SYS_ADMIN in the initial user namespace.
/// There the EPERM made sdme conclude a subvolume was missing and recreate it,
/// corrupting create/commit state (`failed to commit base subvolume`).
pub fn is_subvolume(path: &Path) -> bool {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return false;
    };
    if !meta.is_dir() || meta.ino() != SUBVOL_ROOT_INO {
        return false;
    }
    // Inode 256 only means "subvolume root" on btrfs; on any other filesystem
    // an ordinary directory could legitimately carry it.
    pool::is_btrfs(path).unwrap_or(false)
}

/// Returns `true` if `path` exists, without following symlinks.
///
/// sdme only ever addresses subvolumes by known paths it chose itself, so a
/// plain `lstat` is the complete existence check: unlike tree-search based
/// enumeration it needs no privilege and works in nested contexts.
pub fn subvolume_exists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
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

/// Subdirectory (inside the subvolume's parent) holding subvolumes whose
/// destroy was denied, parked until a privileged `sdme prune` on the host.
pub(crate) const TRASH_SUBDIR: &str = ".trash";

/// Delete the subvolume at `path`. No-op if the path does not exist.
///
/// When the destroy ioctl is denied (EPERM: nested context on a btrfs mount
/// without `user_subvol_rm_allowed`), the subvolume is parked in a `.trash`
/// directory next to it and its contents removed with plain file operations.
/// Rollback therefore never strands state on a denied destroy; a later
/// privileged `sdme prune` on the host destroys trash entries.
pub fn delete_subvol(path: &Path, verbose: bool) -> Result<()> {
    if !subvolume_exists(path) {
        return Ok(());
    }
    match destroy_subvol_tree(path, verbose) {
        Ok(()) => Ok(()),
        Err(e) if is_destroy_denied(&e) => trash_subvol(path, verbose),
        Err(e) => Err(e),
    }
}

/// Destroy a subvolume, removing any nested child subvolumes deepest-first.
fn destroy_subvol_tree(path: &Path, verbose: bool) -> Result<()> {
    // Fast path: a plain destroy succeeds unless the subvolume still contains
    // nested subvolumes, so the common case (no nesting) pays nothing extra.
    if delete_one_subvol(path, verbose).is_ok() {
        return Ok(());
    }
    // A container that ran a nested btrfs-backed engine (Docker or Podman with
    // the btrfs driver) leaves child subvolumes under the root, and btrfs
    // refuses to destroy a subvolume that still contains them. Remove the
    // children deepest-first, then retry the root.
    for child in nested_subvols(path)? {
        delete_one_subvol(&child, verbose)?;
    }
    delete_one_subvol(path, verbose)
}

/// Whether `e` reports the destroy ioctl being denied, the signature of a
/// nested context on a btrfs mount without `user_subvol_rm_allowed` (the
/// kernel's `may_delete_subvol` check returns EPERM there).
fn is_destroy_denied(e: &anyhow::Error) -> bool {
    e.chain()
        .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
        .any(|io| {
            matches!(io.raw_os_error(), Some(code) if code == libc::EPERM || code == libc::EACCES)
        })
}

/// Park a subvolume that could not be destroyed in `.trash`, then empty its
/// contents with plain file operations.
///
/// Rename is an ordinary directory operation needing only write access on the
/// parent directories, so it succeeds where the destroy ioctl EPERMs. The
/// parked subvolume root itself stays behind (only a privileged destroy on the
/// host removes it); child subvolume roots from nested btrfs engines likewise
/// survive the emptying and go away with the host-side destroy.
fn trash_subvol(path: &Path, verbose: bool) -> Result<()> {
    let parent = path.parent().context("subvolume path has no parent")?;
    let name = path
        .file_name()
        .context("subvolume path has no basename")?
        .to_string_lossy();
    let trash_dir = parent.join(TRASH_SUBDIR);
    fs::create_dir_all(&trash_dir)
        .with_context(|| format!("failed to create {}", trash_dir.display()))?;
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut target = trash_dir.join(format!("{name}.{ts}"));
    if subvolume_exists(&target) {
        target = trash_dir.join(format!("{name}.{ts}.{}", std::process::id()));
    }
    fs::rename(path, &target).with_context(|| {
        format!(
            "failed to park {} in trash {}",
            path.display(),
            target.display()
        )
    })?;
    eprintln!(
        "note: permission denied destroying subvolume {}; parked as {}\n\
         (a privileged `sdme prune` on the host removes parked subvolumes)",
        path.display(),
        target.display()
    );
    if let Ok(entries) = fs::read_dir(&target) {
        for entry in entries.flatten() {
            let p = entry.path();
            let _ = if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                fs::remove_dir_all(&p)
            } else {
                fs::remove_file(&p)
            };
        }
    }
    if verbose {
        eprintln!("emptied parked subvolume {}", target.display());
    }
    Ok(())
}

/// `BTRFS_IOC_SNAP_DESTROY_V2` request number:
/// `_IOW(BTRFS_IOCTL_MAGIC = 0x94, 63, btrfs_ioctl_vol_args_v2)`.
/// Verified against /usr/include/linux/btrfs.h.
const BTRFS_IOC_SNAP_DESTROY_V2: libc::c_ulong = 0x5000_943f;

/// Maximum length of a subvolume name (`BTRFS_SUBVOL_NAME_MAX`).
const SUBVOL_NAME_MAX: usize = 4039;

/// `struct btrfs_ioctl_vol_args_v2` from <linux/btrfs.h>, by-name form: `fd`
/// is an open fd of the parent directory, `name` the NUL-terminated basename.
#[repr(C)]
struct SnapDestroyArgs {
    fd: i64,
    transid: u64,
    flags: u64,
    unused: [u64; 4],
    name: [u8; SUBVOL_NAME_MAX + 1],
}

/// Destroy a single btrfs subvolume via `BTRFS_IOC_SNAP_DESTROY_V2`, with no
/// handling of nested children.
///
/// Calling the ioctl directly (by name, through the parent directory fd)
/// skips btrfs-progs' privileged pre-checks: `btrfs subvolume delete` probes
/// the default subvolume id first, which requires CAP_SYS_ADMIN in the
/// initial user namespace and fails with EPERM in nested contexts, hiding the
/// real result and leaving stale subvolumes behind. Here one syscall yields
/// one honest errno.
fn delete_one_subvol(path: &Path, verbose: bool) -> Result<()> {
    if verbose {
        eprintln!("destroying subvolume {}", path.display());
    }
    let parent = path.parent().context("subvolume path has no parent")?;
    let name = path.file_name().context("subvolume path has no basename")?;
    let name = name.as_bytes();
    if name.len() > SUBVOL_NAME_MAX {
        bail!("subvolume name too long: {}", path.display());
    }
    let parent_dir = fs::File::open(parent)
        .with_context(|| format!("failed to open {}", parent.display()))?;
    let mut args = SnapDestroyArgs {
        fd: i64::from(parent_dir.as_raw_fd()),
        transid: 0,
        flags: 0,
        unused: [0; 4],
        name: [0; SUBVOL_NAME_MAX + 1],
    };
    args.name[..name.len()].copy_from_slice(name);
    // SAFETY: `args` is a fully initialized ioctl argument struct and outlives
    // the call; this request writes nothing back into it.
    let rc = unsafe { libc::ioctl(parent_dir.as_raw_fd(), BTRFS_IOC_SNAP_DESTROY_V2, &args) };
    check_interrupted()?;
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("failed to destroy subvolume {}", path.display()));
    }
    Ok(())
}

/// Nested subvolume roots under `path`, deepest-first so children are removed
/// before their parents. btrfs gives every subvolume root inode number 256, so
/// `find -inum 256` locates them independently of the pool's mount layout (Mode
/// A vs Mode B), where a `btrfs subvolume list` path would need remapping.
fn nested_subvols(path: &Path) -> Result<Vec<PathBuf>> {
    let out = Command::new("find")
        .arg(path)
        .args(["-mindepth", "1", "-inum", "256", "-print0"])
        .output()
        .context("failed to enumerate nested btrfs subvolumes")?;
    check_interrupted()?;
    if !out.status.success() {
        bail!(
            "enumerating nested subvolumes under {} failed: {}",
            path.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let mut subvols: Vec<PathBuf> = out
        .stdout
        .split(|&b| b == 0)
        .filter(|entry| !entry.is_empty())
        .map(|entry| PathBuf::from(OsStr::from_bytes(entry)))
        .collect();
    sort_deepest_first(&mut subvols);
    Ok(subvols)
}

/// Order subvolume paths so the deepest come first: a child always has more path
/// components than the parent that contains it.
fn sort_deepest_first(subvols: &mut [PathBuf]) {
    subvols.sort_by_key(|p| std::cmp::Reverse(p.components().count()));
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
///
/// This is the one remaining btrfs-progs shell-out for inspection: it only
/// feeds qgroup usage reporting, an optional diagnostic that degrades to `None`
/// (no usage shown) in nested contexts where the tree-search ioctls EPERM.
/// Existence and deletion decisions never go through it; see [`is_subvolume`].
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
    fn snap_destroy_args_layout_matches_kernel() {
        // Layout verified against /usr/include/linux/btrfs.h:
        // sizeof(struct btrfs_ioctl_vol_args_v2) == 4096, name at offset 56.
        assert_eq!(std::mem::size_of::<SnapDestroyArgs>(), 4096);
        assert_eq!(std::mem::offset_of!(SnapDestroyArgs, name), 56);
        // _IOW(0x94, 63, args): (1 << 30) | (4096 << 16) | (0x94 << 8) | 63.
        assert_eq!(
            BTRFS_IOC_SNAP_DESTROY_V2,
            (1 << 30) | (4096 << 16) | (0x94 << 8) | 63
        );
    }

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
    fn sort_deepest_first_orders_children_before_parents() {
        // The container root, a mid-level dir, and a deep Docker layer subvolume,
        // shuffled. Deleting deepest-first is what lets btrfs remove the root.
        let mut v = vec![
            PathBuf::from("/pool/containers/c"),
            PathBuf::from("/pool/containers/c/var/lib/docker/btrfs/subvolumes/a"),
            PathBuf::from("/pool/containers/c/var/lib/docker"),
        ];
        sort_deepest_first(&mut v);
        assert_eq!(
            v.first().unwrap(),
            &PathBuf::from("/pool/containers/c/var/lib/docker/btrfs/subvolumes/a")
        );
        assert_eq!(v.last().unwrap(), &PathBuf::from("/pool/containers/c"));
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

    #[test]
    fn is_subvolume_false_for_plain_dirs_and_missing_paths() {
        let dir = std::env::temp_dir().join(format!("sdme-test-isubvol-{}", std::process::id()));
        let nested = dir.join("a/b/c");
        fs::create_dir_all(&nested).unwrap();
        // Plain directories are never subvolume roots, even on btrfs: only the
        // root of a subvolume gets inode 256.
        assert!(!is_subvolume(&dir));
        assert!(!is_subvolume(&nested));
        assert!(!is_subvolume(&dir.join("missing")));
        assert!(subvolume_exists(&dir));
        assert!(!subvolume_exists(&dir.join("missing")));
        fs::remove_dir_all(&dir).unwrap();
    }

    /// The true case needs a real btrfs subvolume: root, btrfs-progs, and a
    /// writable btrfs mount. Skips when any is missing; e2e suites cover this
    /// path on real pools.
    #[test]
    fn is_subvolume_true_for_real_subvolume() {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skipping: not root");
            return;
        }
        let Some(mount) = find_writable_btrfs_mount() else {
            eprintln!("skipping: no writable btrfs mount");
            return;
        };
        let sub = mount.join(format!(".sdme-test-isubvol-{}", std::process::id()));
        let st = Command::new("btrfs")
            .args(["subvolume", "create"])
            .arg(&sub)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("failed to run btrfs subvolume create");
        if !st.success() {
            let _ = fs::remove_dir(&sub);
            eprintln!("skipping: cannot create subvolume on {}", mount.display());
            return;
        }
        assert!(is_subvolume(&sub));
        // A plain directory inside a subvolume is not itself a subvolume root.
        let plain = sub.join("plain");
        fs::create_dir(&plain).unwrap();
        assert!(!is_subvolume(&plain));
        let st = Command::new("btrfs")
            .args(["subvolume", "delete"])
            .arg(&sub)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("failed to run btrfs subvolume delete");
        assert!(st.success());
    }

    /// First btrfs mount point from /proc/self/mounts we can create entries in.
    fn find_writable_btrfs_mount() -> Option<PathBuf> {
        let mounts = fs::read_to_string("/proc/self/mounts").ok()?;
        for line in mounts.lines() {
            let mut parts = line.split_whitespace();
            let (Some(_src), Some(target), Some(fstype)) =
                (parts.next(), parts.next(), parts.next())
            else {
                continue;
            };
            if fstype != "btrfs" {
                continue;
            }
            let dir = PathBuf::from(target);
            let probe = dir.join(format!(".sdme-test-probe-{}", std::process::id()));
            if fs::create_dir(&probe).is_ok() {
                let _ = fs::remove_dir(&probe);
                return Some(dir);
            }
        }
        None
    }
}
