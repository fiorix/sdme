//! User namespace UID shift allocation and pre-chown for overlayfs.
//!
//! When the kernel does not support idmapped mounts on overlayfs, nspawn's
//! `--private-users-ownership=auto` falls back to a slow recursive chown
//! that triggers full copy-ups on every file. This module provides:
//!
//! - Deterministic UID shift allocation matching nspawn's `--private-users=pick`
//! - Conflict detection against other sdme containers and running machines
//! - Parallel pre-chown at create time so boot is fast
//! - Nested container support: sub-ranges allocated inside a parent user namespace
//!
//! # TODO
//!
//! On systemd 256+, register UID ranges with nsresourced for persistent
//! cross-tool coordination. This eliminates the theoretical conflict window
//! between stopped sdme containers and nspawn's `pick`.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{bail, Context, Result};
use rayon::prelude::*;

use crate::{lock, State};

/// Minimum UID base for container user namespaces (matches systemd's
/// CONTAINER_UID_BASE_MIN = 0x00080000).
const UID_BASE_MIN: u64 = 0x0008_0000; // 524288

/// Maximum UID base for container user namespaces (matches systemd's
/// CONTAINER_UID_BASE_MAX = 0x6FFF0000).
const UID_BASE_MAX: u64 = 0x6FFF_0000; // 1879048192

/// Number of UIDs per container namespace.
pub const UID_RANGE: u64 = 0x1_0000; // 65536

/// SipHash-2-4 key used by nspawn's `uid_shift_pick()` to hash the
/// machine name into a candidate UID shift. Extracted from systemd
/// source (src/nspawn/nspawn.c).
const SIPHASH_KEY: [u8; 16] = [
    0xe1, 0x56, 0xe0, 0xf0, 0x4a, 0xf0, 0x41, 0xaf, 0x96, 0x41, 0xcf, 0x41, 0x33, 0x94, 0xff, 0x72,
];

/// Maximum allocation attempts before giving up.
const MAX_RETRIES: u32 = 100;

/// Read the parent user namespace mapping for UID 0.
///
/// Returns `(outside_start, length)` from the `/proc/self/uid_map` line whose
/// inside start is `0`. In the initial user namespace this is `(0, 2^32-1)`;
/// inside an nspawn container it is the host base and length of the range
/// mapped for the container (e.g. `(524288, 65536)`).
pub fn current_parent_range() -> Option<(u64, u64)> {
    let content = fs::read_to_string("/proc/self/uid_map").ok()?;
    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 && parts[0] == "0" {
            let outside = parts[1].parse().ok()?;
            let length = parts[2].parse().ok()?;
            return Some((outside, length));
        }
    }
    None
}

/// Return true if the current process is running in the initial user namespace.
///
/// The initial user namespace maps all 32-bit UIDs 1:1, so its uid_map is
/// exactly `0 0 4294967295`.
pub fn is_initial_user_namespace() -> bool {
    matches!(current_parent_range(), Some((0, 0xFFFF_FFFF)))
}

/// Return the host base of the current user namespace (the outside start of
/// the UID-0 mapping). In the initial user namespace this is `0`.
pub fn current_userns_base() -> u64 {
    current_parent_range().map(|(base, _)| base).unwrap_or(0)
}

/// Reserve a contiguous UID/GID range for a container.
///
/// The base matches nspawn's `pick` algorithm: the same SipHash-2-4 hash of
/// the machine name with the same key, so for a given container name the
/// result is what `--private-users=pick` would choose (absent conflicts).
/// Conflicts are checked against other sdme containers with a stored
/// `USERNS_SHIFT` and against currently running machines (via
/// `/proc/{leader}/uid_map`).
///
/// `extra_64k_slots` requests additional 64K ranges beyond the container's own
/// range. A value of `0` allocates the usual single 64K block; `N` allocates
/// `(1 + N) * 65536` contiguous IDs. The returned `base` is the absolute host
/// UID/GID at the start of the block, and `range` is the total length.
///
/// When running inside an existing user namespace, the block is constrained to
/// fit entirely within the parent namespace's mapped range. Inner containers
/// can then allocate offsets inside this block.
///
/// The range is written to the container's state file as `USERNS_SHIFT` and
/// `USERNS_RANGE` before the "userns" lock is released, so a concurrent
/// `sdme create` waits and then sees it. Use [`release_uid_range`] to give it
/// back if the caller cannot finish setting the container up.
pub fn reserve_uid_range(datadir: &Path, name: &str, extra_64k_slots: u32) -> Result<(u64, u64)> {
    let parent = current_parent_range().context("failed to read current user namespace range")?;
    // Queried before taking the lock: running machines are not what the lock
    // serializes, and each lookup is a D-Bus round trip.
    let running = running_machine_ranges();
    reserve_uid_range_in(datadir, name, extra_64k_slots, parent, &running)
}

/// [`reserve_uid_range`] with the parent mapping and running machines supplied.
fn reserve_uid_range_in(
    datadir: &Path,
    name: &str,
    extra_64k_slots: u32,
    parent: (u64, u64),
    running: &[UsedRange],
) -> Result<(u64, u64)> {
    let slots = 1u64 + u64::from(extra_64k_slots);
    let total_range = slots
        .checked_mul(UID_RANGE)
        .context("requested UID range overflow")?;

    let _lock = lock::lock_exclusive_blocking(datadir, "userns", "shift")
        .context("cannot lock userns allocation")?;

    let mut used = stored_ranges(datadir, name);
    used.extend_from_slice(running);
    let (base, range) = pick_uid_range(name, total_range, parent, &used)?;

    let state_path = datadir.join("state").join(name);
    let mut state = State::read_from(&state_path)?;
    state.set("USERNS_SHIFT", base.to_string());
    state.set("USERNS_RANGE", range.to_string());
    state.write_to(&state_path)?;

    Ok((base, range))
}

/// Drop a container's reserved UID/GID range from its state file.
///
/// Without a stored shift the container starts with `--private-users=pick`.
pub fn release_uid_range(datadir: &Path, name: &str) -> Result<()> {
    let _lock = lock::lock_exclusive_blocking(datadir, "userns", "shift")
        .context("cannot lock userns allocation")?;
    let state_path = datadir.join("state").join(name);
    let mut state = State::read_from(&state_path)?;
    state.remove("USERNS_SHIFT");
    state.remove("USERNS_RANGE");
    state.write_to(&state_path)
}

/// Pick a free block of `total_range` IDs for `name` inside the parent mapping.
fn pick_uid_range(
    name: &str,
    total_range: u64,
    (parent_base, parent_range): (u64, u64),
    used: &[UsedRange],
) -> Result<(u64, u64)> {
    // Determine the usable absolute host range. It must be inside both the
    // global [UID_BASE_MIN, UID_BASE_MAX] window and the current parent namespace.
    let global_min = UID_BASE_MIN;
    let global_max = UID_BASE_MAX;

    let usable_min = parent_base.max(global_min);
    let usable_end = parent_base
        .saturating_add(parent_range)
        .min(global_max.saturating_add(UID_RANGE));

    if usable_min + total_range > usable_end {
        bail!(
            "parent user namespace only provides {} UIDs starting at {}, \
             but {} UIDs are required",
            parent_range,
            parent_base,
            total_range
        );
    }

    // First candidate: SipHash of the machine name (matches nspawn's pick).
    let hash = siphash24(name.as_bytes(), &SIPHASH_KEY);
    let mut candidate = hash_to_shift(hash);

    // Clamp the SipHash candidate into the usable window and align it.
    if candidate < usable_min {
        candidate = usable_min + ((usable_min - candidate + UID_RANGE - 1) & !0xFFFF);
    }
    if candidate + total_range > usable_end {
        candidate = usable_min;
    }
    candidate &= !0xFFFF;

    for _ in 0..MAX_RETRIES {
        if candidate + total_range <= usable_end && range_is_free(candidate, total_range, used) {
            return Ok((candidate, total_range));
        }

        // Linear probe for the next free slot.
        candidate = candidate.saturating_add(UID_RANGE);
        if candidate + total_range > usable_end {
            candidate = usable_min;
        }
        candidate &= !0xFFFF;
    }

    bail!(
        "failed to allocate UID range of size {total_range} after {MAX_RETRIES} attempts \
         (all slots in use)"
    )
}

/// Check whether a stored UID shift conflicts with any currently running machine.
///
/// Returns the name of the conflicting machine if found.
pub fn check_shift_conflict(name: &str, shift: u64) -> Option<String> {
    for (machine, machine_shift) in running_machine_shifts() {
        if machine != name && machine_shift == shift {
            return Some(machine);
        }
    }
    None
}

/// Pre-chown an overlayfs rootfs in parallel to shift UIDs for user namespaces.
///
/// Mounts the overlayfs temporarily, walks the merged tree with rayon, and
/// shifts all UIDs/GIDs in range 0..65535 by the local shift. This triggers
/// copy-ups to the upper layer (intended). After unmounting, the upper layer
/// retains the shifted ownership so nspawn's boot-time chown is a no-op.
///
/// `absolute_shift` is the host-level UID base stored in the container state.
/// Inside a nested container this is converted to a local offset before calling
/// `lchown()`, because `lchown()` interprets UIDs in the current namespace.
pub fn prechown_overlayfs(
    datadir: &Path,
    name: &str,
    lowerdir: &str,
    absolute_shift: u64,
) -> Result<()> {
    let container_dir = datadir.join("containers").join(name);
    let upper = container_dir.join("upper");
    let work = container_dir.join("work");
    let merged = container_dir.join("merged");

    let opts = format!(
        "lowerdir={lowerdir},upperdir={},workdir={}",
        upper.display(),
        work.display()
    );
    crate::system_check::mount_overlay(&merged, &opts)
        .context("failed to mount overlayfs for pre-chown")?;

    let local_shift = absolute_shift.saturating_sub(current_userns_base());
    if local_shift > u64::from(u32::MAX) {
        bail!("local UID shift {local_shift} exceeds u32");
    }
    let result = do_prechown(&merged, local_shift);

    if let Err(e) = crate::system_check::umount(&merged) {
        if result.is_ok() {
            return Err(e).context("failed to unmount overlayfs after pre-chown");
        }
        eprintln!("warning: failed to unmount overlayfs after pre-chown: {e:#}");
    }

    result
}

/// Walk a directory tree and shift UIDs/GIDs in parallel.
fn do_prechown(root: &Path, shift: u64) -> Result<()> {
    let shift_uid = shift as u32;
    let counter = AtomicU64::new(0);
    let errors = std::sync::Mutex::new(Vec::<String>::new());

    // Collect all entries first, then chown in parallel. We collect rather
    // than walk in parallel because readdir order matters for overlayfs
    // copy-up consistency (parent dirs must exist in upper before children).
    let entries = collect_entries(root)?;
    let total = entries.len() as u64;

    eprint!("pre-chown: shifting {total} files 1");

    let last_milestone = AtomicU64::new(0);
    let interrupted = std::sync::atomic::AtomicBool::new(false);

    entries.par_iter().for_each(|path| {
        // Check for Ctrl+C; once seen, skip remaining work.
        if interrupted.load(Ordering::Relaxed) {
            return;
        }
        if crate::INTERRUPTED.load(Ordering::Relaxed) {
            interrupted.store(true, Ordering::Relaxed);
            return;
        }
        if let Err(e) = shift_ownership(path, shift_uid) {
            let mut errs = errors.lock().unwrap();
            if errs.len() < 10 {
                errs.push(format!("{}: {e}", path.display()));
            }
        }
        let count = counter.fetch_add(1, Ordering::Relaxed) + 1;
        if let Some(pct) = (count * 100).checked_div(total) {
            let pct = pct.min(100);
            let target = (pct / 2) * 2;
            loop {
                let prev = last_milestone.load(Ordering::Relaxed);
                if target <= prev {
                    break;
                }
                match last_milestone.compare_exchange_weak(
                    prev,
                    target,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        use std::io::Write;
                        let stderr = std::io::stderr();
                        let mut lock = stderr.lock();
                        let mut m = prev + 2;
                        while m <= target {
                            if m == 100 {
                                let _ = write!(lock, "100%");
                            } else if m.is_multiple_of(10) {
                                let _ = write!(lock, "{m}");
                            } else {
                                let _ = write!(lock, ".");
                            }
                            m += 2;
                        }
                        let _ = lock.flush();
                        break;
                    }
                    Err(_) => continue,
                }
            }
        }
    });

    eprintln!();

    crate::check_interrupted()?;

    let errs = errors.into_inner().unwrap();
    if !errs.is_empty() {
        let first_few = errs.join("; ");
        bail!("pre-chown failed on {n} files: {first_few}", n = errs.len());
    }

    Ok(())
}

/// Recursively collect all filesystem entries under `root`.
///
/// The rootfs under the overlay is not frozen while it is walked: it can be
/// edited in place, and `sdme cp` can write to it. An entry that is gone by
/// the time the walk reaches it has nothing left to shift and is skipped, here
/// and in [`shift_ownership`]. Only `root` itself must exist.
fn collect_entries(root: &Path) -> Result<Vec<PathBuf>> {
    let mut entries = Vec::new();
    let read_dir = fs::read_dir(root)
        .with_context(|| format!("failed to read directory {}", root.display()))?;
    collect_dir_entries(root, read_dir, &mut entries)?;
    Ok(entries)
}

fn collect_dir_entries(dir: &Path, read_dir: fs::ReadDir, out: &mut Vec<PathBuf>) -> Result<()> {
    crate::check_interrupted()?;

    for entry in read_dir {
        let entry = entry.with_context(|| format!("failed to read entry in {}", dir.display()))?;
        let path = entry.path();
        out.push(path.clone());

        // Follow directory entries but not symlinks (avoid loops).
        let ft = match entry.file_type() {
            Ok(ft) => ft,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("failed to get file type for {}", path.display()))
            }
        };
        if ft.is_dir() {
            match fs::read_dir(&path) {
                Ok(sub) => collect_dir_entries(&path, sub, out)?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(e)
                        .with_context(|| format!("failed to read directory {}", path.display()))
                }
            }
        }
    }
    Ok(())
}

/// Shift ownership of a single file/dir/symlink.
///
/// A path that no longer exists is not an error; see [`collect_entries`].
fn shift_ownership(path: &Path, shift: u32) -> Result<()> {
    use std::io::ErrorKind::NotFound;

    let meta = match path.symlink_metadata() {
        Ok(meta) => meta,
        Err(e) if e.kind() == NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("stat {}", path.display())),
    };

    let uid = meta.uid();
    let gid = meta.gid();

    // Only shift UIDs/GIDs in the unprivileged range (0..65535).
    // UIDs >= 65536 are left alone (they may belong to other
    // namespaces or already be shifted).
    let new_uid = if uid < UID_RANGE as u32 {
        uid + shift
    } else {
        uid
    };
    let new_gid = if gid < UID_RANGE as u32 {
        gid + shift
    } else {
        gid
    };

    if new_uid == uid && new_gid == gid {
        return Ok(());
    }

    let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .context("path contains null byte")?;

    // AT_SYMLINK_NOFOLLOW: change the symlink itself, not the target.
    let ret = unsafe { libc::lchown(c_path.as_ptr(), new_uid, new_gid) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        if err.kind() == NotFound {
            return Ok(());
        }
        bail!("lchown {}: {err}", path.display());
    }

    // chown clears the setuid/setgid bits on Linux, even for root, so a
    // pre-installed setuid binary (e.g. sudo, 04755) would come out 0755 and
    // stop working once the container boots. Re-apply the original mode for
    // files that carry those bits. Skip symlinks: they have no meaningful
    // mode and chmod would follow to the target; they never carry suid/sgid
    // anyway. Guarding on 0o6000 keeps the extra syscall off the vast majority
    // of files in a full rootfs walk (chown only ever clears those two bits).
    let mode = meta.mode();
    if !meta.file_type().is_symlink() && mode & 0o6000 != 0 {
        let ret = unsafe { libc::chmod(c_path.as_ptr(), (mode & 0o7777) as libc::mode_t) };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == NotFound {
                return Ok(());
            }
            bail!("chmod {}: {err}", path.display());
        }
    }
    Ok(())
}

/// A used UID/GID range collected from state files or running machines.
#[derive(Debug, Clone, Copy)]
struct UsedRange {
    start: u64,
    len: u64,
}

/// Collect the UID ranges other sdme containers have stored in their state.
fn stored_ranges(datadir: &Path, exclude_name: &str) -> Vec<UsedRange> {
    let mut used = Vec::new();

    let state_dir = datadir.join("state");
    if let Ok(entries) = fs::read_dir(&state_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name == exclude_name {
                continue;
            }
            if let Ok(state) = State::read_from(&entry.path()) {
                if let Some(shift_str) = state.get_nonempty("USERNS_SHIFT") {
                    if let Ok(start) = shift_str.parse::<u64>() {
                        let len = state
                            .get_nonempty("USERNS_RANGE")
                            .and_then(|s| s.parse::<u64>().ok())
                            .unwrap_or(UID_RANGE);
                        used.push(UsedRange { start, len });
                    }
                }
            }
        }
    }

    used
}

/// Collect the UID ranges of running machines via `/proc/{leader}/uid_map`.
///
/// Their configured range is not known, so the standard 64K is assumed.
fn running_machine_ranges() -> Vec<UsedRange> {
    running_machine_shifts()
        .into_iter()
        .map(|(_, shift)| UsedRange {
            start: shift,
            len: UID_RANGE,
        })
        .collect()
}

/// Check whether `[start, start + len)` overlaps any used range.
fn range_is_free(start: u64, len: u64, used: &[UsedRange]) -> bool {
    let end = match start.checked_add(len) {
        Some(e) => e,
        None => return false,
    };
    for r in used {
        let r_end = r.start.saturating_add(r.len);
        if start < r_end && end > r.start {
            return false;
        }
    }
    true
}

/// Read UID shifts of all currently running machines from machined.
fn running_machine_shifts() -> Vec<(String, u64)> {
    let mut shifts = Vec::new();
    for name in crate::systemd::list_machines() {
        if let Ok(Some(leader)) = crate::systemd::get_machine_leader(&name) {
            if let Some(shift) = read_uid_map_shift(leader) {
                shifts.push((name, shift));
            }
        }
    }
    shifts
}

/// Parse the UID shift from /proc/{pid}/uid_map.
///
/// The format is: `<inside_start> <outside_start> <count>`
/// For nspawn containers: `0 <shift> 65536`
fn read_uid_map_shift(pid: u32) -> Option<u64> {
    let path = format!("/proc/{pid}/uid_map");
    let content = fs::read_to_string(&path).ok()?;
    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 && parts[0] == "0" {
            return parts[1].parse().ok();
        }
    }
    None
}

/// Convert a SipHash-2-4 output to a UID shift in the valid range.
///
/// Matches nspawn's algorithm exactly. nspawn casts the 64-bit siphash
/// result to `uid_t` (uint32_t) before computing the modulo:
/// `candidate = (uid_t) siphash24(...);`
/// `candidate = (candidate % (MAX - MIN)) + MIN;`
/// `candidate &= 0xFFFF0000;`
fn hash_to_shift(hash: u64) -> u64 {
    // Truncate to 32 bits first, matching nspawn's (uid_t) cast.
    let truncated = hash as u32 as u64;
    let range = UID_BASE_MAX - UID_BASE_MIN;
    let candidate = (truncated % range) + UID_BASE_MIN;
    candidate & !0xFFFF
}

// ---------------------------------------------------------------------------
// SipHash-2-4 implementation (public domain, from the SipHash reference).
//
// We inline this rather than adding a crate dependency because it's small
// and we need to match systemd's exact output for a specific key.
// ---------------------------------------------------------------------------

fn siphash24(data: &[u8], key: &[u8; 16]) -> u64 {
    let k0 = u64::from_le_bytes(key[..8].try_into().unwrap());
    let k1 = u64::from_le_bytes(key[8..].try_into().unwrap());

    let mut v0: u64 = 0x736f6d6570736575 ^ k0;
    let mut v1: u64 = 0x646f72616e646f6d ^ k1;
    let mut v2: u64 = 0x6c7967656e657261 ^ k0;
    let mut v3: u64 = 0x7465646279746573 ^ k1;

    let len = data.len();
    let blocks = len / 8;

    for i in 0..blocks {
        let m = u64::from_le_bytes(data[i * 8..(i + 1) * 8].try_into().unwrap());
        v3 ^= m;
        sipround(&mut v0, &mut v1, &mut v2, &mut v3);
        sipround(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= m;
    }

    let mut last: u64 = (len as u64) << 56;
    let remaining = &data[blocks * 8..];
    for (i, &byte) in remaining.iter().enumerate() {
        last |= (byte as u64) << (i * 8);
    }

    v3 ^= last;
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= last;

    v2 ^= 0xff;
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);

    v0 ^ v1 ^ v2 ^ v3
}

#[inline]
fn sipround(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = v1.rotate_left(13);
    *v1 ^= *v0;
    *v0 = v0.rotate_left(32);
    *v2 = v2.wrapping_add(*v3);
    *v3 = v3.rotate_left(16);
    *v3 ^= *v2;
    *v0 = v0.wrapping_add(*v3);
    *v3 = v3.rotate_left(21);
    *v3 ^= *v0;
    *v2 = v2.wrapping_add(*v1);
    *v1 = v1.rotate_left(17);
    *v1 ^= *v2;
    *v2 = v2.rotate_left(32);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDataDir;

    #[test]
    fn test_hash_to_shift_alignment() {
        // All shifts must be 64K-aligned.
        for i in 0..100u64 {
            let shift = hash_to_shift(i * 12345);
            assert_eq!(shift & 0xFFFF, 0, "shift {shift} not 64K-aligned");
            assert!(shift >= UID_BASE_MIN, "shift {shift} below minimum");
            assert!(shift <= UID_BASE_MAX, "shift {shift} above maximum");
        }
    }

    #[test]
    fn test_siphash24_known_vector() {
        // SipHash-2-4 test vector from the reference implementation:
        // key = 00 01 02 ... 0f, data = 00 01 02 ... 0e (15 bytes)
        // expected = a129ca6149be45e5
        let key: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let data: Vec<u8> = (0u8..15).collect();
        let result = siphash24(&data, &key);
        assert_eq!(result, 0xa129ca6149be45e5, "SipHash test vector mismatch");
    }

    #[test]
    fn test_siphash24_deterministic() {
        let hash1 = siphash24(b"test-machine", &SIPHASH_KEY);
        let hash2 = siphash24(b"test-machine", &SIPHASH_KEY);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_siphash24_different_names() {
        let hash1 = siphash24(b"container-a", &SIPHASH_KEY);
        let hash2 = siphash24(b"container-b", &SIPHASH_KEY);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_nspawn_shift_for_known_name() {
        // Verify our hash matches nspawn's output for a known container name.
        // From the user's journal: container "iporakepaba" got shift 1678049280.
        let hash = siphash24(b"iporakepaba", &SIPHASH_KEY);
        let shift = hash_to_shift(hash);
        assert_eq!(
            shift, 1678049280,
            "shift for 'iporakepaba' does not match nspawn's output"
        );
    }

    #[test]
    fn test_range_is_free() {
        let used = vec![
            UsedRange {
                start: 0x8_0000,
                len: 0x1_0000,
            },
            UsedRange {
                start: 0xA_0000,
                len: 0x2_0000,
            },
        ];
        assert!(range_is_free(0x9_0000, 0x1_0000, &used));
        assert!(!range_is_free(0x8_0000, 0x1_0000, &used));
        assert!(!range_is_free(0x7_FFFF, 0x2_0000, &used));
        assert!(!range_is_free(0x9_FFFF, 0x2_0000, &used));
        assert!(!range_is_free(0xA_0001, 0x1_0000, &used));
    }

    /// The initial namespace mapping, so reservations do not depend on the
    /// namespace the tests happen to run in.
    const FULL_PARENT: (u64, u64) = (0, 0xFFFF_FFFF);

    fn datadir_with_containers(prefix: &str, names: &[&str]) -> TempDataDir {
        let tmp = TempDataDir::new(prefix);
        let state_dir = tmp.path().join("state");
        fs::create_dir_all(&state_dir).unwrap();
        for name in names {
            State::new().write_to(&state_dir.join(name)).unwrap();
        }
        tmp
    }

    fn first_candidate(name: &str) -> u64 {
        hash_to_shift(siphash24(name.as_bytes(), &SIPHASH_KEY))
    }

    /// Two container names that hash to the same first candidate.
    fn colliding_names() -> (String, String) {
        let mut seen = std::collections::HashMap::new();
        for i in 0u32.. {
            let name = format!("ct{i}");
            if let Some(other) = seen.insert(first_candidate(&name), name.clone()) {
                return (other, name);
            }
        }
        unreachable!()
    }

    fn stored_range(datadir: &Path, name: &str) -> Option<(u64, u64)> {
        let state = State::read_from(&datadir.join("state").join(name)).unwrap();
        let shift = state.get_nonempty("USERNS_SHIFT")?.parse().ok()?;
        let range = state.get_nonempty("USERNS_RANGE")?.parse().ok()?;
        Some((shift, range))
    }

    fn overlaps(a: (u64, u64), b: (u64, u64)) -> bool {
        a.0 < b.0 + b.1 && b.0 < a.0 + a.1
    }

    #[test]
    fn test_reserve_stores_the_range() {
        let tmp = datadir_with_containers("userns-store", &["web"]);
        let got = reserve_uid_range_in(tmp.path(), "web", 1, FULL_PARENT, &[]).unwrap();
        assert_eq!(got, (first_candidate("web"), 2 * UID_RANGE));
        assert_eq!(stored_range(tmp.path(), "web"), Some(got));
    }

    #[test]
    fn test_reserve_skips_a_stored_range() {
        let (a, b) = colliding_names();
        let tmp = datadir_with_containers("userns-skip", &[&a, &b]);
        let first = reserve_uid_range_in(tmp.path(), &a, 0, FULL_PARENT, &[]).unwrap();
        let second = reserve_uid_range_in(tmp.path(), &b, 0, FULL_PARENT, &[]).unwrap();
        assert_eq!(first.0, first_candidate(&b), "names do not collide");
        assert!(!overlaps(first, second), "{first:?} overlaps {second:?}");
    }

    #[test]
    fn test_reserve_skips_a_running_machine() {
        let tmp = datadir_with_containers("userns-running", &["web"]);
        let running = [UsedRange {
            start: first_candidate("web"),
            len: UID_RANGE,
        }];
        let got = reserve_uid_range_in(tmp.path(), "web", 0, FULL_PARENT, &running).unwrap();
        assert!(!overlaps(got, (running[0].start, running[0].len)));
    }

    #[test]
    fn test_reserve_concurrent_ranges_are_disjoint() {
        let (a, b) = colliding_names();
        let mut names = vec![a, b];
        names.extend((0..6).map(|i| format!("extra{i}")));
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let tmp = datadir_with_containers("userns-concurrent", &refs);

        let ranges: Vec<(u64, u64)> = std::thread::scope(|scope| {
            let handles: Vec<_> = names
                .iter()
                .map(|name| {
                    let dir = tmp.path();
                    scope.spawn(move || reserve_uid_range_in(dir, name, 0, FULL_PARENT, &[]))
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().unwrap().expect("a concurrent reservation failed"))
                .collect()
        });

        for (i, x) in ranges.iter().enumerate() {
            for y in &ranges[i + 1..] {
                assert!(!overlaps(*x, *y), "{x:?} overlaps {y:?}");
            }
        }
    }

    #[test]
    fn test_release_frees_the_range() {
        let (a, b) = colliding_names();
        let tmp = datadir_with_containers("userns-release", &[&a, &b]);
        let first = reserve_uid_range_in(tmp.path(), &a, 0, FULL_PARENT, &[]).unwrap();
        release_uid_range(tmp.path(), &a).unwrap();
        assert_eq!(stored_range(tmp.path(), &a), None);
        let second = reserve_uid_range_in(tmp.path(), &b, 0, FULL_PARENT, &[]).unwrap();
        assert_eq!(second, first, "released range was not reusable");
    }

    #[test]
    fn test_prechown_skips_entries_that_vanished() {
        let tmp = TempDataDir::new("userns-vanish");
        let root = tmp.path();
        fs::create_dir_all(root.join("etc")).unwrap();
        fs::write(root.join("etc/hosts"), b"x").unwrap();

        // Listed by the walk, gone before it is shifted.
        shift_ownership(&root.join("tmp/removed-file"), 0x8_0000).unwrap();

        // The walk reports what is still there.
        let mut entries = collect_entries(root).unwrap();
        entries.sort();
        assert_eq!(entries, vec![root.join("etc"), root.join("etc/hosts")]);

        // The root of the walk itself has to exist.
        assert!(collect_entries(&root.join("missing")).is_err());
    }

    #[test]
    fn test_parent_range_parses() {
        // A restricted test sandbox may expose only the caller's single-ID
        // mapping, with no allocatable parent range. That is a supported
        // runtime condition, not a parser failure.
        let Some((base, len)) = current_parent_range() else {
            return;
        };
        assert!(len > 0, "uid_map length must be positive");
        if is_initial_user_namespace() {
            assert_eq!(base, 0);
            assert_eq!(len, 0xFFFF_FFFF);
        }
    }

    #[test]
    fn test_shift_ownership_preserves_setuid_setgid() {
        use std::os::unix::fs::PermissionsExt;

        // chown to a new UID requires CAP_CHOWN, so this can only exercise the
        // real shift as root. Skip otherwise, mirroring the root-gating in
        // import's test_import_preserves_permissions.
        if unsafe { libc::geteuid() } != 0 {
            return;
        }

        let dir = std::env::temp_dir().join(format!(
            "sdme-test-userns-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let shift = 0x8_0000u32; // 524288: a valid 64K-aligned base.

        for (name, mode) in [("suid", 0o4755u32), ("sgid", 0o2755u32)] {
            let path = dir.join(name);
            fs::write(&path, b"x").unwrap();

            // Normalize ownership to 0:0 so the expected shifted owner is
            // deterministic, then set the mode (chmod after chown restores the
            // special bit that the normalizing lchown cleared).
            let cpath = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
            assert_eq!(unsafe { libc::lchown(cpath.as_ptr(), 0, 0) }, 0);
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();

            shift_ownership(&path, shift).unwrap();

            let meta = fs::symlink_metadata(&path).unwrap();
            assert_eq!(meta.uid(), shift, "{name}: uid not shifted");
            assert_eq!(meta.gid(), shift, "{name}: gid not shifted");
            assert_eq!(
                meta.mode() & 0o7777,
                mode,
                "{name}: special bit dropped by pre-chown"
            );
        }

        let _ = fs::remove_dir_all(&dir);
    }
}
