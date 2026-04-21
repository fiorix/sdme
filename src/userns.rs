//! User namespace UID shift allocation and pre-chown for overlayfs.
//!
//! When the kernel does not support idmapped mounts on overlayfs, nspawn's
//! `--private-users-ownership=auto` falls back to a slow recursive chown
//! that triggers full copy-ups on every file. This module provides:
//!
//! - Deterministic UID shift allocation matching nspawn's `--private-users=pick`
//! - Conflict detection against other sdme containers and running machines
//! - Parallel pre-chown at create time so boot is fast
//!
//! # TODO
//!
//! On systemd 256+, register UID ranges with nsresourced for persistent
//! cross-tool coordination. This eliminates the theoretical conflict window
//! between stopped sdme containers and nspawn's `pick`.

use std::collections::HashSet;
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
const UID_RANGE: u64 = 0x1_0000; // 65536

/// SipHash-2-4 key used by nspawn's `uid_shift_pick()` to hash the
/// machine name into a candidate UID shift. Extracted from systemd
/// source (src/nspawn/nspawn.c).
const SIPHASH_KEY: [u8; 16] = [
    0xe1, 0x56, 0xe0, 0xf0, 0x4a, 0xf0, 0x41, 0xaf, 0x96, 0x41, 0xcf, 0x41, 0x33, 0x94, 0xff, 0x72,
];

/// Maximum allocation attempts before giving up.
const MAX_RETRIES: u32 = 100;

/// Allocate a UID shift for a container, matching nspawn's `pick` algorithm.
///
/// Uses the same SipHash-2-4 hash of the machine name with the same key
/// as nspawn, so for a given container name the result matches what
/// `--private-users=pick` would choose (absent conflicts).
///
/// Checks for conflicts against:
/// - Other sdme containers with stored `USERNS_SHIFT` values
/// - Currently running machines (via `/proc/{leader}/uid_map`)
///
/// Acquires an exclusive lock on the "userns" resource to prevent races
/// between concurrent `sdme create` calls.
pub fn allocate_uid_shift(datadir: &Path, name: &str) -> Result<u64> {
    let _lock = lock::lock_exclusive(datadir, "userns", "shift")
        .context("cannot lock userns allocation")?;

    let used = collect_used_shifts(datadir, name)?;

    // First candidate: SipHash of the machine name (matches nspawn's pick).
    let hash = siphash24(name.as_bytes(), &SIPHASH_KEY);
    let mut candidate = hash_to_shift(hash);

    for _ in 0..MAX_RETRIES {
        if (UID_BASE_MIN..=UID_BASE_MAX).contains(&candidate)
            && candidate & 0xFFFF == 0
            && !used.contains(&candidate)
        {
            return Ok(candidate);
        }

        // Linear probe for the next free slot (nspawn uses random_bytes
        // for retries, but linear is deterministic and avoids a CSPRNG).
        candidate =
            UID_BASE_MIN + ((candidate - UID_BASE_MIN + UID_RANGE) % (UID_BASE_MAX - UID_BASE_MIN));
        candidate &= !0xFFFF;
    }

    bail!(
        "failed to allocate UID shift after {MAX_RETRIES} attempts \
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
/// shifts all UIDs/GIDs in range 0..65535 by `shift`. This triggers copy-ups
/// to the upper layer (intended). After unmounting, the upper layer retains
/// the shifted ownership so nspawn's boot-time chown is a no-op.
pub fn prechown_overlayfs(datadir: &Path, name: &str, lowerdir: &str, shift: u64) -> Result<()> {
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

    let result = do_prechown(&merged, shift);

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
fn collect_entries(root: &Path) -> Result<Vec<PathBuf>> {
    let mut entries = Vec::new();
    collect_entries_recursive(root, &mut entries)?;
    Ok(entries)
}

fn collect_entries_recursive(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    crate::check_interrupted()?;
    let read_dir =
        fs::read_dir(dir).with_context(|| format!("failed to read directory {}", dir.display()))?;

    for entry in read_dir {
        let entry = entry.with_context(|| format!("failed to read entry in {}", dir.display()))?;
        let path = entry.path();
        out.push(path.clone());

        // Follow directory entries but not symlinks (avoid loops).
        let ft = entry
            .file_type()
            .with_context(|| format!("failed to get file type for {}", path.display()))?;
        if ft.is_dir() {
            collect_entries_recursive(&path, out)?;
        }
    }
    Ok(())
}

/// Shift ownership of a single file/dir/symlink.
fn shift_ownership(path: &Path, shift: u32) -> Result<()> {
    let meta = path
        .symlink_metadata()
        .with_context(|| format!("stat {}", path.display()))?;

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
        bail!("lchown {}: {err}", path.display());
    }
    Ok(())
}

/// Collect UID shifts used by other sdme containers and running machines.
fn collect_used_shifts(datadir: &Path, exclude_name: &str) -> Result<HashSet<u64>> {
    let mut used = HashSet::new();

    // Scan sdme state files for USERNS_SHIFT.
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
                    if let Ok(shift) = shift_str.parse::<u64>() {
                        used.insert(shift);
                    }
                }
            }
        }
    }

    // Collect shifts from running machines via /proc/{leader}/uid_map.
    for (_, shift) in running_machine_shifts() {
        used.insert(shift);
    }

    Ok(used)
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
}
