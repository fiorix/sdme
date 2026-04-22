//! Container filesystem diff: show changes in overlayfs upper layers.
//!
//! Each sdme container mounts a copy-on-write overlay on top of an
//! immutable base rootfs. Files created, modified, or deleted inside the
//! container are recorded in the overlay's upper layer, so the difference
//! between the upper layer and the base rootfs is exactly what the user
//! changed at runtime. [`diff`] walks that upper layer and reports each
//! path with a single-character status:
//!
//! - `A` — file exists only in the upper (Added)
//! - `M` — file exists in both and differs (Modified)
//! - `D` — file was removed via an overlayfs whiteout (Deleted)
//!
//! Whiteouts are character devices with `rdev == 0`; opaque directories
//! carry the `trusted.overlay.opaque=y` xattr and hide every lower-layer
//! entry underneath them. Both are handled transparently.
//!
//! Range diffs between two containers (`sdme diff from..to`) compare the
//! two upper layers directly; files that exist in both but differ are
//! reported as Modified, everything else is Added/Deleted as one-sided.
//!
//! # CLI examples
//!
//! ```text
//! sdme diff mybox                 # against the base rootfs
//! sdme diff mybox -- /etc         # filter to /etc and below
//! sdme diff dev..prod --stat      # counts only
//! sdme diff mybox --name-only     # paths only, for scripting
//! ```

use std::collections::BTreeSet;
use std::ffi::{CString, OsStr};
use std::fmt;
use std::fs;
use std::io::{BufRead, BufReader};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::{check_interrupted, lock};

/// Change type for a file in the diff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    /// File exists only in the target (new file).
    Added,
    /// File exists in both but differs.
    Modified,
    /// File was removed (overlayfs whiteout).
    Deleted,
}

impl fmt::Display for ChangeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Added => write!(f, "A"),
            Self::Modified => write!(f, "M"),
            Self::Deleted => write!(f, "D"),
        }
    }
}

/// A single change entry in the diff output.
#[derive(Debug, Clone)]
pub struct DiffEntry {
    /// The type of change.
    pub kind: ChangeKind,
    /// Absolute path inside the container (e.g. `/etc/hostname`).
    pub path: String,
    /// Whether the file appears to be binary.
    pub is_binary: bool,
}

/// Options for the diff command.
pub struct DiffOptions {
    /// Show summary statistics only.
    pub stat: bool,
    /// Show only file paths (no status prefix).
    pub name_only: bool,
}

/// A parsed diff target.
#[derive(Debug)]
enum DiffTarget {
    /// Single container diff against base rootfs.
    Single { name: String },
    /// Range diff between two containers.
    Range { from: String, to: String },
}

/// Parse a diff target string into a `DiffTarget`.
///
/// Supported formats:
/// - `NAME`: single container diff against its base rootfs
/// - `FROM..TO`: range diff between two containers
fn parse_target(target: &str) -> Result<DiffTarget> {
    if let Some((from, to)) = target.split_once("..") {
        if from.is_empty() || to.is_empty() {
            bail!("invalid range: both sides of '..' must be container names");
        }
        Ok(DiffTarget::Range {
            from: from.to_string(),
            to: to.to_string(),
        })
    } else {
        Ok(DiffTarget::Single {
            name: target.to_string(),
        })
    }
}

/// Check if a metadata entry is an overlayfs whiteout file.
///
/// Overlayfs represents deleted files as character devices with major 0,
/// minor 0. The `rdev` field is 0 when both major and minor are 0.
fn is_whiteout(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_char_device() && metadata.rdev() == 0
}

/// Check if a directory has the `trusted.overlay.opaque` xattr set to `"y"`.
///
/// An opaque directory hides all lower layer contents, so everything
/// beneath it is effectively new (Added).
fn is_opaque_dir(path: &Path) -> bool {
    let c_path = match CString::new(path.as_os_str().as_encoded_bytes()) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let c_name = match CString::new("trusted.overlay.opaque") {
        Ok(n) => n,
        Err(_) => return false,
    };
    let mut buf = [0u8; 2];
    let ret = unsafe {
        libc::lgetxattr(
            c_path.as_ptr(),
            c_name.as_ptr(),
            buf.as_mut_ptr().cast::<libc::c_void>(),
            buf.len(),
        )
    };
    ret == 1 && buf[0] == b'y'
}

/// Check if a file appears to be binary by scanning its first bytes for NUL.
fn is_binary_file(path: &Path) -> bool {
    let Ok(file) = fs::File::open(path) else {
        return false;
    };
    let mut buf = [0u8; 8192];
    let Ok(n) = std::io::Read::read(&mut &file, &mut buf) else {
        return false;
    };
    buf[..n].contains(&0)
}

/// Check whether `abs_path` matches the filter. If `filters` is empty,
/// everything matches. Otherwise the path must be under (or equal to) one
/// of the filter paths, OR a filter path must be under this path (so the
/// traversal descends into directories on the way to a filter target).
///
/// Filters are compared as absolute path strings (e.g. `/etc`); the caller
/// is expected to pass normalized absolute paths. No string conversion
/// happens per entry — the input slice is consumed as-is.
fn matches_filter(abs_path: &str, filters: &[String]) -> bool {
    if filters.is_empty() {
        return true;
    }
    filters.iter().any(|f| path_relation_matches(abs_path, f))
}

/// Return true if `abs_path` is under `filter`, equal to it, or an ancestor
/// of it. Used by [`matches_filter`] and tested directly.
///
/// The trailing-slash check handles the root filter `/` correctly:
/// `"/etc".strip_prefix("/") = "etc"` has no leading slash, but the filter
/// itself ends in `/`, so the match still stands.
fn path_relation_matches(abs_path: &str, filter: &str) -> bool {
    if abs_path == filter {
        return true;
    }
    let path_under_filter = abs_path
        .strip_prefix(filter)
        .is_some_and(|rest| rest.starts_with('/') || filter.ends_with('/'));
    let filter_under_path = filter
        .strip_prefix(abs_path)
        .is_some_and(|rest| rest.starts_with('/') || abs_path.ends_with('/'));
    path_under_filter || filter_under_path
}

/// Read a directory and return its entries sorted by file name. Returns
/// errors from `read_dir` only; unreadable individual entries are dropped
/// silently (same policy as the original walkers).
fn sorted_dir_entries(dir: &Path) -> Result<Vec<fs::DirEntry>> {
    let mut items: Vec<_> = fs::read_dir(dir)
        .with_context(|| format!("failed to read {}", dir.display()))?
        .filter_map(|e| e.ok())
        .collect();
    items.sort_by_key(|e| e.file_name());
    Ok(items)
}

/// Build the relative path and the display-friendly absolute path string
/// for an entry under `prefix`.
fn rel_and_abs(prefix: &Path, name: &OsStr) -> (PathBuf, String) {
    let name_str = name.to_string_lossy();
    let rel = prefix.join(&*name_str);
    let abs_path = format!("/{}", rel.display());
    (rel, abs_path)
}

/// Walk the upper layer and collect diff entries against the lower layer.
fn collect_upper_diff(
    upper: &Path,
    lower: &Path,
    prefix: &Path,
    filters: &[String],
    entries: &mut Vec<DiffEntry>,
) -> Result<()> {
    let dir = upper.join(prefix);
    if !dir.is_dir() {
        return Ok(());
    }

    for entry in sorted_dir_entries(&dir)? {
        check_interrupted()?;
        let (rel, abs_path) = rel_and_abs(prefix, &entry.file_name());
        if !matches_filter(&abs_path, filters) {
            continue;
        }
        let Ok(metadata) = entry.path().symlink_metadata() else {
            continue;
        };

        if is_whiteout(&metadata) {
            entries.push(DiffEntry {
                kind: ChangeKind::Deleted,
                path: abs_path,
                is_binary: false,
            });
            continue;
        }

        let upper_path = entry.path();
        if metadata.is_dir() {
            if is_opaque_dir(&upper_path) {
                // Opaque directory: lower layer is hidden, everything is Added.
                collect_all_as(&upper_path, &rel, ChangeKind::Added, filters, entries)?;
            } else {
                // Regular directory: recurse.
                collect_upper_diff(upper, lower, &rel, filters, entries)?;
            }
            continue;
        }

        // Regular file or symlink.
        let kind = if lower.join(&rel).symlink_metadata().is_ok() {
            ChangeKind::Modified
        } else {
            ChangeKind::Added
        };
        let is_binary = metadata.is_file() && is_binary_file(&upper_path);
        entries.push(DiffEntry {
            kind,
            path: abs_path,
            is_binary,
        });
    }
    Ok(())
}

/// Recursively collect all files under a directory with a fixed change kind.
///
/// Used for opaque directories (all Added) and one-sided range diffs.
fn collect_all_as(
    dir: &Path,
    prefix: &Path,
    kind: ChangeKind,
    filters: &[String],
    entries: &mut Vec<DiffEntry>,
) -> Result<()> {
    for entry in sorted_dir_entries(dir)? {
        check_interrupted()?;
        let (rel, abs_path) = rel_and_abs(prefix, &entry.file_name());
        if !matches_filter(&abs_path, filters) {
            continue;
        }
        let Ok(metadata) = entry.path().symlink_metadata() else {
            continue;
        };

        if metadata.is_dir() {
            collect_all_as(&entry.path(), &rel, kind, filters, entries)?;
        } else {
            let is_binary = metadata.is_file() && is_binary_file(&entry.path());
            entries.push(DiffEntry {
                kind,
                path: abs_path,
                is_binary,
            });
        }
    }
    Ok(())
}

/// Walk both upper layers and collect differences between them.
///
/// Semantics: what changed going from `from_upper` to `to_upper`.
/// - Files only in `to_upper` → Added
/// - Files only in `from_upper` → Deleted
/// - Files in both with different content → Modified
fn collect_range_diff(
    from_upper: &Path,
    to_upper: &Path,
    prefix: &Path,
    filters: &[String],
    entries: &mut Vec<DiffEntry>,
) -> Result<()> {
    let from_dir = from_upper.join(prefix);
    let to_dir = to_upper.join(prefix);

    // Collect names from both sides.
    let from_names = list_dir_names(&from_dir);
    let to_names = list_dir_names(&to_dir);
    let all_names: BTreeSet<_> = from_names.union(&to_names).cloned().collect();

    for name in &all_names {
        check_interrupted()?;

        let rel = prefix.join(name);
        let abs_path = format!("/{}", rel.display());

        if !matches_filter(&abs_path, filters) {
            continue;
        }

        let from_path = from_dir.join(name);
        let to_path = to_dir.join(name);
        let from_meta = from_path.symlink_metadata().ok();
        let to_meta = to_path.symlink_metadata().ok();

        match (from_meta, to_meta) {
            (Some(fm), Some(tm)) => {
                // Both sides have this entry.
                let from_is_dir = fm.is_dir() && !is_whiteout(&fm);
                let to_is_dir = tm.is_dir() && !is_whiteout(&tm);

                if from_is_dir && to_is_dir {
                    // Both directories: recurse.
                    collect_range_diff(from_upper, to_upper, &rel, filters, entries)?;
                } else if from_is_dir {
                    // Was a dir, now a file (or whiteout).
                    collect_all_as(&from_path, &rel, ChangeKind::Deleted, filters, entries)?;
                    if !is_whiteout(&tm) {
                        let is_binary = tm.is_file() && is_binary_file(&to_path);
                        entries.push(DiffEntry {
                            kind: ChangeKind::Added,
                            path: abs_path,
                            is_binary,
                        });
                    }
                } else if to_is_dir {
                    // Was a file, now a dir.
                    if !is_whiteout(&fm) {
                        entries.push(DiffEntry {
                            kind: ChangeKind::Deleted,
                            path: abs_path.clone(),
                            is_binary: false,
                        });
                    }
                    collect_all_as(&to_path, &rel, ChangeKind::Added, filters, entries)?;
                } else {
                    // Both are files (or whiteouts).
                    let from_whiteout = is_whiteout(&fm);
                    let to_whiteout = is_whiteout(&tm);
                    if from_whiteout && to_whiteout {
                        // Both deleted: no diff.
                    } else if from_whiteout {
                        // Was deleted, now exists: Added.
                        let is_binary = tm.is_file() && is_binary_file(&to_path);
                        entries.push(DiffEntry {
                            kind: ChangeKind::Added,
                            path: abs_path,
                            is_binary,
                        });
                    } else if to_whiteout {
                        // Was present, now deleted: Deleted.
                        entries.push(DiffEntry {
                            kind: ChangeKind::Deleted,
                            path: abs_path,
                            is_binary: false,
                        });
                    } else {
                        // Both are real files. Compare content.
                        if files_differ(&from_path, &to_path) {
                            let is_binary = (fm.is_file() && is_binary_file(&from_path))
                                || (tm.is_file() && is_binary_file(&to_path));
                            entries.push(DiffEntry {
                                kind: ChangeKind::Modified,
                                path: abs_path,
                                is_binary,
                            });
                        }
                    }
                }
            }
            (None, Some(tm)) => {
                // Only in to_upper.
                if is_whiteout(&tm) {
                    // Deleted in to but never existed in from: skip.
                } else if tm.is_dir() {
                    collect_all_as(&to_path, &rel, ChangeKind::Added, filters, entries)?;
                } else {
                    let is_binary = tm.is_file() && is_binary_file(&to_path);
                    entries.push(DiffEntry {
                        kind: ChangeKind::Added,
                        path: abs_path,
                        is_binary,
                    });
                }
            }
            (Some(fm), None) => {
                // Only in from_upper.
                if is_whiteout(&fm) {
                    // Deleted in from but never existed in to: skip.
                } else if fm.is_dir() {
                    collect_all_as(&from_path, &rel, ChangeKind::Deleted, filters, entries)?;
                } else {
                    entries.push(DiffEntry {
                        kind: ChangeKind::Deleted,
                        path: abs_path,
                        is_binary: false,
                    });
                }
            }
            (None, None) => {}
        }
    }

    Ok(())
}

/// List directory entry names, returning an empty set if the dir doesn't exist.
fn list_dir_names(dir: &Path) -> BTreeSet<String> {
    let Ok(rd) = fs::read_dir(dir) else {
        return BTreeSet::new();
    };
    rd.filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().to_str().map(String::from))
        .collect()
}

/// Compare two files for differences. Returns true if they differ.
fn files_differ(a: &Path, b: &Path) -> bool {
    let a_meta = match a.symlink_metadata() {
        Ok(m) => m,
        Err(_) => return true,
    };
    let b_meta = match b.symlink_metadata() {
        Ok(m) => m,
        Err(_) => return true,
    };

    // Different types always differ.
    if a_meta.file_type() != b_meta.file_type() {
        return true;
    }

    // Symlinks: compare targets.
    if a_meta.is_symlink() {
        let a_target = fs::read_link(a).ok();
        let b_target = fs::read_link(b).ok();
        return a_target != b_target;
    }

    // Regular files: compare size first, then content chunk by chunk.
    if a_meta.is_file() {
        return files_bytes_differ(a, b, a_meta.len(), b_meta.len());
    }

    // Directories, devices, etc: compare metadata.
    a_meta.mode() != b_meta.mode()
}

/// Byte-wise compare two regular files whose sizes are already known.
///
/// Uses buffered readers and advances both sides by the min of the two
/// buffered slice lengths so unequal `read(2)` chunk sizes never produce
/// a false-positive "differ" result. Any I/O error or early EOF on one
/// side is treated as "differ" — the caller can't rely on partial data.
fn files_bytes_differ(a: &Path, b: &Path, a_len: u64, b_len: u64) -> bool {
    if a_len != b_len {
        return true;
    }
    if a_len == 0 {
        return false;
    }
    let (Ok(fa), Ok(fb)) = (fs::File::open(a), fs::File::open(b)) else {
        return true;
    };
    let mut ra = BufReader::with_capacity(65536, fa);
    let mut rb = BufReader::with_capacity(65536, fb);
    let mut remaining = a_len;
    while remaining > 0 {
        // Inner scope so the borrowed slices from `fill_buf` drop before
        // we call `consume` on the same readers.
        let step = {
            let ba = match ra.fill_buf() {
                Ok(s) => s,
                Err(_) => return true,
            };
            if ba.is_empty() {
                return true; // file shrunk under us
            }
            let bb = match rb.fill_buf() {
                Ok(s) => s,
                Err(_) => return true,
            };
            if bb.is_empty() {
                return true;
            }
            let n = ba.len().min(bb.len()).min(remaining as usize);
            if ba[..n] != bb[..n] {
                return true;
            }
            n
        };
        ra.consume(step);
        rb.consume(step);
        remaining -= step as u64;
    }
    false
}

/// Show the diff for a container target.
///
/// `target` can be a container name (diff against base rootfs) or a range
/// (`from..to`, diff between two containers). Optional `paths` filter the
/// output to specific subtrees.
pub fn diff(datadir: &Path, target: &str, paths: &[String], opts: &DiffOptions) -> Result<()> {
    let parsed = parse_target(target)?;
    // Filters are compared directly as absolute path strings (e.g. "/etc").
    // The caller's &[String] already has exactly the right representation,
    // so walkers borrow it verbatim and do no per-entry allocation.

    let entries = match parsed {
        DiffTarget::Single { name } => {
            let name = crate::containers::resolve_name(datadir, &name)?;
            let _lock = lock::lock_shared(datadir, "containers", &name)
                .with_context(|| format!("cannot lock container '{name}' for diff"))?;
            let state_path = datadir.join("state").join(&name);
            let state = crate::State::read_from(&state_path)?;
            let rootfs_name = state.rootfs();
            let rootfs = crate::containers::resolve_rootfs(
                datadir,
                if rootfs_name.is_empty() {
                    None
                } else {
                    Some(rootfs_name)
                },
            )?;
            let _fs_lock = if !rootfs_name.is_empty() {
                Some(
                    lock::lock_shared(datadir, "fs", rootfs_name)
                        .with_context(|| format!("cannot lock rootfs '{rootfs_name}' for diff"))?,
                )
            } else {
                None
            };
            let upper = datadir.join("containers").join(&name).join("upper");
            if !upper.is_dir() {
                bail!("container directory not found: {}", upper.display());
            }

            let mut entries = Vec::new();
            collect_upper_diff(&upper, &rootfs, Path::new(""), paths, &mut entries)?;
            entries
        }
        DiffTarget::Range { from, to } => {
            let from = crate::containers::resolve_name(datadir, &from)?;
            let to = crate::containers::resolve_name(datadir, &to)?;

            let _lock_from = lock::lock_shared(datadir, "containers", &from)
                .with_context(|| format!("cannot lock container '{from}' for diff"))?;
            let _lock_to = lock::lock_shared(datadir, "containers", &to)
                .with_context(|| format!("cannot lock container '{to}' for diff"))?;

            let from_state = crate::State::read_from(&datadir.join("state").join(&from))?;
            let to_state = crate::State::read_from(&datadir.join("state").join(&to))?;
            if from_state.rootfs() != to_state.rootfs() {
                eprintln!(
                    "warning: containers use different base rootfs ('{}' vs '{}'); \
                     upper layers are relative to different lowers",
                    from_state.rootfs(),
                    to_state.rootfs(),
                );
            }

            let from_upper = datadir.join("containers").join(&from).join("upper");
            let to_upper = datadir.join("containers").join(&to).join("upper");

            if !from_upper.is_dir() {
                bail!("container directory not found: {}", from_upper.display());
            }
            if !to_upper.is_dir() {
                bail!("container directory not found: {}", to_upper.display());
            }

            let mut entries = Vec::new();
            collect_range_diff(&from_upper, &to_upper, Path::new(""), paths, &mut entries)?;
            entries
        }
    };

    if entries.is_empty() {
        return Ok(());
    }

    if opts.stat {
        print_stat(&entries);
    } else if opts.name_only {
        for entry in &entries {
            println!("{}", entry.path);
        }
    } else {
        for entry in &entries {
            if entry.is_binary {
                println!("{}\t{} (binary)", entry.kind, entry.path);
            } else {
                println!("{}\t{}", entry.kind, entry.path);
            }
        }
    }

    Ok(())
}

/// Print summary statistics for the diff entries.
fn print_stat(entries: &[DiffEntry]) {
    let added = entries
        .iter()
        .filter(|e| e.kind == ChangeKind::Added)
        .count();
    let modified = entries
        .iter()
        .filter(|e| e.kind == ChangeKind::Modified)
        .count();
    let deleted = entries
        .iter()
        .filter(|e| e.kind == ChangeKind::Deleted)
        .count();
    let binary = entries.iter().filter(|e| e.is_binary).count();

    println!("{} file(s) changed", entries.len());
    if added > 0 {
        println!("  {added} added");
    }
    if modified > 0 {
        println!("  {modified} modified");
    }
    if deleted > 0 {
        println!("  {deleted} deleted");
    }
    if binary > 0 {
        println!("  {binary} binary");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDataDir;

    fn make_test_dirs() -> (TempDataDir, PathBuf, PathBuf) {
        let tmp = TempDataDir::new("diff");
        let upper = tmp.path().join("upper");
        let lower = tmp.path().join("lower");
        fs::create_dir_all(&upper).unwrap();
        fs::create_dir_all(&lower).unwrap();
        (tmp, upper, lower)
    }

    #[test]
    fn test_parse_target_single() {
        match parse_target("mycontainer").unwrap() {
            DiffTarget::Single { name } => assert_eq!(name, "mycontainer"),
            _ => panic!("expected Single"),
        }
    }

    #[test]
    fn test_parse_target_range() {
        match parse_target("a..b").unwrap() {
            DiffTarget::Range { from, to } => {
                assert_eq!(from, "a");
                assert_eq!(to, "b");
            }
            _ => panic!("expected Range"),
        }
    }

    #[test]
    fn test_parse_target_range_empty_side() {
        assert!(parse_target("a..").is_err());
        assert!(parse_target("..b").is_err());
    }

    #[test]
    fn test_added_file() {
        let (_tmp, upper, lower) = make_test_dirs();
        fs::write(upper.join("newfile.txt"), "hello").unwrap();

        let mut entries = Vec::new();
        collect_upper_diff(&upper, &lower, Path::new(""), &[], &mut entries).unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind, ChangeKind::Added);
        assert_eq!(entries[0].path, "/newfile.txt");
        assert!(!entries[0].is_binary);
    }

    #[test]
    fn test_modified_file() {
        let (_tmp, upper, lower) = make_test_dirs();
        fs::write(lower.join("existing.txt"), "original").unwrap();
        fs::write(upper.join("existing.txt"), "modified").unwrap();

        let mut entries = Vec::new();
        collect_upper_diff(&upper, &lower, Path::new(""), &[], &mut entries).unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind, ChangeKind::Modified);
        assert_eq!(entries[0].path, "/existing.txt");
    }

    #[test]
    fn test_nested_file() {
        let (_tmp, upper, lower) = make_test_dirs();
        fs::create_dir_all(upper.join("etc")).unwrap();
        fs::write(upper.join("etc/hostname"), "newhost").unwrap();
        fs::create_dir_all(lower.join("etc")).unwrap();
        fs::write(lower.join("etc/hostname"), "oldhost").unwrap();

        let mut entries = Vec::new();
        collect_upper_diff(&upper, &lower, Path::new(""), &[], &mut entries).unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind, ChangeKind::Modified);
        assert_eq!(entries[0].path, "/etc/hostname");
    }

    #[test]
    fn test_binary_detection() {
        let (_tmp, upper, lower) = make_test_dirs();
        // Write a file with NUL bytes.
        fs::write(upper.join("binary.bin"), b"\x00\x01\x02\x03").unwrap();

        let mut entries = Vec::new();
        collect_upper_diff(&upper, &lower, Path::new(""), &[], &mut entries).unwrap();

        assert_eq!(entries.len(), 1);
        assert!(entries[0].is_binary);
    }

    #[test]
    fn test_path_filter() {
        let (_tmp, upper, lower) = make_test_dirs();
        fs::create_dir_all(upper.join("etc")).unwrap();
        fs::write(upper.join("etc/hostname"), "host").unwrap();
        fs::create_dir_all(upper.join("var/log")).unwrap();
        fs::write(upper.join("var/log/test.log"), "log").unwrap();

        let filter = vec!["/etc".to_string()];
        let mut entries = Vec::new();
        collect_upper_diff(&upper, &lower, Path::new(""), &filter, &mut entries).unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "/etc/hostname");
    }

    #[test]
    fn test_range_diff_added() {
        let (_tmp, from_upper, _) = make_test_dirs();
        let to_upper = _tmp.path().join("to_upper");
        fs::create_dir_all(&to_upper).unwrap();
        fs::write(to_upper.join("newfile.txt"), "hello").unwrap();

        let mut entries = Vec::new();
        collect_range_diff(&from_upper, &to_upper, Path::new(""), &[], &mut entries).unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind, ChangeKind::Added);
        assert_eq!(entries[0].path, "/newfile.txt");
    }

    #[test]
    fn test_range_diff_deleted() {
        let (_tmp, from_upper, _) = make_test_dirs();
        let to_upper = _tmp.path().join("to_upper");
        fs::create_dir_all(&to_upper).unwrap();
        fs::write(from_upper.join("oldfile.txt"), "hello").unwrap();

        let mut entries = Vec::new();
        collect_range_diff(&from_upper, &to_upper, Path::new(""), &[], &mut entries).unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind, ChangeKind::Deleted);
        assert_eq!(entries[0].path, "/oldfile.txt");
    }

    #[test]
    fn test_range_diff_modified() {
        let (_tmp, from_upper, _) = make_test_dirs();
        let to_upper = _tmp.path().join("to_upper");
        fs::create_dir_all(&to_upper).unwrap();
        fs::write(from_upper.join("file.txt"), "old").unwrap();
        fs::write(to_upper.join("file.txt"), "new").unwrap();

        let mut entries = Vec::new();
        collect_range_diff(&from_upper, &to_upper, Path::new(""), &[], &mut entries).unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind, ChangeKind::Modified);
        assert_eq!(entries[0].path, "/file.txt");
    }

    #[test]
    fn test_range_diff_same_content() {
        let (_tmp, from_upper, _) = make_test_dirs();
        let to_upper = _tmp.path().join("to_upper");
        fs::create_dir_all(&to_upper).unwrap();
        fs::write(from_upper.join("same.txt"), "same").unwrap();
        fs::write(to_upper.join("same.txt"), "same").unwrap();

        let mut entries = Vec::new();
        collect_range_diff(&from_upper, &to_upper, Path::new(""), &[], &mut entries).unwrap();

        assert!(
            entries.is_empty(),
            "identical files should not appear in diff"
        );
    }

    #[test]
    fn test_matches_filter_empty() {
        assert!(matches_filter("/any/path", &[]));
    }

    #[test]
    fn test_matches_filter_match() {
        let filters = vec!["/etc".to_string()];
        assert!(matches_filter("/etc/hostname", &filters));
        assert!(matches_filter("/etc", &filters));
        assert!(!matches_filter("/var/log", &filters));
    }

    #[test]
    fn test_matches_filter_boundary() {
        let filters = vec!["/etc".to_string()];
        assert!(!matches_filter("/etcpasswd", &filters));
        assert!(!matches_filter("/etcpasswd/foo", &filters));
    }

    #[test]
    fn test_matches_filter_parent_traversal() {
        // A directory "/etc" should match filter "/etc/hostname" so we traverse into it.
        let filters = vec!["/etc/hostname".to_string()];
        assert!(matches_filter("/etc", &filters));
        assert!(matches_filter("/etc/hostname", &filters));
        assert!(!matches_filter("/var", &filters));
    }

    #[test]
    fn test_matches_filter_multiple() {
        // Any single filter matching is enough.
        let filters = vec!["/etc".to_string(), "/usr/bin".to_string()];
        assert!(matches_filter("/etc/hosts", &filters));
        assert!(matches_filter("/usr/bin/ls", &filters));
        assert!(!matches_filter("/var/log", &filters));
    }

    #[test]
    fn test_path_relation_matches_root_like() {
        // "/" has special semantics: every path is under "/".
        assert!(path_relation_matches("/etc", "/"));
        assert!(path_relation_matches("/", "/etc"));
        // Identical roots still match.
        assert!(path_relation_matches("/", "/"));
    }

    #[test]
    fn test_parse_target_edge_cases() {
        // A bare ".." is not a range (empty on both sides).
        assert!(parse_target("..").is_err());
        // A name containing ".." later is still a range.
        let DiffTarget::Range { from, to } = parse_target("dev..prod-1.2").unwrap() else {
            panic!("expected Range");
        };
        assert_eq!(from, "dev");
        assert_eq!(to, "prod-1.2");
        // Empty input: a Single with an empty name. resolve_name() catches it later.
        let DiffTarget::Single { name } = parse_target("").unwrap() else {
            panic!("expected Single");
        };
        assert_eq!(name, "");
    }

    #[test]
    fn test_files_bytes_differ_large_aligned() {
        // Exercise the multi-chunk path: two files larger than the 64 KiB
        // BufReader capacity, identical content. Must report no diff.
        let tmp = TempDataDir::new("diff-bytes");
        let a = tmp.path().join("a");
        let b = tmp.path().join("b");
        let payload: Vec<u8> = (0u8..=255).cycle().take(200_000).collect();
        fs::write(&a, &payload).unwrap();
        fs::write(&b, &payload).unwrap();
        assert!(!files_differ(&a, &b));
    }

    #[test]
    fn test_files_bytes_differ_trailing_byte() {
        // Same length, differ only in the very last byte. Previously at
        // risk of false negatives with short reads; must report a diff.
        let tmp = TempDataDir::new("diff-bytes-trail");
        let a = tmp.path().join("a");
        let b = tmp.path().join("b");
        let mut pa: Vec<u8> = (0u8..=255).cycle().take(100_000).collect();
        let mut pb = pa.clone();
        *pa.last_mut().unwrap() = 0;
        *pb.last_mut().unwrap() = 1;
        fs::write(&a, &pa).unwrap();
        fs::write(&b, &pb).unwrap();
        assert!(files_differ(&a, &b));
    }

    #[test]
    fn test_files_differ_same() {
        let tmp = TempDataDir::new("diff-misc");
        let a = tmp.path().join("a");
        let b = tmp.path().join("b");
        fs::write(&a, "same").unwrap();
        fs::write(&b, "same").unwrap();
        assert!(!files_differ(&a, &b));
    }

    #[test]
    fn test_files_differ_different() {
        let tmp = TempDataDir::new("diff-misc");
        let a = tmp.path().join("a");
        let b = tmp.path().join("b");
        fs::write(&a, "old").unwrap();
        fs::write(&b, "new").unwrap();
        assert!(files_differ(&a, &b));
    }

    #[test]
    fn test_files_differ_size() {
        let tmp = TempDataDir::new("diff-misc");
        let a = tmp.path().join("a");
        let b = tmp.path().join("b");
        fs::write(&a, "short").unwrap();
        fs::write(&b, "much longer content").unwrap();
        assert!(files_differ(&a, &b));
    }

    #[test]
    fn test_stat_output() {
        let entries = vec![
            DiffEntry {
                kind: ChangeKind::Added,
                path: "/a".to_string(),
                is_binary: false,
            },
            DiffEntry {
                kind: ChangeKind::Modified,
                path: "/b".to_string(),
                is_binary: true,
            },
            DiffEntry {
                kind: ChangeKind::Deleted,
                path: "/c".to_string(),
                is_binary: false,
            },
        ];
        // Just verify it doesn't panic.
        print_stat(&entries);
    }

    #[test]
    fn test_display_change_kind() {
        assert_eq!(format!("{}", ChangeKind::Added), "A");
        assert_eq!(format!("{}", ChangeKind::Modified), "M");
        assert_eq!(format!("{}", ChangeKind::Deleted), "D");
    }

    #[test]
    fn test_symlink_diff() {
        let (_tmp, upper, lower) = make_test_dirs();
        std::os::unix::fs::symlink("/target", upper.join("link")).unwrap();

        let mut entries = Vec::new();
        collect_upper_diff(&upper, &lower, Path::new(""), &[], &mut entries).unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind, ChangeKind::Added);
        assert_eq!(entries[0].path, "/link");
        assert!(!entries[0].is_binary);
    }

    #[test]
    fn test_empty_upper() {
        let (_tmp, upper, lower) = make_test_dirs();

        let mut entries = Vec::new();
        collect_upper_diff(&upper, &lower, Path::new(""), &[], &mut entries).unwrap();

        assert!(entries.is_empty());
    }
}
