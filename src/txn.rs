//! Enumerated transaction staging for filesystem operations.
//!
//! Provides `Txn` for staging filesystem changes in named directories
//! that encode the operation type and creator PID. On commit, the staging
//! directory is atomically renamed to its final location. On drop without
//! commit, the staging directory is left behind for cleanup by a future
//! operation (when [`auto_fs_gc`](crate::config::Config::auto_fs_gc) is enabled)
//! or by `sdme fs gc`.
//!
//! Transaction names follow the pattern `.{name}.{kind}-txn-{pid}`,
//! e.g. `.ubuntu.import-txn-42195`. The PID component allows
//! `cleanup_stale_txns` to detect whether the creator is still running
//! by probing `/proc/{pid}`.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// The kind of transactional operation, encoded in the staging directory name.
#[derive(Debug, Clone, Copy)]
pub(crate) enum TxnKind {
    /// Rootfs or OCI image import.
    Import,
    /// Rootfs removal (rename-to-staging then delete).
    Remove,
    /// Rootfs build from config.
    Build,
}

impl TxnKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Import => "import",
            Self::Remove => "remove",
            Self::Build => "build",
        }
    }
}

/// A transactional staging context.
///
/// On creation, computes the staging path as `.{name}.{kind}-txn-{pid}`
/// under the given base directory. [`prepare`](Txn::prepare) creates the
/// directory (optionally cleaning stale transactions first). [`commit`](Txn::commit)
/// atomically renames to the final path.
///
/// On drop without [`commit`](Txn::commit) or [`done`](Txn::done), the
/// staging directory is left in place — no cleanup is attempted. This
/// ensures that signal handlers never need to perform filesystem writes.
pub(crate) struct Txn {
    /// The staging directory path.
    staging: PathBuf,
    /// The base directory containing the staging dir.
    base_dir: PathBuf,
    /// The target name (used for stale-txn scanning).
    name: String,
    /// Whether to auto-clean stale transactions on prepare.
    auto_gc: bool,
    /// Whether commit() or done() was called.
    finished: bool,
    /// Verbose output.
    verbose: bool,
}

impl Txn {
    /// Create a new transaction context.
    ///
    /// Computes the staging path but does NOT create the directory.
    /// Call [`prepare`](Txn::prepare) to create it.
    pub fn new(base_dir: &Path, name: &str, kind: TxnKind, auto_gc: bool, verbose: bool) -> Self {
        let pid = std::process::id();
        let staging_name = format!(".{name}.{}-txn-{pid}", kind.as_str());
        Self {
            staging: base_dir.join(&staging_name),
            base_dir: base_dir.to_path_buf(),
            name: name.to_string(),
            auto_gc,
            finished: false,
            verbose,
        }
    }

    /// The staging directory path.
    pub fn path(&self) -> &Path {
        &self.staging
    }

    /// Clean stale transactions (if auto_gc enabled) and create the staging directory.
    pub fn prepare(&self) -> Result<()> {
        if self.auto_gc {
            cleanup_stale_txns(&self.base_dir, &self.name, self.verbose)?;
        }
        // Remove our own staging dir if it somehow exists (e.g. re-run with same PID).
        if self.staging.exists() {
            crate::copy::safe_remove_dir(&self.staging)?;
        }
        fs::create_dir_all(&self.staging)
            .with_context(|| format!("failed to create staging dir {}", self.staging.display()))?;
        if self.verbose {
            eprintln!("created staging dir: {}", self.staging.display());
        }
        Ok(())
    }

    /// Atomically commit: rename the staging directory to the final path.
    pub fn commit(&mut self, final_path: &Path) -> Result<()> {
        fs::rename(&self.staging, final_path).with_context(|| {
            format!(
                "failed to rename {} to {}",
                self.staging.display(),
                final_path.display()
            )
        })?;
        self.finished = true;
        if self.verbose {
            eprintln!(
                "committed {} -> {}",
                self.staging.display(),
                final_path.display()
            );
        }
        Ok(())
    }

    /// Mark the transaction as complete without renaming.
    ///
    /// Use this for delete operations where the final step is removal of
    /// the staging directory itself, not a rename to a final path.
    pub fn done(&mut self) {
        self.finished = true;
    }
}

impl Drop for Txn {
    fn drop(&mut self) {
        // Intentionally no-op: leave staging behind for gc.
    }
}

/// Return true if a PID is still running (has a `/proc/{pid}` entry).
fn pid_alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

/// Extract the PID from a transaction staging name.
///
/// Expects the pattern `.*-txn-{pid}` and returns the pid if parseable.
fn extract_txn_pid(file_name: &str) -> Option<u32> {
    let suffix = file_name.rsplit_once("-txn-")?;
    suffix.1.parse().ok()
}

/// Return true if an entry name looks like a stale transaction for `name`.
///
/// Matches `.{name}.*-txn-{pid}` where the PID is no longer running.
fn is_stale_entry(entry_name: &str, name: &str) -> bool {
    let prefix = format!(".{name}.");
    if entry_name.starts_with(&prefix) {
        if let Some(pid) = extract_txn_pid(entry_name) {
            return !pid_alive(pid);
        }
    }
    false
}

/// Scan a directory for stale transaction artifacts for `name` and remove them.
///
/// A transaction is stale if its creator PID is no longer running.
pub(crate) fn cleanup_stale_txns(dir: &Path, name: &str, verbose: bool) -> Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    let entries =
        fs::read_dir(dir).with_context(|| format!("failed to read directory {}", dir.display()))?;
    for entry in entries {
        let entry = entry?;
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();
        if is_stale_entry(&file_name, name) {
            let path = entry.path();
            if verbose {
                eprintln!("cleaning stale transaction: {}", path.display());
            }
            if path.is_dir() {
                crate::copy::safe_remove_dir(&path)?;
            } else {
                let _ = fs::remove_file(&path);
            }
        }
    }
    Ok(())
}

/// Scan a directory for ALL stale transaction artifacts (for `sdme gc`).
///
/// Returns paths to stale entries. An entry is stale if its creator PID is
/// no longer running.
pub(crate) fn find_all_stale_txns(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut stale = Vec::new();
    if !dir.is_dir() {
        return Ok(stale);
    }
    let entries =
        fs::read_dir(dir).with_context(|| format!("failed to read directory {}", dir.display()))?;
    for entry in entries {
        let entry = entry?;
        let file_name = entry.file_name();
        let file_name_str = file_name.to_string_lossy();
        if !file_name_str.starts_with('.') {
            continue;
        }
        if let Some(pid) = extract_txn_pid(&file_name_str) {
            if !pid_alive(pid) {
                stale.push(entry.path());
            }
        }
    }
    Ok(stale)
}

/// Clean up all stale transaction artifacts under a directory.
///
/// Scans for dead-PID transactions, removes each one, and returns the
/// count of entries cleaned.
pub fn gc(dir: &Path, verbose: bool) -> Result<usize> {
    let stale = find_all_stale_txns(dir)?;
    let count = stale.len();
    for path in &stale {
        if verbose {
            eprintln!("gc: removing {}", path.display());
        }
        if path.is_dir() {
            if let Err(e) = crate::copy::safe_remove_dir(path) {
                eprintln!(
                    "warning: failed to remove {}: {e}",
                    path.file_name()
                        .map(|n| n.to_string_lossy())
                        .unwrap_or_default()
                );
            }
        } else {
            let _ = fs::remove_file(path);
        }
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "sdme-test-txn-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ))
    }

    fn setup_dir(name: &str) -> PathBuf {
        let dir = test_dir(name);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_txn_staging_path_format() {
        let dir = setup_dir("path-format");
        let txn = Txn::new(&dir, "ubuntu", TxnKind::Import, false, false);
        let path = txn.path().to_path_buf();
        let name = path.file_name().unwrap().to_string_lossy();
        assert!(name.starts_with(".ubuntu.import-txn-"));
        assert!(name.ends_with(&std::process::id().to_string()));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_txn_prepare_creates_dir() {
        let dir = setup_dir("prepare");
        let txn = Txn::new(&dir, "test", TxnKind::Import, false, false);
        assert!(!txn.path().exists());
        txn.prepare().unwrap();
        assert!(txn.path().is_dir());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_txn_commit_renames() {
        let dir = setup_dir("commit");
        let mut txn = Txn::new(&dir, "test", TxnKind::Import, false, false);
        txn.prepare().unwrap();
        // Write a marker file.
        fs::write(txn.path().join("marker"), "ok").unwrap();
        let final_path = dir.join("test");
        txn.commit(&final_path).unwrap();
        assert!(!txn.staging.exists());
        assert!(final_path.is_dir());
        assert_eq!(fs::read_to_string(final_path.join("marker")).unwrap(), "ok");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_txn_drop_leaves_staging() {
        let dir = setup_dir("drop");
        let staging_path;
        {
            let txn = Txn::new(&dir, "test", TxnKind::Build, false, false);
            txn.prepare().unwrap();
            staging_path = txn.path().to_path_buf();
            // Drop without commit.
        }
        assert!(
            staging_path.is_dir(),
            "staging dir should remain after drop"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_txn_done_marks_finished() {
        let dir = setup_dir("done");
        let mut txn = Txn::new(&dir, "test", TxnKind::Remove, false, false);
        txn.prepare().unwrap();
        txn.done();
        assert!(txn.finished);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_cleanup_stale_removes_dead_pid() {
        let dir = setup_dir("stale-dead");
        // Create a staging dir with PID 1 (init — always running).
        let live = dir.join(".myfs.import-txn-1");
        fs::create_dir_all(&live).unwrap();
        // Create a staging dir with a PID that doesn't exist.
        let dead = dir.join(".myfs.import-txn-999999999");
        fs::create_dir_all(&dead).unwrap();

        cleanup_stale_txns(&dir, "myfs", false).unwrap();

        assert!(live.exists(), "live PID staging should remain");
        assert!(!dead.exists(), "dead PID staging should be removed");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_cleanup_stale_skips_live_pid() {
        let dir = setup_dir("stale-live");
        let pid = std::process::id();
        let staging = dir.join(format!(".myfs.build-txn-{pid}"));
        fs::create_dir_all(&staging).unwrap();

        cleanup_stale_txns(&dir, "myfs", false).unwrap();

        assert!(staging.exists(), "our own PID staging should remain");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_find_all_stale_txns() {
        let dir = setup_dir("find-all");
        // Dead PID transaction.
        let dead = dir.join(".foo.import-txn-999999999");
        fs::create_dir_all(&dead).unwrap();
        // Live PID transaction (PID 1 = init).
        let live = dir.join(".bar.build-txn-1");
        fs::create_dir_all(&live).unwrap();
        // Non-hidden entry (not a transaction).
        let normal = dir.join("ubuntu");
        fs::create_dir_all(&normal).unwrap();

        let stale = find_all_stale_txns(&dir).unwrap();

        assert!(stale.contains(&dead));
        assert!(!stale.contains(&live));
        assert!(!stale.contains(&normal));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_extract_txn_pid() {
        assert_eq!(extract_txn_pid(".ubuntu.import-txn-12345"), Some(12345));
        assert_eq!(extract_txn_pid(".foo.build-txn-1"), Some(1));
        assert_eq!(extract_txn_pid(".bar.removing"), None);
        assert_eq!(extract_txn_pid("no-match"), None);
    }

    #[test]
    fn test_prepare_with_auto_gc() {
        let dir = setup_dir("auto-gc");
        // Create a stale dead-PID entry.
        let stale = dir.join(".myfs.import-txn-999999999");
        fs::create_dir_all(&stale).unwrap();

        let txn = Txn::new(&dir, "myfs", TxnKind::Import, true, false);
        txn.prepare().unwrap();

        assert!(!stale.exists(), "auto_gc should clean stale staging");
        assert!(txn.path().is_dir());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_prepare_without_auto_gc() {
        let dir = setup_dir("no-auto-gc");
        // Create a stale dead-PID entry.
        let stale = dir.join(".myfs.import-txn-999999999");
        fs::create_dir_all(&stale).unwrap();

        let txn = Txn::new(&dir, "myfs", TxnKind::Import, false, false);
        txn.prepare().unwrap();

        assert!(
            stale.exists(),
            "without auto_gc, stale staging should remain"
        );
        assert!(txn.path().is_dir());
        let _ = fs::remove_dir_all(&dir);
    }
}
