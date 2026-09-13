//! Internal API for managing root filesystems used as overlayfs lower layers.
//!
//! NOTE: Internally the code uses "rootfs" (variables, structs, module name),
//! but the CLI command is "fs" and the on-disk path is {datadir}/fs/.
//!
//! Provides functions for importing, listing, and removing root filesystems
//! stored under `{datadir}/fs/{name}/`. Each rootfs is a complete
//! directory tree that containers reference via their state file.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::{validate_name, State};

/// Recovery backup paths for a rootfs replacement (forced import).
///
/// The names deliberately lack the `-txn-` marker, so neither the
/// stale-transaction sweep nor `sdme fs gc` ever deletes them: while a
/// replacement is in flight they hold the only copy of the pre-replacement
/// state. They are never restored or deleted automatically after an
/// interruption; [`ensure_no_interrupted_replacement`] fails closed and
/// tells the operator exactly how to reconcile them.
pub(crate) struct ReplaceRecover {
    /// Parked old rootfs tree.
    pub tree: std::path::PathBuf,
    /// Parked old metadata sidecar.
    pub meta: std::path::PathBuf,
    /// Parked old environment sidecar.
    pub env: std::path::PathBuf,
}

impl ReplaceRecover {
    pub(crate) fn new(rootfs_dir: &Path, name: &str) -> Self {
        Self {
            tree: rootfs_dir.join(format!(".{name}.replace-recover")),
            meta: rootfs_dir.join(format!(".{name}.meta.replace-recover")),
            env: rootfs_dir.join(format!(".{name}.env.replace-recover")),
        }
    }
}

fn path_present(p: &Path) -> bool {
    p.symlink_metadata().is_ok()
}

/// Fail closed if a previous forced-import replacement of `name` left
/// recovery backups behind.
///
/// Must run under the exclusive fs lock for `name`, before the operation
/// inspects the tree. Any backup means an earlier replacement did not
/// finish. Rather than guess which state is complete from filesystem
/// existence, the operation is refused, every backup is preserved, and the
/// error names each preserved path with the exact commands to roll back to
/// the pre-replacement state or to discard it.
pub(crate) fn ensure_no_interrupted_replacement(rootfs_dir: &Path, name: &str) -> Result<()> {
    let rec = ReplaceRecover::new(rootfs_dir, name);
    let final_dir = rootfs_dir.join(name);
    let meta_path = rootfs_dir.join(format!(".{name}.meta"));
    let env_path = rootfs_dir.join(format!(".{name}.env"));

    let mut preserved: Vec<(&Path, &Path)> = Vec::new();
    if path_present(&rec.tree) {
        preserved.push((&rec.tree, &final_dir));
    }
    if path_present(&rec.meta) {
        preserved.push((&rec.meta, &meta_path));
    }
    if path_present(&rec.env) {
        preserved.push((&rec.env, &env_path));
    }
    if preserved.is_empty() {
        return Ok(());
    }

    let mut listed = String::new();
    let mut rollback = String::new();
    let mut discard = String::new();
    for (backup, visible) in &preserved {
        listed.push_str(&format!("  {}\n", backup.display()));
        if path_present(visible) {
            rollback.push_str(&format!("  rm -rf {}\n", visible.display()));
        }
        rollback.push_str(&format!(
            "  mv {} {}\n",
            backup.display(),
            visible.display()
        ));
        discard.push_str(&format!("  rm -rf {}\n", backup.display()));
    }
    bail!(
        "a previous forced import of fs '{name}' was interrupted mid-replacement; \
         refusing to proceed so no state is lost.\n\
         Preserved pre-replacement state:\n{listed}\
         To roll back to it, inspect both states, then run:\n{rollback}\
         To keep the current state instead, inspect it, then run:\n{discard}\
         Retry the operation afterwards."
    )
}

/// An entry returned by [`list`].
#[derive(serde::Serialize)]
pub struct RootfsEntry {
    /// Rootfs directory name.
    pub name: String,
    /// OS name from os-release, or empty if unknown.
    pub os: String,
    /// Container names using this rootfs as their base.
    pub containers: Vec<String>,
}

/// Parse an `os-release` file into a key-value map.
///
/// Reads `{rootfs}/etc/os-release`, falling back to
/// `{rootfs}/usr/lib/os-release` per the freedesktop spec.
/// Returns an empty map if neither file exists.
pub(crate) fn parse_os_release(rootfs: &Path) -> HashMap<String, String> {
    let primary = rootfs.join("etc/os-release");
    let fallback = rootfs.join("usr/lib/os-release");

    let content = match fs::read_to_string(&primary) {
        Ok(c) => c,
        Err(_) => match fs::read_to_string(&fallback) {
            Ok(c) => c,
            Err(_) => return HashMap::new(),
        },
    };

    let mut map = HashMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let value = value.trim();
            // Strip surrounding double quotes if present.
            let value = value
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .unwrap_or(value);
            map.insert(key.trim().to_string(), value.to_string());
        }
    }
    map
}

/// Detect the distro name from `os-release` inside a rootfs.
///
/// Returns `PRETTY_NAME` if present, else `NAME`, else an empty string.
pub(crate) fn detect_distro(rootfs: &Path) -> String {
    let map = parse_os_release(rootfs);
    if let Some(v) = map.get("PRETTY_NAME") {
        return v.clone();
    }
    if let Some(v) = map.get("NAME") {
        return v.clone();
    }
    String::new()
}

/// Distro family classification for package manager selection.
#[derive(Debug, Clone, PartialEq)]
pub enum DistroFamily {
    /// Debian, Ubuntu, and derivatives (uses apt-get).
    Debian,
    /// Fedora, CentOS, AlmaLinux, RHEL, Rocky (uses dnf).
    Fedora,
    /// Arch Linux and derivatives (uses pacman).
    Arch,
    /// openSUSE, SLES, and derivatives (uses zypper).
    Suse,
    /// NixOS (declarative; no imperative package install).
    NixOS,
    /// Unrecognized distribution.
    Unknown,
}

impl DistroFamily {
    /// Return the config key used to look up per-distro hook overrides.
    pub fn config_key(&self) -> &'static str {
        match self {
            DistroFamily::Debian => "debian",
            DistroFamily::Fedora => "fedora",
            DistroFamily::Arch => "arch",
            DistroFamily::Suse => "suse",
            DistroFamily::NixOS => "nixos",
            DistroFamily::Unknown => "unknown",
        }
    }
}

/// Detect the distro family from `os-release` inside a rootfs.
///
/// Uses the `ID` and `ID_LIKE` fields to classify into a [`DistroFamily`].
pub(crate) fn detect_distro_family(rootfs: &Path) -> DistroFamily {
    let map = parse_os_release(rootfs);

    let id = map.get("ID").map(|s| s.as_str()).unwrap_or("");
    let id_like = map.get("ID_LIKE").map(|s| s.as_str()).unwrap_or("");

    if id == "nixos" {
        return DistroFamily::NixOS;
    }

    if id == "debian" || id == "ubuntu" || id_like.split_whitespace().any(|w| w == "debian") {
        return DistroFamily::Debian;
    }

    const FEDORA_IDS: &[&str] = &["fedora", "centos", "almalinux", "rhel", "rocky"];
    if FEDORA_IDS.contains(&id)
        || id_like
            .split_whitespace()
            .any(|w| w == "fedora" || w == "rhel")
    {
        return DistroFamily::Fedora;
    }

    if id == "arch" || id_like.split_whitespace().any(|w| w == "arch") {
        return DistroFamily::Arch;
    }

    const SUSE_IDS: &[&str] = &[
        "opensuse-leap",
        "opensuse-tumbleweed",
        "opensuse-microos",
        "sles",
        "sled",
    ];
    if SUSE_IDS.contains(&id)
        || id_like
            .split_whitespace()
            .any(|w| w == "suse" || w == "opensuse")
    {
        return DistroFamily::Suse;
    }

    DistroFamily::Unknown
}

/// List all imported root filesystems under `{datadir}/fs/`.
///
/// Returns entries sorted by name. If no fs directory exists,
/// returns an empty vec (not an error).
pub fn list(datadir: &Path) -> Result<Vec<RootfsEntry>> {
    let rootfs_dir = datadir.join("fs");
    if !rootfs_dir.exists() {
        return Ok(Vec::new());
    }

    let mut entries = Vec::new();
    for entry in fs::read_dir(&rootfs_dir)
        .with_context(|| format!("failed to read {}", rootfs_dir.display()))?
    {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();

        // Skip hidden entries (staging dirs, meta files).
        if name.starts_with('.') {
            continue;
        }

        if !entry.file_type()?.is_dir() {
            continue;
        }

        // Try sidecar metadata first; fall back to live detection.
        let meta_path = rootfs_dir.join(format!(".{name}.meta"));
        let os = if meta_path.exists() {
            State::read_from(&meta_path)
                .ok()
                .and_then(|s| s.get("DISTRO").map(|v| v.to_string()))
                .unwrap_or_default()
        } else {
            detect_distro(&entry.path())
        };

        entries.push(RootfsEntry {
            name,
            os,
            containers: Vec::new(),
        });
    }

    // Scan state files once and group containers by rootfs name.
    let state_dir = datadir.join("state");
    if state_dir.is_dir() {
        if let Ok(state_entries) = fs::read_dir(&state_dir) {
            for se in state_entries.flatten() {
                if let Ok(state) = State::read_from(&se.path()) {
                    let rootfs_val = state.rootfs();
                    if !rootfs_val.is_empty() {
                        let cname = match state.get("NAME") {
                            Some(n) => n.to_string(),
                            None => se.file_name().to_string_lossy().into_owned(),
                        };
                        if let Some(entry) = entries.iter_mut().find(|e| e.name == rootfs_val) {
                            entry.containers.push(cname);
                        }
                    }
                }
            }
        }
    }
    for entry in &mut entries {
        entry.containers.sort();
    }

    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(entries)
}

/// Import a root filesystem from a directory, tarball, URL, or OCI image,
/// returning its explicit or inferred name.
///
/// Delegates to [`crate::import::run`]. CLI command: `sdme fs import`.
pub fn import(datadir: &Path, opts: &crate::import::ImportOptions) -> Result<String> {
    crate::import::run(datadir, opts)
}

/// Remove an imported root filesystem.
///
/// Validates the name, checks that no container references it, then removes
/// the fs directory and its `.meta` and `.env` sidecars.
///
/// To prevent a TOCTOU race where `sdme create --fs <name>` could
/// reference the rootfs between the usage check and the deletion, we
/// first rename the fs directory to a staging name (atomic on the same
/// filesystem), then verify no container was created referencing it. If a
/// reference appeared, we rename it back and bail.
pub fn remove(datadir: &Path, name: &str, auto_gc: bool, verbose: bool) -> Result<()> {
    validate_name(name)?;

    // Acquire exclusive lock to prevent removal while a build is using this rootfs.
    let _lock = crate::lock::lock_exclusive(datadir, "fs", name)
        .with_context(|| format!("cannot remove rootfs '{name}': in use"))?;

    // Refuse if an earlier forced-import replacement was interrupted; the
    // recovery backups are the only copy of one of the two states.
    let rootfs_dir = datadir.join("fs");
    ensure_no_interrupted_replacement(&rootfs_dir, name)?;

    let rootfs_path = rootfs_dir.join(name);
    if !rootfs_path.exists() {
        bail!("fs not found: {name}");
    }

    // Check that no container is using this rootfs (first pass).
    check_rootfs_in_use(datadir, name)?;

    // Atomically rename the fs entry to a staging name so that any concurrent
    // `sdme create --fs <name>` will fail with "fs not found" instead
    // of creating a container with a dangling reference.
    let mut txn = crate::txn::Txn::new(
        &rootfs_dir,
        name,
        crate::txn::TxnKind::Remove,
        auto_gc,
        verbose,
    );
    // Clean up stale transactions (but don't create a staging dir; we rename into it).
    if auto_gc {
        crate::txn::cleanup_stale_txns(&rootfs_dir, name, verbose)?;
    }

    fs::rename(&rootfs_path, txn.path()).with_context(|| {
        format!(
            "failed to rename {} to {}",
            rootfs_path.display(),
            txn.path().display()
        )
    })?;

    // Re-check after rename: if a container was created between the first check
    // and the rename, we need to restore the fs entry.
    if let Err(e) = check_rootfs_in_use(datadir, name) {
        // Restore the rootfs directory.
        let _ = fs::rename(txn.path(), &rootfs_path);
        return Err(e);
    }

    crate::copy::safe_remove_dir(txn.path())?;
    txn.done();

    // Drop any cached btrfs base subvolume for this rootfs so it is not reused
    // by a future container. The tree is already gone, so a failure here only
    // leaves a stale cache behind; warn so it is not silently reused to seed
    // a future same-named rootfs's containers (overlay-only hosts have no
    // pool, making this a no-op).
    if let Err(e) = crate::storage::btrfs::invalidate_base(datadir, name, verbose) {
        eprintln!(
            "warning: failed to invalidate btrfs base for '{name}': {e}; \
             a stale base subvolume may seed future containers"
        );
    }

    let meta_path = datadir.join("fs").join(format!(".{name}.meta"));
    let _ = fs::remove_file(meta_path);
    let env_path = datadir.join("fs").join(format!(".{name}.env"));
    let _ = fs::remove_file(env_path);

    if verbose {
        eprintln!("removed fs '{name}'");
    }

    Ok(())
}

/// Bail if any container state file references rootfs `name`.
///
/// Used by `fs rm` and by forced `fs import` replacement, which applies the
/// same policy: a referenced base is never removed or replaced, whether the
/// container is running or stopped.
pub(crate) fn check_rootfs_in_use(datadir: &Path, name: &str) -> Result<()> {
    let state_dir = datadir.join("state");
    if !state_dir.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(&state_dir)
        .with_context(|| format!("failed to read {}", state_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if let Ok(state) = State::read_from(&path) {
            if state.get("ROOTFS") == Some(name) {
                let container = match state.get("NAME") {
                    Some(n) => n.to_string(),
                    None => entry.file_name().to_str().unwrap_or("unknown").to_string(),
                };
                bail!("fs '{name}' is in use by container '{container}'");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::import::{ImportOptions, InstallPackages, OciMode};
    use crate::testutil::TempDataDir;

    /// Helper to import a rootfs in tests, bypassing systemd checks.
    fn test_import(datadir: &Path, source: &str, name: &str) -> Result<()> {
        let cfg = crate::config::Config {
            oci_cache_max_size: "0".to_string(),
            ..crate::config::Config::default()
        };
        let cache = crate::oci::cache::BlobCache::from_config(&cfg).unwrap();
        import(
            datadir,
            &ImportOptions {
                source,
                name: Some(name),
                verbose: false,
                force: true,
                interactive: false,
                install_packages: InstallPackages::No,
                oci_mode: OciMode::Auto,
                base_fs: None,
                docker_credentials: None,
                cache: &cache,
                http: crate::config::HttpConfig {
                    connect_timeout: cfg.http_timeout,
                    body_timeout: cfg.http_body_timeout,
                    max_download_size: 0,
                    manifest_cache_ttl: cfg.oci_manifest_cache_ttl,
                },
                auto_gc: true,
                distros: &std::collections::HashMap::new(),
            },
        )
        .map(|_| ())
    }

    fn tmp() -> TempDataDir {
        TempDataDir::new("rootfs")
    }

    struct TempSourceDir {
        dir: std::path::PathBuf,
    }

    impl TempSourceDir {
        fn new(suffix: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "sdme-test-rootfs-src-{}-{:?}-{suffix}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            Self { dir }
        }

        fn path(&self) -> &Path {
            &self.dir
        }
    }

    impl Drop for TempSourceDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn test_parse_os_release_quoted() {
        let tmp = TempSourceDir::new("quoted");

        fs::create_dir_all(tmp.path().join("etc")).unwrap();
        fs::write(
            tmp.path().join("etc/os-release"),
            "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nNAME=\"Debian GNU/Linux\"\nID=debian\n",
        )
        .unwrap();

        let map = parse_os_release(tmp.path());
        assert_eq!(
            map.get("PRETTY_NAME").unwrap(),
            "Debian GNU/Linux 12 (bookworm)"
        );
        assert_eq!(map.get("NAME").unwrap(), "Debian GNU/Linux");
        assert_eq!(map.get("ID").unwrap(), "debian");
    }

    #[test]
    fn test_parse_os_release_fallback_path() {
        let tmp = TempSourceDir::new("fallback");

        // No etc/os-release, but usr/lib/os-release exists.
        fs::create_dir_all(tmp.path().join("usr/lib")).unwrap();
        fs::write(
            tmp.path().join("usr/lib/os-release"),
            "PRETTY_NAME=\"Arch Linux\"\n",
        )
        .unwrap();

        let map = parse_os_release(tmp.path());
        assert_eq!(map.get("PRETTY_NAME").unwrap(), "Arch Linux");
    }

    #[test]
    fn test_list_empty() {
        let tmp = tmp();
        let entries = list(tmp.path()).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_list_entries() {
        let tmp = tmp();

        // Import two rootfs with different distros.
        let src_a = TempSourceDir::new("list-a");
        fs::create_dir_all(src_a.path().join("etc")).unwrap();
        fs::write(
            src_a.path().join("etc/os-release"),
            "PRETTY_NAME=\"Ubuntu 24.04 LTS\"\n",
        )
        .unwrap();

        let src_b = TempSourceDir::new("list-b");
        fs::create_dir_all(src_b.path().join("etc")).unwrap();
        fs::write(
            src_b.path().join("etc/os-release"),
            "PRETTY_NAME=\"Debian 12\"\n",
        )
        .unwrap();

        test_import(tmp.path(), src_a.path().to_str().unwrap(), "ubuntu").unwrap();
        test_import(tmp.path(), src_b.path().to_str().unwrap(), "debian").unwrap();

        let entries = list(tmp.path()).unwrap();
        assert_eq!(entries.len(), 2);
        // Sorted by name.
        assert_eq!(entries[0].name, "debian");
        assert_eq!(entries[0].os, "Debian 12");
        assert_eq!(entries[1].name, "ubuntu");
        assert_eq!(entries[1].os, "Ubuntu 24.04 LTS");
    }

    #[test]
    fn test_list_skips_staging_dirs() {
        let tmp = tmp();

        // Import a real rootfs.
        let src = TempSourceDir::new("staging");
        test_import(tmp.path(), src.path().to_str().unwrap(), "real").unwrap();

        // Create a fake staging dir that should be skipped.
        fs::create_dir_all(tmp.path().join("fs/.fake.import-txn-999999999")).unwrap();

        let entries = list(tmp.path()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "real");
    }

    #[test]
    fn test_remove_basic() {
        let tmp = tmp();
        let src = TempSourceDir::new("rm-basic");
        fs::write(src.path().join("file.txt"), "data\n").unwrap();

        test_import(tmp.path(), src.path().to_str().unwrap(), "rmme").unwrap();
        assert!(tmp.path().join("fs/rmme").is_dir());
        assert!(tmp.path().join("fs/.rmme.meta").exists());

        remove(tmp.path(), "rmme", true, false).unwrap();
        assert!(!tmp.path().join("fs/rmme").exists());
        assert!(!tmp.path().join("fs/.rmme.meta").exists());
    }

    #[test]
    fn test_remove_not_found() {
        let tmp = tmp();
        let err = remove(tmp.path(), "nonexistent", true, false).unwrap_err();
        assert!(
            err.to_string().contains("not found"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_remove_in_use() {
        let tmp = tmp();
        let src = TempSourceDir::new("rm-inuse");
        test_import(tmp.path(), src.path().to_str().unwrap(), "inuse").unwrap();

        // Create a container state file that references this rootfs.
        let state_dir = tmp.path().join("state");
        fs::create_dir_all(&state_dir).unwrap();
        let mut state = State::new();
        state.set("NAME", "mycontainer");
        state.set("ROOTFS", "inuse");
        state.write_to(&state_dir.join("mycontainer")).unwrap();

        let err = remove(tmp.path(), "inuse", true, false).unwrap_err();
        assert!(
            err.to_string().contains("in use"),
            "unexpected error: {err}"
        );
        // Rootfs should still exist.
        assert!(tmp.path().join("fs/inuse").is_dir());
    }

    #[test]
    fn test_remove_multiple() {
        let tmp = tmp();
        let src_a = TempSourceDir::new("rm-multi-a");
        let src_b = TempSourceDir::new("rm-multi-b");

        test_import(tmp.path(), src_a.path().to_str().unwrap(), "alpha").unwrap();
        test_import(tmp.path(), src_b.path().to_str().unwrap(), "beta").unwrap();
        assert_eq!(list(tmp.path()).unwrap().len(), 2);

        remove(tmp.path(), "alpha", true, false).unwrap();
        remove(tmp.path(), "beta", true, false).unwrap();

        assert!(list(tmp.path()).unwrap().is_empty());
        assert!(!tmp.path().join("fs/alpha").exists());
        assert!(!tmp.path().join("fs/beta").exists());
    }

    // --- Interrupted replacement detection (fail closed) ---

    /// Helper: a datadir with fs/base (marker v1) and its sidecars.
    fn make_base() -> TempDataDir {
        let tmp = tmp();
        let fs_dir = tmp.path().join("fs");
        fs::create_dir_all(fs_dir.join("base")).unwrap();
        fs::write(fs_dir.join("base/marker"), "v1").unwrap();
        fs::write(fs_dir.join(".base.meta"), "DISTRO=old\n").unwrap();
        fs::write(fs_dir.join(".base.env"), "A=1\n").unwrap();
        tmp
    }

    #[test]
    fn test_ensure_no_interrupted_replacement_clean_state() {
        let tmp = make_base();
        ensure_no_interrupted_replacement(&tmp.path().join("fs"), "base").unwrap();
    }

    #[test]
    fn test_interrupted_replacement_refuses_and_preserves() {
        // A parked old tree (crash before or after the commit) fails the
        // next operation closed: the error names the backup with recovery
        // guidance, and nothing is moved or deleted.
        let tmp = make_base();
        let fs_dir = tmp.path().join("fs");
        fs::rename(fs_dir.join("base"), fs_dir.join(".base.replace-recover")).unwrap();

        let err = ensure_no_interrupted_replacement(&fs_dir, "base").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("interrupted"), "got: {msg}");
        assert!(
            msg.contains(".base.replace-recover"),
            "guidance must name the backup: {msg}"
        );
        assert!(
            msg.contains("mv") && msg.contains("rm -rf"),
            "guidance must give exact recovery commands: {msg}"
        );

        assert_eq!(
            fs::read_to_string(fs_dir.join(".base.replace-recover/marker")).unwrap(),
            "v1",
            "the backup must be preserved exactly"
        );
        assert!(!fs_dir.join("base").exists());
    }

    #[test]
    fn test_interrupted_replacement_sidecar_backups_refuse_and_preserve() {
        // Sidecar backups without the tree backup (a crash deep in
        // publication, or a failed in-run rollback) also fail closed.
        let tmp = make_base();
        let fs_dir = tmp.path().join("fs");
        fs::rename(
            fs_dir.join(".base.meta"),
            fs_dir.join(".base.meta.replace-recover"),
        )
        .unwrap();
        fs::rename(
            fs_dir.join(".base.env"),
            fs_dir.join(".base.env.replace-recover"),
        )
        .unwrap();

        let err = ensure_no_interrupted_replacement(&fs_dir, "base").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains(".base.meta.replace-recover"), "got: {msg}");
        assert!(msg.contains(".base.env.replace-recover"), "got: {msg}");

        assert_eq!(
            fs::read_to_string(fs_dir.join(".base.meta.replace-recover")).unwrap(),
            "DISTRO=old\n"
        );
        assert_eq!(
            fs::read_to_string(fs_dir.join(".base.env.replace-recover")).unwrap(),
            "A=1\n"
        );
        // The visible tree is untouched.
        assert_eq!(
            fs::read_to_string(fs_dir.join("base/marker")).unwrap(),
            "v1"
        );
    }

    #[test]
    fn test_remove_refuses_interrupted_replacement() {
        // fs rm also fails closed rather than deleting a rootfs whose
        // replacement state is unresolved.
        let tmp = make_base();
        let fs_dir = tmp.path().join("fs");
        fs::rename(
            fs_dir.join(".base.meta"),
            fs_dir.join(".base.meta.replace-recover"),
        )
        .unwrap();

        let err = remove(tmp.path(), "base", true, false).unwrap_err();
        assert!(format!("{err:#}").contains("interrupted"), "got: {err:#}");
        assert!(fs_dir.join("base/marker").is_file());
        assert!(fs_dir.join(".base.meta.replace-recover").is_file());
    }

    #[test]
    fn test_recovery_artifacts_survive_txn_gc() {
        // Recovery backups use names outside the -txn- pattern: neither the
        // stale-transaction sweep nor `sdme fs gc` may delete the only copy
        // of a recoverable state.
        let tmp = make_base();
        let fs_dir = tmp.path().join("fs");
        fs::rename(fs_dir.join("base"), fs_dir.join(".base.replace-recover")).unwrap();
        fs::rename(
            fs_dir.join(".base.meta"),
            fs_dir.join(".base.meta.replace-recover"),
        )
        .unwrap();

        crate::txn::cleanup_stale_txns(&fs_dir, "base", false).unwrap();
        crate::txn::gc(&fs_dir, false).unwrap();

        assert!(fs_dir.join(".base.replace-recover/marker").is_file());
        assert!(fs_dir.join(".base.meta.replace-recover").is_file());
    }

    #[test]
    fn test_detect_distro_family_debian() {
        let tmp = TempSourceDir::new("family-debian");
        fs::create_dir_all(tmp.path().join("etc")).unwrap();
        fs::write(tmp.path().join("etc/os-release"), "ID=debian\nID_LIKE=\n").unwrap();
        assert_eq!(detect_distro_family(tmp.path()), DistroFamily::Debian);
    }

    #[test]
    fn test_detect_distro_family_ubuntu() {
        let tmp = TempSourceDir::new("family-ubuntu");
        fs::create_dir_all(tmp.path().join("etc")).unwrap();
        fs::write(
            tmp.path().join("etc/os-release"),
            "ID=ubuntu\nID_LIKE=debian\n",
        )
        .unwrap();
        assert_eq!(detect_distro_family(tmp.path()), DistroFamily::Debian);
    }

    #[test]
    fn test_detect_distro_family_debian_derivative() {
        let tmp = TempSourceDir::new("family-mint");
        fs::create_dir_all(tmp.path().join("etc")).unwrap();
        fs::write(
            tmp.path().join("etc/os-release"),
            "ID=linuxmint\nID_LIKE=\"ubuntu debian\"\n",
        )
        .unwrap();
        assert_eq!(detect_distro_family(tmp.path()), DistroFamily::Debian);
    }

    #[test]
    fn test_detect_distro_family_fedora() {
        let tmp = TempSourceDir::new("family-fedora");
        fs::create_dir_all(tmp.path().join("etc")).unwrap();
        fs::write(tmp.path().join("etc/os-release"), "ID=fedora\n").unwrap();
        assert_eq!(detect_distro_family(tmp.path()), DistroFamily::Fedora);
    }

    #[test]
    fn test_detect_distro_family_almalinux() {
        let tmp = TempSourceDir::new("family-alma");
        fs::create_dir_all(tmp.path().join("etc")).unwrap();
        fs::write(
            tmp.path().join("etc/os-release"),
            "ID=almalinux\nID_LIKE=\"rhel centos fedora\"\n",
        )
        .unwrap();
        assert_eq!(detect_distro_family(tmp.path()), DistroFamily::Fedora);
    }

    #[test]
    fn test_detect_distro_family_rhel_like() {
        let tmp = TempSourceDir::new("family-rhel-like");
        fs::create_dir_all(tmp.path().join("etc")).unwrap();
        fs::write(
            tmp.path().join("etc/os-release"),
            "ID=custom\nID_LIKE=\"rhel fedora\"\n",
        )
        .unwrap();
        assert_eq!(detect_distro_family(tmp.path()), DistroFamily::Fedora);
    }

    #[test]
    fn test_detect_distro_family_nixos() {
        let tmp = TempSourceDir::new("family-nixos");
        fs::create_dir_all(tmp.path().join("etc")).unwrap();
        fs::write(tmp.path().join("etc/os-release"), "ID=nixos\n").unwrap();
        assert_eq!(detect_distro_family(tmp.path()), DistroFamily::NixOS);
    }

    #[test]
    fn test_detect_distro_family_unknown() {
        let tmp = TempSourceDir::new("family-unknown");
        fs::create_dir_all(tmp.path().join("etc")).unwrap();
        fs::write(tmp.path().join("etc/os-release"), "ID=gentoo\n").unwrap();
        assert_eq!(detect_distro_family(tmp.path()), DistroFamily::Unknown);
    }

    #[test]
    fn test_detect_distro_family_no_os_release() {
        let tmp = TempSourceDir::new("family-none");
        assert_eq!(detect_distro_family(tmp.path()), DistroFamily::Unknown);
    }

    #[test]
    fn test_detect_distro_family_arch() {
        let tmp = TempSourceDir::new("family-arch");
        fs::create_dir_all(tmp.path().join("etc")).unwrap();
        fs::write(tmp.path().join("etc/os-release"), "ID=arch\n").unwrap();
        assert_eq!(detect_distro_family(tmp.path()), DistroFamily::Arch);
    }

    #[test]
    fn test_detect_distro_family_arch_derivative() {
        let tmp = TempSourceDir::new("family-endeavour");
        fs::create_dir_all(tmp.path().join("etc")).unwrap();
        fs::write(
            tmp.path().join("etc/os-release"),
            "ID=endeavouros\nID_LIKE=arch\n",
        )
        .unwrap();
        assert_eq!(detect_distro_family(tmp.path()), DistroFamily::Arch);
    }

    #[test]
    fn test_detect_distro_family_cachyos() {
        let tmp = TempSourceDir::new("family-cachyos");
        fs::create_dir_all(tmp.path().join("etc")).unwrap();
        fs::write(
            tmp.path().join("etc/os-release"),
            "ID=cachyos\nID_LIKE=arch\n",
        )
        .unwrap();
        assert_eq!(detect_distro_family(tmp.path()), DistroFamily::Arch);
    }

    #[test]
    fn test_detect_distro_family_opensuse_tumbleweed() {
        let tmp = TempSourceDir::new("family-tumbleweed");
        fs::create_dir_all(tmp.path().join("etc")).unwrap();
        fs::write(
            tmp.path().join("etc/os-release"),
            "ID=opensuse-tumbleweed\nID_LIKE=\"opensuse suse\"\n",
        )
        .unwrap();
        assert_eq!(detect_distro_family(tmp.path()), DistroFamily::Suse);
    }

    #[test]
    fn test_detect_distro_family_opensuse_leap() {
        let tmp = TempSourceDir::new("family-leap");
        fs::create_dir_all(tmp.path().join("etc")).unwrap();
        fs::write(
            tmp.path().join("etc/os-release"),
            "ID=opensuse-leap\nID_LIKE=\"opensuse suse\"\n",
        )
        .unwrap();
        assert_eq!(detect_distro_family(tmp.path()), DistroFamily::Suse);
    }

    #[test]
    fn test_detect_distro_family_sles() {
        let tmp = TempSourceDir::new("family-sles");
        fs::create_dir_all(tmp.path().join("etc")).unwrap();
        fs::write(tmp.path().join("etc/os-release"), "ID=sles\nID_LIKE=suse\n").unwrap();
        assert_eq!(detect_distro_family(tmp.path()), DistroFamily::Suse);
    }
}
