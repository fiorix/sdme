//! Internal API for managing root filesystems used as overlayfs lower layers.
//!
//! Provides functions for importing, listing, and removing root filesystems
//! stored under `{datadir}/rootfs/{name}/`. Each rootfs is a complete
//! directory tree that containers reference via their state file.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::{State, validate_name};

/// An entry returned by [`list`].
pub struct RootfsEntry {
    pub name: String,
    pub distro: String,
}

/// Parse an `os-release` file into a key-value map.
///
/// Reads `{rootfs}/etc/os-release`, falling back to
/// `{rootfs}/usr/lib/os-release` per the freedesktop spec.
/// Returns an empty map if neither file exists.
fn parse_os_release(rootfs: &Path) -> HashMap<String, String> {
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
            let value = if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
                &value[1..value.len() - 1]
            } else {
                value
            };
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

/// List all imported root filesystems under `{datadir}/rootfs/`.
///
/// Returns entries sorted by name. If no rootfs directory exists,
/// returns an empty vec (not an error).
pub fn list(datadir: &Path) -> Result<Vec<RootfsEntry>> {
    let rootfs_dir = datadir.join("rootfs");
    if !rootfs_dir.exists() {
        return Ok(Vec::new());
    }

    let mut entries = Vec::new();
    for entry in fs::read_dir(&rootfs_dir)
        .with_context(|| format!("failed to read {}", rootfs_dir.display()))?
    {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();

        // Skip hidden entries (staging dirs like .foo.importing, meta files).
        if name.starts_with('.') {
            continue;
        }

        if !entry.file_type()?.is_dir() {
            continue;
        }

        // Try sidecar metadata first; fall back to live detection.
        let meta_path = rootfs_dir.join(format!(".{name}.meta"));
        let distro = if meta_path.exists() {
            State::read_from(&meta_path)
                .ok()
                .and_then(|s| s.get("DISTRO").map(|v| v.to_string()))
                .unwrap_or_default()
        } else {
            detect_distro(&entry.path())
        };

        entries.push(RootfsEntry { name, distro });
    }

    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(entries)
}

/// Import a root filesystem from a directory, tarball, URL, or OCI image.
///
/// Delegates to [`crate::import::run`].
pub fn import(datadir: &Path, source: &str, name: &str, verbose: bool, force: bool) -> Result<()> {
    crate::import::run(datadir, source, name, verbose, force)
}

/// Remove an imported root filesystem.
///
/// Validates the name, checks that no container references it, then removes
/// the rootfs directory and its `.meta` sidecar.
///
/// To prevent a TOCTOU race where `sdme create --rootfs <name>` could
/// reference the rootfs between the usage check and the deletion, we
/// first rename the rootfs directory to a staging name (atomic on the same
/// filesystem), then verify no container was created referencing it. If a
/// reference appeared, we rename it back and bail.
pub fn remove(datadir: &Path, name: &str, verbose: bool) -> Result<()> {
    validate_name(name)?;

    let rootfs_path = datadir.join("rootfs").join(name);
    if !rootfs_path.exists() {
        bail!("rootfs not found: {name}");
    }

    // Check that no container is using this rootfs (first pass).
    check_rootfs_in_use(datadir, name)?;

    // Atomically rename the rootfs to a staging name so that any concurrent
    // `sdme create --rootfs <name>` will fail with "rootfs not found" instead
    // of creating a container with a dangling reference.
    let removing_path = datadir.join("rootfs").join(format!(".{name}.removing"));
    fs::rename(&rootfs_path, &removing_path).with_context(|| {
        format!(
            "failed to rename {} to {}",
            rootfs_path.display(),
            removing_path.display()
        )
    })?;

    // Re-check after rename: if a container was created between the first check
    // and the rename, we need to restore the rootfs.
    if let Err(e) = check_rootfs_in_use(datadir, name) {
        // Restore the rootfs directory.
        let _ = fs::rename(&removing_path, &rootfs_path);
        return Err(e);
    }

    make_removable(&removing_path)?;
    fs::remove_dir_all(&removing_path)
        .with_context(|| format!("failed to remove {}", removing_path.display()))?;

    let meta_path = datadir.join("rootfs").join(format!(".{name}.meta"));
    let _ = fs::remove_file(meta_path);

    if verbose {
        eprintln!("removed rootfs '{name}'");
    }

    Ok(())
}

fn check_rootfs_in_use(datadir: &Path, name: &str) -> Result<()> {
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
                    None => entry
                        .file_name()
                        .to_str()
                        .unwrap_or("unknown")
                        .to_string(),
                };
                bail!("rootfs '{name}' is in use by container '{container}'");
            }
        }
    }
    Ok(())
}

/// Recursively restore directory permissions so `remove_dir_all` can succeed.
fn make_removable(path: &Path) -> std::io::Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if meta.is_dir() {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode();
        if mode & 0o700 != 0o700 {
            fs::set_permissions(path, fs::Permissions::from_mode(mode | 0o700))?;
        }
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                let _ = make_removable(&entry.path());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDataDir {
        dir: std::path::PathBuf,
    }

    impl TempDataDir {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "sdme-test-rootfs-{}-{:?}",
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

    impl Drop for TempDataDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
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
        let tmp = TempDataDir::new();
        let entries = list(tmp.path()).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_list_entries() {
        let tmp = TempDataDir::new();

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

        import(tmp.path(), src_a.path().to_str().unwrap(), "ubuntu", false, false).unwrap();
        import(tmp.path(), src_b.path().to_str().unwrap(), "debian", false, false).unwrap();

        let entries = list(tmp.path()).unwrap();
        assert_eq!(entries.len(), 2);
        // Sorted by name.
        assert_eq!(entries[0].name, "debian");
        assert_eq!(entries[0].distro, "Debian 12");
        assert_eq!(entries[1].name, "ubuntu");
        assert_eq!(entries[1].distro, "Ubuntu 24.04 LTS");
    }

    #[test]
    fn test_list_skips_staging_dirs() {
        let tmp = TempDataDir::new();

        // Import a real rootfs.
        let src = TempSourceDir::new("staging");
        import(tmp.path(), src.path().to_str().unwrap(), "real", false, false).unwrap();

        // Create a fake staging dir that should be skipped.
        fs::create_dir_all(tmp.path().join("rootfs/.fake.importing")).unwrap();

        let entries = list(tmp.path()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "real");
    }

    #[test]
    fn test_remove_basic() {
        let tmp = TempDataDir::new();
        let src = TempSourceDir::new("rm-basic");
        fs::write(src.path().join("file.txt"), "data\n").unwrap();

        import(tmp.path(), src.path().to_str().unwrap(), "rmme", false, false).unwrap();
        assert!(tmp.path().join("rootfs/rmme").is_dir());
        assert!(tmp.path().join("rootfs/.rmme.meta").exists());

        remove(tmp.path(), "rmme", false).unwrap();
        assert!(!tmp.path().join("rootfs/rmme").exists());
        assert!(!tmp.path().join("rootfs/.rmme.meta").exists());
    }

    #[test]
    fn test_remove_not_found() {
        let tmp = TempDataDir::new();
        let err = remove(tmp.path(), "nonexistent", false).unwrap_err();
        assert!(
            err.to_string().contains("not found"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_remove_in_use() {
        let tmp = TempDataDir::new();
        let src = TempSourceDir::new("rm-inuse");
        import(tmp.path(), src.path().to_str().unwrap(), "inuse", false, false).unwrap();

        // Create a container state file that references this rootfs.
        let state_dir = tmp.path().join("state");
        fs::create_dir_all(&state_dir).unwrap();
        let mut state = State::new();
        state.set("NAME", "mycontainer");
        state.set("ROOTFS", "inuse");
        state.write_to(&state_dir.join("mycontainer")).unwrap();

        let err = remove(tmp.path(), "inuse", false).unwrap_err();
        assert!(
            err.to_string().contains("in use"),
            "unexpected error: {err}"
        );
        // Rootfs should still exist.
        assert!(tmp.path().join("rootfs/inuse").is_dir());
    }

    #[test]
    fn test_remove_multiple() {
        let tmp = TempDataDir::new();
        let src_a = TempSourceDir::new("rm-multi-a");
        let src_b = TempSourceDir::new("rm-multi-b");

        import(tmp.path(), src_a.path().to_str().unwrap(), "alpha", false, false).unwrap();
        import(tmp.path(), src_b.path().to_str().unwrap(), "beta", false, false).unwrap();
        assert_eq!(list(tmp.path()).unwrap().len(), 2);

        remove(tmp.path(), "alpha", false).unwrap();
        remove(tmp.path(), "beta", false).unwrap();

        assert!(list(tmp.path()).unwrap().is_empty());
        assert!(!tmp.path().join("rootfs/alpha").exists());
        assert!(!tmp.path().join("rootfs/beta").exists());
    }
}
