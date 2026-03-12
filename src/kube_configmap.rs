//! Kubernetes configmap store for sdme.
//!
//! ConfigMaps are stored on disk at `{datadir}/configmaps/{name}/data/{key}` and
//! referenced by name in pod YAML volume specs. Files are created with
//! standard permissions (dirs `0o755`, files `0o644`).

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::{validate_name, State};

/// Subdirectory under datadir for configmap storage.
const CONFIGMAPS_SUBDIR: &str = "configmaps";

/// Information about a listed configmap.
pub struct ConfigMapInfo {
    pub name: String,
    pub keys: usize,
    pub created: String,
}

/// Create a new configmap from literal values and/or file contents.
///
/// `literals` are `(key, value)` pairs; `files` are `(key, path)` pairs.
/// At least one entry is required.
pub fn create(
    datadir: &Path,
    name: &str,
    literals: &[(String, String)],
    files: &[(String, String)],
) -> Result<()> {
    validate_name(name)?;

    if literals.is_empty() && files.is_empty() {
        bail!("at least one --from-literal or --from-file is required");
    }

    let configmap_dir = datadir.join(CONFIGMAPS_SUBDIR).join(name);
    if configmap_dir.exists() {
        bail!("configmap already exists: {name}");
    }

    let data_dir = configmap_dir.join("data");
    fs::create_dir_all(&data_dir)
        .with_context(|| format!("failed to create {}", data_dir.display()))?;
    set_dir_perms(&configmap_dir)?;
    set_dir_perms(&data_dir)?;

    // Validate all keys before writing any data.
    let mut seen_keys = std::collections::HashSet::new();
    for (key, _) in literals.iter().chain(files.iter()) {
        validate_key(key)?;
        if !seen_keys.insert(key) {
            bail!("duplicate key: {key}");
        }
    }

    // Write literal values.
    for (key, value) in literals {
        let key_path = data_dir.join(key);
        fs::write(&key_path, value.as_bytes())
            .with_context(|| format!("failed to write {}", key_path.display()))?;
        set_file_perms(&key_path)?;
    }

    // Write file contents.
    for (key, path) in files {
        let contents = fs::read(path).with_context(|| format!("failed to read file: {path}"))?;
        let key_path = data_dir.join(key);
        fs::write(&key_path, &contents)
            .with_context(|| format!("failed to write {}", key_path.display()))?;
        set_file_perms(&key_path)?;
    }

    // Write state file.
    let mut state = State::new();
    let created = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs();
    state.set("CREATED", created.to_string());
    state.write_to(&configmap_dir.join("state"))?;

    Ok(())
}

/// List all configmaps.
pub fn list(datadir: &Path) -> Result<Vec<ConfigMapInfo>> {
    let configmaps_dir = datadir.join(CONFIGMAPS_SUBDIR);
    if !configmaps_dir.is_dir() {
        return Ok(Vec::new());
    }

    let mut entries = Vec::new();
    for entry in fs::read_dir(&configmaps_dir)
        .with_context(|| format!("failed to read {}", configmaps_dir.display()))?
    {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = match entry.file_name().to_str() {
            Some(s) => s.to_string(),
            None => continue,
        };

        let state_path = configmaps_dir.join(&name).join("state");
        if !state_path.exists() {
            continue;
        }

        let created = match State::read_from(&state_path) {
            Ok(s) => s.get("CREATED").unwrap_or("").to_string(),
            Err(_) => String::new(),
        };

        let data_dir = configmaps_dir.join(&name).join("data");
        let keys = if data_dir.is_dir() {
            fs::read_dir(&data_dir).map_or(0, |d| d.count())
        } else {
            0
        };

        entries.push(ConfigMapInfo {
            name,
            keys,
            created,
        });
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(entries)
}

/// Remove one or more configmaps.
pub fn remove(datadir: &Path, names: &[String]) -> Result<()> {
    for name in names {
        let configmap_dir = datadir.join(CONFIGMAPS_SUBDIR).join(name);
        if !configmap_dir.join("state").exists() {
            bail!("configmap not found: {name}");
        }
        fs::remove_dir_all(&configmap_dir)
            .with_context(|| format!("failed to remove {}", configmap_dir.display()))?;
    }
    Ok(())
}

/// Read all key-value pairs from a configmap's data directory.
///
/// Returns `(key, contents)` pairs. Errors if the configmap doesn't exist.
pub fn read_configmap_data(datadir: &Path, name: &str) -> Result<Vec<(String, Vec<u8>)>> {
    let data_dir = datadir.join(CONFIGMAPS_SUBDIR).join(name).join("data");
    if !data_dir.is_dir() {
        bail!(
            "configmap not found: {name}\n\
             hint: create it with: sdme kube configmap create {name} --from-literal key=value"
        );
    }

    let mut entries = Vec::new();
    for entry in
        fs::read_dir(&data_dir).with_context(|| format!("failed to read {}", data_dir.display()))?
    {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let key = match entry.file_name().to_str() {
            Some(s) => s.to_string(),
            None => continue,
        };
        let contents = fs::read(entry.path())
            .with_context(|| format!("failed to read {}", entry.path().display()))?;
        entries.push((key, contents));
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(entries)
}

/// Validate a configmap key name.
fn validate_key(key: &str) -> Result<()> {
    if key.is_empty() {
        bail!("configmap key cannot be empty");
    }
    if key.contains('/') || key.contains("..") {
        bail!("configmap key must not contain '/' or '..': {key}");
    }
    if key.starts_with('.') {
        bail!("configmap key must not start with '.': {key}");
    }
    Ok(())
}

fn set_dir_perms(path: &Path) -> Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
        .with_context(|| format!("failed to set permissions on {}", path.display()))
}

fn set_file_perms(path: &Path) -> Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o644))
        .with_context(|| format!("failed to set permissions on {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDataDir;

    fn tmp() -> TempDataDir {
        TempDataDir::new("kube-configmap")
    }

    #[test]
    fn test_create_and_list() {
        let tmp = tmp();
        create(
            tmp.path(),
            "app-config",
            &[
                ("database-url".into(), "postgres://localhost/db".into()),
                ("log-level".into(), "info".into()),
            ],
            &[],
        )
        .unwrap();

        let configmaps = list(tmp.path()).unwrap();
        assert_eq!(configmaps.len(), 1);
        assert_eq!(configmaps[0].name, "app-config");
        assert_eq!(configmaps[0].keys, 2);
        assert!(!configmaps[0].created.is_empty());
    }

    #[test]
    fn test_create_from_file() {
        let tmp = tmp();
        let file_path = tmp.path().join("config.yaml");
        fs::write(&file_path, b"key: value\n").unwrap();

        create(
            tmp.path(),
            "file-config",
            &[],
            &[("config".into(), file_path.to_str().unwrap().into())],
        )
        .unwrap();

        let data = read_configmap_data(tmp.path(), "file-config").unwrap();
        assert_eq!(data.len(), 1);
        assert_eq!(data[0].0, "config");
        assert_eq!(data[0].1, b"key: value\n");
    }

    #[test]
    fn test_create_rejects_invalid_name() {
        let tmp = tmp();
        let err = create(tmp.path(), "INVALID", &[("k".into(), "v".into())], &[]).unwrap_err();
        assert!(err.to_string().contains("lowercase"));
    }

    #[test]
    fn test_create_rejects_duplicate() {
        let tmp = tmp();
        create(
            tmp.path(),
            "my-config",
            &[("k".into(), "v".into())],
            &[],
        )
        .unwrap();
        let err = create(
            tmp.path(),
            "my-config",
            &[("k".into(), "v".into())],
            &[],
        )
        .unwrap_err();
        assert!(err.to_string().contains("already exists"));
    }

    #[test]
    fn test_create_rejects_no_data() {
        let tmp = tmp();
        let err = create(tmp.path(), "empty", &[], &[]).unwrap_err();
        assert!(err.to_string().contains("at least one"));
    }

    #[test]
    fn test_create_rejects_duplicate_key() {
        let tmp = tmp();
        let err = create(
            tmp.path(),
            "dup-key",
            &[("k".into(), "v1".into()), ("k".into(), "v2".into())],
            &[],
        )
        .unwrap_err();
        assert!(err.to_string().contains("duplicate key"));
    }

    #[test]
    fn test_create_rejects_bad_key() {
        let tmp = tmp();
        for (i, bad_key) in ["", "../etc", "foo/bar", ".hidden"].iter().enumerate() {
            let name = format!("bad-key-{i}");
            let err =
                create(tmp.path(), &name, &[(bad_key.to_string(), "v".into())], &[]).unwrap_err();
            assert!(
                err.to_string().contains("configmap key"),
                "should reject key '{bad_key}': {err}"
            );
        }
    }

    #[test]
    fn test_remove() {
        let tmp = tmp();
        create(
            tmp.path(),
            "to-remove",
            &[("k".into(), "v".into())],
            &[],
        )
        .unwrap();
        remove(tmp.path(), &["to-remove".into()]).unwrap();

        let configmaps = list(tmp.path()).unwrap();
        assert!(configmaps.is_empty());
    }

    #[test]
    fn test_remove_not_found() {
        let tmp = tmp();
        let err = remove(tmp.path(), &["nonexistent".into()]).unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn test_read_configmap_data() {
        let tmp = tmp();
        create(
            tmp.path(),
            "read-test",
            &[
                ("alpha".into(), "aaa".into()),
                ("beta".into(), "bbb".into()),
            ],
            &[],
        )
        .unwrap();

        let data = read_configmap_data(tmp.path(), "read-test").unwrap();
        assert_eq!(data.len(), 2);
        assert_eq!(data[0].0, "alpha");
        assert_eq!(data[0].1, b"aaa");
        assert_eq!(data[1].0, "beta");
        assert_eq!(data[1].1, b"bbb");
    }

    #[test]
    fn test_read_configmap_not_found() {
        let tmp = tmp();
        let err = read_configmap_data(tmp.path(), "nope").unwrap_err();
        assert!(err.to_string().contains("not found"));
        assert!(err.to_string().contains("sdme kube configmap create"));
    }

    #[test]
    fn test_list_empty() {
        let tmp = tmp();
        let configmaps = list(tmp.path()).unwrap();
        assert!(configmaps.is_empty());
    }

    #[test]
    fn test_permissions() {
        let tmp = tmp();
        create(
            tmp.path(),
            "perm-test",
            &[("key".into(), "val".into())],
            &[],
        )
        .unwrap();

        let configmap_dir = tmp.path().join(CONFIGMAPS_SUBDIR).join("perm-test");
        let dir_mode = fs::metadata(&configmap_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o755);

        let data_dir = configmap_dir.join("data");
        let data_mode = fs::metadata(&data_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(data_mode, 0o755);

        let file_path = data_dir.join("key");
        let file_mode = fs::metadata(&file_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o644);
    }
}
