//! Shared key-value store for secrets and configmaps.
//!
//! Both stores have identical CRUD logic, differing only in directory
//! names, permissions, and user-facing nouns. This module extracts the
//! common implementation.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::{validate_name, State};

/// Configuration that distinguishes a secret store from a configmap store.
pub(super) struct StoreConfig {
    pub subdir: &'static str,
    pub noun: &'static str,
    pub cli_cmd: &'static str,
    pub dir_mode: u32,
    pub file_mode: u32,
}

/// Information about a listed store entry (secret or configmap).
pub struct StoreInfo {
    /// Entry name.
    pub name: String,
    /// Number of data keys in the entry.
    pub keys: usize,
    /// Human-readable creation timestamp.
    pub created: String,
}

/// Create a new entry from literal values and/or file contents.
pub(super) fn create(
    cfg: &StoreConfig,
    datadir: &Path,
    name: &str,
    literals: &[(String, String)],
    files: &[(String, String)],
) -> Result<()> {
    validate_name(name)?;

    // Exclusive lock prevents concurrent creates of the same entry.
    let _lock = crate::lock::lock_exclusive(datadir, cfg.subdir, name)
        .with_context(|| format!("cannot lock {} '{name}' for creation", cfg.noun))?;

    if literals.is_empty() && files.is_empty() {
        bail!("at least one --from-literal or --from-file is required");
    }

    let entry_dir = datadir.join(cfg.subdir).join(name);
    if entry_dir.exists() {
        bail!("{} already exists: {name}", cfg.noun);
    }

    let data_dir = entry_dir.join("data");
    fs::create_dir_all(&data_dir)
        .with_context(|| format!("failed to create {}", data_dir.display()))?;
    set_perms(&entry_dir, cfg.dir_mode)?;
    set_perms(&data_dir, cfg.dir_mode)?;

    // Validate all keys before writing any data.
    let mut seen_keys = std::collections::HashSet::new();
    for (key, _) in literals.iter().chain(files.iter()) {
        validate_key(cfg.noun, key)?;
        if !seen_keys.insert(key) {
            bail!("duplicate key: {key}");
        }
    }

    // Write literal values.
    for (key, value) in literals {
        let key_path = data_dir.join(key);
        fs::write(&key_path, value.as_bytes())
            .with_context(|| format!("failed to write {}", key_path.display()))?;
        set_perms(&key_path, cfg.file_mode)?;
    }

    // Write file contents.
    for (key, path) in files {
        let contents = fs::read(path).with_context(|| format!("failed to read file: {path}"))?;
        let key_path = data_dir.join(key);
        fs::write(&key_path, &contents)
            .with_context(|| format!("failed to write {}", key_path.display()))?;
        set_perms(&key_path, cfg.file_mode)?;
    }

    // Write state file.
    let mut state = State::new();
    let created = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| anyhow::anyhow!("system clock is before UNIX epoch"))?
        .as_secs();
    state.set("CREATED", created.to_string());
    state.write_to(&entry_dir.join("state"))?;

    Ok(())
}

/// List all entries.
pub(super) fn list(cfg: &StoreConfig, datadir: &Path) -> Result<Vec<StoreInfo>> {
    let store_dir = datadir.join(cfg.subdir);
    if !store_dir.is_dir() {
        return Ok(Vec::new());
    }

    let mut entries = Vec::new();
    for entry in fs::read_dir(&store_dir)
        .with_context(|| format!("failed to read {}", store_dir.display()))?
    {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = match entry.file_name().to_str() {
            Some(s) => s.to_string(),
            None => continue,
        };

        let state_path = store_dir.join(&name).join("state");
        if !state_path.exists() {
            continue;
        }

        let created = match State::read_from(&state_path) {
            Ok(s) => s.get("CREATED").unwrap_or("").to_string(),
            Err(_) => String::new(),
        };

        let data_dir = store_dir.join(&name).join("data");
        let keys = if data_dir.is_dir() {
            fs::read_dir(&data_dir).map_or(0, |d| d.count())
        } else {
            0
        };

        entries.push(StoreInfo {
            name,
            keys,
            created,
        });
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(entries)
}

/// Remove one or more entries.
pub(super) fn remove(cfg: &StoreConfig, datadir: &Path, names: &[String]) -> Result<()> {
    for name in names {
        crate::check_interrupted()?;
        // Exclusive lock prevents deletion while a kube create is reading.
        let _lock = crate::lock::lock_exclusive(datadir, cfg.subdir, name)
            .with_context(|| format!("cannot lock {} '{name}' for removal", cfg.noun))?;
        let entry_dir = datadir.join(cfg.subdir).join(name);
        if !entry_dir.join("state").exists() {
            bail!("{} not found: {name}", cfg.noun);
        }
        fs::remove_dir_all(&entry_dir)
            .with_context(|| format!("failed to remove {}", entry_dir.display()))?;
    }
    Ok(())
}

/// Read all key-value pairs from an entry's data directory.
pub(super) fn read_data(
    cfg: &StoreConfig,
    datadir: &Path,
    name: &str,
) -> Result<Vec<(String, Vec<u8>)>> {
    let data_dir = datadir.join(cfg.subdir).join(name).join("data");
    if !data_dir.is_dir() {
        bail!(
            "{noun} not found: {name}\n\
             hint: create it with: {cmd} {name} --from-literal key=value",
            noun = cfg.noun,
            cmd = cfg.cli_cmd,
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

/// Validate a key name.
fn validate_key(noun: &str, key: &str) -> Result<()> {
    if key.is_empty() {
        bail!("{noun} key cannot be empty");
    }
    if key.contains('/') || key.contains("..") {
        bail!("{noun} key must not contain '/' or '..': {key}");
    }
    if key.starts_with('.') {
        bail!("{noun} key must not start with '.': {key}");
    }
    Ok(())
}

fn set_perms(path: &Path, mode: u32) -> Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("failed to set permissions on {}", path.display()))
}
