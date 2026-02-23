//! Internal API for managing sdme configuration.
//!
//! Handles loading, saving, and resolving the configuration file
//! (default: `~/.config/sdme/sdmerc`, TOML format). Provides the
//! [`Config`] struct and functions for reading/writing it to disk.

use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_interactive")]
    pub interactive: bool,

    #[serde(default = "default_datadir")]
    pub datadir: PathBuf,

    #[serde(default = "default_boot_timeout")]
    pub boot_timeout: u64,

    #[serde(default = "default_join_as_sudo_user")]
    pub join_as_sudo_user: bool,
}

fn default_interactive() -> bool {
    true
}

fn default_datadir() -> PathBuf {
    PathBuf::from("/var/lib/sdme")
}

fn default_boot_timeout() -> u64 {
    60
}

fn default_join_as_sudo_user() -> bool {
    true
}

impl Default for Config {
    fn default() -> Self {
        Self {
            interactive: true,
            datadir: default_datadir(),
            boot_timeout: default_boot_timeout(),
            join_as_sudo_user: default_join_as_sudo_user(),
        }
    }
}

impl Config {
    pub fn display(&self) {
        let interactive = if self.interactive { "yes" } else { "no" };
        let join_as_sudo_user = if self.join_as_sudo_user { "yes" } else { "no" };
        println!("interactive = {interactive}");
        println!("datadir = {}", self.datadir.display());
        println!("boot_timeout = {}", self.boot_timeout);
        println!("join_as_sudo_user = {join_as_sudo_user}");
    }
}

fn sudo_user_config_path() -> Option<PathBuf> {
    let su = crate::sudo_user()?;
    Some(su.home.join(".config").join("sdme").join("sdmerc"))
}

pub fn config_path() -> Result<PathBuf> {
    // When running under sudo, prefer the invoking user's config if it exists.
    if let Some(path) = sudo_user_config_path() {
        if path.exists() {
            return Ok(path);
        }
    }
    let base = if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        PathBuf::from(xdg)
    } else {
        let home = std::env::var("HOME").context("HOME not set")?;
        PathBuf::from(home).join(".config")
    };
    Ok(base.join("sdme").join("sdmerc"))
}

pub fn resolve_path(path: Option<&Path>) -> Result<PathBuf> {
    match path {
        Some(p) => Ok(p.to_path_buf()),
        None => config_path(),
    }
}

pub fn load(path: Option<&Path>) -> Result<Config> {
    let path = resolve_path(path)?;
    if !path.exists() {
        return Ok(Config::default());
    }
    let contents = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let config: Config =
        toml::from_str(&contents).with_context(|| format!("failed to parse {}", path.display()))?;
    Ok(config)
}

pub fn save(config: &Config, path: Option<&Path>) -> Result<()> {
    let path = resolve_path(path)?;
    if let Some(parent) = path.parent() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let contents =
        toml::to_string(config).with_context(|| format!("failed to serialize config"))?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    file.write_all(contents.as_bytes())
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    use std::sync::Mutex;

    // Tests must run serially because they modify XDG_CONFIG_HOME.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct TempConfig {
        dir: PathBuf,
        _guard: std::sync::MutexGuard<'static, ()>,
    }

    impl TempConfig {
        fn new() -> Self {
            let guard = ENV_LOCK.lock().unwrap();
            let dir = std::env::temp_dir().join(format!(
                "sdme-test-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            std::env::set_var("XDG_CONFIG_HOME", &dir);
            Self {
                dir,
                _guard: guard,
            }
        }
    }

    impl Drop for TempConfig {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
            std::env::remove_var("XDG_CONFIG_HOME");
        }
    }

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(config.interactive);
        assert_eq!(config.datadir, PathBuf::from("/var/lib/sdme"));
    }

    #[test]
    fn test_load_missing_file() {
        let _tmp = TempConfig::new();
        let config = load(None).unwrap();
        assert!(config.interactive);
    }

    #[test]
    fn test_save_and_load() {
        let _tmp = TempConfig::new();
        let config = Config {
            interactive: false,
            ..Config::default()
        };
        save(&config, None).unwrap();
        let loaded = load(None).unwrap();
        assert!(!loaded.interactive);
    }

    #[test]
    fn test_load_partial_config() {
        let _tmp = TempConfig::new();
        let path = config_path().unwrap();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        // Write an empty TOML file — missing keys should get defaults.
        fs::write(&path, "").unwrap();
        let config = load(None).unwrap();
        assert!(config.interactive);
    }

    #[test]
    fn test_explicit_path() {
        let dir = std::env::temp_dir().join(format!("sdme-test-explicit-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("custom-sdmerc");

        // Load from non-existent explicit path returns default.
        let config = load(Some(&path)).unwrap();
        assert!(config.interactive);

        // Save to explicit path then reload.
        let config = Config {
            interactive: false,
            ..Config::default()
        };
        save(&config, Some(&path)).unwrap();
        let loaded = load(Some(&path)).unwrap();
        assert!(!loaded.interactive);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_save_and_load_custom_datadir() {
        let _tmp = TempConfig::new();
        let config = Config {
            interactive: true,
            datadir: PathBuf::from("/tmp/custom-data"),
            ..Config::default()
        };
        save(&config, None).unwrap();
        let loaded = load(None).unwrap();
        assert_eq!(loaded.datadir, PathBuf::from("/tmp/custom-data"));
    }

    #[test]
    fn test_config_path_xdg() {
        let _tmp = TempConfig::new();
        let path = config_path().unwrap();
        assert!(path.ends_with("sdme/sdmerc"));
    }

    #[test]
    fn test_sudo_user_config_path_unset() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var("SUDO_USER");
        assert!(sudo_user_config_path().is_none());
    }

    #[test]
    fn test_sudo_user_config_path_valid() {
        let _guard = ENV_LOCK.lock().unwrap();
        let user = std::env::var("USER").unwrap();
        std::env::set_var("SUDO_USER", &user);
        let path = sudo_user_config_path();
        std::env::remove_var("SUDO_USER");
        let path = path.expect("should resolve for current user");
        assert!(path.ends_with(".config/sdme/sdmerc"));
    }
}
