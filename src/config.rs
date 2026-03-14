//! Internal API for managing sdme configuration.
//!
//! Handles loading, saving, and resolving the configuration file
//! (default: `/etc/sdme.conf`, TOML format). Provides the
//! [`Config`] struct and functions for reading/writing it to disk.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    /// Prompt for confirmation on destructive operations.
    #[serde(default = "default_interactive")]
    pub interactive: bool,

    /// Root data directory for all container state and filesystems.
    #[serde(default = "default_datadir")]
    pub datadir: PathBuf,

    /// Seconds to wait for a container to boot before giving up.
    #[serde(default = "default_boot_timeout")]
    pub boot_timeout: u64,

    /// Drop to the sudo-invoking user when joining a container.
    #[serde(default = "default_join_as_sudo_user")]
    pub join_as_sudo_user: bool,

    /// Comma-separated overlayfs opaque dirs for host-rootfs containers.
    #[serde(default = "default_host_rootfs_opaque_dirs")]
    pub host_rootfs_opaque_dirs: String,

    /// Comma-separated capabilities dropped by `--hardened`.
    #[serde(default = "default_hardened_drop_caps")]
    pub hardened_drop_caps: String,

    /// Default base rootfs for OCI application images.
    #[serde(default)]
    pub default_base_fs: String,

    /// Docker Hub username for authenticated pulls.
    #[serde(default)]
    pub docker_user: String,

    /// Docker Hub personal access token for authenticated pulls.
    #[serde(default)]
    pub docker_token: String,

    /// Default filesystem type for raw disk image export (ext4 or btrfs).
    #[serde(default = "default_export_fs")]
    pub default_export_fs: String,

    /// OCI blob cache directory (empty = {datadir}/cache/oci).
    #[serde(default)]
    pub oci_cache_dir: String,

    /// Maximum OCI blob cache size (e.g. "10G"). "0" disables the cache.
    #[serde(default = "default_oci_cache_max_size")]
    pub oci_cache_max_size: String,
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

fn default_host_rootfs_opaque_dirs() -> String {
    "/etc/systemd/system,/var/log".to_string()
}

fn default_hardened_drop_caps() -> String {
    crate::security::HARDENED_DROP_CAPS.join(",")
}

fn default_export_fs() -> String {
    "ext4".to_string()
}

fn default_oci_cache_max_size() -> String {
    "10G".to_string()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            interactive: true,
            datadir: default_datadir(),
            boot_timeout: default_boot_timeout(),
            join_as_sudo_user: default_join_as_sudo_user(),
            host_rootfs_opaque_dirs: default_host_rootfs_opaque_dirs(),
            hardened_drop_caps: default_hardened_drop_caps(),
            default_base_fs: String::new(),
            default_export_fs: default_export_fs(),
            docker_user: String::new(),
            docker_token: String::new(),
            oci_cache_dir: String::new(),
            oci_cache_max_size: default_oci_cache_max_size(),
        }
    }
}

impl Config {
    /// Print all configuration values to stdout.
    pub fn display(&self) {
        let interactive = if self.interactive { "yes" } else { "no" };
        let join_as_sudo_user = if self.join_as_sudo_user { "yes" } else { "no" };
        println!("interactive = {interactive}");
        println!("datadir = {}", self.datadir.display());
        println!("boot_timeout = {}", self.boot_timeout);
        println!("join_as_sudo_user = {join_as_sudo_user}");
        println!("host_rootfs_opaque_dirs = {}", self.host_rootfs_opaque_dirs);
        println!("hardened_drop_caps = {}", self.hardened_drop_caps);
        println!("default_base_fs = {}", self.default_base_fs);
        println!("default_export_fs = {}", self.default_export_fs);
        println!("docker_user = {}", self.docker_user);
        let docker_token_display = if self.docker_token.is_empty() {
            String::new()
        } else {
            let len = self.docker_token.len();
            if len <= 8 {
                "*".repeat(len)
            } else {
                format!(
                    "{}…{}",
                    &self.docker_token[..4],
                    &self.docker_token[len - 4..]
                )
            }
        };
        println!("docker_token = {docker_token_display}");
        println!("oci_cache_dir = {}", self.oci_cache_dir);
        println!("oci_cache_max_size = {}", self.oci_cache_max_size);
    }
}

/// Return the path to the configuration file.
pub fn config_path() -> PathBuf {
    PathBuf::from("/etc/sdme.conf")
}

/// Return the given path, or the default config path if `None`.
pub fn resolve_path(path: Option<&Path>) -> PathBuf {
    match path {
        Some(p) => p.to_path_buf(),
        None => config_path(),
    }
}

/// Load the configuration from disk, falling back to defaults if missing.
pub fn load(path: Option<&Path>) -> Result<Config> {
    let path = resolve_path(path);
    if !path.exists() {
        return Ok(Config::default());
    }
    let contents = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let config: Config =
        toml::from_str(&contents).with_context(|| format!("failed to parse {}", path.display()))?;
    Ok(config)
}

/// Save the configuration to disk with restrictive permissions.
pub fn save(config: &Config, path: Option<&Path>) -> Result<()> {
    let path = resolve_path(path);
    let contents = toml::to_string(config).context("failed to serialize config")?;
    crate::atomic_write(&path, contents.as_bytes())
        .with_context(|| format!("failed to write config {}", path.display()))?;
    // Ensure restrictive permissions (atomic_write creates with default umask).
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("failed to set permissions on {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_config_path() -> PathBuf {
        std::env::temp_dir().join(format!(
            "sdme-test-config-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ))
    }

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(config.interactive);
        assert_eq!(config.datadir, PathBuf::from("/var/lib/sdme"));
    }

    #[test]
    fn test_config_path() {
        assert_eq!(config_path(), PathBuf::from("/etc/sdme.conf"));
    }

    #[test]
    fn test_load_missing_file() {
        let path = temp_config_path();
        let _ = fs::remove_file(&path);
        let config = load(Some(&path)).unwrap();
        assert!(config.interactive);
    }

    #[test]
    fn test_save_and_load() {
        let path = temp_config_path();
        let config = Config {
            interactive: false,
            ..Config::default()
        };
        save(&config, Some(&path)).unwrap();
        let loaded = load(Some(&path)).unwrap();
        assert!(!loaded.interactive);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_load_partial_config() {
        let path = temp_config_path();
        // Write an empty TOML file; missing keys should get defaults.
        fs::write(&path, "").unwrap();
        let config = load(Some(&path)).unwrap();
        assert!(config.interactive);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_explicit_path() {
        let dir = std::env::temp_dir().join(format!("sdme-test-explicit-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("custom-config");

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
        let path = temp_config_path();
        let config = Config {
            interactive: true,
            datadir: PathBuf::from("/tmp/custom-data"),
            ..Config::default()
        };
        save(&config, Some(&path)).unwrap();
        let loaded = load(Some(&path)).unwrap();
        assert_eq!(loaded.datadir, PathBuf::from("/tmp/custom-data"));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_default_host_rootfs_opaque_dirs() {
        let config = Config::default();
        assert_eq!(
            config.host_rootfs_opaque_dirs,
            "/etc/systemd/system,/var/log"
        );
    }

    #[test]
    fn test_save_and_load_host_rootfs_opaque_dirs() {
        let path = temp_config_path();
        let config = Config {
            host_rootfs_opaque_dirs: "/var/log".to_string(),
            ..Config::default()
        };
        save(&config, Some(&path)).unwrap();
        let loaded = load(Some(&path)).unwrap();
        assert_eq!(loaded.host_rootfs_opaque_dirs, "/var/log");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_save_and_load_host_rootfs_opaque_dirs_empty() {
        let path = temp_config_path();
        let config = Config {
            host_rootfs_opaque_dirs: String::new(),
            ..Config::default()
        };
        save(&config, Some(&path)).unwrap();
        let loaded = load(Some(&path)).unwrap();
        assert_eq!(loaded.host_rootfs_opaque_dirs, "");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_default_base_fs_empty_by_default() {
        let config = Config::default();
        assert_eq!(config.default_base_fs, "");
    }

    #[test]
    fn test_save_and_load_default_base_fs() {
        let path = temp_config_path();
        let config = Config {
            default_base_fs: "ubuntu".to_string(),
            ..Config::default()
        };
        save(&config, Some(&path)).unwrap();
        let loaded = load(Some(&path)).unwrap();
        assert_eq!(loaded.default_base_fs, "ubuntu");
        let _ = fs::remove_file(&path);
    }
}
