//! Internal API for managing sdme configuration.
//!
//! Handles loading, saving, and resolving the configuration file
//! (default: `/etc/sdme.conf`, TOML format). Provides the
//! [`Config`] struct and functions for reading/writing it to disk.

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Per-distro chroot command overrides for import/export preparation.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct DistroCommands {
    /// Chroot commands to prepare a rootfs for nspawn boot (import).
    /// Installs systemd, dbus, pam/login, sets timezone, cleans cache.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub import_prehook: Option<Vec<String>>,

    /// Chroot commands to prepare a rootfs for container/rootfs export.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub export_prehook: Option<Vec<String>>,

    /// Chroot commands to prepare a rootfs for VM export (`fs export --vm`).
    /// Installs udev and restores file capabilities stripped during import.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub export_vm_prehook: Option<Vec<String>>,
}

/// Global sdme configuration loaded from `/etc/sdme.conf`.
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

    /// Default extra free space for auto-calculated raw disk image size (e.g. "256M").
    #[serde(default = "default_export_free_space")]
    pub default_export_free_space: String,

    /// Maximum number of tasks (processes/threads) per container.
    #[serde(default = "default_tasks_max")]
    pub tasks_max: u32,

    /// OCI blob cache directory (empty = {datadir}/cache/oci).
    #[serde(default)]
    pub oci_cache_dir: String,

    /// Maximum OCI blob cache size (e.g. "10G"). "0" disables the cache.
    #[serde(default = "default_oci_cache_max_size")]
    pub oci_cache_max_size: String,

    /// HTTP connect/resolve timeout in seconds for downloads and OCI pulls.
    #[serde(default = "default_http_timeout")]
    pub http_timeout: u64,

    /// HTTP body receive timeout in seconds for downloads and OCI pulls.
    #[serde(default = "default_http_body_timeout")]
    pub http_body_timeout: u64,

    /// Maximum download size for rootfs imports and OCI pulls (e.g. "50G", "0" = unlimited).
    #[serde(default = "default_max_download_size")]
    pub max_download_size: String,

    /// Nixpkgs channel for NixOS rootfs builds (e.g. "nixos-unstable").
    #[serde(default = "default_nixpkgs_channel")]
    pub nixpkgs_channel: String,

    /// Path to a custom NixOS configuration template for nix-build imports.
    /// When set, this file replaces the embedded DEFAULT_NIXOS_CONFIG entirely.
    /// The `--nix-config` CLI flag still merges on top via NixOS module imports.
    #[serde(default)]
    pub nix_config_template: String,

    /// Graceful stop timeout in seconds (SIGRTMIN+4 to leader).
    #[serde(default = "default_stop_timeout_graceful")]
    pub stop_timeout_graceful: u64,

    /// Terminate stop timeout in seconds (SIGTERM to nspawn leader).
    #[serde(default = "default_stop_timeout_terminate")]
    pub stop_timeout_terminate: u64,

    /// Force-kill stop timeout in seconds (SIGKILL to all).
    #[serde(default = "default_stop_timeout_kill")]
    pub stop_timeout_kill: u64,

    /// Automatically clean up stale transactions before mutating operations.
    ///
    /// When `true` (default), operations like `import`, `build`, and `export`
    /// clean up leftover staging directories from previously interrupted runs.
    /// Set to `false` to skip auto-cleanup; use `sdme fs gc` to clean manually.
    #[serde(default = "default_auto_fs_gc")]
    pub auto_fs_gc: bool,

    /// Per-distro chroot command overrides for import/export preparation.
    /// Absent = use built-in defaults. Empty vec = explicitly do nothing.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub distros: HashMap<String, DistroCommands>,
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

fn default_export_free_space() -> String {
    "256M".to_string()
}

fn default_tasks_max() -> u32 {
    16384
}

fn default_oci_cache_max_size() -> String {
    "10G".to_string()
}

fn default_http_timeout() -> u64 {
    30
}

fn default_http_body_timeout() -> u64 {
    300
}

fn default_max_download_size() -> String {
    "50G".to_string()
}

fn default_nixpkgs_channel() -> String {
    "nixos-unstable".to_string()
}

fn default_stop_timeout_graceful() -> u64 {
    90
}

fn default_stop_timeout_terminate() -> u64 {
    30
}

fn default_stop_timeout_kill() -> u64 {
    15
}

fn default_auto_fs_gc() -> bool {
    true
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
            default_export_free_space: default_export_free_space(),
            tasks_max: default_tasks_max(),
            docker_user: String::new(),
            docker_token: String::new(),
            oci_cache_dir: String::new(),
            oci_cache_max_size: default_oci_cache_max_size(),
            http_timeout: default_http_timeout(),
            http_body_timeout: default_http_body_timeout(),
            max_download_size: default_max_download_size(),
            nixpkgs_channel: default_nixpkgs_channel(),
            nix_config_template: String::new(),
            stop_timeout_graceful: default_stop_timeout_graceful(),
            stop_timeout_terminate: default_stop_timeout_terminate(),
            stop_timeout_kill: default_stop_timeout_kill(),
            auto_fs_gc: default_auto_fs_gc(),
            distros: HashMap::new(),
        }
    }
}

/// HTTP-related configuration for downloads and OCI registry pulls.
#[derive(Debug, Clone)]
pub struct HttpConfig {
    /// HTTP connect/resolve timeout in seconds.
    pub connect_timeout: u64,
    /// HTTP body receive timeout in seconds.
    pub body_timeout: u64,
    /// Maximum download size in bytes (0 = unlimited).
    pub max_download_size: u64,
}

impl Config {
    /// Build an [`HttpConfig`] from this config, parsing the `max_download_size` string.
    pub fn http_config(&self) -> Result<HttpConfig> {
        Ok(HttpConfig {
            connect_timeout: self.http_timeout,
            body_timeout: self.http_body_timeout,
            max_download_size: crate::parse_size(&self.max_download_size)?,
        })
    }

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
        println!(
            "default_export_free_space = {}",
            self.default_export_free_space
        );
        println!("tasks_max = {}", self.tasks_max);
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
        println!("http_timeout = {}", self.http_timeout);
        println!("http_body_timeout = {}", self.http_body_timeout);
        println!("max_download_size = {}", self.max_download_size);
        println!("nixpkgs_channel = {}", self.nixpkgs_channel);
        println!("nix_config_template = {}", self.nix_config_template);
        println!("stop_timeout_graceful = {}", self.stop_timeout_graceful);
        println!("stop_timeout_terminate = {}", self.stop_timeout_terminate);
        println!("stop_timeout_kill = {}", self.stop_timeout_kill);
        let auto_fs_gc = if self.auto_fs_gc { "yes" } else { "no" };
        println!("auto_fs_gc = {auto_fs_gc}");
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

/// Save the full configuration to disk with restrictive permissions.
pub fn save(config: &Config, path: Option<&Path>) -> Result<()> {
    let path = resolve_path(path);
    let contents = toml::to_string(config).context("failed to serialize config")?;
    write_config(&path, &contents)
}

/// Set or remove a single key in the config file without touching other keys.
///
/// Supports dot-separated keys for nested tables (e.g. `distros.debian.import_prehook`).
/// When `value` is `None`, the key is removed; empty parent tables are cleaned up.
pub fn save_key(path: Option<&Path>, key: &str, value: Option<toml::Value>) -> Result<()> {
    let path = resolve_path(path);
    let mut table = if path.exists() {
        let contents = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        contents
            .parse::<toml::Table>()
            .with_context(|| format!("failed to parse {}", path.display()))?
    } else {
        toml::Table::new()
    };

    let parts: Vec<&str> = key.split('.').collect();
    match value {
        Some(val) => set_nested(&mut table, &parts, val),
        None => {
            remove_nested(&mut table, &parts);
        }
    }

    let contents = toml::to_string(&table).context("failed to serialize config")?;
    write_config(&path, &contents)
}

fn write_config(path: &Path, contents: &str) -> Result<()> {
    crate::atomic_write(path, contents.as_bytes())
        .with_context(|| format!("failed to write config {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("failed to set permissions on {}", path.display()))?;
    Ok(())
}

/// Set a value at a dot-separated key path, creating intermediate tables as needed.
fn set_nested(table: &mut toml::Table, parts: &[&str], value: toml::Value) {
    if parts.len() == 1 {
        table.insert(parts[0].to_string(), value);
        return;
    }
    let entry = table
        .entry(parts[0])
        .or_insert_with(|| toml::Value::Table(toml::Table::new()));
    if let toml::Value::Table(ref mut inner) = entry {
        set_nested(inner, &parts[1..], value);
    }
}

/// Remove a value at a dot-separated key path, cleaning up empty parent tables.
fn remove_nested(table: &mut toml::Table, parts: &[&str]) {
    if parts.len() == 1 {
        table.remove(parts[0]);
        return;
    }
    if let Some(toml::Value::Table(ref mut inner)) = table.get_mut(parts[0]) {
        remove_nested(inner, &parts[1..]);
        if inner.is_empty() {
            table.remove(parts[0]);
        }
    }
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

    #[test]
    fn test_default_distros_empty() {
        let config = Config::default();
        assert!(config.distros.is_empty());
    }

    #[test]
    fn test_save_and_load_distros() {
        let path = temp_config_path();
        let mut distros = HashMap::new();
        distros.insert(
            "debian".to_string(),
            DistroCommands {
                import_prehook: Some(vec!["echo hello".to_string()]),
                export_prehook: None,
                export_vm_prehook: None,
            },
        );
        let config = Config {
            distros,
            ..Config::default()
        };
        save(&config, Some(&path)).unwrap();
        let loaded = load(Some(&path)).unwrap();
        let debian = loaded.distros.get("debian").unwrap();
        assert_eq!(debian.import_prehook, Some(vec!["echo hello".to_string()]));
        assert_eq!(debian.export_prehook, None);
        assert_eq!(debian.export_vm_prehook, None);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_distros_not_serialized_when_empty() {
        let path = temp_config_path();
        let config = Config::default();
        save(&config, Some(&path)).unwrap();
        let contents = fs::read_to_string(&path).unwrap();
        assert!(
            !contents.contains("[distros"),
            "empty distros should not appear in config file"
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_load_config_with_distros_section() {
        let path = temp_config_path();
        fs::write(
            &path,
            r#"
[distros.fedora]
import_prehook = ["dnf install -y custom-pkg"]
export_prehook = ["dnf install -y custom-udev"]
export_vm_prehook = ["dnf install -y udev-vm"]
"#,
        )
        .unwrap();
        let config = load(Some(&path)).unwrap();
        let fedora = config.distros.get("fedora").unwrap();
        assert_eq!(
            fedora.import_prehook,
            Some(vec!["dnf install -y custom-pkg".to_string()])
        );
        assert_eq!(
            fedora.export_prehook,
            Some(vec!["dnf install -y custom-udev".to_string()])
        );
        assert_eq!(
            fedora.export_vm_prehook,
            Some(vec!["dnf install -y udev-vm".to_string()])
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_distros_roundtrip_empty_vec() {
        let path = temp_config_path();
        let mut distros = HashMap::new();
        distros.insert(
            "arch".to_string(),
            DistroCommands {
                import_prehook: Some(vec![]),
                export_prehook: None,
                export_vm_prehook: None,
            },
        );
        let config = Config {
            distros,
            ..Config::default()
        };
        save(&config, Some(&path)).unwrap();
        let loaded = load(Some(&path)).unwrap();
        let arch = loaded.distros.get("arch").unwrap();
        assert_eq!(arch.import_prehook, Some(vec![]));
        assert_eq!(arch.export_prehook, None);
        assert_eq!(arch.export_vm_prehook, None);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_save_key_only_writes_target_key() {
        let path = temp_config_path();
        // Start with a file that has just one key.
        fs::write(&path, "boot_timeout = 30\n").unwrap();

        // Set a different key; boot_timeout should remain untouched.
        save_key(
            Some(&path),
            "interactive",
            Some(toml::Value::Boolean(false)),
        )
        .unwrap();

        let contents = fs::read_to_string(&path).unwrap();
        assert!(contents.contains("boot_timeout = 30"), "got: {contents}");
        assert!(contents.contains("interactive = false"), "got: {contents}");
        // Should NOT contain default keys that weren't in the original file.
        assert!(
            !contents.contains("datadir"),
            "save_key should not add default keys: {contents}"
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_save_key_creates_file() {
        let path = temp_config_path();
        let _ = fs::remove_file(&path);

        save_key(
            Some(&path),
            "docker_user",
            Some(toml::Value::String("me".into())),
        )
        .unwrap();

        let contents = fs::read_to_string(&path).unwrap();
        assert_eq!(contents.trim(), r#"docker_user = "me""#);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_save_key_nested_set_and_remove() {
        let path = temp_config_path();
        let _ = fs::remove_file(&path);

        // Set a nested distros key.
        save_key(
            Some(&path),
            "distros.debian.import_prehook",
            Some(toml::Value::Array(vec![toml::Value::String(
                "echo hi".into(),
            )])),
        )
        .unwrap();

        let loaded = load(Some(&path)).unwrap();
        let debian = loaded.distros.get("debian").unwrap();
        assert_eq!(debian.import_prehook, Some(vec!["echo hi".to_string()]));

        // Remove it; the distros section should disappear.
        save_key(Some(&path), "distros.debian.import_prehook", None).unwrap();

        let contents = fs::read_to_string(&path).unwrap();
        assert!(
            !contents.contains("distros"),
            "empty distros table should be cleaned up: {contents}"
        );
        let _ = fs::remove_file(&path);
    }
}
