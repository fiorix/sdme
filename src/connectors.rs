//! Connector configuration for containers.
//!
//! Controls which service connectors are bind-mounted into a container,
//! enabling cross-container service access via the proxy mechanism.
//! Configuration is stored in the container's state file and converted
//! to systemd-nspawn flags at start time.

use std::path::Path;

use anyhow::{bail, Result};

use crate::{validate_name, State};

/// Connector directory on the host filesystem.
pub const CONNECTORS_DIR: &str = "/var/lib/sdme/connectors";

/// Connector configuration for containers.
///
/// Stores the names of service connectors to bind-mount into the container.
/// Each connector name corresponds to a directory under [`CONNECTORS_DIR`].
#[derive(Debug, Default, Clone, PartialEq)]
pub struct ConnectorConfig {
    /// Connector names (each maps to a directory under CONNECTORS_DIR).
    pub connectors: Vec<String>,
}

impl ConnectorConfig {
    /// Returns true if no connectors are configured.
    pub fn is_empty(&self) -> bool {
        self.connectors.is_empty()
    }

    /// Read connector config from a state file's key-value pairs.
    pub fn from_state(state: &State) -> Self {
        Self {
            connectors: state
                .get("CONNECTORS")
                .filter(|s| !s.is_empty())
                .map(|s| s.split(',').map(String::from).collect())
                .unwrap_or_default(),
        }
    }

    /// Write connector config into a state's key-value pairs.
    pub fn write_to_state(&self, state: &mut State) {
        if self.connectors.is_empty() {
            state.remove("CONNECTORS");
        } else {
            state.set("CONNECTORS", self.connectors.join(","));
        }
    }

    /// Validate all connector names and verify their directories exist.
    pub fn validate(&self, datadir: &Path) -> Result<()> {
        let mut seen = std::collections::HashSet::new();
        for name in &self.connectors {
            validate_name(name)
                .map_err(|_| anyhow::anyhow!("invalid connector name: {name}"))?;
            if !seen.insert(name.clone()) {
                bail!("duplicate connector: {name}");
            }
            let dir = connector_dir(datadir, name);
            if !dir.is_dir() {
                bail!(
                    "connector directory not found: {} \
                     (has a rootfs been imported with --oci-mode=connector?)",
                    dir.display()
                );
            }
        }
        Ok(())
    }

    /// Generate systemd-nspawn arguments for connector bind mounts.
    ///
    /// For each connector, generates a read-only bind mount from the
    /// host-side connector directory into `/connectors/<name>/` inside
    /// the container. Also sets `SDME_CONNECTOR_DIR` so busybox-style
    /// proxy client symlinks can find the connector directory.
    pub fn to_nspawn_args(&self, datadir: &Path) -> Vec<String> {
        let mut args = Vec::new();

        for name in &self.connectors {
            let host_dir = connector_dir(datadir, name);
            args.push(format!(
                "--bind-ro={}:/connectors/{name}",
                host_dir.display()
            ));
        }

        // Set SDME_CONNECTOR_DIR for the client proxy.
        if self.connectors.len() == 1 {
            args.push(format!(
                "--setenv=SDME_CONNECTOR_DIR=/connectors/{}",
                self.connectors[0]
            ));
        } else if self.connectors.len() > 1 {
            args.push("--setenv=SDME_CONNECTOR_DIR=/connectors".to_string());
        }

        args
    }

    /// Add a connector, returning true if it was newly added.
    pub fn add(&mut self, name: &str) -> bool {
        if self.connectors.iter().any(|n| n == name) {
            return false;
        }
        self.connectors.push(name.to_string());
        true
    }

    /// Remove a connector, returning true if it was present.
    pub fn remove(&mut self, name: &str) -> bool {
        let len_before = self.connectors.len();
        self.connectors.retain(|n| n != name);
        self.connectors.len() < len_before
    }
}

/// Returns the host-side path for a connector directory.
pub fn connector_dir(datadir: &Path, name: &str) -> std::path::PathBuf {
    datadir.join("connectors").join(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connector_config_default_is_empty() {
        let config = ConnectorConfig::default();
        assert!(config.is_empty());
        assert!(config.to_nspawn_args(Path::new("/var/lib/sdme")).is_empty());
    }

    #[test]
    fn test_connector_config_state_roundtrip() {
        let config = ConnectorConfig {
            connectors: vec!["nginx".to_string(), "redis".to_string()],
        };

        let mut state = State::new();
        state.set("NAME", "test");
        config.write_to_state(&mut state);

        let serialized = state.serialize();
        let parsed = State::parse(&serialized).unwrap();
        let restored = ConnectorConfig::from_state(&parsed);

        assert_eq!(restored.connectors, config.connectors);
    }

    #[test]
    fn test_connector_config_state_empty() {
        let config = ConnectorConfig::default();

        let mut state = State::new();
        state.set("CONNECTORS", "old");
        config.write_to_state(&mut state);

        assert_eq!(state.get("CONNECTORS"), None);
    }

    #[test]
    fn test_connector_config_to_nspawn_args_single() {
        let config = ConnectorConfig {
            connectors: vec!["nginx".to_string()],
        };
        let args = config.to_nspawn_args(Path::new("/var/lib/sdme"));
        assert_eq!(
            args,
            vec![
                "--bind-ro=/var/lib/sdme/connectors/nginx:/connectors/nginx",
                "--setenv=SDME_CONNECTOR_DIR=/connectors/nginx",
            ]
        );
    }

    #[test]
    fn test_connector_config_to_nspawn_args_multiple() {
        let config = ConnectorConfig {
            connectors: vec!["nginx".to_string(), "redis".to_string()],
        };
        let args = config.to_nspawn_args(Path::new("/var/lib/sdme"));
        assert_eq!(
            args,
            vec![
                "--bind-ro=/var/lib/sdme/connectors/nginx:/connectors/nginx",
                "--bind-ro=/var/lib/sdme/connectors/redis:/connectors/redis",
                "--setenv=SDME_CONNECTOR_DIR=/connectors",
            ]
        );
    }

    #[test]
    fn test_connector_config_add_remove() {
        let mut config = ConnectorConfig::default();
        assert!(config.add("nginx"));
        assert!(!config.add("nginx")); // duplicate
        assert!(config.add("redis"));
        assert_eq!(config.connectors, vec!["nginx", "redis"]);

        assert!(config.remove("nginx"));
        assert!(!config.remove("nginx")); // already removed
        assert_eq!(config.connectors, vec!["redis"]);
    }

    #[test]
    fn test_connector_validate_missing_dir() {
        let tmp = std::env::temp_dir().join(format!(
            "sdme-test-connector-validate-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let config = ConnectorConfig {
            connectors: vec!["nonexistent".to_string()],
        };
        let err = config.validate(&tmp).unwrap_err();
        assert!(
            err.to_string().contains("not found"),
            "unexpected error: {err}"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_connector_validate_duplicate() {
        let tmp = std::env::temp_dir().join(format!(
            "sdme-test-connector-validate-dup-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        let connector_dir = tmp.join("connectors/nginx");
        std::fs::create_dir_all(&connector_dir).unwrap();

        let config = ConnectorConfig {
            connectors: vec!["nginx".to_string(), "nginx".to_string()],
        };
        let err = config.validate(&tmp).unwrap_err();
        assert!(
            err.to_string().contains("duplicate"),
            "unexpected error: {err}"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_connector_validate_ok() {
        let tmp = std::env::temp_dir().join(format!(
            "sdme-test-connector-validate-ok-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        let connector_dir = tmp.join("connectors/nginx");
        std::fs::create_dir_all(&connector_dir).unwrap();

        let config = ConnectorConfig {
            connectors: vec!["nginx".to_string()],
        };
        assert!(config.validate(&tmp).is_ok());

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
