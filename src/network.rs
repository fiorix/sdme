//! Network configuration for containers.
//!
//! Controls network namespace isolation and connectivity options.
//! Configuration is stored in the container's state file and converted
//! to systemd-nspawn flags at start time.

use anyhow::{bail, Result};

use crate::State;

/// Network configuration for containers.
///
/// Controls network namespace isolation and connectivity options.
/// Stored in the container's state file and converted to systemd-nspawn
/// flags at start time.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct NetworkConfig {
    /// Use private network namespace (--private-network)
    pub private_network: bool,
    /// Create virtual ethernet link (--network-veth)
    pub network_veth: bool,
    /// Connect to host bridge (--network-bridge=<name>)
    pub network_bridge: Option<String>,
    /// Join named network zone (--network-zone=<name>)
    pub network_zone: Option<String>,
    /// Port forwarding rules (--port=<host>:<container>[/<proto>])
    pub ports: Vec<String>,
}

impl NetworkConfig {
    /// Returns true if no network options are set (uses host network).
    pub fn is_empty(&self) -> bool {
        !self.private_network
            && !self.network_veth
            && self.network_bridge.is_none()
            && self.network_zone.is_none()
            && self.ports.is_empty()
    }

    /// Read network config from a state file's key-value pairs.
    pub fn from_state(state: &State) -> Self {
        Self {
            private_network: state.get("PRIVATE_NETWORK").map_or(false, |s| s == "1"),
            network_veth: state.get("NETWORK_VETH").map_or(false, |s| s == "1"),
            network_bridge: state
                .get("NETWORK_BRIDGE")
                .filter(|s| !s.is_empty())
                .map(String::from),
            network_zone: state
                .get("NETWORK_ZONE")
                .filter(|s| !s.is_empty())
                .map(String::from),
            ports: state
                .get("PORTS")
                .filter(|s| !s.is_empty())
                .map(|s| s.split(',').map(String::from).collect())
                .unwrap_or_default(),
        }
    }

    /// Write network config into a state's key-value pairs.
    pub fn write_to_state(&self, state: &mut State) {
        if self.private_network {
            state.set("PRIVATE_NETWORK", "1");
        } else {
            state.remove("PRIVATE_NETWORK");
        }

        if self.network_veth {
            state.set("NETWORK_VETH", "1");
        } else {
            state.remove("NETWORK_VETH");
        }

        match &self.network_bridge {
            Some(v) => state.set("NETWORK_BRIDGE", v.as_str()),
            None => state.remove("NETWORK_BRIDGE"),
        }

        match &self.network_zone {
            Some(v) => state.set("NETWORK_ZONE", v.as_str()),
            None => state.remove("NETWORK_ZONE"),
        }

        if self.ports.is_empty() {
            state.remove("PORTS");
        } else {
            state.set("PORTS", self.ports.join(","));
        }
    }

    /// Generate systemd-nspawn arguments for network configuration.
    ///
    /// Returns the arguments as a space-separated string suitable for
    /// inclusion in an environment file.
    pub fn to_nspawn_args(&self) -> String {
        let mut args = Vec::new();

        if self.private_network {
            args.push("--private-network".to_string());
        }

        // --resolv-conf=auto is always needed
        args.push("--resolv-conf=auto".to_string());

        if self.network_veth {
            args.push("--network-veth".to_string());
        }

        if let Some(bridge) = &self.network_bridge {
            args.push(format!("--network-bridge={bridge}"));
        }

        if let Some(zone) = &self.network_zone {
            args.push(format!("--network-zone={zone}"));
        }

        for port in &self.ports {
            args.push(format!("--port={port}"));
        }

        args.join(" ")
    }

    /// Validate all network options.
    ///
    /// Checks that:
    /// - Port forwarding, veth, bridge, and zone require private-network
    /// - Port format is valid
    /// - Bridge/zone names are valid identifiers
    pub fn validate(&self) -> Result<()> {
        // Check that options requiring private-network have it enabled
        let requires_private = self.network_veth
            || self.network_bridge.is_some()
            || self.network_zone.is_some()
            || !self.ports.is_empty();

        if requires_private && !self.private_network {
            bail!(
                "--network-veth, --network-bridge, --network-zone, and --port \
                 require --private-network"
            );
        }

        // Validate bridge name
        if let Some(bridge) = &self.network_bridge {
            validate_network_name(bridge, "bridge")?;
        }

        // Validate zone name
        if let Some(zone) = &self.network_zone {
            validate_network_name(zone, "zone")?;
        }

        // Validate port forwarding rules
        for port in &self.ports {
            validate_port(port)?;
        }

        Ok(())
    }
}

/// Validate a network bridge or zone name.
///
/// Names must be non-empty and contain only alphanumeric characters,
/// hyphens, and underscores.
fn validate_network_name(name: &str, kind: &str) -> Result<()> {
    if name.is_empty() {
        bail!("--network-{kind} name cannot be empty");
    }
    for ch in name.chars() {
        if !ch.is_ascii_alphanumeric() && ch != '-' && ch != '_' {
            bail!(
                "invalid --network-{kind} name '{name}': \
                 may only contain alphanumeric characters, hyphens, and underscores"
            );
        }
    }
    Ok(())
}

/// Validate a port forwarding rule.
///
/// Format: `<host>:<container>` or `<host>:<container>/<proto>`
/// where proto is `tcp` or `udp`.
fn validate_port(port: &str) -> Result<()> {
    // Split off protocol if present
    let (port_part, proto) = if let Some((p, proto)) = port.rsplit_once('/') {
        (p, Some(proto))
    } else {
        (port, None)
    };

    // Validate protocol
    if let Some(proto) = proto {
        if proto != "tcp" && proto != "udp" {
            bail!(
                "invalid port protocol '{proto}' in '{port}': \
                 expected 'tcp' or 'udp'"
            );
        }
    }

    // Split host:container
    let (host, container) = port_part.split_once(':').ok_or_else(|| {
        anyhow::anyhow!(
            "invalid port format '{port}': expected <host>:<container>[/<proto>]"
        )
    })?;

    // Validate port numbers
    validate_port_number(host, port, "host")?;
    validate_port_number(container, port, "container")?;

    Ok(())
}

/// Validate a port number string.
fn validate_port_number(s: &str, full: &str, which: &str) -> Result<()> {
    let n: u16 = s.parse().map_err(|_| {
        anyhow::anyhow!(
            "invalid {which} port '{s}' in '{full}': expected 1–65535"
        )
    })?;
    if n == 0 {
        bail!("invalid {which} port '{s}' in '{full}': port 0 is not allowed");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- NetworkConfig tests ---

    #[test]
    fn test_network_default_is_empty() {
        let network = NetworkConfig::default();
        assert!(network.is_empty());
    }

    #[test]
    fn test_network_private_network_not_empty() {
        let network = NetworkConfig {
            private_network: true,
            ..Default::default()
        };
        assert!(!network.is_empty());
    }

    #[test]
    fn test_network_validate_ok() {
        // Private network only
        let network = NetworkConfig {
            private_network: true,
            ..Default::default()
        };
        assert!(network.validate().is_ok());

        // Private network with veth
        let network = NetworkConfig {
            private_network: true,
            network_veth: true,
            ..Default::default()
        };
        assert!(network.validate().is_ok());

        // Private network with bridge
        let network = NetworkConfig {
            private_network: true,
            network_bridge: Some("br0".to_string()),
            ..Default::default()
        };
        assert!(network.validate().is_ok());

        // Private network with zone
        let network = NetworkConfig {
            private_network: true,
            network_zone: Some("myzone".to_string()),
            ..Default::default()
        };
        assert!(network.validate().is_ok());

        // Private network with port
        let network = NetworkConfig {
            private_network: true,
            ports: vec!["8080:80".to_string()],
            ..Default::default()
        };
        assert!(network.validate().is_ok());
    }

    #[test]
    fn test_network_validate_requires_private() {
        // veth without private network
        let network = NetworkConfig {
            network_veth: true,
            ..Default::default()
        };
        assert!(network.validate().is_err());

        // bridge without private network
        let network = NetworkConfig {
            network_bridge: Some("br0".to_string()),
            ..Default::default()
        };
        assert!(network.validate().is_err());

        // zone without private network
        let network = NetworkConfig {
            network_zone: Some("myzone".to_string()),
            ..Default::default()
        };
        assert!(network.validate().is_err());

        // port without private network
        let network = NetworkConfig {
            ports: vec!["8080:80".to_string()],
            ..Default::default()
        };
        assert!(network.validate().is_err());
    }

    #[test]
    fn test_network_validate_port_formats() {
        let make_network = |port: &str| NetworkConfig {
            private_network: true,
            ports: vec![port.to_string()],
            ..Default::default()
        };

        // Valid formats
        assert!(make_network("8080:80").validate().is_ok());
        assert!(make_network("8080:80/tcp").validate().is_ok());
        assert!(make_network("8080:80/udp").validate().is_ok());
        assert!(make_network("1:1").validate().is_ok());
        assert!(make_network("65535:65535").validate().is_ok());

        // Invalid formats
        assert!(make_network("8080").validate().is_err()); // missing container port
        assert!(make_network("8080:").validate().is_err()); // empty container port
        assert!(make_network(":80").validate().is_err()); // empty host port
        assert!(make_network("8080:80/http").validate().is_err()); // invalid protocol
        assert!(make_network("0:80").validate().is_err()); // port 0
        assert!(make_network("8080:0").validate().is_err()); // port 0
        assert!(make_network("65536:80").validate().is_err()); // port > 65535
        assert!(make_network("abc:80").validate().is_err()); // non-numeric
    }

    #[test]
    fn test_network_validate_bridge_zone_names() {
        // Valid names
        let network = NetworkConfig {
            private_network: true,
            network_bridge: Some("br0".to_string()),
            network_zone: Some("my_zone-1".to_string()),
            ..Default::default()
        };
        assert!(network.validate().is_ok());

        // Invalid bridge name
        let network = NetworkConfig {
            private_network: true,
            network_bridge: Some("br/0".to_string()),
            ..Default::default()
        };
        assert!(network.validate().is_err());

        // Invalid zone name
        let network = NetworkConfig {
            private_network: true,
            network_zone: Some("my zone".to_string()),
            ..Default::default()
        };
        assert!(network.validate().is_err());

        // Empty names
        let network = NetworkConfig {
            private_network: true,
            network_bridge: Some("".to_string()),
            ..Default::default()
        };
        assert!(network.validate().is_err());
    }

    #[test]
    fn test_network_to_nspawn_args_empty() {
        let network = NetworkConfig::default();
        assert_eq!(network.to_nspawn_args(), "--resolv-conf=auto");
    }

    #[test]
    fn test_network_to_nspawn_args_private_only() {
        let network = NetworkConfig {
            private_network: true,
            ..Default::default()
        };
        assert_eq!(
            network.to_nspawn_args(),
            "--private-network --resolv-conf=auto"
        );
    }

    #[test]
    fn test_network_to_nspawn_args_full() {
        let network = NetworkConfig {
            private_network: true,
            network_veth: true,
            network_bridge: Some("br0".to_string()),
            network_zone: Some("myzone".to_string()),
            ports: vec!["8080:80".to_string(), "443:443/tcp".to_string()],
        };
        let args = network.to_nspawn_args();
        assert!(args.contains("--private-network"));
        assert!(args.contains("--resolv-conf=auto"));
        assert!(args.contains("--network-veth"));
        assert!(args.contains("--network-bridge=br0"));
        assert!(args.contains("--network-zone=myzone"));
        assert!(args.contains("--port=8080:80"));
        assert!(args.contains("--port=443:443/tcp"));
    }

    #[test]
    fn test_network_state_roundtrip() {
        let network = NetworkConfig {
            private_network: true,
            network_veth: true,
            network_bridge: Some("br0".to_string()),
            network_zone: None,
            ports: vec!["8080:80".to_string(), "443:443".to_string()],
        };

        let mut state = State::new();
        state.set("NAME", "test");
        network.write_to_state(&mut state);

        let serialized = state.serialize();
        let parsed = State::parse(&serialized).unwrap();
        let restored = NetworkConfig::from_state(&parsed);

        assert_eq!(restored.private_network, true);
        assert_eq!(restored.network_veth, true);
        assert_eq!(restored.network_bridge, Some("br0".to_string()));
        assert_eq!(restored.network_zone, None);
        assert_eq!(restored.ports, vec!["8080:80", "443:443"]);
    }

    #[test]
    fn test_network_state_remove() {
        let mut state = State::new();
        state.set("PRIVATE_NETWORK", "1");
        state.set("NETWORK_VETH", "1");
        state.set("NETWORK_BRIDGE", "br0");
        state.set("PORTS", "8080:80");

        let network = NetworkConfig {
            private_network: true,
            ..Default::default()
        };
        network.write_to_state(&mut state);

        assert_eq!(state.get("PRIVATE_NETWORK"), Some("1"));
        assert_eq!(state.get("NETWORK_VETH"), None); // removed
        assert_eq!(state.get("NETWORK_BRIDGE"), None); // removed
        assert_eq!(state.get("PORTS"), None); // removed
    }
}
