//! Serde deserialization types for devcontainer.json.
//!
//! These types map directly to the Dev Container specification schema.
//! Validation and conversion to internal types happens in [`super::plan`].

use std::collections::HashMap;

use serde::Deserialize;

/// Root devcontainer.json configuration.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub(super) struct DevcontainerConfig {
    /// Human-readable name for the dev container.
    pub name: Option<String>,

    // --- Container source (one of these must be set) ---
    /// OCI image reference (e.g. "ubuntu:22.04", "mcr.microsoft.com/devcontainers/base:ubuntu").
    pub image: Option<String>,

    /// Build configuration using a Dockerfile.
    pub build: Option<BuildConfig>,

    // --- Workspace ---
    /// Override the default workspace mount (set to empty string to disable).
    pub workspace_mount: Option<String>,

    /// Path inside the container where the workspace is mounted.
    pub workspace_folder: Option<String>,

    // --- User ---
    /// User to run commands as inside the container.
    pub remote_user: Option<String>,

    /// User to use when creating the container (affects file ownership).
    pub container_user: Option<String>,

    // --- Environment variables ---
    /// Environment variables set at container runtime.
    pub remote_env: Option<HashMap<String, String>>,

    /// Environment variables set during container build and runtime.
    pub container_env: Option<HashMap<String, String>>,

    // --- Mounts ---
    /// Additional mounts (bind, volume, tmpfs).
    #[serde(default)]
    pub mounts: Vec<MountEntry>,

    // --- Ports ---
    /// Ports to forward from the container.
    #[serde(default)]
    pub forward_ports: Vec<PortEntry>,

    // --- Lifecycle hooks ---
    /// Runs once when the container is first created.
    pub on_create_command: Option<LifecycleCommand>,

    /// Runs when container is created or source code changes.
    pub update_content_command: Option<LifecycleCommand>,

    /// Runs after updateContentCommand completes.
    pub post_create_command: Option<LifecycleCommand>,

    /// Runs every time the container starts.
    pub post_start_command: Option<LifecycleCommand>,

    /// Runs when a tool attaches to the container.
    pub post_attach_command: Option<LifecycleCommand>,

    // --- Features ---
    /// Dev Container Features to install (OCI artifact references with options).
    #[serde(default)]
    pub features: HashMap<String, serde_json::Value>,

    // --- Container runtime settings ---
    /// Additional arguments to pass to the container runtime.
    #[serde(default)]
    pub run_args: Vec<String>,

    /// Capabilities to add to the container.
    #[serde(default)]
    pub cap_add: Vec<String>,

    /// Security options for the container.
    #[serde(default)]
    pub security_opt: Vec<String>,

    /// Run an init process (PID 1) inside the container.
    pub init: Option<bool>,

    /// Run the container in privileged mode.
    pub privileged: Option<bool>,

    /// Override the default command.
    pub override_command: Option<bool>,

    /// Action to take when the tool stops: "none" or "stopContainer".
    pub shutdown_action: Option<String>,

    // --- Customizations ---
    /// Tool-specific customizations (e.g. vscode extensions/settings).
    pub customizations: Option<HashMap<String, serde_json::Value>>,
}

/// Dockerfile build configuration.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct BuildConfig {
    /// Path to the Dockerfile (relative to devcontainer.json).
    pub dockerfile: String,

    /// Build context directory (relative to devcontainer.json).
    pub context: Option<String>,

    /// Build arguments.
    #[serde(default)]
    pub args: HashMap<String, String>,

    /// Target build stage.
    pub target: Option<String>,
}

/// A mount entry can be either a structured object or a Docker-style string.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(super) enum MountEntry {
    /// Structured mount object.
    Object(MountObject),
    /// Docker CLI-style string: "source=...,target=...,type=bind".
    String(String),
}

/// Structured mount definition.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct MountObject {
    /// Mount type: "bind", "volume", or "tmpfs".
    #[serde(rename = "type")]
    pub mount_type: Option<String>,

    /// Source path (host path for bind, volume name for volume).
    pub source: Option<String>,

    /// Target path inside the container.
    pub target: String,

    /// Whether the mount is read-only.
    #[serde(default)]
    pub readonly: bool,
}

/// A port entry can be a number or a string like "8443:8443".
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(super) enum PortEntry {
    /// Simple port number (same port on host and container).
    Number(u16),
    /// Port mapping string "host:container" or just "port".
    String(String),
}

/// A lifecycle command can be a string, array of strings, or object of parallel commands.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(super) enum LifecycleCommand {
    /// Single command string (run via shell).
    String(String),
    /// Array of command strings (run sequentially).
    Array(Vec<String>),
    /// Named parallel commands (keys are labels, values are commands).
    Object(HashMap<String, String>),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_image() {
        let json = r#"{ "image": "ubuntu:22.04" }"#;
        let config: DevcontainerConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.image.as_deref(), Some("ubuntu:22.04"));
        assert!(config.build.is_none());
        assert!(config.name.is_none());
    }

    #[test]
    fn test_parse_full_config() {
        let json = r#"{
            "name": "Test Dev Container",
            "image": "mcr.microsoft.com/devcontainers/base:ubuntu",
            "workspaceFolder": "/workspace",
            "remoteUser": "vscode",
            "remoteEnv": { "MY_VAR": "value" },
            "containerEnv": { "BUILD_VAR": "dev" },
            "forwardPorts": [3000, "8080:8080"],
            "postCreateCommand": "npm install",
            "postStartCommand": { "server": "npm start", "watcher": "npm run watch" },
            "mounts": [
                { "type": "bind", "source": "/host/path", "target": "/container/path" },
                "source=/tmp,target=/tmp,type=bind"
            ],
            "capAdd": ["SYS_PTRACE"],
            "features": {
                "ghcr.io/devcontainers/features/node:1": { "version": "20" }
            },
            "customizations": {
                "vscode": {
                    "extensions": ["rust-lang.rust-analyzer"]
                }
            }
        }"#;
        let config: DevcontainerConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.name.as_deref(), Some("Test Dev Container"));
        assert_eq!(config.workspace_folder.as_deref(), Some("/workspace"));
        assert_eq!(config.remote_user.as_deref(), Some("vscode"));
        assert_eq!(config.forward_ports.len(), 2);
        assert_eq!(config.mounts.len(), 2);
        assert_eq!(config.cap_add, vec!["SYS_PTRACE"]);
        assert_eq!(config.features.len(), 1);
        assert!(config.post_create_command.is_some());
        assert!(config.post_start_command.is_some());
    }

    #[test]
    fn test_parse_build_config() {
        let json = r#"{
            "build": {
                "dockerfile": "Dockerfile",
                "context": "..",
                "args": { "VARIANT": "bullseye" }
            }
        }"#;
        let config: DevcontainerConfig = serde_json::from_str(json).unwrap();
        let build = config.build.unwrap();
        assert_eq!(build.dockerfile, "Dockerfile");
        assert_eq!(build.context.as_deref(), Some(".."));
        assert_eq!(build.args.get("VARIANT").unwrap(), "bullseye");
    }

    #[test]
    fn test_lifecycle_command_variants() {
        // String
        let json = r#"{ "postCreateCommand": "npm install" }"#;
        let config: DevcontainerConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.post_create_command,
            Some(LifecycleCommand::String(_))
        ));

        // Array
        let json = r#"{ "postCreateCommand": ["npm install", "npm build"] }"#;
        let config: DevcontainerConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.post_create_command,
            Some(LifecycleCommand::Array(_))
        ));

        // Object
        let json = r#"{ "postCreateCommand": { "install": "npm install", "build": "npm build" } }"#;
        let config: DevcontainerConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.post_create_command,
            Some(LifecycleCommand::Object(_))
        ));
    }

    #[test]
    fn test_mount_entry_variants() {
        let json = r#"{
            "mounts": [
                { "type": "bind", "source": "/src", "target": "/dst", "readonly": true },
                "source=/a,target=/b,type=bind"
            ]
        }"#;
        let config: DevcontainerConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.mounts.len(), 2);
        match &config.mounts[0] {
            MountEntry::Object(m) => {
                assert_eq!(m.mount_type.as_deref(), Some("bind"));
                assert!(m.readonly);
            }
            _ => panic!("expected object mount"),
        }
        match &config.mounts[1] {
            MountEntry::String(s) => assert!(s.contains("source=/a")),
            _ => panic!("expected string mount"),
        }
    }

    #[test]
    fn test_port_entry_variants() {
        let json = r#"{ "forwardPorts": [3000, "8443:8443"] }"#;
        let config: DevcontainerConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.forward_ports.len(), 2);
        assert!(matches!(config.forward_ports[0], PortEntry::Number(3000)));
        assert!(matches!(&config.forward_ports[1], PortEntry::String(s) if s == "8443:8443"));
    }
}
