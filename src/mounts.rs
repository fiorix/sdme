//! Bind mount and environment variable configuration for containers.
//!
//! Controls custom bind mounts and environment variables passed to
//! systemd-nspawn at start time. Configuration is stored in the
//! container's state file and converted to systemd-nspawn flags.

use std::path::{Component, Path};

use anyhow::{bail, Result};

use crate::State;

/// Bind mount configuration for containers.
///
/// Stores bind mount specifications as `HOST:CONTAINER:MODE` where
/// MODE is `rw` (read-write) or `ro` (read-only).
#[derive(Debug, Default, Clone, PartialEq)]
pub struct BindConfig {
    /// Bind mount specifications in internal format: "host:container:rw" or "host:container:ro"
    pub binds: Vec<String>,
}

impl BindConfig {
    /// Returns true if no bind mounts are configured.
    pub fn is_empty(&self) -> bool {
        self.binds.is_empty()
    }

    /// Read bind config from a state file's key-value pairs.
    pub fn from_state(state: &State) -> Self {
        Self {
            binds: state
                .get("BINDS")
                .filter(|s| !s.is_empty())
                .map(|s| s.split('|').map(String::from).collect())
                .unwrap_or_default(),
        }
    }

    /// Write bind config into a state's key-value pairs.
    pub fn write_to_state(&self, state: &mut State) {
        if self.binds.is_empty() {
            state.remove("BINDS");
        } else {
            state.set("BINDS", self.binds.join("|"));
        }
    }

    /// Generate systemd-nspawn arguments for bind mounts.
    ///
    /// Returns individual arguments suitable for direct inclusion in a
    /// systemd unit file's `ExecStart` line. Each element is one nspawn flag.
    pub fn to_nspawn_args(&self) -> Vec<String> {
        let mut args = Vec::new();

        for bind in &self.binds {
            // Parse "host:container:mode"
            let parts: Vec<&str> = bind.split(':').collect();
            if parts.len() < 3 {
                continue; // Invalid format, skip
            }
            let host = parts[0];
            let container = parts[1];
            let mode = parts[2];

            if mode == "ro" {
                args.push(format!("--bind-ro={host}:{container}"));
            } else {
                args.push(format!("--bind={host}:{container}"));
            }
        }

        args
    }

    /// Validate all bind mount specifications.
    ///
    /// Checks that:
    /// - Both paths are absolute
    /// - Host path exists
    /// - No `..` components (path traversal prevention)
    /// - Format is valid
    pub fn validate(&self) -> Result<()> {
        for bind in &self.binds {
            validate_bind(bind)?;
        }
        Ok(())
    }

    /// Parse CLI bind arguments into internal format.
    ///
    /// Input format: `HOST:CONTAINER[:ro]`
    /// Output format: `host:container:rw` or `host:container:ro`
    pub fn from_cli_args(args: Vec<String>) -> Result<Self> {
        let mut binds = Vec::new();
        for arg in args {
            binds.push(parse_bind_arg(&arg)?);
        }
        Ok(Self { binds })
    }
}

/// Parse a CLI bind argument into internal storage format.
///
/// Input: `HOST:CONTAINER[:ro]`
/// Output: `host:container:rw` or `host:container:ro`
fn parse_bind_arg(arg: &str) -> Result<String> {
    // Check for :ro suffix
    let (spec, mode) = if let Some(stripped) = arg.strip_suffix(":ro") {
        (stripped, "ro")
    } else {
        (arg, "rw")
    };

    // Split host:container
    let (host, container) = spec.split_once(':').ok_or_else(|| {
        anyhow::anyhow!(
            "invalid bind format '{arg}': expected HOST:CONTAINER[:ro]"
        )
    })?;

    if host.is_empty() {
        bail!("invalid bind format '{arg}': host path cannot be empty");
    }
    if container.is_empty() {
        bail!("invalid bind format '{arg}': container path cannot be empty");
    }

    Ok(format!("{host}:{container}:{mode}"))
}

/// Validate a single bind mount specification (internal format).
fn validate_bind(bind: &str) -> Result<()> {
    let parts: Vec<&str> = bind.split(':').collect();
    if parts.len() < 3 {
        bail!("invalid bind format '{bind}': expected host:container:mode");
    }

    let host = parts[0];
    let container = parts[1];
    let mode = parts[2];

    // Validate mode
    if mode != "rw" && mode != "ro" {
        bail!("invalid bind mode '{mode}' in '{bind}': expected 'rw' or 'ro'");
    }

    // Validate host path
    let host_path = Path::new(host);
    if !host_path.is_absolute() {
        bail!("bind host path must be absolute: {host}");
    }
    for comp in host_path.components() {
        if comp == Component::ParentDir {
            bail!("bind host path must not contain '..': {host}");
        }
    }
    if !host_path.exists() {
        bail!("bind host path does not exist: {host}");
    }

    // Validate container path
    let container_path = Path::new(container);
    if !container_path.is_absolute() {
        bail!("bind container path must be absolute: {container}");
    }
    for comp in container_path.components() {
        if comp == Component::ParentDir {
            bail!("bind container path must not contain '..': {container}");
        }
    }

    // Pipe is the separator in the state file serialization format.
    if host.contains('|') || container.contains('|') {
        bail!("bind paths may not contain '|' (reserved separator): {bind}");
    }

    Ok(())
}

/// Environment variable configuration for containers.
///
/// Stores environment variables as `KEY=value` strings.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct EnvConfig {
    /// Environment variables in `KEY=value` format.
    pub vars: Vec<String>,
}

impl EnvConfig {
    /// Returns true if no environment variables are configured.
    pub fn is_empty(&self) -> bool {
        self.vars.is_empty()
    }

    /// Read env config from a state file's key-value pairs.
    pub fn from_state(state: &State) -> Self {
        Self {
            vars: state
                .get("ENVS")
                .filter(|s| !s.is_empty())
                .map(|s| s.split('|').map(String::from).collect())
                .unwrap_or_default(),
        }
    }

    /// Write env config into a state's key-value pairs.
    pub fn write_to_state(&self, state: &mut State) {
        if self.vars.is_empty() {
            state.remove("ENVS");
        } else {
            state.set("ENVS", self.vars.join("|"));
        }
    }

    /// Generate systemd-nspawn arguments for environment variables.
    ///
    /// Returns individual arguments suitable for direct inclusion in a
    /// systemd unit file's `ExecStart` line. Each element is one nspawn flag.
    pub fn to_nspawn_args(&self) -> Vec<String> {
        let mut args = Vec::new();

        for var in &self.vars {
            if let Some((key, _)) = var.split_once('=') {
                // Pass the full KEY=VALUE through; quoting for the systemd
                // unit file context is handled by the drop-in writer.
                args.push(format!("--setenv={key}={}", &var[key.len() + 1..]));
            }
        }

        args
    }

    /// Validate all environment variable specifications.
    ///
    /// Checks that:
    /// - Each spec contains `=`
    /// - Key is a valid env var name (alphanumeric + underscore, not starting with digit)
    pub fn validate(&self) -> Result<()> {
        for var in &self.vars {
            validate_env(var)?;
        }
        Ok(())
    }
}

/// Validate a single environment variable specification.
fn validate_env(spec: &str) -> Result<()> {
    let (key, _value) = spec.split_once('=').ok_or_else(|| {
        anyhow::anyhow!(
            "invalid environment variable '{spec}': expected KEY=VALUE"
        )
    })?;

    if key.is_empty() {
        bail!("invalid environment variable '{spec}': key cannot be empty");
    }

    // Key must be valid: alphanumeric + underscore, not starting with digit
    let first = key.chars().next().unwrap();
    if first.is_ascii_digit() {
        bail!(
            "invalid environment variable key '{key}': cannot start with a digit"
        );
    }

    for ch in key.chars() {
        if !ch.is_ascii_alphanumeric() && ch != '_' {
            bail!(
                "invalid environment variable key '{key}': \
                 may only contain letters, digits, and underscores"
            );
        }
    }

    // Pipe is the separator in the state file serialization format.
    let (_, value) = spec.split_once('=').unwrap();
    if value.contains('|') {
        bail!(
            "invalid environment variable value for '{key}': \
             may not contain '|' (reserved separator)"
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- BindConfig tests ---

    #[test]
    fn test_bind_default_is_empty() {
        let binds = BindConfig::default();
        assert!(binds.is_empty());
    }

    #[test]
    fn test_bind_parse_cli_args() {
        let args = vec![
            "/host/path:/container/path".to_string(),
            "/data:/mnt:ro".to_string(),
        ];
        let binds = BindConfig::from_cli_args(args).unwrap();
        assert_eq!(binds.binds.len(), 2);
        assert_eq!(binds.binds[0], "/host/path:/container/path:rw");
        assert_eq!(binds.binds[1], "/data:/mnt:ro");
    }

    #[test]
    fn test_bind_parse_cli_args_invalid() {
        // Missing colon
        let args = vec!["/path".to_string()];
        assert!(BindConfig::from_cli_args(args).is_err());

        // Empty host
        let args = vec![":/container".to_string()];
        assert!(BindConfig::from_cli_args(args).is_err());

        // Empty container
        let args = vec!["/host:".to_string()];
        assert!(BindConfig::from_cli_args(args).is_err());
    }

    #[test]
    fn test_bind_to_nspawn_args() {
        let binds = BindConfig {
            binds: vec![
                "/host:/container:rw".to_string(),
                "/data:/mnt:ro".to_string(),
            ],
        };
        let args = binds.to_nspawn_args();
        assert_eq!(args, vec!["--bind=/host:/container", "--bind-ro=/data:/mnt"]);
    }

    #[test]
    fn test_bind_to_nspawn_args_empty() {
        let binds = BindConfig::default();
        assert!(binds.to_nspawn_args().is_empty());
    }

    #[test]
    fn test_bind_validate_ok() {
        // Create a temp directory to use as host path
        let tmp = std::env::temp_dir();
        let binds = BindConfig {
            binds: vec![format!("{}:/container:rw", tmp.display())],
        };
        assert!(binds.validate().is_ok());
    }

    #[test]
    fn test_bind_validate_relative_host() {
        let binds = BindConfig {
            binds: vec!["relative:/container:rw".to_string()],
        };
        let err = binds.validate().unwrap_err();
        assert!(err.to_string().contains("absolute"), "unexpected error: {err}");
    }

    #[test]
    fn test_bind_validate_relative_container() {
        let tmp = std::env::temp_dir();
        let binds = BindConfig {
            binds: vec![format!("{}:relative:rw", tmp.display())],
        };
        let err = binds.validate().unwrap_err();
        assert!(err.to_string().contains("absolute"), "unexpected error: {err}");
    }

    #[test]
    fn test_bind_validate_host_dotdot() {
        let binds = BindConfig {
            binds: vec!["/foo/../bar:/container:rw".to_string()],
        };
        let err = binds.validate().unwrap_err();
        assert!(err.to_string().contains(".."), "unexpected error: {err}");
    }

    #[test]
    fn test_bind_validate_container_dotdot() {
        let tmp = std::env::temp_dir();
        let binds = BindConfig {
            binds: vec![format!("{}:/foo/../bar:rw", tmp.display())],
        };
        let err = binds.validate().unwrap_err();
        assert!(err.to_string().contains(".."), "unexpected error: {err}");
    }

    #[test]
    fn test_bind_validate_host_not_exist() {
        let binds = BindConfig {
            binds: vec!["/nonexistent/path/xyz:/container:rw".to_string()],
        };
        let err = binds.validate().unwrap_err();
        assert!(err.to_string().contains("does not exist"), "unexpected error: {err}");
    }

    #[test]
    fn test_bind_state_roundtrip() {
        let binds = BindConfig {
            binds: vec![
                "/host:/container:rw".to_string(),
                "/data:/mnt:ro".to_string(),
            ],
        };

        let mut state = State::new();
        state.set("NAME", "test");
        binds.write_to_state(&mut state);

        let serialized = state.serialize();
        let parsed = State::parse(&serialized).unwrap();
        let restored = BindConfig::from_state(&parsed);

        assert_eq!(restored.binds, binds.binds);
    }

    #[test]
    fn test_bind_state_empty() {
        let binds = BindConfig::default();

        let mut state = State::new();
        state.set("BINDS", "old|value");
        binds.write_to_state(&mut state);

        assert_eq!(state.get("BINDS"), None);
    }

    // --- EnvConfig tests ---

    #[test]
    fn test_env_default_is_empty() {
        let envs = EnvConfig::default();
        assert!(envs.is_empty());
    }

    #[test]
    fn test_env_validate_ok() {
        let envs = EnvConfig {
            vars: vec![
                "MY_VAR=hello".to_string(),
                "ANOTHER_VAR=world".to_string(),
                "_UNDERSCORE=value".to_string(),
                "A=b".to_string(),
            ],
        };
        assert!(envs.validate().is_ok());
    }

    #[test]
    fn test_env_validate_empty_value_ok() {
        let envs = EnvConfig {
            vars: vec!["EMPTY=".to_string()],
        };
        assert!(envs.validate().is_ok());
    }

    #[test]
    fn test_env_validate_no_equals() {
        let envs = EnvConfig {
            vars: vec!["NOEQUALS".to_string()],
        };
        let err = envs.validate().unwrap_err();
        assert!(err.to_string().contains("KEY=VALUE"), "unexpected error: {err}");
    }

    #[test]
    fn test_env_validate_empty_key() {
        let envs = EnvConfig {
            vars: vec!["=value".to_string()],
        };
        let err = envs.validate().unwrap_err();
        assert!(err.to_string().contains("empty"), "unexpected error: {err}");
    }

    #[test]
    fn test_env_validate_digit_start() {
        let envs = EnvConfig {
            vars: vec!["1VAR=value".to_string()],
        };
        let err = envs.validate().unwrap_err();
        assert!(err.to_string().contains("digit"), "unexpected error: {err}");
    }

    #[test]
    fn test_env_validate_invalid_char() {
        let envs = EnvConfig {
            vars: vec!["MY-VAR=value".to_string()],
        };
        let err = envs.validate().unwrap_err();
        assert!(err.to_string().contains("letters, digits, and underscores"), "unexpected error: {err}");
    }

    #[test]
    fn test_env_validate_pipe_in_value() {
        let envs = EnvConfig {
            vars: vec!["MY_VAR=hello|world".to_string()],
        };
        let err = envs.validate().unwrap_err();
        assert!(err.to_string().contains("reserved separator"), "unexpected error: {err}");
    }

    #[test]
    fn test_env_to_nspawn_args() {
        let envs = EnvConfig {
            vars: vec![
                "MY_VAR=hello".to_string(),
                "ANOTHER=world".to_string(),
            ],
        };
        let args = envs.to_nspawn_args();
        assert_eq!(args, vec!["--setenv=MY_VAR=hello", "--setenv=ANOTHER=world"]);
    }

    #[test]
    fn test_env_to_nspawn_args_with_spaces() {
        let envs = EnvConfig {
            vars: vec!["MSG=hello world".to_string()],
        };
        let args = envs.to_nspawn_args();
        assert_eq!(args, vec!["--setenv=MSG=hello world"]);
    }

    #[test]
    fn test_env_to_nspawn_args_empty() {
        let envs = EnvConfig::default();
        assert!(envs.to_nspawn_args().is_empty());
    }

    #[test]
    fn test_env_state_roundtrip() {
        let envs = EnvConfig {
            vars: vec![
                "MY_VAR=hello".to_string(),
                "ANOTHER=world".to_string(),
            ],
        };

        let mut state = State::new();
        state.set("NAME", "test");
        envs.write_to_state(&mut state);

        let serialized = state.serialize();
        let parsed = State::parse(&serialized).unwrap();
        let restored = EnvConfig::from_state(&parsed);

        assert_eq!(restored.vars, envs.vars);
    }

    #[test]
    fn test_env_state_empty() {
        let envs = EnvConfig::default();

        let mut state = State::new();
        state.set("ENVS", "old|value");
        envs.write_to_state(&mut state);

        assert_eq!(state.get("ENVS"), None);
    }
}
