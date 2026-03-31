//! Validation layer: convert raw [`DevcontainerConfig`] into a validated [`DevcontainerPlan`].
//!
//! Variable substitution, mount parsing, port normalization, and lifecycle
//! command flattening all happen here so the orchestration layer can consume
//! a fully-validated plan without re-checking.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use super::types::*;

/// A validated, ready-to-execute devcontainer plan.
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct DevcontainerPlan {
    /// Human-readable name (falls back to workspace directory name).
    pub name: String,
    /// Container source: OCI image reference.
    pub image: Option<String>,
    /// Container source: Dockerfile build.
    pub build: Option<BuildPlan>,
    /// Absolute path inside the container for the workspace.
    pub workspace_folder: String,
    /// User to run as inside the container.
    pub remote_user: Option<String>,
    /// User for container creation (file ownership).
    pub container_user: Option<String>,
    /// Bind mounts (host:container:mode).
    pub binds: Vec<String>,
    /// Port forwards (host:container).
    pub ports: Vec<String>,
    /// Runtime environment variables.
    pub env_vars: Vec<String>,
    /// Build-time environment variables.
    pub container_env_vars: Vec<String>,
    /// Lifecycle hooks flattened to shell commands.
    pub on_create_commands: Vec<String>,
    pub update_content_commands: Vec<String>,
    pub post_create_commands: Vec<String>,
    pub post_start_commands: Vec<String>,
    pub post_attach_commands: Vec<String>,
    /// Capabilities to add.
    pub cap_add: Vec<String>,
    /// Features to install (reference -> options JSON).
    pub features: HashMap<String, serde_json::Value>,
    /// Whether the container uses init.
    pub init: bool,
    /// Whether the container is privileged.
    pub privileged: bool,
}

/// Validated Dockerfile build configuration.
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct BuildPlan {
    /// Absolute path to the Dockerfile.
    pub dockerfile: PathBuf,
    /// Absolute path to the build context directory.
    pub context: PathBuf,
    /// Build arguments.
    pub args: HashMap<String, String>,
    /// Target build stage.
    pub target: Option<String>,
}

/// Substitute `${localWorkspaceFolder}`, `${containerWorkspaceFolder}`,
/// `${localWorkspaceFolderBasename}`, and `${localEnv:VAR}` in a string.
fn substitute_vars(s: &str, workspace_folder: &Path, container_workspace: &str) -> String {
    let workspace_str = workspace_folder.to_string_lossy();
    let basename = workspace_folder
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();

    let mut result = s.to_string();
    result = result.replace("${localWorkspaceFolder}", &workspace_str);
    result = result.replace("${containerWorkspaceFolder}", container_workspace);
    result = result.replace("${localWorkspaceFolderBasename}", &basename);

    // Handle ${localEnv:VAR} and ${localEnv:VAR:default}
    while let Some(start) = result.find("${localEnv:") {
        let rest = &result[start + "${localEnv:".len()..];
        if let Some(end) = rest.find('}') {
            let var_spec = &rest[..end];
            let (var_name, default) = if let Some((name, def)) = var_spec.split_once(':') {
                (name, Some(def))
            } else {
                (var_spec, None)
            };
            let value =
                std::env::var(var_name).unwrap_or_else(|_| default.unwrap_or("").to_string());
            let full_pattern = format!("${{localEnv:{}}}", var_spec);
            result = result.replace(&full_pattern, &value);
        } else {
            break;
        }
    }

    // Handle ${containerEnv:VAR} - resolved at runtime, pass through as $VAR
    loop {
        let Some(start) = result.find("${containerEnv:") else {
            break;
        };
        let rest = &result[start + "${containerEnv:".len()..];
        let Some(end) = rest.find('}') else {
            break;
        };
        let var_spec = rest[..end].to_string();
        let var_name = var_spec
            .split_once(':')
            .map(|(n, _)| n)
            .unwrap_or(&var_spec);
        let replacement = format!("${{{var_name}}}");
        let full_pattern = format!("${{containerEnv:{var_spec}}}");
        result = result.replace(&full_pattern, &replacement);
    }

    result
}

/// Parse a Docker-style mount string: "source=...,target=...,type=bind[,readonly]".
fn parse_mount_string(
    s: &str,
    workspace_folder: &Path,
    container_workspace: &str,
) -> Result<String> {
    let s = substitute_vars(s, workspace_folder, container_workspace);
    let mut source = None;
    let mut target = None;
    let mut readonly = false;

    for part in s.split(',') {
        if let Some((key, value)) = part.split_once('=') {
            match key.trim() {
                "source" | "src" => source = Some(value.to_string()),
                "target" | "dst" | "destination" => target = Some(value.to_string()),
                "type" => {}        // we only support bind mounts in sdme
                "consistency" => {} // ignored (Docker-specific)
                "readonly" | "ro" => {
                    readonly = value.eq_ignore_ascii_case("true") || value == "1";
                }
                _ => {}
            }
        } else if part.trim() == "readonly" || part.trim() == "ro" {
            readonly = true;
        }
    }

    let source = source.context("mount string missing 'source' field")?;
    let target = target.context("mount string missing 'target' field")?;
    let mode = if readonly { "ro" } else { "rw" };
    Ok(format!("{source}:{target}:{mode}"))
}

/// Parse a structured mount object into a bind string.
fn parse_mount_object(
    m: &MountObject,
    workspace_folder: &Path,
    container_workspace: &str,
) -> Result<Option<String>> {
    let mount_type = m.mount_type.as_deref().unwrap_or("bind");
    if mount_type != "bind" {
        // sdme only supports bind mounts; skip volume/tmpfs with a warning.
        eprintln!(
            "warning: skipping unsupported mount type '{}' for target '{}'",
            mount_type, m.target
        );
        return Ok(None);
    }
    let source = m
        .source
        .as_deref()
        .context("bind mount missing 'source' field")?;
    let source = substitute_vars(source, workspace_folder, container_workspace);
    let target = substitute_vars(&m.target, workspace_folder, container_workspace);
    let mode = if m.readonly { "ro" } else { "rw" };
    Ok(Some(format!("{source}:{target}:{mode}")))
}

/// Flatten a lifecycle command into a list of shell command strings.
fn flatten_lifecycle(cmd: &LifecycleCommand) -> Vec<String> {
    match cmd {
        LifecycleCommand::String(s) => vec![s.clone()],
        LifecycleCommand::Array(arr) => arr.clone(),
        LifecycleCommand::Object(map) => {
            // Object commands are parallel in the spec, but we run them
            // sequentially since sdme doesn't have a parallel executor.
            // Sort by key for deterministic ordering.
            let mut pairs: Vec<_> = map.iter().collect();
            pairs.sort_by_key(|(k, _)| *k);
            pairs.into_iter().map(|(_, v)| v.clone()).collect()
        }
    }
}

/// Normalize a port entry into a "host:container" string.
fn normalize_port(entry: &PortEntry) -> Result<String> {
    match entry {
        PortEntry::Number(p) => Ok(format!("{p}:{p}")),
        PortEntry::String(s) => {
            if s.contains(':') {
                Ok(s.clone())
            } else {
                let p: u16 = s.parse().with_context(|| format!("invalid port: {s}"))?;
                Ok(format!("{p}:{p}"))
            }
        }
    }
}

/// Find the devcontainer.json file starting from the workspace folder.
///
/// Searches in order:
/// 1. `.devcontainer/devcontainer.json`
/// 2. `.devcontainer.json`
/// 3. `.devcontainer/<subdir>/devcontainer.json` (first match)
pub fn find_config(workspace_folder: &Path) -> Result<PathBuf> {
    let primary = workspace_folder.join(".devcontainer/devcontainer.json");
    if primary.is_file() {
        return Ok(primary);
    }
    let root_config = workspace_folder.join(".devcontainer.json");
    if root_config.is_file() {
        return Ok(root_config);
    }
    // Look for subdirectories under .devcontainer/
    let devcontainer_dir = workspace_folder.join(".devcontainer");
    if devcontainer_dir.is_dir() {
        if let Ok(entries) = std::fs::read_dir(&devcontainer_dir) {
            for entry in entries.flatten() {
                if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    let sub = entry.path().join("devcontainer.json");
                    if sub.is_file() {
                        return Ok(sub);
                    }
                }
            }
        }
    }
    bail!(
        "no devcontainer.json found in {}",
        workspace_folder.display()
    )
}

/// Parse and validate a devcontainer.json file into an executable plan.
pub(crate) fn load_plan(config_path: &Path, workspace_folder: &Path) -> Result<DevcontainerPlan> {
    let content = std::fs::read_to_string(config_path)
        .with_context(|| format!("failed to read {}", config_path.display()))?;

    // Strip JSON comments (// and /* */) for JSONC compatibility.
    let content = strip_json_comments(&content);

    let config: DevcontainerConfig = serde_json::from_str(&content)
        .with_context(|| format!("failed to parse {}", config_path.display()))?;

    validate_and_plan(config, config_path, workspace_folder)
}

/// Strip single-line (//) and multi-line (/* */) comments from JSON content.
/// This provides basic JSONC support for devcontainer.json files.
fn strip_json_comments(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    let mut in_string = false;

    while let Some(&ch) = chars.peek() {
        if in_string {
            result.push(ch);
            chars.next();
            if ch == '\\' {
                // Skip escaped character
                if let Some(&next) = chars.peek() {
                    result.push(next);
                    chars.next();
                }
            } else if ch == '"' {
                in_string = false;
            }
        } else if ch == '"' {
            in_string = true;
            result.push(ch);
            chars.next();
        } else if ch == '/' {
            chars.next();
            match chars.peek() {
                Some(&'/') => {
                    // Single-line comment: skip until newline
                    for c in chars.by_ref() {
                        if c == '\n' {
                            result.push('\n');
                            break;
                        }
                    }
                }
                Some(&'*') => {
                    // Multi-line comment: skip until */
                    chars.next();
                    let mut prev = ' ';
                    for c in chars.by_ref() {
                        if prev == '*' && c == '/' {
                            break;
                        }
                        if c == '\n' {
                            result.push('\n');
                        }
                        prev = c;
                    }
                }
                _ => {
                    result.push('/');
                }
            }
        } else {
            result.push(ch);
            chars.next();
        }
    }
    result
}

/// Convert a parsed config into a validated plan.
fn validate_and_plan(
    config: DevcontainerConfig,
    config_path: &Path,
    workspace_folder: &Path,
) -> Result<DevcontainerPlan> {
    // Must have either image or build.
    if config.image.is_none() && config.build.is_none() {
        bail!(
            "{}: must specify either 'image' or 'build'",
            config_path.display()
        );
    }

    let config_dir = config_path.parent().unwrap_or(Path::new("."));

    // Resolve workspace folder inside container.
    let container_workspace = config
        .workspace_folder
        .clone()
        .unwrap_or_else(|| "/workspace".to_string());

    // Resolve name.
    let name = config.name.unwrap_or_else(|| {
        workspace_folder
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "devcontainer".to_string())
    });

    // Sanitize name for sdme (lowercase, alphanumeric + hyphens).
    let name = sanitize_container_name(&name);

    // Resolve build config.
    let build = config.build.map(|b| {
        let dockerfile = config_dir.join(&b.dockerfile);
        let context = b
            .context
            .as_ref()
            .map(|c| config_dir.join(c))
            .unwrap_or_else(|| config_dir.to_path_buf());
        BuildPlan {
            dockerfile,
            context,
            args: b.args,
            target: b.target,
        }
    });

    // Parse mounts.
    let mut binds = Vec::new();

    // Default workspace mount: bind the workspace folder into the container.
    let workspace_mount = config.workspace_mount.as_deref();
    match workspace_mount {
        Some("") => {} // Explicitly disabled
        Some(custom) => {
            let mount_str = parse_mount_string(custom, workspace_folder, &container_workspace)?;
            binds.push(mount_str);
        }
        None => {
            // Default: bind workspace folder to containerWorkspaceFolder
            let ws = workspace_folder.to_string_lossy();
            binds.push(format!("{ws}:{container_workspace}:rw"));
        }
    }

    // Additional mounts.
    for mount in &config.mounts {
        match mount {
            MountEntry::String(s) => {
                let bind = parse_mount_string(s, workspace_folder, &container_workspace)?;
                binds.push(bind);
            }
            MountEntry::Object(m) => {
                if let Some(bind) = parse_mount_object(m, workspace_folder, &container_workspace)? {
                    binds.push(bind);
                }
            }
        }
    }

    // Parse ports.
    let mut ports = Vec::new();
    for entry in &config.forward_ports {
        ports.push(normalize_port(entry)?);
    }

    // Parse environment variables.
    let mut env_vars = Vec::new();
    if let Some(ref env) = config.container_env {
        for (k, v) in env {
            let v = substitute_vars(v, workspace_folder, &container_workspace);
            env_vars.push(format!("{k}={v}"));
        }
    }
    if let Some(ref env) = config.remote_env {
        for (k, v) in env {
            let v = substitute_vars(v, workspace_folder, &container_workspace);
            env_vars.push(format!("{k}={v}"));
        }
    }

    // Container env vars (for build-time).
    let container_env_vars = config
        .container_env
        .unwrap_or_default()
        .into_iter()
        .map(|(k, v)| {
            let v = substitute_vars(&v, workspace_folder, &container_workspace);
            format!("{k}={v}")
        })
        .collect();

    // Flatten lifecycle hooks.
    let on_create_commands = config
        .on_create_command
        .as_ref()
        .map(flatten_lifecycle)
        .unwrap_or_default();
    let update_content_commands = config
        .update_content_command
        .as_ref()
        .map(flatten_lifecycle)
        .unwrap_or_default();
    let post_create_commands = config
        .post_create_command
        .as_ref()
        .map(flatten_lifecycle)
        .unwrap_or_default();
    let post_start_commands = config
        .post_start_command
        .as_ref()
        .map(flatten_lifecycle)
        .unwrap_or_default();
    let post_attach_commands = config
        .post_attach_command
        .as_ref()
        .map(flatten_lifecycle)
        .unwrap_or_default();

    Ok(DevcontainerPlan {
        name,
        image: config.image,
        build,
        workspace_folder: container_workspace,
        remote_user: config.remote_user,
        container_user: config.container_user,
        binds,
        ports,
        env_vars,
        container_env_vars,
        on_create_commands,
        update_content_commands,
        post_create_commands,
        post_start_commands,
        post_attach_commands,
        cap_add: config.cap_add,
        features: config.features,
        init: config.init.unwrap_or(false),
        privileged: config.privileged.unwrap_or(false),
    })
}

/// Convert a human-readable name to a valid sdme container name.
///
/// Lowercase, replace non-alphanumeric with hyphens, collapse hyphens,
/// strip leading/trailing hyphens, ensure starts with a letter.
fn sanitize_container_name(name: &str) -> String {
    let mut result: String = name
        .to_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();

    // Collapse consecutive hyphens.
    while result.contains("--") {
        result = result.replace("--", "-");
    }

    // Strip leading/trailing hyphens.
    result = result.trim_matches('-').to_string();

    // Ensure starts with a letter.
    if result.is_empty() || !result.as_bytes()[0].is_ascii_lowercase() {
        result = format!("dc-{result}");
    }

    // Truncate to 64 chars.
    if result.len() > 64 {
        result.truncate(64);
        result = result.trim_end_matches('-').to_string();
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_container_name() {
        assert_eq!(
            sanitize_container_name("My Dev Container"),
            "my-dev-container"
        );
        assert_eq!(sanitize_container_name("test_123"), "test-123");
        assert_eq!(sanitize_container_name("123-test"), "dc-123-test");
        assert_eq!(sanitize_container_name("---"), "dc-");
        assert_eq!(sanitize_container_name("Hello World!"), "hello-world");
    }

    #[test]
    fn test_substitute_vars() {
        let ws = Path::new("/home/user/myproject");
        let result = substitute_vars("${localWorkspaceFolder}/src", ws, "/workspace");
        assert_eq!(result, "/home/user/myproject/src");

        let result = substitute_vars("${containerWorkspaceFolder}/app", ws, "/workspace");
        assert_eq!(result, "/workspace/app");

        let result = substitute_vars("${localWorkspaceFolderBasename}", ws, "/workspace");
        assert_eq!(result, "myproject");
    }

    #[test]
    fn test_strip_json_comments() {
        let input = r#"{
            // This is a comment
            "key": "value", // inline comment
            /* multi-line
               comment */
            "key2": "value2"
        }"#;
        let result = strip_json_comments(input);
        assert!(!result.contains("// This is a comment"));
        assert!(!result.contains("inline comment"));
        assert!(!result.contains("multi-line"));
        assert!(result.contains(r#""key": "value""#));
        assert!(result.contains(r#""key2": "value2""#));
    }

    #[test]
    fn test_strip_json_comments_preserves_strings() {
        let input = r#"{ "url": "https://example.com" }"#;
        let result = strip_json_comments(input);
        assert_eq!(result, input);
    }

    #[test]
    fn test_normalize_port() {
        assert_eq!(
            normalize_port(&PortEntry::Number(3000)).unwrap(),
            "3000:3000"
        );
        assert_eq!(
            normalize_port(&PortEntry::String("8080:80".into())).unwrap(),
            "8080:80"
        );
        assert_eq!(
            normalize_port(&PortEntry::String("3000".into())).unwrap(),
            "3000:3000"
        );
    }

    #[test]
    fn test_flatten_lifecycle_string() {
        let cmd = LifecycleCommand::String("npm install".into());
        assert_eq!(flatten_lifecycle(&cmd), vec!["npm install"]);
    }

    #[test]
    fn test_flatten_lifecycle_array() {
        let cmd = LifecycleCommand::Array(vec!["a".into(), "b".into()]);
        assert_eq!(flatten_lifecycle(&cmd), vec!["a", "b"]);
    }

    #[test]
    fn test_flatten_lifecycle_object() {
        let mut map = HashMap::new();
        map.insert("beta".into(), "cmd-b".into());
        map.insert("alpha".into(), "cmd-a".into());
        let cmd = LifecycleCommand::Object(map);
        let result = flatten_lifecycle(&cmd);
        // Should be sorted by key
        assert_eq!(result, vec!["cmd-a", "cmd-b"]);
    }

    #[test]
    fn test_parse_mount_string() {
        let ws = Path::new("/home/user/project");
        let result =
            parse_mount_string("source=/host,target=/container,type=bind", ws, "/workspace")
                .unwrap();
        assert_eq!(result, "/host:/container:rw");

        let result = parse_mount_string(
            "source=${localWorkspaceFolder}/.config,target=/home/dev/.config,type=bind,readonly",
            ws,
            "/workspace",
        )
        .unwrap();
        assert_eq!(result, "/home/user/project/.config:/home/dev/.config:ro");
    }

    #[test]
    fn test_load_plan_minimal() {
        let dir = std::env::temp_dir().join("sdme-test-devcontainer-plan");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let config_path = dir.join("devcontainer.json");
        std::fs::write(
            &config_path,
            r#"{ "image": "ubuntu:22.04", "workspaceFolder": "/work" }"#,
        )
        .unwrap();

        let plan = load_plan(&config_path, &dir).unwrap();
        assert_eq!(plan.image.as_deref(), Some("ubuntu:22.04"));
        assert_eq!(plan.workspace_folder, "/work");
        // Default workspace mount
        assert_eq!(plan.binds.len(), 1);
        assert!(plan.binds[0].ends_with(":/work:rw"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_plan_no_image_or_build() {
        let dir = std::env::temp_dir().join("sdme-test-devcontainer-plan-err");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let config_path = dir.join("devcontainer.json");
        std::fs::write(&config_path, r#"{ "name": "test" }"#).unwrap();

        let result = load_plan(&config_path, &dir);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("image"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
