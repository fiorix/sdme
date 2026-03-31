//! Devcontainer orchestration: up, exec, stop, remove.
//!
//! Follows the same pattern as [`crate::kube::create`]: parse config,
//! set up rootfs, construct [`CreateOptions`], call [`containers::create`],
//! run lifecycle hooks, and write devcontainer-specific state.

use std::path::Path;

use anyhow::{bail, Context, Result};

use super::plan::{find_config, load_plan, DevcontainerPlan};
use crate::{check_interrupted, validate_name, State};

/// Options for `sdme devcontainer up`.
pub struct DevcontainerUpOptions<'a> {
    /// Path to the workspace folder on the host (contains .devcontainer/).
    pub workspace_folder: &'a Path,
    /// Explicit path to devcontainer.json (overrides auto-detection).
    pub config_path: Option<&'a Path>,
    /// Docker Hub credentials `(user, token)` for authenticated pulls.
    pub docker_credentials: Option<(&'a str, &'a str)>,
    /// OCI blob cache for registry downloads.
    pub cache: &'a crate::oci::cache::BlobCache,
    /// Enable verbose output.
    pub verbose: bool,
    /// HTTP configuration for downloads and OCI pulls.
    pub http: &'a crate::config::HttpConfig,
    /// Automatically clean up stale transactions.
    pub auto_gc: bool,
    /// Per-distro chroot command overrides from config.
    pub distros: &'a std::collections::HashMap<String, crate::config::DistroCommands>,
    /// Boot timeout in seconds.
    pub boot_timeout: u64,
    /// Maximum tasks for systemd.
    pub tasks_max: u32,
    /// Stop timeout (terminate tier) in seconds.
    pub stop_timeout_terminate: u64,
    /// Whether to rebuild/recreate even if container exists.
    pub rebuild: bool,
    /// Allow interactive prompts.
    pub interactive: bool,
}

/// Bring up a devcontainer: find config, import image, create container,
/// start it, and run lifecycle hooks.
///
/// Returns the container name on success.
pub fn devcontainer_up(datadir: &Path, opts: &DevcontainerUpOptions<'_>) -> Result<String> {
    let workspace_folder = opts.workspace_folder.canonicalize().with_context(|| {
        format!(
            "workspace folder not found: {}",
            opts.workspace_folder.display()
        )
    })?;

    // 1. Find and parse devcontainer.json.
    let config_path = match opts.config_path {
        Some(p) => p.to_path_buf(),
        None => find_config(&workspace_folder)?,
    };

    if opts.verbose {
        eprintln!("config: {}", config_path.display());
    }

    let plan = load_plan(&config_path, &workspace_folder)?;

    if opts.verbose {
        eprintln!("devcontainer name: {}", plan.name);
        if let Some(ref img) = plan.image {
            eprintln!("image: {img}");
        }
    }

    // Check if container already exists.
    let container_name = format!("dc-{}", plan.name);
    let state_path = datadir.join("state").join(&container_name);
    if state_path.exists() {
        let state = State::read_from(&state_path)?;
        if state.is_yes("DEVCONTAINER") {
            if opts.rebuild {
                eprintln!("rebuilding devcontainer '{container_name}'");
                devcontainer_rm(datadir, &container_name, opts.verbose)?;
            } else {
                // Container exists, check if running.
                let is_running = crate::systemd::unit_active_state(&container_name)
                    .map(|s| s == "active")
                    .unwrap_or(false);
                if is_running {
                    eprintln!("devcontainer '{container_name}' is already running");
                    // Run postStartCommand if defined.
                    run_lifecycle_commands(
                        &container_name,
                        "postStartCommand",
                        &plan.post_start_commands,
                        plan.remote_user.as_deref(),
                        opts.verbose,
                    )?;
                    return Ok(container_name);
                }
                // Exists but stopped: start it.
                eprintln!("starting existing devcontainer '{container_name}'");
                let boot_timeout = std::time::Duration::from_secs(opts.boot_timeout);
                crate::systemd::start(
                    datadir,
                    &container_name,
                    opts.tasks_max,
                    boot_timeout.as_secs(),
                    opts.verbose,
                )?;
                crate::systemd::await_boot(&container_name, boot_timeout, opts.verbose)?;
                run_lifecycle_commands(
                    &container_name,
                    "postStartCommand",
                    &plan.post_start_commands,
                    plan.remote_user.as_deref(),
                    opts.verbose,
                )?;
                return Ok(container_name);
            }
        } else {
            bail!(
                "container '{container_name}' already exists but is not a devcontainer; \
                 remove it first with: sdme rm {container_name}"
            );
        }
    }

    check_interrupted()?;

    // 2. Import OCI image as rootfs (if image-based).
    let rootfs_name = format!("dc-{}", plan.name);
    if let Some(ref image) = plan.image {
        import_image(datadir, &rootfs_name, image, opts)?;
    } else if plan.build.is_some() {
        bail!(
            "Dockerfile builds are not yet supported by sdme devcontainer; \
             use 'image' instead, or build the image externally and reference it"
        );
    }

    check_interrupted()?;

    // 3. Create the container.
    let create_opts = build_create_options(&plan, &container_name, &rootfs_name)?;
    let name = crate::containers::create(datadir, &create_opts, opts.verbose)?;

    // 4. Write devcontainer-specific state.
    let state_path = datadir.join("state").join(&name);
    let mut state = State::read_from(&state_path)?;
    state.set("DEVCONTAINER", "yes");
    state.set("DEVCONTAINER_WORKSPACE", plan.workspace_folder.as_str());
    if let Some(ref user) = plan.remote_user {
        state.set("DEVCONTAINER_USER", user);
    }
    let config_hash = {
        use sha2::{Digest, Sha256};
        let content = std::fs::read(&config_path).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(&content);
        format!("{:x}", hasher.finalize())
    };
    state.set("DEVCONTAINER_CONFIG_HASH", &config_hash);
    state.write_to(&state_path)?;

    check_interrupted()?;

    // 5. Start the container.
    eprintln!("starting '{name}'");
    let boot_timeout = std::time::Duration::from_secs(opts.boot_timeout);
    crate::systemd::start(
        datadir,
        &name,
        opts.tasks_max,
        boot_timeout.as_secs(),
        opts.verbose,
    )?;
    crate::systemd::await_boot(&name, boot_timeout, opts.verbose)?;

    check_interrupted()?;

    // 6. Run lifecycle hooks (in spec order).
    run_lifecycle_commands(
        &name,
        "onCreateCommand",
        &plan.on_create_commands,
        plan.remote_user.as_deref(),
        opts.verbose,
    )?;
    run_lifecycle_commands(
        &name,
        "updateContentCommand",
        &plan.update_content_commands,
        plan.remote_user.as_deref(),
        opts.verbose,
    )?;
    run_lifecycle_commands(
        &name,
        "postCreateCommand",
        &plan.post_create_commands,
        plan.remote_user.as_deref(),
        opts.verbose,
    )?;
    run_lifecycle_commands(
        &name,
        "postStartCommand",
        &plan.post_start_commands,
        plan.remote_user.as_deref(),
        opts.verbose,
    )?;

    // Install features (after container is running).
    if !plan.features.is_empty() {
        install_features(&name, &plan, opts.verbose)?;
    }

    Ok(name)
}

/// Execute a command inside a running devcontainer.
pub fn devcontainer_exec(
    datadir: &Path,
    name: &str,
    command: &[String],
    verbose: bool,
) -> Result<std::process::ExitStatus> {
    let state_path = datadir.join("state").join(name);
    if !state_path.exists() {
        bail!("devcontainer not found: {name}");
    }
    let state = State::read_from(&state_path)?;
    if !state.is_yes("DEVCONTAINER") {
        bail!("container '{name}' is not a devcontainer");
    }

    let remote_user = state.get("DEVCONTAINER_USER");
    let workspace = state.get("DEVCONTAINER_WORKSPACE").unwrap_or("/workspace");

    // Build machinectl shell command with user and working directory.
    exec_in_container(name, command, remote_user, Some(workspace), verbose)
}

/// Stop a running devcontainer.
pub fn devcontainer_stop(datadir: &Path, name: &str, verbose: bool) -> Result<()> {
    let state_path = datadir.join("state").join(name);
    if !state_path.exists() {
        bail!("devcontainer not found: {name}");
    }
    let state = State::read_from(&state_path)?;
    if !state.is_yes("DEVCONTAINER") {
        bail!("container '{name}' is not a devcontainer");
    }

    crate::containers::stop(name, crate::containers::StopMode::Graceful, 90, verbose)
}

/// Remove a devcontainer: stop, remove container, remove rootfs.
pub fn devcontainer_rm(datadir: &Path, name: &str, verbose: bool) -> Result<()> {
    validate_name(name)?;

    let state_path = datadir.join("state").join(name);
    if state_path.exists() {
        let state = State::read_from(&state_path)?;
        if !state.is_yes("DEVCONTAINER") {
            bail!("container '{name}' is not a devcontainer; use 'sdme rm' instead");
        }
        let rootfs_name = state.rootfs().to_string();

        // Remove the container (stops it if running).
        crate::containers::remove(datadir, name, verbose)?;

        // Remove the rootfs.
        if !rootfs_name.is_empty() {
            let rootfs_path = datadir.join("fs").join(&rootfs_name);
            if rootfs_path.exists() {
                if verbose {
                    eprintln!("removing rootfs: {rootfs_name}");
                }
                crate::rootfs::remove(datadir, &rootfs_name, false, verbose)?;
            }
        }
    } else {
        bail!("devcontainer not found: {name}");
    }

    Ok(())
}

// --- Internal helpers ---

/// Import an OCI image as a rootfs for the devcontainer.
fn import_image(
    datadir: &Path,
    rootfs_name: &str,
    image: &str,
    opts: &DevcontainerUpOptions<'_>,
) -> Result<()> {
    let rootfs_path = datadir.join("fs").join(rootfs_name);
    if rootfs_path.exists() {
        if opts.verbose {
            eprintln!("rootfs '{rootfs_name}' already exists, reusing");
        }
        return Ok(());
    }

    eprintln!("importing image: {image}");
    let import_opts = crate::import::ImportOptions {
        source: image,
        name: rootfs_name,
        verbose: opts.verbose,
        force: false,
        interactive: opts.interactive,
        install_packages: crate::import::InstallPackages::Yes,
        oci_mode: crate::import::OciMode::Base,
        base_fs: None,
        docker_credentials: opts.docker_credentials,
        cache: opts.cache,
        http: opts.http.clone(),
        auto_gc: opts.auto_gc,
        distros: opts.distros,
    };
    crate::rootfs::import(datadir, &import_opts)
}

/// Construct CreateOptions from the validated plan.
fn build_create_options(
    plan: &DevcontainerPlan,
    container_name: &str,
    rootfs_name: &str,
) -> Result<crate::containers::CreateOptions> {
    let binds = crate::BindConfig {
        binds: plan.binds.clone(),
    };
    let envs = crate::EnvConfig {
        vars: plan.env_vars.clone(),
    };

    // Build network config: private network with port forwarding if ports are defined.
    let mut network = crate::NetworkConfig::default();
    if !plan.ports.is_empty() {
        network.private_network = true;
        network.network_veth = true;
        for p in &plan.ports {
            network.ports.push(p.clone());
        }
    }

    // Build security config from capabilities.
    let mut security = crate::SecurityConfig::default();
    for cap in &plan.cap_add {
        let cap_name = if cap.starts_with("CAP_") {
            cap.clone()
        } else {
            format!("CAP_{}", cap.to_uppercase())
        };
        security.add_caps.push(cap_name);
    }

    Ok(crate::containers::CreateOptions {
        name: Some(container_name.to_string()),
        rootfs: Some(rootfs_name.to_string()),
        binds,
        envs,
        network,
        security,
        ..Default::default()
    })
}

/// Run a list of lifecycle commands inside the container.
fn run_lifecycle_commands(
    name: &str,
    hook_name: &str,
    commands: &[String],
    remote_user: Option<&str>,
    verbose: bool,
) -> Result<()> {
    if commands.is_empty() {
        return Ok(());
    }

    for cmd_str in commands {
        check_interrupted()?;
        if verbose {
            eprintln!("{hook_name}: {cmd_str}");
        } else {
            eprintln!("running {hook_name}");
        }
        let command = vec!["/bin/sh".to_string(), "-c".to_string(), cmd_str.clone()];
        let status = exec_in_container(name, &command, remote_user, None, verbose)?;
        if !status.success() {
            let code = status.code().unwrap_or(1);
            bail!("{hook_name} failed (exit code {code}): {cmd_str}");
        }
    }
    Ok(())
}

/// Execute a command inside a container, optionally as a specific user.
fn exec_in_container(
    name: &str,
    command: &[String],
    user: Option<&str>,
    _workdir: Option<&str>,
    verbose: bool,
) -> Result<std::process::ExitStatus> {
    // Verify the container is running before exec.
    let active = crate::systemd::unit_active_state(name);
    if active.as_deref() != Some("active") {
        anyhow::bail!("container '{name}' is not running");
    }

    let mut cmd = std::process::Command::new("machinectl");
    cmd.arg("shell");
    if let Some(u) = user {
        cmd.args(["--uid", u]);
    }
    cmd.arg(name);
    if !command.is_empty() {
        cmd.args(command);
    }
    if verbose {
        eprintln!(
            "exec: machinectl {}",
            cmd.get_args()
                .map(|a| a.to_string_lossy())
                .collect::<Vec<_>>()
                .join(" ")
        );
    }
    let status = cmd.status().context("failed to run machinectl")?;
    check_interrupted()?;
    Ok(status)
}

/// Install Dev Container Features by running their install scripts inside the container.
///
/// Features are OCI artifacts containing install.sh scripts. For the initial
/// implementation, we support a simplified approach: download the feature
/// layer, extract install.sh, and run it with the option values as environment
/// variables.
fn install_features(name: &str, plan: &DevcontainerPlan, verbose: bool) -> Result<()> {
    for (feature_ref, options) in &plan.features {
        check_interrupted()?;
        eprintln!("installing feature: {feature_ref}");

        // Build environment variables from feature options.
        let mut env_args = Vec::new();
        if let Some(obj) = options.as_object() {
            for (key, value) in obj {
                let val_str = match value {
                    serde_json::Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                let env_key = key.to_uppercase();
                env_args.push(format!("{env_key}={val_str}"));
            }
        }

        // For now, generate a helper script that tries to install the feature.
        // Full OCI feature pulling would reuse oci::registry, but that's a
        // follow-up enhancement. For now, we warn and skip unknown features.
        if feature_ref.starts_with("ghcr.io/devcontainers/features/") {
            let feature_name = feature_ref
                .rsplit('/')
                .next()
                .unwrap_or(feature_ref)
                .split(':')
                .next()
                .unwrap_or(feature_ref);

            // Generate a simple install command based on well-known features.
            let install_cmd = match feature_name {
                "node" => {
                    let version = env_args
                        .iter()
                        .find(|e| e.starts_with("VERSION="))
                        .map(|e| e.split_once('=').unwrap().1)
                        .unwrap_or("lts");
                    format!(
                        "if command -v apt-get >/dev/null 2>&1; then \
                         apt-get update && apt-get install -y curl && \
                         curl -fsSL https://deb.nodesource.com/setup_{version}.x | bash - && \
                         apt-get install -y nodejs; \
                         elif command -v dnf >/dev/null 2>&1; then \
                         dnf install -y nodejs; fi"
                    )
                }
                "python" => {
                    let version = env_args
                        .iter()
                        .find(|e| e.starts_with("VERSION="))
                        .map(|e| e.split_once('=').unwrap().1)
                        .unwrap_or("3");
                    format!(
                        "if command -v apt-get >/dev/null 2>&1; then \
                         apt-get update && apt-get install -y python{version} python3-pip; \
                         elif command -v dnf >/dev/null 2>&1; then \
                         dnf install -y python{version} python3-pip; fi"
                    )
                }
                "git" => "if command -v apt-get >/dev/null 2>&1; then \
                     apt-get update && apt-get install -y git; \
                     elif command -v dnf >/dev/null 2>&1; then \
                     dnf install -y git; fi"
                    .to_string(),
                _ => {
                    eprintln!(
                        "warning: feature '{feature_ref}' is not natively supported; \
                         skipping (full OCI feature support is planned)"
                    );
                    continue;
                }
            };

            let command = vec!["/bin/sh".to_string(), "-c".to_string(), install_cmd];
            let status = exec_in_container(name, &command, None, None, verbose)?;
            if !status.success() {
                eprintln!(
                    "warning: feature '{feature_ref}' installation failed (exit code {})",
                    status.code().unwrap_or(1)
                );
            }
        } else {
            eprintln!("warning: custom feature '{feature_ref}' is not yet supported; skipping");
        }
    }
    Ok(())
}
