//! Kubernetes Pod YAML support for sdme.
//!
//! Parses `kind: Pod` (v1) and `kind: Deployment` (apps/v1) YAML files,
//! mapping each pod to a single nspawn container running multiple OCI
//! workloads as separate systemd services under `/oci/apps/{name}/`.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::copy::make_removable;
use crate::import::registry::{ImageReference, OciContainerConfig};
use crate::import::{resolve_oci_user, shell_join};
use crate::{check_interrupted, validate_name, State};

// --- YAML types ---

/// Top-level Kubernetes manifest (Pod or Deployment).
#[derive(serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct KubeManifest {
    #[allow(dead_code)]
    api_version: Option<String>,
    kind: String,
    metadata: Option<Metadata>,
    spec: Option<serde_yml::Value>,
}

#[derive(serde::Deserialize, Debug)]
struct Metadata {
    name: Option<String>,
}

/// Deployment spec wrapper to extract the pod template.
#[derive(serde::Deserialize, Debug)]
struct DeploymentSpec {
    template: PodTemplate,
}

#[derive(serde::Deserialize, Debug)]
struct PodTemplate {
    metadata: Option<Metadata>,
    spec: PodSpec,
}

/// Core pod specification.
#[derive(serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PodSpec {
    pub(crate) containers: Vec<Container>,
    #[serde(default)]
    pub(crate) volumes: Vec<Volume>,
    #[serde(default)]
    pub(crate) restart_policy: Option<String>,
}

#[derive(serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Container {
    pub(crate) name: String,
    pub(crate) image: String,
    #[serde(default)]
    pub(crate) command: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) args: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) env: Vec<EnvVar>,
    #[serde(default)]
    pub(crate) ports: Vec<ContainerPort>,
    #[serde(default)]
    pub(crate) volume_mounts: Vec<VolumeMount>,
}

#[derive(serde::Deserialize, Debug)]
pub(crate) struct EnvVar {
    pub(crate) name: String,
    pub(crate) value: Option<String>,
}

#[derive(serde::Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ContainerPort {
    pub(crate) container_port: u16,
    #[serde(default)]
    pub(crate) protocol: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    pub(crate) name: Option<String>,
}

#[derive(serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VolumeMount {
    pub(crate) name: String,
    pub(crate) mount_path: String,
    #[serde(default)]
    pub(crate) read_only: bool,
}

#[derive(serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Volume {
    pub(crate) name: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub(crate) empty_dir: Option<serde_yml::Value>,
    #[serde(default)]
    pub(crate) host_path: Option<HostPathVolume>,
}

#[derive(serde::Deserialize, Debug)]
pub(crate) struct HostPathVolume {
    pub(crate) path: String,
}

// --- Parsed / validated plan ---

/// A validated plan for creating a kube pod container.
#[derive(Debug)]
pub(crate) struct KubePlan {
    pub(crate) pod_name: String,
    pub(crate) containers: Vec<KubeContainer>,
    pub(crate) volumes: Vec<KubeVolume>,
    pub(crate) restart_policy: String,
    /// Aggregated ports from all containers.
    pub(crate) ports: Vec<ContainerPort>,
    /// Host-path binds needed at nspawn level.
    pub(crate) host_binds: Vec<(String, String)>,
}

#[derive(Debug)]
pub(crate) struct KubeContainer {
    pub(crate) name: String,
    pub(crate) image: String,
    pub(crate) image_ref: ImageReference,
    pub(crate) command_override: Option<Vec<String>>,
    pub(crate) args_override: Option<Vec<String>>,
    pub(crate) env: Vec<(String, String)>,
    pub(crate) volume_mounts: Vec<KubeVolumeMount>,
}

#[derive(Debug)]
pub(crate) struct KubeVolumeMount {
    pub(crate) volume_name: String,
    pub(crate) mount_path: String,
    pub(crate) read_only: bool,
}

#[derive(Debug)]
pub(crate) enum KubeVolumeKind {
    EmptyDir,
    HostPath(String),
}

#[derive(Debug)]
pub(crate) struct KubeVolume {
    pub(crate) name: String,
    pub(crate) kind: KubeVolumeKind,
}

// --- Parsing ---

/// Parse a YAML file into a pod name and PodSpec.
pub(crate) fn parse_yaml(content: &str) -> Result<(String, PodSpec)> {
    let manifest: KubeManifest =
        serde_yml::from_str(content).context("failed to parse Kubernetes YAML")?;

    match manifest.kind.as_str() {
        "Pod" => {
            let name = manifest
                .metadata
                .as_ref()
                .and_then(|m| m.name.clone())
                .unwrap_or_default();
            let spec: PodSpec =
                serde_yml::from_value(manifest.spec.context("Pod manifest missing 'spec' field")?)
                    .context("failed to parse Pod spec")?;
            Ok((name, spec))
        }
        "Deployment" => {
            let deploy_spec: DeploymentSpec = serde_yml::from_value(
                manifest
                    .spec
                    .context("Deployment manifest missing 'spec' field")?,
            )
            .context("failed to parse Deployment spec")?;
            let name = deploy_spec
                .template
                .metadata
                .as_ref()
                .and_then(|m| m.name.clone())
                .or_else(|| manifest.metadata.as_ref().and_then(|m| m.name.clone()))
                .unwrap_or_default();
            Ok((name, deploy_spec.template.spec))
        }
        other => bail!("unsupported kind: {other}; only Pod and Deployment are supported"),
    }
}

// --- Validation ---

/// Validate a PodSpec and produce a KubePlan.
pub(crate) fn validate_and_plan(pod_name: &str, spec: PodSpec) -> Result<KubePlan> {
    if spec.containers.is_empty() {
        bail!("pod must have at least one container");
    }

    // Validate pod name.
    if pod_name.is_empty() {
        bail!("pod name is required (set metadata.name in the YAML)");
    }
    validate_name(pod_name).context("invalid pod name")?;

    // Validate container names are unique and valid.
    let mut seen_names = HashSet::new();
    for c in &spec.containers {
        validate_name(&c.name).with_context(|| format!("invalid container name: {}", c.name))?;
        if !seen_names.insert(&c.name) {
            bail!("duplicate container name: {}", c.name);
        }
        if c.image.is_empty() {
            bail!("container '{}' has empty image", c.name);
        }
    }

    // Validate volume names are unique.
    let mut vol_names = HashSet::new();
    for v in &spec.volumes {
        if !vol_names.insert(&v.name) {
            bail!("duplicate volume name: {}", v.name);
        }
        // Validate hostPath.
        if let Some(ref hp) = v.host_path {
            if !hp.path.starts_with('/') {
                bail!(
                    "volume '{}' hostPath must be absolute, got: {}",
                    v.name,
                    hp.path
                );
            }
            if hp.path.contains("..") {
                bail!(
                    "volume '{}' hostPath must not contain '..': {}",
                    v.name,
                    hp.path
                );
            }
        }
    }

    // Validate volume mount references.
    for c in &spec.containers {
        for vm in &c.volume_mounts {
            if !vol_names.contains(&vm.name) {
                bail!(
                    "container '{}' references undefined volume: {}",
                    c.name,
                    vm.name
                );
            }
            if !vm.mount_path.starts_with('/') {
                bail!(
                    "container '{}' volumeMount path must be absolute: {}",
                    c.name,
                    vm.mount_path
                );
            }
            if vm.mount_path.contains("..") {
                bail!(
                    "container '{}' volumeMount path must not contain '..': {}",
                    c.name,
                    vm.mount_path
                );
            }
        }
    }

    // Parse restart policy.
    let restart_policy = match spec.restart_policy.as_deref() {
        None | Some("Always") => "always".to_string(),
        Some("OnFailure") => "on-failure".to_string(),
        Some("Never") => "no".to_string(),
        Some(other) => bail!("unsupported restartPolicy: {other}"),
    };

    // Build volumes.
    let volumes: Vec<KubeVolume> = spec
        .volumes
        .iter()
        .map(|v| {
            let kind = if let Some(ref hp) = v.host_path {
                KubeVolumeKind::HostPath(hp.path.clone())
            } else {
                KubeVolumeKind::EmptyDir
            };
            KubeVolume {
                name: v.name.clone(),
                kind,
            }
        })
        .collect();

    // Collect host-path binds for nspawn --bind= arguments.
    let host_binds: Vec<(String, String)> = volumes
        .iter()
        .filter_map(|v| match &v.kind {
            KubeVolumeKind::HostPath(path) => {
                Some((path.clone(), format!("/oci/volumes/{}", v.name)))
            }
            KubeVolumeKind::EmptyDir => None,
        })
        .collect();

    // Aggregate ports from all containers, warn on duplicates.
    let mut ports = Vec::new();
    let mut seen_ports = HashSet::new();
    for c in &spec.containers {
        for p in &c.ports {
            if !seen_ports.insert(p.container_port) {
                eprintln!(
                    "warning: duplicate port {} in container '{}', skipping",
                    p.container_port, c.name
                );
                continue;
            }
            ports.push(p.clone());
        }
    }

    // Build container plans.
    let containers: Vec<KubeContainer> = spec
        .containers
        .into_iter()
        .map(|c| {
            let image_ref = ImageReference::parse(&c.image)
                .with_context(|| format!("invalid image reference: {}", c.image))?;
            let env: Vec<(String, String)> = c
                .env
                .iter()
                .map(|e| (e.name.clone(), e.value.clone().unwrap_or_default()))
                .collect();
            let volume_mounts: Vec<KubeVolumeMount> = c
                .volume_mounts
                .iter()
                .map(|vm| KubeVolumeMount {
                    volume_name: vm.name.clone(),
                    mount_path: vm.mount_path.clone(),
                    read_only: vm.read_only,
                })
                .collect();
            Ok(KubeContainer {
                name: c.name,
                image: c.image,
                image_ref,
                command_override: c.command,
                args_override: c.args,
                env,
                volume_mounts,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(KubePlan {
        pod_name: pod_name.to_string(),
        containers,
        volumes,
        restart_policy,
        ports,
        host_binds,
    })
}

// --- Orchestration ---

/// Create a kube pod: parse YAML, pull images, build combined rootfs, create container.
///
/// Returns the container name on success.
pub fn kube_create(
    datadir: &Path,
    yaml_content: &str,
    base_fs: &str,
    verbose: bool,
) -> Result<String> {
    validate_name(base_fs)?;
    let base_dir = datadir.join("fs").join(base_fs);
    if !base_dir.is_dir() {
        bail!("base rootfs not found: {base_fs}");
    }

    let (pod_name, spec) = parse_yaml(yaml_content)?;
    let plan = validate_and_plan(&pod_name, spec)?;

    let rootfs_name = format!("kube-{}", plan.pod_name);
    let rootfs_dir = datadir.join("fs");
    let final_dir = rootfs_dir.join(&rootfs_name);
    let staging_name = format!(".{rootfs_name}.importing");
    let staging_dir = rootfs_dir.join(&staging_name);

    // Fail if rootfs already exists.
    if final_dir.exists() {
        bail!("rootfs already exists: {rootfs_name}; delete the existing kube pod first");
    }

    // Clean up any leftover staging dir.
    if staging_dir.exists() {
        let _ = make_removable(&staging_dir);
        fs::remove_dir_all(&staging_dir)
            .with_context(|| format!("failed to remove {}", staging_dir.display()))?;
    }

    // 1. Copy base rootfs to staging dir.
    eprintln!("copying base rootfs '{base_fs}' to staging directory");
    fs::create_dir_all(&staging_dir)
        .with_context(|| format!("failed to create {}", staging_dir.display()))?;
    crate::copy::copy_tree(&base_dir, &staging_dir, verbose)
        .with_context(|| format!("failed to copy base rootfs from {}", base_dir.display()))?;

    // 2. Create /oci/apps/ and /oci/volumes/ directories.
    let apps_dir = staging_dir.join("oci/apps");
    fs::create_dir_all(&apps_dir)
        .with_context(|| format!("failed to create {}", apps_dir.display()))?;
    let volumes_dir = staging_dir.join("oci/volumes");
    fs::create_dir_all(&volumes_dir)
        .with_context(|| format!("failed to create {}", volumes_dir.display()))?;

    // Create emptyDir volumes.
    for vol in &plan.volumes {
        if matches!(vol.kind, KubeVolumeKind::EmptyDir) {
            let vol_path = volumes_dir.join(&vol.name);
            fs::create_dir_all(&vol_path)
                .with_context(|| format!("failed to create volume dir {}", vol_path.display()))?;
        }
    }

    // 3. Pull each container image and set up its app directory.
    let unit_dir = staging_dir.join("etc/systemd/system");
    fs::create_dir_all(&unit_dir)
        .with_context(|| format!("failed to create {}", unit_dir.display()))?;
    let wants_dir = unit_dir.join("multi-user.target.wants");
    fs::create_dir_all(&wants_dir)
        .with_context(|| format!("failed to create {}", wants_dir.display()))?;

    for kc in &plan.containers {
        check_interrupted()?;

        let app_dir = apps_dir.join(&kc.name);
        let app_root = app_dir.join("root");
        fs::create_dir_all(&app_root)
            .with_context(|| format!("failed to create {}", app_root.display()))?;

        // Pull the image.
        let oci_config = crate::import::registry::import_registry_image(
            &kc.image_ref,
            &app_root,
            &rootfs_dir,
            verbose,
        )
        .with_context(|| format!("failed to pull image for container '{}'", kc.name))?;

        // Set up the app.
        setup_kube_container(
            &staging_dir,
            &app_dir,
            kc,
            oci_config.as_ref(),
            &plan.restart_policy,
            &plan.volumes,
            verbose,
        )
        .with_context(|| format!("failed to set up container '{}'", kc.name))?;
    }

    // 4. Atomic rename.
    fs::rename(&staging_dir, &final_dir).with_context(|| {
        format!(
            "failed to rename {} to {}",
            staging_dir.display(),
            final_dir.display()
        )
    })?;

    eprintln!("created rootfs: {rootfs_name}");

    // 5. Create the sdme container.
    let yaml_hash = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(yaml_content.as_bytes());
        format!("{:x}", hasher.finalize())
    };

    let container_names: Vec<&str> = plan.containers.iter().map(|c| c.name.as_str()).collect();

    // Build bind mounts for hostPath volumes.
    let binds = crate::BindConfig {
        binds: plan
            .host_binds
            .iter()
            .map(|(host, container)| format!("{host}:{container}:rw"))
            .collect(),
    };

    // Build port forwarding.
    let mut network = crate::NetworkConfig::default();
    if !plan.ports.is_empty() {
        network.private_network = true;
        for p in &plan.ports {
            let proto = p.protocol.as_deref().unwrap_or("tcp").to_lowercase();
            let port_str = format!("{proto}:{0}:{0}", p.container_port);
            network.ports.push(port_str);
        }
    }

    let opts = crate::containers::CreateOptions {
        name: Some(plan.pod_name.clone()),
        rootfs: Some(rootfs_name.clone()),
        network,
        binds,
        ..Default::default()
    };
    let name = crate::containers::create(datadir, &opts, verbose)?;

    // Write kube-specific state fields.
    let state_path = datadir.join("state").join(&name);
    let mut state = State::read_from(&state_path)?;
    state.set("KUBE", "yes");
    state.set("KUBE_CONTAINERS", container_names.join(","));
    state.set("KUBE_YAML_HASH", &yaml_hash);
    state.write_to(&state_path)?;

    Ok(name)
}

/// Delete a kube pod: stop container, remove container, remove rootfs.
pub fn kube_delete(datadir: &Path, name: &str, force: bool, verbose: bool) -> Result<()> {
    validate_name(name)?;

    let state_path = datadir.join("state").join(name);
    if !state_path.exists() {
        bail!("container not found: {name}");
    }

    let state = State::read_from(&state_path)?;
    if !state.is_yes("KUBE") && !force {
        bail!("container '{name}' is not a kube pod; use --force to delete anyway");
    }

    let rootfs_name = state.rootfs().to_string();

    // Stop and remove the container.
    crate::containers::remove(datadir, name, verbose)?;

    // Remove the rootfs.
    if !rootfs_name.is_empty() {
        let rootfs_path = datadir.join("fs").join(&rootfs_name);
        if rootfs_path.exists() {
            eprintln!("removing rootfs: {rootfs_name}");
            let _ = make_removable(&rootfs_path);
            fs::remove_dir_all(&rootfs_path)
                .with_context(|| format!("failed to remove {}", rootfs_path.display()))?;
        }
    }

    Ok(())
}

// --- Per-container setup ---

/// Set up a single container app inside the combined rootfs.
///
/// Creates the service unit, env file, deploys devfd shim and drop_privs binary.
fn setup_kube_container(
    staging_dir: &Path,
    app_dir: &Path,
    kc: &KubeContainer,
    oci_config: Option<&OciContainerConfig>,
    restart_policy: &str,
    _volumes: &[KubeVolume],
    verbose: bool,
) -> Result<()> {
    let app_root = app_dir.join("root");
    let default_config = OciContainerConfig::default();
    let config = oci_config.unwrap_or(&default_config);

    // Build ExecStart from command/args overrides per K8s semantics:
    // - K8s `command` replaces Docker ENTRYPOINT
    // - K8s `args` replaces Docker CMD
    // - If only `args`, keep original ENTRYPOINT
    let mut exec_args: Vec<String> = Vec::new();
    if let Some(ref cmd_override) = kc.command_override {
        exec_args.extend(cmd_override.iter().cloned());
    } else if let Some(ref ep) = config.entrypoint {
        exec_args.extend(ep.iter().cloned());
    }
    if let Some(ref args_override) = kc.args_override {
        exec_args.extend(args_override.iter().cloned());
    } else if kc.command_override.is_none() {
        if let Some(ref cmd) = config.cmd {
            exec_args.extend(cmd.iter().cloned());
        }
    }
    if exec_args.is_empty() {
        bail!(
            "container '{}': no command to run (no entrypoint/cmd in image and no command/args override)",
            kc.name
        );
    }
    let exec_start = shell_join(&exec_args);

    let working_dir = config.working_dir.as_deref().unwrap_or("/");
    let user = config.user.as_deref().unwrap_or("root");

    // Ensure essential runtime directories.
    for (dir, mode) in [
        ("tmp", 0o1777),
        ("run", 0o755),
        ("var/run", 0o755),
        ("var/tmp", 0o1777),
    ] {
        use std::os::unix::fs::DirBuilderExt;
        let path = app_root.join(dir);
        if !path.exists() {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("failed to create {}", parent.display()))?;
            }
            fs::DirBuilder::new()
                .mode(mode)
                .create(&path)
                .with_context(|| format!("failed to create {}", path.display()))?;
        }
    }

    // Deploy devfd shim.
    let arch = match std::env::consts::ARCH {
        "x86_64" => crate::drop_privs::Arch::X86_64,
        "aarch64" => crate::drop_privs::Arch::Aarch64,
        other => bail!("unsupported architecture: {other}"),
    };
    let shim_bytes = crate::devfd_shim::generate(arch);
    let shim_path = app_root.join(".sdme-devfd-shim.so");
    fs::write(&shim_path, &shim_bytes)
        .with_context(|| format!("failed to write {}", shim_path.display()))?;
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&shim_path, fs::Permissions::from_mode(0o444))
        .with_context(|| format!("failed to set permissions on {}", shim_path.display()))?;

    // Deploy drop_privs if non-root user.
    let resolved_user = resolve_oci_user(&app_root, user)?;
    if let Some(ref ru) = resolved_user {
        let elf_bytes = crate::drop_privs::generate(arch);
        let drop_privs_path = app_root.join(".sdme-drop-privs");
        fs::write(&drop_privs_path, &elf_bytes)
            .with_context(|| format!("failed to write {}", drop_privs_path.display()))?;
        fs::set_permissions(&drop_privs_path, fs::Permissions::from_mode(0o111)).with_context(
            || format!("failed to set permissions on {}", drop_privs_path.display()),
        )?;
        if verbose {
            eprintln!(
                "wrote drop_privs binary for uid={} gid={}: {}",
                ru.uid,
                ru.gid,
                drop_privs_path.display()
            );
        }
    }

    // Write env file: combine OCI image env + K8s env overrides.
    let mut env_lines: Vec<String> = Vec::new();
    if let Some(ref image_env) = config.env {
        env_lines.extend(image_env.iter().cloned());
    }
    // K8s env vars override image env vars (by key).
    let mut seen_keys: HashMap<String, usize> = HashMap::new();
    for (i, line) in env_lines.iter().enumerate() {
        if let Some(key) = line.split('=').next() {
            seen_keys.insert(key.to_string(), i);
        }
    }
    for (key, value) in &kc.env {
        let line = format!("{key}={value}");
        if let Some(&idx) = seen_keys.get(key) {
            env_lines[idx] = line;
        } else {
            env_lines.push(line);
        }
    }
    if !env_lines.is_empty() {
        let env_path = app_dir.join("env");
        let content = env_lines.join("\n") + "\n";
        fs::write(&env_path, &content)
            .with_context(|| format!("failed to write {}", env_path.display()))?;
    }

    // Write ports file.
    if let Some(ref ports) = config.exposed_ports {
        if !ports.is_empty() {
            let mut keys: Vec<&str> = ports.keys().map(|s| s.as_str()).collect();
            keys.sort();
            let content = keys.join("\n") + "\n";
            fs::write(app_dir.join("ports"), &content).context("failed to write ports file")?;
        }
    }

    // Write volumes file.
    if let Some(ref vols) = config.volumes {
        if !vols.is_empty() {
            let mut keys: Vec<&str> = vols.keys().map(|s| s.as_str()).collect();
            keys.sort();
            let content = keys.join("\n") + "\n";
            fs::write(app_dir.join("volumes"), &content).context("failed to write volumes file")?;
        }
    }

    // Build BindPaths for volume mounts.
    let mut bind_paths: Vec<String> = Vec::new();
    for vm in &kc.volume_mounts {
        let vol_src = format!("/oci/volumes/{}", vm.volume_name);
        let vol_dst = format!("/oci/apps/{}/root{}", kc.name, vm.mount_path);
        // Create the mount point dir inside the app root.
        let mount_dir = app_root.join(vm.mount_path.trim_start_matches('/'));
        fs::create_dir_all(&mount_dir)
            .with_context(|| format!("failed to create mount point {}", mount_dir.display()))?;
        if vm.read_only {
            bind_paths.push(format!("BindReadOnlyPaths={vol_src} {vol_dst}"));
        } else {
            bind_paths.push(format!("BindPaths={vol_src} {vol_dst}"));
        }
    }
    let bind_paths_section = if bind_paths.is_empty() {
        String::new()
    } else {
        bind_paths.join("\n") + "\n"
    };

    // Build the [Service] section.
    let service_section = if let Some(ref ru) = resolved_user {
        let drop_privs_exec = format!(
            "/.sdme-drop-privs {} {} {} {}",
            ru.uid, ru.gid, working_dir, exec_start
        );
        format!(
            "\
RootDirectory=/oci/apps/{name}/root
MountAPIVFS=yes
Environment=LD_PRELOAD=/.sdme-devfd-shim.so
EnvironmentFile=-/oci/apps/{name}/env
ExecStart={drop_privs_exec}
{bind_paths_section}",
            name = kc.name
        )
    } else {
        format!(
            "\
RootDirectory=/oci/apps/{name}/root
MountAPIVFS=yes
Environment=LD_PRELOAD=/.sdme-devfd-shim.so
ExecStart={exec_start}
WorkingDirectory={working_dir}
EnvironmentFile=-/oci/apps/{name}/env
User={user}
{bind_paths_section}",
            name = kc.name
        )
    };

    let service_name = format!("sdme-oci-{}.service", kc.name);
    let unit_content = format!(
        r#"# Generated by sdme kube from image: {image}
[Unit]
Description=sdme kube container: {name} ({image})
After=network.target

[Service]
Type=exec
{service_section}Restart={restart_policy}

[Install]
WantedBy=multi-user.target
"#,
        image = kc.image,
        name = kc.name,
    );

    let unit_dir = staging_dir.join("etc/systemd/system");
    let unit_path = unit_dir.join(&service_name);
    fs::write(&unit_path, &unit_content)
        .with_context(|| format!("failed to write {}", unit_path.display()))?;

    // Enable via symlink.
    let wants_dir = unit_dir.join("multi-user.target.wants");
    let symlink_path = wants_dir.join(&service_name);
    std::os::unix::fs::symlink(format!("../{service_name}"), &symlink_path)
        .with_context(|| format!("failed to create symlink {}", symlink_path.display()))?;

    if verbose {
        eprintln!("wrote unit file: {}", unit_path.display());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_pod() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: nginx-pod
spec:
  containers:
  - name: nginx
    image: docker.io/nginx:latest
    ports:
    - containerPort: 80
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        assert_eq!(name, "nginx-pod");
        assert_eq!(spec.containers.len(), 1);
        assert_eq!(spec.containers[0].name, "nginx");
        assert_eq!(spec.containers[0].image, "docker.io/nginx:latest");
        assert_eq!(spec.containers[0].ports.len(), 1);
        assert_eq!(spec.containers[0].ports[0].container_port, 80);
    }

    #[test]
    fn test_parse_multi_container_pod() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: web-cache
spec:
  containers:
  - name: nginx
    image: docker.io/nginx:latest
    ports:
    - containerPort: 80
    volumeMounts:
    - name: cache-vol
      mountPath: /var/cache
  - name: redis
    image: docker.io/redis:latest
    ports:
    - containerPort: 6379
    volumeMounts:
    - name: cache-vol
      mountPath: /data
  volumes:
  - name: cache-vol
    emptyDir: {}
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        assert_eq!(name, "web-cache");
        assert_eq!(spec.containers.len(), 2);
        assert_eq!(spec.containers[0].name, "nginx");
        assert_eq!(spec.containers[1].name, "redis");
        assert_eq!(spec.volumes.len(), 1);
        assert_eq!(spec.volumes[0].name, "cache-vol");
        assert!(spec.volumes[0].empty_dir.is_some());
    }

    #[test]
    fn test_parse_deployment() {
        let yaml = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-deploy
spec:
  replicas: 1
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      name: my-pod
    spec:
      containers:
      - name: web
        image: docker.io/nginx:latest
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        assert_eq!(name, "my-pod");
        assert_eq!(spec.containers.len(), 1);
        assert_eq!(spec.containers[0].name, "web");
    }

    #[test]
    fn test_parse_deployment_name_fallback() {
        let yaml = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-deploy
spec:
  replicas: 1
  selector:
    matchLabels:
      app: web
  template:
    spec:
      containers:
      - name: web
        image: docker.io/nginx:latest
"#;
        let (name, _) = parse_yaml(yaml).unwrap();
        assert_eq!(name, "my-deploy");
    }

    #[test]
    fn test_parse_invalid_kind() {
        let yaml = r#"
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: my-sts
spec:
  containers:
  - name: web
    image: docker.io/nginx:latest
"#;
        let err = parse_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("unsupported kind: StatefulSet"));
    }

    #[test]
    fn test_parse_env_vars() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: env-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    env:
    - name: FOO
      value: bar
    - name: BAZ
      value: "123"
"#;
        let (_, spec) = parse_yaml(yaml).unwrap();
        assert_eq!(spec.containers[0].env.len(), 2);
        assert_eq!(spec.containers[0].env[0].name, "FOO");
        assert_eq!(spec.containers[0].env[0].value, Some("bar".to_string()));
    }

    #[test]
    fn test_parse_volumes() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: vol-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    volumeMounts:
    - name: data
      mountPath: /data
    - name: host-config
      mountPath: /etc/app
      readOnly: true
  volumes:
  - name: data
    emptyDir: {}
  - name: host-config
    hostPath:
      path: /opt/config
"#;
        let (_, spec) = parse_yaml(yaml).unwrap();
        assert_eq!(spec.volumes.len(), 2);
        assert!(spec.volumes[0].empty_dir.is_some());
        assert!(spec.volumes[0].host_path.is_none());
        assert!(spec.volumes[1].empty_dir.is_none());
        assert_eq!(
            spec.volumes[1].host_path.as_ref().unwrap().path,
            "/opt/config"
        );
        assert!(spec.containers[0].volume_mounts[1].read_only);
    }

    #[test]
    fn test_parse_volume_mount_validation() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: bad-vol
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    volumeMounts:
    - name: nonexistent
      mountPath: /data
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let err = validate_and_plan(&name, spec).unwrap_err();
        assert!(err.to_string().contains("undefined volume"));
    }

    #[test]
    fn test_parse_command_args_override() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: cmd-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    command: ["/bin/sh", "-c"]
    args: ["echo hello"]
"#;
        let (_, spec) = parse_yaml(yaml).unwrap();
        assert_eq!(
            spec.containers[0].command,
            Some(vec!["/bin/sh".to_string(), "-c".to_string()])
        );
        assert_eq!(
            spec.containers[0].args,
            Some(vec!["echo hello".to_string()])
        );
    }

    #[test]
    fn test_parse_restart_policy() {
        for (policy, expected) in [
            ("Always", "always"),
            ("OnFailure", "on-failure"),
            ("Never", "no"),
        ] {
            let yaml = format!(
                r#"
apiVersion: v1
kind: Pod
metadata:
  name: restart-pod
spec:
  restartPolicy: {policy}
  containers:
  - name: app
    image: docker.io/busybox:latest
"#
            );
            let (name, spec) = parse_yaml(&yaml).unwrap();
            let plan = validate_and_plan(&name, spec).unwrap();
            assert_eq!(plan.restart_policy, expected, "policy={policy}");
        }
    }

    #[test]
    fn test_port_aggregation() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: multi-port
spec:
  containers:
  - name: web
    image: docker.io/nginx:latest
    ports:
    - containerPort: 80
    - containerPort: 443
  - name: api
    image: docker.io/node:latest
    ports:
    - containerPort: 3000
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();
        assert_eq!(plan.ports.len(), 3);
        let port_nums: Vec<u16> = plan.ports.iter().map(|p| p.container_port).collect();
        assert!(port_nums.contains(&80));
        assert!(port_nums.contains(&443));
        assert!(port_nums.contains(&3000));
    }

    #[test]
    fn test_validate_empty_containers() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: empty-pod
spec:
  containers: []
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let err = validate_and_plan(&name, spec).unwrap_err();
        assert!(err.to_string().contains("at least one container"));
    }

    #[test]
    fn test_validate_duplicate_container_names() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: dup-pod
spec:
  containers:
  - name: app
    image: docker.io/nginx:latest
  - name: app
    image: docker.io/redis:latest
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let err = validate_and_plan(&name, spec).unwrap_err();
        assert!(err.to_string().contains("duplicate container name"));
    }

    #[test]
    fn test_validate_hostpath_relative() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: bad-host
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
  volumes:
  - name: data
    hostPath:
      path: relative/path
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let err = validate_and_plan(&name, spec).unwrap_err();
        assert!(err.to_string().contains("absolute"));
    }

    #[test]
    fn test_validate_hostpath_dotdot() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: bad-host2
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
  volumes:
  - name: data
    hostPath:
      path: /tmp/../etc
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let err = validate_and_plan(&name, spec).unwrap_err();
        assert!(err.to_string().contains(".."));
    }

    #[test]
    fn test_default_restart_policy() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: default-restart
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();
        assert_eq!(plan.restart_policy, "always");
    }
}
