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
use crate::import::shell_join;
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
    pub(crate) init_containers: Vec<Container>,
    #[serde(default)]
    pub(crate) volumes: Vec<Volume>,
    #[serde(default)]
    pub(crate) restart_policy: Option<String>,
    #[serde(default)]
    pub(crate) termination_grace_period_seconds: Option<u32>,
    #[serde(default)]
    pub(crate) security_context: Option<PodSecurityContext>,
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
    #[serde(default)]
    pub(crate) working_dir: Option<String>,
    #[serde(default)]
    pub(crate) image_pull_policy: Option<String>,
    #[serde(default)]
    pub(crate) resources: Option<ResourceRequirements>,
    #[serde(default)]
    pub(crate) liveness_probe: Option<Probe>,
    #[serde(default)]
    pub(crate) readiness_probe: Option<Probe>,
}

#[derive(serde::Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PodSecurityContext {
    pub(crate) run_as_user: Option<u32>,
    pub(crate) run_as_group: Option<u32>,
    pub(crate) run_as_non_root: Option<bool>,
}

#[derive(serde::Deserialize, Debug, Default)]
pub(crate) struct ResourceRequirements {
    #[serde(default)]
    pub(crate) limits: Option<ResourceList>,
    #[serde(default)]
    pub(crate) requests: Option<ResourceList>,
}

#[derive(serde::Deserialize, Debug, Default)]
pub(crate) struct ResourceList {
    pub(crate) memory: Option<String>,
    pub(crate) cpu: Option<String>,
}

#[derive(serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Probe {
    pub(crate) exec: Option<ExecAction>,
    #[serde(default)]
    pub(crate) initial_delay_seconds: Option<u32>,
    #[serde(default)]
    pub(crate) period_seconds: Option<u32>,
    #[serde(default)]
    #[allow(dead_code)]
    pub(crate) timeout_seconds: Option<u32>,
    #[serde(default)]
    pub(crate) failure_threshold: Option<u32>,
}

#[derive(serde::Deserialize, Debug)]
pub(crate) struct ExecAction {
    pub(crate) command: Vec<String>,
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
    pub(crate) init_containers: Vec<KubeContainer>,
    pub(crate) volumes: Vec<KubeVolume>,
    pub(crate) restart_policy: String,
    /// Aggregated ports from all containers.
    pub(crate) ports: Vec<ContainerPort>,
    /// Host-path binds needed at nspawn level.
    pub(crate) host_binds: Vec<(String, String)>,
    pub(crate) termination_grace_period: Option<u32>,
    pub(crate) run_as_user: Option<u32>,
    pub(crate) run_as_group: Option<u32>,
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
    pub(crate) working_dir_override: Option<String>,
    pub(crate) image_pull_policy: String,
    pub(crate) resource_lines: Vec<String>,
    pub(crate) readiness_exec: Option<String>,
    /// Parsed but not yet enforced at runtime (future: watchdog integration).
    #[allow(dead_code)]
    pub(crate) liveness_probe: Option<Probe>,
}

#[derive(Debug)]
pub(crate) struct KubeVolumeMount {
    pub(crate) volume_name: String,
    pub(crate) mount_path: String,
    // TODO: enforce read-only volume mounts (symlinks can't be read-only;
    // may need BindReadOnlyPaths or mount options in the future).
    #[allow(dead_code)]
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

// --- Known fields for unknown-field warnings ---

const KNOWN_POD_SPEC_FIELDS: &[&str] = &[
    "containers",
    "initContainers",
    "volumes",
    "restartPolicy",
    "terminationGracePeriodSeconds",
    "securityContext",
];

const KNOWN_CONTAINER_FIELDS: &[&str] = &[
    "name",
    "image",
    "command",
    "args",
    "env",
    "ports",
    "volumeMounts",
    "workingDir",
    "imagePullPolicy",
    "resources",
    "livenessProbe",
    "readinessProbe",
];

const KNOWN_SECURITY_CONTEXT_FIELDS: &[&str] = &["runAsUser", "runAsGroup", "runAsNonRoot"];

/// Walk raw YAML and warn about unrecognized fields.
fn warn_unknown_fields(raw: &serde_yml::Value, path: &str, known: &[&str]) {
    if let serde_yml::Value::Mapping(map) = raw {
        for (key, _val) in map {
            if let serde_yml::Value::String(k) = key {
                if !known.contains(&k.as_str()) {
                    eprintln!("warning: unknown field '{path}.{k}' will be ignored");
                }
            }
        }
    }
}

/// Warn about unknown fields in a pod spec value tree.
fn warn_pod_spec_unknown_fields(spec_value: &serde_yml::Value) {
    warn_unknown_fields(spec_value, "spec", KNOWN_POD_SPEC_FIELDS);

    if let serde_yml::Value::Mapping(map) = spec_value {
        // Check securityContext fields.
        if let Some(sc) = map.get(serde_yml::Value::String("securityContext".into())) {
            warn_unknown_fields(sc, "spec.securityContext", KNOWN_SECURITY_CONTEXT_FIELDS);
        }

        // Check container fields.
        for list_key in ["containers", "initContainers"] {
            if let Some(serde_yml::Value::Sequence(containers)) =
                map.get(serde_yml::Value::String(list_key.into()))
            {
                for (i, c) in containers.iter().enumerate() {
                    let fallback = format!("{i}");
                    let cname = c
                        .as_mapping()
                        .and_then(|m| m.get(serde_yml::Value::String("name".into())))
                        .and_then(|v| v.as_str())
                        .unwrap_or(&fallback);
                    warn_unknown_fields(
                        c,
                        &format!("spec.{list_key}[{cname}]"),
                        KNOWN_CONTAINER_FIELDS,
                    );
                }
            }
        }
    }
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
            let spec_value = manifest.spec.context("Pod manifest missing 'spec' field")?;
            warn_pod_spec_unknown_fields(&spec_value);
            let spec: PodSpec =
                serde_yml::from_value(spec_value).context("failed to parse Pod spec")?;
            Ok((name, spec))
        }
        "Deployment" => {
            let spec_value = manifest
                .spec
                .context("Deployment manifest missing 'spec' field")?;
            // For deployments, warn on the template spec inside.
            if let serde_yml::Value::Mapping(ref map) = spec_value {
                if let Some(template) = map.get(serde_yml::Value::String("template".into())) {
                    if let serde_yml::Value::Mapping(ref tmap) = template {
                        if let Some(tspec) = tmap.get(serde_yml::Value::String("spec".into())) {
                            warn_pod_spec_unknown_fields(tspec);
                        }
                    }
                }
            }
            let deploy_spec: DeploymentSpec =
                serde_yml::from_value(spec_value).context("failed to parse Deployment spec")?;
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

/// Parse a K8s memory string (e.g. "128Mi", "1Gi", "1000") to a systemd-compatible string.
fn parse_k8s_memory(s: &str) -> Result<String> {
    for (suffix, unit) in [("Ki", "K"), ("Mi", "M"), ("Gi", "G"), ("Ti", "T")] {
        if let Some(num) = s.strip_suffix(suffix) {
            if num.is_empty() || !num.chars().all(|c| c.is_ascii_digit()) {
                bail!("invalid memory value: {s}");
            }
            return Ok(format!("{num}{unit}"));
        }
    }
    if !s.is_empty() && s.chars().all(|c| c.is_ascii_digit()) {
        // Plain bytes.
        Ok(s.to_string())
    } else {
        bail!("unsupported memory format: {s}")
    }
}

/// Parse a K8s CPU string (e.g. "500m", "2") to a CPUQuota percentage.
fn parse_k8s_cpu_quota(s: &str) -> Result<u32> {
    if s.ends_with('m') {
        let millis: u32 = s[..s.len() - 1]
            .parse()
            .with_context(|| format!("invalid CPU millicore value: {s}"))?;
        Ok(millis / 10) // 1000m = 100%
    } else {
        let cores: f64 = s
            .parse()
            .with_context(|| format!("invalid CPU value: {s}"))?;
        Ok((cores * 100.0) as u32)
    }
}

/// Parse a K8s CPU request to a systemd CPUWeight (1-10000).
fn parse_k8s_cpu_weight(s: &str) -> Result<u32> {
    let millis = if s.ends_with('m') {
        s[..s.len() - 1]
            .parse::<u32>()
            .with_context(|| format!("invalid CPU millicore value: {s}"))?
    } else {
        let cores: f64 = s
            .parse()
            .with_context(|| format!("invalid CPU value: {s}"))?;
        (cores * 1000.0) as u32
    };
    // Map millicores to weight: 100m = 100 (default), scale linearly, clamp to 1-10000.
    Ok(millis.clamp(1, 10000))
}

/// Build resource directive lines from a container's resources spec.
fn build_resource_lines(resources: &ResourceRequirements) -> Result<Vec<String>> {
    let mut lines = Vec::new();
    if let Some(ref limits) = resources.limits {
        if let Some(ref mem) = limits.memory {
            let val = parse_k8s_memory(mem)?;
            lines.push(format!("MemoryMax={val}"));
        }
        if let Some(ref cpu) = limits.cpu {
            let pct = parse_k8s_cpu_quota(cpu)?;
            lines.push(format!("CPUQuota={pct}%"));
        }
    }
    if let Some(ref requests) = resources.requests {
        if let Some(ref mem) = requests.memory {
            let val = parse_k8s_memory(mem)?;
            lines.push(format!("MemoryLow={val}"));
        }
        if let Some(ref cpu) = requests.cpu {
            let weight = parse_k8s_cpu_weight(cpu)?;
            lines.push(format!("CPUWeight={weight}"));
        }
    }
    Ok(lines)
}

/// Build a readiness check ExecStartPost command from a readiness probe.
fn build_readiness_exec(probe: &Probe) -> Result<String> {
    let exec = probe
        .exec
        .as_ref()
        .context("only exec readiness probes are supported")?;
    if exec.command.is_empty() {
        bail!("readiness probe exec command is empty");
    }
    let initial_delay = probe.initial_delay_seconds.unwrap_or(0);
    let period = probe.period_seconds.unwrap_or(10);
    let threshold = probe.failure_threshold.unwrap_or(3);
    let cmd = shell_join(&exec.command);
    // The `-` prefix means systemd won't fail the unit if the check fails.
    Ok(format!(
        "-/bin/sh -c 'sleep {initial_delay}; for i in $(seq 1 {threshold}); do if {cmd}; then exit 0; fi; sleep {period}; done; exit 1'"
    ))
}

/// Validate a container and build a KubeContainer plan entry.
fn validate_container(c: Container) -> Result<KubeContainer> {
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

    // Validate imagePullPolicy.
    let image_pull_policy = match c.image_pull_policy.as_deref() {
        None | Some("Always") => "Always".to_string(),
        Some("IfNotPresent") => "IfNotPresent".to_string(),
        Some("Never") => "Never".to_string(),
        Some(other) => bail!(
            "container '{}': unsupported imagePullPolicy: {other}",
            c.name
        ),
    };

    // Validate workingDir.
    if let Some(ref wd) = c.working_dir {
        if !wd.starts_with('/') {
            bail!("container '{}': workingDir must be absolute: {wd}", c.name);
        }
        if wd.contains("..") {
            bail!(
                "container '{}': workingDir must not contain '..': {wd}",
                c.name
            );
        }
    }

    // Build resource lines.
    let resource_lines = if let Some(ref res) = c.resources {
        build_resource_lines(res)
            .with_context(|| format!("container '{}': invalid resources", c.name))?
    } else {
        Vec::new()
    };

    // Validate probes.
    if let Some(ref probe) = c.liveness_probe {
        if probe.exec.is_none() {
            bail!(
                "container '{}': only exec liveness probes are supported (httpGet/tcpSocket are not implemented)",
                c.name
            );
        }
    }
    let readiness_exec = if let Some(ref probe) = c.readiness_probe {
        Some(
            build_readiness_exec(probe)
                .with_context(|| format!("container '{}': invalid readiness probe", c.name))?,
        )
    } else {
        None
    };

    Ok(KubeContainer {
        name: c.name,
        image: c.image,
        image_ref,
        command_override: c.command,
        args_override: c.args,
        env,
        volume_mounts,
        working_dir_override: c.working_dir,
        image_pull_policy,
        resource_lines,
        readiness_exec,
        liveness_probe: c.liveness_probe,
    })
}

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

    // Validate container names are unique and valid (across both init and regular).
    let mut seen_names = HashSet::new();
    for c in spec.init_containers.iter().chain(spec.containers.iter()) {
        validate_name(&c.name).with_context(|| format!("invalid container name: {}", c.name))?;
        if !seen_names.insert(&c.name) {
            bail!("duplicate container name: {}", c.name);
        }
        if c.image.is_empty() {
            bail!("container '{}' has empty image", c.name);
        }
    }

    // Validate terminationGracePeriodSeconds.
    if let Some(t) = spec.termination_grace_period_seconds {
        if t == 0 {
            bail!("terminationGracePeriodSeconds must be > 0");
        }
    }

    // Validate securityContext.
    let (run_as_user, run_as_group) = if let Some(ref sc) = spec.security_context {
        if sc.run_as_non_root == Some(true) && sc.run_as_user.is_none() {
            bail!("securityContext.runAsNonRoot is true but runAsUser is not set");
        }
        if sc.run_as_non_root == Some(true) && sc.run_as_user == Some(0) {
            bail!("securityContext.runAsNonRoot is true but runAsUser is 0 (root)");
        }
        (sc.run_as_user, sc.run_as_group)
    } else {
        (None, None)
    };

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

    // Validate volume mount references (across both init and regular containers).
    for c in spec.init_containers.iter().chain(spec.containers.iter()) {
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

    // Collect nspawn --bind= arguments for hostPath volumes only.
    // emptyDir volumes live inside the rootfs at /oci/volumes/{name} and are
    // bind-mounted to each app's root via sdme-kube-volumes.service.
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

    // Build init container plans.
    let init_containers: Vec<KubeContainer> = spec
        .init_containers
        .into_iter()
        .map(validate_container)
        .collect::<Result<Vec<_>>>()?;

    // Build container plans.
    let containers: Vec<KubeContainer> = spec
        .containers
        .into_iter()
        .map(validate_container)
        .collect::<Result<Vec<_>>>()?;

    Ok(KubePlan {
        pod_name: pod_name.to_string(),
        containers,
        init_containers,
        volumes,
        restart_policy,
        ports,
        host_binds,
        termination_grace_period: spec.termination_grace_period_seconds,
        run_as_user,
        run_as_group,
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
    docker_credentials: Option<(&str, &str)>,
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

    // Collect init container names for dependency ordering.
    let init_container_names: Vec<String> = plan
        .init_containers
        .iter()
        .map(|c| c.name.clone())
        .collect();

    // Process init containers first, then regular containers.
    let all_containers: Vec<(&KubeContainer, bool)> = plan
        .init_containers
        .iter()
        .map(|c| (c, true))
        .chain(plan.containers.iter().map(|c| (c, false)))
        .collect();

    for (kc, is_init) in &all_containers {
        check_interrupted()?;

        let app_dir = apps_dir.join(&kc.name);
        let app_root = app_dir.join("root");
        fs::create_dir_all(&app_root)
            .with_context(|| format!("failed to create {}", app_root.display()))?;

        // Check imagePullPolicy before pulling.
        let should_pull = match kc.image_pull_policy.as_str() {
            "Never" => {
                eprintln!(
                    "skipping image pull for '{}' (imagePullPolicy: Never)",
                    kc.name
                );
                false
            }
            "IfNotPresent" => {
                let has_content = app_root
                    .read_dir()
                    .map_or(false, |mut d| d.next().is_some());
                if has_content {
                    eprintln!(
                        "skipping image pull for '{}' (imagePullPolicy: IfNotPresent, app root not empty)",
                        kc.name
                    );
                    false
                } else {
                    true
                }
            }
            _ => true, // "Always" or default
        };

        // Pull the image.
        let oci_config = if should_pull {
            crate::import::registry::import_registry_image(
                &kc.image_ref,
                &app_root,
                &rootfs_dir,
                docker_credentials,
                verbose,
            )
            .with_context(|| format!("failed to pull image for container '{}'", kc.name))?
        } else {
            None
        };

        // Set up the app.
        setup_kube_container(
            &staging_dir,
            &app_dir,
            kc,
            oci_config.as_ref(),
            &plan.restart_policy,
            &plan.volumes,
            &plan,
            *is_init,
            &init_container_names,
            verbose,
        )
        .with_context(|| format!("failed to set up container '{}'", kc.name))?;
    }

    // 4. Generate sdme-kube-volumes.service for shared volume mounts.
    //
    // This oneshot service runs `mount --bind` in the container's PID 1 mount
    // namespace so all OCI app services see the same shared directories.
    let has_volume_mounts = plan
        .containers
        .iter()
        .any(|kc| !kc.volume_mounts.is_empty());
    if has_volume_mounts {
        let mut exec_lines = Vec::new();
        for kc in &plan.containers {
            for vm in &kc.volume_mounts {
                let src = format!("/oci/volumes/{}", vm.volume_name);
                let dst = format!("/oci/apps/{}/root{}", kc.name, vm.mount_path);
                exec_lines.push(format!("ExecStart=/bin/mount --bind {src} {dst}"));
                if vm.read_only {
                    exec_lines.push(format!("ExecStart=/bin/mount -o remount,ro,bind {dst}"));
                }
            }
        }
        let vol_unit = format!(
            "\
# Generated by sdme kube
[Unit]
Description=Kube volume mounts
DefaultDependencies=no
After=local-fs.target

[Service]
Type=oneshot
RemainAfterExit=yes
{}

[Install]
WantedBy=multi-user.target
",
            exec_lines.join("\n")
        );
        let vol_unit_path = unit_dir.join("sdme-kube-volumes.service");
        fs::write(&vol_unit_path, &vol_unit)
            .with_context(|| format!("failed to write {}", vol_unit_path.display()))?;
        // Enable via symlink.
        let symlink_path = wants_dir.join("sdme-kube-volumes.service");
        std::os::unix::fs::symlink(
            "/etc/systemd/system/sdme-kube-volumes.service",
            &symlink_path,
        )
        .with_context(|| format!("failed to symlink {}", symlink_path.display()))?;
    }

    // 5. Atomic rename.
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

    let container_names: Vec<&str> = plan
        .init_containers
        .iter()
        .chain(plan.containers.iter())
        .map(|c| c.name.as_str())
        .collect();

    // Build bind mounts for hostPath volumes only.
    let bind_strings: Vec<String> = plan
        .host_binds
        .iter()
        .map(|(host_path, container_path)| format!("{host_path}:{container_path}:rw"))
        .collect();
    let binds = crate::BindConfig {
        binds: bind_strings,
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
/// Builds the K8s command/args overrides, merges env vars, constructs volume
/// bind paths, then delegates to `setup_oci_app()` for the common logic.
fn setup_kube_container(
    staging_dir: &Path,
    app_dir: &Path,
    kc: &KubeContainer,
    oci_config: Option<&OciContainerConfig>,
    restart_policy: &str,
    _volumes: &[KubeVolume],
    plan: &KubePlan,
    is_init: bool,
    init_container_names: &[String],
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

    // Use workingDir override from YAML, then OCI config, then "/".
    let working_dir = kc
        .working_dir_override
        .as_deref()
        .or(config.working_dir.as_deref())
        .unwrap_or("/");

    // Use pod-level securityContext user override, then OCI config, then "root".
    let user_override;
    let user = if let Some(uid) = plan.run_as_user {
        let gid = plan.run_as_group.unwrap_or(uid);
        user_override = format!("{uid}:{gid}");
        &user_override
    } else {
        config.user.as_deref().unwrap_or("root")
    };

    // Merge env: OCI image env + K8s env overrides (by key).
    let mut env_lines: Vec<String> = Vec::new();
    if let Some(ref image_env) = config.env {
        env_lines.extend(image_env.iter().cloned());
    }
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

    // Create mount point directories inside the app root (needed as bind targets
    // for sdme-kube-volumes.service).
    for vm in &kc.volume_mounts {
        let mount_dir = app_root.join(vm.mount_path.trim_start_matches('/'));
        fs::create_dir_all(&mount_dir)
            .with_context(|| format!("failed to create mount point {}", mount_dir.display()))?;
    }

    // If there are volume mounts, add ordering dependency on the volume mount service.
    let extra_after = if kc.volume_mounts.is_empty() {
        vec![]
    } else {
        vec!["sdme-kube-volumes.service".to_string()]
    };

    // Build unit ordering dependencies for regular containers:
    // they depend on all init containers.
    let (after_units, requires_units) = if !is_init && !init_container_names.is_empty() {
        let after: Vec<String> = init_container_names
            .iter()
            .map(|n| format!("sdme-oci-{n}.service"))
            .collect();
        (after.clone(), after)
    } else {
        (Vec::new(), Vec::new())
    };

    crate::import::setup_oci_app(&crate::import::OciAppSetup {
        name: &kc.name,
        staging_dir,
        app_dir,
        app_root: &app_root,
        exec_start: &exec_start,
        working_dir,
        user,
        env_lines,
        config,
        image_ref: &kc.image,
        restart_policy: Some(restart_policy),
        bind_paths: vec![],
        extra_after,
        verbose,
        timeout_stop_sec: plan.termination_grace_period,
        resource_lines: kc.resource_lines.clone(),
        unit_type: if is_init { Some("oneshot") } else { None },
        remain_after_exit: is_init,
        after_units,
        requires_units,
        readiness_exec: kc.readiness_exec.clone(),
    })
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

    // --- Feature 1: Unknown fields ---

    #[test]
    fn test_unknown_fields_parse_ok() {
        // Unknown fields should not cause parse errors.
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: warn-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    livenessProbe:
      exec:
        command: ["true"]
    securityContext:
      runAsUser: 1000
    unknownField: "hello"
"#;
        let result = parse_yaml(yaml);
        assert!(result.is_ok(), "parse should succeed with unknown fields");
    }

    // --- Feature 2: imagePullPolicy ---

    #[test]
    fn test_image_pull_policy_parse() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: pull-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    imagePullPolicy: IfNotPresent
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();
        assert_eq!(plan.containers[0].image_pull_policy, "IfNotPresent");
    }

    #[test]
    fn test_image_pull_policy_default() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: pull-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();
        assert_eq!(plan.containers[0].image_pull_policy, "Always");
    }

    #[test]
    fn test_image_pull_policy_invalid() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: pull-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    imagePullPolicy: Bogus
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let err = validate_and_plan(&name, spec).unwrap_err();
        assert!(err.to_string().contains("unsupported imagePullPolicy"));
    }

    // --- Feature 3: terminationGracePeriodSeconds ---

    #[test]
    fn test_termination_grace_period() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: grace-pod
spec:
  terminationGracePeriodSeconds: 45
  containers:
  - name: app
    image: docker.io/busybox:latest
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();
        assert_eq!(plan.termination_grace_period, Some(45));
    }

    #[test]
    fn test_termination_grace_period_zero() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: grace-pod
spec:
  terminationGracePeriodSeconds: 0
  containers:
  - name: app
    image: docker.io/busybox:latest
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let err = validate_and_plan(&name, spec).unwrap_err();
        assert!(err.to_string().contains("must be > 0"));
    }

    // --- Feature 4: workingDir ---

    #[test]
    fn test_working_dir() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: wd-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    workingDir: /app
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();
        assert_eq!(
            plan.containers[0].working_dir_override,
            Some("/app".to_string())
        );
    }

    #[test]
    fn test_working_dir_relative_rejected() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: wd-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    workingDir: relative/path
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let err = validate_and_plan(&name, spec).unwrap_err();
        assert!(err.to_string().contains("workingDir must be absolute"));
    }

    #[test]
    fn test_working_dir_dotdot_rejected() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: wd-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    workingDir: /app/../etc
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let err = validate_and_plan(&name, spec).unwrap_err();
        assert!(err.to_string().contains("must not contain '..'"));
    }

    // --- Feature 5: resources ---

    #[test]
    fn test_resource_limits_memory() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: res-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    resources:
      limits:
        memory: 256Mi
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();
        assert!(plan.containers[0]
            .resource_lines
            .contains(&"MemoryMax=256M".to_string()));
    }

    #[test]
    fn test_resource_limits_cpu() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: res-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    resources:
      limits:
        cpu: "2"
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();
        assert!(plan.containers[0]
            .resource_lines
            .contains(&"CPUQuota=200%".to_string()));
    }

    #[test]
    fn test_resource_limits_cpu_millicore() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: res-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    resources:
      limits:
        cpu: 500m
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();
        assert!(plan.containers[0]
            .resource_lines
            .contains(&"CPUQuota=50%".to_string()));
    }

    #[test]
    fn test_resource_requests() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: res-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    resources:
      requests:
        memory: 128Mi
        cpu: 250m
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();
        assert!(plan.containers[0]
            .resource_lines
            .contains(&"MemoryLow=128M".to_string()));
        assert!(plan.containers[0]
            .resource_lines
            .contains(&"CPUWeight=250".to_string()));
    }

    #[test]
    fn test_parse_k8s_memory_formats() {
        assert_eq!(parse_k8s_memory("128Ki").unwrap(), "128K");
        assert_eq!(parse_k8s_memory("256Mi").unwrap(), "256M");
        assert_eq!(parse_k8s_memory("1Gi").unwrap(), "1G");
        assert_eq!(parse_k8s_memory("2Ti").unwrap(), "2T");
        assert_eq!(parse_k8s_memory("1048576").unwrap(), "1048576");
        assert!(parse_k8s_memory("10MB").is_err());
    }

    #[test]
    fn test_parse_k8s_cpu_quota() {
        assert_eq!(parse_k8s_cpu_quota("1000m").unwrap(), 100);
        assert_eq!(parse_k8s_cpu_quota("500m").unwrap(), 50);
        assert_eq!(parse_k8s_cpu_quota("250m").unwrap(), 25);
        assert_eq!(parse_k8s_cpu_quota("2").unwrap(), 200);
        assert_eq!(parse_k8s_cpu_quota("0.5").unwrap(), 50);
    }

    // --- Feature 6: securityContext ---

    #[test]
    fn test_security_context_run_as_user() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: sec-pod
spec:
  securityContext:
    runAsUser: 1000
    runAsGroup: 1000
  containers:
  - name: app
    image: docker.io/busybox:latest
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();
        assert_eq!(plan.run_as_user, Some(1000));
        assert_eq!(plan.run_as_group, Some(1000));
    }

    #[test]
    fn test_security_context_run_as_non_root_without_user() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: sec-pod
spec:
  securityContext:
    runAsNonRoot: true
  containers:
  - name: app
    image: docker.io/busybox:latest
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let err = validate_and_plan(&name, spec).unwrap_err();
        assert!(err.to_string().contains("runAsNonRoot is true"));
    }

    #[test]
    fn test_security_context_run_as_non_root_with_root_user() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: sec-pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 0
  containers:
  - name: app
    image: docker.io/busybox:latest
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let err = validate_and_plan(&name, spec).unwrap_err();
        assert!(err.to_string().contains("runAsUser is 0"));
    }

    // --- Feature 7: initContainers ---

    #[test]
    fn test_init_containers() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: init-pod
spec:
  initContainers:
  - name: init-setup
    image: docker.io/busybox:latest
    command: ["/bin/sh", "-c"]
    args: ["echo init"]
  containers:
  - name: app
    image: docker.io/nginx:latest
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        assert_eq!(spec.init_containers.len(), 1);
        assert_eq!(spec.init_containers[0].name, "init-setup");
        let plan = validate_and_plan(&name, spec).unwrap();
        assert_eq!(plan.init_containers.len(), 1);
        assert_eq!(plan.init_containers[0].name, "init-setup");
        assert_eq!(plan.containers.len(), 1);
        assert_eq!(plan.containers[0].name, "app");
    }

    #[test]
    fn test_init_container_duplicate_name() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: init-pod
spec:
  initContainers:
  - name: app
    image: docker.io/busybox:latest
  containers:
  - name: app
    image: docker.io/nginx:latest
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let err = validate_and_plan(&name, spec).unwrap_err();
        assert!(err.to_string().contains("duplicate container name"));
    }

    // --- Feature 8: Probes ---

    #[test]
    fn test_readiness_probe_exec() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: probe-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    readinessProbe:
      exec:
        command: ["/bin/sh", "-c", "test -f /tmp/ready"]
      initialDelaySeconds: 5
      periodSeconds: 3
      failureThreshold: 5
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();
        let exec = plan.containers[0].readiness_exec.as_ref().unwrap();
        assert!(exec.contains("sleep 5"));
        assert!(exec.contains("seq 1 5"));
        assert!(exec.contains("sleep 3"));
        assert!(exec.contains("test -f /tmp/ready"));
    }

    #[test]
    fn test_liveness_probe_non_exec_rejected() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: probe-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    livenessProbe:
      initialDelaySeconds: 5
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let err = validate_and_plan(&name, spec).unwrap_err();
        assert!(err.to_string().contains("only exec liveness probes"));
    }

    #[test]
    fn test_liveness_probe_exec_ok() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: probe-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    livenessProbe:
      exec:
        command: ["true"]
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();
        assert!(plan.containers[0].liveness_probe.is_some());
    }

    // --- Combined feature test ---

    #[test]
    fn test_all_features_combined() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: full-pod
spec:
  terminationGracePeriodSeconds: 30
  securityContext:
    runAsUser: 1000
    runAsGroup: 1000
  initContainers:
  - name: init-setup
    image: docker.io/busybox:latest
    command: ["/bin/sh", "-c"]
    args: ["echo init"]
  containers:
  - name: app
    image: docker.io/busybox:latest
    workingDir: /app
    imagePullPolicy: IfNotPresent
    resources:
      limits:
        memory: 256Mi
        cpu: "1"
      requests:
        memory: 128Mi
        cpu: 250m
    readinessProbe:
      exec:
        command: ["/bin/sh", "-c", "test -f /tmp/ready"]
    volumeMounts:
    - name: shared
      mountPath: /data
  volumes:
  - name: shared
    emptyDir: {}
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();

        assert_eq!(plan.termination_grace_period, Some(30));
        assert_eq!(plan.run_as_user, Some(1000));
        assert_eq!(plan.run_as_group, Some(1000));
        assert_eq!(plan.init_containers.len(), 1);
        assert_eq!(plan.containers.len(), 1);

        let app = &plan.containers[0];
        assert_eq!(app.working_dir_override, Some("/app".to_string()));
        assert_eq!(app.image_pull_policy, "IfNotPresent");
        assert!(app.resource_lines.contains(&"MemoryMax=256M".to_string()));
        assert!(app.resource_lines.contains(&"CPUQuota=100%".to_string()));
        assert!(app.resource_lines.contains(&"MemoryLow=128M".to_string()));
        assert!(app.resource_lines.contains(&"CPUWeight=250".to_string()));
        assert!(app.readiness_exec.is_some());
    }

    // --- Unit file integration tests ---
    //
    // These tests call `setup_kube_container()` with a temp directory and
    // verify the generated systemd unit file contains correct directives.

    use crate::testutil::TempDataDir;
    use std::sync::Mutex;

    static UNIT_TEST_LOCK: Mutex<()> = Mutex::new(());

    /// Helper: set up a temp dir, call `setup_kube_container()`, return the
    /// generated unit file content.
    fn setup_test_container(
        name: &str,
        kc: &KubeContainer,
        plan: &KubePlan,
        is_init: bool,
        init_container_names: &[String],
    ) -> String {
        let tmp = TempDataDir::new("kube-unit");
        let staging = tmp.path().join("staging");
        let app_dir = staging.join(format!("oci/apps/{name}"));
        let app_root = app_dir.join("root");
        fs::create_dir_all(&app_root).unwrap();
        fs::create_dir_all(staging.join("etc/systemd/system/multi-user.target.wants")).unwrap();

        setup_kube_container(
            &staging,
            &app_dir,
            kc,
            None,
            &plan.restart_policy,
            &plan.volumes,
            plan,
            is_init,
            init_container_names,
            false,
        )
        .unwrap();

        let unit_path = staging.join(format!("etc/systemd/system/sdme-oci-{name}.service"));
        fs::read_to_string(&unit_path).unwrap()
    }

    fn make_test_container(name: &str) -> KubeContainer {
        KubeContainer {
            name: name.to_string(),
            image: "docker.io/busybox:latest".to_string(),
            image_ref: ImageReference::parse("docker.io/busybox:latest").unwrap(),
            command_override: Some(vec!["/bin/sh".to_string(), "-c".to_string()]),
            args_override: Some(vec!["echo hello".to_string()]),
            env: vec![],
            volume_mounts: vec![],
            working_dir_override: None,
            image_pull_policy: "Always".to_string(),
            resource_lines: vec![],
            readiness_exec: None,
            liveness_probe: None,
        }
    }

    fn make_test_plan() -> KubePlan {
        KubePlan {
            pod_name: "test-pod".to_string(),
            containers: vec![],
            init_containers: vec![],
            volumes: vec![],
            restart_policy: "always".to_string(),
            ports: vec![],
            host_binds: vec![],
            termination_grace_period: None,
            run_as_user: None,
            run_as_group: None,
        }
    }

    #[test]
    fn test_unit_default_container() {
        let _lock = UNIT_TEST_LOCK.lock().unwrap();
        let kc = make_test_container("app");
        let plan = make_test_plan();
        let unit = setup_test_container("app", &kc, &plan, false, &[]);

        assert!(unit.contains("Type=exec"), "default type should be exec");
        assert!(
            unit.contains("Restart=always"),
            "should have restart policy"
        );
        assert!(
            !unit.contains("RemainAfterExit"),
            "should not have RemainAfterExit"
        );
        assert!(
            !unit.contains("TimeoutStopSec"),
            "should not have TimeoutStopSec"
        );
        assert!(
            unit.contains("After=network.target\n"),
            "should have After=network.target only"
        );
        assert!(
            !unit.contains("Requires="),
            "should not have Requires= line"
        );
    }

    #[test]
    fn test_unit_init_container_type() {
        let _lock = UNIT_TEST_LOCK.lock().unwrap();
        let kc = make_test_container("init-setup");
        let plan = make_test_plan();
        let unit = setup_test_container("init-setup", &kc, &plan, true, &[]);

        assert!(
            unit.contains("Type=oneshot"),
            "init container should be oneshot"
        );
        assert!(
            unit.contains("RemainAfterExit=yes"),
            "init container should have RemainAfterExit"
        );
        assert!(
            !unit.contains("Restart="),
            "oneshot init container should not have Restart="
        );
    }

    #[test]
    fn test_unit_main_container_deps() {
        let _lock = UNIT_TEST_LOCK.lock().unwrap();
        let kc = make_test_container("app");
        let plan = make_test_plan();
        let init_names = vec!["init-setup".to_string()];
        let unit = setup_test_container("app", &kc, &plan, false, &init_names);

        assert!(
            unit.contains("After=network.target sdme-oci-init-setup.service"),
            "should depend on init container, got: {unit}"
        );
        assert!(
            unit.contains("Requires=sdme-oci-init-setup.service"),
            "should require init container"
        );
    }

    #[test]
    fn test_unit_termination_grace_period() {
        let _lock = UNIT_TEST_LOCK.lock().unwrap();
        let kc = make_test_container("app");
        let mut plan = make_test_plan();
        plan.termination_grace_period = Some(45);
        let unit = setup_test_container("app", &kc, &plan, false, &[]);

        assert!(
            unit.contains("TimeoutStopSec=45s"),
            "should have TimeoutStopSec=45s"
        );
    }

    #[test]
    fn test_unit_working_dir_override() {
        let _lock = UNIT_TEST_LOCK.lock().unwrap();
        let mut kc = make_test_container("app");
        kc.working_dir_override = Some("/app".to_string());
        let plan = make_test_plan();
        let unit = setup_test_container("app", &kc, &plan, false, &[]);

        assert!(
            unit.contains("WorkingDirectory=/app"),
            "should have WorkingDirectory=/app"
        );
    }

    #[test]
    fn test_unit_resources() {
        let _lock = UNIT_TEST_LOCK.lock().unwrap();
        let mut kc = make_test_container("app");
        kc.resource_lines = vec!["MemoryMax=256M".to_string(), "CPUQuota=100%".to_string()];
        let plan = make_test_plan();
        let unit = setup_test_container("app", &kc, &plan, false, &[]);

        assert!(unit.contains("MemoryMax=256M"), "should have MemoryMax");
        assert!(unit.contains("CPUQuota=100%"), "should have CPUQuota");
    }

    #[test]
    fn test_unit_readiness_probe() {
        let _lock = UNIT_TEST_LOCK.lock().unwrap();
        let mut kc = make_test_container("app");
        kc.readiness_exec = Some("/bin/sh -c 'test -f /tmp/ready'".to_string());
        let plan = make_test_plan();
        let unit = setup_test_container("app", &kc, &plan, false, &[]);

        assert!(
            unit.contains("ExecStartPost=/bin/sh -c 'test -f /tmp/ready'"),
            "should have ExecStartPost for readiness probe"
        );
    }

    #[test]
    fn test_unit_security_context_user() {
        let _lock = UNIT_TEST_LOCK.lock().unwrap();
        let kc = make_test_container("app");
        let mut plan = make_test_plan();
        plan.run_as_user = Some(1000);
        plan.run_as_group = Some(1000);

        // setup_kube_container passes "1000:1000" as user, which
        // resolve_oci_user() resolves as numeric UID:GID, deploying
        // drop_privs. We need etc/passwd for name lookups but numeric
        // UIDs work without it.
        let tmp = TempDataDir::new("kube-unit-sec");
        let staging = tmp.path().join("staging");
        let app_dir = staging.join("oci/apps/app");
        let app_root = app_dir.join("root");
        fs::create_dir_all(&app_root).unwrap();
        fs::create_dir_all(staging.join("etc/systemd/system/multi-user.target.wants")).unwrap();

        setup_kube_container(
            &staging,
            &app_dir,
            &kc,
            None,
            &plan.restart_policy,
            &plan.volumes,
            &plan,
            false,
            &[],
            false,
        )
        .unwrap();

        let unit_path = staging.join("etc/systemd/system/sdme-oci-app.service");
        let unit = fs::read_to_string(&unit_path).unwrap();

        // Non-root user: should use drop_privs with uid/gid.
        assert!(
            unit.contains("/.sdme-drop-privs 1000 1000"),
            "should use drop_privs with uid=1000 gid=1000, got: {unit}"
        );
        // drop_privs binary should be deployed.
        assert!(app_root.join(".sdme-drop-privs").is_file());
    }
}
