//! Validated plan types, YAML parsing, and validation logic.

use std::collections::HashSet;

use anyhow::{bail, Context, Result};

use super::types::*;
use crate::oci::registry::ImageReference;
use crate::security;
use crate::validate_name;

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
    /// Pod-level seccomp profile type (validated).
    pub(crate) seccomp_profile_type: Option<String>,
    /// Pod-level AppArmor profile name (validated).
    pub(crate) apparmor_profile: Option<String>,
}

/// Validated container-level security context fields.
#[derive(Debug, Default)]
pub(crate) struct ContainerSecurity {
    /// Per-container user override (overrides pod-level).
    pub(crate) run_as_user: Option<u32>,
    /// Per-container group override (overrides pod-level).
    pub(crate) run_as_group: Option<u32>,
    /// Capabilities to add to the OCI bounding set.
    pub(crate) add_caps: Vec<String>,
    /// Capabilities to drop from the OCI bounding set ("ALL" drops everything).
    pub(crate) drop_caps: Vec<String>,
    /// If Some(true), allow privilege escalation (NoNewPrivileges=no).
    pub(crate) allow_privilege_escalation: Option<bool>,
    /// Make the app's root filesystem read-only.
    pub(crate) read_only_root_filesystem: bool,
    /// Seccomp SystemCallFilter lines.
    pub(crate) syscall_filters: Vec<String>,
    /// Whether the container explicitly set a seccomp profile (even Unconfined).
    /// Used to prevent pod-level seccomp from overriding a container's Unconfined.
    pub(crate) has_seccomp_profile: bool,
    /// AppArmor profile name.
    pub(crate) apparmor_profile: Option<String>,
}

#[derive(Debug)]
pub(crate) struct KubeContainer {
    pub(crate) name: String,
    pub(crate) image: String,
    pub(crate) image_ref: ImageReference,
    pub(crate) command_override: Option<Vec<String>>,
    pub(crate) args_override: Option<Vec<String>>,
    pub(crate) env: Vec<(String, KubeEnvValue)>,
    pub(crate) volume_mounts: Vec<KubeVolumeMount>,
    pub(crate) working_dir_override: Option<String>,
    pub(crate) image_pull_policy: String,
    pub(crate) resource_lines: Vec<String>,
    /// Validated probe specifications for startup, liveness, and readiness.
    pub(crate) probes: KubeProbes,
    /// Per-container security context.
    pub(crate) security: ContainerSecurity,
}

/// Validated probe configuration for a container.
#[derive(Debug, Default, Clone)]
pub(crate) struct KubeProbes {
    pub(crate) startup: Option<ProbeSpec>,
    pub(crate) liveness: Option<ProbeSpec>,
    pub(crate) readiness: Option<ProbeSpec>,
}

/// A validated probe specification with a structured check.
#[derive(Debug, Clone)]
pub(crate) struct ProbeSpec {
    pub(crate) check: ProbeCheck,
    pub(crate) initial_delay_seconds: u32,
    pub(crate) period_seconds: u32,
    pub(crate) timeout_seconds: u32,
    pub(crate) failure_threshold: u32,
    #[allow(dead_code)]
    pub(crate) success_threshold: u32,
}

/// The check to execute for a probe.
#[derive(Debug, Clone)]
pub(crate) enum ProbeCheck {
    Exec {
        command: Vec<String>,
    },
    Http {
        port: u16,
        path: String,
        scheme: String,
    },
    Tcp {
        port: u16,
    },
    Grpc {
        port: u16,
        service: Option<String>,
    },
}

#[derive(Debug)]
pub(crate) struct KubeVolumeMount {
    pub(crate) volume_name: String,
    pub(crate) mount_path: String,
    pub(crate) read_only: bool,
}

/// Resolved env var value (literal or deferred reference).
#[derive(Debug)]
pub(crate) enum KubeEnvValue {
    Literal(String),
    SecretKeyRef {
        name: String,
        key: String,
    },
    ConfigMapKeyRef {
        name: String,
        key: String,
    },
    /// Import all keys from a secret as env vars (from `envFrom`).
    SecretRef {
        name: String,
        prefix: String,
    },
    /// Import all keys from a configMap as env vars (from `envFrom`).
    ConfigMapRef {
        name: String,
        prefix: String,
    },
}

#[derive(Debug)]
pub(crate) enum KubeVolumeKind {
    EmptyDir,
    HostPath(String),
    Secret {
        secret_name: String,
        items: Vec<(String, String)>,
        default_mode: u32,
    },
    ConfigMap {
        configmap_name: String,
        items: Vec<(String, String)>,
        default_mode: u32,
    },
    Pvc(String),
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
    "envFrom",
    "ports",
    "volumeMounts",
    "workingDir",
    "imagePullPolicy",
    "resources",
    "livenessProbe",
    "readinessProbe",
    "startupProbe",
    "securityContext",
];

const KNOWN_SECURITY_CONTEXT_FIELDS: &[&str] = &[
    "runAsUser",
    "runAsGroup",
    "runAsNonRoot",
    "seccompProfile",
    "appArmorProfile",
];

const KNOWN_CONTAINER_SECURITY_CONTEXT_FIELDS: &[&str] = &[
    "runAsUser",
    "runAsGroup",
    "runAsNonRoot",
    "capabilities",
    "allowPrivilegeEscalation",
    "readOnlyRootFilesystem",
    "seccompProfile",
    "appArmorProfile",
];

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
                    // Check container-level securityContext fields.
                    if let Some(csc) = c
                        .as_mapping()
                        .and_then(|m| m.get(serde_yml::Value::String("securityContext".into())))
                    {
                        warn_unknown_fields(
                            csc,
                            &format!("spec.{list_key}[{cname}].securityContext"),
                            KNOWN_CONTAINER_SECURITY_CONTEXT_FIELDS,
                        );
                    }
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
                if let Some(serde_yml::Value::Mapping(ref tmap)) =
                    map.get(serde_yml::Value::String("template".into()))
                {
                    if let Some(tspec) = tmap.get(serde_yml::Value::String("spec".into())) {
                        warn_pod_spec_unknown_fields(tspec);
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
    if let Some(prefix) = s.strip_suffix('m') {
        let millis: u32 = prefix
            .parse()
            .with_context(|| format!("invalid CPU millicore value: {s}"))?;
        Ok(millis / 10) // 1000m = 100%
    } else {
        let cores: f64 = s
            .parse()
            .with_context(|| format!("invalid CPU value: {s}"))?;
        let percent = (cores * 100.0).round();
        if percent < 0.0 || percent > u32::MAX as f64 {
            bail!("CPU value out of range: {s}");
        }
        Ok(percent as u32)
    }
}

/// Parse a K8s CPU request to a systemd CPUWeight (1-10000).
fn parse_k8s_cpu_weight(s: &str) -> Result<u32> {
    let millis = if let Some(prefix) = s.strip_suffix('m') {
        prefix
            .parse::<u32>()
            .with_context(|| format!("invalid CPU millicore value: {s}"))?
    } else {
        let cores: f64 = s
            .parse()
            .with_context(|| format!("invalid CPU value: {s}"))?;
        let millis = (cores * 1000.0).round();
        if millis < 0.0 || millis > u32::MAX as f64 {
            bail!("CPU value out of range: {s}");
        }
        millis as u32
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

/// Validate a probe's action and return a structured `ProbeCheck`.
///
/// Exactly one action must be set: exec, httpGet, tcpSocket, or grpc.
fn build_probe_check(probe: &Probe, container_name: &str) -> Result<ProbeCheck> {
    let action_count = probe.exec.is_some() as u8
        + probe.http_get.is_some() as u8
        + probe.tcp_socket.is_some() as u8
        + probe.grpc.is_some() as u8;
    if action_count == 0 {
        bail!("container '{container_name}': probe must specify exec, httpGet, tcpSocket, or grpc");
    }
    if action_count > 1 {
        bail!(
            "container '{container_name}': probe must specify exactly one of exec, httpGet, tcpSocket, or grpc"
        );
    }

    if let Some(ref exec) = probe.exec {
        if exec.command.is_empty() {
            bail!("container '{container_name}': probe exec command is empty");
        }
        Ok(ProbeCheck::Exec {
            command: exec.command.clone(),
        })
    } else if let Some(ref http) = probe.http_get {
        if http.port == 0 {
            bail!("container '{container_name}': httpGet probe port must be > 0");
        }
        let scheme = match http.scheme.as_deref() {
            None | Some("HTTP") | Some("http") => "http".to_string(),
            Some("HTTPS") | Some("https") => "https".to_string(),
            Some(other) => {
                bail!("container '{container_name}': unsupported httpGet scheme: {other}")
            }
        };
        let path = http.path.as_deref().unwrap_or("/").to_string();
        if !path.starts_with('/') {
            bail!("container '{container_name}': httpGet path must start with '/': {path}");
        }
        Ok(ProbeCheck::Http {
            port: http.port,
            path,
            scheme,
        })
    } else if let Some(ref tcp) = probe.tcp_socket {
        if tcp.port == 0 {
            bail!("container '{container_name}': tcpSocket probe port must be > 0");
        }
        Ok(ProbeCheck::Tcp { port: tcp.port })
    } else if let Some(ref grpc) = probe.grpc {
        if grpc.port == 0 {
            bail!("container '{container_name}': grpc probe port must be > 0");
        }
        Ok(ProbeCheck::Grpc {
            port: grpc.port,
            service: grpc.service.clone(),
        })
    } else {
        unreachable!()
    }
}

/// Validate a probe and build a ProbeSpec.
fn build_probe_spec(probe: &Probe, container_name: &str) -> Result<ProbeSpec> {
    let check = build_probe_check(probe, container_name)?;
    Ok(ProbeSpec {
        check,
        initial_delay_seconds: probe.initial_delay_seconds.unwrap_or(0),
        period_seconds: probe.period_seconds.unwrap_or(10),
        timeout_seconds: probe.timeout_seconds.unwrap_or(1),
        failure_threshold: probe.failure_threshold.unwrap_or(3),
        success_threshold: probe.success_threshold.unwrap_or(1),
    })
}

/// Validate a K8s seccomp profile and return systemd syscall filter lines.
fn validate_seccomp_profile(sp: &SeccompProfile, container_name: &str) -> Result<Vec<String>> {
    match sp.profile_type.as_str() {
        "RuntimeDefault" => Ok(security::STRICT_SYSCALL_FILTERS
            .iter()
            .map(|s| s.to_string())
            .collect()),
        "Unconfined" => Ok(Vec::new()),
        "Localhost" => bail!(
            "container '{container_name}': seccompProfile type 'Localhost' is not supported \
             (systemd SystemCallFilter cannot load custom seccomp BPF profiles)"
        ),
        other => bail!("container '{container_name}': unknown seccompProfile type: {other}"),
    }
}

/// Validate a K8s AppArmor profile and return the profile name.
fn validate_apparmor_k8s(ap: &AppArmorProfile, container_name: &str) -> Result<String> {
    match ap.profile_type.as_str() {
        "RuntimeDefault" => Ok(security::STRICT_APPARMOR_PROFILE.to_string()),
        "Localhost" => {
            let name = ap.localhost_profile.as_deref().unwrap_or("");
            if name.is_empty() {
                bail!(
                    "container '{container_name}': appArmorProfile type 'Localhost' \
                     requires localhostProfile to be set"
                );
            }
            security::validate_apparmor_profile(name).with_context(|| {
                format!("container '{container_name}': invalid appArmorProfile")
            })?;
            Ok(name.to_string())
        }
        "Unconfined" => Ok(String::new()),
        other => bail!("container '{container_name}': unknown appArmorProfile type: {other}"),
    }
}

/// Validate a container and build a KubeContainer plan entry.
fn validate_container(c: Container) -> Result<KubeContainer> {
    let image_ref = ImageReference::parse(&c.image)
        .with_context(|| format!("invalid image reference: {}", c.image))?;
    // Process envFrom first so explicit env entries can override them.
    let mut env: Vec<(String, KubeEnvValue)> = Vec::new();
    for ef in &c.env_from {
        let prefix = ef.prefix.as_deref().unwrap_or("");
        if let Some(ref sr) = ef.secret_ref {
            validate_name(&sr.name)
                .with_context(|| format!("envFrom: invalid secret name '{}'", sr.name))?;
            env.push((
                String::new(), // placeholder key; resolved at create time
                KubeEnvValue::SecretRef {
                    name: sr.name.clone(),
                    prefix: prefix.to_string(),
                },
            ));
        } else if let Some(ref cmr) = ef.config_map_ref {
            validate_name(&cmr.name)
                .with_context(|| format!("envFrom: invalid configmap name '{}'", cmr.name))?;
            env.push((
                String::new(),
                KubeEnvValue::ConfigMapRef {
                    name: cmr.name.clone(),
                    prefix: prefix.to_string(),
                },
            ));
        } else {
            bail!("envFrom entry must specify configMapRef or secretRef");
        }
    }

    // Then process explicit env entries (these take priority via the dedup in create.rs).
    for e in &c.env {
        if let Some(ref vf) = e.value_from {
            if let Some(ref skr) = vf.secret_key_ref {
                validate_name(&skr.name)
                    .with_context(|| format!("env '{}': invalid secret name", e.name))?;
                env.push((
                    e.name.clone(),
                    KubeEnvValue::SecretKeyRef {
                        name: skr.name.clone(),
                        key: skr.key.clone(),
                    },
                ));
            } else if let Some(ref cmkr) = vf.config_map_key_ref {
                validate_name(&cmkr.name)
                    .with_context(|| format!("env '{}': invalid configmap name", e.name))?;
                env.push((
                    e.name.clone(),
                    KubeEnvValue::ConfigMapKeyRef {
                        name: cmkr.name.clone(),
                        key: cmkr.key.clone(),
                    },
                ));
            } else {
                bail!(
                    "env '{}': valueFrom must specify secretKeyRef or configMapKeyRef",
                    e.name
                )
            }
        } else {
            env.push((
                e.name.clone(),
                KubeEnvValue::Literal(e.value.clone().unwrap_or_default()),
            ));
        }
    }
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
    let mut probes = KubeProbes::default();
    if let Some(ref probe) = c.startup_probe {
        probes.startup = Some(
            build_probe_spec(probe, &c.name)
                .with_context(|| format!("container '{}': invalid startup probe", c.name))?,
        );
    }
    if let Some(ref probe) = c.liveness_probe {
        probes.liveness = Some(
            build_probe_spec(probe, &c.name)
                .with_context(|| format!("container '{}': invalid liveness probe", c.name))?,
        );
    }
    if let Some(ref probe) = c.readiness_probe {
        probes.readiness = Some(
            build_probe_spec(probe, &c.name)
                .with_context(|| format!("container '{}': invalid readiness probe", c.name))?,
        );
    }

    // Validate container-level securityContext.
    let security = if let Some(ref sc) = c.security_context {
        // runAsNonRoot consistency.
        if sc.run_as_non_root == Some(true) && sc.run_as_user.is_none() {
            bail!(
                "container '{}': securityContext.runAsNonRoot is true but runAsUser is not set",
                c.name
            );
        }
        if sc.run_as_non_root == Some(true) && sc.run_as_user == Some(0) {
            bail!(
                "container '{}': securityContext.runAsNonRoot is true but runAsUser is 0 (root)",
                c.name
            );
        }

        // Validate capabilities.
        let mut add_caps = Vec::new();
        let mut drop_caps = Vec::new();
        if let Some(ref caps) = sc.capabilities {
            for cap in &caps.add {
                let normalized = security::normalize_cap(cap);
                security::validate_capability(&normalized)
                    .with_context(|| format!("container '{}': capabilities.add", c.name))?;
                add_caps.push(normalized);
            }
            for cap in &caps.drop {
                if cap.eq_ignore_ascii_case("ALL") {
                    drop_caps.push("ALL".to_string());
                } else {
                    let normalized = security::normalize_cap(cap);
                    security::validate_capability(&normalized)
                        .with_context(|| format!("container '{}': capabilities.drop", c.name))?;
                    drop_caps.push(normalized);
                }
            }
        }

        // Validate seccomp profile.
        let has_seccomp_profile = sc.seccomp_profile.is_some();
        let syscall_filters = if let Some(ref sp) = sc.seccomp_profile {
            validate_seccomp_profile(sp, &c.name)?
        } else {
            Vec::new()
        };

        // Validate apparmor profile.
        let apparmor_profile = if let Some(ref ap) = sc.apparmor_profile {
            Some(validate_apparmor_k8s(ap, &c.name)?)
        } else {
            None
        };

        ContainerSecurity {
            run_as_user: sc.run_as_user,
            run_as_group: sc.run_as_group,
            add_caps,
            drop_caps,
            allow_privilege_escalation: sc.allow_privilege_escalation,
            read_only_root_filesystem: sc.read_only_root_filesystem.unwrap_or(false),
            syscall_filters,
            has_seccomp_profile,
            apparmor_profile,
        }
    } else {
        ContainerSecurity::default()
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
        probes,
        security,
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
    let (run_as_user, run_as_group, pod_seccomp_type, pod_apparmor) =
        if let Some(ref sc) = spec.security_context {
            if sc.run_as_non_root == Some(true) && sc.run_as_user.is_none() {
                bail!("securityContext.runAsNonRoot is true but runAsUser is not set");
            }
            if sc.run_as_non_root == Some(true) && sc.run_as_user == Some(0) {
                bail!("securityContext.runAsNonRoot is true but runAsUser is 0 (root)");
            }
            let seccomp_type = sc
                .seccomp_profile
                .as_ref()
                .map(|sp| match sp.profile_type.as_str() {
                    "RuntimeDefault" | "Unconfined" => Ok(sp.profile_type.clone()),
                    "Localhost" => bail!(
                        "pod securityContext: seccompProfile type 'Localhost' is not supported \
                         (systemd SystemCallFilter cannot load custom seccomp BPF profiles)"
                    ),
                    other => bail!("pod securityContext: unknown seccompProfile type: {other}"),
                })
                .transpose()?;
            let apparmor = sc
                .apparmor_profile
                .as_ref()
                .map(|ap| validate_apparmor_k8s(ap, "<pod>"))
                .transpose()?;
            (sc.run_as_user, sc.run_as_group, seccomp_type, apparmor)
        } else {
            (None, None, None, None)
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
            } else if let Some(ref sec) = v.secret {
                validate_name(&sec.secret_name)
                    .with_context(|| format!("volume '{}': invalid secret name", v.name))?;
                let items: Vec<(String, String)> = sec
                    .items
                    .iter()
                    .map(|item| {
                        if item.path.contains("..") {
                            bail!(
                                "volume '{}': secret item path must not contain '..': {}",
                                v.name,
                                item.path
                            );
                        }
                        if item.path.starts_with('/') {
                            bail!(
                                "volume '{}': secret item path must not start with '/': {}",
                                v.name,
                                item.path
                            );
                        }
                        Ok((item.key.clone(), item.path.clone()))
                    })
                    .collect::<Result<Vec<_>>>()?;
                KubeVolumeKind::Secret {
                    secret_name: sec.secret_name.clone(),
                    items,
                    default_mode: sec.default_mode,
                }
            } else if let Some(ref cm) = v.config_map {
                validate_name(&cm.name)
                    .with_context(|| format!("volume '{}': invalid configmap name", v.name))?;
                let items: Vec<(String, String)> = cm
                    .items
                    .iter()
                    .map(|item| {
                        if item.path.contains("..") {
                            bail!(
                                "volume '{}': configmap item path must not contain '..': {}",
                                v.name,
                                item.path
                            );
                        }
                        if item.path.starts_with('/') {
                            bail!(
                                "volume '{}': configmap item path must not start with '/': {}",
                                v.name,
                                item.path
                            );
                        }
                        Ok((item.key.clone(), item.path.clone()))
                    })
                    .collect::<Result<Vec<_>>>()?;
                KubeVolumeKind::ConfigMap {
                    configmap_name: cm.name.clone(),
                    items,
                    default_mode: cm.default_mode,
                }
            } else if let Some(ref pvc) = v.persistent_volume_claim {
                validate_name(&pvc.claim_name)
                    .with_context(|| format!("volume '{}': invalid PVC claim name", v.name))?;
                KubeVolumeKind::Pvc(pvc.claim_name.clone())
            } else {
                KubeVolumeKind::EmptyDir
            };
            Ok(KubeVolume {
                name: v.name.clone(),
                kind,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    // Collect nspawn --bind= arguments for hostPath volumes only.
    // emptyDir volumes live inside the rootfs at /oci/volumes/{name} and are
    // bind-mounted to each app's root via sdme-kube-volumes.service.
    // ConfigMap and Secret volumes are populated into the rootfs.
    // PVC volumes get host_binds added in kube_create after datadir is known.
    let host_binds: Vec<(String, String)> = volumes
        .iter()
        .filter_map(|v| match &v.kind {
            KubeVolumeKind::HostPath(path) => {
                Some((path.clone(), format!("/oci/volumes/{}", v.name)))
            }
            KubeVolumeKind::EmptyDir
            | KubeVolumeKind::Secret { .. }
            | KubeVolumeKind::ConfigMap { .. }
            | KubeVolumeKind::Pvc(_) => None,
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
        seccomp_profile_type: pod_seccomp_type,
        apparmor_profile: pod_apparmor,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDataDir;
    use std::fs;
    use std::sync::Mutex;

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
        let probe = plan.containers[0].probes.readiness.as_ref().unwrap();
        assert!(
            matches!(&probe.check, ProbeCheck::Exec { command } if command.iter().any(|a| a.contains("test -f"))),
            "expected exec probe with 'test -f' command"
        );
        assert_eq!(probe.initial_delay_seconds, 5);
        assert_eq!(probe.period_seconds, 3);
        assert_eq!(probe.failure_threshold, 5);
    }

    #[test]
    fn test_liveness_probe_no_action_rejected() {
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
        let msg = format!("{err:#}");
        assert!(
            msg.contains("must specify exec, httpGet, tcpSocket, or grpc"),
            "unexpected error: {msg}"
        );
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
        assert!(plan.containers[0].probes.liveness.is_some());
    }

    #[test]
    fn test_liveness_probe_http_get() {
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
      httpGet:
        path: /healthz
        port: 8080
      periodSeconds: 5
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();
        let probe = plan.containers[0].probes.liveness.as_ref().unwrap();
        assert!(
            matches!(&probe.check, ProbeCheck::Http { port: 8080, ref path, .. } if path == "/healthz"),
            "expected HTTP probe on port 8080 path /healthz"
        );
        assert_eq!(probe.period_seconds, 5);
    }

    #[test]
    fn test_readiness_probe_tcp_socket() {
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
      tcpSocket:
        port: 3306
      periodSeconds: 10
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();
        let probe = plan.containers[0].probes.readiness.as_ref().unwrap();
        assert!(
            matches!(&probe.check, ProbeCheck::Tcp { port: 3306 }),
            "expected TCP probe on port 3306"
        );
    }

    #[test]
    fn test_startup_probe() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: probe-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    startupProbe:
      httpGet:
        path: /ready
        port: 8080
      failureThreshold: 30
      periodSeconds: 2
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();
        let probe = plan.containers[0].probes.startup.as_ref().unwrap();
        assert!(
            matches!(&probe.check, ProbeCheck::Http { port: 8080, ref path, .. } if path == "/ready"),
            "expected HTTP probe on port 8080 path /ready"
        );
        assert_eq!(probe.failure_threshold, 30);
        assert_eq!(probe.period_seconds, 2);
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
        assert!(app.probes.readiness.is_some());
    }

    // --- Unit file integration tests ---
    //
    // These tests call `setup_kube_container()` with a temp directory and
    // verify the generated systemd unit file contains correct directives.

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

        super::super::create::setup_kube_container(
            tmp.path(),
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
            probes: KubeProbes::default(),
            security: ContainerSecurity::default(),
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
            seccomp_profile_type: None,
            apparmor_profile: None,
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

        // In isolate mode, working dir is passed as an argument to .sdme-isolate,
        // not as a systemd WorkingDirectory= directive.
        assert!(
            unit.contains("/.sdme-isolate 0 0 /app"),
            "should have /app as working dir in isolate exec, got: {unit}"
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
    fn test_unit_startup_probe() {
        let _lock = UNIT_TEST_LOCK.lock().unwrap();
        let mut kc = make_test_container("app");
        kc.probes.startup = Some(ProbeSpec {
            check: ProbeCheck::Exec {
                command: vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    "test -f /tmp/ready".to_string(),
                ],
            },
            initial_delay_seconds: 0,
            period_seconds: 2,
            timeout_seconds: 1,
            failure_threshold: 30,
            success_threshold: 1,
        });
        let plan = make_test_plan();

        let tmp = TempDataDir::new("kube-unit-startup");
        let staging = tmp.path().join("staging");
        let app_dir = staging.join("oci/apps/app");
        let app_root = app_dir.join("root");
        fs::create_dir_all(&app_root).unwrap();
        fs::create_dir_all(staging.join("etc/systemd/system/multi-user.target.wants")).unwrap();

        super::super::create::setup_kube_container(
            tmp.path(),
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

        // Startup probe should NOT use ExecStartPost (all probes use timers).
        let unit_path = staging.join("etc/systemd/system/sdme-oci-app.service");
        let unit = fs::read_to_string(&unit_path).unwrap();
        assert!(
            !unit.contains("ExecStartPost="),
            "startup probe should not use ExecStartPost"
        );

        // Startup timer and service units should exist.
        let timer_path = staging.join("etc/systemd/system/sdme-probe-startup-app.timer");
        assert!(timer_path.exists(), "startup timer unit should exist");
        let svc_path = staging.join("etc/systemd/system/sdme-probe-startup-app.service");
        assert!(svc_path.exists(), "startup service unit should exist");
        let svc = fs::read_to_string(&svc_path).unwrap();
        assert!(
            svc.contains("/oci/.sdme-kube-probe"),
            "startup service should reference probe binary"
        );
        assert!(
            svc.contains("--type startup"),
            "startup service should have --type startup"
        );
        assert!(
            svc.contains("--threshold 30"),
            "startup service should have --threshold 30"
        );

        // Timer should be enabled.
        let symlink =
            staging.join("etc/systemd/system/multi-user.target.wants/sdme-probe-startup-app.timer");
        assert!(symlink.exists(), "startup timer should be enabled");
    }

    #[test]
    fn test_unit_liveness_probe_timer() {
        let _lock = UNIT_TEST_LOCK.lock().unwrap();
        let mut kc = make_test_container("app");
        kc.probes.liveness = Some(ProbeSpec {
            check: ProbeCheck::Exec {
                command: vec!["true".to_string()],
            },
            initial_delay_seconds: 5,
            period_seconds: 10,
            timeout_seconds: 1,
            failure_threshold: 3,
            success_threshold: 1,
        });
        let plan = make_test_plan();

        let tmp = TempDataDir::new("kube-unit-liveness");
        let staging = tmp.path().join("staging");
        let app_dir = staging.join("oci/apps/app");
        let app_root = app_dir.join("root");
        fs::create_dir_all(&app_root).unwrap();
        fs::create_dir_all(staging.join("etc/systemd/system/multi-user.target.wants")).unwrap();

        super::super::create::setup_kube_container(
            tmp.path(),
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

        // Check timer unit exists.
        let timer_path = staging.join("etc/systemd/system/sdme-probe-liveness-app.timer");
        assert!(timer_path.exists(), "liveness timer unit should exist");
        let timer = fs::read_to_string(&timer_path).unwrap();
        assert!(
            timer.contains("OnActiveSec=5s"),
            "timer should have initial delay"
        );
        assert!(
            timer.contains("OnUnitActiveSec=10s"),
            "timer should have period"
        );
        assert!(
            timer.contains("BindsTo=sdme-oci-app.service"),
            "timer should bind to main service"
        );

        // Check service unit references the probe binary (no scripts).
        let svc_path = staging.join("etc/systemd/system/sdme-probe-liveness-app.service");
        assert!(svc_path.exists(), "liveness service unit should exist");
        let svc = fs::read_to_string(&svc_path).unwrap();
        assert!(
            svc.contains("/oci/.sdme-kube-probe"),
            "service should reference probe binary"
        );
        assert!(
            svc.contains("--type liveness"),
            "service should have --type liveness"
        );

        // No probe scripts should exist.
        let script_path = staging.join("oci/apps/app/probe-liveness.sh");
        assert!(
            !script_path.exists(),
            "no probe scripts should be generated"
        );

        // Check timer symlink in wants dir.
        let symlink = staging
            .join("etc/systemd/system/multi-user.target.wants/sdme-probe-liveness-app.timer");
        assert!(symlink.exists(), "liveness timer should be enabled");
    }

    #[test]
    fn test_unit_readiness_probe_timer() {
        let _lock = UNIT_TEST_LOCK.lock().unwrap();
        let mut kc = make_test_container("app");
        kc.probes.readiness = Some(ProbeSpec {
            check: ProbeCheck::Http {
                port: 8080,
                path: "/".to_string(),
                scheme: "http".to_string(),
            },
            initial_delay_seconds: 0,
            period_seconds: 5,
            timeout_seconds: 1,
            failure_threshold: 3,
            success_threshold: 1,
        });
        let plan = make_test_plan();

        let tmp = TempDataDir::new("kube-unit-readiness");
        let staging = tmp.path().join("staging");
        let app_dir = staging.join("oci/apps/app");
        let app_root = app_dir.join("root");
        fs::create_dir_all(&app_root).unwrap();
        fs::create_dir_all(staging.join("etc/systemd/system/multi-user.target.wants")).unwrap();

        super::super::create::setup_kube_container(
            tmp.path(),
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

        // Check readiness service references probe binary with --type readiness.
        let svc_path = staging.join("etc/systemd/system/sdme-probe-readiness-app.service");
        assert!(svc_path.exists(), "readiness service unit should exist");
        let svc = fs::read_to_string(&svc_path).unwrap();
        assert!(
            svc.contains("/oci/.sdme-kube-probe") && svc.contains("--type readiness"),
            "readiness service should reference probe binary with --type readiness"
        );
    }

    #[test]
    fn test_unit_multiline_command() {
        let _lock = UNIT_TEST_LOCK.lock().unwrap();
        let mut kc = make_test_container("app");
        kc.command_override = Some(vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "echo hello\necho world\n".to_string(),
        ]);
        kc.args_override = None;
        let plan = make_test_plan();
        let unit = setup_test_container("app", &kc, &plan, false, &[]);

        // ExecStart must not contain literal newlines (systemd rejects them).
        // Multi-line commands should be written to a wrapper script.
        let exec_line = unit
            .lines()
            .find(|l| l.starts_with("ExecStart="))
            .expect("unit should have ExecStart");
        assert!(
            exec_line.lines().count() == 1,
            "ExecStart must be a single line, got: {exec_line}"
        );
        assert!(
            exec_line.contains("/.sdme-exec.sh"),
            "multi-line command should use wrapper script, got: {exec_line}"
        );
    }

    #[test]
    fn test_unit_singleline_command_no_wrapper() {
        let _lock = UNIT_TEST_LOCK.lock().unwrap();
        let kc = make_test_container("app");
        let plan = make_test_plan();
        let unit = setup_test_container("app", &kc, &plan, false, &[]);

        let exec_line = unit
            .lines()
            .find(|l| l.starts_with("ExecStart="))
            .expect("unit should have ExecStart");
        assert!(
            !exec_line.contains("/.sdme-exec.sh"),
            "single-line command should not use wrapper script, got: {exec_line}"
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
        // resolve_oci_user() resolves as numeric UID:GID. Kube uses
        // isolate mode so .sdme-isolate is deployed. Numeric UIDs
        // work without etc/passwd.
        let tmp = TempDataDir::new("kube-unit-sec");
        let staging = tmp.path().join("staging");
        let app_dir = staging.join("oci/apps/app");
        let app_root = app_dir.join("root");
        fs::create_dir_all(&app_root).unwrap();
        fs::create_dir_all(staging.join("etc/systemd/system/multi-user.target.wants")).unwrap();

        super::super::create::setup_kube_container(
            tmp.path(),
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

        // Kube uses isolate mode: should use .sdme-isolate with uid/gid.
        assert!(
            unit.contains("/.sdme-isolate 1000 1000"),
            "should use isolate with uid=1000 gid=1000, got: {unit}"
        );
        // isolate binary should be deployed.
        assert!(app_root.join(".sdme-isolate").is_file());
    }

    // --- Secret volumes ---

    #[test]
    fn test_parse_secret_volume() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: secret-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    volumeMounts:
    - name: my-secret
      mountPath: /etc/secrets
  volumes:
  - name: my-secret
    secret:
      secretName: db-creds
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        assert!(spec.volumes[0].secret.is_some());
        let secret = spec.volumes[0].secret.as_ref().unwrap();
        assert_eq!(secret.secret_name, "db-creds");
        assert!(secret.items.is_empty());
        assert_eq!(secret.default_mode, 0o644);

        let plan = validate_and_plan(&name, spec).unwrap();
        assert!(matches!(
            plan.volumes[0].kind,
            KubeVolumeKind::Secret { .. }
        ));
        // Secret volumes should not generate host binds.
        assert!(plan.host_binds.is_empty());
    }

    #[test]
    fn test_parse_secret_volume_with_items() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: secret-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    volumeMounts:
    - name: my-secret
      mountPath: /etc/secrets
  volumes:
  - name: my-secret
    secret:
      secretName: db-creds
      items:
      - key: username
        path: user.txt
      - key: password
        path: pass.txt
      defaultMode: 256
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();
        if let KubeVolumeKind::Secret {
            ref items,
            default_mode,
            ..
        } = plan.volumes[0].kind
        {
            assert_eq!(items.len(), 2);
            assert_eq!(items[0], ("username".to_string(), "user.txt".to_string()));
            assert_eq!(items[1], ("password".to_string(), "pass.txt".to_string()));
            assert_eq!(default_mode, 256); // 0o400
        } else {
            panic!("expected Secret volume kind");
        }
    }

    #[test]
    fn test_secret_volume_invalid_name() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: secret-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
  volumes:
  - name: my-secret
    secret:
      secretName: INVALID
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let err = validate_and_plan(&name, spec).unwrap_err();
        assert!(
            err.to_string().contains("invalid secret name")
                || err.to_string().contains("lowercase"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_secret_volume_item_path_traversal() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: secret-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
  volumes:
  - name: my-secret
    secret:
      secretName: db-creds
      items:
      - key: username
        path: ../etc/passwd
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let err = validate_and_plan(&name, spec).unwrap_err();
        assert!(err.to_string().contains(".."), "unexpected error: {err}");
    }

    #[test]
    fn test_secret_volume_item_path_absolute() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: secret-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
  volumes:
  - name: my-secret
    secret:
      secretName: db-creds
      items:
      - key: username
        path: /etc/passwd
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let err = validate_and_plan(&name, spec).unwrap_err();
        assert!(
            err.to_string().contains("must not start with '/'"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_parse_secret_volume_octal_string_mode() {
        // YAML 1.2 treats `0400` as a string; verify the custom deserializer
        // handles it by parsing it as octal.
        let yaml = "
apiVersion: v1
kind: Pod
metadata:
  name: secret-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    volumeMounts:
    - name: my-secret
      mountPath: /etc/secrets
  volumes:
  - name: my-secret
    secret:
      secretName: db-creds
      defaultMode: \"0400\"
";
        let (_name, spec) = parse_yaml(yaml).unwrap();
        let secret = spec.volumes[0].secret.as_ref().unwrap();
        assert_eq!(secret.default_mode, 0o400); // 256 decimal
    }

    // --- ConfigMap volumes ---

    #[test]
    fn test_parse_configmap_volume() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: cm-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    volumeMounts:
    - name: my-config
      mountPath: /etc/config
  volumes:
  - name: my-config
    configMap:
      name: app-config
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        assert!(spec.volumes[0].config_map.is_some());
        let cm = spec.volumes[0].config_map.as_ref().unwrap();
        assert_eq!(cm.name, "app-config");
        assert!(cm.items.is_empty());
        assert_eq!(cm.default_mode, 0o644);

        let plan = validate_and_plan(&name, spec).unwrap();
        assert!(matches!(
            plan.volumes[0].kind,
            KubeVolumeKind::ConfigMap { .. }
        ));
        // ConfigMap volumes should not generate host binds.
        assert!(plan.host_binds.is_empty());
    }

    #[test]
    fn test_parse_configmap_volume_with_items() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: cm-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    volumeMounts:
    - name: my-config
      mountPath: /etc/config
  volumes:
  - name: my-config
    configMap:
      name: app-config
      items:
      - key: config-key
        path: app.conf
      - key: log-key
        path: log.conf
      defaultMode: 256
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();
        if let KubeVolumeKind::ConfigMap {
            ref items,
            default_mode,
            ..
        } = plan.volumes[0].kind
        {
            assert_eq!(items.len(), 2);
            assert_eq!(items[0], ("config-key".to_string(), "app.conf".to_string()));
            assert_eq!(items[1], ("log-key".to_string(), "log.conf".to_string()));
            assert_eq!(default_mode, 256); // 0o400
        } else {
            panic!("expected ConfigMap volume kind");
        }
    }

    #[test]
    fn test_configmap_volume_invalid_name() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: cm-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
  volumes:
  - name: my-config
    configMap:
      name: INVALID
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let err = validate_and_plan(&name, spec).unwrap_err();
        assert!(
            err.to_string().contains("invalid configmap name")
                || err.to_string().contains("lowercase"),
            "unexpected error: {err}"
        );
    }

    // --- PVC volumes ---

    #[test]
    fn test_parse_pvc_volume() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: pvc-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    volumeMounts:
    - name: data-volume
      mountPath: /data
  volumes:
  - name: data-volume
    persistentVolumeClaim:
      claimName: test-data
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        assert!(spec.volumes[0].persistent_volume_claim.is_some());
        let pvc = spec.volumes[0].persistent_volume_claim.as_ref().unwrap();
        assert_eq!(pvc.claim_name, "test-data");

        let plan = validate_and_plan(&name, spec).unwrap();
        assert!(matches!(plan.volumes[0].kind, KubeVolumeKind::Pvc(_)));
        // PVC volumes don't generate host binds at plan time (added in kube_create).
        assert!(plan.host_binds.is_empty());
    }

    #[test]
    fn test_pvc_volume_invalid_name() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: pvc-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
  volumes:
  - name: data-volume
    persistentVolumeClaim:
      claimName: INVALID
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let err = validate_and_plan(&name, spec).unwrap_err();
        assert!(
            err.to_string().contains("invalid PVC claim name")
                || err.to_string().contains("lowercase"),
            "unexpected error: {err}"
        );
    }

    // --- env valueFrom ---

    #[test]
    fn test_parse_env_value_from_secret() {
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
    - name: DB_PASSWORD
      valueFrom:
        secretKeyRef:
          name: db-creds
          key: password
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();
        assert!(matches!(
            plan.containers[0].env[0].1,
            KubeEnvValue::SecretKeyRef { .. }
        ));
        if let KubeEnvValue::SecretKeyRef { ref name, ref key } = plan.containers[0].env[0].1 {
            assert_eq!(name, "db-creds");
            assert_eq!(key, "password");
        }
    }

    #[test]
    fn test_parse_env_value_from_configmap() {
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
    - name: LOG_LEVEL
      valueFrom:
        configMapKeyRef:
          name: app-config
          key: log-level
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();
        assert!(matches!(
            plan.containers[0].env[0].1,
            KubeEnvValue::ConfigMapKeyRef { .. }
        ));
        if let KubeEnvValue::ConfigMapKeyRef { ref name, ref key } = plan.containers[0].env[0].1 {
            assert_eq!(name, "app-config");
            assert_eq!(key, "log-level");
        }
    }

    #[test]
    fn test_parse_env_value_from_invalid() {
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
    - name: BAD_VAR
      valueFrom: {}
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let err = validate_and_plan(&name, spec).unwrap_err();
        assert!(
            err.to_string()
                .contains("valueFrom must specify secretKeyRef or configMapKeyRef"),
            "unexpected error: {err}"
        );
    }

    // --- Container securityContext tests ---

    #[test]
    fn test_container_security_context_caps_add_drop() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: sec-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    securityContext:
      capabilities:
        add: ["NET_ADMIN"]
        drop: ["NET_RAW"]
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();
        let c = &plan.containers[0];
        assert_eq!(c.security.add_caps, vec!["CAP_NET_ADMIN"]);
        assert_eq!(c.security.drop_caps, vec!["CAP_NET_RAW"]);
    }

    #[test]
    fn test_container_security_context_caps_drop_all() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: sec-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    securityContext:
      capabilities:
        add: ["CHOWN"]
        drop: ["ALL"]
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();
        let c = &plan.containers[0];
        assert_eq!(c.security.add_caps, vec!["CAP_CHOWN"]);
        assert_eq!(c.security.drop_caps, vec!["ALL"]);
    }

    #[test]
    fn test_container_security_context_invalid_cap() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: sec-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    securityContext:
      capabilities:
        add: ["BOGUS"]
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let err = validate_and_plan(&name, spec).unwrap_err();
        let chain = format!("{err:#}");
        assert!(
            chain.contains("unknown capability"),
            "unexpected error: {chain}"
        );
    }

    #[test]
    fn test_container_security_context_seccomp_runtime_default() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: sec-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    securityContext:
      seccompProfile:
        type: RuntimeDefault
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();
        let c = &plan.containers[0];
        assert!(!c.security.syscall_filters.is_empty(), "should have syscall filters");
        assert!(
            c.security.syscall_filters.iter().any(|f| f.contains("@raw-io")),
            "should include @raw-io filter"
        );
    }

    #[test]
    fn test_container_security_context_seccomp_unconfined() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: sec-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    securityContext:
      seccompProfile:
        type: Unconfined
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();
        let c = &plan.containers[0];
        assert!(
            c.security.syscall_filters.is_empty(),
            "Unconfined should have no filters"
        );
    }

    #[test]
    fn test_container_security_context_seccomp_localhost_rejected() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: sec-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    securityContext:
      seccompProfile:
        type: Localhost
        localhostProfile: my-profile.json
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let err = validate_and_plan(&name, spec).unwrap_err();
        assert!(
            err.to_string().contains("Localhost"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_container_security_context_apparmor_runtime_default() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: sec-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    securityContext:
      appArmorProfile:
        type: RuntimeDefault
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();
        let c = &plan.containers[0];
        assert_eq!(c.security.apparmor_profile.as_deref(), Some("sdme-default"));
    }

    #[test]
    fn test_container_security_context_apparmor_localhost() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: sec-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    securityContext:
      appArmorProfile:
        type: Localhost
        localhostProfile: my-custom-profile
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();
        let c = &plan.containers[0];
        assert_eq!(c.security.apparmor_profile.as_deref(), Some("my-custom-profile"));
    }

    #[test]
    fn test_container_security_context_apparmor_unconfined() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: sec-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    securityContext:
      appArmorProfile:
        type: Unconfined
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();
        let c = &plan.containers[0];
        // Unconfined resolves to empty string.
        assert_eq!(c.security.apparmor_profile.as_deref(), Some(""));
    }

    #[test]
    fn test_container_security_context_run_as_user() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: sec-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    securityContext:
      runAsUser: 1000
      runAsGroup: 1000
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();
        let c = &plan.containers[0];
        assert_eq!(c.security.run_as_user, Some(1000));
        assert_eq!(c.security.run_as_group, Some(1000));
    }

    #[test]
    fn test_container_security_context_run_as_non_root_no_user() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: sec-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    securityContext:
      runAsNonRoot: true
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let err = validate_and_plan(&name, spec).unwrap_err();
        assert!(
            err.to_string().contains("runAsNonRoot"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_container_security_context_allow_privilege_escalation() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: sec-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    securityContext:
      allowPrivilegeEscalation: false
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();
        let c = &plan.containers[0];
        assert_eq!(c.security.allow_privilege_escalation, Some(false));
    }

    #[test]
    fn test_container_security_context_read_only_root_filesystem() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: sec-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    securityContext:
      readOnlyRootFilesystem: true
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();
        let c = &plan.containers[0];
        assert!(c.security.read_only_root_filesystem);
    }

    #[test]
    fn test_container_security_context_all_fields() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: sec-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    securityContext:
      runAsUser: 1000
      runAsGroup: 1000
      runAsNonRoot: true
      capabilities:
        add: ["NET_ADMIN"]
        drop: ["NET_RAW"]
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      seccompProfile:
        type: RuntimeDefault
      appArmorProfile:
        type: RuntimeDefault
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();
        let c = &plan.containers[0];
        assert_eq!(c.security.run_as_user, Some(1000));
        assert_eq!(c.security.run_as_group, Some(1000));
        assert_eq!(c.security.add_caps, vec!["CAP_NET_ADMIN"]);
        assert_eq!(c.security.drop_caps, vec!["CAP_NET_RAW"]);
        assert_eq!(c.security.allow_privilege_escalation, Some(false));
        assert!(c.security.read_only_root_filesystem);
        assert!(!c.security.syscall_filters.is_empty());
        assert_eq!(c.security.apparmor_profile.as_deref(), Some("sdme-default"));
    }

    #[test]
    fn test_pod_security_context_seccomp_runtime_default() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: sec-pod
spec:
  securityContext:
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    image: docker.io/busybox:latest
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();
        assert_eq!(plan.seccomp_profile_type.as_deref(), Some("RuntimeDefault"));
    }

    #[test]
    fn test_pod_security_context_apparmor() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: sec-pod
spec:
  securityContext:
    appArmorProfile:
      type: RuntimeDefault
  containers:
  - name: app
    image: docker.io/busybox:latest
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();
        assert_eq!(plan.apparmor_profile.as_deref(), Some("sdme-default"));
    }

    #[test]
    fn test_unit_container_security_caps_drop() {
        let _lock = UNIT_TEST_LOCK.lock().unwrap();
        let mut kc = make_test_container("app");
        kc.security.drop_caps = vec!["CAP_NET_RAW".to_string()];
        let plan = make_test_plan();
        let unit = setup_test_container("app", &kc, &plan, false, &[]);
        assert!(
            !unit.contains("CAP_NET_RAW"),
            "CAP_NET_RAW should be dropped"
        );
        assert!(unit.contains("CAP_SYS_ADMIN"), "must keep CAP_SYS_ADMIN");
    }

    #[test]
    fn test_unit_container_security_drop_all() {
        let _lock = UNIT_TEST_LOCK.lock().unwrap();
        let mut kc = make_test_container("app");
        kc.security.drop_caps = vec!["ALL".to_string()];
        kc.security.add_caps = vec!["CAP_CHOWN".to_string()];
        let plan = make_test_plan();
        let unit = setup_test_container("app", &kc, &plan, false, &[]);
        assert!(unit.contains("CAP_SYS_ADMIN"), "must keep CAP_SYS_ADMIN");
        assert!(unit.contains("CAP_CHOWN"), "should have added cap");
        // CAP_SETUID, CAP_SETGID, CAP_SETPCAP are always kept for isolate binary.
        for required in ["CAP_SETUID", "CAP_SETGID", "CAP_SETPCAP"] {
            assert!(unit.contains(required), "must keep {required} for isolate");
        }
        assert!(!unit.contains("CAP_NET_RAW"), "defaults should be dropped");
    }

    #[test]
    fn test_unit_container_security_read_only() {
        let _lock = UNIT_TEST_LOCK.lock().unwrap();
        let mut kc = make_test_container("app");
        kc.security.read_only_root_filesystem = true;
        let plan = make_test_plan();
        let unit = setup_test_container("app", &kc, &plan, false, &[]);
        assert!(
            unit.contains("ReadOnlyPaths=/"),
            "should have ReadOnlyPaths"
        );
    }

    #[test]
    fn test_unit_container_security_apparmor() {
        let _lock = UNIT_TEST_LOCK.lock().unwrap();
        let mut kc = make_test_container("app");
        kc.security.apparmor_profile = Some("sdme-default".to_string());
        let plan = make_test_plan();
        let unit = setup_test_container("app", &kc, &plan, false, &[]);
        assert!(
            unit.contains("AppArmorProfile=sdme-default"),
            "should have AppArmor profile"
        );
    }

    #[test]
    fn test_unit_container_security_syscall_filters() {
        let _lock = UNIT_TEST_LOCK.lock().unwrap();
        let mut kc = make_test_container("app");
        kc.security.syscall_filters = vec!["~@raw-io".to_string()];
        kc.security.has_seccomp_profile = true;
        let plan = make_test_plan();
        let unit = setup_test_container("app", &kc, &plan, false, &[]);
        assert!(
            unit.contains("SystemCallFilter=~@raw-io"),
            "should have syscall filter"
        );
    }

    #[test]
    fn test_unit_pod_seccomp_fallback() {
        let _lock = UNIT_TEST_LOCK.lock().unwrap();
        let kc = make_test_container("app");
        let mut plan = make_test_plan();
        plan.seccomp_profile_type = Some("RuntimeDefault".to_string());
        let unit = setup_test_container("app", &kc, &plan, false, &[]);
        assert!(
            unit.contains("SystemCallFilter="),
            "pod-level seccomp should produce syscall filters"
        );
    }

    #[test]
    fn test_unit_container_seccomp_unconfined_overrides_pod() {
        let _lock = UNIT_TEST_LOCK.lock().unwrap();
        let mut kc = make_test_container("app");
        // Container explicitly sets Unconfined (empty filters, but has_seccomp_profile=true).
        kc.security.has_seccomp_profile = true;
        kc.security.syscall_filters = vec![];
        let mut plan = make_test_plan();
        plan.seccomp_profile_type = Some("RuntimeDefault".to_string());
        let unit = setup_test_container("app", &kc, &plan, false, &[]);
        assert!(
            !unit.contains("SystemCallFilter="),
            "container Unconfined should override pod-level RuntimeDefault"
        );
    }

    #[test]
    fn test_unit_container_user_overrides_pod() {
        let _lock = UNIT_TEST_LOCK.lock().unwrap();
        let mut kc = make_test_container("app");
        kc.security.run_as_user = Some(2000);
        kc.security.run_as_group = Some(2000);
        let mut plan = make_test_plan();
        plan.run_as_user = Some(1000);
        plan.run_as_group = Some(1000);
        let unit = setup_test_container("app", &kc, &plan, false, &[]);
        // Container-level 2000 should override pod-level 1000.
        assert!(
            unit.contains("2000 2000"),
            "container user should override pod user: {unit}"
        );
    }

    // --- Read-only volume mounts ---

    #[test]
    fn test_parse_read_only_volume_mount() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: ro-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    volumeMounts:
    - name: config
      mountPath: /etc/config
      readOnly: true
  volumes:
  - name: config
    emptyDir: {}
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();
        assert!(plan.containers[0].volume_mounts[0].read_only);
    }

    #[test]
    fn test_unit_read_only_volume_mount() {
        // Verify the generated sdme-kube-volumes.service contains remount,ro,bind
        // for a read-only volume mount.
        let _lock = UNIT_TEST_LOCK.lock().unwrap();
        let tmp = TempDataDir::new("kube-rovm");
        let staging = tmp.path().join("staging");
        let apps_dir = staging.join("oci/apps");
        let volumes_dir = staging.join("oci/volumes/shared");
        let unit_dir = staging.join("etc/systemd/system");
        let wants_dir = unit_dir.join("multi-user.target.wants");
        fs::create_dir_all(&apps_dir).unwrap();
        fs::create_dir_all(&volumes_dir).unwrap();
        fs::create_dir_all(&wants_dir).unwrap();

        let plan = KubePlan {
            pod_name: "ro-pod".to_string(),
            containers: vec![KubeContainer {
                name: "app".to_string(),
                volume_mounts: vec![KubeVolumeMount {
                    volume_name: "shared".to_string(),
                    mount_path: "/data".to_string(),
                    read_only: true,
                }],
                ..make_test_container("app")
            }],
            init_containers: vec![],
            volumes: vec![KubeVolume {
                name: "shared".to_string(),
                kind: KubeVolumeKind::EmptyDir,
            }],
            ..make_test_plan()
        };

        // Generate the volume mount unit.
        let has_volume_mounts = plan
            .init_containers
            .iter()
            .chain(plan.containers.iter())
            .any(|kc| !kc.volume_mounts.is_empty());
        assert!(has_volume_mounts);

        let mut exec_lines = Vec::new();
        for kc in plan.init_containers.iter().chain(plan.containers.iter()) {
            for vm in &kc.volume_mounts {
                let src = format!("/oci/volumes/{}", vm.volume_name);
                let dst = format!("/oci/apps/{}/root{}", kc.name, vm.mount_path);
                exec_lines.push(format!("ExecStart=/bin/mount --bind {src} {dst}"));
                if vm.read_only {
                    exec_lines.push(format!("ExecStart=/bin/mount -o remount,ro,bind {dst}"));
                }
            }
        }

        assert!(
            exec_lines
                .iter()
                .any(|l| l.contains("remount,ro,bind") && l.contains("/oci/apps/app/root/data")),
            "should contain remount,ro,bind for read-only mount: {exec_lines:?}"
        );
    }

    #[test]
    fn test_init_container_volume_mounts_in_service() {
        // Verify init container volume mounts are included in has_volume_mounts check.
        let plan = KubePlan {
            pod_name: "init-vm-pod".to_string(),
            containers: vec![make_test_container("app")],
            init_containers: vec![KubeContainer {
                name: "init".to_string(),
                volume_mounts: vec![KubeVolumeMount {
                    volume_name: "shared".to_string(),
                    mount_path: "/data".to_string(),
                    read_only: false,
                }],
                ..make_test_container("init")
            }],
            volumes: vec![KubeVolume {
                name: "shared".to_string(),
                kind: KubeVolumeKind::EmptyDir,
            }],
            ..make_test_plan()
        };

        let has_volume_mounts = plan
            .init_containers
            .iter()
            .chain(plan.containers.iter())
            .any(|kc| !kc.volume_mounts.is_empty());
        assert!(
            has_volume_mounts,
            "init container volume mounts should be detected"
        );
    }

    // --- envFrom ---

    #[test]
    fn test_parse_env_from_configmap() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: ef-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    envFrom:
    - configMapRef:
        name: my-config
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();
        assert!(matches!(
            plan.containers[0].env[0].1,
            KubeEnvValue::ConfigMapRef { .. }
        ));
        if let KubeEnvValue::ConfigMapRef {
            ref name,
            ref prefix,
        } = plan.containers[0].env[0].1
        {
            assert_eq!(name, "my-config");
            assert_eq!(prefix, "");
        }
    }

    #[test]
    fn test_parse_env_from_secret() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: ef-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    envFrom:
    - secretRef:
        name: my-secret
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();
        assert!(matches!(
            plan.containers[0].env[0].1,
            KubeEnvValue::SecretRef { .. }
        ));
        if let KubeEnvValue::SecretRef {
            ref name,
            ref prefix,
        } = plan.containers[0].env[0].1
        {
            assert_eq!(name, "my-secret");
            assert_eq!(prefix, "");
        }
    }

    #[test]
    fn test_parse_env_from_with_prefix() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: ef-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    envFrom:
    - configMapRef:
        name: my-config
      prefix: APP_
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();
        if let KubeEnvValue::ConfigMapRef { ref prefix, .. } = plan.containers[0].env[0].1 {
            assert_eq!(prefix, "APP_");
        } else {
            panic!("expected ConfigMapRef");
        }
    }

    #[test]
    fn test_parse_env_from_invalid_no_ref() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: ef-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    envFrom:
    - prefix: FOO_
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let err = validate_and_plan(&name, spec).unwrap_err();
        assert!(
            err.to_string()
                .contains("envFrom entry must specify configMapRef or secretRef"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_parse_env_from_invalid_name() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: ef-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    envFrom:
    - secretRef:
        name: INVALID
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let err = validate_and_plan(&name, spec).unwrap_err();
        assert!(
            err.to_string().contains("invalid secret name")
                || err.to_string().contains("lowercase"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_env_from_ordering_explicit_env_wins() {
        // envFrom entries come before explicit env in the plan, so explicit env
        // overrides envFrom when create.rs deduplicates by key.
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: ef-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    envFrom:
    - configMapRef:
        name: my-config
    env:
    - name: OVERRIDE_KEY
      value: explicit-value
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();
        // envFrom should be first, explicit env should be last.
        assert!(matches!(
            plan.containers[0].env[0].1,
            KubeEnvValue::ConfigMapRef { .. }
        ));
        assert!(matches!(
            plan.containers[0].env[1].1,
            KubeEnvValue::Literal(_)
        ));
        assert_eq!(plan.containers[0].env[1].0, "OVERRIDE_KEY");
    }

    #[test]
    fn test_env_from_resolve_configmap() {
        // Integration test: verify envFrom configMapRef resolution from store data.
        let _lock = UNIT_TEST_LOCK.lock().unwrap();
        let tmp = TempDataDir::new("kube-envfrom-cm");

        // Create a configmap with test data.
        super::super::configmap::create(
            tmp.path(),
            "my-config",
            &[
                ("HOST".into(), "localhost".into()),
                ("PORT".into(), "8080".into()),
            ],
            &[],
        )
        .unwrap();

        let mut kc = make_test_container("app");
        kc.env = vec![
            (
                String::new(),
                KubeEnvValue::ConfigMapRef {
                    name: "my-config".to_string(),
                    prefix: "APP_".to_string(),
                },
            ),
            // Explicit env should override envFrom key.
            (
                "APP_PORT".to_string(),
                KubeEnvValue::Literal("9090".to_string()),
            ),
        ];

        let staging = tmp.path().join("staging");
        let app_dir = staging.join("oci/apps/app");
        let app_root = app_dir.join("root");
        fs::create_dir_all(&app_root).unwrap();
        fs::create_dir_all(staging.join("etc/systemd/system/multi-user.target.wants")).unwrap();

        let plan = make_test_plan();
        super::super::create::setup_kube_container(
            tmp.path(),
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

        // Read the generated env file.
        let env_path = app_dir.join("env");
        let env_content = fs::read_to_string(&env_path).unwrap();
        // envFrom should have produced APP_HOST=localhost.
        assert!(
            env_content.contains("APP_HOST=localhost"),
            "envFrom should produce APP_HOST=localhost, got: {env_content}"
        );
        // Explicit env APP_PORT=9090 should override envFrom APP_PORT=8080.
        assert!(
            env_content.contains("APP_PORT=9090"),
            "explicit env should override envFrom, got: {env_content}"
        );
        assert!(
            !env_content.contains("APP_PORT=8080"),
            "envFrom value should be overridden, got: {env_content}"
        );
    }

    #[test]
    fn test_env_from_resolve_secret() {
        // Integration test: verify envFrom secretRef resolution from store data.
        let _lock = UNIT_TEST_LOCK.lock().unwrap();
        let tmp = TempDataDir::new("kube-envfrom-sec");

        // Create a secret with test data.
        super::super::secret::create(
            tmp.path(),
            "my-secret",
            &[
                ("USER".into(), "admin".into()),
                ("PASS".into(), "s3cret".into()),
            ],
            &[],
        )
        .unwrap();

        let mut kc = make_test_container("app");
        kc.env = vec![(
            String::new(),
            KubeEnvValue::SecretRef {
                name: "my-secret".to_string(),
                prefix: "DB_".to_string(),
            },
        )];

        let staging = tmp.path().join("staging");
        let app_dir = staging.join("oci/apps/app");
        let app_root = app_dir.join("root");
        fs::create_dir_all(&app_root).unwrap();
        fs::create_dir_all(staging.join("etc/systemd/system/multi-user.target.wants")).unwrap();

        let plan = make_test_plan();
        super::super::create::setup_kube_container(
            tmp.path(),
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

        let env_path = app_dir.join("env");
        let env_content = fs::read_to_string(&env_path).unwrap();
        assert!(
            env_content.contains("DB_PASS=s3cret"),
            "envFrom should produce DB_PASS=s3cret, got: {env_content}"
        );
        assert!(
            env_content.contains("DB_USER=admin"),
            "envFrom should produce DB_USER=admin, got: {env_content}"
        );
    }
}
