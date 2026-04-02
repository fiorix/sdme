//! Validation and plan building from parsed Kubernetes YAML.

use std::collections::HashSet;

use anyhow::{bail, Context, Result};

use super::*;
use crate::kube::types::*;
use crate::oci::registry::ImageReference;
use crate::security;
use crate::validate_name;

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
pub(super) fn build_probe_check(probe: &Probe, container_name: &str) -> Result<ProbeCheck> {
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
        if path.contains(['\r', '\n']) {
            bail!("container '{container_name}': httpGet path contains CR/LF");
        }
        let headers: Vec<(String, String)> = http
            .http_headers
            .iter()
            .map(|h| (h.name.clone(), h.value.clone()))
            .collect();
        for (name, value) in &headers {
            if name.contains(['\r', '\n']) || value.contains(['\r', '\n']) {
                bail!("container '{container_name}': httpGet header contains CR/LF: {name}");
            }
        }
        Ok(ProbeCheck::Http {
            port: http.port,
            path,
            scheme,
            headers,
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
fn validate_container(c: Container, default_registry: &str) -> Result<KubeContainer> {
    let image_ref = ImageReference::parse(&c.image)
        .or_else(|| {
            // Retry with default registry prefix for unqualified image names.
            let qualified = format!("{}/{}", default_registry, c.image);
            ImageReference::parse(&qualified)
        })
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
pub(crate) fn validate_and_plan(
    pod_name: &str,
    spec: PodSpec,
    default_kube_registry: &str,
) -> Result<KubePlan> {
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
        .map(|c| validate_container(c, default_kube_registry))
        .collect::<Result<Vec<_>>>()?;

    // Build container plans.
    let containers: Vec<KubeContainer> = spec
        .containers
        .into_iter()
        .map(|c| validate_container(c, default_kube_registry))
        .collect::<Result<Vec<_>>>()?;

    Ok(KubePlan {
        pod_name: pod_name.to_string(),
        containers,
        init_containers,
        volumes,
        restart_policy,
        ports,
        host_network: spec.host_network,
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
}
