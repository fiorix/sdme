//! Validated plan types, YAML parsing, and validation logic.

use crate::oci::registry::ImageReference;

mod parse;
mod validate;

#[cfg(test)]
mod tests;

pub(crate) use parse::parse_yaml;
pub(crate) use validate::validate_and_plan;

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
    pub(crate) ports: Vec<super::types::ContainerPort>,
    /// Whether the pod uses host networking (hostNetwork: true).
    pub(crate) host_network: bool,
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
        headers: Vec<(String, String)>,
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
