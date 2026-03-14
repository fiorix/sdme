//! YAML deserialization types for Kubernetes Pod manifests.

/// Top-level Kubernetes manifest (Pod or Deployment).
#[derive(serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(super) struct KubeManifest {
    #[allow(dead_code)]
    pub api_version: Option<String>,
    pub kind: String,
    pub metadata: Option<Metadata>,
    pub spec: Option<serde_yml::Value>,
}

/// Kubernetes object metadata (name, labels, etc.).
#[derive(serde::Deserialize, Debug)]
pub(super) struct Metadata {
    pub name: Option<String>,
}

/// Deployment spec wrapper to extract the pod template.
#[derive(serde::Deserialize, Debug)]
pub(super) struct DeploymentSpec {
    pub template: PodTemplate,
}

/// Pod template within a Deployment spec.
#[derive(serde::Deserialize, Debug)]
pub(super) struct PodTemplate {
    pub metadata: Option<Metadata>,
    pub spec: PodSpec,
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
    pub(crate) env_from: Vec<EnvFromSource>,
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
    #[serde(default)]
    pub(crate) security_context: Option<ContainerSecurityContext>,
}

#[derive(serde::Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PodSecurityContext {
    pub(crate) run_as_user: Option<u32>,
    pub(crate) run_as_group: Option<u32>,
    pub(crate) run_as_non_root: Option<bool>,
    pub(crate) seccomp_profile: Option<SeccompProfile>,
    #[serde(alias = "appArmorProfile")]
    pub(crate) apparmor_profile: Option<AppArmorProfile>,
}

#[derive(serde::Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ContainerSecurityContext {
    pub(crate) run_as_user: Option<u32>,
    pub(crate) run_as_group: Option<u32>,
    pub(crate) run_as_non_root: Option<bool>,
    pub(crate) capabilities: Option<Capabilities>,
    pub(crate) allow_privilege_escalation: Option<bool>,
    pub(crate) read_only_root_filesystem: Option<bool>,
    pub(crate) seccomp_profile: Option<SeccompProfile>,
    #[serde(alias = "appArmorProfile")]
    pub(crate) apparmor_profile: Option<AppArmorProfile>,
}

#[derive(serde::Deserialize, Debug, Default)]
pub(crate) struct Capabilities {
    #[serde(default)]
    pub(crate) add: Vec<String>,
    #[serde(default)]
    pub(crate) drop: Vec<String>,
}

#[derive(serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SeccompProfile {
    #[serde(rename = "type")]
    pub(crate) profile_type: String,
    #[allow(dead_code)]
    pub(crate) localhost_profile: Option<String>,
}

#[derive(serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AppArmorProfile {
    #[serde(rename = "type")]
    pub(crate) profile_type: String,
    pub(crate) localhost_profile: Option<String>,
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
#[serde(rename_all = "camelCase")]
pub(crate) struct EnvVar {
    pub(crate) name: String,
    pub(crate) value: Option<String>,
    #[serde(default)]
    pub(crate) value_from: Option<EnvVarSource>,
}

#[derive(serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EnvVarSource {
    pub(crate) secret_key_ref: Option<KeySelector>,
    pub(crate) config_map_key_ref: Option<KeySelector>,
}

#[derive(serde::Deserialize, Debug)]
pub(crate) struct KeySelector {
    pub(crate) name: String,
    pub(crate) key: String,
}

#[derive(serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EnvFromSource {
    #[serde(default)]
    pub(crate) prefix: Option<String>,
    #[serde(default)]
    pub(crate) config_map_ref: Option<EnvFromRef>,
    #[serde(default)]
    pub(crate) secret_ref: Option<EnvFromRef>,
}

#[derive(serde::Deserialize, Debug)]
pub(crate) struct EnvFromRef {
    pub(crate) name: String,
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
    #[serde(default)]
    pub(crate) secret: Option<SecretVolume>,
    #[serde(default)]
    pub(crate) config_map: Option<ConfigMapVolume>,
    #[serde(default)]
    pub(crate) persistent_volume_claim: Option<PVCVolume>,
}

#[derive(serde::Deserialize, Debug)]
pub(crate) struct HostPathVolume {
    pub(crate) path: String,
}

#[derive(serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SecretVolume {
    pub(crate) secret_name: String,
    #[serde(default)]
    pub(crate) items: Vec<SecretKeyToPath>,
    #[serde(
        default = "default_secret_mode",
        deserialize_with = "deserialize_file_mode"
    )]
    pub(crate) default_mode: u32,
}

fn default_secret_mode() -> u32 {
    0o644
}

/// Deserialize a file mode from either a YAML integer or an octal string.
///
/// YAML 1.2 (used by serde_yml) treats `0400` as a string, not an octal
/// integer like YAML 1.1. Kubernetes YAML files commonly use this syntax
/// for `defaultMode`, so we accept both forms.
pub(super) fn deserialize_file_mode<'de, D>(deserializer: D) -> std::result::Result<u32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{self, Visitor};

    struct FileModeVisitor;

    impl<'de> Visitor<'de> for FileModeVisitor {
        type Value = u32;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("an integer or octal string (e.g. 0644, \"0400\")")
        }

        fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<u32, E> {
            u32::try_from(v).map_err(|_| E::custom(format!("file mode out of range: {v}")))
        }

        fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<u32, E> {
            u32::try_from(v).map_err(|_| E::custom(format!("file mode out of range: {v}")))
        }

        fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<u32, E> {
            // Parse octal strings like "0400", "0644".
            let v = v.trim();
            if let Some(octal) = v.strip_prefix('0') {
                if octal.is_empty() {
                    return Ok(0);
                }
                u32::from_str_radix(octal, 8)
                    .map_err(|_| E::custom(format!("invalid octal file mode: {v}")))
            } else {
                v.parse::<u32>()
                    .map_err(|_| E::custom(format!("invalid file mode: {v}")))
            }
        }
    }

    deserializer.deserialize_any(FileModeVisitor)
}

/// Maps a secret key to a file path within a volume.
#[derive(serde::Deserialize, Debug)]
pub(crate) struct SecretKeyToPath {
    pub(crate) key: String,
    pub(crate) path: String,
}

#[derive(serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConfigMapVolume {
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) items: Vec<ConfigMapKeyToPath>,
    #[serde(
        default = "default_configmap_mode",
        deserialize_with = "deserialize_file_mode"
    )]
    pub(crate) default_mode: u32,
}

fn default_configmap_mode() -> u32 {
    0o644
}

#[derive(serde::Deserialize, Debug)]
pub(crate) struct ConfigMapKeyToPath {
    pub(crate) key: String,
    pub(crate) path: String,
}

#[derive(serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PVCVolume {
    pub(crate) claim_name: String,
}
