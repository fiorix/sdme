//! YAML parsing for Kubernetes Pod manifests.

use anyhow::{bail, Context, Result};

use super::*;
use crate::kube::types::*;

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
