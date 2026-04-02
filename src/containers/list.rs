//! Container listing, health checks, and status reporting.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

use crate::{rootfs, systemd, NetworkConfig, ResourceLimits, State};

/// Kube-specific metadata for a container created via `sdme kube create`.
#[derive(serde::Serialize)]
pub struct KubeInfo {
    /// SHA-256 hash of the YAML used to create the pod.
    pub yaml_hash: String,
    /// Whether any container has liveness/readiness/startup probes.
    pub has_probes: bool,
}

/// Status information for a single container, as shown by `sdme ps`.
#[derive(serde::Serialize)]
pub struct ContainerInfo {
    /// Container name.
    pub name: String,
    /// Systemd unit status (e.g. "running", "stopped").
    pub status: String,
    /// Health status (e.g. "ok", "broken").
    pub health: String,
    /// OS name from os-release, if detected.
    pub os: String,
    /// Root filesystem name (from ROOTFS state key).
    pub rootfs: String,
    /// Pod name (nspawn-level), if any.
    pub pod: String,
    /// Pod name (OCI app-level), if any.
    pub oci_pod: String,
    /// Whether user namespace isolation is enabled.
    pub userns: bool,
    /// Whether auto-start on boot is enabled.
    pub enabled: bool,
    /// Bind mount specs from the state file.
    pub binds: Vec<String>,
    /// OCI apps detected from `/oci/apps/` in the container's rootfs.
    pub oci_apps: Vec<crate::oci::rootfs::OciAppInfo>,
    /// Per-submount overlayfs paths (relative, e.g. "home", "opt").
    ///
    /// Detected from the container's submounts directory on disk.
    pub submounts: Vec<String>,
    /// Network configuration from the state file.
    pub network: NetworkConfig,
    /// Resource limits (CPU, memory) from the state file.
    pub limits: ResourceLimits,
    /// Kube metadata, or null for non-kube containers.
    pub kube: Option<KubeInfo>,
    /// IP addresses assigned to the container's network interface.
    ///
    /// Empty when the container is stopped, uses host networking, or
    /// has no dedicated interface (veth, bridge, zone).
    pub addresses: Vec<String>,
}

impl ContainerInfo {
    /// Format addresses for display in `sdme ps`.
    ///
    /// Joins all addresses with commas. Example: `10.0.0.2,fd00::1`
    pub fn addresses_display(&self) -> String {
        self.addresses.join(",")
    }
}

/// Check readiness probe files for a kube container with probes.
///
/// Looks for `probe-ready` files under `/oci/apps/{name}/` in the container's
/// overlayfs (merged when running, upper when stopped). Returns "ready" if all
/// apps with probe-ready files report "ready", "not-ready" if any report
/// "not-ready", or "ok" if no probe-ready files exist.
fn probe_readiness_health(container_dir: &Path, state: &State) -> String {
    // Determine which apps to check from KUBE_CONTAINERS or OCI_APP.
    let app_names: Vec<&str> = if let Some(kc) = state.get("KUBE_CONTAINERS") {
        kc.split(',').collect()
    } else if let Some(app) = state.get("OCI_APP") {
        vec![app]
    } else {
        return "ok".to_string();
    };

    // Check merged first (running), then upper (stopped).
    let bases = [container_dir.join("merged"), container_dir.join("upper")];

    let mut found_any = false;
    let mut all_ready = true;
    for name in &app_names {
        for base in &bases {
            let probe_file = base.join("oci/apps").join(name).join("probe-ready");
            if let Ok(content) = fs::read_to_string(&probe_file) {
                let trimmed = content.trim();
                found_any = true;
                if trimmed != "ready" {
                    all_ready = false;
                }
                break; // Found in this base, no need to check the other.
            }
        }
    }

    if !found_any {
        "ok".to_string()
    } else if all_ready {
        "ready".to_string()
    } else {
        "not-ready".to_string()
    }
}

/// List all containers with their status, health, OS, and metadata.
pub fn list(datadir: &Path) -> Result<Vec<ContainerInfo>> {
    let state_dir = datadir.join("state");
    if !state_dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut entries: Vec<String> = Vec::new();
    for entry in fs::read_dir(&state_dir)
        .with_context(|| format!("failed to read {}", state_dir.display()))?
    {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            if let Some(name) = entry.file_name().to_str() {
                entries.push(name.to_string());
            }
        }
    }
    entries.sort();

    let mut result = Vec::new();
    for name in &entries {
        let container_dir = datadir.join("containers").join(name);

        // Health checks.
        let mut problems = Vec::new();
        if !container_dir.exists() {
            problems.push("missing container dir");
        }
        let state_path = state_dir.join(name);
        let state = State::read_from(&state_path);

        // Extract all state-dependent fields at once.
        let (rootfs_name, pod, oci_pod, userns, enabled, binds, network, limits, kube) =
            match &state {
                Ok(s) => {
                    let kube = if s.is_yes("KUBE") {
                        Some(KubeInfo {
                            yaml_hash: s.get("KUBE_YAML_HASH").unwrap_or("").to_string(),
                            has_probes: s.is_yes("HAS_PROBES"),
                        })
                    } else {
                        None
                    };
                    (
                        s.rootfs().to_string(),
                        s.get("POD").unwrap_or("").to_string(),
                        s.get("OCI_POD").unwrap_or("").to_string(),
                        s.is_yes("USERNS"),
                        s.is_yes("ENABLED"),
                        s.get_list("BINDS", '|'),
                        NetworkConfig::from_state(s),
                        ResourceLimits::from_state(s),
                        kube,
                    )
                }
                Err(_) => {
                    problems.push("unreadable state file");
                    (
                        String::new(),
                        String::new(),
                        String::new(),
                        false,
                        false,
                        Vec::new(),
                        NetworkConfig::default(),
                        ResourceLimits::default(),
                        None,
                    )
                }
            };

        if !rootfs_name.is_empty() && !datadir.join("fs").join(&rootfs_name).exists() {
            problems.push("missing fs");
        }

        // Query systemd ActiveState before health and status.
        let active_state = if container_dir.exists() {
            systemd::unit_active_state(name)
        } else {
            None
        };

        let health = if !problems.is_empty() {
            problems.join(", ")
        } else if active_state.as_deref() == Some("failed") {
            "failed".to_string()
        } else if let Ok(ref s) = state {
            // For kube containers with readiness probes, check the probe-ready
            // file in the container's overlayfs to report ready/not-ready.
            if s.is_yes("HAS_PROBES") {
                probe_readiness_health(&container_dir, s)
            } else {
                "ok".to_string()
            }
        } else {
            "ok".to_string()
        };

        // OS detection: prefer the container's overlayfs view (merged when
        // running, upper when stopped), fall back to the imported rootfs.
        let os = {
            let merged = container_dir.join("merged");
            let upper = container_dir.join("upper");
            let detected = [&merged, &upper]
                .iter()
                .map(|p| rootfs::detect_distro(p))
                .find(|d| !d.is_empty())
                .unwrap_or_else(|| {
                    if !rootfs_name.is_empty() {
                        rootfs::detect_distro(&datadir.join("fs").join(&rootfs_name))
                    } else {
                        // Host-rootfs container with overlayfs not mounted
                        // (stopped): the lower layer is the host's /.
                        rootfs::detect_distro(Path::new("/"))
                    }
                });
            if detected.is_empty() {
                "unknown".to_string()
            } else {
                detected
            }
        };

        let status = match active_state.as_deref() {
            Some("active") => "running",
            Some("activating") => "starting",
            Some("deactivating") => "stopping",
            _ => "stopped",
        };

        // IP addresses (only for running containers with a network interface).
        let addresses = if status == "running" && network.has_interface() {
            systemd::get_machine_addresses(name)
        } else {
            Vec::new()
        };

        // Detect OCI apps from the container's rootfs overlay.
        // Try merged (running), then upper (stopped, modified), then base rootfs.
        let oci_apps = {
            let merged = container_dir.join("merged");
            let upper = container_dir.join("upper");
            let candidates: Vec<std::path::PathBuf> = if !rootfs_name.is_empty() {
                vec![merged, upper, datadir.join("fs").join(&rootfs_name)]
            } else {
                vec![merged, upper]
            };
            candidates
                .iter()
                .map(|p| crate::oci::rootfs::read_all_oci_apps(p))
                .find(|apps| !apps.is_empty())
                .unwrap_or_default()
        };

        // Detect per-submount overlays from the container directory.
        let submounts = {
            let sub_dir = container_dir.join("submounts");
            if sub_dir.is_dir() {
                let mut subs: Vec<String> = fs::read_dir(&sub_dir)
                    .ok()
                    .into_iter()
                    .flatten()
                    .filter_map(|e| {
                        let e = e.ok()?;
                        if e.file_type().ok()?.is_dir() {
                            e.file_name().to_str().map(String::from)
                        } else {
                            None
                        }
                    })
                    .collect();
                subs.sort();
                subs
            } else {
                Vec::new()
            }
        };

        result.push(ContainerInfo {
            name: name.clone(),
            status: status.to_string(),
            health,
            os,
            rootfs: rootfs_name,
            pod,
            oci_pod,
            userns,
            enabled,
            binds,
            oci_apps,
            submounts,
            network,
            limits,
            kube,
            addresses,
        });
    }
    Ok(result)
}
