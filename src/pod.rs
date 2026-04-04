//! Pod network namespace management and external connectivity.
//!
//! A pod is a shared network namespace that multiple containers can join,
//! so their processes see the same localhost. This enables patterns like
//! "database :5432 + app :8080, reachable via 127.0.0.1".
//!
//! Pods start with loopback only. External connectivity can be added with
//! [`net_attach`] (veth or zone mode), which creates a veth pair between
//! the pod's netns and the host. The host's systemd-networkd handles DHCP
//! and NAT; a host-managed dhcpcd service runs inside the pod's netns.
//! [`net_detach`] removes the veth and stops the DHCP service.
//!
//! **State (persistent):** `{datadir}/pods/{name}/state` (KEY=VALUE file).
//! Networking keys: `NET_MODE`, `NET_HOST_IFACE`, `NET_ZONE`, `NET_DNS`,
//! `NET_SEARCH`.
//! **Runtime (volatile):** `/run/sdme/pods/{name}/netns`: bind-mount of the
//! network namespace fd. Disappears on reboot; lazily recreated by
//! [`ensure_runtime`] when a container references the pod.

use std::ffi::CString;
use std::fmt;
use std::fmt::Write;
use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::{validate_name, State};

/// Persistent state directory for pods.
const STATE_SUBDIR: &str = "pods";

/// Runtime directory for netns bind-mounts (volatile, under /run).
const RUNTIME_DIR: &str = "/run/sdme/pods";

/// Path for the volatile systemd template unit that runs dhcpcd in a pod's netns.
const DHCP_TEMPLATE_UNIT_PATH: &str = "/run/systemd/system/sdme-pod-net@.service";

/// Generate the dhcpcd template unit content with the resolved dhcpcd path.
fn dhcp_template_unit(dhcpcd: &Path) -> String {
    let dhcpcd = dhcpcd.display();
    format!(
        "\
[Unit]
Description=DHCP client for sdme pod %i

[Service]
NetworkNamespacePath=/run/sdme/pods/%i/netns
ExecStart={dhcpcd} host0
Type=forking
"
    )
}

/// Linux IFNAMSIZ limit (including null terminator). Interface names are at most 15 bytes.
const IFNAMSIZ: usize = 15;

/// Network attach mode for a pod.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum NetMode {
    /// Point-to-point veth between pod and host.
    Veth,
    /// Veth connected to a shared zone bridge.
    Zone,
}

impl NetMode {
    /// Parse from a state file value ("veth" or "zone").
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "veth" => Some(Self::Veth),
            "zone" => Some(Self::Zone),
            _ => None,
        }
    }
}

impl fmt::Display for NetMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Veth => f.write_str("veth"),
            Self::Zone => f.write_str("zone"),
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Derive the host-side veth interface name for a pod.
///
/// Veth mode: `ve-pod-{pod}`. Zone mode: `vb-pod-{pod}`.
/// The `pod` infix prevents collisions with nspawn's `ve-{container}` /
/// `vb-{container}` names. networkd's default configs match `ve-*` and
/// `vb-*` globs, so the infix does not break auto-configuration.
/// Truncated to 15 characters (IFNAMSIZ - 1 for the null terminator).
pub fn host_iface_name(pod_name: &str, mode: NetMode) -> String {
    let prefix = match mode {
        NetMode::Veth => "ve-pod-",
        NetMode::Zone => "vb-pod-",
    };
    let mut name = format!("{prefix}{pod_name}");
    name.truncate(IFNAMSIZ);
    name
}

/// Write the dhcpcd systemd template unit to `/run/systemd/system/`.
///
/// Idempotent: skips the write if the file already has the correct content.
/// Returns true if the file was written (daemon-reload needed), false if skipped.
fn write_dhcp_template_unit(dhcpcd: &Path, verbose: bool) -> Result<bool> {
    let content = dhcp_template_unit(dhcpcd);
    if let Ok(existing) = fs::read_to_string(DHCP_TEMPLATE_UNIT_PATH) {
        if existing == content {
            if verbose {
                eprintln!("dhcp template unit already exists, skipping write");
            }
            return Ok(false);
        }
    }
    // Ensure parent directory exists (it should under /run/systemd/system/).
    if let Some(parent) = Path::new(DHCP_TEMPLATE_UNIT_PATH).parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }
    fs::write(DHCP_TEMPLATE_UNIT_PATH, &content).context("failed to write dhcp template unit")?;
    if verbose {
        eprintln!("wrote {DHCP_TEMPLATE_UNIT_PATH}");
    }
    Ok(true)
}

/// Run a command, returning `Ok(())` on success or an error on failure.
///
/// With `verbose`, prints the command before running it.
fn run_cmd(program: &str, args: &[&str], verbose: bool) -> Result<()> {
    if verbose {
        eprintln!("running: {program} {}", args.join(" "));
    }
    let status = Command::new(program)
        .args(args)
        .status()
        .with_context(|| format!("failed to run {program}"))?;
    if !status.success() {
        bail!("{program} {} failed with {status}", args.join(" "));
    }
    Ok(())
}

/// Run a command, returning true if it succeeded and false if it failed.
///
/// Stderr is suppressed; used for probing (e.g. checking if an interface
/// exists) where failure is expected and not an error.
fn run_cmd_ok(program: &str, args: &[&str], verbose: bool) -> bool {
    if verbose {
        eprintln!("running: {program} {}", args.join(" "));
    }
    Command::new(program)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// A container that belongs to a pod, as shown by `sdme pod ls --json`.
#[derive(serde::Serialize)]
pub struct PodContainer {
    /// Container name.
    pub name: String,
    /// How the container joins the pod: "pod" or "oci-pod".
    pub pod_mode: String,
}

/// Information about a listed pod, as shown by `sdme pod ls`.
#[derive(serde::Serialize)]
pub struct PodInfo {
    /// Pod name.
    pub name: String,
    /// Unix timestamp (seconds since epoch) of pod creation.
    pub created: String,
    /// Human-readable creation timestamp (`YYYY-MM-DD HH:MM`).
    pub created_at: String,
    /// Whether the pod's network namespace is currently active.
    pub active: bool,
    /// Network attach mode: "veth", "zone", or empty string.
    pub net_mode: String,
    /// Zone name (zone mode only), or empty string.
    pub net_zone: String,
    /// DNS nameservers from the DHCP lease (space-separated).
    pub dns: String,
    /// DNS search domains from the DHCP lease (space-separated).
    pub search: String,
    /// IP addresses assigned to host0 in the pod's netns.
    ///
    /// Empty when the pod is inactive, has no external networking, or
    /// DHCP has not yet assigned an address.
    pub addresses: Vec<String>,
    /// Containers that belong to this pod.
    pub containers: Vec<PodContainer>,
}

/// Create a new pod: allocate a network namespace with loopback up,
/// bind-mount it to the runtime path, and write the persistent state file.
pub fn create(datadir: &Path, name: &str, verbose: bool) -> Result<()> {
    validate_name(name)?;

    // Exclusive lock prevents concurrent pod creation with the same name.
    let _lock = crate::lock::lock_exclusive(datadir, "pods", name)
        .with_context(|| format!("cannot lock pod '{name}' for creation"))?;

    // Ensure persistent state directory exists.
    let pod_dir = datadir.join(STATE_SUBDIR).join(name);
    if pod_dir.exists() {
        bail!("pod already exists: {name}");
    }
    fs::create_dir_all(&pod_dir)
        .with_context(|| format!("failed to create {}", pod_dir.display()))?;

    // Create the network namespace and bind-mount it.
    if let Err(e) = create_netns(name, verbose) {
        let _ = fs::remove_dir_all(&pod_dir);
        return Err(e);
    }

    // Write persistent state.
    let mut state = State::new();
    let created = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs();
    state.set("CREATED", created.to_string());
    let state_path = pod_dir.join("state");
    if let Err(e) = state.write_to(&state_path) {
        let _ = fs::remove_dir_all(&pod_dir);
        return Err(e);
    }

    if verbose {
        eprintln!("wrote state: {}", state_path.display());
    }

    Ok(())
}

/// List all pods.
pub fn list(datadir: &Path) -> Result<Vec<PodInfo>> {
    let state_dir = datadir.join(STATE_SUBDIR);
    if !state_dir.is_dir() {
        return Ok(Vec::new());
    }

    let mut entries = Vec::new();
    for entry in fs::read_dir(&state_dir)
        .with_context(|| format!("failed to read {}", state_dir.display()))?
    {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = match entry.file_name().to_str() {
            Some(s) => s.to_string(),
            None => continue,
        };

        let state_path = state_dir.join(&name).join("state");
        if !state_path.exists() {
            continue;
        }
        let (created, net_mode, net_zone, dns, search) = match State::read_from(&state_path) {
            Ok(s) => {
                let created = s.get("CREATED").unwrap_or("").to_string();
                let net_mode = s.get("NET_MODE").unwrap_or("").to_string();
                let net_zone = s.get("NET_ZONE").unwrap_or("").to_string();
                let dns = s.get("NET_DNS").unwrap_or("").to_string();
                let search = s.get("NET_SEARCH").unwrap_or("").to_string();
                (created, net_mode, net_zone, dns, search)
            }
            Err(_) => (
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
            ),
        };

        let runtime_path = Path::new(RUNTIME_DIR).join(&name).join("netns");
        let active = runtime_path.exists();

        // Read pod addresses if networking is attached and the pod is active.
        let addresses = if active && !net_mode.is_empty() {
            read_pod_addresses(&name)
        } else {
            Vec::new()
        };

        let created_at = crate::format_timestamp(&created);
        entries.push(PodInfo {
            name,
            created,
            created_at,
            active,
            net_mode,
            net_zone,
            dns,
            search,
            addresses,
            containers: Vec::new(),
        });
    }

    // Scan container state files for pod membership.
    let ct_state_dir = datadir.join("state");
    if ct_state_dir.is_dir() {
        if let Ok(ct_entries) = fs::read_dir(&ct_state_dir) {
            for ce in ct_entries.flatten() {
                if let Ok(ct_state) = State::read_from(&ce.path()) {
                    let ct_name = match ct_state.get("NAME") {
                        Some(n) => n.to_string(),
                        None => ce.file_name().to_string_lossy().into_owned(),
                    };
                    if let Some(pod_name) = ct_state.get("POD").filter(|s| !s.is_empty()) {
                        if let Some(pod) = entries.iter_mut().find(|p| p.name == pod_name) {
                            pod.containers.push(PodContainer {
                                name: ct_name.clone(),
                                pod_mode: "pod".to_string(),
                            });
                        }
                    }
                    if let Some(pod_name) = ct_state.get("OCI_POD").filter(|s| !s.is_empty()) {
                        if let Some(pod) = entries.iter_mut().find(|p| p.name == pod_name) {
                            pod.containers.push(PodContainer {
                                name: ct_name,
                                pod_mode: "oci-pod".to_string(),
                            });
                        }
                    }
                }
            }
        }
    }

    // Sort containers within each pod for deterministic output.
    for pod in &mut entries {
        pod.containers.sort_by(|a, b| a.name.cmp(&b.name));
    }

    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(entries)
}

/// Read IP addresses of `host0` in a pod's network namespace.
///
/// Returns addresses (without prefix length), both IPv4 and IPv6,
/// excluding link-local (fe80::/10). Returns an empty vec if the
/// interface has no addresses or the command fails.
pub fn read_pod_addresses(name: &str) -> Vec<String> {
    let netns_path = runtime_path(name);
    let net_arg = format!("--net={netns_path}");
    let output = Command::new("nsenter")
        .args([&net_arg, "ip", "-o", "addr", "show", "host0"])
        .output();
    let mut addrs = Vec::new();
    if let Ok(out) = output {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout);
            // Each line: "N: host0    inet 10.0.0.2/28 ..." or
            //            "N: host0    inet6 fd00::1/64 ..."
            // We want the token after "inet" or "inet6", stripped of /prefix.
            for line in text.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                for (i, &p) in parts.iter().enumerate() {
                    if (p == "inet" || p == "inet6") && i + 1 < parts.len() {
                        if let Some(ip) = parts[i + 1].split('/').next() {
                            // Skip link-local IPv6 (fe80::/10).
                            if !ip.starts_with("fe80:") {
                                addrs.push(ip.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    addrs
}

/// Generate a resolv.conf from DNS and search domain strings.
///
/// `dns` is space-separated nameserver IPs, `search` is space-separated domains.
pub fn generate_resolv_conf(dns: &str, search: &str) -> String {
    let mut content = String::from("# Generated by sdme from pod DHCP lease\n");
    for ns in dns.split_whitespace() {
        writeln!(content, "nameserver {ns}").unwrap();
    }
    let search = search.trim();
    if !search.is_empty() {
        writeln!(content, "search {search}").unwrap();
    }
    content
}

/// Find all containers that reference a pod via POD or OCI_POD state keys.
///
/// Returns container names. Skips unreadable state files.
pub fn find_pod_containers(datadir: &Path, pod_name: &str) -> Vec<String> {
    let state_dir = datadir.join("state");
    let mut names = Vec::new();
    if let Ok(entries) = fs::read_dir(&state_dir) {
        for entry in entries.flatten() {
            if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            if let Ok(s) = State::read_from(&entry.path()) {
                let has_pod = s.get("POD").is_some_and(|v| v == pod_name);
                let has_oci_pod = s.get("OCI_POD").is_some_and(|v| v == pod_name);
                if has_pod || has_oci_pod {
                    names.push(name);
                }
            }
        }
    }
    names
}

/// Parse DNS servers and search domains from a dhcpcd `--dumplease` output.
///
/// Returns `(dns, search)` where dns is space-separated nameserver IPs
/// and search is space-separated domain names. Either may be empty.
fn parse_lease_dns(dumplease: &str) -> (String, String) {
    let mut nameservers = Vec::new();
    let mut search_domains = Vec::new();

    for line in dumplease.lines() {
        if let Some(value) = line.strip_prefix("domain_name_servers=") {
            for ns in value.split_whitespace() {
                if !nameservers.contains(&ns) {
                    nameservers.push(ns);
                }
            }
        } else if let Some(value) = line.strip_prefix("domain_search=") {
            for domain in value.split_whitespace() {
                if !search_domains.contains(&domain) {
                    search_domains.push(domain);
                }
            }
        } else if let Some(value) = line.strip_prefix("domain_name=") {
            let domain = value.trim();
            if !domain.is_empty() && !search_domains.contains(&domain) {
                search_domains.push(domain);
            }
        }
    }

    (nameservers.join(" "), search_domains.join(" "))
}

/// Write a resolv.conf atomically to a directory containing `etc/`.
///
/// Uses temp file + rename to avoid partial reads. Creates `etc/` if needed.
fn write_resolv_conf_to(dir: &Path, content: &str, verbose: bool) -> Result<()> {
    let etc_dir = dir.join("etc");
    if !etc_dir.exists() {
        fs::create_dir_all(&etc_dir)
            .with_context(|| format!("failed to create {}", etc_dir.display()))?;
    }
    let target = etc_dir.join("resolv.conf");
    let tmp = etc_dir.join(".resolv.conf.sdme-tmp");
    fs::write(&tmp, content).with_context(|| format!("failed to write {}", tmp.display()))?;
    fs::rename(&tmp, &target)
        .with_context(|| format!("failed to rename to {}", target.display()))?;
    if verbose {
        eprintln!("wrote {}", target.display());
    }
    Ok(())
}

/// Remove the sdme-generated resolv.conf from a directory containing `etc/`.
///
/// Only removes if the file starts with our header comment to avoid
/// clobbering user edits.
fn remove_resolv_conf_from(dir: &Path, verbose: bool) -> Result<()> {
    let target = dir.join("etc").join("resolv.conf");
    if target.exists() {
        if let Ok(content) = fs::read_to_string(&target) {
            if content.starts_with("# Generated by sdme") {
                fs::remove_file(&target)
                    .with_context(|| format!("failed to remove {}", target.display()))?;
                if verbose {
                    eprintln!("removed {}", target.display());
                }
            }
        }
    }
    Ok(())
}

/// Write pod DNS resolv.conf into a container's overlayfs.
///
/// For `--pod` containers, writes to `{base}/etc/resolv.conf`.
/// For `--oci-pod` containers, writes to each OCI app's chroot:
/// `{base}/oci/apps/{app}/root/etc/resolv.conf`.
/// Skips kube containers (they manage their own DNS).
pub fn write_container_resolv_conf(
    datadir: &Path,
    container: &str,
    base: &str,
    content: &str,
    verbose: bool,
) -> Result<()> {
    let state_path = datadir.join("state").join(container);
    let state = State::read_from(&state_path)?;

    // Kube containers manage their own DNS.
    if state.is_yes("KUBE") {
        return Ok(());
    }

    let base_dir = datadir.join("containers").join(container).join(base);

    // --pod: write to the container root.
    if state.get("POD").is_some_and(|v| !v.is_empty()) {
        write_resolv_conf_to(&base_dir, content, verbose)?;
    }

    // --oci-pod: write to each OCI app's chroot.
    if state.get("OCI_POD").is_some_and(|v| !v.is_empty()) {
        let app_names = crate::oci::rootfs::detect_all_oci_app_names(&base_dir);
        for app in &app_names {
            let app_root = base_dir.join("oci").join("apps").join(app).join("root");
            if app_root.exists() {
                write_resolv_conf_to(&app_root, content, verbose)?;
            }
        }
    }

    Ok(())
}

/// Remove pod DNS resolv.conf from a container's overlayfs.
///
/// Mirrors `write_container_resolv_conf`: removes from container root
/// for `--pod`, from each OCI app chroot for `--oci-pod`. Skips kube.
fn remove_container_resolv_conf(
    datadir: &Path,
    container: &str,
    base: &str,
    verbose: bool,
) -> Result<()> {
    let state_path = datadir.join("state").join(container);
    let state = match State::read_from(&state_path) {
        Ok(s) => s,
        Err(_) => return Ok(()),
    };

    if state.is_yes("KUBE") {
        return Ok(());
    }

    let base_dir = datadir.join("containers").join(container).join(base);

    if state.get("POD").is_some_and(|v| !v.is_empty()) {
        remove_resolv_conf_from(&base_dir, verbose)?;
    }

    if state.get("OCI_POD").is_some_and(|v| !v.is_empty()) {
        let app_names = crate::oci::rootfs::detect_all_oci_app_names(&base_dir);
        for app in &app_names {
            let app_root = base_dir.join("oci").join("apps").join(app).join("root");
            if app_root.exists() {
                remove_resolv_conf_from(&app_root, verbose)?;
            }
        }
    }

    Ok(())
}

/// Remove a pod.
///
/// Unmounts the runtime netns, removes the runtime dir, and deletes the
/// persistent state directory. Errors if any container still references
/// this pod (via POD or OCI_POD keys) unless `force` is true.
pub fn remove(datadir: &Path, name: &str, force: bool, verbose: bool) -> Result<()> {
    let pod_dir = datadir.join(STATE_SUBDIR).join(name);
    let state_path = pod_dir.join("state");
    if !state_path.exists() {
        bail!("pod not found: {name}");
    }

    // Exclusive lock prevents concurrent delete and blocks new container joins.
    let _lock = crate::lock::lock_exclusive(datadir, "pods", name)
        .with_context(|| format!("cannot lock pod '{name}' for removal"))?;

    // Check for containers referencing this pod.
    let ct_names = find_pod_containers(datadir, name);
    if !ct_names.is_empty() {
        if !force {
            bail!(
                "pod '{name}' is referenced by container(s): {}; \
                 remove them first or use --force",
                ct_names.join(", ")
            );
        }
        // Force: stop and remove all containers referencing this pod.
        for ct in &ct_names {
            if verbose {
                eprintln!("force-removing container '{ct}' from pod '{name}'");
            }
            if let Err(e) = crate::containers::remove(datadir, ct, verbose) {
                eprintln!("warning: failed to remove container '{ct}': {e}");
            }
        }
    }

    // Auto-detach external networking if attached (best-effort).
    // Done inline to avoid lock contention with net_detach().
    let state = State::read_from(&state_path)?;
    if state.get("NET_MODE").is_some() {
        let unit = format!("sdme-pod-net@{name}.service");
        let _ = run_cmd("systemctl", &["stop", &unit], verbose);
        if let Some(iface) = state.get("NET_HOST_IFACE") {
            let _ = run_cmd("ip", &["link", "del", iface], verbose);
        }
        // State file is about to be deleted, no need to clear NET_* keys.
    }

    // Unmount and remove runtime files.
    let runtime_netns = Path::new(RUNTIME_DIR).join(name).join("netns");
    if runtime_netns.exists() {
        unmount_netns(&runtime_netns, verbose)?;
    }
    // Remove runtime dir (may already be empty).
    let runtime_dir = Path::new(RUNTIME_DIR).join(name);
    let _ = fs::remove_dir(&runtime_dir);

    // Remove persistent state directory.
    fs::remove_dir_all(&pod_dir)
        .with_context(|| format!("failed to remove {}", pod_dir.display()))?;
    if verbose {
        eprintln!("removed state: {}", pod_dir.display());
    }

    Ok(())
}

/// Ensure the runtime netns bind-mount exists for a pod.
///
/// Called at container start time. If the runtime file is missing (e.g. after
/// reboot) but the persistent state exists, the netns is recreated. If the
/// pod had external networking attached, the veth pair and DHCP service are
/// also restored.
pub fn ensure_runtime(datadir: &Path, name: &str, verbose: bool) -> Result<()> {
    let state_path = datadir.join(STATE_SUBDIR).join(name).join("state");
    if !state_path.exists() {
        bail!("pod not found: {name}");
    }

    let runtime_netns = Path::new(RUNTIME_DIR).join(name).join("netns");
    if runtime_netns.exists() {
        if verbose {
            eprintln!("pod '{name}' runtime netns already exists");
        }
        // Netns exists; check if networking needs restoring (e.g. systemd
        // service not running after reboot).
        restore_networking_if_needed(datadir, name, verbose)?;
        return Ok(());
    }

    if verbose {
        eprintln!("recreating runtime netns for pod '{name}'");
    }
    create_netns(name, verbose)?;

    // Restore external networking if it was attached before reboot.
    restore_networking_if_needed(datadir, name, verbose)?;

    Ok(())
}

/// Check that a pod exists in the catalogue (state file present).
pub fn exists(datadir: &Path, name: &str) -> bool {
    datadir.join(STATE_SUBDIR).join(name).join("state").exists()
}

/// Return the runtime path for a pod's netns bind-mount.
pub fn runtime_path(name: &str) -> String {
    format!("{RUNTIME_DIR}/{name}/netns")
}

/// Restore external networking for a pod after reboot.
///
/// Reads the pod's state file; if `NET_MODE` is set, temporarily clears it
/// and calls `net_attach` to rebuild the veth pair and DHCP service. This
/// avoids duplicating the attach logic.
fn restore_networking_if_needed(datadir: &Path, name: &str, verbose: bool) -> Result<()> {
    let state_path = datadir.join(STATE_SUBDIR).join(name).join("state");
    let state = State::read_from(&state_path)?;

    let mode_str = match state.get("NET_MODE") {
        Some(s) => s.to_string(),
        None => return Ok(()),
    };
    let mode = match NetMode::parse(&mode_str) {
        Some(m) => m,
        None => return Ok(()),
    };

    // Check if the host-side interface already exists (networking already restored).
    let host_iface = state.get("NET_HOST_IFACE").unwrap_or("").to_string();
    if !host_iface.is_empty() && run_cmd_ok("ip", &["link", "show", &host_iface], false) {
        return Ok(());
    }

    if verbose {
        eprintln!("restoring {mode} networking for pod '{name}'");
    }

    let zone = state.get("NET_ZONE").map(String::from);

    // Clear NET_MODE so net_attach does not reject with "already attached".
    let mut state = state;
    state.remove("NET_MODE");
    state.remove("NET_HOST_IFACE");
    state.remove("NET_ZONE");
    state.write_to(&state_path)?;

    // Re-attach. On failure, the NET_* keys are already cleared, so the pod
    // is left in a clean "no networking" state rather than a broken half-state.
    net_attach(datadir, name, mode, zone.as_deref(), verbose)
}

// ---------------------------------------------------------------------------
// Pod external connectivity (attach / detach)
// ---------------------------------------------------------------------------

/// Attach external networking to a pod.
///
/// Creates a veth pair between the pod's netns and the host, then starts a
/// host-managed dhcpcd service inside the pod's netns for DHCP. The host's
/// systemd-networkd handles DHCP serving, NAT (IPMasquerade), and ip_forward
/// via its default configs for `ve-*` and `vz-*` interfaces.
///
/// Works while containers are running: they immediately see the new interface.
pub fn net_attach(
    datadir: &Path,
    name: &str,
    mode: NetMode,
    zone: Option<&str>,
    verbose: bool,
) -> Result<()> {
    let state_path = datadir.join(STATE_SUBDIR).join(name).join("state");
    if !state_path.exists() {
        bail!("pod not found: {name}");
    }

    let _lock = crate::lock::lock_exclusive(datadir, "pods", name)
        .with_context(|| format!("cannot lock pod '{name}' for net attach"))?;

    // Bail early on interrupt before the atomic sequence.
    crate::check_interrupted()?;

    let mut state = State::read_from(&state_path)?;
    if state.get("NET_MODE").is_some() {
        bail!("pod '{name}' already has external networking attached");
    }

    let runtime_netns = Path::new(RUNTIME_DIR).join(name).join("netns");
    if !runtime_netns.exists() {
        bail!(
            "pod '{name}' is not active (no runtime netns); \
             start a container in the pod first"
        );
    }

    if mode == NetMode::Zone && zone.is_none() {
        bail!("zone mode requires a zone name");
    }

    // Check dependencies.
    crate::system_check::find_program("ip").context("ip not found; install iproute2")?;
    crate::system_check::find_program("nsenter")
        .context("nsenter not found; install util-linux")?;
    let dhcpcd =
        crate::system_check::find_program("dhcpcd").context("dhcpcd not found; install dhcpcd")?;

    let host_iface = host_iface_name(name, mode);
    let netns_path = runtime_path(name);

    // Cleanup guard: if anything fails after creating the veth, delete it.
    let mut veth_created = false;
    let mut dhcp_started = false;

    let result = (|| -> Result<()> {
        // Zone: create bridge if it does not exist.
        if let NetMode::Zone = mode {
            let zone_name = zone.unwrap();
            let bridge = format!("vz-{zone_name}");
            if !run_cmd_ok("ip", &["link", "show", &bridge], false) {
                run_cmd("ip", &["link", "add", &bridge, "type", "bridge"], verbose)
                    .with_context(|| format!("failed to create bridge {bridge}"))?;
                run_cmd("ip", &["link", "set", &bridge, "up"], verbose)?;
            }
        }

        // Create veth pair (both modes).
        run_cmd(
            "ip",
            &[
                "link",
                "add",
                &host_iface,
                "type",
                "veth",
                "peer",
                "name",
                "host0",
            ],
            verbose,
        )?;
        veth_created = true;

        // Zone: connect host end to bridge.
        if let NetMode::Zone = mode {
            let zone_name = zone.unwrap();
            let bridge = format!("vz-{zone_name}");
            run_cmd(
                "ip",
                &["link", "set", &host_iface, "master", &bridge],
                verbose,
            )?;
        }

        // Move pod end into the pod's netns.
        run_cmd(
            "ip",
            &["link", "set", "host0", "netns", &netns_path],
            verbose,
        )?;

        // Bring up host end.
        run_cmd("ip", &["link", "set", &host_iface, "up"], verbose)?;

        // Bring up pod end.
        let net_arg = format!("--net={netns_path}");
        run_cmd(
            "nsenter",
            &[net_arg.as_str(), "ip", "link", "set", "host0", "up"],
            verbose,
        )?;

        // Write the dhcpcd template unit (idempotent) and daemon-reload if needed.
        if write_dhcp_template_unit(&dhcpcd, verbose)? {
            run_cmd("systemctl", &["daemon-reload"], verbose)?;
        }

        // Start the DHCP client service for this pod.
        let unit = format!("sdme-pod-net@{name}.service");
        run_cmd("systemctl", &["start", &unit], verbose)?;
        dhcp_started = true;

        Ok(())
    })();

    if let Err(e) = result {
        // Best-effort cleanup.
        if dhcp_started {
            let unit = format!("sdme-pod-net@{name}.service");
            let _ = run_cmd("systemctl", &["stop", &unit], false);
        }
        if veth_created {
            let _ = run_cmd("ip", &["link", "del", &host_iface], false);
        }
        return Err(e).context("pod net attach failed");
    }

    // Extract DNS servers from the DHCP lease. Without this, containers
    // in the pod's netns cannot resolve names (the host's stub resolver
    // 127.0.0.53 is unreachable from the pod's network namespace).
    let (dns, search) = match Command::new(&dhcpcd)
        .args(["--dumplease", "host0"])
        .output()
    {
        Ok(out) if out.status.success() => parse_lease_dns(&String::from_utf8_lossy(&out.stdout)),
        _ => {
            if verbose {
                eprintln!("warning: dhcpcd --dumplease failed, no DNS for pod containers");
            }
            (String::new(), String::new())
        }
    };

    // Update persistent state.
    state.set("NET_MODE", mode.to_string());
    state.set("NET_HOST_IFACE", &host_iface);
    if let Some(zone_name) = zone {
        state.set("NET_ZONE", zone_name);
    }
    if !dns.is_empty() {
        state.set("NET_DNS", &dns);
    }
    if !search.is_empty() {
        state.set("NET_SEARCH", &search);
    }
    state
        .write_to(&state_path)
        .context("failed to write pod state after net attach")?;

    // Update resolv.conf on running containers that belong to this pod.
    if !dns.is_empty() {
        let content = generate_resolv_conf(&dns, &search);
        let containers = find_pod_containers(datadir, name);
        for ct in &containers {
            let _lock = crate::lock::lock_exclusive(datadir, "containers", ct);
            let merged = datadir.join("containers").join(ct).join("merged");
            if merged.exists() {
                if let Err(e) =
                    write_container_resolv_conf(datadir, ct, "merged", &content, verbose)
                {
                    eprintln!("warning: failed to update resolv.conf for {ct}: {e}");
                }
            }
        }
    }

    if verbose {
        eprintln!("attached {mode} networking to pod '{name}' (iface: {host_iface})");
    }

    Ok(())
}

/// Detach external networking from a pod.
///
/// Stops the dhcpcd service, deletes the host-side veth (which auto-removes
/// the pod side), and clears networking state. Each step is independently
/// atomic, so interrupting between steps is safe.
pub fn net_detach(datadir: &Path, name: &str, verbose: bool) -> Result<()> {
    let state_path = datadir.join(STATE_SUBDIR).join(name).join("state");
    if !state_path.exists() {
        bail!("pod not found: {name}");
    }

    let _lock = crate::lock::lock_exclusive(datadir, "pods", name)
        .with_context(|| format!("cannot lock pod '{name}' for net detach"))?;

    let mut state = State::read_from(&state_path)?;
    if state.get("NET_MODE").is_none() {
        bail!("pod '{name}' does not have external networking attached");
    }

    let host_iface = state.get("NET_HOST_IFACE").unwrap_or("").to_string();

    // Stop DHCP client service (best-effort).
    let unit = format!("sdme-pod-net@{name}.service");
    if let Err(e) = run_cmd("systemctl", &["stop", &unit], verbose) {
        if verbose {
            eprintln!("warning: failed to stop {unit}: {e}");
        }
    }

    // Delete host-side veth (auto-removes pod side, best-effort).
    if !host_iface.is_empty() {
        if let Err(e) = run_cmd("ip", &["link", "del", &host_iface], verbose) {
            if verbose {
                eprintln!("warning: failed to delete interface {host_iface}: {e}");
            }
        }
    }

    // Remove resolv.conf from running containers before clearing DNS state.
    let containers = find_pod_containers(datadir, name);
    for ct in &containers {
        let _lock = crate::lock::lock_exclusive(datadir, "containers", ct);
        let merged = datadir.join("containers").join(ct).join("merged");
        if merged.exists() {
            if let Err(e) = remove_container_resolv_conf(datadir, ct, "merged", verbose) {
                if verbose {
                    eprintln!("warning: failed to remove resolv.conf for {ct}: {e}");
                }
            }
        }
    }

    // Clear networking state.
    state.remove("NET_MODE");
    state.remove("NET_HOST_IFACE");
    state.remove("NET_ZONE");
    state.remove("NET_DNS");
    state.remove("NET_SEARCH");
    state
        .write_to(&state_path)
        .context("failed to write pod state after net detach")?;

    if verbose {
        eprintln!("detached networking from pod '{name}'");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Network namespace syscall helpers
// ---------------------------------------------------------------------------

/// Create a new network namespace with loopback up and bind-mount it
/// to `/run/sdme/pods/{name}/netns`.
fn create_netns(name: &str, verbose: bool) -> Result<()> {
    // 1. Save current netns fd.
    let saved_fd = {
        let path = CString::new("/proc/self/ns/net").expect("static string literal");
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to open /proc/self/ns/net");
        }
        fd
    };

    // 2. unshare(CLONE_NEWNET): create new network namespace.
    let ret = unsafe { libc::unshare(libc::CLONE_NEWNET) };
    if ret != 0 {
        unsafe { libc::close(saved_fd) };
        return Err(std::io::Error::last_os_error()).context("unshare(CLONE_NEWNET) failed");
    }

    // 3. Bring up loopback in the new netns.
    let lo_result = bring_up_loopback();

    // Steps 4-6: bind-mount the new netns, then restore original netns.
    // We must restore even on failure.
    let mount_result = lo_result.and_then(|()| bind_mount_netns(name, verbose));

    // 7. Restore original netns.
    let ret = unsafe { libc::setns(saved_fd, libc::CLONE_NEWNET) };
    unsafe { libc::close(saved_fd) };
    if ret != 0 {
        // Unrecoverable: the process is now in the wrong network namespace.
        // Returning an error would let the caller continue operating on
        // the wrong netns, which is worse than crashing. exit(1) is correct.
        let err = std::io::Error::last_os_error();
        eprintln!("FATAL: failed to restore network namespace: {err}");
        std::process::exit(1);
    }

    mount_result
}

/// Bring up the loopback interface in the current network namespace.
fn bring_up_loopback() -> Result<()> {
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to create socket for loopback");
    }

    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    let lo_name = b"lo\0";
    for (i, &b) in lo_name.iter().enumerate() {
        ifr.ifr_name[i] = b as _;
    }

    // Get current flags.
    let ret = unsafe { libc::ioctl(sock, libc::SIOCGIFFLAGS as _, &mut ifr) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(sock) };
        return Err(err).context("ioctl SIOCGIFFLAGS failed on lo");
    }

    // Set IFF_UP.
    unsafe { ifr.ifr_ifru.ifru_flags |= libc::IFF_UP as i16 };

    let ret = unsafe { libc::ioctl(sock, libc::SIOCSIFFLAGS as _, &ifr) };
    let err = std::io::Error::last_os_error();
    unsafe { libc::close(sock) };
    if ret != 0 {
        return Err(err).context("ioctl SIOCSIFFLAGS failed on lo");
    }

    Ok(())
}

/// Bind-mount `/proc/self/ns/net` to `/run/sdme/pods/{name}/netns`.
fn bind_mount_netns(name: &str, verbose: bool) -> Result<()> {
    let pod_runtime_dir = Path::new(RUNTIME_DIR).join(name);
    fs::create_dir_all(&pod_runtime_dir)
        .with_context(|| format!("failed to create {}", pod_runtime_dir.display()))?;

    let target = pod_runtime_dir.join("netns");

    // Create empty file as mount point.
    fs::write(&target, "").with_context(|| format!("failed to create {}", target.display()))?;

    let source = CString::new("/proc/self/ns/net").expect("static string literal");
    let c_target =
        CString::new(target.as_os_str().as_encoded_bytes()).context("path contains null byte")?;

    let ret = unsafe {
        libc::mount(
            source.as_ptr(),
            c_target.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        let _ = fs::remove_file(&target);
        let _ = fs::remove_dir(&pod_runtime_dir);
        return Err(err).context("failed to bind-mount network namespace");
    }

    if verbose {
        eprintln!("bind-mounted netns: {}", target.display());
    }

    Ok(())
}

/// Unmount a netns bind-mount and remove the file.
fn unmount_netns(path: &Path, verbose: bool) -> Result<()> {
    let c_path =
        CString::new(path.as_os_str().as_encoded_bytes()).context("path contains null byte")?;

    let ret = unsafe { libc::umount2(c_path.as_ptr(), 0) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        // EINVAL means not mounted (already cleaned up); not a hard error.
        if err.raw_os_error() != Some(libc::EINVAL) {
            return Err(err).with_context(|| format!("failed to unmount {}", path.display()));
        }
    }

    let _ = fs::remove_file(path);

    if verbose {
        eprintln!("unmounted netns: {}", path.display());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDataDir;

    fn tmp() -> TempDataDir {
        TempDataDir::new("pod")
    }

    #[test]
    fn test_create_rejects_invalid_name() {
        let tmp = tmp();
        let err = create(tmp.path(), "INVALID", false).unwrap_err();
        assert!(
            err.to_string().contains("lowercase"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_create_rejects_duplicate() {
        let tmp = tmp();
        // Manually create state dir/file to simulate existing pod.
        let pod_dir = tmp.path().join(STATE_SUBDIR).join("mypod");
        fs::create_dir_all(&pod_dir).unwrap();
        fs::write(pod_dir.join("state"), "CREATED=1234\n").unwrap();

        let err = create(tmp.path(), "mypod", false).unwrap_err();
        assert!(
            err.to_string().contains("already exists"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_list_empty() {
        let tmp = tmp();
        let pods = list(tmp.path()).unwrap();
        assert!(pods.is_empty());
    }

    #[test]
    fn test_list_with_entries() {
        let tmp = tmp();
        let state_dir = tmp.path().join(STATE_SUBDIR);
        let alpha_dir = state_dir.join("alpha");
        let beta_dir = state_dir.join("beta");
        fs::create_dir_all(&alpha_dir).unwrap();
        fs::create_dir_all(&beta_dir).unwrap();
        fs::write(alpha_dir.join("state"), "CREATED=1000\n").unwrap();
        fs::write(beta_dir.join("state"), "CREATED=2000\n").unwrap();

        let pods = list(tmp.path()).unwrap();
        assert_eq!(pods.len(), 2);
        assert_eq!(pods[0].name, "alpha");
        assert_eq!(pods[0].created, "1000");
        assert!(pods[0].net_mode.is_empty());
        assert!(pods[0].containers.is_empty());
        assert_eq!(pods[1].name, "beta");
        assert_eq!(pods[1].created, "2000");
        // Runtime files don't exist in tests.
        assert!(!pods[0].active);
        assert!(!pods[1].active);
    }

    #[test]
    fn test_remove_not_found() {
        let tmp = tmp();
        let err = remove(tmp.path(), "nonexistent", false, false).unwrap_err();
        assert!(
            err.to_string().contains("not found"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_remove_blocked_by_container_oci_pod() {
        let tmp = tmp();
        // Create pod state.
        let pod_dir = tmp.path().join(STATE_SUBDIR).join("mypod");
        fs::create_dir_all(&pod_dir).unwrap();
        fs::write(pod_dir.join("state"), "CREATED=1234\n").unwrap();

        // Create container state referencing the pod via OCI_POD.
        let ct_dir = tmp.path().join("state");
        fs::create_dir_all(&ct_dir).unwrap();
        fs::write(
            ct_dir.join("mycontainer"),
            "NAME=mycontainer\nOCI_POD=mypod\n",
        )
        .unwrap();

        let err = remove(tmp.path(), "mypod", false, false).unwrap_err();
        assert!(
            err.to_string().contains("referenced by container"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_remove_blocked_by_container_pod() {
        let tmp = tmp();
        // Create pod state.
        let pod_dir = tmp.path().join(STATE_SUBDIR).join("mypod");
        fs::create_dir_all(&pod_dir).unwrap();
        fs::write(pod_dir.join("state"), "CREATED=1234\n").unwrap();

        // Create container state referencing the pod via POD.
        let ct_dir = tmp.path().join("state");
        fs::create_dir_all(&ct_dir).unwrap();
        fs::write(ct_dir.join("mycontainer"), "NAME=mycontainer\nPOD=mypod\n").unwrap();

        let err = remove(tmp.path(), "mypod", false, false).unwrap_err();
        assert!(
            err.to_string().contains("referenced by container"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_remove_force_ignores_references() {
        let tmp = tmp();
        // Create pod state.
        let pod_dir = tmp.path().join(STATE_SUBDIR).join("mypod");
        fs::create_dir_all(&pod_dir).unwrap();
        fs::write(pod_dir.join("state"), "CREATED=1234\n").unwrap();

        // Create container state referencing the pod.
        let ct_dir = tmp.path().join("state");
        fs::create_dir_all(&ct_dir).unwrap();
        fs::write(
            ct_dir.join("mycontainer"),
            "NAME=mycontainer\nOCI_POD=mypod\n",
        )
        .unwrap();

        // Force remove succeeds (no runtime file to unmount).
        remove(tmp.path(), "mypod", true, false).unwrap();
        assert!(!pod_dir.exists());
    }

    #[test]
    fn test_exists() {
        let tmp = tmp();
        assert!(!exists(tmp.path(), "mypod"));

        let pod_dir = tmp.path().join(STATE_SUBDIR).join("mypod");
        fs::create_dir_all(&pod_dir).unwrap();
        fs::write(pod_dir.join("state"), "CREATED=1234\n").unwrap();

        assert!(exists(tmp.path(), "mypod"));
    }

    #[test]
    fn test_runtime_path() {
        assert_eq!(runtime_path("mypod"), "/run/sdme/pods/mypod/netns");
    }

    #[test]
    fn test_ensure_runtime_not_found() {
        let tmp = tmp();
        let err = ensure_runtime(tmp.path(), "nonexistent", false).unwrap_err();
        assert!(
            err.to_string().contains("not found"),
            "unexpected error: {err}"
        );
    }

    // --- NetMode tests ---

    #[test]
    fn test_net_mode_from_str() {
        assert_eq!(NetMode::parse("veth"), Some(NetMode::Veth));
        assert_eq!(NetMode::parse("zone"), Some(NetMode::Zone));
        assert_eq!(NetMode::parse("bridge"), None);
        assert_eq!(NetMode::parse(""), None);
    }

    #[test]
    fn test_net_mode_display() {
        assert_eq!(NetMode::Veth.to_string(), "veth");
        assert_eq!(NetMode::Zone.to_string(), "zone");
    }

    // --- host_iface_name tests ---

    #[test]
    fn test_host_iface_name_veth_short() {
        assert_eq!(host_iface_name("mypod", NetMode::Veth), "ve-pod-mypod");
    }

    #[test]
    fn test_host_iface_name_zone_short() {
        assert_eq!(host_iface_name("mypod", NetMode::Zone), "vb-pod-mypod");
    }

    #[test]
    fn test_host_iface_name_truncation() {
        // "ve-pod-" (7) + 8 chars = 15 = IFNAMSIZ
        assert_eq!(
            host_iface_name("averylongpodname", NetMode::Veth),
            "ve-pod-averylon"
        );
        assert_eq!(
            host_iface_name("averylongpodname", NetMode::Veth).len(),
            IFNAMSIZ
        );
    }

    #[test]
    fn test_host_iface_name_exact_limit() {
        // "ve-pod-" (7) + 8 chars = exactly 15
        assert_eq!(
            host_iface_name("12345678", NetMode::Veth),
            "ve-pod-12345678"
        );
        assert_eq!(host_iface_name("12345678", NetMode::Veth).len(), IFNAMSIZ);
    }

    // --- net_attach / net_detach error path tests ---

    #[test]
    fn test_net_attach_not_found() {
        let tmp = tmp();
        let err = net_attach(tmp.path(), "nonexistent", NetMode::Veth, None, false).unwrap_err();
        assert!(
            err.to_string().contains("not found"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_net_attach_already_attached() {
        let tmp = tmp();
        let pod_dir = tmp.path().join(STATE_SUBDIR).join("mypod");
        fs::create_dir_all(&pod_dir).unwrap();
        fs::write(
            pod_dir.join("state"),
            "CREATED=1234\nNET_MODE=veth\nNET_HOST_IFACE=ve-pod-mypod\n",
        )
        .unwrap();

        let err = net_attach(tmp.path(), "mypod", NetMode::Veth, None, false).unwrap_err();
        assert!(
            err.to_string().contains("already has external networking"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_net_detach_not_found() {
        let tmp = tmp();
        let err = net_detach(tmp.path(), "nonexistent", false).unwrap_err();
        assert!(
            err.to_string().contains("not found"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_net_detach_not_attached() {
        let tmp = tmp();
        let pod_dir = tmp.path().join(STATE_SUBDIR).join("mypod");
        fs::create_dir_all(&pod_dir).unwrap();
        fs::write(pod_dir.join("state"), "CREATED=1234\n").unwrap();

        let err = net_detach(tmp.path(), "mypod", false).unwrap_err();
        assert!(
            err.to_string()
                .contains("does not have external networking"),
            "unexpected error: {err}"
        );
    }

    // --- list with net_mode and containers ---

    #[test]
    fn test_list_with_net_mode() {
        let tmp = tmp();
        let state_dir = tmp.path().join(STATE_SUBDIR);

        let alpha_dir = state_dir.join("alpha");
        fs::create_dir_all(&alpha_dir).unwrap();
        fs::write(
            alpha_dir.join("state"),
            "CREATED=1000\nNET_MODE=veth\nNET_HOST_IFACE=ve-pod-alpha\n",
        )
        .unwrap();

        let beta_dir = state_dir.join("beta");
        fs::create_dir_all(&beta_dir).unwrap();
        fs::write(beta_dir.join("state"), "CREATED=2000\n").unwrap();

        let gamma_dir = state_dir.join("gamma");
        fs::create_dir_all(&gamma_dir).unwrap();
        fs::write(
            gamma_dir.join("state"),
            "CREATED=3000\nNET_MODE=zone\nNET_ZONE=myzone\nNET_HOST_IFACE=vb-pod-gamma\n",
        )
        .unwrap();

        let pods = list(tmp.path()).unwrap();
        assert_eq!(pods.len(), 3);

        assert_eq!(pods[0].name, "alpha");
        assert_eq!(pods[0].net_mode, "veth");

        assert_eq!(pods[1].name, "beta");
        assert_eq!(pods[1].net_mode, "");

        assert_eq!(pods[2].name, "gamma");
        assert_eq!(pods[2].net_mode, "zone");
        assert_eq!(pods[2].net_zone, "myzone");
    }

    #[test]
    fn test_list_with_containers() {
        let tmp = tmp();
        let state_dir = tmp.path().join(STATE_SUBDIR);

        let pod_dir = state_dir.join("mypod");
        fs::create_dir_all(&pod_dir).unwrap();
        fs::write(pod_dir.join("state"), "CREATED=1000\n").unwrap();

        // Create container state files referencing the pod.
        let ct_dir = tmp.path().join("state");
        fs::create_dir_all(&ct_dir).unwrap();
        fs::write(ct_dir.join("app1"), "NAME=app1\nPOD=mypod\n").unwrap();
        fs::write(ct_dir.join("app2"), "NAME=app2\nOCI_POD=mypod\n").unwrap();
        fs::write(ct_dir.join("other"), "NAME=other\n").unwrap();

        let pods = list(tmp.path()).unwrap();
        assert_eq!(pods.len(), 1);
        assert_eq!(pods[0].containers.len(), 2);
        assert_eq!(pods[0].containers[0].name, "app1");
        assert_eq!(pods[0].containers[0].pod_mode, "pod");
        assert_eq!(pods[0].containers[1].name, "app2");
        assert_eq!(pods[0].containers[1].pod_mode, "oci-pod");
    }

    // --- generate_resolv_conf tests ---

    #[test]
    fn test_generate_resolv_conf_single_ns() {
        let content = generate_resolv_conf("8.8.8.8", "");
        assert_eq!(
            content,
            "# Generated by sdme from pod DHCP lease\nnameserver 8.8.8.8\n"
        );
    }

    #[test]
    fn test_generate_resolv_conf_multiple_ns_and_search() {
        let content = generate_resolv_conf("8.8.8.8 8.8.4.4", "example.com local");
        assert_eq!(
            content,
            "# Generated by sdme from pod DHCP lease\n\
             nameserver 8.8.8.8\n\
             nameserver 8.8.4.4\n\
             search example.com local\n"
        );
    }

    #[test]
    fn test_generate_resolv_conf_empty_dns() {
        let content = generate_resolv_conf("", "example.com");
        // Empty DNS means no nameserver lines, but search still appears.
        assert_eq!(
            content,
            "# Generated by sdme from pod DHCP lease\nsearch example.com\n"
        );
    }

    #[test]
    fn test_generate_resolv_conf_empty_both() {
        let content = generate_resolv_conf("", "");
        assert_eq!(content, "# Generated by sdme from pod DHCP lease\n");
    }

    // --- parse_lease_dns tests ---

    #[test]
    fn test_parse_lease_dns_basic() {
        let lease = "domain_name_servers=8.8.8.8 8.8.4.4\ndomain_name=example.com\n";
        let (dns, search) = parse_lease_dns(lease);
        assert_eq!(dns, "8.8.8.8 8.8.4.4");
        assert_eq!(search, "example.com");
    }

    #[test]
    fn test_parse_lease_dns_with_search() {
        let lease = "domain_name_servers=1.1.1.1\ndomain_search=corp.example.com example.com\n";
        let (dns, search) = parse_lease_dns(lease);
        assert_eq!(dns, "1.1.1.1");
        assert_eq!(search, "corp.example.com example.com");
    }

    #[test]
    fn test_parse_lease_dns_domain_name_after_search() {
        // domain_name should be appended to search domains if not already present.
        let lease = "domain_search=corp.example.com\ndomain_name=example.com\n";
        let (dns, search) = parse_lease_dns(lease);
        assert!(dns.is_empty());
        assert_eq!(search, "corp.example.com example.com");
    }

    #[test]
    fn test_parse_lease_dns_dedup() {
        // Duplicate nameservers and domains should be deduplicated.
        let lease = "domain_name_servers=8.8.8.8 8.8.8.8\n\
                     domain_search=example.com\n\
                     domain_name=example.com\n";
        let (dns, search) = parse_lease_dns(lease);
        assert_eq!(dns, "8.8.8.8");
        assert_eq!(search, "example.com");
    }

    #[test]
    fn test_parse_lease_dns_empty() {
        let (dns, search) = parse_lease_dns("");
        assert!(dns.is_empty());
        assert!(search.is_empty());
    }

    #[test]
    fn test_parse_lease_dns_no_dns_keys() {
        let lease = "ip_address=10.0.0.2\nrouters=10.0.0.1\n";
        let (dns, search) = parse_lease_dns(lease);
        assert!(dns.is_empty());
        assert!(search.is_empty());
    }

    // --- find_pod_containers tests ---

    #[test]
    fn test_find_pod_containers_empty() {
        let tmp = tmp();
        let names = find_pod_containers(tmp.path(), "mypod");
        assert!(names.is_empty());
    }

    #[test]
    fn test_find_pod_containers_matches() {
        let tmp = tmp();
        let ct_dir = tmp.path().join("state");
        fs::create_dir_all(&ct_dir).unwrap();
        fs::write(ct_dir.join("app1"), "NAME=app1\nPOD=mypod\n").unwrap();
        fs::write(ct_dir.join("app2"), "NAME=app2\nOCI_POD=mypod\n").unwrap();
        fs::write(ct_dir.join("other"), "NAME=other\nPOD=otherpod\n").unwrap();
        fs::write(ct_dir.join("plain"), "NAME=plain\n").unwrap();

        let mut names = find_pod_containers(tmp.path(), "mypod");
        names.sort();
        assert_eq!(names, vec!["app1", "app2"]);
    }
}
