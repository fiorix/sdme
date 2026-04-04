//! Pod network namespace management.
//!
//! A pod is a shared network namespace that multiple containers can join,
//! so their processes see the same localhost. This enables patterns like
//! "database :5432 + app :8080, reachable via 127.0.0.1".
//!
//! **State (persistent):** `{datadir}/pods/{name}/state` (KEY=VALUE file).
//! **Runtime (volatile):** `/run/sdme/pods/{name}/netns`: bind-mount of the
//! network namespace fd. Disappears on reboot; lazily recreated by
//! [`ensure_runtime`] when a container references the pod.

use std::ffi::CString;
use std::fmt;
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

/// Content of the dhcpcd template unit. `%i` is the pod name, resolved by systemd.
const DHCP_TEMPLATE_UNIT: &str = "\
[Unit]
Description=DHCP client for sdme pod %i

[Service]
NetworkNamespacePath=/run/sdme/pods/%i/netns
ExecStart=/usr/bin/dhcpcd -B host0
Type=forking
";

/// Linux IFNAMSIZ limit (including null terminator). Interface names are at most 15 bytes.
const IFNAMSIZ: usize = 15;

/// Network attach mode for a pod.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetMode {
    /// Point-to-point veth between pod and host.
    Veth,
    /// Veth connected to a shared zone bridge.
    Zone,
}

impl NetMode {
    /// Parse from the state file value.
    pub fn from_str(s: &str) -> Option<Self> {
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
/// Veth mode: `ve-{pod}`. Zone mode: `vb-{pod}`.
/// Truncated to 15 characters (IFNAMSIZ - 1 for the null terminator).
pub fn host_iface_name(pod_name: &str, mode: NetMode) -> String {
    let prefix = match mode {
        NetMode::Veth => "ve-",
        NetMode::Zone => "vb-",
    };
    let mut name = format!("{prefix}{pod_name}");
    name.truncate(IFNAMSIZ);
    name
}

/// Write the dhcpcd systemd template unit to `/run/systemd/system/`.
///
/// Idempotent: skips the write if the file already has the correct content.
/// Returns true if the file was written (daemon-reload needed), false if skipped.
fn write_dhcp_template_unit(verbose: bool) -> Result<bool> {
    if let Ok(existing) = fs::read_to_string(DHCP_TEMPLATE_UNIT_PATH) {
        if existing == DHCP_TEMPLATE_UNIT {
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
    fs::write(DHCP_TEMPLATE_UNIT_PATH, DHCP_TEMPLATE_UNIT)
        .context("failed to write dhcp template unit")?;
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
/// Does not return an error; failures are silent (used for EEXIST-style checks).
fn run_cmd_ok(program: &str, args: &[&str], verbose: bool) -> bool {
    if verbose {
        eprintln!("running: {program} {}", args.join(" "));
    }
    Command::new(program)
        .args(args)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Information about a listed pod.
pub struct PodInfo {
    /// Pod name.
    pub name: String,
    /// Human-readable creation timestamp.
    pub created: String,
    /// Whether the pod's network namespace is currently active.
    pub active: bool,
    /// Network attach mode, if external connectivity is configured.
    pub net_mode: Option<NetMode>,
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
        let (created, net_mode) = match State::read_from(&state_path) {
            Ok(s) => {
                let created = s.get("CREATED").unwrap_or("").to_string();
                let net_mode = s.get("NET_MODE").and_then(NetMode::from_str);
                (created, net_mode)
            }
            Err(_) => (String::new(), None),
        };

        let runtime_path = Path::new(RUNTIME_DIR).join(&name).join("netns");
        let active = runtime_path.exists();

        entries.push(PodInfo {
            name,
            created,
            active,
            net_mode,
        });
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(entries)
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
    if !force {
        let ct_state_dir = datadir.join("state");
        if ct_state_dir.is_dir() {
            for entry in fs::read_dir(&ct_state_dir)? {
                let entry = entry?;
                if !entry.file_type()?.is_file() {
                    continue;
                }
                let ct_name = entry.file_name().to_string_lossy().to_string();
                let ct_state_path = ct_state_dir.join(&ct_name);
                if let Ok(state) = State::read_from(&ct_state_path) {
                    let is_referenced =
                        state.get("POD") == Some(name) || state.get("OCI_POD") == Some(name);
                    if is_referenced {
                        bail!(
                            "pod '{name}' is referenced by container '{ct_name}'; \
                             remove the container first or use --force"
                        );
                    }
                }
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
    let mode = match NetMode::from_str(&mode_str) {
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

    // Check dependencies.
    crate::system_check::find_program("ip").context("ip not found; install iproute2")?;
    crate::system_check::find_program("dhcpcd").context("dhcpcd not found; install dhcpcd")?;

    let host_iface = host_iface_name(name, mode);
    let netns_path = runtime_path(name);

    // Cleanup guard: if anything fails after creating the veth, delete it.
    let mut veth_created = false;
    let mut dhcp_started = false;

    let result = (|| -> Result<()> {
        match mode {
            NetMode::Zone => {
                let zone_name = zone.expect("zone name required for zone mode");
                let bridge = format!("vz-{zone_name}");

                // Create bridge if it does not exist (ignore EEXIST).
                if !run_cmd_ok("ip", &["link", "show", &bridge], false) {
                    run_cmd("ip", &["link", "add", &bridge, "type", "bridge"], verbose)
                        .with_context(|| format!("failed to create bridge {bridge}"))?;
                    run_cmd("ip", &["link", "set", &bridge, "up"], verbose)?;
                }

                // Create veth pair.
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

                // Connect host end to bridge.
                run_cmd(
                    "ip",
                    &["link", "set", &host_iface, "master", &bridge],
                    verbose,
                )?;
            }
            NetMode::Veth => {
                // Create veth pair.
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
            }
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
        run_cmd(
            "nsenter",
            &["--net", &netns_path, "ip", "link", "set", "host0", "up"],
            verbose,
        )?;

        // Write the dhcpcd template unit (idempotent) and daemon-reload if needed.
        if write_dhcp_template_unit(verbose)? {
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

    // Update persistent state.
    state.set("NET_MODE", &mode.to_string());
    state.set("NET_HOST_IFACE", &host_iface);
    if let Some(zone_name) = zone {
        state.set("NET_ZONE", zone_name);
    }
    state
        .write_to(&state_path)
        .context("failed to write pod state after net attach")?;

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

    // Clear networking state.
    state.remove("NET_MODE");
    state.remove("NET_HOST_IFACE");
    state.remove("NET_ZONE");
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
        assert_eq!(NetMode::from_str("veth"), Some(NetMode::Veth));
        assert_eq!(NetMode::from_str("zone"), Some(NetMode::Zone));
        assert_eq!(NetMode::from_str("bridge"), None);
        assert_eq!(NetMode::from_str(""), None);
    }

    #[test]
    fn test_net_mode_display() {
        assert_eq!(NetMode::Veth.to_string(), "veth");
        assert_eq!(NetMode::Zone.to_string(), "zone");
    }

    // --- host_iface_name tests ---

    #[test]
    fn test_host_iface_name_veth_short() {
        assert_eq!(host_iface_name("mypod", NetMode::Veth), "ve-mypod");
    }

    #[test]
    fn test_host_iface_name_zone_short() {
        assert_eq!(host_iface_name("mypod", NetMode::Zone), "vb-mypod");
    }

    #[test]
    fn test_host_iface_name_truncation() {
        // "ve-" (3) + 12 chars = 15 = IFNAMSIZ
        assert_eq!(
            host_iface_name("averylongpodname", NetMode::Veth),
            "ve-averylongpod"
        );
        assert_eq!(
            host_iface_name("averylongpodname", NetMode::Veth).len(),
            IFNAMSIZ
        );
    }

    #[test]
    fn test_host_iface_name_exact_limit() {
        // "ve-" (3) + 12 chars = exactly 15
        assert_eq!(
            host_iface_name("123456789012", NetMode::Veth),
            "ve-123456789012"
        );
        assert_eq!(
            host_iface_name("123456789012", NetMode::Veth).len(),
            IFNAMSIZ
        );
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
            "CREATED=1234\nNET_MODE=veth\nNET_HOST_IFACE=ve-mypod\n",
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

    // --- list with net_mode ---

    #[test]
    fn test_list_with_net_mode() {
        let tmp = tmp();
        let state_dir = tmp.path().join(STATE_SUBDIR);

        let alpha_dir = state_dir.join("alpha");
        fs::create_dir_all(&alpha_dir).unwrap();
        fs::write(
            alpha_dir.join("state"),
            "CREATED=1000\nNET_MODE=veth\nNET_HOST_IFACE=ve-alpha\n",
        )
        .unwrap();

        let beta_dir = state_dir.join("beta");
        fs::create_dir_all(&beta_dir).unwrap();
        fs::write(beta_dir.join("state"), "CREATED=2000\n").unwrap();

        let gamma_dir = state_dir.join("gamma");
        fs::create_dir_all(&gamma_dir).unwrap();
        fs::write(
            gamma_dir.join("state"),
            "CREATED=3000\nNET_MODE=zone\nNET_ZONE=myzone\nNET_HOST_IFACE=vb-gamma\n",
        )
        .unwrap();

        let pods = list(tmp.path()).unwrap();
        assert_eq!(pods.len(), 3);

        assert_eq!(pods[0].name, "alpha");
        assert_eq!(pods[0].net_mode, Some(NetMode::Veth));

        assert_eq!(pods[1].name, "beta");
        assert_eq!(pods[1].net_mode, None);

        assert_eq!(pods[2].name, "gamma");
        assert_eq!(pods[2].net_mode, Some(NetMode::Zone));
    }
}
