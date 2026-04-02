//! CLI helper functions for argument parsing and validation.

use std::collections::HashSet;
use std::path::Path;
use std::sync::atomic::Ordering;

use anyhow::{bail, Context, Result};
use sdme::{
    check_interrupted, config, containers, lock, oci, pod, security, systemd, BindConfig,
    EnvConfig, NetworkConfig, ResourceLimits, SecurityConfig, INTERRUPTED,
};

// ---------------------------------------------------------------------------
// Clap Args structs (shared by create/new/kube)
// ---------------------------------------------------------------------------

/// Network configuration CLI arguments (shared by create/new).
#[derive(clap::Args, Default)]
pub(crate) struct NetworkArgs {
    /// Use private network namespace (isolated from host)
    #[arg(long)]
    pub private_network: bool,

    /// Create virtual ethernet link (implies --private-network)
    #[arg(long)]
    pub network_veth: bool,

    /// Connect to host bridge (implies --private-network)
    #[arg(long)]
    pub network_bridge: Option<String>,

    /// Join named network zone for inter-container networking (implies --private-network)
    #[arg(long)]
    pub network_zone: Option<String>,

    /// Forward port [PROTO:]HOST[:CONTAINER] (implies --private-network, repeatable).
    /// Works for external traffic; from the host use the container IP (sdme ps)
    #[arg(long = "port", short = 'p')]
    pub ports: Vec<String>,
}

/// Bind mount and environment variable CLI arguments (shared by create/new).
#[derive(clap::Args, Default)]
pub(crate) struct MountArgs {
    /// Bind mount HOST:CONTAINER[:ro] (repeatable)
    #[arg(long = "bind", short = 'b')]
    pub binds: Vec<String>,

    /// Set environment variable KEY=VALUE (repeatable)
    #[arg(long = "env", short = 'e')]
    pub envs: Vec<String>,
}

/// Security hardening CLI arguments (shared by create/new).
#[derive(clap::Args, Default)]
pub(crate) struct SecurityArgs {
    /// Enable user namespace isolation (container root != host root)
    #[arg(short = 'u', long)]
    pub userns: bool,

    /// Drop a capability (e.g. CAP_SYS_PTRACE, repeatable)
    #[arg(long = "drop-capability")]
    pub drop_caps: Vec<String>,

    /// Add a capability (e.g. CAP_NET_ADMIN, repeatable)
    #[arg(long = "capability")]
    pub add_caps: Vec<String>,

    /// Prevent gaining privileges via setuid binaries or file capabilities
    #[arg(long)]
    pub no_new_privileges: bool,

    /// Mount the container rootfs read-only
    #[arg(long)]
    pub read_only: bool,

    /// Seccomp system call filter (e.g. @system-service, ~@mount, repeatable)
    #[arg(long = "system-call-filter")]
    pub system_call_filter: Vec<String>,

    /// AppArmor profile to confine the container
    #[arg(long)]
    pub apparmor_profile: Option<String>,

    /// Enable hardened security defaults (userns, private-network, no-new-privileges,
    /// drops CAP_SYS_PTRACE, CAP_NET_RAW, CAP_SYS_RAWIO, CAP_SYS_BOOT)
    #[arg(long)]
    pub hardened: bool,

    /// Maximum security (hardened + Docker-equivalent cap drops, seccomp, AppArmor).
    /// Retains CAP_SYS_ADMIN for systemd init. Requires the sdme-default AppArmor
    /// profile to be loaded (see: sdme config apparmor-profile --help)
    #[arg(long)]
    pub strict: bool,
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

pub(crate) fn for_each_container(
    datadir: &Path,
    targets: &[String],
    verb: &str,
    past: &str,
    action: impl Fn(&str) -> Result<()>,
) -> Result<()> {
    let mut failed = false;
    for input in targets {
        check_interrupted()?;
        let name = match containers::resolve_name(datadir, input) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("error: {input}: {e}");
                failed = true;
                continue;
            }
        };
        eprintln!("{verb} '{name}'");
        if let Err(e) = action(&name) {
            eprintln!("error: {name}: {e}");
            failed = true;
        } else {
            println!("{name}");
        }
        if INTERRUPTED.load(Ordering::Relaxed) {
            break;
        }
    }
    check_interrupted()?;
    if failed {
        bail!("some containers could not be {past}");
    }
    Ok(())
}

/// Start a container and wait for it to boot.
///
/// On boot failure (or Ctrl+C), resets the interrupt flag and stops the
/// container so it doesn't linger in a half-booted state. If the container
/// is still running at timeout (e.g. slow first-boot userns chown), it is
/// left running and the user is told how to check or increase the timeout.
pub(crate) fn start_and_await_boot(
    datadir: &Path,
    name: &str,
    tasks_max: u32,
    boot_timeout: std::time::Duration,
    stop_timeout: u64,
    verbose: bool,
) -> Result<()> {
    // Hold shared lock to prevent `sdme rm` during start+boot window.
    let _lock = lock::lock_shared(datadir, "containers", name)
        .with_context(|| format!("cannot lock container '{name}' for starting"))?;
    systemd::start(&systemd::ServiceConfig {
        datadir,
        name,
        tasks_max,
        boot_timeout: boot_timeout.as_secs(),
        verbose,
    })?;
    if let Err(e) = systemd::await_boot(name, boot_timeout, verbose) {
        // Check whether the container is still alive (active or still
        // activating). If it is, the boot didn't fail: sdme just timed
        // out waiting for the readiness signal (e.g. slow first-boot
        // userns chown). Don't kill it.
        let still_alive = matches!(
            systemd::unit_active_state(name).as_deref(),
            Some("active" | "activating")
        );
        if still_alive {
            eprintln!(
                "container '{name}' is still starting but sdme timed out \
                 waiting for boot readiness ({}s)",
                boot_timeout.as_secs()
            );
            eprintln!(
                "hint: check logs with 'sdme logs {name}', or try \
                 'sdme stop {name}' then 'sdme start -t <seconds> {name}'"
            );
            return Err(e);
        }
        let _guard = sdme::InterruptGuard::save_and_reset();
        eprintln!("boot failed, stopping '{name}'");
        let _ = containers::stop(name, containers::StopMode::Terminate, stop_timeout, verbose);
        return Err(e);
    }
    Ok(())
}

/// Build a `ResourceLimits` from CLI flags (for `create` / `new`).
///
/// `None` means the flag was not provided; the limit is left unset.
pub(crate) fn parse_limits(
    memory: Option<String>,
    cpus: Option<String>,
    cpu_weight: Option<String>,
) -> Result<ResourceLimits> {
    let limits = ResourceLimits {
        memory,
        cpus,
        cpu_weight,
    };
    limits.validate()?;
    Ok(limits)
}

/// Build a `NetworkConfig` from CLI flags (for `create` / `new`).
///
/// Options that imply `--private-network` automatically enable it.
pub(crate) fn parse_network(args: NetworkArgs) -> Result<NetworkConfig> {
    // Auto-enable private_network if any option that requires it is set
    let private_network = args.private_network
        || args.network_veth
        || args.network_bridge.is_some()
        || args.network_zone.is_some()
        || !args.ports.is_empty();

    let network = NetworkConfig {
        private_network,
        network_veth: args.network_veth,
        network_bridge: args.network_bridge,
        network_zone: args.network_zone,
        ports: args.ports,
    };
    network.validate()?;
    Ok(network)
}

/// Build `BindConfig` and `EnvConfig` from CLI flags (for `create` / `new`).
pub(crate) fn parse_mounts(args: MountArgs) -> Result<(BindConfig, EnvConfig)> {
    let binds = BindConfig::from_cli_args(args.binds)?;
    binds.validate()?;
    let envs = EnvConfig { vars: args.envs };
    envs.validate()?;
    Ok((binds, envs))
}

/// Validate `--oci-env` values using the same rules as `-e`/`--env`.
pub(crate) fn validate_oci_envs(envs: Vec<String>) -> Result<Vec<String>> {
    let tmp = EnvConfig { vars: envs };
    tmp.validate()?;
    Ok(tmp.vars)
}

/// Build a `SecurityConfig` from CLI flags (for `create` / `new`).
///
/// When `--hardened` is set, merges the config's `hardened_drop_caps` with
/// any explicit flags. When `--strict` is set, applies Docker-equivalent
/// restrictions (implies `--hardened`). Explicit `--capability` and
/// `--drop-capability` flags take priority over both presets.
pub(crate) fn parse_security(
    args: SecurityArgs,
    cfg: &config::Config,
) -> Result<(SecurityConfig, bool)> {
    let mut drop_caps: Vec<String> = args
        .drop_caps
        .iter()
        .map(|c| security::normalize_cap(c))
        .collect();
    let add_caps: Vec<String> = args
        .add_caps
        .iter()
        .map(|c| security::normalize_cap(c))
        .collect();
    let mut userns = args.userns;
    let mut no_new_privileges = args.no_new_privileges;
    let mut system_call_filter = args.system_call_filter;
    let mut apparmor_profile = args.apparmor_profile;

    // --strict implies --hardened and adds Docker-equivalent restrictions.
    let strict = args.strict;
    let hardened = args.hardened || strict;

    if strict {
        userns = true;
        no_new_privileges = true;

        // Drop all caps except Docker's default set + CAP_SYS_ADMIN.
        for cap in security::STRICT_DROP_CAPS {
            let cap = cap.to_string();
            if !add_caps.contains(&cap) && !drop_caps.contains(&cap) {
                drop_caps.push(cap);
            }
        }

        // Add seccomp filters if none were explicitly provided.
        if system_call_filter.is_empty() {
            system_call_filter = security::STRICT_SYSCALL_FILTERS
                .iter()
                .map(|s| s.to_string())
                .collect();
        }

        // Set AppArmor profile if not explicitly provided.
        if apparmor_profile.is_none() {
            apparmor_profile = Some(security::STRICT_APPARMOR_PROFILE.to_string());
        }
    } else if hardened {
        userns = true;
        no_new_privileges = true;

        // Merge hardened drop_caps from config.
        let hardened_caps: Vec<String> = if cfg.hardened_drop_caps.is_empty() {
            Vec::new()
        } else {
            cfg.hardened_drop_caps
                .split(',')
                .map(|c| security::normalize_cap(c.trim()))
                .collect()
        };
        for cap in hardened_caps {
            // Don't add if user explicitly re-adds via --capability.
            if !add_caps.contains(&cap) && !drop_caps.contains(&cap) {
                drop_caps.push(cap);
            }
        }
    }

    let sec = SecurityConfig {
        userns,
        drop_caps,
        add_caps,
        no_new_privileges,
        read_only: args.read_only,
        system_call_filter,
        apparmor_profile,
    };
    sec.validate()?;
    Ok((sec, hardened))
}

/// When hardened/strict mode drops CAP_NET_RAW but the container has a network
/// interface (veth, zone, bridge), retain CAP_NET_RAW so DHCP works.
/// systemd-networkd needs raw sockets for the DHCP client.
pub(crate) fn retain_net_raw_for_dhcp(sec: &mut SecurityConfig, network: &NetworkConfig) {
    if network.has_interface() && sec.drop_caps.iter().any(|c| c == "CAP_NET_RAW") {
        sec.drop_caps.retain(|c| c != "CAP_NET_RAW");
        eprintln!("note: retaining CAP_NET_RAW for DHCP on network interface");
    }
}

/// Display distro prehook configuration, showing effective commands
/// (overrides or built-in defaults) for all configurable families.
pub(crate) fn display_distro_hooks(cfg: &config::Config) {
    use sdme::export::{builtin_export_prehook, builtin_export_vm_prehook};
    use sdme::import::builtin_import_prehook;
    use sdme::rootfs::DistroFamily;

    let families = [
        DistroFamily::Debian,
        DistroFamily::Fedora,
        DistroFamily::Arch,
        DistroFamily::Suse,
    ];

    for family in &families {
        let key = family.config_key();
        let overrides = cfg.distros.get(key);

        let (import_cmds, import_custom) = match overrides.and_then(|d| d.import_prehook.as_ref()) {
            Some(cmds) => (cmds.clone(), true),
            None => (builtin_import_prehook(family), false),
        };
        let (export_cmds, export_custom) = match overrides.and_then(|d| d.export_prehook.as_ref()) {
            Some(cmds) => (cmds.clone(), true),
            None => (builtin_export_prehook(family), false),
        };
        let (export_vm_cmds, export_vm_custom) =
            match overrides.and_then(|d| d.export_vm_prehook.as_ref()) {
                Some(cmds) => (cmds.clone(), true),
                None => (builtin_export_vm_prehook(family), false),
            };

        println!("\n[distros.{key}]");
        let tag = if import_custom { " (custom)" } else { "" };
        print!("import_prehook{tag} = ");
        print_hook_commands(&import_cmds);
        let tag = if export_custom { " (custom)" } else { "" };
        print!("export_prehook{tag} = ");
        print_hook_commands(&export_cmds);
        let tag = if export_vm_custom { " (custom)" } else { "" };
        print!("export_vm_prehook{tag} = ");
        print_hook_commands(&export_vm_cmds);
    }
}

/// Print a command list in a human-readable multi-line format.
pub(crate) fn print_hook_commands(cmds: &[String]) {
    if cmds.is_empty() {
        println!("[]");
        return;
    }
    if cmds.len() == 1 {
        println!("{:?}", cmds);
        return;
    }
    println!("[");
    for (i, cmd) in cmds.iter().enumerate() {
        let comma = if i + 1 < cmds.len() { "," } else { "" };
        println!("  {cmd:?}{comma}");
    }
    println!("]");
}

/// Extract Docker Hub credentials from config, if both user and token are set.
pub(crate) fn docker_credentials(cfg: &config::Config) -> Option<(String, String)> {
    if cfg.docker_user.is_empty() || cfg.docker_token.is_empty() {
        return None;
    }
    Some((cfg.docker_user.clone(), cfg.docker_token.clone()))
}

/// Parse the comma-separated `host_rootfs_opaque_dirs` config value into a Vec.
pub(crate) fn parse_opaque_dirs_config(s: &str) -> Vec<String> {
    if s.is_empty() {
        return Vec::new();
    }
    s.split(',').map(|p| p.trim().to_string()).collect()
}

/// Resolve opaque dirs for container creation.
///
/// If the user passed explicit `-o` flags, those take priority.
/// Otherwise, for host-rootfs containers (no `-r`), apply the config defaults.
/// For imported-rootfs containers, return an empty vec.
pub(crate) fn resolve_opaque_dirs(
    cli_dirs: Vec<String>,
    is_host_rootfs: bool,
    cfg: &config::Config,
) -> Vec<String> {
    if !cli_dirs.is_empty() {
        cli_dirs
    } else if is_host_rootfs {
        parse_opaque_dirs_config(&cfg.host_rootfs_opaque_dirs)
    } else {
        Vec::new()
    }
}

/// Resolve which systemd services to mask at create time.
///
/// If the user passed explicit `--masked-services`, use that as-is.
/// Otherwise, use the config default. When using defaults and a
/// network interface is configured (veth, zone, or bridge),
/// automatically remove `systemd-resolved.service` from the list
/// so resolved can provide DNS inside the container.
pub(crate) fn resolve_masked_services(
    cli_masked: Option<Vec<String>>,
    network: &NetworkConfig,
    cfg: &config::Config,
) -> anyhow::Result<Vec<String>> {
    let list = if let Some(explicit) = cli_masked {
        // Explicit override: use as-is (even if empty).
        explicit.into_iter().filter(|s| !s.is_empty()).collect()
    } else {
        // Config defaults.
        let mut list: Vec<String> = cfg
            .default_create_masked_services
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        // Auto-unmask resolved for containers with a network interface
        // (veth, zone, bridge) so DNS works inside the container.
        if network.network_veth
            || network.network_zone.is_some()
            || network.network_bridge.is_some()
        {
            list.retain(|s| s != "systemd-resolved.service");
        }
        list
    };
    for svc in &list {
        if svc.contains('/') || svc.contains("..") {
            anyhow::bail!("invalid masked service name: {svc:?}");
        }
    }
    Ok(list)
}

/// Auto-wire OCI port forwarding from the rootfs `/oci/ports` file.
///
/// When private network is enabled, merges OCI-declared ports into the
/// network config (skipping any already covered by user `--port` flags).
/// When using host network, prints an informational message instead.
pub(crate) fn auto_wire_oci_ports(rootfs_path: &Path, network: &mut NetworkConfig) {
    let oci_ports = oci::rootfs::read_oci_ports(rootfs_path);
    if oci_ports.is_empty() {
        return;
    }

    if network.private_network {
        // Collect container port numbers already specified by the user.
        // User ports may be "[proto:]host[:container]"; container port
        // is the last colon-separated segment (or the only one).
        let user_container_ports: HashSet<u16> = network
            .ports
            .iter()
            .filter_map(|p| p.rsplit(':').next().and_then(|s| s.parse::<u16>().ok()))
            .collect();

        let mut added = Vec::new();
        for port in &oci_ports {
            // Extract container port from "PROTO:HOST:CONTAINER"
            let container_port: Option<u16> = port.rsplit(':').next().and_then(|s| s.parse().ok());
            if let Some(cp) = container_port {
                if !user_container_ports.contains(&cp) {
                    network.ports.push(port.clone());
                    added.push(port.clone());
                }
            }
        }

        if !added.is_empty() {
            eprintln!("auto-forwarding OCI ports: {}", added.join(", "));
        }
    } else {
        // Display as "PORT/PROTO" for readability (e.g. "8080/tcp").
        let display: Vec<String> = oci_ports
            .iter()
            .filter_map(|p| {
                // Format is "PROTO:HOST:CONTAINER"; show "CONTAINER/PROTO"
                let parts: Vec<&str> = p.splitn(3, ':').collect();
                if parts.len() == 3 {
                    Some(format!("{}/{}", parts[2], parts[0]))
                } else {
                    None
                }
            })
            .collect();
        eprintln!(
            "OCI image exposes ports: {} (host network, no forwarding needed)",
            display.join(", ")
        );
    }
}

/// Read OCI volume paths from a rootfs, or return an empty vec.
///
/// Resolves the rootfs path and reads `/oci/volumes`. Prints the
/// auto-mounting message when volumes are found.
pub(crate) fn read_oci_volumes_for_rootfs(
    datadir: &Path,
    rootfs_name: Option<&str>,
    no_oci_volumes: bool,
) -> Result<Vec<String>> {
    if no_oci_volumes {
        return Ok(Vec::new());
    }
    let rootfs_name = match rootfs_name {
        Some(n) => n,
        None => return Ok(Vec::new()),
    };
    let rootfs_path = containers::resolve_rootfs(datadir, Some(rootfs_name))?;
    let volumes = oci::rootfs::read_oci_volumes(&rootfs_path);
    if !volumes.is_empty() {
        eprintln!("auto-mounting OCI volumes: {}", volumes.join(", "));
    }
    Ok(volumes)
}

/// Convert an `--oci` flag value to `Option<&str>`: empty means "auto-detect".
pub(crate) fn oci_app_explicit(s: &str) -> Option<&str> {
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Resolve the OCI app name for a container.
///
/// If `explicit` is provided, validates it against known apps and returns it.
/// Otherwise checks the state file for `OCI_APP` or `KUBE_CONTAINERS` keys,
/// then falls back to auto-detecting from the rootfs.
///
/// For kube containers with multiple apps and no explicit selection, returns
/// an error listing available container names.
pub(crate) fn resolve_oci_app_name(
    datadir: &Path,
    name: &str,
    explicit: Option<&str>,
) -> Result<String> {
    let state_path = datadir.join("state").join(name);
    if let Ok(state) = sdme::State::read_from(&state_path) {
        // If an explicit app name was given, validate it.
        if let Some(app) = explicit {
            if let Some(kube_containers) = state.get("KUBE_CONTAINERS") {
                let names: Vec<&str> = kube_containers.split(',').collect();
                if names.contains(&app) {
                    return Ok(app.to_string());
                }
                bail!(
                    "container '{app}' not found in kube pod '{name}'; available: {}",
                    kube_containers
                );
            }
            // For non-kube OCI containers, validate against OCI_APP.
            if let Some(oci_app) = state.get("OCI_APP") {
                if !oci_app.is_empty() && oci_app == app {
                    return Ok(app.to_string());
                }
            }
            // Fall back: trust the explicit name (it may exist in rootfs).
            return Ok(app.to_string());
        }

        if let Some(app) = state.get("OCI_APP") {
            if !app.is_empty() {
                return Ok(app.to_string());
            }
        }
        // For kube containers, require --oci NAME when multiple containers exist.
        if let Some(kube_containers) = state.get("KUBE_CONTAINERS") {
            let names: Vec<&str> = kube_containers
                .split(',')
                .filter(|s| !s.is_empty())
                .collect();
            if names.len() == 1 {
                return Ok(names[0].to_string());
            }
            bail!(
                "kube pod '{name}' has multiple containers: {}; use --oci NAME to select one",
                kube_containers
            );
        }
        // Fall back to auto-detection from rootfs.
        if let Some(rootfs_name) = state.get("ROOTFS") {
            if !rootfs_name.is_empty() {
                let rootfs_path = datadir.join("fs").join(rootfs_name);
                if let Some(app) = oci::rootfs::detect_oci_app_name(&rootfs_path) {
                    return Ok(app);
                }
            }
        }
    }
    bail!("cannot determine OCI app name for container '{name}'; no OCI_APP in state file and no /oci/apps/ in rootfs")
}

/// Validate `--pod` constraints before creating a container.
///
/// Checks that:
/// - The pod exists in the catalogue
/// - `--pod` is not combined with user namespace isolation (`--userns`,
///   `--hardened`). The kernel blocks `setns(CLONE_NEWNET)` from a child
///   user namespace into the pod's netns (owned by the init userns).
///   Use `--oci-pod` instead: its inner systemd drop-in joins the pod
///   netns from inside the container, avoiding the cross-userns restriction.
pub(crate) fn validate_pod_args(
    datadir: &Path,
    pod_name: Option<&str>,
    userns: bool,
) -> Result<()> {
    let pod_name = match pod_name {
        Some(n) => n,
        None => return Ok(()),
    };

    if !pod::exists(datadir, pod_name) {
        bail!("pod not found: {pod_name}");
    }

    if userns {
        bail!(
            "--pod is incompatible with user namespace isolation (--userns, --hardened);\n\
             the kernel blocks setns(CLONE_NEWNET) across user namespace boundaries.\n\
             Use --oci-pod instead, which joins the pod netns from inside the container."
        );
    }

    Ok(())
}

/// Validate `--oci-pod` constraints before creating a container.
///
/// Checks that:
/// - The pod exists in the catalogue
/// - The rootfs is an OCI app rootfs (contains an `sdme-oci-*.service` unit)
/// - Private network is enabled (required for `NetworkNamespacePath=` inside
///   the container; nspawn strips `CAP_NET_ADMIN` on host-network containers,
///   which prevents systemd from calling `setns(CLONE_NEWNET)`)
pub(crate) fn validate_oci_pod_args(
    datadir: &Path,
    oci_pod: Option<&str>,
    rootfs: Option<&str>,
    private_network: bool,
) -> Result<()> {
    let pod_name = match oci_pod {
        Some(n) => n,
        None => return Ok(()),
    };

    if !pod::exists(datadir, pod_name) {
        bail!("pod not found: {pod_name}");
    }

    if !private_network {
        bail!(
            "--oci-pod requires --private-network (or --hardened/--strict which imply it); \
             without a private network namespace, systemd-nspawn strips CAP_NET_ADMIN \
             and the inner NetworkNamespacePath= directive cannot work"
        );
    }

    // Validate that the rootfs is an OCI app rootfs.
    let rootfs_name = match rootfs {
        Some(name) => name,
        None => bail!("--oci-pod requires an OCI app rootfs (use -r/--fs)"),
    };
    let rootfs_path = datadir.join("fs").join(rootfs_name);
    // Check for any sdme-oci-*.service file.  On most distros the unit
    // lives in etc/systemd/system, but on NixOS it is placed in
    // etc/systemd/system.control because NixOS activation replaces
    // /etc/systemd/system with an immutable symlink to the Nix store
    // (see oci::app::systemd_unit_dir).  We check both directories so
    // this validation works regardless of the base distro.
    let has_oci_service = ["etc/systemd/system", "etc/systemd/system.control"]
        .iter()
        .any(|dir| {
            rootfs_path
                .join(dir)
                .read_dir()
                .ok()
                .and_then(|entries| {
                    entries.filter_map(|e| e.ok()).find(|e| {
                        let name = e.file_name();
                        let name = name.to_string_lossy();
                        name.starts_with("sdme-oci-") && name.ends_with(".service")
                    })
                })
                .is_some()
        });
    if !has_oci_service {
        bail!(
            "--oci-pod requires an OCI app rootfs; \
             '{rootfs_name}' does not contain an sdme-oci-*.service unit"
        );
    }

    Ok(())
}

/// Validate `--oci-pod` constraints for kube commands.
///
/// Simplified version of `validate_oci_pod_args` for kube: skips the rootfs
/// OCI service check since kube always creates OCI services during build.
/// Only checks that the pod exists.
pub(crate) fn validate_kube_oci_pod_args(datadir: &Path, oci_pod: Option<&str>) -> Result<()> {
    let pod_name = match oci_pod {
        Some(n) => n,
        None => return Ok(()),
    };

    if !pod::exists(datadir, pod_name) {
        bail!("pod not found: {pod_name}");
    }

    Ok(())
}
