//! Systemd unit template generation and dropin management.

use std::fmt::Write;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::storage::{self, Backend};
use crate::{BindConfig, EnvConfig, NetworkConfig, ResourceLimits, SecurityConfig, State};

/// Return the systemd service unit name for a container.
pub fn service_name(name: &str) -> String {
    format!("sdme@{name}.service")
}

/// Resolved paths to external programs needed for the template unit.
pub struct UnitPaths {
    /// Path to `systemd-nspawn`.
    pub nspawn: PathBuf,
    /// Path to `mount`.
    pub mount: PathBuf,
    /// Path to `umount`.
    pub umount: PathBuf,
    /// Path to `nsenter` (used when a pod provides the network namespace).
    pub nsenter: PathBuf,
}

/// Resolve the external program paths needed for the template unit.
pub fn resolve_paths() -> Result<UnitPaths> {
    use crate::system_check::find_program;
    let nspawn = find_program("systemd-nspawn")
        .context("systemd-nspawn not found; install systemd-container")?;
    let mount = find_program("mount").context("mount not found")?;
    let umount = find_program("umount").context("umount not found")?;
    let nsenter = find_program("nsenter").context("nsenter not found; install util-linux")?;
    Ok(UnitPaths {
        nspawn,
        mount,
        umount,
        nsenter,
    })
}

/// Generate the thin template unit for `sdme@.service`.
///
/// Contains only the Unit section and Service metadata. The actual
/// ExecStartPre/ExecStart/ExecStopPost commands are written per-container
/// in a drop-in file by [`write_nspawn_dropin`].
///
/// `boot_timeout` is the Rust-side wait duration in seconds. The systemd
/// `TimeoutStartSec` is set to `boot_timeout + 30` so that the Rust wait
/// loop always expires before systemd kills the container.
///
/// `systemd_version` is the host systemd major version. `DelegateSubgroup=`
/// (systemd 256+) is emitted only when supported; on older systemd it would be
/// an unknown directive. With `--keep-unit` the container lives in this unit's
/// cgroup, so `Slice=machine.slice` places it under machine.slice like the
/// reference `systemd-nspawn@.service`.
pub fn unit_template(tasks_max: u32, boot_timeout: u64, systemd_version: u32) -> String {
    let systemd_timeout = boot_timeout + 30;
    // DelegateSubgroup= landed in systemd 256. It puts the container leader in
    // <unit>/payload so machined's subgroup-aware Terminate/Kill (256+) targets
    // the payload, matching upstream. nspawn creates the split itself under
    // --keep-unit regardless, but declaring it keeps sdme byte-for-byte aligned.
    let delegate_subgroup = if systemd_version >= 256 {
        "DelegateSubgroup=supervisor\n"
    } else {
        ""
    };
    format!(
        r#"[Unit]
Description=sdme container %i
After=network.target local-fs.target systemd-machined.service dbus.service
Wants=systemd-machined.service

[Service]
Type=notify
RestartForceExitStatus=133
SuccessExitStatus=133
ExecStart=/bin/false
KillMode=mixed
Slice=machine.slice
Delegate=yes
{delegate_subgroup}TasksMax={tasks_max}
DevicePolicy=closed
DeviceAllow=/dev/net/tun rwm
DeviceAllow=char-pts rw
TimeoutStartSec={systemd_timeout}s

[Install]
WantedBy=multi-user.target
"#
    )
}

/// Escape an argument for a systemd unit file `ExecStart` line.
///
/// If the argument contains spaces, double quotes, or backslashes,
/// it is wrapped in double quotes with internal `"` and `\` escaped.
/// This follows systemd's C-style escape rules for quoted strings.
pub(super) fn escape_exec_arg(arg: &str) -> String {
    if !arg.contains([' ', '"', '\\', '\t']) {
        return arg.to_string();
    }
    let escaped = arg.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

/// Build the opt-in restart-policy `[Service]` directives for a container.
///
/// Returns `Restart=`/`RestartSec=` lines for a whitelisted systemd token, or an
/// empty vec for `no`/unset/unknown. The whitelist means a hand-edited state
/// file cannot inject arbitrary directives into the generated unit. Kept as a
/// pure function so the mapping is unit-testable without a live state file.
pub(super) fn restart_directives(policy: Option<&str>, restart_sec: u64) -> Vec<String> {
    // Only `on-failure` is supported (see cli::normalize_restart_policy for why
    // `always` is excluded). The whitelist also blocks a tampered state file
    // from injecting arbitrary directives.
    let token = match policy {
        Some("on-failure") => "on-failure",
        _ => return Vec::new(),
    };
    vec![
        format!("Restart={token}"),
        format!("RestartSec={restart_sec}s"),
    ]
}

/// Configuration for generating a per-container nspawn drop-in.
pub struct DropinConfig<'a> {
    /// Storage backend for the container root (overlay or btrfs).
    pub backend: Backend,
    /// Data directory path (e.g. `/var/lib/sdme`).
    pub datadir: &'a str,
    /// Container name.
    pub name: &'a str,
    /// The `systemd-nspawn --directory=` target: the overlay `merged` mount for
    /// overlay, or the container subvolume path for btrfs.
    pub root_dir: &'a str,
    /// For a Mode B btrfs container, the pool mount point to require before
    /// nspawn starts (`RequiresMountsFor=`). `None` for overlay and Mode A.
    pub pool_mount: Option<&'a str>,
    /// Lower directory for the root overlayfs (e.g. `/` or a rootfs path).
    pub lowerdir: &'a str,
    /// Resolved paths to mount/umount/nspawn binaries.
    pub paths: &'a UnitPaths,
    /// Arguments passed to systemd-nspawn.
    pub nspawn_args: &'a [String],
    /// Service-level directives (e.g. `AppArmorProfile=...`).
    pub service_directives: &'a [String],
    /// Per-submount overlay relative paths (e.g. `["home", "data"]`).
    pub submounts: &'a [String],
    /// Pod network namespace path. When set, nspawn is launched via
    /// `nsenter --net={path} --` so the userns is created after
    /// entering the netns (avoids the cross-userns setns restriction).
    pub pod_netns: Option<&'a str>,
}

/// Generate the per-container nspawn drop-in content.
///
/// Contains ExecStartPre (overlayfs mount), ExecStart (systemd-nspawn
/// with all arguments baked in), and ExecStopPost (unmount). Every
/// argument is explicit; no environment variable substitution needed.
pub fn nspawn_dropin(cfg: &DropinConfig<'_>) -> String {
    let mount = cfg.paths.mount.display();
    let umount = cfg.paths.umount.display();
    let nspawn = cfg.paths.nspawn.display();
    let datadir = cfg.datadir;
    let name = cfg.name;
    let lowerdir = cfg.lowerdir;

    let mut out = String::new();
    writeln!(out, "[Service]").unwrap();
    for directive in cfg.service_directives {
        writeln!(out, "{directive}").unwrap();
    }
    writeln!(out, "ExecStart=").unwrap();

    // Backend-specific root setup. Overlay mounts an overlayfs onto `merged`
    // (plus per-submount overlays for host-rootfs containers). btrfs needs no
    // root mount because the subvolume is a real directory, but in Mode B the
    // pool image must be mounted before nspawn starts.
    match cfg.backend {
        Backend::Overlay => {
            writeln!(out, "ExecStartPre={mount} -t overlay overlay \\").unwrap();
            writeln!(
                out,
                "    -o lowerdir={lowerdir},upperdir={datadir}/containers/{name}/upper,workdir={datadir}/containers/{name}/work \\"
            )
            .unwrap();
            writeln!(out, "    {datadir}/containers/{name}/merged").unwrap();

            // Per-submount overlayfs layers (best-effort, =-).
            for rel in cfg.submounts {
                writeln!(out, "ExecStartPre=-{mount} -t overlay overlay \\").unwrap();
                writeln!(
                    out,
                    "    -o lowerdir=/{rel},upperdir={datadir}/containers/{name}/submounts/{rel}/upper,workdir={datadir}/containers/{name}/submounts/{rel}/work \\"
                )
                .unwrap();
                writeln!(out, "    {datadir}/containers/{name}/merged/{rel}").unwrap();
            }
        }
        Backend::Btrfs => {
            if let Some(pool_mount) = cfg.pool_mount {
                writeln!(out, "RequiresMountsFor={pool_mount}").unwrap();
            }
        }
    }

    // When a pod provides the network namespace, launch nspawn via nsenter
    // so the netns is entered before nspawn creates its userns. This avoids
    // the kernel's cross-userns setns(CLONE_NEWNET) restriction.
    if let Some(netns) = cfg.pod_netns {
        let nsenter = cfg.paths.nsenter.display();
        writeln!(out, "ExecStart={nsenter} --net={netns} -- {nspawn} \\").unwrap();
    } else {
        writeln!(out, "ExecStart={nspawn} \\").unwrap();
    }
    writeln!(out, "    --directory={} \\", cfg.root_dir).unwrap();
    writeln!(out, "    --machine={name} \\").unwrap();
    // Register the machine against this service unit instead of letting machined
    // create a separate machine-<name>.scope. This drops the StartTransientUnit
    // call to PID 1 (the boot-storm stall point) and the second unit per
    // container, and matches systemd's own systemd-nspawn@.service. --register
    // stays on (default), so machinectl, nss-mymachines, and the machined D-Bus
    // APIs sdme relies on keep working; only the cgroup home changes to this unit.
    writeln!(out, "    --keep-unit \\").unwrap();
    for arg in cfg.nspawn_args {
        writeln!(out, "    {} \\", escape_exec_arg(arg)).unwrap();
    }
    writeln!(out, "    --boot").unwrap();

    // Unmount overlay layers in reverse order (deepest first), then the root
    // overlay. btrfs subvolumes need no teardown.
    if cfg.backend == Backend::Overlay {
        for rel in cfg.submounts.iter().rev() {
            writeln!(
                out,
                "ExecStopPost=-{umount} {datadir}/containers/{name}/merged/{rel}"
            )
            .unwrap();
        }
        writeln!(
            out,
            "ExecStopPost=-{umount} {datadir}/containers/{name}/merged"
        )
        .unwrap();
    }
    out
}

fn write_unit_if_changed(unit_path: &Path, content: &str, verbose: bool) -> Result<bool> {
    if unit_path.exists() {
        let existing = fs::read_to_string(unit_path)
            .with_context(|| format!("failed to read {}", unit_path.display()))?;
        if existing == content {
            if verbose {
                eprintln!("template unit up to date: {}", unit_path.display());
            }
            return Ok(false);
        }
        if verbose {
            eprintln!("updating template unit: {}", unit_path.display());
        }
    } else if verbose {
        eprintln!("installing template unit: {}", unit_path.display());
    }
    fs::write(unit_path, content)
        .with_context(|| format!("failed to write template unit {}", unit_path.display()))?;
    Ok(true)
}

pub(super) fn ensure_template_unit(tasks_max: u32, boot_timeout: u64, verbose: bool) -> Result<()> {
    let unit_path = Path::new("/etc/systemd/system/sdme@.service");
    // Host systemd version gates version-specific directives (DelegateSubgroup=).
    // Same parse pattern used for nspawn arg generation in write_nspawn_dropin.
    let sd_version =
        crate::system_check::parse_systemd_version(&super::systemd_version()?).unwrap_or(0);
    let content = unit_template(tasks_max, boot_timeout, sd_version);
    if write_unit_if_changed(unit_path, &content, verbose)? {
        super::dbus::daemon_reload()?;
    }
    Ok(())
}

/// Write the per-container nspawn drop-in.
///
/// Reads the container's state file and generates a drop-in with the full
/// ExecStartPre/ExecStart/ExecStopPost commands, all arguments baked in.
/// Returns the path to the drop-in file (for cleanup on failure).
pub fn write_nspawn_dropin(datadir: &Path, name: &str, verbose: bool) -> Result<PathBuf> {
    let datadir_str = datadir
        .to_str()
        .context("datadir path is not valid UTF-8")?;

    let paths = resolve_paths()?;
    if verbose {
        eprintln!("found mount: {}", paths.mount.display());
        eprintln!("found umount: {}", paths.umount.display());
        eprintln!("found systemd-nspawn: {}", paths.nspawn.display());
    }

    let state_path = datadir.join("state").join(name);
    let state = State::read_from(&state_path)?;
    let rootfs = state.rootfs();
    let lowerdir = if rootfs.is_empty() {
        "/".to_string()
    } else {
        crate::validate_name(rootfs)
            .with_context(|| format!("invalid ROOTFS value in state file: {rootfs:?}"))?;
        let path = datadir.join("fs").join(rootfs);
        path.to_str()
            .context("rootfs path is not valid UTF-8")?
            .to_string()
    };
    if verbose {
        eprintln!("lowerdir: {lowerdir}");
    }

    // Collect all nspawn arguments from state.
    let mut nspawn_args = Vec::new();

    let pod = state.get("POD").filter(|s| !s.is_empty()).map(String::from);

    let network = NetworkConfig::from_state(&state);
    let mut net_args = network.to_nspawn_args();
    // When a pod provides the network namespace:
    // 1. --private-network must be omitted; it would create a second netns
    //    inside the pod's, defeating shared networking. The pod's netns
    //    already provides equivalent isolation (loopback only).
    // 2. If the pod has DNS from its DHCP lease, write a resolv.conf into the
    //    container's upper layer and tell nspawn to leave it alone. Without
    //    this, "auto" would copy the host's stub resolver (127.0.0.53) which
    //    is unreachable from the pod's netns.
    if let Some(ref pod_name) = pod {
        net_args.retain(|a| a != "--private-network");
        let pod_state_path = datadir.join("pods").join(pod_name).join("state");
        if let Ok(ps) = crate::State::read_from(&pod_state_path) {
            if let Some(dns) = ps.get("NET_DNS") {
                let search = ps.get("NET_SEARCH").unwrap_or("");
                let content = crate::pod::generate_resolv_conf(dns, search);
                crate::pod::write_container_resolv_conf(
                    &crate::pod::ResolvConfTarget {
                        datadir,
                        container: name,
                        base: "upper",
                        verbose,
                    },
                    &content,
                )?;
                if let Some(arg) = net_args
                    .iter_mut()
                    .find(|a| a.starts_with("--resolv-conf="))
                {
                    *arg = "--resolv-conf=off".to_string();
                }
            }
        }
    }
    nspawn_args.extend(net_args);

    let userns = state.is_yes("USERNS");
    let binds = BindConfig::from_state(&state);
    nspawn_args.extend(binds.to_nspawn_args(userns));

    let envs = EnvConfig::from_state(&state);
    nspawn_args.extend(envs.to_nspawn_args());

    // OCI pod: bind-mount the pod's netns into the container so the
    // sdme-oci-{name}.service can use NetworkNamespacePath= to enter it.
    // Also write DNS resolv.conf into each OCI app's chroot if the pod
    // has external networking (same mechanism as --pod DNS).
    let oci_pod = state
        .get("OCI_POD")
        .filter(|s| !s.is_empty())
        .map(String::from);
    if let Some(ref pod_name) = oci_pod {
        crate::pod::ensure_runtime(datadir, pod_name, verbose)?;
        let netns_path = crate::pod::runtime_path(pod_name);
        nspawn_args.push(format!("--bind-ro={netns_path}:/run/sdme/oci-pod-netns"));
        if verbose {
            eprintln!("oci-pod '{pod_name}': bind-mounting netns {netns_path} into container");
        }
        // Write DNS if the pod has it and this isn't already handled by --pod above.
        if pod.is_none() && !state.is_yes("KUBE") {
            let pod_state_path = datadir.join("pods").join(pod_name).join("state");
            if let Ok(ps) = crate::State::read_from(&pod_state_path) {
                if let Some(dns) = ps.get("NET_DNS") {
                    let search = ps.get("NET_SEARCH").unwrap_or("");
                    let content = crate::pod::generate_resolv_conf(dns, search);
                    crate::pod::write_container_resolv_conf(
                        &crate::pod::ResolvConfTarget {
                            datadir,
                            container: name,
                            base: "upper",
                            verbose,
                        },
                        &content,
                    )?;
                }
            }
        }
    }

    // Security: userns, capabilities, seccomp, no-new-privileges, read-only.
    let sd_version =
        crate::system_check::parse_systemd_version(&super::systemd_version()?).unwrap_or(0);
    let security = SecurityConfig::from_state(&state);
    nspawn_args.extend(security.to_nspawn_args(sd_version));

    // Pod: entire container runs in the pod's network namespace.
    // The netns is entered via nsenter before nspawn, so nspawn creates its
    // userns (if any) after the netns is already joined. This avoids the
    // kernel's cross-userns setns(CLONE_NEWNET) restriction.
    let pod_netns = if let Some(ref pod_name) = pod {
        crate::pod::ensure_runtime(datadir, pod_name, verbose)?;
        let netns_path = crate::pod::runtime_path(pod_name);
        if verbose {
            eprintln!("pod '{pod_name}': using netns {netns_path}");
        }
        Some(netns_path)
    } else {
        None
    };

    // Service-level directives (not nspawn flags).
    let mut service_directives = Vec::new();

    // Set SYSTEMD_LOG_LEVEL for the nspawn host process (not the container).
    if let Some(level) = state.get_nonempty("SYSTEMD_LOG_LEVEL") {
        service_directives.push(format!("Environment=SYSTEMD_LOG_LEVEL={level}"));
        if verbose {
            eprintln!("nspawn host log level: {level}");
        }
    }

    if let Some(profile) = &security.apparmor_profile {
        crate::security::check_apparmor_loaded(profile)?;
        service_directives.push(format!("AppArmorProfile={profile}"));
        if verbose {
            eprintln!("apparmor profile: {profile}");
        }
    }

    // Opt-in restart policy. Emitted per container into this drop-in, never in
    // the shared template, and the start-rate limiter is left at its systemd
    // default (never disabled) so a genuinely broken container still parks in
    // `failed` instead of thrashing forever.
    let restart_sec = state
        .get("RESTART_SEC")
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(2);
    let restart = restart_directives(state.get_nonempty("RESTART_POLICY"), restart_sec);
    if verbose {
        for d in &restart {
            eprintln!("restart directive: {d}");
        }
    }
    service_directives.extend(restart);

    if verbose {
        for arg in &nspawn_args {
            eprintln!("nspawn arg: {arg}");
        }
    }

    // Detect per-submount overlayfs layers for host-rootfs containers.
    let submounts = if lowerdir == "/" {
        let subs = crate::submounts::host_submounts()?;
        if !subs.is_empty() {
            let container_dir = datadir.join("containers").join(name);
            crate::submounts::ensure_submount_dirs(&container_dir, &subs)?;
            if verbose {
                for rel in &subs {
                    eprintln!("submount: /{rel}");
                }
            }
        }
        subs
    } else {
        Vec::new()
    };

    // Resolve the nspawn root and (for Mode B btrfs) the pool mount to require.
    let backend = Backend::from_state(&state);
    let (root_dir, pool_mount) = match backend {
        Backend::Overlay => (format!("{datadir_str}/containers/{name}/merged"), None),
        Backend::Btrfs => {
            let pool_root = storage::pool::root(datadir)?;
            let root = storage::btrfs::container_root(&pool_root, name)
                .to_str()
                .context("btrfs subvolume path is not valid UTF-8")?
                .to_string();
            // Mode A (native btrfs datadir) needs no RequiresMountsFor; Mode B
            // must wait for the loopback pool to mount.
            let pool_mount = if storage::pool::is_btrfs(datadir)? {
                None
            } else {
                Some(
                    pool_root
                        .to_str()
                        .context("btrfs pool path is not valid UTF-8")?
                        .to_string(),
                )
            };
            (root, pool_mount)
        }
    };

    let content = nspawn_dropin(&DropinConfig {
        backend,
        datadir: datadir_str,
        name,
        root_dir: &root_dir,
        pool_mount: pool_mount.as_deref(),
        lowerdir: &lowerdir,
        paths: &paths,
        nspawn_args: &nspawn_args,
        service_directives: &service_directives,
        submounts: &submounts,
        pod_netns: pod_netns.as_deref(),
    });

    let dir = dropin_dir(name);
    fs::create_dir_all(&dir).with_context(|| format!("failed to create {}", dir.display()))?;

    let dropin_path = dir.join("nspawn.conf");
    if write_unit_if_changed(&dropin_path, &content, verbose)? {
        super::dbus::daemon_reload()?;
    }

    Ok(dropin_path)
}

pub(super) fn dropin_dir(name: &str) -> PathBuf {
    PathBuf::from(format!("/etc/systemd/system/sdme@{name}.service.d"))
}

/// Write or remove the resource-limits drop-in for a container.
///
/// If `limits` has any values set, writes a `limits.conf` drop-in under
/// `/etc/systemd/system/sdme@{name}.service.d/`. If no limits are set,
/// removes the drop-in (and its parent directory if empty).
/// Triggers a daemon-reload when the drop-in changes.
pub fn write_limits_dropin(name: &str, limits: &ResourceLimits, verbose: bool) -> Result<()> {
    let dir = dropin_dir(name);
    let dropin_path = dir.join("limits.conf");

    match limits.dropin_content() {
        Some(content) => {
            fs::create_dir_all(&dir)
                .with_context(|| format!("failed to create {}", dir.display()))?;
            if write_unit_if_changed(&dropin_path, &content, verbose)? {
                super::dbus::daemon_reload()?;
            }
        }
        None => {
            if dropin_path.exists() {
                fs::remove_file(&dropin_path)
                    .with_context(|| format!("failed to remove {}", dropin_path.display()))?;
                // Remove parent dir if empty.
                let _ = fs::remove_dir(&dir);
                if verbose {
                    eprintln!("removed limits drop-in: {}", dropin_path.display());
                }
                super::dbus::daemon_reload()?;
            }
        }
    }
    Ok(())
}

/// Remove the drop-in directory for a container (used during `rm`).
pub fn remove_limits_dropin(name: &str, verbose: bool) -> Result<()> {
    let dir = dropin_dir(name);
    if dir.exists() {
        fs::remove_dir_all(&dir).with_context(|| format!("failed to remove {}", dir.display()))?;
        if verbose {
            eprintln!("removed drop-in dir: {}", dir.display());
        }
        super::dbus::daemon_reload()?;
    }
    Ok(())
}
