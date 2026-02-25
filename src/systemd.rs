//! Internal API for managing interactions with systemd and D-Bus.
//!
//! Provides helpers for installing the `sdme@.service` template unit,
//! writing per-container nspawn drop-in files, and starting containers
//! via the systemd D-Bus interface.

use std::fs;
use std::path::Path;

use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::{BindConfig, EnvConfig, NetworkConfig, ResourceLimits, State};

mod dbus {
    use anyhow::{bail, Context, Result};
    use zbus::blocking::proxy::Proxy;
    use zbus::blocking::{Connection, MessageIterator};
    use zbus::MatchRule;

    pub fn connect() -> Result<Connection> {
        Connection::system().context("failed to connect to system dbus")
    }

    fn systemd_manager(conn: &Connection) -> Result<Proxy<'_>> {
        Proxy::new(
            conn,
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager",
        )
        .context("failed to create systemd manager proxy")
    }

    fn machine1_manager(conn: &Connection) -> Result<Proxy<'_>> {
        Proxy::new(
            conn,
            "org.freedesktop.machine1",
            "/org/freedesktop/machine1",
            "org.freedesktop.machine1.Manager",
        )
        .context("failed to create machine1 manager proxy")
    }

    fn is_machine_not_found(e: &zbus::Error) -> bool {
        let msg = format!("{e:#}");
        msg.contains("NoSuchMachine")
            || msg.contains("No machine")
            || msg.contains("UnknownObject")
            || msg.contains("no such object")
    }

    pub fn daemon_reload() -> Result<()> {
        let conn = connect()?;
        let proxy = systemd_manager(&conn)?;
        proxy
            .call_method("Reload", &())
            .context("systemctl daemon-reload failed")?;
        Ok(())
    }

    pub fn start_unit(unit: &str) -> Result<()> {
        let conn = connect()?;
        let proxy = systemd_manager(&conn)?;
        proxy
            .call_method("StartUnit", &(unit, "replace"))
            .with_context(|| format!("systemctl start {unit} failed"))?;
        Ok(())
    }

    pub fn is_unit_active(unit: &str) -> Result<bool> {
        let conn = connect()?;
        let manager = systemd_manager(&conn)?;
        let unit_path: zbus::zvariant::OwnedObjectPath = manager
            .call_method("GetUnit", &(unit,))
            .with_context(|| format!("failed to get unit {unit}"))?
            .body()
            .deserialize()
            .context("failed to deserialize unit path")?;
        let unit_proxy = Proxy::new(
            &conn,
            "org.freedesktop.systemd1",
            unit_path,
            "org.freedesktop.systemd1.Unit",
        )
        .context("failed to create unit proxy")?;
        let state: String = unit_proxy
            .get_property("ActiveState")
            .context("failed to read ActiveState")?;
        Ok(state == "active")
    }

    pub fn get_systemd_version() -> Result<String> {
        let conn = connect()?;
        let proxy = systemd_manager(&conn)?;
        proxy
            .get_property::<String>("Version")
            .context("failed to read systemd version")
    }

    /// Query the machine State property via org.freedesktop.machine1.
    ///
    /// Returns `None` if the machine is not registered (not found).
    /// Returns `Some(state)` where state is e.g. "opening", "running",
    /// "closing", or "abandoned".
    pub fn get_machine_state(conn: &Connection, name: &str) -> Result<Option<String>> {
        let manager = machine1_manager(conn)?;

        let reply = match manager.call_method("GetMachine", &(name,)) {
            Ok(r) => r,
            Err(e) => {
                if is_machine_not_found(&e) {
                    return Ok(None);
                }
                return Err(e).context("failed to call GetMachine");
            }
        };

        let machine_path: zbus::zvariant::OwnedObjectPath = reply
            .body()
            .deserialize()
            .context("failed to deserialize machine path")?;

        let machine_proxy = Proxy::new(
            conn,
            "org.freedesktop.machine1",
            machine_path,
            "org.freedesktop.machine1.Machine",
        )
        .context("failed to create machine proxy")?;

        // The machine may be removed between GetMachine and get_property
        // (TOCTOU race). Treat this as "not found" rather than a hard error
        // so the caller can retry.
        let state: String = match machine_proxy.get_property("State") {
            Ok(s) => s,
            Err(e) => {
                if is_machine_not_found(&e) {
                    return Ok(None);
                }
                return Err(e).context("failed to read machine State property");
            }
        };

        Ok(Some(state))
    }

    /// Subscribe to all signals from org.freedesktop.machine1.Manager.
    ///
    /// Returns an owned `MessageIterator` that yields `MachineNew` and
    /// `MachineRemoved` signals (among others). The iterator is `Send`
    /// and can be moved to another thread.
    pub fn subscribe_machine_signals(conn: &Connection) -> Result<MessageIterator> {
        let rule = MatchRule::builder()
            .msg_type(zbus::message::Type::Signal)
            .sender("org.freedesktop.machine1")?
            .interface("org.freedesktop.machine1.Manager")?
            .path("/org/freedesktop/machine1")?
            .build();
        MessageIterator::for_match_rule(rule, conn, Some(64))
            .context("failed to subscribe to machine1 signals")
    }

    /// Check whether a boot state is terminal.
    ///
    /// Returns `Ok(true)` if the container is running, `Err` if it reached
    /// a terminal failure state, or `Ok(false)` if boot is still in progress.
    fn check_boot_state(name: &str, state: &str) -> Result<bool> {
        if state == "running" {
            return Ok(true);
        }
        if state == "closing" || state == "abandoned" {
            bail!("container '{name}' failed during boot (state: {state})");
        }
        Ok(false)
    }

    /// Wait for a machine to reach the "running" state.
    ///
    /// Subscribes to `MachineNew`/`MachineRemoved` signals from
    /// `org.freedesktop.machine1.Manager`, then checks the current state.
    /// If not yet running, processes signals on a background thread:
    ///
    /// - `MachineNew` → re-check the `State` property (may still be "opening")
    /// - `MachineRemoved` → container failed, bail immediately
    ///
    /// After `MachineNew`, the state may be "opening" (boot in progress).
    /// Since `PropertiesChanged` on the machine object requires a second
    /// subscription on a different path, we fall back to periodic D-Bus
    /// property reads (sub-millisecond IPC, no process spawning) until the
    /// state transitions to "running" or a terminal state.
    pub fn wait_for_boot(name: &str, timeout: std::time::Duration, verbose: bool) -> Result<()> {
        let conn = connect()?;

        // Subscribe to manager signals BEFORE checking current state to
        // avoid missing a MachineNew/MachineRemoved that fires in between.
        let signals = subscribe_machine_signals(&conn)?;

        // Fast path: machine may already be running.
        if let Some(state) = get_machine_state(&conn, name)? {
            if verbose {
                eprintln!("container state: {state}");
            }
            if check_boot_state(name, &state)? {
                return Ok(());
            }
        }

        // Process signals on a background thread so we can apply a timeout
        // from the main thread via recv_timeout.
        let name_owned = name.to_string();
        let (tx, rx) = std::sync::mpsc::channel::<BootEvent>();

        std::thread::spawn(move || {
            for msg_result in signals {
                let msg = match msg_result {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                let member = match msg.header().member() {
                    Some(m) => m.to_string(),
                    None => continue,
                };
                let body = msg.body();
                let sig_name: String =
                    match body.deserialize::<(String, zbus::zvariant::OwnedObjectPath)>() {
                        Ok((n, _)) => n,
                        Err(_) => continue,
                    };
                if sig_name != name_owned {
                    continue;
                }
                let event = match member.as_str() {
                    "MachineNew" => BootEvent::MachineNew,
                    "MachineRemoved" => BootEvent::MachineRemoved,
                    _ => continue,
                };
                if tx.send(event).is_err() {
                    break; // receiver dropped (timeout)
                }
            }
        });

        // Main loop: wait for signals or poll state on channel timeout.
        let deadline = std::time::Instant::now() + timeout;
        let poll_interval = std::time::Duration::from_millis(500);

        loop {
            crate::check_interrupted()?;

            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                bail!(
                    "timed out waiting for container '{name}' to boot ({}s)",
                    timeout.as_secs()
                );
            }

            let wait = poll_interval.min(remaining);
            match rx.recv_timeout(wait) {
                Ok(BootEvent::MachineNew) => {
                    if verbose {
                        eprintln!("machine '{name}' registered");
                    }
                    // Machine appeared — check its state.
                    if let Some(state) = get_machine_state(&conn, name)? {
                        if verbose {
                            eprintln!("container state: {state}");
                        }
                        if check_boot_state(name, &state)? {
                            return Ok(());
                        }
                    }
                }
                Ok(BootEvent::MachineRemoved) => {
                    bail!("container '{name}' exited during boot");
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    // No signal received — poll the state via D-Bus.
                    // This handles the "opening" → "running" transition
                    // that is signaled via PropertiesChanged (which we
                    // don't subscribe to separately).
                    if let Some(state) = get_machine_state(&conn, name)? {
                        if verbose {
                            eprintln!("container state: {state}");
                        }
                        if check_boot_state(name, &state)? {
                            return Ok(());
                        }
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    bail!("signal watcher exited unexpectedly for container '{name}'");
                }
            }
        }
    }

    enum BootEvent {
        MachineNew,
        MachineRemoved,
    }

    /// Get the leader PID of a registered machine via org.freedesktop.machine1.
    ///
    /// Returns `None` if the machine is not registered.
    fn get_machine_leader(conn: &Connection, name: &str) -> Result<Option<u32>> {
        let manager = machine1_manager(conn)?;

        let reply = match manager.call_method("GetMachine", &(name,)) {
            Ok(r) => r,
            Err(e) => {
                if is_machine_not_found(&e) {
                    return Ok(None);
                }
                return Err(e).context("failed to call GetMachine");
            }
        };

        let machine_path: zbus::zvariant::OwnedObjectPath = reply
            .body()
            .deserialize()
            .context("failed to deserialize machine path")?;

        let machine_proxy = Proxy::new(
            conn,
            "org.freedesktop.machine1",
            machine_path,
            "org.freedesktop.machine1.Machine",
        )
        .context("failed to create machine proxy")?;

        let leader: u32 = machine_proxy
            .get_property("Leader")
            .context("failed to read machine Leader property")?;

        Ok(Some(leader))
    }

    /// Wait for the container's D-Bus socket to become available.
    ///
    /// After `wait_for_boot` returns, machined reports the container as
    /// "running", but the container's internal systemd may still be
    /// booting. `machinectl shell` requires the container's D-Bus
    /// socket, so we poll by attempting to connect to the container's
    /// system bus via `/proc/{leader}/root/run/dbus/system_bus_socket`
    /// (the same mechanism `busctl --machine=` uses internally) until
    /// the connection succeeds or the timeout expires.
    pub fn wait_for_dbus(name: &str, timeout: std::time::Duration, verbose: bool) -> Result<()> {
        let conn = connect()?;
        let deadline = std::time::Instant::now() + timeout;
        let poll_interval = std::time::Duration::from_millis(200);

        let leader = get_machine_leader(&conn, name)?
            .with_context(|| format!("machine '{name}' not found"))?;

        let socket_path = format!("/proc/{leader}/root/run/dbus/system_bus_socket");
        let address = format!("unix:path={socket_path}");

        if verbose {
            eprintln!("waiting for container D-Bus at {socket_path}");
        }

        loop {
            crate::check_interrupted()?;

            match zbus::blocking::connection::Builder::address(address.as_str())
                .and_then(|b| b.build())
            {
                Ok(_) => {
                    if verbose {
                        eprintln!("container '{name}' D-Bus is ready");
                    }
                    return Ok(());
                }
                Err(e) => {
                    if verbose {
                        eprintln!("container D-Bus not ready: {e}");
                    }
                }
            }

            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                bail!(
                    "timed out waiting for D-Bus in container '{name}' ({}s)",
                    timeout.as_secs()
                );
            }

            std::thread::sleep(poll_interval.min(remaining));
        }
    }

    /// Terminate a machine via org.freedesktop.machine1.
    ///
    /// Calls `TerminateMachine(name)` on the machined Manager, which
    /// sends SIGTERM to the container leader process (nspawn).
    /// nspawn handles SIGTERM by initiating a clean container shutdown.
    ///
    /// This is a non-blocking call — the machine shuts down asynchronously.
    /// Use [`wait_for_shutdown`] to wait for full shutdown.
    pub fn terminate_machine(name: &str) -> Result<()> {
        let conn = connect()?;
        let manager = machine1_manager(&conn)?;

        manager
            .call_method("TerminateMachine", &(name,))
            .with_context(|| format!("failed to terminate machine '{name}'"))?;

        Ok(())
    }

    /// List all registered machines via org.freedesktop.machine1.
    ///
    /// Returns a vector of machine names. Returns an empty vector if the
    /// call fails (e.g. machined is not running).
    pub fn list_machines() -> Vec<String> {
        fn inner() -> Result<Vec<String>> {
            let conn = connect()?;
            let manager = machine1_manager(&conn)?;
            let reply = manager.call_method("ListMachines", &())?;
            // ListMachines returns a(ssso): name, class, service, object_path
            let machines: Vec<(String, String, String, zbus::zvariant::OwnedObjectPath)> =
                reply.body().deserialize()?;
            Ok(machines.into_iter().map(|(name, _, _, _)| name).collect())
        }
        inner().unwrap_or_default()
    }

    /// Read the ActiveState property of a systemd unit.
    ///
    /// Returns the state string (e.g. "active", "inactive", "failed",
    /// "activating", "deactivating"). Returns `None` if the unit is
    /// not loaded or not found.
    fn get_unit_active_state(conn: &Connection, unit: &str) -> Option<String> {
        let manager = systemd_manager(conn).ok()?;
        let reply = manager.call_method("GetUnit", &(unit,)).ok()?;
        let unit_path: zbus::zvariant::OwnedObjectPath = reply.body().deserialize().ok()?;
        let unit_proxy = Proxy::new(
            conn,
            "org.freedesktop.systemd1",
            unit_path,
            "org.freedesktop.systemd1.Unit",
        )
        .ok()?;
        unit_proxy.get_property::<String>("ActiveState").ok()
    }

    /// Wait for a machine to fully shut down.
    ///
    /// Two-phase wait:
    ///
    /// 1. **Machine removal**: subscribes to `MachineRemoved` signal from
    ///    `org.freedesktop.machine1.Manager` and waits for the container's
    ///    machine registration to disappear. This means nspawn has exited.
    ///
    /// 2. **Unit inactive**: after the machine is gone, polls the systemd
    ///    unit's `ActiveState` until it reaches `inactive` or `failed`.
    ///    This ensures `ExecStopPost` has run (overlayfs unmounted), making
    ///    it safe to delete container files on disk.
    pub fn wait_for_shutdown(
        name: &str,
        timeout: std::time::Duration,
        verbose: bool,
    ) -> Result<()> {
        let conn = connect()?;

        // Subscribe to manager signals BEFORE checking current state.
        let signals = subscribe_machine_signals(&conn)?;

        // Fast path: machine may already be gone.
        if get_machine_state(&conn, name)?.is_none() {
            if verbose {
                eprintln!("machine '{name}' already removed");
            }
            return wait_for_unit_inactive(&conn, &super::service_name(name), timeout, verbose);
        }

        if verbose {
            eprintln!("waiting for container '{name}' to shut down...");
        }

        // Phase 1: wait for MachineRemoved.
        let name_owned = name.to_string();
        let (tx, rx) = std::sync::mpsc::channel::<()>();

        std::thread::spawn(move || {
            for msg_result in signals {
                let msg = match msg_result {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                let member = match msg.header().member() {
                    Some(m) => m.to_string(),
                    None => continue,
                };
                if member != "MachineRemoved" {
                    continue;
                }
                let body = msg.body();
                if let Ok((sig_name, _)) =
                    body.deserialize::<(String, zbus::zvariant::OwnedObjectPath)>()
                {
                    if sig_name == name_owned {
                        let _ = tx.send(());
                        break;
                    }
                }
            }
        });

        let deadline = std::time::Instant::now() + timeout;
        let poll_interval = std::time::Duration::from_millis(500);

        loop {
            crate::check_interrupted()?;

            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                bail!(
                    "timed out waiting for container '{name}' to shut down ({}s)",
                    timeout.as_secs()
                );
            }

            let wait = poll_interval.min(remaining);
            match rx.recv_timeout(wait) {
                Ok(()) => {
                    if verbose {
                        eprintln!("machine '{name}' removed");
                    }
                    break;
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    // Fallback: check if machine is already gone via D-Bus.
                    if get_machine_state(&conn, name)?.is_none() {
                        if verbose {
                            eprintln!("machine '{name}' removed");
                        }
                        break;
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    bail!("signal watcher exited unexpectedly for '{name}'");
                }
            }
        }

        // Phase 2: wait for the systemd unit to become inactive.
        // ExecStopPost (overlayfs unmount) runs after nspawn exits.
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        wait_for_unit_inactive(&conn, &super::service_name(name), remaining, verbose)
    }

    /// Poll a systemd unit's ActiveState until it reaches "inactive" or "failed".
    fn wait_for_unit_inactive(
        conn: &Connection,
        unit: &str,
        timeout: std::time::Duration,
        verbose: bool,
    ) -> Result<()> {
        let deadline = std::time::Instant::now() + timeout;
        let poll_interval = std::time::Duration::from_millis(200);

        loop {
            match get_unit_active_state(conn, unit) {
                Some(state) => {
                    if verbose {
                        eprintln!("unit state: {state}");
                    }
                    if state == "inactive" || state == "failed" {
                        return Ok(());
                    }
                }
                None => {
                    // Unit not found — treat as inactive.
                    return Ok(());
                }
            }

            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                bail!("timed out waiting for unit '{unit}' to become inactive");
            }

            std::thread::sleep(poll_interval.min(remaining));
        }
    }
}

pub fn systemd_version() -> Result<String> {
    dbus::get_systemd_version()
}

pub fn is_active(name: &str) -> Result<bool> {
    match dbus::is_unit_active(&service_name(name)) {
        Ok(active) => Ok(active),
        Err(e) => {
            let msg = format!("{e:#}");
            if msg.contains("NoSuchUnit") || msg.contains("not loaded") {
                Ok(false)
            } else {
                Err(e)
            }
        }
    }
}

pub fn wait_for_boot(name: &str, timeout: std::time::Duration, verbose: bool) -> Result<()> {
    dbus::wait_for_boot(name, timeout, verbose)
}

pub fn wait_for_dbus(name: &str, timeout: std::time::Duration, verbose: bool) -> Result<()> {
    dbus::wait_for_dbus(name, timeout, verbose)
}

/// Wait for a container to complete boot and D-Bus readiness.
///
/// Combines `wait_for_boot` and `wait_for_dbus` with shared timeout tracking.
pub fn await_boot(name: &str, timeout: std::time::Duration, verbose: bool) -> Result<()> {
    let boot_start = std::time::Instant::now();
    wait_for_boot(name, timeout, verbose)?;
    let remaining = timeout.saturating_sub(boot_start.elapsed());
    wait_for_dbus(name, remaining, verbose)?;
    Ok(())
}

pub fn terminate_machine(name: &str) -> Result<()> {
    dbus::terminate_machine(name)
}

pub fn wait_for_shutdown(name: &str, timeout: std::time::Duration, verbose: bool) -> Result<()> {
    dbus::wait_for_shutdown(name, timeout, verbose)
}

pub fn list_machines() -> Vec<String> {
    dbus::list_machines()
}

pub fn service_name(name: &str) -> String {
    format!("sdme@{name}.service")
}

pub struct UnitPaths {
    pub nspawn: PathBuf,
    pub mount: PathBuf,
    pub umount: PathBuf,
}

pub fn resolve_paths() -> Result<UnitPaths> {
    use crate::system_check::find_program;
    let nspawn = find_program("systemd-nspawn")
        .context("systemd-nspawn not found; install systemd-container")?;
    let mount = find_program("mount").context("mount not found")?;
    let umount = find_program("umount").context("umount not found")?;
    Ok(UnitPaths {
        nspawn,
        mount,
        umount,
    })
}

/// Generate the thin template unit for `sdme@.service`.
///
/// Contains only the Unit section and Service metadata. The actual
/// ExecStartPre/ExecStart/ExecStopPost commands are written per-container
/// in a drop-in file by [`write_nspawn_dropin`].
pub fn unit_template() -> String {
    r#"[Unit]
Description=sdme container %i
After=network.target local-fs.target

[Service]
Type=simple
ExecStart=/bin/false
KillMode=mixed
Delegate=yes
"#
    .to_string()
}

/// Escape an argument for a systemd unit file `ExecStart` line.
///
/// If the argument contains spaces, double quotes, or backslashes,
/// it is wrapped in double quotes with internal `"` and `\` escaped.
/// This follows systemd's C-style escape rules for quoted strings.
fn escape_exec_arg(arg: &str) -> String {
    if !arg.contains([' ', '"', '\\', '\t']) {
        return arg.to_string();
    }
    let escaped = arg.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

/// Generate the per-container nspawn drop-in content.
///
/// Contains ExecStartPre (overlayfs mount), ExecStart (systemd-nspawn
/// with all arguments baked in), and ExecStopPost (unmount). Every
/// argument is explicit — no environment variable substitution needed.
pub fn nspawn_dropin(
    datadir: &str,
    name: &str,
    lowerdir: &str,
    paths: &UnitPaths,
    nspawn_args: &[String],
) -> String {
    let mount = paths.mount.display();
    let umount = paths.umount.display();
    let nspawn = paths.nspawn.display();

    let mut lines = Vec::new();
    lines.push("[Service]".to_string());
    lines.push("ExecStart=".to_string());
    lines.push(format!("ExecStartPre={mount} -t overlay overlay \\",));
    lines.push(format!(
        "    -o lowerdir={lowerdir},upperdir={datadir}/containers/{name}/upper,workdir={datadir}/containers/{name}/work \\",
    ));
    lines.push(format!("    {datadir}/containers/{name}/merged",));
    lines.push(format!("ExecStart={nspawn} \\",));
    lines.push(format!(
        "    --directory={datadir}/containers/{name}/merged \\",
    ));
    lines.push(format!("    --machine={name} \\",));
    lines.push(format!(
        "    --bind={datadir}/containers/{name}/shared:/shared \\",
    ));

    for arg in nspawn_args {
        lines.push(format!("    {} \\", escape_exec_arg(arg)));
    }

    lines.push("    --boot".to_string());
    lines.push(format!(
        "ExecStopPost=-{umount} {datadir}/containers/{name}/merged",
    ));
    // Trailing newline.
    lines.push(String::new());

    lines.join("\n")
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

fn ensure_template_unit(verbose: bool) -> Result<()> {
    let unit_path = Path::new("/etc/systemd/system/sdme@.service");
    let content = unit_template();
    if write_unit_if_changed(unit_path, &content, verbose)? {
        dbus::daemon_reload()?;
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

    let network = NetworkConfig::from_state(&state);
    nspawn_args.extend(network.to_nspawn_args());

    let binds = BindConfig::from_state(&state);
    nspawn_args.extend(binds.to_nspawn_args());

    let envs = EnvConfig::from_state(&state);
    nspawn_args.extend(envs.to_nspawn_args());

    if verbose {
        for arg in &nspawn_args {
            eprintln!("nspawn arg: {arg}");
        }
    }

    let content = nspawn_dropin(datadir_str, name, &lowerdir, &paths, &nspawn_args);

    let dir = dropin_dir(name);
    fs::create_dir_all(&dir).with_context(|| format!("failed to create {}", dir.display()))?;

    let dropin_path = dir.join("nspawn.conf");
    if write_unit_if_changed(&dropin_path, &content, verbose)? {
        dbus::daemon_reload()?;
    }
    Ok(dropin_path)
}

fn dropin_dir(name: &str) -> PathBuf {
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
                dbus::daemon_reload()?;
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
                dbus::daemon_reload()?;
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
        dbus::daemon_reload()?;
    }
    Ok(())
}

pub fn start(datadir: &Path, name: &str, verbose: bool) -> Result<()> {
    ensure_template_unit(verbose)?;

    crate::containers::ensure_permissions(datadir, name)?;

    let nspawn_dropin_path = write_nspawn_dropin(datadir, name, verbose)?;

    // Read limits from state and write/remove the drop-in file.
    let state_path = datadir.join("state").join(name);
    let state = State::read_from(&state_path)?;
    let limits = ResourceLimits::from_state(&state);
    write_limits_dropin(name, &limits, verbose)?;

    if verbose {
        eprintln!("starting unit: {}", service_name(name));
    }
    if let Err(e) = dbus::start_unit(&service_name(name)) {
        let _ = fs::remove_file(&nspawn_dropin_path);
        return Err(e);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::containers::{create, CreateOptions};
    use crate::testutil::TempDataDir;

    fn tmp() -> TempDataDir {
        TempDataDir::new("systemd")
    }

    #[test]
    fn test_service_name() {
        assert_eq!(service_name("mybox"), "sdme@mybox.service");
    }

    fn test_paths() -> UnitPaths {
        UnitPaths {
            nspawn: PathBuf::from("/usr/bin/systemd-nspawn"),
            mount: PathBuf::from("/usr/bin/mount"),
            umount: PathBuf::from("/usr/bin/umount"),
        }
    }

    #[test]
    fn test_unit_template() {
        let template = unit_template();
        assert!(template.contains("Description=sdme container %i"));
        assert!(template.contains("Type=simple"));
        assert!(template.contains("ExecStart=/bin/false"));
        assert!(template.contains("KillMode=mixed"));
        assert!(template.contains("Delegate=yes"));
        // Template should NOT contain per-container details.
        assert!(!template.contains("EnvironmentFile"));
        assert!(!template.contains("systemd-nspawn"));
        assert!(!template.contains("overlay"));
    }

    #[test]
    fn test_nspawn_dropin_host_rootfs() {
        let paths = test_paths();
        let content = nspawn_dropin(
            "/var/lib/sdme",
            "mybox",
            "/",
            &paths,
            &["--resolv-conf=auto".to_string()],
        );
        assert!(content.contains("[Service]"));
        assert!(content.contains("ExecStart=\n"));
        assert!(content.contains("lowerdir=/,upperdir=/var/lib/sdme/containers/mybox/upper"));
        assert!(content.contains("workdir=/var/lib/sdme/containers/mybox/work"));
        assert!(content.contains("/var/lib/sdme/containers/mybox/merged"));
        assert!(content.contains("--machine=mybox"));
        assert!(content.contains("--bind=/var/lib/sdme/containers/mybox/shared:/shared"));
        assert!(content.contains("--resolv-conf=auto"));
        assert!(content.contains("--boot"));
        assert!(content.contains("/usr/bin/systemd-nspawn"));
        assert!(content.contains("/usr/bin/mount"));
        assert!(content.contains("/usr/bin/umount"));
    }

    #[test]
    fn test_nspawn_dropin_explicit_rootfs() {
        let paths = test_paths();
        let content = nspawn_dropin(
            "/var/lib/sdme",
            "ubox",
            "/var/lib/sdme/fs/ubuntu",
            &paths,
            &["--resolv-conf=auto".to_string()],
        );
        assert!(content.contains(
            "lowerdir=/var/lib/sdme/fs/ubuntu,upperdir=/var/lib/sdme/containers/ubox/upper"
        ));
    }

    #[test]
    fn test_nspawn_dropin_with_binds_and_envs() {
        let paths = test_paths();
        let args = vec![
            "--resolv-conf=auto".to_string(),
            "--bind=/data:/data".to_string(),
            "--bind-ro=/logs:/logs".to_string(),
            "--setenv=FOO=bar".to_string(),
        ];
        let content = nspawn_dropin("/var/lib/sdme", "mybox", "/", &paths, &args);
        assert!(content.contains("    --bind=/data:/data \\\n"));
        assert!(content.contains("    --bind-ro=/logs:/logs \\\n"));
        assert!(content.contains("    --setenv=FOO=bar \\\n"));
    }

    #[test]
    fn test_nspawn_dropin_escapes_spaces() {
        let paths = test_paths();
        let args = vec![
            "--resolv-conf=auto".to_string(),
            "--setenv=MSG=hello world".to_string(),
        ];
        let content = nspawn_dropin("/var/lib/sdme", "mybox", "/", &paths, &args);
        assert!(content.contains("\"--setenv=MSG=hello world\""));
    }

    #[test]
    fn test_escape_exec_arg_safe() {
        assert_eq!(escape_exec_arg("--boot"), "--boot");
        assert_eq!(escape_exec_arg("--bind=/a:/b"), "--bind=/a:/b");
    }

    #[test]
    fn test_escape_exec_arg_spaces() {
        assert_eq!(
            escape_exec_arg("--setenv=FOO=hello world"),
            "\"--setenv=FOO=hello world\""
        );
    }

    #[test]
    fn test_escape_exec_arg_quotes_and_backslashes() {
        assert_eq!(
            escape_exec_arg("--setenv=MSG=say \"hi\""),
            "\"--setenv=MSG=say \\\"hi\\\"\""
        );
        assert_eq!(
            escape_exec_arg("--setenv=PATH=C:\\foo"),
            "\"--setenv=PATH=C:\\\\foo\""
        );
    }

    #[test]
    fn test_dropin_dir_path() {
        let dir = dropin_dir("mybox");
        assert_eq!(
            dir,
            PathBuf::from("/etc/systemd/system/sdme@mybox.service.d")
        );
    }

    #[test]
    fn test_create_with_limits_state() {
        let tmp = tmp();
        let limits = crate::ResourceLimits {
            memory: Some("1G".to_string()),
            cpus: Some("2".to_string()),
            cpu_weight: Some("50".to_string()),
        };
        let opts = CreateOptions {
            name: Some("limitbox".to_string()),
            rootfs: None,
            limits,
            network: Default::default(),
            opaque_dirs: vec![],
            binds: Default::default(),
            envs: Default::default(),
        };
        create(tmp.path(), &opts, false).unwrap();

        // Verify limits are persisted in state file.
        let state = crate::State::read_from(&tmp.path().join("state/limitbox")).unwrap();
        let restored = crate::ResourceLimits::from_state(&state);
        assert_eq!(restored.memory.as_deref(), Some("1G"));
        assert_eq!(restored.cpus.as_deref(), Some("2"));
        assert_eq!(restored.cpu_weight.as_deref(), Some("50"));
    }
}
