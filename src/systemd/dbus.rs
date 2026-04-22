//! D-Bus communication with systemd and machined.

use anyhow::{bail, Context, Result};
use zbus::blocking::proxy::Proxy;
use zbus::blocking::{Connection, MessageIterator};
use zbus::MatchRule;

/// Marker error indicating a boot/dbus wait timed out (container may still
/// be alive). Attached via `context()` so `await_boot` can downcast to
/// distinguish timeout from container exit.
#[derive(Debug)]
pub(super) struct BootTimeout;

impl std::fmt::Display for BootTimeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("boot timeout")
    }
}

impl std::error::Error for BootTimeout {}

pub(super) fn connect() -> Result<Connection> {
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

pub(super) fn daemon_reload() -> Result<()> {
    let conn = connect()?;
    let proxy = systemd_manager(&conn)?;
    proxy
        .call_method("Reload", &())
        .context("systemctl daemon-reload failed")?;
    Ok(())
}

pub(super) fn start_unit(unit: &str) -> Result<()> {
    let conn = connect()?;
    let proxy = systemd_manager(&conn)?;
    proxy
        .call_method("StartUnit", &(unit, "replace"))
        .with_context(|| format!("systemctl start {unit} failed"))?;
    Ok(())
}

pub(super) fn enable_unit(unit: &str) -> Result<()> {
    let conn = connect()?;
    let proxy = systemd_manager(&conn)?;
    proxy
        .call_method("EnableUnitFiles", &(vec![unit], false, false))
        .with_context(|| format!("systemctl enable {unit} failed"))?;
    Ok(())
}

pub(super) fn disable_unit(unit: &str) -> Result<()> {
    let conn = connect()?;
    let proxy = systemd_manager(&conn)?;
    proxy
        .call_method("DisableUnitFiles", &(vec![unit], false))
        .with_context(|| format!("systemctl disable {unit} failed"))?;
    Ok(())
}

pub(super) fn is_unit_active(unit: &str) -> Result<bool> {
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

/// Return the ActiveState string for a systemd unit via a new connection.
///
/// Public wrapper around the private `get_unit_active_state` used
/// internally by `wait_for_shutdown`.
pub(super) fn pub_get_unit_active_state(unit: &str) -> Option<String> {
    let conn = connect().ok()?;
    get_unit_active_state(&conn, unit)
}

pub(super) fn get_systemd_version() -> Result<String> {
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
pub(super) fn get_machine_state(conn: &Connection, name: &str) -> Result<Option<String>> {
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
pub(super) fn subscribe_machine_signals(conn: &Connection) -> Result<MessageIterator> {
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
/// - `MachineNew`: re-check the `State` property (may still be "opening")
/// - `MachineRemoved`: container failed, bail immediately
///
/// After `MachineNew`, the state may be "opening" (boot in progress).
/// Since `PropertiesChanged` on the machine object requires a second
/// subscription on a different path, we fall back to periodic D-Bus
/// property reads (sub-millisecond IPC, no process spawning) until the
/// state transitions to "running" or a terminal state.
pub(super) fn wait_for_boot(name: &str, timeout: std::time::Duration, verbose: bool) -> Result<()> {
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
            return Err(anyhow::anyhow!(
                "timed out waiting for container '{name}' to boot ({}s)",
                timeout.as_secs()
            )
            .context(BootTimeout));
        }

        let wait = poll_interval.min(remaining);
        match rx.recv_timeout(wait) {
            Ok(BootEvent::MachineNew) => {
                if verbose {
                    eprintln!("machine '{name}' registered");
                }
                // Machine appeared; check its state.
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
                // No signal received; poll the state via D-Bus.
                // This handles the "opening" -> "running" transition
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
pub(super) fn get_machine_leader(conn: &Connection, name: &str) -> Result<Option<u32>> {
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
/// socket, so we poll until the connection succeeds or the timeout
/// expires.
///
/// For standard containers we connect directly from the host via
/// `/proc/{leader}/root/run/dbus/system_bus_socket` using zbus.
///
/// For `--userns` containers we use `busctl --machine=` instead.
/// Direct access fails because (a) the kernel blocks
/// `/proc/{leader}/root/` traversal across user namespace boundaries,
/// and (b) `SO_PEERCRED` returns the overflow UID (65534) causing
/// EXTERNAL auth rejection. Doing `setns(CLONE_NEWUSER)` in-process
/// is not an option either: the kernel requires a single-threaded
/// caller and zbus has already spawned background threads by this
/// point. `busctl` handles all of this internally (it forks a helper
/// child via `bus_container_connect_socket()`).
pub(super) fn wait_for_dbus(name: &str, timeout: std::time::Duration, verbose: bool) -> Result<()> {
    let conn = connect()?;
    let deadline = std::time::Instant::now() + timeout;
    let poll_interval = std::time::Duration::from_millis(200);

    let leader =
        get_machine_leader(&conn, name)?.with_context(|| format!("machine '{name}' not found"))?;

    // Detect whether the container has its own user namespace.
    let uses_userns = has_foreign_userns(leader);

    if verbose {
        if uses_userns {
            eprintln!("waiting for container D-Bus via busctl --machine={name} (userns)");
        } else {
            eprintln!(
                "waiting for container D-Bus at /proc/{leader}/root/run/dbus/system_bus_socket"
            );
        }
    }

    loop {
        crate::check_interrupted()?;

        let ready = if uses_userns {
            // Why busctl instead of zbus for userns containers:
            //
            // We can't connect to the container's D-Bus socket directly
            // from the host because:
            // 1. /proc/{leader}/root/ traversal is blocked by the kernel
            //    when the container has a foreign user namespace.
            // 2. Even with a reachable socket, SO_PEERCRED returns UID
            //    65534 (nobody/overflow) since host UID 0 has no mapping
            //    in the container's userns, so EXTERNAL auth is rejected.
            //
            // The natural fix would be setns(CLONE_NEWUSER) to enter the
            // container's user namespace before connecting, but the kernel
            // requires the calling process to be single-threaded for
            // setns(CLONE_NEWUSER) (returns EINVAL otherwise). By this
            // point, zbus has spawned internal threads for the host D-Bus
            // connection used in wait_for_boot, so in-process setns is
            // impossible.
            //
            // busctl solves this: its --machine= flag uses systemd's
            // bus_container_connect_socket(), which forks a single-threaded
            // child to do the setns + socket connect. We just exec busctl
            // and check the exit code.
            std::process::Command::new("busctl")
                .arg(format!("--machine={name}"))
                .arg("list")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        } else {
            let address = format!("unix:path=/proc/{leader}/root/run/dbus/system_bus_socket");
            zbus::blocking::connection::Builder::address(address.as_str())
                .and_then(|b| b.build())
                .is_ok()
        };

        if ready {
            if verbose {
                eprintln!("container '{name}' D-Bus is ready");
            }
            return Ok(());
        } else if verbose {
            eprintln!("container D-Bus not ready");
        }

        // Detect early container exit so we don't poll until timeout.
        if !std::path::Path::new(&format!("/proc/{leader}")).exists() {
            bail!("container '{name}' exited during boot");
        }

        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(anyhow::anyhow!(
                "timed out waiting for D-Bus in container '{name}' ({}s)",
                timeout.as_secs()
            )
            .context(BootTimeout));
        }

        std::thread::sleep(poll_interval.min(remaining));
    }
}

/// Check whether the container leader has a different user namespace
/// than the host (i.e., the container was started with `--userns`).
pub(super) fn has_foreign_userns(leader: u32) -> bool {
    use std::os::unix::fs::MetadataExt;
    let host_ino = match std::fs::metadata("/proc/self/ns/user") {
        Ok(m) => m.ino(),
        Err(_) => return false,
    };
    let container_ino = match std::fs::metadata(format!("/proc/{leader}/ns/user")) {
        Ok(m) => m.ino(),
        Err(_) => return false,
    };
    host_ino != container_ino
}

/// Terminate a machine via org.freedesktop.machine1.
///
/// Calls `TerminateMachine(name)` on the machined Manager, which
/// sends SIGTERM to the container leader process (nspawn).
/// nspawn handles SIGTERM by initiating a clean container shutdown.
///
/// This is a non-blocking call; the machine shuts down asynchronously.
/// Use [`wait_for_shutdown`] to wait for full shutdown.
pub(super) fn terminate_machine(name: &str) -> Result<()> {
    let conn = connect()?;
    let manager = machine1_manager(&conn)?;

    manager
        .call_method("TerminateMachine", &(name,))
        .with_context(|| format!("failed to terminate machine '{name}'"))?;

    Ok(())
}

/// Send a signal to a machine via org.freedesktop.machine1.
///
/// Calls `KillMachine(name, who, signal)` on the machined Manager.
/// `who` is either `"leader"` (just the init process) or `"all"`
/// (every process in the machine). `signal` is the signal number.
///
/// This is a non-blocking call; the machine shuts down asynchronously.
/// Use [`wait_for_shutdown`] to wait for full shutdown.
pub(super) fn kill_machine(name: &str, who: &str, signal: i32) -> Result<()> {
    let conn = connect()?;
    let manager = machine1_manager(&conn)?;

    manager
        .call_method("KillMachine", &(name, who, signal))
        .with_context(|| format!("failed to kill machine '{name}'"))?;

    Ok(())
}

/// List all registered machines via org.freedesktop.machine1.
///
/// Returns a vector of machine names. Returns an empty vector if the
/// call fails (e.g. machined is not running).
pub(super) fn list_machines() -> Vec<String> {
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

/// Query IP addresses assigned to a container via machined D-Bus.
///
/// Calls `GetAddresses` on the `org.freedesktop.machine1.Machine`
/// interface. Returns human-readable IP strings. Link-local IPv6
/// addresses (`fe80::`) are filtered out. Returns an empty vector
/// if the machine is not registered or the call fails.
pub(super) fn get_machine_addresses(name: &str) -> Vec<String> {
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn inner(name: &str) -> Result<Vec<String>> {
        let conn = connect()?;
        let manager = machine1_manager(&conn)?;

        let reply = match manager.call_method("GetMachine", &(name,)) {
            Ok(r) => r,
            Err(e) => {
                if is_machine_not_found(&e) {
                    return Ok(Vec::new());
                }
                return Err(e).context("failed to call GetMachine");
            }
        };

        let machine_path: zbus::zvariant::OwnedObjectPath = reply
            .body()
            .deserialize()
            .context("failed to deserialize machine path")?;

        let machine_proxy = Proxy::new(
            &conn,
            "org.freedesktop.machine1",
            machine_path,
            "org.freedesktop.machine1.Machine",
        )
        .context("failed to create machine proxy")?;

        let reply = machine_proxy
            .call_method("GetAddresses", &())
            .context("failed to call GetAddresses")?;

        // GetAddresses returns a(iay): address_family, address_bytes.
        let addrs: Vec<(i32, Vec<u8>)> = reply
            .body()
            .deserialize()
            .context("failed to deserialize addresses")?;

        let mut result = Vec::new();
        for (family, bytes) in addrs {
            match family {
                2 if bytes.len() == 4 => {
                    // AF_INET
                    let ip = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
                    result.push(ip.to_string());
                }
                10 if bytes.len() == 16 => {
                    // AF_INET6: skip link-local (fe80::/10)
                    let octets: [u8; 16] = bytes.try_into().expect("length already checked");
                    let ip = Ipv6Addr::from(octets);
                    if (ip.segments()[0] & 0xffc0) != 0xfe80 {
                        result.push(ip.to_string());
                    }
                }
                _ => {}
            }
        }
        Ok(result)
    }
    inner(name).unwrap_or_default()
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
pub(super) fn wait_for_shutdown(
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
        return wait_for_unit_inactive(&conn, &super::units::service_name(name), timeout, verbose);
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
    wait_for_unit_inactive(&conn, &super::units::service_name(name), remaining, verbose)
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
        crate::check_interrupted()?;

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
                // Unit not found; treat as inactive.
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
