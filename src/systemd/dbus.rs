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

/// systemd's typed D-Bus error name for a unit that is not loaded.
const NO_SUCH_UNIT_ERROR: &str = "org.freedesktop.systemd1.NoSuchUnit";

/// Standard D-Bus error for a call on an object path that does not exist.
/// A unit object path disappears when systemd collects an inactive unit.
const UNKNOWN_OBJECT_ERROR: &str = "org.freedesktop.DBus.Error.UnknownObject";

/// Whether a D-Bus error reply carries the given typed error name.
///
/// Only the error name is matched, never the free-form message text: a
/// message that merely mentions an absent unit (for example a permission
/// error quoting the unit name) is not evidence that the unit is gone.
fn error_name_is(e: &zbus::Error, name: &str) -> bool {
    matches!(e, zbus::Error::MethodError(n, _, _) if n.as_str() == name)
}

pub(crate) fn daemon_reload() -> Result<()> {
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

/// Issue a systemd `StopUnit` job for a unit (equivalent to `systemctl stop`).
///
/// Unlike the machined `TerminateMachine`/`KillMachine` calls, this creates a
/// real stop job on the unit, so systemd treats the shutdown as intentional and
/// suppresses any `Restart=` policy, cancelling a pending auto-restart.
pub(super) fn stop_unit(unit: &str) -> Result<()> {
    let conn = connect()?;
    let proxy = systemd_manager(&conn)?;
    proxy
        .call_method("StopUnit", &(unit, "replace"))
        .with_context(|| format!("systemctl stop {unit} failed"))?;
    Ok(())
}

/// Clear the failed state of a unit (equivalent to `systemctl reset-failed`).
pub(super) fn reset_failed(unit: &str) -> Result<()> {
    let conn = connect()?;
    let proxy = systemd_manager(&conn)?;
    proxy
        .call_method("ResetFailedUnit", &(unit,))
        .with_context(|| format!("systemctl reset-failed {unit} failed"))?;
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
/// internally by `wait_for_shutdown`. `Ok(None)` means systemd confirmed
/// the unit does not exist; `Err` means the state could not be
/// determined.
pub(super) fn pub_get_unit_active_state(unit: &str) -> Result<Option<String>> {
    let conn = connect()?;
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
/// Returns `Ok(Some(state))` with the state string (e.g. "active",
/// "inactive", "failed", "activating", "deactivating") when the unit is
/// loaded. Returns `Ok(None)` only when systemd confirms the unit does
/// not exist (a typed `NoSuchUnit` error). Every other failure
/// (connection, method, reply-decoding, proxy, or property error) is an
/// `Err`, so destructive callers can distinguish "confirmed absent" from
/// "could not determine".
fn get_unit_active_state(conn: &Connection, unit: &str) -> Result<Option<String>> {
    let manager = systemd_manager(conn)?;
    let reply = match manager.call_method("GetUnit", &(unit,)) {
        Ok(r) => r,
        Err(e) => {
            if error_name_is(&e, NO_SUCH_UNIT_ERROR) {
                return Ok(None);
            }
            return Err(e).with_context(|| format!("failed to query unit {unit}"));
        }
    };
    let unit_path: zbus::zvariant::OwnedObjectPath = reply
        .body()
        .deserialize()
        .with_context(|| format!("failed to decode GetUnit reply for {unit}"))?;
    let unit_proxy = Proxy::new(
        conn,
        "org.freedesktop.systemd1",
        unit_path,
        "org.freedesktop.systemd1.Unit",
    )
    .with_context(|| format!("failed to create unit proxy for {unit}"))?;
    match unit_proxy.get_property::<String>("ActiveState") {
        Ok(state) => Ok(Some(state)),
        Err(e) => {
            // The unit may have been collected between GetUnit and the
            // property read, which removes its object path. Treat that as
            // confirmed absence only when a fresh GetUnit agrees; any
            // other property error leaves the state unknown.
            if error_name_is(&e, NO_SUCH_UNIT_ERROR) || error_name_is(&e, UNKNOWN_OBJECT_ERROR) {
                if let Err(confirm) = manager.call_method("GetUnit", &(unit,)) {
                    if error_name_is(&confirm, NO_SUCH_UNIT_ERROR) {
                        return Ok(None);
                    }
                }
            }
            Err(e).with_context(|| format!("failed to read ActiveState of unit {unit}"))
        }
    }
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
///
/// Fails if the machine or unit state cannot be determined (bus or query
/// error); uncertainty is never treated as a completed shutdown.
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
    wait_until_unit_inactive(unit, timeout, verbose, || get_unit_active_state(conn, unit))
}

/// Poll `query` until the unit is confirmed inactive, failed, or absent.
///
/// A failed query is an error, never success: callers use this result to
/// decide whether filesystem teardown may begin, and an undetermined
/// state is not proof that nspawn and ExecStopPost have finished. In
/// particular, a failed query after an earlier successful one aborts the
/// wait rather than completing it.
fn wait_until_unit_inactive(
    unit: &str,
    timeout: std::time::Duration,
    verbose: bool,
    mut query: impl FnMut() -> Result<Option<String>>,
) -> Result<()> {
    let deadline = std::time::Instant::now() + timeout;
    let poll_interval = std::time::Duration::from_millis(200);

    loop {
        crate::check_interrupted()?;

        match query().with_context(|| format!("failed to determine the state of unit {unit}"))? {
            Some(state) => {
                if verbose {
                    eprintln!("unit state: {state}");
                }
                if state == "inactive" || state == "failed" {
                    return Ok(());
                }
            }
            // systemd confirmed the unit is gone.
            None => return Ok(()),
        }

        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            bail!("timed out waiting for unit '{unit}' to become inactive");
        }

        std::thread::sleep(poll_interval.min(remaining));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    // ---- typed error-name classification ----

    /// Build the zbus error a client would receive for an error reply with
    /// the given typed name and free-form detail text.
    fn dbus_error_reply(error_name: &str, detail: &str) -> zbus::Error {
        let call = zbus::Message::method_call("/org/freedesktop/systemd1", "GetUnit")
            .unwrap()
            .build(&("sdme@test.service",))
            .unwrap();
        let reply = zbus::Message::error(&call.header(), error_name)
            .unwrap()
            .build(&detail.to_string())
            .unwrap();
        zbus::Error::from(reply)
    }

    #[test]
    fn test_error_name_matches_no_such_unit() {
        let e = dbus_error_reply(NO_SUCH_UNIT_ERROR, "Unit sdme@test.service not loaded.");
        assert!(error_name_is(&e, NO_SUCH_UNIT_ERROR));
        assert!(!error_name_is(&e, UNKNOWN_OBJECT_ERROR));
    }

    #[test]
    fn test_error_name_matches_unknown_object() {
        let e = dbus_error_reply(UNKNOWN_OBJECT_ERROR, "Unknown object '/org/x'.");
        assert!(error_name_is(&e, UNKNOWN_OBJECT_ERROR));
        assert!(!error_name_is(&e, NO_SUCH_UNIT_ERROR));
    }

    #[test]
    fn test_absent_phrase_in_message_text_is_not_absence() {
        // A permission error whose detail text mentions an absent unit
        // must not be treated as confirmation that the unit is gone.
        let e = dbus_error_reply(
            "org.freedesktop.DBus.Error.AccessDenied",
            "Permission denied reading NoSuchUnit sdme@test.service",
        );
        assert!(!error_name_is(&e, NO_SUCH_UNIT_ERROR));
        assert!(!error_name_is(&e, UNKNOWN_OBJECT_ERROR));
        // Non-reply errors (transport, handshake, ...) never match either.
        let io = zbus::Error::InputOutput(std::sync::Arc::new(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "NoSuchUnit",
        )));
        assert!(!error_name_is(&io, NO_SUCH_UNIT_ERROR));
    }

    // ---- injected shutdown waits ----

    /// Script a sequence of query responses; a `None` entry is a query
    /// failure. The last entry repeats once the script is exhausted.
    fn scripted(
        responses: Vec<Option<Option<&'static str>>>,
    ) -> impl FnMut() -> Result<Option<String>> {
        let mut queue: std::collections::VecDeque<_> = responses.into();
        move || {
            let item = if queue.len() > 1 {
                queue.pop_front().unwrap()
            } else {
                *queue.front().unwrap()
            };
            match item {
                Some(state) => Ok(state.map(String::from)),
                None => Err(anyhow::anyhow!("bus query failed")),
            }
        }
    }

    #[test]
    fn test_wait_query_error_is_not_success() {
        let err =
            wait_until_unit_inactive("u", Duration::from_secs(30), false, scripted(vec![None]))
                .unwrap_err();
        assert!(
            format!("{err:#}").contains("failed to determine the state of unit u"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn test_wait_query_error_after_success_is_not_success() {
        // A failed query after an initial successful one must not become a
        // completed shutdown.
        let err = wait_until_unit_inactive(
            "u",
            Duration::from_secs(30),
            false,
            scripted(vec![Some(Some("deactivating")), None]),
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("failed to determine"));
    }

    #[test]
    fn test_wait_deactivating_then_inactive() {
        wait_until_unit_inactive(
            "u",
            Duration::from_secs(30),
            false,
            scripted(vec![Some(Some("deactivating")), Some(Some("inactive"))]),
        )
        .unwrap();
    }

    #[test]
    fn test_wait_failed_unit_completes() {
        wait_until_unit_inactive(
            "u",
            Duration::from_secs(30),
            false,
            scripted(vec![Some(Some("failed"))]),
        )
        .unwrap();
    }

    #[test]
    fn test_wait_absent_unit_completes() {
        wait_until_unit_inactive(
            "u",
            Duration::from_secs(30),
            false,
            scripted(vec![Some(None)]),
        )
        .unwrap();
    }

    #[test]
    fn test_wait_active_unit_times_out() {
        let err = wait_until_unit_inactive(
            "u",
            Duration::ZERO,
            false,
            scripted(vec![Some(Some("active"))]),
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("timed out"));
    }

    // ---- isolated session bus with a fake systemd1 service ----

    const MANAGER_PATH: &str = "/org/freedesktop/systemd1";
    const UNIT_PATH: &str = "/org/freedesktop/systemd1/unit/test";

    /// Error identity for the fake Manager. The AccessDenied variant's
    /// detail text deliberately claims the unit is missing: only the
    /// typed error name may ever grant absence.
    #[derive(Debug)]
    enum UnitError {
        NoSuchUnit,
        AccessDenied,
    }

    impl zbus::DBusError for UnitError {
        fn create_reply(&self, call: &zbus::message::Header<'_>) -> zbus::Result<zbus::Message> {
            let name = match self {
                UnitError::NoSuchUnit => NO_SUCH_UNIT_ERROR,
                UnitError::AccessDenied => "org.freedesktop.DBus.Error.AccessDenied",
            };
            zbus::Message::error(call, name)?
                .build(&self.description().unwrap_or_default().to_string())
        }

        fn name(&self) -> zbus::names::ErrorName<'_> {
            match self {
                UnitError::NoSuchUnit => NO_SUCH_UNIT_ERROR.try_into().unwrap(),
                UnitError::AccessDenied => "org.freedesktop.DBus.Error.AccessDenied"
                    .try_into()
                    .unwrap(),
            }
        }

        fn description(&self) -> Option<&str> {
            match self {
                UnitError::NoSuchUnit => Some("Unit sdme@test.service not loaded."),
                UnitError::AccessDenied => Some("Access denied; unit sdme@test.service not loaded"),
            }
        }
    }

    /// The zbus `interface` macro must see the literal `Result<T, E>`
    /// return type, so no type alias is used for the GetUnit result.
    fn unit_path() -> zbus::zvariant::OwnedObjectPath {
        UNIT_PATH.try_into().unwrap()
    }

    /// GetUnit always resolves the unit object path.
    struct LoadedManager;

    #[zbus::interface(name = "org.freedesktop.systemd1.Manager")]
    impl LoadedManager {
        fn get_unit(&self, _name: String) -> Result<zbus::zvariant::OwnedObjectPath, UnitError> {
            Ok(unit_path())
        }
    }

    /// GetUnit replies with the typed NoSuchUnit error.
    struct NoSuchUnitManager;

    #[zbus::interface(name = "org.freedesktop.systemd1.Manager")]
    impl NoSuchUnitManager {
        fn get_unit(&self, _name: String) -> Result<zbus::zvariant::OwnedObjectPath, UnitError> {
            Err(UnitError::NoSuchUnit)
        }
    }

    /// GetUnit replies AccessDenied.
    struct DeniedManager;

    #[zbus::interface(name = "org.freedesktop.systemd1.Manager")]
    impl DeniedManager {
        fn get_unit(&self, _name: String) -> Result<zbus::zvariant::OwnedObjectPath, UnitError> {
            Err(UnitError::AccessDenied)
        }
    }

    /// GetUnit replies with a body of the wrong type ("s" instead of "o").
    struct MalformedManager;

    #[zbus::interface(name = "org.freedesktop.systemd1.Manager")]
    impl MalformedManager {
        fn get_unit(&self, _name: String) -> String {
            "not an object path".to_string()
        }
    }

    /// First GetUnit succeeds; subsequent ones report NoSuchUnit. Models a
    /// unit collected by systemd between GetUnit and the property read.
    struct CollectingManager(AtomicUsize);

    #[zbus::interface(name = "org.freedesktop.systemd1.Manager")]
    impl CollectingManager {
        fn get_unit(&self, _name: String) -> Result<zbus::zvariant::OwnedObjectPath, UnitError> {
            if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
                Ok(unit_path())
            } else {
                Err(UnitError::NoSuchUnit)
            }
        }
    }

    /// Unit object with a fixed ActiveState.
    struct FakeUnit(&'static str);

    #[zbus::interface(name = "org.freedesktop.systemd1.Unit")]
    impl FakeUnit {
        #[zbus(property)]
        fn active_state(&self) -> String {
            self.0.to_string()
        }
    }

    /// Unit object whose ActiveState property read is denied.
    struct DeniedUnit;

    #[zbus::interface(name = "org.freedesktop.systemd1.Unit")]
    impl DeniedUnit {
        #[zbus(property)]
        fn active_state(&self) -> zbus::fdo::Result<String> {
            Err(zbus::fdo::Error::AccessDenied(
                "property read denied".to_string(),
            ))
        }
    }

    /// Unit object that reports "deactivating" once, then "inactive".
    struct StoppingUnit(AtomicUsize);

    #[zbus::interface(name = "org.freedesktop.systemd1.Unit")]
    impl StoppingUnit {
        #[zbus(property)]
        fn active_state(&self) -> String {
            if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
                "deactivating".to_string()
            } else {
                "inactive".to_string()
            }
        }
    }

    /// A private dbus-daemon session bus. The daemon is killed on drop.
    struct TestBus {
        address: String,
        daemon: std::process::Child,
    }

    impl TestBus {
        /// Returns None when dbus-daemon is not installed; tests skip.
        fn spawn() -> Option<TestBus> {
            use std::io::BufRead;
            let mut daemon = std::process::Command::new("dbus-daemon")
                .args(["--session", "--nofork", "--print-address=1"])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .spawn()
                .ok()?;
            let stdout = daemon.stdout.take().unwrap();
            let mut line = String::new();
            if std::io::BufReader::new(stdout)
                .read_line(&mut line)
                .is_err()
                || line.trim().is_empty()
            {
                let _ = daemon.kill();
                let _ = daemon.wait();
                return None;
            }
            Some(TestBus {
                address: line.trim().to_string(),
                daemon,
            })
        }

        fn client(&self) -> Connection {
            zbus::blocking::connection::Builder::address(self.address.as_str())
                .unwrap()
                .build()
                .unwrap()
        }

        /// Serve a fake systemd1 Manager, and optionally a unit object at
        /// UNIT_PATH, under the well-known systemd1 name.
        fn serve<M, U>(&self, manager: M, unit: Option<U>) -> zbus::blocking::Connection
        where
            M: zbus::object_server::Interface,
            U: zbus::object_server::Interface,
        {
            let builder = zbus::blocking::connection::Builder::address(self.address.as_str())
                .unwrap()
                .name("org.freedesktop.systemd1")
                .unwrap()
                .serve_at(MANAGER_PATH, manager)
                .unwrap();
            match unit {
                Some(u) => builder.serve_at(UNIT_PATH, u).unwrap().build().unwrap(),
                None => builder.build().unwrap(),
            }
        }
    }

    impl Drop for TestBus {
        fn drop(&mut self) {
            let _ = self.daemon.kill();
            let _ = self.daemon.wait();
        }
    }

    /// Skip silently (with a note) when no dbus-daemon is available.
    macro_rules! require_bus {
        () => {
            match TestBus::spawn() {
                Some(bus) => bus,
                None => {
                    eprintln!("dbus-daemon unavailable; skipping isolated-bus test");
                    return;
                }
            }
        };
    }

    #[test]
    fn test_absent_unit_is_confirmed_none() {
        let bus = require_bus!();
        let _server = bus.serve(NoSuchUnitManager, None::<FakeUnit>);
        let conn = bus.client();
        assert_eq!(
            get_unit_active_state(&conn, "sdme@test.service").unwrap(),
            None
        );
    }

    #[test]
    fn test_access_denied_is_error_not_absence() {
        let bus = require_bus!();
        let _server = bus.serve(DeniedManager, None::<FakeUnit>);
        let conn = bus.client();
        let err = get_unit_active_state(&conn, "sdme@test.service").unwrap_err();
        assert!(format!("{err:#}").contains("failed to query unit"));
    }

    #[test]
    fn test_loaded_unit_returns_state() {
        let bus = require_bus!();
        let _server = bus.serve(LoadedManager, Some(FakeUnit("active")));
        let conn = bus.client();
        assert_eq!(
            get_unit_active_state(&conn, "sdme@test.service")
                .unwrap()
                .as_deref(),
            Some("active")
        );
    }

    #[test]
    fn test_malformed_reply_is_error() {
        let bus = require_bus!();
        let _server = bus.serve(MalformedManager, None::<FakeUnit>);
        let conn = bus.client();
        assert!(get_unit_active_state(&conn, "sdme@test.service").is_err());
    }

    #[test]
    fn test_property_error_is_error_not_absence() {
        let bus = require_bus!();
        let _server = bus.serve(LoadedManager, Some(DeniedUnit));
        let conn = bus.client();
        assert!(get_unit_active_state(&conn, "sdme@test.service").is_err());
    }

    #[test]
    fn test_collected_unit_is_absent_only_after_confirmation() {
        // GetUnit resolves, the unit object is gone by the property read
        // (nothing served at its path), and a fresh GetUnit confirms the
        // unit no longer exists.
        let bus = require_bus!();
        let _server = bus.serve(CollectingManager(AtomicUsize::new(0)), None::<FakeUnit>);
        let conn = bus.client();
        assert_eq!(
            get_unit_active_state(&conn, "sdme@test.service").unwrap(),
            None
        );
    }

    #[test]
    fn test_vanished_object_without_no_such_unit_is_error() {
        // The unit object path vanished but GetUnit still resolves it, so
        // the state is unknown and must stay an error.
        let bus = require_bus!();
        let _server = bus.serve(LoadedManager, None::<FakeUnit>);
        let conn = bus.client();
        assert!(get_unit_active_state(&conn, "sdme@test.service").is_err());
    }

    #[test]
    fn test_wait_over_bus_until_inactive() {
        let bus = require_bus!();
        let _server = bus.serve(LoadedManager, Some(StoppingUnit(AtomicUsize::new(0))));
        let conn = bus.client();
        wait_for_unit_inactive(&conn, "sdme@test.service", Duration::from_secs(10), false).unwrap();
    }

    #[test]
    fn test_wait_fails_when_bus_disconnects() {
        let bus = require_bus!();
        let server = bus.serve(LoadedManager, Some(FakeUnit("active")));
        let conn = bus.client();
        // Drop the server mid-wait; the next poll must fail the wait
        // rather than complete it.
        let dropper = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(400));
            drop(server);
        });
        let err =
            wait_for_unit_inactive(&conn, "sdme@test.service", Duration::from_secs(15), false)
                .unwrap_err();
        dropper.join().unwrap();
        assert!(format!("{err:#}").contains("failed to determine"));
    }
}
