//! Systemd D-Bus helpers, unit template management, and container lifecycle.
//!
//! Provides helpers for installing the `sdme@.service` template unit,
//! writing per-container nspawn drop-in files, and starting containers
//! via the systemd D-Bus interface.

pub(crate) mod dbus;
pub(crate) mod units;

#[cfg(test)]
mod tests;

use std::fs;
use std::path::Path;

use anyhow::Result;

use crate::{ResourceLimits, State};

pub use units::{
    nspawn_dropin, remove_limits_dropin, resolve_paths, service_name, unit_template,
    write_limits_dropin, write_nspawn_dropin, DropinConfig, UnitPaths,
};

/// Return the systemd version string from D-Bus.
pub fn systemd_version() -> Result<String> {
    dbus::get_systemd_version()
}

/// Check whether a container's systemd unit is currently active.
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

/// Check whether an arbitrary systemd unit is currently active.
/// Returns false if the unit does not exist or if the D-Bus query fails.
pub fn is_unit_active(unit: &str) -> bool {
    dbus::is_unit_active(unit).unwrap_or(false)
}

/// Return the ActiveState of a container's systemd unit.
///
/// Returns `None` if the unit does not exist. Possible values include
/// `"active"`, `"activating"`, `"deactivating"`, `"inactive"`, `"failed"`.
pub fn unit_active_state(name: &str) -> Option<String> {
    dbus::pub_get_unit_active_state(&service_name(name))
}

/// Shared configuration for container service operations (enable, start).
pub struct ServiceConfig<'a> {
    /// Data directory containing container state.
    pub datadir: &'a Path,
    /// Container name.
    pub name: &'a str,
    /// Maximum number of tasks (PIDs) for the container unit.
    pub tasks_max: u32,
    /// Boot timeout in seconds for the template unit.
    pub boot_timeout: u64,
    /// Enable verbose output.
    pub verbose: bool,
}

/// Enable a container to auto-start on boot.
pub fn enable(cfg: &ServiceConfig) -> Result<()> {
    let ServiceConfig {
        datadir,
        name,
        tasks_max,
        boot_timeout,
        verbose,
    } = *cfg;
    units::ensure_template_unit(tasks_max, boot_timeout, verbose)?;
    let unit = service_name(name);
    if verbose {
        eprintln!("enabling unit: {unit}");
    }
    dbus::enable_unit(&unit)?;
    let state_path = datadir.join("state").join(name);
    let mut state = State::read_from(&state_path)?;
    state.set("ENABLED", "yes");
    state.write_to(&state_path)?;
    Ok(())
}

/// Disable a container's auto-start on boot.
pub fn disable(datadir: &Path, name: &str, verbose: bool) -> Result<()> {
    let unit = service_name(name);
    if verbose {
        eprintln!("disabling unit: {unit}");
    }
    dbus::disable_unit(&unit)?;
    let state_path = datadir.join("state").join(name);
    let mut state = State::read_from(&state_path)?;
    state.set("ENABLED", "no");
    state.write_to(&state_path)?;
    Ok(())
}

/// Disable the systemd unit without updating the state file.
///
/// Used during container removal to clean up the enabled symlink
/// before the state file is deleted. Best-effort: errors are ignored
/// by the caller.
pub fn disable_unit_only(name: &str) -> Result<()> {
    dbus::disable_unit(&service_name(name))
}

/// Wait for a container's systemd to report boot completion.
pub fn wait_for_boot(name: &str, timeout: std::time::Duration, verbose: bool) -> Result<()> {
    dbus::wait_for_boot(name, timeout, verbose)
}

/// Wait for D-Bus to become available inside the container.
pub fn wait_for_dbus(name: &str, timeout: std::time::Duration, verbose: bool) -> Result<()> {
    dbus::wait_for_dbus(name, timeout, verbose)
}

/// Outcome of waiting for a container to boot.
///
/// [`await_boot`] returns this instead of a plain `Result` so callers can
/// decide whether the container is worth keeping when boot didn't finish
/// in time.
///
/// # Examples
///
/// ```ignore
/// use sdme::systemd::{await_boot, BootOutcome};
///
/// match await_boot(name, timeout, verbose) {
///     BootOutcome::Ready => { /* success */ }
///     BootOutcome::TimedOut(e) => {
///         // Still alive; a slow first-boot chown is common. Leave it
///         // running and ask the user to re-check with `sdme logs`.
///         return Err(e);
///     }
///     BootOutcome::Exited(e) => {
///         // Dead; stop + clean up before propagating.
///         cleanup();
///         return Err(e);
///     }
/// }
/// ```
pub enum BootOutcome {
    /// Container booted and D-Bus is ready.
    Ready,
    /// Boot timed out but the container is likely still alive (e.g.
    /// slow first-boot userns chown). Caller should not kill it.
    TimedOut(anyhow::Error),
    /// Container exited or failed during boot. Caller should clean up.
    Exited(anyhow::Error),
}

/// Wait for a container to complete boot and D-Bus readiness.
///
/// Combines `wait_for_boot` and `wait_for_dbus` with shared timeout tracking.
/// Returns a `BootOutcome` that distinguishes timeout (container alive)
/// from exit (container dead) so callers don't need to re-derive liveness.
///
/// Known limitation: for OCI app containers, we do not wait for the
/// `sdme-oci-{name}.service` to reach active state. A failing OCI app service
/// (e.g. port conflict) goes unnoticed until the user checks `sdme logs --oci`.
pub fn await_boot(name: &str, timeout: std::time::Duration, verbose: bool) -> BootOutcome {
    let boot_start = std::time::Instant::now();
    if let Err(e) = wait_for_boot(name, timeout, verbose) {
        return classify_boot_error(e);
    }
    let remaining = timeout.saturating_sub(boot_start.elapsed());
    if let Err(e) = wait_for_dbus(name, remaining, verbose) {
        return classify_boot_error(e);
    }
    BootOutcome::Ready
}

/// Classify a boot/dbus error as timeout or exit based on the error
/// chain. Timeout errors carry a `BootTimeout` marker; everything else
/// (container exited, signal watcher died, interrupted) is treated as
/// an exit.
fn classify_boot_error(e: anyhow::Error) -> BootOutcome {
    if e.downcast_ref::<dbus::BootTimeout>().is_some() {
        BootOutcome::TimedOut(e)
    } else {
        BootOutcome::Exited(e)
    }
}

/// Terminate a container via the machined D-Bus API.
pub fn terminate_machine(name: &str) -> Result<()> {
    dbus::terminate_machine(name)
}

/// Send a signal to a container via the machined D-Bus API.
pub fn kill_machine(name: &str, who: &str, signal: i32) -> Result<()> {
    dbus::kill_machine(name, who, signal)
}

/// Wait for a container's systemd unit to become inactive.
pub fn wait_for_shutdown(name: &str, timeout: std::time::Duration, verbose: bool) -> Result<()> {
    dbus::wait_for_shutdown(name, timeout, verbose)
}

/// Get the leader PID of a running container via machined D-Bus.
/// Returns `None` if the machine is not registered.
pub fn get_machine_leader(name: &str) -> Result<Option<u32>> {
    let conn = dbus::connect()?;
    dbus::get_machine_leader(&conn, name)
}

/// Check whether a container's leader has a different user namespace than the host.
pub fn has_foreign_userns(leader: u32) -> bool {
    dbus::has_foreign_userns(leader)
}

/// Return the names of all registered machines from machined.
pub fn list_machines() -> Vec<String> {
    dbus::list_machines()
}

/// Return IP addresses assigned to a container's network interface.
///
/// Returns an empty vector for stopped containers, machines not
/// registered with machined, or on any D-Bus error.
pub fn get_machine_addresses(name: &str) -> Vec<String> {
    dbus::get_machine_addresses(name)
}

/// Install the template unit, write the drop-in, and start a container via D-Bus.
pub fn start(cfg: &ServiceConfig) -> Result<()> {
    let ServiceConfig {
        datadir,
        name,
        tasks_max,
        boot_timeout,
        verbose,
    } = *cfg;
    units::ensure_template_unit(tasks_max, boot_timeout, verbose)?;

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
        let _ = remove_limits_dropin(name, verbose);
        return Err(e);
    }

    Ok(())
}
