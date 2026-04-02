//! Container stop, removal, and resource limit management.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

use crate::{systemd, ResourceLimits, State};

use super::{ensure_exists, volumes_dir};

/// Stop a container if running, then delete its state file and overlayfs directories.
pub fn remove(datadir: &Path, name: &str, verbose: bool) -> Result<()> {
    ensure_exists(datadir, name)?;

    // Acquire exclusive lock to prevent removal while a build is reading from this container.
    let _lock = crate::lock::lock_exclusive(datadir, "containers", name)
        .with_context(|| format!("cannot remove container '{name}': in use"))?;

    // Read state before removal to check for OCI volumes and enabled state.
    let state_file = datadir.join("state").join(name);
    let (has_oci_volumes, is_enabled) = if state_file.exists() {
        State::read_from(&state_file)
            .ok()
            .map(|s| {
                let oci = s.get("OCI_VOLUMES").map(|v| !v.is_empty()).unwrap_or(false);
                let enabled = s.is_yes("ENABLED");
                (oci, enabled)
            })
            .unwrap_or((false, false))
    } else {
        (false, false)
    };

    // Disable the unit if it was enabled (best-effort).
    if is_enabled {
        if verbose {
            eprintln!("disabling unit for '{name}'");
        }
        let _ = systemd::disable_unit_only(name);
    }

    if systemd::is_active(name)? {
        if verbose {
            eprintln!("stopping container '{name}'");
        }
        stop(name, StopMode::Terminate, 30, verbose)?;
    }

    let container_dir = datadir.join("containers").join(name);
    if container_dir.exists() {
        crate::copy::safe_remove_dir(&container_dir)?;
        if verbose {
            eprintln!("removed {}", container_dir.display());
        }
    }

    if state_file.exists() {
        fs::remove_file(&state_file)
            .with_context(|| format!("failed to remove {}", state_file.display()))?;
        if verbose {
            eprintln!("removed {}", state_file.display());
        }
    }

    systemd::remove_limits_dropin(name, verbose)?;

    if has_oci_volumes {
        let vol_dir = volumes_dir(datadir, name);
        if vol_dir.exists() {
            eprintln!("volume data retained at {}", vol_dir.display());
        }
    }

    Ok(())
}

/// Update resource limits on an existing container.
///
/// Reads the current state file, merges the new limits, writes it back,
/// and regenerates the systemd drop-in. If the container is running,
/// prints a note that a restart is needed.
pub fn set_limits(
    datadir: &Path,
    name: &str,
    limits: &ResourceLimits,
    verbose: bool,
) -> Result<()> {
    ensure_exists(datadir, name)?;

    let state_path = datadir.join("state").join(name);
    let mut state = State::read_from(&state_path)?;
    limits.write_to_state(&mut state);
    state.write_to(&state_path)?;

    if verbose {
        eprintln!("updated state file: {}", state_path.display());
    }

    systemd::write_limits_dropin(name, limits, verbose)?;

    if systemd::is_active(name)? {
        eprintln!("note: container '{name}' is running; restart for limits to take effect");
    }

    Ok(())
}

/// Controls how `stop()` shuts down a container.
#[derive(Debug, Clone, Copy)]
pub enum StopMode {
    /// Send SIGRTMIN+4 to the container leader (graceful poweroff).
    Graceful,
    /// Call TerminateMachine (SIGTERM to nspawn leader).
    Terminate,
    /// Send SIGKILL to all processes in the container.
    Kill,
}

/// Stop a container using the specified mode (graceful, terminate, or kill).
///
/// `timeout_secs` is the number of seconds to wait for the container to
/// shut down before returning an error. Pass the appropriate value from
/// the config (`stop_timeout_graceful`, `stop_timeout_terminate`, or
/// `stop_timeout_kill`).
pub fn stop(name: &str, mode: StopMode, timeout_secs: u64, verbose: bool) -> Result<()> {
    let timeout = std::time::Duration::from_secs(timeout_secs);
    match mode {
        StopMode::Graceful => {
            if verbose {
                eprintln!("powering off machine '{name}'");
            }
            let signal = libc::SIGRTMIN() + 4;
            systemd::kill_machine(name, "leader", signal)?;
            systemd::wait_for_shutdown(name, timeout, verbose).with_context(|| {
                if crate::INTERRUPTED.load(std::sync::atomic::Ordering::Relaxed) {
                    format!("shutdown of '{name}' interrupted")
                } else {
                    format!(
                        "hint: the container may be stuck during shutdown; \
                             try 'sdme stop --kill {name}' to force-kill it"
                    )
                }
            })
        }
        StopMode::Terminate => {
            if verbose {
                eprintln!("terminating machine '{name}'");
            }
            systemd::terminate_machine(name)?;
            systemd::wait_for_shutdown(name, timeout, verbose).with_context(|| {
                if crate::INTERRUPTED.load(std::sync::atomic::Ordering::Relaxed) {
                    format!("shutdown of '{name}' interrupted")
                } else {
                    format!(
                        "hint: the container may be stuck; \
                             try 'sdme stop --kill {name}' to force-kill it"
                    )
                }
            })
        }
        StopMode::Kill => {
            if verbose {
                eprintln!("killing machine '{name}'");
            }
            systemd::kill_machine(name, "all", libc::SIGKILL)?;
            systemd::wait_for_shutdown(name, timeout, verbose)
        }
    }
}
