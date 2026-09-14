//! Container stop, removal, and resource limit management.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

use crate::{systemd, ResourceLimits, State};

use super::{ensure_exists, volumes_dir};

/// Stop a container if running, then delete its state file and overlayfs directories.
///
/// Refuses to remove anything when the unit state cannot be determined:
/// an undetermined state is not proof that the container is stopped, so
/// no unit mutation, filesystem teardown, state file removal, or drop-in
/// removal happens and the command stays retryable.
pub fn remove(datadir: &Path, name: &str, verbose: bool) -> Result<()> {
    remove_with_ops(
        datadir,
        name,
        verbose,
        &RemovalOps {
            unit_state: &systemd::unit_active_state,
            disable_unit: &systemd::disable_unit_only,
            remove_dropin: &systemd::remove_limits_dropin,
            reclaim_runtime: &reclaim_nspawn_runtime,
        },
    )
}

/// Host side effects of container removal, injected for testing.
struct RemovalOps<'a> {
    /// Query the unit's ActiveState; `Ok(None)` means confirmed absent,
    /// `Err` means the state could not be determined.
    unit_state: &'a dyn Fn(&str) -> Result<Option<String>>,
    /// Disable the container's unit (best-effort, errors ignored).
    disable_unit: &'a dyn Fn(&str) -> Result<()>,
    /// Remove the container's systemd drop-in directory on the host.
    remove_dropin: &'a dyn Fn(&str, bool) -> Result<()>,
    /// Reclaim the container's systemd-nspawn runtime state under `/run`.
    reclaim_runtime: &'a dyn Fn(&str, bool) -> Result<()>,
}

/// Container removal with host side effects injected for testing.
fn remove_with_ops(datadir: &Path, name: &str, verbose: bool, ops: &RemovalOps) -> Result<()> {
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

    // Determine the unit state before any unit mutation or file removal.
    // A failed query is not proof of absence: abort here so an
    // undetermined state cannot be read as permission to delete, and the
    // command stays retryable.
    let active_state = (ops.unit_state)(name).with_context(|| {
        format!("cannot determine whether container '{name}' is stopped; refusing to remove it")
    })?;

    // Disable the unit if it was enabled (best-effort).
    if is_enabled {
        if verbose {
            eprintln!("disabling unit for '{name}'");
        }
        let _ = (ops.disable_unit)(name);
    }

    // Stop the container before deleting its files. Check the raw unit state
    // rather than is_active (which is true only for "active"): a container in an
    // auto-restart window ("activating") or a failed/looping state must also be
    // brought down, otherwise a pending Restart= would remount the overlay onto
    // the directories we are about to delete. For the normal "active" case use
    // the existing graceful Terminate stop; for the abnormal states issue a real
    // StopUnit job (cancels the pending restart) and clear the failed latch.
    match active_state.as_deref() {
        None | Some("inactive") => {}
        Some("active") => {
            if verbose {
                eprintln!("stopping container '{name}'");
            }
            stop(name, StopMode::Terminate, 30, verbose)?;
        }
        Some(other) => {
            if verbose {
                eprintln!("stopping container '{name}' (unit state: {other})");
            }
            let _ = systemd::stop_unit(name);
            systemd::wait_for_shutdown(name, std::time::Duration::from_secs(30), verbose)?;
            let _ = systemd::reset_failed(name);
        }
    }

    // A btrfs container root is a subvolume under the pool, not a directory in
    // container_dir, and must be deleted with `btrfs subvolume delete`. Do this
    // after the container is stopped (above) and best-effort, so a pool/mount
    // hiccup never blocks removing the rest of the container's state.
    if let Ok(state) = State::read_from(&state_file) {
        if crate::storage::Backend::from_state(&state) == crate::storage::Backend::Btrfs {
            let _ = crate::storage::btrfs::teardown(datadir, name, verbose);
            // Verify the subvolume is actually gone before deleting state. If a
            // teardown failure left it behind, abort rm and keep the state file
            // so the command stays retryable and the leaked subvolume can never
            // silently block reusing the name. If the pool itself is gone, there
            // is nothing to leak, so proceed.
            if let Ok(pool_root) = crate::storage::pool::ensure_mounted(datadir, verbose) {
                let subvol = crate::storage::btrfs::container_root(&pool_root, name);
                if crate::storage::btrfs::is_subvolume(&subvol) {
                    anyhow::bail!(
                        "failed to delete btrfs subvolume {}; container state kept for retry",
                        subvol.display()
                    );
                }
            }
        }
    }

    let container_dir = datadir.join("containers").join(name);
    if container_dir.exists() {
        crate::copy::safe_remove_dir(&container_dir)?;
        if verbose {
            eprintln!("removed {}", container_dir.display());
        }
    }

    // systemd-nspawn's per-container state under /run outlives an unclean
    // exit, and nothing else on the host owns it once the container is gone.
    // Best-effort: the container is already torn down, so a failure here only
    // leaves a stale mount that a future start would have to reclaim.
    if let Err(e) = (ops.reclaim_runtime)(name, verbose) {
        eprintln!(
            "warning: {e:#}; leftover systemd-nspawn runtime state may block \
             a future container named '{name}'"
        );
    }

    if state_file.exists() {
        fs::remove_file(&state_file)
            .with_context(|| format!("failed to remove {}", state_file.display()))?;
        if verbose {
            eprintln!("removed {}", state_file.display());
        }
    }

    (ops.remove_dropin)(name, verbose)?;

    if has_oci_volumes {
        let vol_dir = volumes_dir(datadir, name);
        if vol_dir.exists() {
            eprintln!("volume data retained at {}", vol_dir.display());
        }
    }

    Ok(())
}

/// Host directory where systemd-nspawn keeps per-container runtime state.
const NSPAWN_RUNTIME_DIR: &str = "/run/systemd/nspawn";

/// Entries under `NSPAWN_RUNTIME_DIR` that belong to systemd-nspawn itself
/// rather than to one container. Both pass `validate_name`, so they are
/// rejected by name to keep shared state out of reach.
const NSPAWN_SHARED_ENTRIES: &[&str] = &["locks", "propagate"];

/// Whether a container is running, as far as the host can prove.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Liveness {
    /// systemd and machined both confirm nothing by this name is running.
    Stopped,
    /// The unit is active, starting, or shutting down, or machined has a
    /// machine registered under this name.
    Running,
    /// A query failed, so the answer is unknown. Callers that would destroy
    /// state must treat this as "may be running".
    Unknown,
}

/// Ask systemd and machined whether a container of this name is running.
///
/// Both are consulted because they can disagree: a machine started outside
/// sdme has no `sdme@<name>.service` unit yet still owns nspawn runtime
/// state. Only a confirmed "does not exist" counts as absence; a bus,
/// permission, or decode failure is `Unknown`, never `Stopped`.
fn probe_liveness(name: &str) -> Liveness {
    let unit_idle = match systemd::unit_active_state(name) {
        Ok(None) => true,
        // "inactive" and "failed" mean no nspawn process is attached to the
        // unit. Every other state may still have one, including "activating"
        // (an auto-restart in flight) and "deactivating" (a shutdown in
        // progress that has not released the mount yet).
        Ok(Some(state)) => state == "inactive" || state == "failed",
        Err(_) => return Liveness::Unknown,
    };
    if !unit_idle {
        return Liveness::Running;
    }
    match systemd::get_machine_leader(name) {
        Ok(None) => Liveness::Stopped,
        Ok(Some(_)) => Liveness::Running,
        Err(_) => Liveness::Unknown,
    }
}

/// Reclaim leftover systemd-nspawn runtime state for a container.
///
/// systemd-nspawn bind-mounts `/run/systemd/nspawn/<name>/unix-export` for
/// the lifetime of a container and tears it down on a clean exit. An unclean
/// exit (SIGKILL after a stop timeout, a host crash) leaves the mount behind,
/// and nspawn refuses to start the next container of that name with
/// "Mount point ... exists already, refusing". sdme owns the container
/// lifecycle, so it reclaims the leftovers on start and on removal.
///
/// Nothing is touched unless both systemd and machined confirm no container
/// of this name is running. Tearing down live runtime state would break a
/// running container, so an undetermined state is an error rather than a
/// licence to delete. Callers report failures as warnings: a start or a
/// removal is still valid without this cleanup.
pub fn reclaim_nspawn_runtime(name: &str, verbose: bool) -> Result<()> {
    reclaim_nspawn_runtime_in(
        Path::new(NSPAWN_RUNTIME_DIR),
        name,
        verbose,
        &probe_liveness,
    )
}

/// Runtime reclamation with the runtime root and the liveness probe injected,
/// so tests exercise the decisions without touching `/run` or the host bus.
fn reclaim_nspawn_runtime_in(
    runtime_dir: &Path,
    name: &str,
    verbose: bool,
    liveness: &dyn Fn(&str) -> Liveness,
) -> Result<()> {
    // The name becomes a path component under a host runtime directory, so it
    // is validated before it is ever joined onto that directory.
    crate::validate_name(name).with_context(|| format!("invalid container name {name:?}"))?;
    if NSPAWN_SHARED_ENTRIES.contains(&name) {
        anyhow::bail!("'{name}' names shared systemd-nspawn state, not a container's");
    }

    let dir = runtime_dir.join(name);
    if !dir.exists() {
        return Ok(());
    }

    match liveness(name) {
        // Live state, not a leftover.
        Liveness::Running => return Ok(()),
        Liveness::Unknown => anyhow::bail!(
            "cannot determine whether container '{name}' is running; \
             leaving {} alone",
            dir.display()
        ),
        Liveness::Stopped => {}
    }

    // safe_remove_dir unmounts what it finds underneath before deleting, and
    // refuses to delete through a mount it could not release.
    crate::copy::safe_remove_dir(&dir)
        .with_context(|| format!("failed to reclaim {}", dir.display()))?;
    if verbose {
        eprintln!("reclaimed leftover nspawn runtime state {}", dir.display());
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
    let backend = crate::storage::Backend::from_state(&state);
    // Whether a disk cap is currently recorded, so an update that leaves --disk
    // unset only clears the quota when one existed. Read before any state write.
    let had_disk = state.get_nonempty("DISK").is_some();

    // Apply the btrfs disk quota BEFORE persisting state, so a quota failure
    // aborts with the recorded limits unchanged (no state/qgroup desync, and a
    // retry still sees the old DISK key). The pool is touched only when the cap
    // actually changes, so memory/CPU-only edits never mount it. The quota takes
    // effect immediately (no restart needed), unlike the memory/CPU limits.
    if backend == crate::storage::Backend::Btrfs {
        if limits.disk.is_some() || had_disk {
            let pool_root = crate::storage::pool::ensure_mounted(datadir, verbose)?;
            let subvol = crate::storage::btrfs::container_root(&pool_root, name);
            match &limits.disk {
                Some(disk) => {
                    let bytes = crate::parse_size(disk)
                        .with_context(|| format!("invalid --disk value {disk:?}"))?;
                    crate::storage::pool::ensure_quota_enabled(datadir, verbose)?;
                    crate::storage::btrfs::set_disk_limit(&subvol, bytes, verbose)?;
                }
                // Reached only when had_disk is true (guarded above).
                None => crate::storage::btrfs::clear_disk_limit(&subvol, verbose)?,
            }
        }
    } else if limits.disk.is_some() {
        eprintln!(
            "warning: --disk requires btrfs storage; the disk cap is not enforced \
             for this container"
        );
    }

    // Persist state and the cgroup drop-in only after the quota is in place.
    // The disk cap is only enforceable on btrfs; do not persist a phantom cap
    // for overlay containers.
    let mut persisted = limits.clone();
    if backend != crate::storage::Backend::Btrfs {
        persisted.disk = None;
    }
    persisted.write_to_state(&mut state);
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
    /// Send SIGRTMIN+3 to the container leader (graceful halt).
    Graceful,
    /// Call TerminateMachine (SIGTERM to nspawn leader).
    Terminate,
    /// Send SIGKILL to all processes in the container.
    Kill,
}

pub(super) fn graceful_stop_signal() -> i32 {
    libc::SIGRTMIN() + 3
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
                eprintln!("halting machine '{name}'");
            }
            let signal = graceful_stop_signal();
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
            // sdme force-kills through machined, not `systemctl stop`, so systemd
            // does not see the SIGKILL as an intentional stop. If the container
            // has a Restart= policy, systemd would otherwise resurrect it. Issue
            // a real StopUnit job to cancel any pending auto-restart. Best-effort:
            // a container with no restart policy is already going down, and its
            // unit may vanish before this lands.
            let _ = systemd::stop_unit(name);
            let result = systemd::wait_for_shutdown(name, timeout, verbose);
            // Clear a lingering failed latch (e.g. from the crash that preceded
            // the kill) so the unit reports cleanly and future starts are not
            // blocked by the start-rate limiter.
            let _ = systemd::reset_failed(name);
            result
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDataDir;
    use std::cell::RefCell;
    use std::path::PathBuf;

    /// Minimal container fixture: a state file plus a container directory
    /// with a sentinel file, satisfying remove's preconditions without
    /// touching systemd or the host. `extra_state` is appended to the
    /// state file (e.g. "ENABLED=yes\n").
    fn fixture(tmp: &TempDataDir, name: &str, extra_state: &str) -> (PathBuf, PathBuf) {
        let state_dir = tmp.path().join("state");
        fs::create_dir_all(&state_dir).unwrap();
        let state_file = state_dir.join(name);
        fs::write(&state_file, format!("NAME=fixture\nROOTFS=\n{extra_state}")).unwrap();
        let container_dir = tmp.path().join("containers").join(name);
        fs::create_dir_all(container_dir.join("upper")).unwrap();
        fs::write(container_dir.join("upper").join("keep.txt"), "user data").unwrap();
        (state_file, container_dir)
    }

    /// Recorded invocations of removal's injected host side effects.
    #[derive(Default)]
    struct OpLog {
        disables: Vec<String>,
        dropin_removals: Vec<String>,
        reclaims: Vec<String>,
    }

    /// Run removal with the given unit-state query and recording disable /
    /// drop-in callbacks, so tests never touch host systemd state.
    fn run_remove(
        tmp: &TempDataDir,
        name: &str,
        query: &dyn Fn(&str) -> Result<Option<String>>,
        log: &RefCell<OpLog>,
    ) -> Result<()> {
        let ops = RemovalOps {
            unit_state: query,
            disable_unit: &|n: &str| {
                log.borrow_mut().disables.push(n.to_string());
                Ok(())
            },
            remove_dropin: &|n: &str, _verbose: bool| {
                log.borrow_mut().dropin_removals.push(n.to_string());
                Ok(())
            },
            reclaim_runtime: &|n: &str, _verbose: bool| {
                log.borrow_mut().reclaims.push(n.to_string());
                Ok(())
            },
        };
        remove_with_ops(tmp.path(), name, false, &ops)
    }

    #[test]
    fn test_remove_aborts_when_unit_state_uncertain() {
        let tmp = TempDataDir::new("remove-uncertain");
        let (state_file, container_dir) = fixture(&tmp, "uncertainbox", "");
        let log = RefCell::new(OpLog::default());
        let err = run_remove(
            &tmp,
            "uncertainbox",
            &|_| Err(anyhow::anyhow!("failed to connect to system dbus")),
            &log,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("refusing to remove"),
            "unexpected error: {msg}"
        );
        // Nothing destructive ran: no drop-in removal, the container
        // storage and state file survive, and the command stays retryable.
        assert!(state_file.exists());
        assert!(container_dir.join("upper").join("keep.txt").exists());
        assert!(log.borrow().dropin_removals.is_empty());
        assert!(log.borrow().disables.is_empty());
        assert!(log.borrow().reclaims.is_empty());
    }

    #[test]
    fn test_remove_enabled_container_does_not_disable_when_state_uncertain() {
        // The unit-state query must run before any unit mutation: an
        // enabled container whose state cannot be determined keeps its
        // enablement, storage, and state file.
        let tmp = TempDataDir::new("remove-enabled-uncertain");
        let (state_file, container_dir) = fixture(&tmp, "enabledbox", "ENABLED=yes\n");
        let log = RefCell::new(OpLog::default());
        let err = run_remove(
            &tmp,
            "enabledbox",
            &|_| Err(anyhow::anyhow!("failed to connect to system dbus")),
            &log,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("refusing to remove"));
        assert!(state_file.exists());
        assert!(container_dir.join("upper").join("keep.txt").exists());
        assert!(log.borrow().disables.is_empty());
        assert!(log.borrow().dropin_removals.is_empty());
        assert!(log.borrow().reclaims.is_empty());
    }

    #[test]
    fn test_remove_proceeds_when_unit_confirmed_absent() {
        let tmp = TempDataDir::new("remove-absent");
        let (state_file, container_dir) = fixture(&tmp, "gonebox", "");
        let log = RefCell::new(OpLog::default());
        run_remove(&tmp, "gonebox", &|_| Ok(None), &log).unwrap();
        assert!(!state_file.exists());
        assert!(!container_dir.exists());
        assert_eq!(log.borrow().dropin_removals, vec!["gonebox"]);
        assert!(log.borrow().disables.is_empty());
        // Removal reclaims the container's nspawn runtime state so a future
        // container reusing the name is not refused by a leftover mount.
        assert_eq!(log.borrow().reclaims, vec!["gonebox"]);
    }

    #[test]
    fn test_remove_proceeds_when_unit_inactive() {
        let tmp = TempDataDir::new("remove-inactive");
        let (state_file, container_dir) = fixture(&tmp, "idlebox", "ENABLED=yes\n");
        let log = RefCell::new(OpLog::default());
        run_remove(&tmp, "idlebox", &|_| Ok(Some("inactive".to_string())), &log).unwrap();
        assert!(!state_file.exists());
        assert!(!container_dir.exists());
        assert_eq!(log.borrow().disables, vec!["idlebox"]);
        assert_eq!(log.borrow().dropin_removals, vec!["idlebox"]);
        assert_eq!(log.borrow().reclaims, vec!["idlebox"]);
    }

    /// Stand-in for what systemd-nspawn leaves under /run: a per-container
    /// directory holding the `unix-export` mount point. Returns the runtime
    /// root and the container's directory inside it.
    fn runtime_fixture(tmp: &TempDataDir, name: &str) -> (PathBuf, PathBuf) {
        let root = tmp.path().join("nspawn");
        let dir = root.join(name);
        fs::create_dir_all(dir.join("unix-export")).unwrap();
        (root, dir)
    }

    /// Liveness probe that always answers `verdict` and records its calls.
    fn probe<'a>(
        verdict: Liveness,
        calls: &'a RefCell<Vec<String>>,
    ) -> impl Fn(&str) -> Liveness + 'a {
        move |n: &str| {
            calls.borrow_mut().push(n.to_string());
            verdict
        }
    }

    #[test]
    fn test_reclaim_removes_leftover_when_container_stopped() {
        let tmp = TempDataDir::new("reclaim-stopped");
        let (root, dir) = runtime_fixture(&tmp, "deadbox");
        let calls = RefCell::new(Vec::new());
        reclaim_nspawn_runtime_in(&root, "deadbox", false, &probe(Liveness::Stopped, &calls))
            .unwrap();
        assert!(!dir.exists());
        assert_eq!(calls.borrow().len(), 1);
    }

    #[test]
    fn test_reclaim_keeps_runtime_state_of_running_container() {
        // The whole point of the liveness check: a running container's
        // unix-export mount is live state, not a leftover.
        let tmp = TempDataDir::new("reclaim-running");
        let (root, dir) = runtime_fixture(&tmp, "livebox");
        let calls = RefCell::new(Vec::new());
        reclaim_nspawn_runtime_in(&root, "livebox", false, &probe(Liveness::Running, &calls))
            .unwrap();
        assert!(dir.join("unix-export").exists());
    }

    #[test]
    fn test_reclaim_refuses_when_liveness_unknown() {
        // An undetermined state is not proof that the container is stopped.
        let tmp = TempDataDir::new("reclaim-unknown");
        let (root, dir) = runtime_fixture(&tmp, "maybebox");
        let calls = RefCell::new(Vec::new());
        let err =
            reclaim_nspawn_runtime_in(&root, "maybebox", false, &probe(Liveness::Unknown, &calls))
                .unwrap_err();
        assert!(
            format!("{err:#}").contains("cannot determine whether"),
            "unexpected error: {err:#}"
        );
        assert!(dir.join("unix-export").exists());
    }

    #[test]
    fn test_reclaim_rejects_shared_nspawn_entries() {
        // "locks" and "propagate" are shared by every container on the host
        // and pass validate_name, so they must be rejected by name.
        let tmp = TempDataDir::new("reclaim-shared");
        let calls = RefCell::new(Vec::new());
        for shared in NSPAWN_SHARED_ENTRIES {
            let (root, dir) = runtime_fixture(&tmp, shared);
            let err =
                reclaim_nspawn_runtime_in(&root, shared, false, &probe(Liveness::Stopped, &calls))
                    .unwrap_err();
            assert!(
                format!("{err:#}").contains("shared systemd-nspawn state"),
                "unexpected error: {err:#}"
            );
            assert!(dir.exists());
        }
        // Rejected before any liveness query, so no bus traffic either.
        assert!(calls.borrow().is_empty());
    }

    #[test]
    fn test_reclaim_rejects_invalid_names() {
        // The name becomes a path component under the runtime root, so
        // traversal and other invalid names never reach the filesystem.
        let tmp = TempDataDir::new("reclaim-invalid");
        let root = tmp.path().join("nspawn");
        let sibling = tmp.path().join("keep");
        fs::create_dir_all(&sibling).unwrap();
        fs::create_dir_all(&root).unwrap();
        let calls = RefCell::new(Vec::new());
        for bad in ["../keep", "..", "", "Upper", "a/b"] {
            let err =
                reclaim_nspawn_runtime_in(&root, bad, false, &probe(Liveness::Stopped, &calls))
                    .unwrap_err();
            assert!(
                format!("{err:#}").contains("invalid container name"),
                "unexpected error for {bad:?}: {err:#}"
            );
        }
        assert!(sibling.exists());
        assert!(calls.borrow().is_empty());
    }

    #[test]
    fn test_reclaim_without_leftover_state_asks_nothing() {
        // The common case: no leftover directory, so no D-Bus round trips.
        let tmp = TempDataDir::new("reclaim-absent");
        let root = tmp.path().join("nspawn");
        fs::create_dir_all(&root).unwrap();
        let calls = RefCell::new(Vec::new());
        reclaim_nspawn_runtime_in(&root, "cleanbox", false, &probe(Liveness::Stopped, &calls))
            .unwrap();
        assert!(calls.borrow().is_empty());
    }
}
