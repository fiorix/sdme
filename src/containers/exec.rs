//! Container exec, join, and OCI app namespace entry.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;

use anyhow::{bail, Context, Result};

use crate::{systemd, State};

use super::ensure_exists;

/// Verify that a container exists and is currently running.
fn ensure_running(datadir: &Path, name: &str) -> Result<()> {
    ensure_exists(datadir, name)?;
    if !systemd::is_active(name)? {
        bail!("container '{name}' is not running");
    }
    Ok(())
}

/// Enter a running container via `machinectl shell`.
pub fn join(
    datadir: &Path,
    name: &str,
    command: &[String],
    join_as_sudo_user: bool,
    verbose: bool,
) -> Result<ExitStatus> {
    ensure_running(datadir, name)?;
    machinectl_shell(datadir, name, command, join_as_sudo_user, verbose)
}

/// Run a one-off command in a running container via `machinectl shell`.
pub fn exec(
    datadir: &Path,
    name: &str,
    command: &[String],
    join_as_sudo_user: bool,
    verbose: bool,
) -> Result<ExitStatus> {
    ensure_running(datadir, name)?;
    machinectl_shell(datadir, name, command, join_as_sudo_user, verbose)
}

/// Candidate inner cgroup paths under a container's cgroup.
/// systemd-nspawn organizes its cgroup subtree differently depending on
/// the version and configuration; we try each one.
const CGROUP_INNER_PATHS: &[&str] = &[
    "init.scope/system.slice",
    "payload/system.slice",
    "system.slice",
];

/// Locate the cgroup directory for the OCI app's systemd service inside
/// the container's cgroup hierarchy (cgroups v2).
///
/// Tries two cgroup root patterns:
/// - `sdme@{name}.service` (systemd < 257, template unit cgroup)
/// - `machine-{escaped}.scope` (systemd >= 257, machine scope cgroup)
fn find_oci_service_cgroup(name: &str, app_name: &str) -> Result<PathBuf> {
    let service_name = format!("sdme-oci-{app_name}.service");
    let machine_slice = PathBuf::from("/sys/fs/cgroup/machine.slice");

    // systemd >= 257 uses machine-{name}.scope with hyphens escaped as \x2d.
    // systemd >= 259 registers the scope directly as {name}.scope.
    let escaped_name = name.replace('-', "\\x2d");
    let cgroup_roots = [
        machine_slice.join(format!("{name}.scope")),
        machine_slice.join(format!("sdme@{name}.service")),
        machine_slice.join(format!("machine-{escaped_name}.scope")),
    ];

    // Retry briefly: the cgroup directory may not be visible on the
    // filesystem immediately after systemd reports the unit as active.
    let mut attempts = 0;
    loop {
        for root in &cgroup_roots {
            for inner in CGROUP_INNER_PATHS {
                let candidate = root.join(inner).join(&service_name);
                if candidate.is_dir() {
                    return Ok(candidate);
                }
            }
        }
        attempts += 1;
        if attempts >= 30 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    bail!(
        "cgroup for {service_name} not found under {}",
        machine_slice.display()
    )
}

/// Parse the `NSpid:` line from `/proc/{pid}/status` content.
/// Returns the list of namespace PIDs (host PID first, then inner PIDs).
fn parse_nspid(status_content: &str) -> Option<Vec<u32>> {
    for line in status_content.lines() {
        if let Some(rest) = line.strip_prefix("NSpid:") {
            let pids: Vec<u32> = rest
                .split_whitespace()
                .filter_map(|s| s.parse().ok())
                .collect();
            if !pids.is_empty() {
                return Some(pids);
            }
        }
    }
    None
}

/// Find the host PID of the OCI app process by reading `cgroup.procs` and
/// checking each process's `NSpid:` line for one that is PID 1 in the
/// innermost (isolate) PID namespace.
fn find_app_pid(service_cgroup: &Path, app_name: &str) -> Result<u32> {
    let procs_path = service_cgroup.join("cgroup.procs");
    let content = fs::read_to_string(&procs_path)
        .with_context(|| format!("failed to read {}", procs_path.display()))?;

    for line in content.lines() {
        let pid: u32 = match line.trim().parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let status_path = format!("/proc/{pid}/status");
        let status = match fs::read_to_string(&status_path) {
            Ok(s) => s,
            Err(_) => continue, // process may have exited
        };
        if let Some(nspids) = parse_nspid(&status) {
            // The app process (inside the isolate namespace) has NSpid with
            // 3+ entries where the last one is 1:
            //   NSpid: <host_pid> <container_pid> 1
            // The isolate parent only has 2 entries (host + container).
            if nspids.len() >= 3 && nspids[nspids.len() - 1] == 1 {
                return Ok(pid);
            }
        }
    }

    bail!(
        "could not find PID 1 process for OCI app '{}' in {}",
        app_name,
        service_cgroup.display()
    )
}

/// Run a command inside a container's OCI app namespaces using `nsenter`.
///
/// Discovers the app's host PID via its cgroup, then enters its PID, IPC,
/// mount, and network namespaces so the command sees the app's filesystem,
/// processes, and network.
pub fn exec_oci(
    datadir: &Path,
    name: &str,
    app_name: &str,
    command: &[String],
    verbose: bool,
) -> Result<ExitStatus> {
    ensure_running(datadir, name)?;

    crate::system_check::find_program("nsenter")
        .context("nsenter is required for exec --oci (install util-linux)")?;

    let service_cgroup = find_oci_service_cgroup(name, app_name)?;
    let app_pid = find_app_pid(&service_cgroup, app_name)?;

    let pid_str = app_pid.to_string();
    let mut cmd = std::process::Command::new("nsenter");
    cmd.args(["-t", &pid_str, "--pid", "--ipc", "--mount", "--net", "--"]);
    cmd.args(command);

    if verbose {
        eprintln!(
            "exec: nsenter {}",
            cmd.get_args()
                .map(|a| a.to_string_lossy())
                .collect::<Vec<_>>()
                .join(" ")
        );
    }

    let status = cmd.status().context("failed to run nsenter")?;
    crate::check_interrupted()?;
    Ok(status)
}

fn machinectl_shell(
    datadir: &Path,
    name: &str,
    command: &[String],
    join_as_sudo_user: bool,
    verbose: bool,
) -> Result<ExitStatus> {
    let mut cmd = std::process::Command::new("machinectl");
    cmd.arg("shell");

    if join_as_sudo_user {
        let state_path = datadir.join("state").join(name);
        if let Ok(state) = State::read_from(&state_path) {
            if state.get("ROOTFS") == Some("") {
                if let Some(su) = crate::sudo_user() {
                    let opaque = state.get("OPAQUE_DIRS").unwrap_or("");
                    if opaque.is_empty() {
                        eprintln!("host rootfs container: joining as user '{}'", su.name);
                    } else {
                        let dirs = opaque.split(',').collect::<Vec<_>>().join(", ");
                        eprintln!(
                            "host rootfs container: joining as user '{}' with opaque dirs {dirs}",
                            su.name
                        );
                    }
                    cmd.args(["--uid", &su.name]);
                } else if verbose {
                    eprintln!("host rootfs container but no sudo user detected; joining as root");
                }
            }
        }
    }

    cmd.arg(name);
    if !command.is_empty() {
        cmd.args(command);
    }
    if verbose {
        eprintln!(
            "exec: machinectl {}",
            cmd.get_args()
                .map(|a| a.to_string_lossy())
                .collect::<Vec<_>>()
                .join(" ")
        );
    }
    let status = cmd.status().context("failed to run machinectl")?;
    crate::check_interrupted()?;
    Ok(status)
}

#[cfg(test)]
pub(super) use self::test_helpers::parse_nspid_public;

#[cfg(test)]
mod test_helpers {
    use super::*;

    /// Expose parse_nspid for tests in the sibling tests module.
    pub fn parse_nspid_public(status_content: &str) -> Option<Vec<u32>> {
        parse_nspid(status_content)
    }
}
