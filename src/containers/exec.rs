//! Container exec, join, and OCI app namespace entry.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;

use anyhow::{bail, Context, Result};

use crate::{systemd, State};

use super::ensure_exists;

/// Shared options for container shell operations (join, exec, exec_oci).
pub struct ShellOptions<'a> {
    /// Data directory containing container state.
    pub datadir: &'a Path,
    /// Container name.
    pub name: &'a str,
    /// Enable verbose output.
    pub verbose: bool,
}

/// Verify that a container exists and is currently running.
fn ensure_running(opts: &ShellOptions) -> Result<()> {
    ensure_exists(opts.datadir, opts.name)?;
    if !systemd::is_active(opts.name)? {
        bail!("container '{}' is not running", opts.name);
    }
    Ok(())
}

/// Enter a running container via `machinectl shell`.
///
/// `user` is the explicit `--user` flag value. `Some("root")` forces root;
/// `Some(name)` runs as that UNIX user; `None` selects the default: for a
/// host-rootfs clone with `join_as_sudo_user` enabled and `$SUDO_USER` set,
/// the default is that sudo user; otherwise it is root.
pub fn join(
    opts: &ShellOptions,
    command: &[String],
    user: Option<&str>,
    join_as_sudo_user: bool,
) -> Result<ExitStatus> {
    ensure_running(opts)?;
    machinectl_shell(opts, command, user, join_as_sudo_user)
}

/// Run a one-off command in a running container via `machinectl shell`.
///
/// `user` follows the same rule as [`join`]: `Some("root")` forces root,
/// `Some(name)` runs as that UNIX user, `None` picks the default (sudo
/// user on host-rootfs clones when `join_as_sudo_user` is on, else root).
pub fn exec(
    opts: &ShellOptions,
    command: &[String],
    user: Option<&str>,
    join_as_sudo_user: bool,
) -> Result<ExitStatus> {
    ensure_running(opts)?;
    machinectl_shell(opts, command, user, join_as_sudo_user)
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
pub fn exec_oci(opts: &ShellOptions, app_name: &str, command: &[String]) -> Result<ExitStatus> {
    ensure_running(opts)?;

    crate::system_check::find_program("nsenter")
        .context("nsenter is required for exec --oci (install util-linux)")?;

    let service_cgroup = find_oci_service_cgroup(opts.name, app_name)?;
    let app_pid = find_app_pid(&service_cgroup, app_name)?;

    let pid_str = app_pid.to_string();
    let mut cmd = std::process::Command::new("nsenter");
    cmd.args(["-t", &pid_str, "--pid", "--ipc", "--mount", "--net", "--"]);
    cmd.args(command);

    if opts.verbose {
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

/// Resolve the UNIX user to pass to `machinectl shell --uid`.
///
/// Rules:
/// - `cli_user = Some("root")` -> `None` (explicit root, rely on
///   machinectl's default).
/// - `cli_user = Some(name)`   -> `Some(name)` (explicit override always wins).
/// - `cli_user = None`         -> only fall through to `$SUDO_USER` when the
///   container is a host clone (`ROOTFS == ""`) AND
///   `join_as_sudo_user` is on AND `sudo_user()` resolves.
///   Otherwise `None` (default to root).
fn resolve_target_user(
    state: Option<&State>,
    cli_user: Option<&str>,
    join_as_sudo_user: bool,
) -> Option<String> {
    if let Some(u) = cli_user {
        return if u == "root" {
            None
        } else {
            Some(u.to_string())
        };
    }
    if !join_as_sudo_user {
        return None;
    }
    let state = state?;
    if state.get("ROOTFS") != Some("") {
        return None;
    }
    crate::sudo_user().map(|su| su.name)
}

fn machinectl_shell(
    opts: &ShellOptions,
    command: &[String],
    user: Option<&str>,
    join_as_sudo_user: bool,
) -> Result<ExitStatus> {
    let ShellOptions {
        datadir,
        name,
        verbose,
    } = *opts;
    let mut cmd = std::process::Command::new("machinectl");
    cmd.arg("shell");

    // Read state once so the user resolution and the opaque-dirs hint
    // share the same view.
    let state = State::read_from(&datadir.join("state").join(name)).ok();
    let state_ref = state.as_ref();

    if let Some(uid_name) = resolve_target_user(state_ref, user, join_as_sudo_user) {
        if user.is_none() {
            // Implicit host-clone fall-through: surface it so the operator
            // sees why the session is not running as root.
            let opaque = state_ref.and_then(|s| s.get("OPAQUE_DIRS")).unwrap_or("");
            if opaque.is_empty() {
                eprintln!("host rootfs container: joining as user '{uid_name}'");
            } else {
                let dirs = opaque.split(',').collect::<Vec<_>>().join(", ");
                eprintln!(
                    "host rootfs container: joining as user '{uid_name}' with opaque dirs {dirs}"
                );
            }
        }
        cmd.args(["--uid", &uid_name]);
    } else if user.is_none() && verbose {
        // Only log this when the user did not ask for anything explicit and
        // we still chose root; otherwise the message is noise.
        if let Some(s) = state_ref {
            if s.get("ROOTFS") == Some("") && join_as_sudo_user {
                eprintln!("host rootfs container but no sudo user detected; joining as root");
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

    // Run machinectl with inherited stdio so interactive PTY sessions
    // work correctly. If it fails, probe stderr separately to decide
    // whether to fall back to nsenter.
    let status = cmd.status().context("failed to run machinectl")?;
    crate::check_interrupted()?;

    if status.success() {
        return Ok(status);
    }

    // machinectl failed. Probe with a trivial command to capture
    // stderr and check if this is a PTY allocation failure.
    let mut probe = std::process::Command::new("machinectl");
    probe.args(["shell", name, "/bin/true"]);
    probe.stdout(std::process::Stdio::null());
    probe.stderr(std::process::Stdio::piped());
    let probe_out = probe.output().unwrap_or_else(|_| std::process::Output {
        status,
        stdout: Vec::new(),
        stderr: Vec::new(),
    });
    let stderr = String::from_utf8_lossy(&probe_out.stderr);
    if !stderr.contains("Failed to get shell PTY") && !stderr.contains("Access denied") {
        return Ok(status);
    }

    // PTY allocation failed; fall back to nsenter.
    if verbose {
        eprint!("machinectl stderr: {}", stderr);
    }
    eprintln!("warning: machinectl shell failed (PTY access denied), falling back to nsenter");
    eprintln!("note: using nsenter with script(1) for PTY allocation");
    nsenter_shell(name, command, verbose)
}

/// Fall back to nsenter when machinectl shell cannot allocate a PTY.
///
/// For interactive sessions (no explicit command), returns success
/// regardless of the shell's exit code. nsenter forwards the child's
/// raw exit code, but a non-zero exit from a login shell (e.g. a
/// failing profile script) does not mean the session failed.
/// machinectl shell returns 0 on normal logout; this matches that
/// behavior.
fn nsenter_shell(name: &str, command: &[String], verbose: bool) -> Result<ExitStatus> {
    use std::os::unix::process::ExitStatusExt;

    let leader = systemd::get_machine_leader(name)?
        .ok_or_else(|| anyhow::anyhow!("container '{}' is not registered with machined", name))?;

    let interactive = command.is_empty();

    let uses_userns = systemd::has_foreign_userns(leader);

    if verbose {
        eprintln!("nsenter: leader PID {leader}, userns={uses_userns}");
    }

    let pid_str = leader.to_string();
    let mut cmd = std::process::Command::new("nsenter");
    cmd.args(["-t", &pid_str, "-m", "-u", "-i", "-n", "-p"]);
    if uses_userns {
        // Enter the user and cgroup namespaces so systemctl and other
        // tools that talk to the container's D-Bus can authenticate.
        cmd.args(["-C", "-U"]);
    }
    cmd.arg("--");
    if interactive {
        // Wrap in `script` to allocate a PTY so the shell has
        // proper line editing, carriage returns, and job control.
        cmd.args(["script", "-qc", "/bin/bash -l", "/dev/null"]);
    } else {
        cmd.args(command);
    }

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

    if interactive {
        Ok(ExitStatus::from_raw(0))
    } else {
        Ok(status)
    }
}

#[cfg(test)]
pub(super) use self::test_helpers::{parse_nspid_public, resolve_target_user_public};

#[cfg(test)]
mod test_helpers {
    use super::*;

    /// Expose parse_nspid for tests in the sibling tests module.
    pub fn parse_nspid_public(status_content: &str) -> Option<Vec<u32>> {
        parse_nspid(status_content)
    }

    /// Expose resolve_target_user for tests in the sibling tests module.
    pub fn resolve_target_user_public(
        state: Option<&State>,
        cli_user: Option<&str>,
        join_as_sudo_user: bool,
    ) -> Option<String> {
        resolve_target_user(state, cli_user, join_as_sudo_user)
    }
}
