//! Ephemeral containers: exit triggers, health checks, and teardown.
//!
//! An ephemeral container runs as a transient systemd unit
//! (`sdme-ephemeral@NAME.service`) and any stop removes it. Exit triggers
//! decide when it stops:
//!
//! - Session trigger: the unit is bound to a transient scope holding the
//!   `sdme new` client (see [`crate::systemd::start_ephemeral`]).
//! - Service trigger: main services get a drop-in in the upper layer with
//!   `SuccessAction=exit` and `FailureAction=exit`, so the container's
//!   systemd exits when the first of them finishes.
//! - Health trigger: a host transient timer runs [`run_health_check`],
//!   which stops the unit after too many consecutive failures.
//!
//! Teardown ([`teardown`]) runs from the unit's `ExecStopPost`.

use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use crate::{systemd, validate_name, State};

/// Default seconds between health checks (Docker-compatible).
pub const DEFAULT_HEALTH_INTERVAL: u64 = 30;
/// Default seconds before a health check attempt counts as failed.
pub const DEFAULT_HEALTH_TIMEOUT: u64 = 30;
/// Default consecutive failures that stop the container.
pub const DEFAULT_HEALTH_RETRIES: u32 = 3;

/// Name of the drop-in that installs the service trigger on a main service.
const TRIGGER_DROPIN: &str = "sdme-ephemeral.conf";

/// Directory holding consecutive health check failure counters.
const HEALTH_RUN_DIR: &str = "/run/sdme/health";

/// How long teardown waits for the container lock. A concurrent `sdme cp`
/// or a client still finishing its boot-failure path holds it briefly.
const TEARDOWN_LOCK_WAIT: Duration = Duration::from_secs(30);

/// What a health check probes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HealthProbe {
    /// Command run via `/bin/sh -c` inside the container.
    Cmd(String),
    /// HTTP GET on 127.0.0.1 in the container's network namespace.
    Http {
        /// TCP port.
        port: u16,
        /// Request path, starting with `/`.
        path: String,
    },
    /// TCP connect to 127.0.0.1 in the container's network namespace.
    Tcp {
        /// TCP port.
        port: u16,
    },
}

/// Health trigger configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthCheck {
    /// The check to run.
    pub probe: HealthProbe,
    /// Seconds between checks.
    pub interval: u64,
    /// Seconds before an attempt counts as failed.
    pub timeout: u64,
    /// Consecutive failures that stop the container.
    pub retries: u32,
    /// Seconds after boot before the first check.
    pub start_period: u64,
}

/// Exit trigger configuration persisted in the state file.
///
/// The session trigger is not persisted: it exists only for the
/// lifetime of the `sdme new` client that started the container.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EphemeralConfig {
    /// Main services (unit names inside the container).
    pub main_services: Vec<String>,
    /// Health trigger, if any.
    pub health: Option<HealthCheck>,
}

impl EphemeralConfig {
    /// Write `EPHEMERAL=yes` and the trigger configuration to `state`.
    pub fn write_to_state(&self, state: &mut State) {
        state.set("EPHEMERAL", "yes");
        state.set_list("MAIN_SERVICES", &self.main_services, ',');
        if let Some(h) = &self.health {
            match &h.probe {
                HealthProbe::Cmd(cmd) => state.set("HEALTH_CMD", cmd.as_str()),
                HealthProbe::Http { port, path } => {
                    state.set("HEALTH_HTTP", format!("{port}{path}"))
                }
                HealthProbe::Tcp { port } => state.set("HEALTH_TCP", port.to_string()),
            }
            state.set("HEALTH_INTERVAL", h.interval.to_string());
            state.set("HEALTH_TIMEOUT", h.timeout.to_string());
            state.set("HEALTH_RETRIES", h.retries.to_string());
            state.set("HEALTH_START_PERIOD", h.start_period.to_string());
        }
    }

    /// Read the trigger configuration from `state`.
    pub fn from_state(state: &State) -> Result<Self> {
        Ok(Self {
            main_services: state.get_list("MAIN_SERVICES", ','),
            health: HealthCheck::from_state(state)?,
        })
    }
}

impl HealthCheck {
    /// Read the health check from `state`. Returns `None` if none is set.
    pub fn from_state(state: &State) -> Result<Option<Self>> {
        let probe = if let Some(cmd) = state.get_nonempty("HEALTH_CMD") {
            HealthProbe::Cmd(cmd.to_string())
        } else if let Some(spec) = state.get_nonempty("HEALTH_HTTP") {
            parse_http_spec(spec)?
        } else if let Some(port) = state.get_nonempty("HEALTH_TCP") {
            HealthProbe::Tcp {
                port: parse_port(port)?,
            }
        } else {
            return Ok(None);
        };
        let num = |key: &str, default: u64| -> Result<u64> {
            match state.get_nonempty(key) {
                Some(v) => v
                    .parse()
                    .with_context(|| format!("invalid {key} in state file: {v:?}")),
                None => Ok(default),
            }
        };
        Ok(Some(Self {
            probe,
            interval: num("HEALTH_INTERVAL", DEFAULT_HEALTH_INTERVAL)?,
            timeout: num("HEALTH_TIMEOUT", DEFAULT_HEALTH_TIMEOUT)?,
            retries: num("HEALTH_RETRIES", DEFAULT_HEALTH_RETRIES as u64)? as u32,
            start_period: num("HEALTH_START_PERIOD", 0)?,
        }))
    }

    /// Validate timing values.
    pub fn validate(&self) -> Result<()> {
        if self.interval == 0 {
            bail!("--health-interval must be at least 1 second");
        }
        if self.timeout == 0 {
            bail!("--health-timeout must be at least 1 second");
        }
        if self.retries == 0 {
            bail!("--health-retries must be at least 1");
        }
        if let HealthProbe::Cmd(cmd) = &self.probe {
            if cmd.trim().is_empty() {
                bail!("--health-cmd cannot be empty");
            }
            // The state file is line-based; a newline would split the entry.
            if cmd.contains(['\n', '\r', '\0']) {
                bail!("--health-cmd cannot contain newlines or NUL bytes");
            }
        }
        Ok(())
    }
}

/// Parse a TCP port number (1-65535).
pub fn parse_port(s: &str) -> Result<u16> {
    let port: u16 = s
        .parse()
        .with_context(|| format!("invalid port '{s}': expected 1-65535"))?;
    if port == 0 {
        bail!("invalid port '{s}': expected 1-65535");
    }
    Ok(port)
}

/// Parse a `--health-http` value: `PORT[/PATH]`.
///
/// # Examples
///
/// ```
/// use sdme::ephemeral::{parse_http_spec, HealthProbe};
/// assert_eq!(
///     parse_http_spec("8080/healthz").unwrap(),
///     HealthProbe::Http { port: 8080, path: "/healthz".into() }
/// );
/// ```
pub fn parse_http_spec(spec: &str) -> Result<HealthProbe> {
    let (port, path) = match spec.find('/') {
        Some(i) => (&spec[..i], &spec[i..]),
        None => (spec, "/"),
    };
    let port = parse_port(port)?;
    // The path goes verbatim into the request line.
    if !path.bytes().all(|b| b.is_ascii_graphic()) {
        bail!("invalid --health-http path '{path}': must be printable ASCII without spaces");
    }
    Ok(HealthProbe::Http {
        port,
        path: path.to_string(),
    })
}

/// Normalize and validate a main service unit name.
///
/// A bare name gets `.service` appended. Unit names are written into the
/// upper layer as `{unit}.d/` directories, so path separators and
/// anything outside systemd's unit name alphabet are rejected.
pub fn normalize_main_service(name: &str) -> Result<String> {
    let unit = if name.ends_with(".service") {
        name.to_string()
    } else if name.contains('.') {
        bail!("invalid main service '{name}': only .service units are supported");
    } else {
        format!("{name}.service")
    };
    let stem = &unit[..unit.len() - ".service".len()];
    if stem.is_empty() || unit.len() > 255 {
        bail!("invalid main service '{name}'");
    }
    if stem.starts_with('.') || stem.ends_with('@') {
        bail!("invalid main service '{name}'");
    }
    if !stem
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '_' | '.' | '-' | '@' | '\\'))
    {
        bail!("invalid main service '{name}': contains characters not allowed in unit names");
    }
    Ok(unit)
}

/// Resolve the main services for a new ephemeral container.
///
/// Explicit services replace the OCI app default; `no_main_service`
/// disables the service trigger entirely.
pub fn resolve_main_services(
    explicit: &[String],
    no_main_service: bool,
    oci_app: Option<&str>,
) -> Result<Vec<String>> {
    if no_main_service {
        if !explicit.is_empty() {
            bail!("--main-service and --no-main-service are mutually exclusive");
        }
        return Ok(Vec::new());
    }
    if !explicit.is_empty() {
        let mut out = Vec::new();
        for s in explicit {
            let unit = normalize_main_service(s)?;
            if !out.contains(&unit) {
                out.push(unit);
            }
        }
        return Ok(out);
    }
    Ok(oci_app
        .map(|app| vec![format!("sdme-oci-{app}.service")])
        .unwrap_or_default())
}

/// Content of the service-trigger drop-in installed on each main service.
pub fn trigger_dropin_content() -> &'static str {
    "\
# Generated by sdme: this is a main service of an ephemeral container.
# When it finishes, the container's systemd exits (propagating the
# service's exit status) and the host tears the container down.
[Unit]
SuccessAction=exit
FailureAction=exit
"
}

/// Write the service-trigger drop-in for each main service into the
/// container's writable root (overlay upper layer or btrfs subvolume).
///
/// `unit_rel` is the unit directory relative to the rootfs (see
/// `oci::app::systemd_unit_dir`).
pub fn write_service_triggers(
    root_dir: &Path,
    unit_rel: &str,
    backend: crate::storage::Backend,
    services: &[String],
    verbose: bool,
) -> Result<()> {
    for svc in services {
        let rel = format!("{unit_rel}/{svc}.d");
        // A btrfs root is a snapshot of the rootfs, whose symlinks could
        // redirect the write outside it.
        if backend == crate::storage::Backend::Btrfs {
            crate::copy::reject_symlinked_path(root_dir, &rel)?;
        }
        let dir = root_dir.join(&rel);
        fs::create_dir_all(&dir).with_context(|| format!("failed to create {}", dir.display()))?;
        let path = dir.join(TRIGGER_DROPIN);
        fs::write(&path, trigger_dropin_content())
            .with_context(|| format!("failed to write {}", path.display()))?;
        if verbose {
            eprintln!("installed service trigger: {}", path.display());
        }
    }
    Ok(())
}

/// Return true if the container's state file marks it as ephemeral.
pub fn is_ephemeral(datadir: &Path, name: &str) -> bool {
    State::read_from(&datadir.join("state").join(name))
        .map(|s| s.is_yes("EPHEMERAL"))
        .unwrap_or(false)
}

/// Fail if the container is ephemeral, with a hint for `verb`.
pub fn refuse_if_ephemeral(datadir: &Path, name: &str, verb: &str) -> Result<()> {
    if is_ephemeral(datadir, name) {
        bail!("cannot {verb} '{name}': ephemeral containers are removed when they stop");
    }
    Ok(())
}

/// Remove an ephemeral container's files after its unit stopped.
///
/// Runs from the transient unit's `ExecStopPost`, after the overlayfs
/// mounts were unmounted. Succeeds if the container is already gone
/// (the client may have removed it). Refuses to touch containers that
/// are not marked ephemeral, so a stray unit cannot delete a persistent
/// container.
pub fn teardown(datadir: &Path, name: &str, verbose: bool) -> Result<()> {
    teardown_with(datadir, name, verbose, crate::containers::delete_stopped)
}

fn teardown_with(
    datadir: &Path,
    name: &str,
    verbose: bool,
    delete: impl FnOnce(&Path, &str, bool) -> Result<()>,
) -> Result<()> {
    validate_name(name)?;
    let state_path = datadir.join("state").join(name);
    if !state_path.exists() {
        if verbose {
            eprintln!("ephemeral container '{name}' already removed");
        }
        return Ok(());
    }
    let state = State::read_from(&state_path)?;
    if !state.is_yes("EPHEMERAL") {
        bail!("refusing to tear down '{name}': not an ephemeral container");
    }

    let _lock = lock_exclusive_wait(datadir, name, TEARDOWN_LOCK_WAIT)?;
    // Re-check under the lock: a concurrent `sdme rm` may have won.
    if !state_path.exists() {
        return Ok(());
    }

    // Same removal as `sdme rm` once stopped: btrfs subvolume, container
    // directory (refusing while anything under it is still mounted), state.
    delete(datadir, name, verbose)?;
    let _ = fs::remove_file(health_counter_path(name));

    let result = std::env::var("SERVICE_RESULT").unwrap_or_default();
    let status = std::env::var("EXIT_STATUS").unwrap_or_default();
    eprintln!("tore down ephemeral container '{name}' (result={result}, exit-status={status})");
    Ok(())
}

fn lock_exclusive_wait(
    datadir: &Path,
    name: &str,
    timeout: Duration,
) -> Result<crate::lock::ResourceLock> {
    let deadline = Instant::now() + timeout;
    loop {
        match crate::lock::lock_exclusive(datadir, "containers", name) {
            Ok(lock) => return Ok(lock),
            Err(e) if Instant::now() >= deadline => return Err(e),
            Err(_) => std::thread::sleep(Duration::from_millis(200)),
        }
    }
}

fn health_counter_path(name: &str) -> PathBuf {
    Path::new(HEALTH_RUN_DIR).join(name)
}

/// Run one health check attempt and stop the container on the
/// configured number of consecutive failures.
///
/// Runs from the `sdme-health@NAME.service` oneshot triggered by the
/// host transient timer. A failed attempt is not an error: the
/// consecutive failure count is kept under `/run/sdme/health/`.
pub fn run_health_check(datadir: &Path, name: &str, verbose: bool) -> Result<()> {
    validate_name(name)?;
    let state = State::read_from(&datadir.join("state").join(name))?;
    if !state.is_yes("EPHEMERAL") {
        bail!("'{name}' is not an ephemeral container");
    }
    let check = HealthCheck::from_state(&state)?
        .with_context(|| format!("no health check configured for '{name}'"))?;
    let leader = systemd::get_machine_leader(name)?
        .with_context(|| format!("container '{name}' is not running"))?;

    let timeout = Duration::from_secs(check.timeout);
    let outcome = match &check.probe {
        HealthProbe::Cmd(cmd) => exec_check(leader, cmd, timeout),
        HealthProbe::Tcp { port } => net_check(leader, *port, None, timeout),
        HealthProbe::Http { port, path } => net_check(leader, *port, Some(path), timeout),
    };

    let counter = health_counter_path(name);
    match outcome {
        Ok(()) => {
            if verbose {
                eprintln!("health check passed for '{name}'");
            }
            let _ = fs::remove_file(&counter);
            Ok(())
        }
        Err(e) => {
            let failures = fs::read_to_string(&counter)
                .ok()
                .and_then(|s| s.trim().parse::<u32>().ok())
                .unwrap_or(0)
                + 1;
            eprintln!(
                "health check failed for '{name}' ({failures}/{}): {e:#}",
                check.retries
            );
            if failures >= check.retries {
                let _ = fs::remove_file(&counter);
                eprintln!(
                    "stopping ephemeral container '{name}': health check failed {failures} times"
                );
                systemd::stop_ephemeral_unit(name)?;
            } else {
                fs::create_dir_all(HEALTH_RUN_DIR)
                    .with_context(|| format!("failed to create {HEALTH_RUN_DIR}"))?;
                fs::write(&counter, failures.to_string())
                    .with_context(|| format!("failed to write {}", counter.display()))?;
            }
            Ok(())
        }
    }
}

/// Run `/bin/sh -c CMD` in the container's namespaces with a timeout.
fn exec_check(leader: u32, cmd: &str, timeout: Duration) -> Result<()> {
    use std::os::unix::process::CommandExt;

    let pid = leader.to_string();
    let mut command = std::process::Command::new("nsenter");
    command.args(["-t", &pid, "-m", "-u", "-i", "-n", "-p"]);
    if systemd::has_foreign_userns(leader) {
        command.args(["-C", "-U"]);
    }
    command
        .args(["--", "/bin/sh", "-c", cmd])
        .env_clear()
        .env(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        )
        .stdin(std::process::Stdio::null())
        // Own process group so a timeout kills nsenter's forked child too.
        .process_group(0);
    let mut child = command.spawn().context("failed to run nsenter")?;
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            if status.success() {
                return Ok(());
            }
            bail!("command exited with {status}");
        }
        if Instant::now() >= deadline {
            unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
            let _ = child.wait();
            bail!("command timed out after {}s", timeout.as_secs());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Connect to 127.0.0.1:port inside the container's network namespace,
/// and for HTTP checks send a GET and require a 2xx or 3xx status.
///
/// setns(CLONE_NEWNET) only affects the calling thread, so the check
/// runs on a dedicated thread and the rest of the process stays in the
/// host namespace.
fn net_check(leader: u32, port: u16, http_path: Option<&str>, timeout: Duration) -> Result<()> {
    let ns_path = format!("/proc/{leader}/ns/net");
    let path = http_path.map(String::from);
    std::thread::spawn(move || -> Result<()> {
        use std::os::fd::AsRawFd;
        let ns = fs::File::open(&ns_path).with_context(|| format!("failed to open {ns_path}"))?;
        if unsafe { libc::setns(ns.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("failed to enter {ns_path}"));
        }
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let mut stream = TcpStream::connect_timeout(&addr, timeout)
            .with_context(|| format!("connect to {addr} failed"))?;
        let Some(path) = path else {
            return Ok(());
        };
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        write!(
            stream,
            "GET {path} HTTP/1.0\r\nHost: 127.0.0.1:{port}\r\nUser-Agent: sdme-health\r\n\r\n"
        )?;
        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf)?;
        let status = http_status(&buf[..n])
            .with_context(|| format!("invalid HTTP response from {addr}{path}"))?;
        if !(200..400).contains(&status) {
            bail!("GET {path} returned HTTP {status}");
        }
        Ok(())
    })
    .join()
    .map_err(|_| anyhow::anyhow!("health check thread panicked"))?
}

/// Parse the status code from the start of an HTTP/1.x response.
fn http_status(resp: &[u8]) -> Option<u16> {
    let line = std::str::from_utf8(resp).ok()?.lines().next()?;
    let mut parts = line.split_whitespace();
    if !parts.next()?.starts_with("HTTP/") {
        return None;
    }
    parts.next()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDataDir;

    #[test]
    fn main_service_normalization() {
        assert_eq!(normalize_main_service("nginx").unwrap(), "nginx.service");
        assert_eq!(
            normalize_main_service("getty@tty1.service").unwrap(),
            "getty@tty1.service"
        );
        assert!(normalize_main_service("../etc").is_err());
        assert!(normalize_main_service("a/b.service").is_err());
        assert!(normalize_main_service("foo.timer").is_err());
        assert!(normalize_main_service(".service").is_err());
        assert!(normalize_main_service("a b").is_err());
    }

    #[test]
    fn main_services_resolution() {
        let none: Vec<String> = Vec::new();
        assert_eq!(
            resolve_main_services(&none, false, Some("nginx")).unwrap(),
            vec!["sdme-oci-nginx.service"]
        );
        assert!(resolve_main_services(&none, true, Some("nginx"))
            .unwrap()
            .is_empty());
        assert!(resolve_main_services(&none, false, None)
            .unwrap()
            .is_empty());
        let explicit = vec!["a".to_string(), "a.service".to_string(), "b".to_string()];
        assert_eq!(
            resolve_main_services(&explicit, false, Some("nginx")).unwrap(),
            vec!["a.service", "b.service"]
        );
        assert!(resolve_main_services(&explicit, true, None).is_err());
    }

    #[test]
    fn http_spec_parsing() {
        assert_eq!(
            parse_http_spec("80").unwrap(),
            HealthProbe::Http {
                port: 80,
                path: "/".into()
            }
        );
        assert!(parse_http_spec("0/x").is_err());
        assert!(parse_http_spec("80/a b").is_err());
        assert!(parse_http_spec("x/").is_err());
    }

    #[test]
    fn http_status_parsing() {
        assert_eq!(http_status(b"HTTP/1.1 204 No Content\r\n"), Some(204));
        assert_eq!(http_status(b"HTTP/1.0 503 x"), Some(503));
        assert_eq!(http_status(b"SSH-2.0-OpenSSH"), None);
    }

    #[test]
    fn state_round_trip() {
        let cfg = EphemeralConfig {
            main_services: vec!["a.service".into(), "b.service".into()],
            health: Some(HealthCheck {
                probe: HealthProbe::Cmd("curl -fs http://localhost/?a=b".into()),
                interval: 5,
                timeout: 2,
                retries: 4,
                start_period: 10,
            }),
        };
        let mut state = State::new();
        cfg.write_to_state(&mut state);
        let parsed = State::parse(&state.serialize()).unwrap();
        assert!(parsed.is_yes("EPHEMERAL"));
        assert_eq!(EphemeralConfig::from_state(&parsed).unwrap(), cfg);

        let tcp = EphemeralConfig {
            main_services: Vec::new(),
            health: Some(HealthCheck {
                probe: HealthProbe::Tcp { port: 6379 },
                interval: DEFAULT_HEALTH_INTERVAL,
                timeout: DEFAULT_HEALTH_TIMEOUT,
                retries: DEFAULT_HEALTH_RETRIES,
                start_period: 0,
            }),
        };
        let mut state = State::new();
        tcp.write_to_state(&mut state);
        assert_eq!(state.get("MAIN_SERVICES"), None);
        assert_eq!(EphemeralConfig::from_state(&state).unwrap(), tcp);
    }

    #[test]
    fn health_validation() {
        let mut h = HealthCheck {
            probe: HealthProbe::Cmd("true".into()),
            interval: 1,
            timeout: 1,
            retries: 1,
            start_period: 0,
        };
        assert!(h.validate().is_ok());
        h.probe = HealthProbe::Cmd("a\nb".into());
        assert!(h.validate().is_err());
        h.probe = HealthProbe::Tcp { port: 1 };
        h.retries = 0;
        assert!(h.validate().is_err());
    }

    #[test]
    fn teardown_refuses_persistent() {
        let tmp = TempDataDir::new("ephemeral-persistent");
        let dir = tmp.path();
        fs::create_dir_all(dir.join("state")).unwrap();
        fs::write(dir.join("state/box"), "NAME=box\n").unwrap();
        let never = |_: &Path, _: &str, _: bool| -> Result<()> { panic!("must not delete") };
        let err = teardown_with(dir, "box", false, never).unwrap_err();
        assert!(format!("{err}").contains("not an ephemeral container"));
        assert!(dir.join("state/box").exists());
    }

    #[test]
    fn teardown_missing_is_ok_and_deletes_ephemeral() {
        let tmp = TempDataDir::new("ephemeral-remove");
        let dir = tmp.path();
        let never = |_: &Path, _: &str, _: bool| -> Result<()> { panic!("must not delete") };
        assert!(teardown_with(dir, "gone", false, never).is_ok());
        assert!(teardown_with(dir, "../x", false, never).is_err());

        fs::create_dir_all(dir.join("state")).unwrap();
        fs::write(dir.join("state/eph"), "EPHEMERAL=yes\nNAME=eph\n").unwrap();
        let mut deleted = false;
        teardown_with(dir, "eph", false, |d, n, _| {
            deleted = true;
            fs::remove_file(d.join("state").join(n))?;
            Ok(())
        })
        .unwrap();
        assert!(deleted);
    }
}
