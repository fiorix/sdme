//! Self-update check and `sdme upgrade` implementation.
//!
//! Three cooperating pieces:
//!
//! 1. **Background probe.** After every non-config command, sdme spawns a
//!    detached subprocess ([`maybe_spawn_background_check`]) that fetches
//!    the latest release JSON from [`Config::update_check.version_url`][v]
//!    with a short timeout and writes a state file under
//!    `{datadir}/update-check.json`. The subprocess uses `setsid` so it
//!    outlives the parent and never blocks the user's command.
//! 2. **Banner.** On subsequent runs, [`maybe_print_banner_from_env`]
//!    reads the state file and prints a one-line banner to stderr if a
//!    newer version is available and stderr is a TTY. No network access.
//! 3. **Upgrade.** [`run_upgrade`] resolves the running binary via
//!    `/proc/self/exe`, streams the release binary to a sibling temp file
//!    with a SHA-256 hasher, verifies the hash against the release's
//!    `SHA256SUMS`, and atomically renames the temp file over the old
//!    binary. A [`TempGuard`] ensures any early return removes the temp.
//!
//! # State file
//!
//! ```json
//! {
//!   "checked_at": 1776856254,
//!   "checked_version": "0.6.11",
//!   "latest_version": "0.7.0",
//!   "download_url":  "https://.../sdme-x86_64-linux",
//!   "checksums_url": "https://.../SHA256SUMS"
//! }
//! ```
//!
//! The `checked_at` timestamp is updated even when the HTTP fetch fails,
//! so a host that can never reach the version URL (air-gapped, strict
//! egress) does not retry the probe on every invocation.
//!
//! # Disabling
//!
//! - Config: `sdme config set update_check.enabled no`
//! - Per-invocation: `SDME_UPDATE_CHECK=0 sdme ...`
//! - Mirror: override the three URL knobs in `[update_check]` to point at
//!   an internal release mirror.
//!
//! [v]: crate::config::UpdateCheckConfig::version_url

use std::env;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::SystemTime;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::{self, Config};

/// Environment override. Setting to `0` disables the probe regardless of config.
const ENV_DISABLE: &str = "SDME_UPDATE_CHECK";

/// Filename of the state file under `Config::datadir`.
const STATE_FILE: &str = "update-check.json";

/// Prefix for the in-flight download temp file: `.sdme.upgrade.<pid>`.
/// The trailing dot matters: it keeps us from matching the probe prefix
/// (which uses a hyphen) when sweeping stale leftovers.
const UPGRADE_TEMP_PREFIX: &str = ".sdme.upgrade.";

/// Prefix for the writability probe file created in `run_upgrade`:
/// `.sdme.upgrade-probe.<pid>`. Deliberately does NOT start with
/// [`UPGRADE_TEMP_PREFIX`] so cleanup never targets it.
const UPGRADE_PROBE_PREFIX: &str = ".sdme.upgrade-probe.";

/// Minimum age before a stale upgrade temp is swept (seconds).
const STALE_TEMP_AGE_SECS: u64 = 600;

/// Connect timeout for background probe (seconds).
const BG_CONNECT_TIMEOUT: u64 = 3;

/// Body timeout for background probe (seconds).
const BG_BODY_TIMEOUT: u64 = 5;

/// Safety cap on the downloaded binary size (128 MiB).
const MAX_BINARY_SIZE: u64 = 128 * 1024 * 1024;

/// Safety cap on JSON / checksum responses (1 MiB).
const MAX_METADATA_SIZE: u64 = 1024 * 1024;

/// Stashed `--config` override from the main command. Read by
/// [`maybe_print_banner_from_env`] so the banner respects the same config
/// file as the rest of the process even though it runs from `main()`.
static CONFIG_OVERRIDE: OnceLock<Option<PathBuf>> = OnceLock::new();

/// Record the effective `--config` path for later use by the banner.
/// Call this exactly once per process, as early as possible in `main`/`run`.
pub fn set_config_override(path: Option<PathBuf>) {
    let _ = CONFIG_OVERRIDE.set(path);
}

/// State recorded after a background check.
#[derive(Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct State {
    /// Unix seconds when the check last ran (success or failure).
    pub checked_at: u64,
    /// Version of the running sdme at the time of the check.
    pub checked_version: String,
    /// Latest version advertised by `version_url` (None on fetch failure).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_version: Option<String>,
    /// Resolved binary download URL for the latest version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download_url: Option<String>,
    /// Resolved SHA256SUMS URL for the latest version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checksums_url: Option<String>,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn env_disabled() -> bool {
    matches!(env::var(ENV_DISABLE), Ok(v) if v == "0")
}

/// Return the path to the update-check state file.
pub fn state_path(cfg: &Config) -> PathBuf {
    cfg.datadir.join(STATE_FILE)
}

/// Read the state file, returning `None` on any read or parse failure.
pub fn read_state(path: &Path) -> Option<State> {
    let contents = fs::read_to_string(path).ok()?;
    serde_json::from_str(&contents).ok()
}

/// Write the state file atomically with world-readable permissions.
pub fn write_state(path: &Path, state: &State) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let body = serde_json::to_vec_pretty(state).context("failed to serialize state")?;
    crate::atomic_write_mode(path, &body, 0o644)
}

/// Map `std::env::consts::ARCH` to the spelling used in sdme release
/// artifact filenames (`sdme-<arch>-linux`).
///
/// The sdme release workflow ships binaries named `sdme-x86_64-linux` and
/// `sdme-aarch64-linux`, matching the Linux kernel's `uname -m` output and
/// the Fedora/glibc/musl target triple. This is intentionally **different**
/// from the OCI architecture spelling used by registries (`amd64`,
/// `arm64`; see [`crate::oci`] internal `host_arch`). Both conventions
/// are correct in their own context: uname-style for kernel / distro
/// tooling, Go-style for OCI images.
pub fn detect_arch() -> Result<&'static str> {
    match env::consts::ARCH {
        "x86_64" => Ok("x86_64"),
        "aarch64" => Ok("aarch64"),
        other => bail!("unsupported architecture: {other} (only x86_64 and aarch64 are supported)"),
    }
}

/// Substitute `{version}` and `{arch}` placeholders in a URL template.
pub fn render_url(template: &str, version: &str, arch: &str) -> String {
    template
        .replace("{version}", version)
        .replace("{arch}", arch)
}

fn parse_semver(s: &str) -> Option<(u32, u32, u32)> {
    let s = s.trim().trim_start_matches('v');
    let mut parts = s.split('.');
    let major: u32 = parts.next()?.parse().ok()?;
    let minor: u32 = parts.next()?.parse().ok()?;
    let patch_raw = parts.next().unwrap_or("0");
    let patch_digits: String = patch_raw
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    let patch: u32 = patch_digits.parse().ok()?;
    Some((major, minor, patch))
}

/// Return `true` iff `latest` parses strictly greater than `current`.
/// Unparseable inputs are treated as "not newer" (safe default).
pub fn semver_newer(latest: &str, current: &str) -> bool {
    match (parse_semver(latest), parse_semver(current)) {
        (Some(l), Some(c)) => l > c,
        _ => false,
    }
}

/// Extract the SHA-256 hex for `binary_name` from a GNU-style SHA256SUMS body.
pub fn parse_sha256sums(body: &str, binary_name: &str) -> Result<String> {
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(2, char::is_whitespace);
        let hash = match parts.next() {
            Some(h) => h,
            None => continue,
        };
        let rest = match parts.next() {
            Some(r) => r.trim_start(),
            None => continue,
        };
        // The path marker may be " filename" (text) or " *filename" (binary).
        let path = rest.strip_prefix('*').unwrap_or(rest);
        let file = Path::new(path).file_name().and_then(|s| s.to_str());
        let matches = file.map(|f| f == binary_name).unwrap_or(false) || path == binary_name;
        if matches {
            if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
                bail!("malformed SHA256 entry for {binary_name}: {hash}");
            }
            return Ok(hash.to_ascii_lowercase());
        }
    }
    bail!("no SHA256 entry found for {binary_name}")
}

/// Resolve `/proc/self/exe` to a canonical absolute path.
fn resolve_self_exe() -> Result<PathBuf> {
    fs::canonicalize("/proc/self/exe")
        .or_else(|_| env::current_exe())
        .context("failed to resolve current executable path")
}

/// Sweep stale `.sdme.upgrade.<pid>` temp files left by crashed upgrades.
///
/// Only removes files whose PID is dead and whose mtime is older than
/// [`STALE_TEMP_AGE_SECS`]. Returns the count removed.
pub fn cleanup_stale_upgrade_temps(binary_dir: &Path) -> Result<usize> {
    let Ok(entries) = fs::read_dir(binary_dir) else {
        return Ok(0);
    };
    let my_pid = std::process::id();
    let now = SystemTime::now();
    Ok(entries
        .flatten()
        .filter(|entry| is_stale_upgrade_temp(entry.path().as_path(), my_pid, now))
        .filter(|entry| fs::remove_file(entry.path()).is_ok())
        .count())
}

/// Decide whether `path` is a stale upgrade temp that we own and may remove.
///
/// A file qualifies only if every condition holds:
///   * name matches `^\.sdme\.upgrade\.(\d+)$`,
///   * PID is not our own and is not currently alive,
///   * file is a regular file (no symlinks or directories),
///   * mtime is at least [`STALE_TEMP_AGE_SECS`] in the past.
fn is_stale_upgrade_temp(path: &Path, my_pid: u32, now: SystemTime) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let Some(pid_str) = name.strip_prefix(UPGRADE_TEMP_PREFIX) else {
        return false;
    };
    if pid_str.is_empty() || !pid_str.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let Ok(pid) = pid_str.parse::<u32>() else {
        return false;
    };
    if pid == my_pid {
        return false;
    }
    // PID still alive: a concurrent upgrade owns this file.
    if unsafe { libc::kill(pid as libc::pid_t, 0) } == 0 {
        return false;
    }
    // symlink_metadata() never follows symlinks, so we won't trust a link
    // even if it targets a regular file elsewhere.
    let Ok(meta) = fs::symlink_metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    // PID-reuse guardrail: recently-touched temps may belong to a process
    // whose PID got recycled after we called kill(0).
    let Ok(mtime) = meta.modified() else {
        return false;
    };
    let Ok(age) = now.duration_since(mtime) else {
        return false;
    };
    age.as_secs() >= STALE_TEMP_AGE_SECS
}

/// Spawn the detached `__update-check` subprocess when due.
///
/// `skip_command` short-circuits the whole mechanism for commands where a
/// probe adds no value (e.g. `sdme config ...`, the probe itself).
pub fn maybe_spawn_background_check(cfg: &Config, skip_command: bool, verbose: bool) {
    if skip_command || !cfg.update_check.enabled || env_disabled() {
        return;
    }
    let interval_secs = cfg.update_check.check_interval_hours.saturating_mul(3600);
    if let Some(state) = read_state(&state_path(cfg)) {
        if now_unix().saturating_sub(state.checked_at) < interval_secs {
            return;
        }
    }
    let exe = match env::current_exe() {
        Ok(p) => p,
        Err(_) => return,
    };
    let mut cmd = Command::new(&exe);
    cmd.arg("__update-check")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // Detach from the controlling terminal so the child survives parent exit.
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    match cmd.spawn() {
        Ok(_) => {
            if verbose {
                eprintln!("update-check: background probe spawned");
            }
        }
        Err(e) => {
            if verbose {
                eprintln!("update-check: failed to spawn probe: {e}");
            }
        }
    }
}

fn bg_http_agent() -> Result<ureq::Agent> {
    crate::import::build_http_agent(false, BG_CONNECT_TIMEOUT, BG_BODY_TIMEOUT)
}

fn upgrade_http_agent(cfg: &Config, verbose: bool) -> Result<ureq::Agent> {
    crate::import::build_http_agent(verbose, cfg.http_timeout, cfg.http_body_timeout)
}

/// Read the response body into a bounded-size `String`.
fn read_body_to_string(response: ureq::http::Response<ureq::Body>) -> Result<String> {
    let mut reader = response.into_body().into_reader().take(MAX_METADATA_SIZE);
    let mut body = String::new();
    reader
        .read_to_string(&mut body)
        .context("failed to read HTTP response body")?;
    Ok(body)
}

/// Fetch the latest version from `version_url` (GitHub-API compatible JSON).
pub fn fetch_latest_version(agent: &ureq::Agent, version_url: &str) -> Result<String> {
    if !version_url.starts_with("https://") {
        bail!("version_url must use https:// scheme");
    }
    let response = agent
        .get(version_url)
        .call()
        .with_context(|| format!("version_url request failed: {version_url}"))?;
    let body = read_body_to_string(response)?;
    let json: serde_json::Value =
        serde_json::from_str(&body).context("version_url response is not JSON")?;
    let tag = json
        .get("tag_name")
        .and_then(|v| v.as_str())
        .context("version_url JSON is missing tag_name")?;
    let version = tag.trim().trim_start_matches('v').to_string();
    if version.is_empty() {
        bail!("tag_name is empty");
    }
    Ok(version)
}

/// Entry point for the hidden `__update-check` subcommand.
///
/// Fetches the latest version, records state, and sweeps stale upgrade
/// temps. All errors are swallowed: this runs detached and must not raise.
pub fn run_background_check(cfg: &Config) -> Result<()> {
    let checked_version = env!("CARGO_PKG_VERSION").to_string();
    let now = now_unix();

    let fetched = bg_http_agent()
        .and_then(|agent| fetch_latest_version(&agent, &cfg.update_check.version_url));

    let state = match fetched {
        Ok(latest) => {
            let arch = detect_arch().unwrap_or("unknown");
            State {
                checked_at: now,
                checked_version,
                latest_version: Some(latest.clone()),
                download_url: Some(render_url(
                    &cfg.update_check.binary_url_template,
                    &latest,
                    arch,
                )),
                checksums_url: Some(render_url(
                    &cfg.update_check.checksums_url_template,
                    &latest,
                    arch,
                )),
            }
        }
        Err(_) => State {
            checked_at: now,
            checked_version,
            ..State::default()
        },
    };

    let _ = write_state(&state_path(cfg), &state);

    if let Ok(exe) = resolve_self_exe() {
        if let Some(dir) = exe.parent() {
            let _ = cleanup_stale_upgrade_temps(dir);
        }
    }

    Ok(())
}

fn stderr_is_tty() -> bool {
    unsafe { libc::isatty(libc::STDERR_FILENO) != 0 }
}

/// Print the "update available" banner to stderr if applicable.
///
/// Loads config from the path stashed by [`set_config_override`] (falling
/// back to the default if not set); swallows all errors.
pub fn maybe_print_banner_from_env() {
    if !stderr_is_tty() || env_disabled() {
        return;
    }
    let config_path = CONFIG_OVERRIDE.get().and_then(|o| o.as_deref());
    let cfg = match config::load(config_path) {
        Ok(c) => c,
        Err(_) => return,
    };
    if !cfg.update_check.enabled {
        return;
    }
    let state = match read_state(&state_path(&cfg)) {
        Some(s) => s,
        None => return,
    };
    let latest = match state.latest_version.as_deref() {
        Some(v) => v,
        None => return,
    };
    let current = env!("CARGO_PKG_VERSION");
    if !semver_newer(latest, current) {
        return;
    }
    eprintln!(
        "sdme: update available: {latest} (you have {current}). \
         Run 'sudo sdme upgrade' or disable with \
         'sdme config set update_check.enabled no'."
    );
}

/// Drop-guard that unlinks a path on drop unless disarmed.
struct TempGuard(Option<PathBuf>);

impl TempGuard {
    fn new(path: PathBuf) -> Self {
        Self(Some(path))
    }
    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for TempGuard {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = fs::remove_file(&path);
        }
    }
}

/// Options for [`run_upgrade`].
pub struct UpgradeOptions<'a> {
    /// Skip the confirmation prompt.
    pub assume_yes: bool,
    /// Only check and report; do not download or replace the binary.
    pub check_only: bool,
    /// Pin to a specific version instead of querying `version_url`.
    pub version_override: Option<&'a str>,
    /// Verbose progress messages to stderr.
    pub verbose: bool,
    /// Interactive session (enables the confirmation prompt).
    pub interactive: bool,
}

/// Execute `sdme upgrade`.
pub fn run_upgrade(cfg: &Config, opts: UpgradeOptions<'_>) -> Result<()> {
    let arch = detect_arch()?;
    let current = env!("CARGO_PKG_VERSION").to_string();

    let target_version = if let Some(v) = opts.version_override {
        let v = v.trim().trim_start_matches('v').to_string();
        if v.is_empty() {
            bail!("--version cannot be empty");
        }
        v
    } else {
        if opts.verbose {
            eprintln!(
                "checking latest version from {}",
                cfg.update_check.version_url
            );
        }
        let agent = upgrade_http_agent(cfg, opts.verbose)?;
        fetch_latest_version(&agent, &cfg.update_check.version_url)?
    };

    if target_version == current {
        println!("sdme is already at version {current}");
        return Ok(());
    }

    if opts.check_only {
        if semver_newer(&target_version, &current) {
            println!("update available: {target_version} (current: {current})");
        } else {
            println!("target version {target_version} is not newer than current {current}");
        }
        return Ok(());
    }

    let exe_path = resolve_self_exe()?;
    let binary_dir = exe_path
        .parent()
        .context("current executable has no parent directory")?
        .to_path_buf();

    let binary_name = format!("sdme-{arch}-linux");
    let download_url = render_url(&cfg.update_check.binary_url_template, &target_version, arch);
    let checksums_url = render_url(
        &cfg.update_check.checksums_url_template,
        &target_version,
        arch,
    );
    if !download_url.starts_with("https://") {
        bail!("binary_url_template must render to an https:// URL: got {download_url}");
    }
    if !checksums_url.starts_with("https://") {
        bail!("checksums_url_template must render to an https:// URL: got {checksums_url}");
    }

    // Writability check on the target directory. Creating a probe file is
    // more reliable than checking mode bits alone because of filesystem,
    // ACL, and bind-mount variations.
    {
        debug_assert!(
            !UPGRADE_PROBE_PREFIX.starts_with(UPGRADE_TEMP_PREFIX),
            "probe prefix must not collide with upgrade temp prefix"
        );
        let probe = binary_dir.join(format!("{UPGRADE_PROBE_PREFIX}{}", std::process::id()));
        fs::File::create(&probe).with_context(|| {
            format!("binary directory is not writable: {}", binary_dir.display())
        })?;
        let _ = fs::remove_file(&probe);
    }

    // Sweep any prior crashed-upgrade leftovers before we add our own.
    match cleanup_stale_upgrade_temps(&binary_dir) {
        Ok(n) if n > 0 && opts.verbose => {
            eprintln!(
                "cleaned up {n} stale upgrade temp file(s) in {}",
                binary_dir.display()
            );
        }
        _ => {}
    }

    println!(
        "sdme: upgrading from {current} to {target_version} ({arch}) at {}",
        exe_path.display()
    );

    if !opts.assume_yes {
        if !opts.interactive {
            bail!("use -y to confirm upgrade in non-interactive mode");
        }
        if !crate::confirm("proceed? [y/N] ")? {
            bail!("aborted");
        }
    }

    let agent = upgrade_http_agent(cfg, opts.verbose)?;

    // Stream the binary into a temp file next to the running binary and
    // compute SHA-256 on the fly.
    let temp_path = binary_dir.join(format!("{UPGRADE_TEMP_PREFIX}{}", std::process::id()));
    let mut guard = TempGuard::new(temp_path.clone());

    if opts.verbose {
        eprintln!("downloading {download_url}");
    }
    let response = agent
        .get(&download_url)
        .call()
        .with_context(|| format!("failed to download {download_url}"))?;
    let mut reader = response.into_body().into_reader();

    let mut file = fs::File::create(&temp_path)
        .with_context(|| format!("failed to create {}", temp_path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    let mut total: u64 = 0;
    loop {
        crate::check_interrupted()?;
        let n = reader
            .read(&mut buf)
            .with_context(|| format!("failed to read from {download_url}"))?;
        if n == 0 {
            break;
        }
        file.write_all(&buf[..n])
            .with_context(|| format!("failed to write to {}", temp_path.display()))?;
        hasher.update(&buf[..n]);
        total += n as u64;
        if total > MAX_BINARY_SIZE {
            bail!("downloaded binary exceeds safety cap of {MAX_BINARY_SIZE} bytes");
        }
    }
    file.flush()?;
    drop(file);

    let actual = format!("{:x}", hasher.finalize());
    if opts.verbose {
        eprintln!("downloaded {total} bytes, sha256={actual}");
    }

    if opts.verbose {
        eprintln!("fetching {checksums_url}");
    }
    let sums_response = agent
        .get(&checksums_url)
        .call()
        .with_context(|| format!("failed to fetch checksums from {checksums_url}"))?;
    let sums_body = read_body_to_string(sums_response)?;
    let expected = parse_sha256sums(&sums_body, &binary_name)?;

    if actual != expected {
        bail!("SHA256 mismatch for {binary_name}: expected {expected}, got {actual}");
    }

    fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o755))
        .with_context(|| format!("failed to chmod {}", temp_path.display()))?;

    fs::rename(&temp_path, &exe_path).with_context(|| {
        format!(
            "failed to replace {} with {}",
            exe_path.display(),
            temp_path.display()
        )
    })?;
    guard.disarm();

    // Refresh state so the banner disappears immediately.
    let new_state = State {
        checked_at: now_unix(),
        checked_version: target_version.clone(),
        latest_version: Some(target_version.clone()),
        download_url: Some(download_url),
        checksums_url: Some(checksums_url),
    };
    let _ = write_state(&state_path(cfg), &new_state);

    println!("sdme: upgraded to {target_version}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::time::{Duration, SystemTime};

    fn tempdir_for(name: &str) -> PathBuf {
        let dir = env::temp_dir().join(format!(
            "sdme-update-test-{}-{}-{:?}",
            name,
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_render_url_substitutes_placeholders() {
        let template = "https://example/v{version}/sdme-{arch}-linux";
        assert_eq!(
            render_url(template, "1.2.3", "x86_64"),
            "https://example/v1.2.3/sdme-x86_64-linux"
        );
    }

    #[test]
    fn test_semver_newer() {
        assert!(semver_newer("0.7.0", "0.6.11"));
        assert!(semver_newer("1.0.0", "0.99.99"));
        assert!(semver_newer("0.6.12", "0.6.11"));
        assert!(!semver_newer("0.6.11", "0.6.11"));
        assert!(!semver_newer("0.6.10", "0.6.11"));
        // Unparseable inputs: not newer.
        assert!(!semver_newer("garbage", "0.6.11"));
        assert!(!semver_newer("0.7.0", "garbage"));
        // Leading "v" is tolerated.
        assert!(semver_newer("v0.7.0", "0.6.11"));
        // Pre-release suffix: patch stops at digits; "0.7.0-alpha" parses as 0.7.0.
        assert!(!semver_newer("0.7.0-alpha", "0.7.0"));
    }

    #[test]
    fn test_parse_sha256sums_matches_filename() {
        let body = "\
deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef  x86_64/sdme-x86_64-linux
cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe *sdme-aarch64-linux
feedface00feedface00feedface00feedface00feedface00feedface00feed  unrelated.deb
";
        assert_eq!(
            parse_sha256sums(body, "sdme-x86_64-linux").unwrap(),
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        );
        assert_eq!(
            parse_sha256sums(body, "sdme-aarch64-linux").unwrap(),
            "cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe"
        );
        assert!(parse_sha256sums(body, "sdme-missing").is_err());
    }

    #[test]
    fn test_parse_sha256sums_rejects_malformed_hash() {
        let body = "NOT_HEX  sdme-x86_64-linux\n";
        assert!(parse_sha256sums(body, "sdme-x86_64-linux").is_err());
    }

    #[test]
    fn test_state_roundtrip() {
        let dir = tempdir_for("state-roundtrip");
        let path = dir.join(STATE_FILE);
        let state = State {
            checked_at: 1_700_000_000,
            checked_version: "0.6.11".into(),
            latest_version: Some("0.7.0".into()),
            download_url: Some("https://example/bin".into()),
            checksums_url: Some("https://example/sums".into()),
        };
        write_state(&path, &state).unwrap();
        let loaded = read_state(&path).unwrap();
        assert_eq!(loaded, state);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_state_roundtrip_failure_shape() {
        let dir = tempdir_for("state-failure");
        let path = dir.join(STATE_FILE);
        let state = State {
            checked_at: 1_700_000_000,
            checked_version: "0.6.11".into(),
            ..State::default()
        };
        write_state(&path, &state).unwrap();
        let loaded = read_state(&path).unwrap();
        assert_eq!(loaded.checked_at, 1_700_000_000);
        assert_eq!(loaded.latest_version, None);
        let _ = fs::remove_dir_all(&dir);
    }

    fn touch_mtime(path: &Path, secs_ago: u64) {
        let now = SystemTime::now();
        let target = now - Duration::from_secs(secs_ago);
        let unix_secs = target
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        let spec = libc::timespec {
            tv_sec: unix_secs,
            tv_nsec: 0,
        };
        let times = [spec, spec];
        unsafe {
            libc::utimensat(libc::AT_FDCWD, c.as_ptr(), times.as_ptr(), 0);
        }
    }

    #[test]
    fn test_cleanup_matrix() {
        let dir = tempdir_for("cleanup");
        let my_pid = std::process::id();

        // (a) matching filename, definitely-dead PID (1 is init; kill(1,0) succeeds
        // only as root so we use a PID that is extremely unlikely to exist)
        let dead_pid = pick_dead_pid();
        let stale = dir.join(format!("{UPGRADE_TEMP_PREFIX}{dead_pid}"));
        fs::write(&stale, b"stale").unwrap();
        touch_mtime(&stale, STALE_TEMP_AGE_SECS + 60);

        // (b) matching, live PID (our own) - must be kept even if old
        let live = dir.join(format!("{UPGRADE_TEMP_PREFIX}{my_pid}"));
        fs::write(&live, b"live").unwrap();
        touch_mtime(&live, STALE_TEMP_AGE_SECS + 60);

        // (c) matching, dead PID but recent mtime - kept
        let recent = dir.join(format!("{UPGRADE_TEMP_PREFIX}{}", dead_pid + 1));
        fs::write(&recent, b"recent").unwrap();

        // (d) non-matching filename - untouched
        let unrelated = dir.join("unrelated.txt");
        fs::write(&unrelated, b"hi").unwrap();

        // (e) a directory matching the pattern - skipped
        let subdir = dir.join(format!("{UPGRADE_TEMP_PREFIX}{}", dead_pid + 2));
        fs::create_dir(&subdir).unwrap();
        touch_mtime(&subdir, STALE_TEMP_AGE_SECS + 60);

        let removed = cleanup_stale_upgrade_temps(&dir).unwrap();
        assert_eq!(removed, 1);

        assert!(!stale.exists(), "stale temp should be removed");
        assert!(live.exists(), "live-PID temp should be kept");
        assert!(recent.exists(), "recent temp should be kept");
        assert!(unrelated.exists(), "unrelated file should be kept");
        assert!(subdir.is_dir(), "directory match should not be recursed");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_cleanup_symlink_safety() {
        let dir = tempdir_for("cleanup-symlink");
        // Create a target we do NOT want deleted.
        let sentinel = dir.join("sentinel");
        fs::write(&sentinel, b"do-not-touch").unwrap();

        // Symlink named like a stale upgrade temp, pointing to sentinel.
        let link = dir.join(format!("{UPGRADE_TEMP_PREFIX}{}", pick_dead_pid()));
        symlink(&sentinel, &link).unwrap();

        cleanup_stale_upgrade_temps(&dir).unwrap();

        // Sentinel must still exist (symlink was never a regular file).
        assert!(sentinel.exists(), "sentinel must not be deleted");
        // Symlink itself is left in place because symlink_metadata().is_file() is false.
        assert!(link.symlink_metadata().is_ok(), "symlink kept");

        let _ = fs::remove_dir_all(&dir);
    }

    fn pick_dead_pid() -> u32 {
        // Find a PID that is not alive. Start high and walk down.
        for candidate in (100_000..110_000).rev() {
            if unsafe { libc::kill(candidate as libc::pid_t, 0) } != 0 {
                return candidate;
            }
        }
        999_999
    }
}
