#![warn(missing_docs)]

//! Lightweight systemd-nspawn container manager with overlayfs.
//!
//! sdme manages containers backed by explicit root filesystems, keeping
//! the base rootfs untouched via overlayfs copy-on-write. Each container
//! gets `upper/work/merged` directories under the data directory and a
//! KEY=VALUE state file that tracks its metadata.
//!
//! Requires Linux with systemd (>= 255) and root privileges.
//!
//! # Modules
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`containers`] | Create, remove, join, exec, stop, list |
//! | [`diff`] | Container filesystem diff (overlayfs upper vs lower) |
//! | [`systemd`] | D-Bus helpers and template unit management |
//! | [`import`] | Rootfs import (dir, tar, URL, OCI, QCOW2) |
//! | [`oci`] | OCI registry, layout, app setup, blob cache |
//! | [`kube`] | Kubernetes Pod YAML support |
//! | [`export`] | Rootfs export (dir, tarball, raw image) |
//! | [`rootfs`] | Rootfs listing, removal, os-release parsing |
//! | [`build`] | Build config parsing and rootfs build execution |
//! | [`config`] | Configuration file loading and saving |
//! | [`cp`] | File copy between host, containers, and rootfs |
//! | [`lock`] | Advisory file locking for resource protection |
//! | [`mounts`] | Bind mount and environment variable config |
//! | [`network`] | Network configuration and state serialization |
//! | [`security`] | Capability, seccomp, AppArmor config |
//! | [`system_check`] | Version and dependency checks |
//! | [`userns`] | User namespace UID shift allocation and pre-chown |
//! | [`pod`] | Shared network namespace management |
//! | [`prune`] | Unused resource analysis and cleanup |
//! | [`txn`] | Enumerated transaction staging and gc |
//! | [`update`] | Update-check state and self-upgrade |

pub mod build;
pub mod config;
pub mod containers;
pub(crate) mod copy;
pub mod cp;
pub(crate) mod devfd_shim;
pub mod diff;
pub(crate) mod elf;
pub mod export;
pub mod import;
pub(crate) mod isolate;
pub mod kube;
pub mod lock;
pub mod mounts;
pub(crate) mod names;
pub mod network;
pub mod oci;
pub mod pod;
pub mod prune;
pub mod rootfs;
pub mod security;
pub(crate) mod submounts;
pub mod system_check;
pub mod systemd;
pub mod txn;
pub mod update;
pub mod userns;

pub use mounts::{BindConfig, EnvConfig};
pub use network::NetworkConfig;
pub use security::SecurityConfig;

use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

use anyhow::{bail, Context, Result};

/// Global flag set by the SIGINT/SIGTERM handler; checked by [`check_interrupted`].
pub static INTERRUPTED: AtomicBool = AtomicBool::new(false);

/// The signal number that triggered the interruption (for exit code selection).
static INTERRUPT_SIGNAL: AtomicI32 = AtomicI32::new(0);

/// Read a line from stdin, returning `ErrorKind::Interrupted` if a signal
/// interrupts the read.
///
/// Unlike `BufRead::read_line()`, this does NOT retry on `EINTR`; it
/// surfaces the interruption to the caller so Ctrl+C works during
/// interactive prompts.
pub fn read_line_interruptible(buf: &mut String) -> std::io::Result<usize> {
    let mut bytes = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = unsafe { libc::read(libc::STDIN_FILENO, byte.as_mut_ptr().cast(), 1) };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if n == 0 {
            break;
        }
        bytes.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }
    let s = String::from_utf8(bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let len = s.len();
    buf.push_str(&s);
    Ok(len)
}

/// Return `Err` if the global SIGINT/SIGTERM flag is set.
pub fn check_interrupted() -> Result<()> {
    if INTERRUPTED.load(Ordering::Relaxed) {
        bail!("interrupted");
    }
    Ok(())
}

/// Return the exit code appropriate for signal-terminated processes.
///
/// Convention: 128 + signal_number (e.g. 130 for SIGINT, 143 for SIGTERM).
pub fn interrupt_exit_code() -> i32 {
    let sig = INTERRUPT_SIGNAL.load(Ordering::Relaxed);
    if sig > 0 {
        128 + sig
    } else {
        130 // default: 128 + SIGINT
    }
}

/// Reset the interrupt flag and re-install the signal handler.
///
/// Called before cleanup operations (e.g. stopping a container after a
/// failed boot in `sdme new`). Without this, a prior Ctrl+C leaves
/// `INTERRUPTED == true` and the cleanup code (which also calls
/// `check_interrupted()`) would bail immediately, skipping the undo.
///
/// Re-installing the handler means a *second* Ctrl+C during cleanup
/// will still force-kill the process (the handler restores SIG_DFL on
/// first invocation).
pub fn reset_interrupt() {
    INTERRUPTED.store(false, Ordering::Relaxed);
    INTERRUPT_SIGNAL.store(0, Ordering::Relaxed);
    install_interrupt_handler();
}

/// Save the current interrupt state and reset it.
///
/// Returns the previous `(INTERRUPTED, INTERRUPT_SIGNAL)` values so the
/// caller can restore them after a cleanup operation (e.g. stopping a
/// container after boot failure). Use [`restore_interrupt`] to put them
/// back.
pub fn save_and_reset_interrupt() -> (bool, i32) {
    let was = INTERRUPTED.load(Ordering::Relaxed);
    let sig = INTERRUPT_SIGNAL.load(Ordering::Relaxed);
    reset_interrupt();
    (was, sig)
}

/// Restore a previously saved interrupt state.
///
/// If the saved state was interrupted, re-sets the global flags so
/// callers higher up the stack (e.g. `for_each_container`) can detect
/// the interruption and break out of loops.
pub fn restore_interrupt(was_interrupted: bool, signal: i32) {
    if was_interrupted {
        INTERRUPTED.store(true, Ordering::Relaxed);
        INTERRUPT_SIGNAL.store(signal, Ordering::Relaxed);
    }
}

/// RAII guard that saves and resets interrupt state on creation, and
/// restores it on drop.
///
/// Use this instead of manual [`save_and_reset_interrupt`] /
/// [`restore_interrupt`] pairs to ensure the restore always happens,
/// even on early returns.
pub struct InterruptGuard {
    was: bool,
    sig: i32,
}

impl InterruptGuard {
    /// Save the current interrupt state and reset it.
    pub fn save_and_reset() -> Self {
        let (was, sig) = save_and_reset_interrupt();
        Self { was, sig }
    }
}

impl Drop for InterruptGuard {
    fn drop(&mut self) {
        restore_interrupt(self.was, self.sig);
    }
}

/// Install the SIGINT and SIGTERM handler that sets the global [`INTERRUPTED`] flag.
pub fn install_interrupt_handler() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = signal_handler as *const () as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        // Deliberately NOT setting SA_RESTART so that blocking syscalls
        // (e.g. read() during interactive prompts) return EINTR on Ctrl+C
        // instead of silently restarting.
        //
        // The handler sets INTERRUPTED and restores the default disposition
        // for the received signal, so a second delivery force-kills the
        // process. This is needed because Rust's stdlib retries
        // poll()/connect() on EINTR, preventing cooperative
        // check_interrupted() from running during blocked connection
        // attempts.
        sa.sa_flags = 0;
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
    }
}

extern "C" fn signal_handler(sig: libc::c_int) {
    INTERRUPTED.store(true, Ordering::Relaxed);
    INTERRUPT_SIGNAL.store(sig, Ordering::Relaxed);
    // Restore default handler for this signal: next delivery terminates.
    unsafe {
        libc::signal(sig, libc::SIG_DFL);
    }
}

/// Display a prompt on stderr and read a line from stdin.
///
/// Returns `Err` if the read is interrupted by a signal.
fn prompt(msg: &str) -> Result<String> {
    eprint!("{msg}");
    let _ = std::io::stderr().flush();
    let mut answer = String::new();
    if let Err(e) = read_line_interruptible(&mut answer) {
        if e.kind() == std::io::ErrorKind::Interrupted {
            eprintln!();
        }
        bail!("interrupted");
    }
    Ok(answer)
}

/// Prompt the user for yes/no confirmation, returning `Ok(true)` for "y".
///
/// Returns `Err` if the read is interrupted by a signal.
pub fn confirm(msg: &str) -> Result<bool> {
    Ok(prompt(msg)?.trim().eq_ignore_ascii_case("y"))
}

/// Prompt the user for yes/no confirmation, returning `Ok(true)` for "y" or
/// empty input (Enter). Only "n"/"no" returns `false`.
///
/// Returns `Err` if the read is interrupted by a signal.
pub fn confirm_default_yes(msg: &str) -> Result<bool> {
    let answer = prompt(msg)?;
    let trimmed = answer.trim();
    Ok(!trimmed.eq_ignore_ascii_case("n") && !trimmed.eq_ignore_ascii_case("no"))
}

/// Information about the real user behind `sudo`.
pub struct SudoUser {
    /// Login name from `SUDO_USER`.
    pub name: String,
    /// Numeric user ID.
    pub uid: u32,
    /// Numeric group ID.
    pub gid: u32,
    /// Home directory path.
    pub home: PathBuf,
}

/// Returns info about the real user behind `sudo`, if applicable.
///
/// Looks up `SUDO_USER` in the environment. Returns `None` if the variable
/// is unset, empty, or set to "root" (running `sudo` as root is a no-op).
pub fn sudo_user() -> Option<SudoUser> {
    let name = std::env::var("SUDO_USER").ok()?;
    if name.is_empty() || name == "root" {
        return None;
    }
    let c_name = CString::new(name.as_bytes()).ok()?;
    let pw = unsafe { libc::getpwnam(c_name.as_ptr()) };
    if pw.is_null() {
        return None;
    }
    let home = unsafe { std::ffi::CStr::from_ptr((*pw).pw_dir) }
        .to_str()
        .ok()?;
    Some(SudoUser {
        name,
        uid: unsafe { (*pw).pw_uid },
        gid: unsafe { (*pw).pw_gid },
        home: PathBuf::from(home),
    })
}

/// Container metadata stored as KEY=VALUE pairs in a state file.
///
/// Backed by a [`BTreeMap`] for stable, sorted ordering of keys.
#[derive(Default)]
pub struct State {
    entries: BTreeMap<String, String>,
}

impl State {
    /// Create an empty state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or update a key-value pair.
    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let key = key.into();
        let value = value.into();
        debug_assert!(
            !key.contains('\n') && !value.contains('\n'),
            "State key/value must not contain newlines: {key}={value}"
        );
        self.entries.insert(key, value);
    }

    /// Look up a value by key.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries.get(key).map(|s| s.as_str())
    }

    /// Shorthand for `self.get("ROOTFS").unwrap_or("")`.
    pub fn rootfs(&self) -> &str {
        self.get("ROOTFS").unwrap_or("")
    }

    /// Returns true if the given key is set to `"yes"`.
    pub fn is_yes(&self, key: &str) -> bool {
        self.get(key) == Some("yes")
    }

    /// Remove a key from the state.
    pub fn remove(&mut self, key: &str) {
        self.entries.remove(key);
    }

    /// Get a delimited list value, returning empty Vec for missing/empty keys.
    pub fn get_list(&self, key: &str, delimiter: char) -> Vec<String> {
        self.get(key)
            .filter(|s| !s.is_empty())
            .map(|s| s.split(delimiter).map(String::from).collect())
            .unwrap_or_default()
    }

    /// Set a delimited list, removing the key when empty.
    pub fn set_list(&mut self, key: &str, values: &[String], delimiter: char) {
        if values.is_empty() {
            self.remove(key);
        } else {
            let joined: String =
                values
                    .iter()
                    .enumerate()
                    .fold(String::new(), |mut acc, (i, v)| {
                        if i > 0 {
                            acc.push(delimiter);
                        }
                        acc.push_str(v);
                        acc
                    });
            self.set(key, joined);
        }
    }

    /// Get a non-empty string value (returns None for missing or empty).
    pub fn get_nonempty(&self, key: &str) -> Option<&str> {
        self.get(key).filter(|s| !s.is_empty())
    }

    /// Parse KEY=VALUE lines into a new state.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sdme::State;
    /// let state = State::parse("NAME=test\nROOTFS=ubuntu\n").unwrap();
    /// assert_eq!(state.get("NAME"), Some("test"));
    /// assert_eq!(state.get("ROOTFS"), Some("ubuntu"));
    /// ```
    pub fn parse(content: &str) -> Result<Self> {
        let mut entries = BTreeMap::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let (key, value) = line
                .split_once('=')
                .with_context(|| format!("invalid state line: {line}"))?;
            entries.insert(key.to_string(), value.to_string());
        }
        Ok(Self { entries })
    }

    /// Serialize all entries to KEY=VALUE text.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sdme::State;
    /// let mut state = State::new();
    /// state.set("NAME", "test");
    /// state.set("ROOTFS", "ubuntu");
    /// let text = state.serialize();
    /// let restored = State::parse(&text).unwrap();
    /// assert_eq!(restored.get("NAME"), Some("test"));
    /// ```
    pub fn serialize(&self) -> String {
        let mut out = String::new();
        for (key, value) in &self.entries {
            out.push_str(key);
            out.push('=');
            out.push_str(value);
            out.push('\n');
        }
        out
    }

    /// Write the state to a file atomically with 0o600 permissions.
    pub fn write_to(&self, path: &Path) -> Result<()> {
        let content = self.serialize();
        atomic_write_mode(path, content.as_bytes(), 0o600)
            .with_context(|| format!("failed to write {}", path.display()))
    }

    /// Read and parse a state file from disk.
    pub fn read_from(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        Self::parse(&content)
    }
}

/// Resource limits that map to systemd cgroup directives.
///
/// Each field is `None` when the limit is not set. Values are stored in the
/// container's state file and converted to a systemd drop-in at start time.
#[derive(Debug, Default, Clone, PartialEq, serde::Serialize)]
pub struct ResourceLimits {
    /// `MemoryMax=`, e.g. "512M", "2G"
    pub memory: Option<String>,
    /// `CPUQuota=`, stored as a number of CPUs (e.g. "2" = 200%)
    pub cpus: Option<String>,
    /// `CPUWeight=`, integer 1-10000
    pub cpu_weight: Option<String>,
}

impl ResourceLimits {
    /// Returns true if no limits are set.
    pub fn is_empty(&self) -> bool {
        self.memory.is_none() && self.cpus.is_none() && self.cpu_weight.is_none()
    }

    /// Read limits from a state file's key-value pairs.
    pub fn from_state(state: &State) -> Self {
        Self {
            memory: state
                .get("MEMORY")
                .filter(|s| !s.is_empty())
                .map(String::from),
            cpus: state
                .get("CPUS")
                .filter(|s| !s.is_empty())
                .map(String::from),
            cpu_weight: state
                .get("CPU_WEIGHT")
                .filter(|s| !s.is_empty())
                .map(String::from),
        }
    }

    /// Write limits into a state's key-value pairs.
    ///
    /// Set fields are written; unset fields are removed from the state.
    pub fn write_to_state(&self, state: &mut State) {
        for (key, val) in [
            ("MEMORY", &self.memory),
            ("CPUS", &self.cpus),
            ("CPU_WEIGHT", &self.cpu_weight),
        ] {
            match val {
                Some(v) => state.set(key, v.as_str()),
                None => state.remove(key),
            }
        }
    }

    /// Generate the content of a systemd drop-in `[Service]` section.
    ///
    /// Returns `None` if no limits are set.
    pub fn dropin_content(&self) -> Option<String> {
        let mut lines = vec!["[Service]".to_string()];
        let mut has_any = false;

        if let Some(mem) = &self.memory {
            lines.push(format!("MemoryMax={mem}"));
            lines.push(format!("MemorySwapMax={mem}"));
            has_any = true;
        }
        if let Some(cpus) = &self.cpus {
            let pct = cpus_to_quota(cpus);
            lines.push(format!("CPUQuota={pct}%"));
            has_any = true;
        }
        if let Some(w) = &self.cpu_weight {
            lines.push(format!("CPUWeight={w}"));
            has_any = true;
        }

        if has_any {
            lines.push(String::new()); // trailing newline
            Some(lines.join("\n"))
        } else {
            None
        }
    }

    /// Validate all set fields. Returns an error describing the first invalid value.
    pub fn validate(&self) -> Result<()> {
        if let Some(mem) = &self.memory {
            validate_memory(mem)?;
        }
        if let Some(cpus) = &self.cpus {
            validate_cpus(cpus)?;
        }
        if let Some(w) = &self.cpu_weight {
            validate_cpu_weight(w)?;
        }
        Ok(())
    }
}

/// Validate a memory value (systemd size: `<number>[K|M|G|T]`).
fn validate_memory(s: &str) -> Result<()> {
    if s.is_empty() {
        bail!("--memory value cannot be empty");
    }
    let (num, suffix) = if s.ends_with(|c: char| c.is_ascii_alphabetic()) {
        let (n, s) = s.split_at(s.len() - 1);
        (n, s)
    } else {
        (s, "")
    };
    let _: u64 = num
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid --memory value '{s}': expected <number>[K|M|G|T]"))?;
    match suffix {
        "" | "K" | "M" | "G" | "T" => Ok(()),
        _ => bail!("invalid --memory suffix '{suffix}': expected K, M, G, or T"),
    }
}

/// Validate a cpus value (positive number, integer or decimal).
fn validate_cpus(s: &str) -> Result<()> {
    let v: f64 = s
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid --cpus value '{s}': expected a positive number"))?;
    if v <= 0.0 {
        bail!("--cpus must be positive, got '{s}'");
    }
    Ok(())
}

/// Convert a cpus string to a percentage for CPUQuota.
// Safe: validate_cpus() has already verified this parses to a positive f64
fn cpus_to_quota(s: &str) -> u64 {
    let v: f64 = s.parse().unwrap_or(1.0);
    (v * 100.0).round() as u64
}

/// Validate a cpu-weight value (integer 1-10000).
fn validate_cpu_weight(s: &str) -> Result<()> {
    let v: u64 = s.parse().map_err(|_| {
        anyhow::anyhow!("invalid --cpu-weight value '{s}': expected integer 1-10000")
    })?;
    if !(1..=10000).contains(&v) {
        bail!("--cpu-weight must be 1-10000, got {v}");
    }
    Ok(())
}

/// Write data to a file atomically via a temporary file and rename.
///
/// Creates a sibling temp file, writes all data, flushes, then renames
/// over the target path. This prevents partial reads on crash or power loss.
pub fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or(Path::new("."));
    let tmp_path = parent.join(format!(
        ".{}.tmp",
        path.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    ));
    let mut file = fs::File::create(&tmp_path)
        .with_context(|| format!("failed to create temp file {}", tmp_path.display()))?;
    file.write_all(data)
        .with_context(|| format!("failed to write temp file {}", tmp_path.display()))?;
    file.flush()?;
    fs::rename(&tmp_path, path).with_context(|| {
        let _ = fs::remove_file(&tmp_path);
        format!(
            "failed to rename {} to {}",
            tmp_path.display(),
            path.display()
        )
    })?;
    Ok(())
}

/// Write data to a file atomically with explicit permissions.
///
/// Like [`atomic_write`], but sets the file permissions after rename.
pub fn atomic_write_mode(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    atomic_write(path, data)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("failed to set permissions on {}", path.display()))?;
    Ok(())
}

/// Parse a human-readable size string (e.g. "10G", "512M") into bytes.
///
/// Accepts an integer followed by an optional suffix:
/// - No suffix or `B`: bytes
/// - `K`: kibibytes (1024)
/// - `M`: mebibytes (1024^2)
/// - `G`: gibibytes (1024^3)
/// - `T`: tebibytes (1024^4)
///
/// Returns 0 for the input `"0"`.
///
/// # Examples
///
/// ```
/// # use sdme::parse_size;
/// assert_eq!(parse_size("512M").unwrap(), 512 * 1024 * 1024);
/// assert_eq!(parse_size("1G").unwrap(), 1024 * 1024 * 1024);
/// assert_eq!(parse_size("0").unwrap(), 0);
/// assert!(parse_size("10X").is_err());
/// ```
pub fn parse_size(s: &str) -> Result<u64> {
    if s.is_empty() {
        bail!("size value cannot be empty");
    }
    let (num_str, suffix) = if s.ends_with(|c: char| c.is_ascii_alphabetic()) {
        let (n, s) = s.split_at(s.len() - 1);
        (n, s)
    } else {
        (s, "")
    };
    let num: u64 = num_str
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid size value '{s}': expected <number>[B|K|M|G|T]"))?;
    let multiplier: u64 = match suffix {
        "" | "B" => 1,
        "K" => 1024,
        "M" => 1024 * 1024,
        "G" => 1024 * 1024 * 1024,
        "T" => 1024 * 1024 * 1024 * 1024,
        _ => bail!("invalid size suffix '{suffix}': expected B, K, M, G, or T"),
    };
    num.checked_mul(multiplier)
        .with_context(|| format!("size value overflows: {s}"))
}

/// Validate a container name.
///
/// Names must start with a lowercase letter, contain only lowercase
/// letters, digits, and hyphens, and be at most 64 characters.
///
/// # Examples
///
/// ```
/// # use sdme::validate_name;
/// assert!(validate_name("my-container").is_ok());
/// assert!(validate_name("test123").is_ok());
/// assert!(validate_name("").is_err());
/// assert!(validate_name("UPPER").is_err());
/// assert!(validate_name("1starts-with-digit").is_err());
/// ```
pub fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("container name cannot be empty");
    }
    let first = name.as_bytes()[0];
    if !first.is_ascii_lowercase() {
        bail!("container name must start with a lowercase letter");
    }
    for ch in name.chars() {
        if !ch.is_ascii_lowercase() && !ch.is_ascii_digit() && ch != '-' {
            bail!("container name may only contain lowercase letters, digits, and hyphens");
        }
    }
    Ok(())
}

/// Format a unix timestamp (seconds since epoch) as `YYYY-MM-DD HH:MM` in
/// local time. Returns the raw number as a string if formatting fails.
pub fn format_timestamp(secs_str: &str) -> String {
    let secs: libc::time_t = match secs_str.parse() {
        Ok(v) => v,
        Err(_) => return secs_str.to_string(),
    };
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::localtime_r(&secs, &mut tm) };
    if ret.is_null() {
        return secs_str.to_string();
    }
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_sudo_user_not_set() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var("SUDO_USER");
        assert!(sudo_user().is_none());
    }

    #[test]
    fn test_sudo_user_valid() {
        let _guard = ENV_LOCK.lock().unwrap();
        let user = std::env::var("USER").unwrap();
        std::env::set_var("SUDO_USER", &user);
        let su = sudo_user();
        std::env::remove_var("SUDO_USER");
        let su = su.expect("should resolve for current user");
        assert_eq!(su.name, user);
        assert!(!su.home.as_os_str().is_empty());
    }

    #[test]
    fn test_sudo_user_root() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("SUDO_USER", "root");
        assert!(sudo_user().is_none());
        std::env::remove_var("SUDO_USER");
    }

    // --- parse_size tests ---

    #[test]
    fn test_parse_size_bytes() {
        assert_eq!(parse_size("0").unwrap(), 0);
        assert_eq!(parse_size("1024").unwrap(), 1024);
        assert_eq!(parse_size("100B").unwrap(), 100);
    }

    #[test]
    fn test_parse_size_kilo() {
        assert_eq!(parse_size("1K").unwrap(), 1024);
        assert_eq!(parse_size("10K").unwrap(), 10240);
    }

    #[test]
    fn test_parse_size_mega() {
        assert_eq!(parse_size("1M").unwrap(), 1024 * 1024);
        assert_eq!(parse_size("512M").unwrap(), 512 * 1024 * 1024);
    }

    #[test]
    fn test_parse_size_giga() {
        assert_eq!(parse_size("1G").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(parse_size("10G").unwrap(), 10 * 1024 * 1024 * 1024);
    }

    #[test]
    fn test_parse_size_tera() {
        assert_eq!(parse_size("1T").unwrap(), 1024u64 * 1024 * 1024 * 1024);
    }

    #[test]
    fn test_parse_size_invalid() {
        assert!(parse_size("").is_err());
        assert!(parse_size("abc").is_err());
        assert!(parse_size("10X").is_err());
        assert!(parse_size("M").is_err());
    }

    // --- ResourceLimits tests ---

    #[test]
    fn test_limits_default_is_empty() {
        let limits = ResourceLimits::default();
        assert!(limits.is_empty());
        assert_eq!(limits.dropin_content(), None);
    }

    #[test]
    fn test_limits_validate_memory_ok() {
        for v in &["512M", "2G", "1T", "4096K", "1073741824"] {
            let limits = ResourceLimits {
                memory: Some(v.to_string()),
                ..Default::default()
            };
            assert!(limits.validate().is_ok(), "should accept memory={v}");
        }
    }

    #[test]
    fn test_limits_validate_memory_bad() {
        for v in &["abc", "2X", "M", ""] {
            let limits = ResourceLimits {
                memory: Some(v.to_string()),
                ..Default::default()
            };
            assert!(limits.validate().is_err(), "should reject memory={v}");
        }
    }

    #[test]
    fn test_limits_validate_cpus_ok() {
        for v in &["1", "2", "0.5", "4.0"] {
            let limits = ResourceLimits {
                cpus: Some(v.to_string()),
                ..Default::default()
            };
            assert!(limits.validate().is_ok(), "should accept cpus={v}");
        }
    }

    #[test]
    fn test_limits_validate_cpus_bad() {
        for v in &["0", "-1", "abc"] {
            let limits = ResourceLimits {
                cpus: Some(v.to_string()),
                ..Default::default()
            };
            assert!(limits.validate().is_err(), "should reject cpus={v}");
        }
    }

    #[test]
    fn test_limits_validate_cpu_weight_ok() {
        for v in &["1", "100", "10000"] {
            let limits = ResourceLimits {
                cpu_weight: Some(v.to_string()),
                ..Default::default()
            };
            assert!(limits.validate().is_ok(), "should accept cpu_weight={v}");
        }
    }

    #[test]
    fn test_limits_validate_cpu_weight_bad() {
        for v in &["0", "10001", "-1", "abc"] {
            let limits = ResourceLimits {
                cpu_weight: Some(v.to_string()),
                ..Default::default()
            };
            assert!(limits.validate().is_err(), "should reject cpu_weight={v}");
        }
    }

    #[test]
    fn test_limits_dropin_content_memory_only() {
        let limits = ResourceLimits {
            memory: Some("2G".to_string()),
            ..Default::default()
        };
        let content = limits.dropin_content().unwrap();
        assert_eq!(content, "[Service]\nMemoryMax=2G\nMemorySwapMax=2G\n");
    }

    #[test]
    fn test_limits_dropin_content_cpus() {
        let limits = ResourceLimits {
            cpus: Some("2".to_string()),
            ..Default::default()
        };
        let content = limits.dropin_content().unwrap();
        assert!(content.contains("CPUQuota=200%"));
    }

    #[test]
    fn test_limits_dropin_content_fractional_cpus() {
        let limits = ResourceLimits {
            cpus: Some("0.5".to_string()),
            ..Default::default()
        };
        let content = limits.dropin_content().unwrap();
        assert!(content.contains("CPUQuota=50%"));
    }

    #[test]
    fn test_limits_dropin_content_all() {
        let limits = ResourceLimits {
            memory: Some("1G".to_string()),
            cpus: Some("4".to_string()),
            cpu_weight: Some("50".to_string()),
        };
        let content = limits.dropin_content().unwrap();
        assert!(content.contains("MemoryMax=1G"));
        assert!(content.contains("CPUQuota=400%"));
        assert!(content.contains("CPUWeight=50"));
    }

    #[test]
    fn test_dropin_memory_includes_swap_max() {
        let limits = ResourceLimits {
            memory: Some("2G".to_string()),
            cpus: None,
            cpu_weight: None,
        };
        let content = limits.dropin_content().unwrap();
        assert!(content.contains("MemoryMax=2G"));
        assert!(content.contains("MemorySwapMax=2G"));
    }

    #[test]
    fn test_limits_state_roundtrip() {
        let limits = ResourceLimits {
            memory: Some("2G".to_string()),
            cpus: Some("1.5".to_string()),
            cpu_weight: None,
        };
        let mut state = State::new();
        state.set("NAME", "test");
        limits.write_to_state(&mut state);

        let serialized = state.serialize();
        let parsed = State::parse(&serialized).unwrap();
        let restored = ResourceLimits::from_state(&parsed);

        assert_eq!(restored.memory, Some("2G".to_string()));
        assert_eq!(restored.cpus, Some("1.5".to_string()));
        assert_eq!(restored.cpu_weight, None);
    }

    #[test]
    fn test_limits_state_remove() {
        let mut state = State::new();
        state.set("MEMORY", "1G");
        state.set("CPUS", "2");

        let limits = ResourceLimits {
            memory: Some("4G".to_string()),
            ..Default::default()
        };
        limits.write_to_state(&mut state);

        assert_eq!(state.get("MEMORY"), Some("4G"));
        assert_eq!(state.get("CPUS"), None); // removed
    }

    // --- State helper tests ---

    #[test]
    fn test_get_list_present() {
        let state = State::parse("CAPS=A,B,C\n").unwrap();
        assert_eq!(state.get_list("CAPS", ','), vec!["A", "B", "C"]);
    }

    #[test]
    fn test_get_list_missing() {
        let state = State::new();
        let result: Vec<String> = state.get_list("CAPS", ',');
        assert!(result.is_empty());
    }

    #[test]
    fn test_get_list_empty_value() {
        let state = State::parse("CAPS=\n").unwrap();
        let result: Vec<String> = state.get_list("CAPS", ',');
        assert!(result.is_empty());
    }

    #[test]
    fn test_get_list_pipe_delimiter() {
        let state = State::parse("BINDS=a|b|c\n").unwrap();
        assert_eq!(state.get_list("BINDS", '|'), vec!["a", "b", "c"]);
    }

    #[test]
    fn test_set_list_nonempty() {
        let mut state = State::new();
        state.set_list("CAPS", &["A".into(), "B".into()], ',');
        assert_eq!(state.get("CAPS"), Some("A,B"));
    }

    #[test]
    fn test_set_list_empty_removes() {
        let mut state = State::new();
        state.set("CAPS", "old");
        state.set_list("CAPS", &[], ',');
        assert_eq!(state.get("CAPS"), None);
    }

    #[test]
    fn test_set_list_roundtrip() {
        let mut state = State::new();
        let values = vec!["x".to_string(), "y".to_string(), "z".to_string()];
        state.set_list("ITEMS", &values, '|');
        assert_eq!(state.get_list("ITEMS", '|'), values);
    }

    #[test]
    fn test_get_nonempty_present() {
        let state = State::parse("KEY=value\n").unwrap();
        assert_eq!(state.get_nonempty("KEY"), Some("value"));
    }

    #[test]
    fn test_get_nonempty_missing() {
        let state = State::new();
        assert_eq!(state.get_nonempty("KEY"), None);
    }

    #[test]
    fn test_get_nonempty_empty_value() {
        let state = State::parse("KEY=\n").unwrap();
        assert_eq!(state.get_nonempty("KEY"), None);
    }
}

#[cfg(test)]
pub(crate) mod testutil {
    use std::fs;
    use std::path::{Path, PathBuf};

    /// Temporary directory for tests. Creates a unique directory on construction
    /// and removes it on drop. The `prefix` identifies the test module to avoid
    /// collisions between parallel tests.
    pub(crate) struct TempDataDir {
        dir: PathBuf,
    }

    impl TempDataDir {
        pub(crate) fn new(prefix: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "sdme-test-{prefix}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            Self { dir }
        }

        pub(crate) fn path(&self) -> &Path {
            &self.dir
        }
    }

    impl Drop for TempDataDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }
}

/// Download progress display for interactive terminals.
///
/// When Content-Length is known, prints percentage ticks on a single line:
/// `downloading 1.5M 1....10....20....30....40....50....60....70....80....90....100%`
///
/// When Content-Length is unknown, prints the downloaded size every 5 seconds:
/// `downloading 256K`
///
/// Output goes to stderr.
pub struct DownloadProgress {
    total_size: Option<u64>,
    downloaded: u64,
    last_tick: u64,
    last_print: std::time::Instant,
    enabled: bool,
    started: bool,
}

impl DownloadProgress {
    /// Create a new progress display.
    ///
    /// `enabled` controls whether anything is printed (set to `interactive`).
    /// `total_size` is the Content-Length if known.
    pub fn new(enabled: bool, total_size: Option<u64>) -> Self {
        Self {
            total_size,
            downloaded: 0,
            last_tick: 0,
            last_print: std::time::Instant::now(),
            enabled,
            started: false,
        }
    }

    /// Update progress after reading `n` bytes.
    pub fn update(&mut self, n: u64) {
        if !self.enabled {
            return;
        }
        self.downloaded += n;
        if let Some(total) = self.total_size {
            if total == 0 {
                return;
            }
            if !self.started {
                self.started = true;
                let size = crate::oci::cache::format_size(total);
                eprint!("downloading {size} 1");
            }
            let pct = ((self.downloaded as f64 / total as f64 * 100.0) as u64).min(100);
            while self.last_tick + 2 <= pct {
                self.last_tick += 2;
                if self.last_tick == 100 {
                    eprint!("100%");
                } else if self.last_tick.is_multiple_of(10) {
                    eprint!("{}", self.last_tick);
                } else {
                    eprint!(".");
                }
            }
        } else {
            let now = std::time::Instant::now();
            if now.duration_since(self.last_print).as_secs() >= 5 {
                self.last_print = now;
                let size = crate::oci::cache::format_size(self.downloaded);
                eprintln!("downloading {size}");
            }
        }
    }

    /// Finish the progress display with a newline.
    pub fn finish(&self) {
        if self.enabled && self.total_size.is_some() && self.downloaded > 0 {
            eprintln!();
        }
    }
}
