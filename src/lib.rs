pub mod build;
pub mod config;
pub mod connectors;
pub mod containers;
pub mod copy;
pub mod devfd_shim;
pub mod drop_privs;
pub mod import;
pub mod mounts;
pub mod names;
pub mod network;
pub mod proxy;
pub mod rootfs;
pub mod system_check;
pub mod systemd;

pub use connectors::ConnectorConfig;
pub use mounts::{BindConfig, EnvConfig};
pub use network::NetworkConfig;

use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{bail, Context, Result};

pub static INTERRUPTED: AtomicBool = AtomicBool::new(false);

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

pub fn check_interrupted() -> Result<()> {
    if INTERRUPTED.load(Ordering::Relaxed) {
        bail!("interrupted");
    }
    Ok(())
}

/// Reset the interrupt flag and re-install the signal handler.
///
/// Called before cleanup operations (e.g. removing a container after a
/// failed boot in `sdme new`). Without this, a prior Ctrl+C leaves
/// `INTERRUPTED == true` and the cleanup code (which also calls
/// `check_interrupted()`) would bail immediately, skipping the undo.
///
/// Re-installing the handler means a *second* Ctrl+C during cleanup
/// will still force-kill the process (the handler restores SIG_DFL on
/// first invocation).
pub fn reset_interrupt() {
    INTERRUPTED.store(false, Ordering::Relaxed);
    install_interrupt_handler();
}

pub fn install_interrupt_handler() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = signal_handler as *const () as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        // Deliberately NOT setting SA_RESTART so that blocking syscalls
        // (e.g. read() during interactive prompts) return EINTR on Ctrl+C
        // instead of silently restarting.
        //
        // The handler sets INTERRUPTED and restores the default SIGINT
        // disposition, so a second Ctrl+C force-kills the process. This
        // is needed because Rust's stdlib retries poll()/connect() on
        // EINTR, preventing cooperative check_interrupted() from running
        // during blocked connection attempts.
        sa.sa_flags = 0;
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
    }
}

extern "C" fn signal_handler(_sig: libc::c_int) {
    INTERRUPTED.store(true, Ordering::Relaxed);
    // Restore default handler: next SIGINT terminates the process.
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_DFL);
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

pub struct SudoUser {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
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

#[derive(Default)]
pub struct State {
    entries: BTreeMap<String, String>,
}

impl State {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.entries.insert(key.into(), value.into());
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries.get(key).map(|s| s.as_str())
    }

    /// Shorthand for `self.get("ROOTFS").unwrap_or("")`.
    pub fn rootfs(&self) -> &str {
        self.get("ROOTFS").unwrap_or("")
    }

    pub fn remove(&mut self, key: &str) {
        self.entries.remove(key);
    }

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

    pub fn write_to(&self, path: &Path) -> Result<()> {
        let content = self.serialize();
        atomic_write(path, content.as_bytes())
            .with_context(|| format!("failed to write {}", path.display()))
    }

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
#[derive(Debug, Default, Clone, PartialEq)]
pub struct ResourceLimits {
    /// `MemoryMax=`, e.g. "512M", "2G"
    pub memory: Option<String>,
    /// `CPUQuota=`, stored as a number of CPUs (e.g. "2" → 200%)
    pub cpus: Option<String>,
    /// `CPUWeight=`, integer 1–10000
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
fn cpus_to_quota(s: &str) -> u64 {
    let v: f64 = s.parse().unwrap_or(1.0);
    (v * 100.0).round() as u64
}

/// Validate a cpu-weight value (integer 1–10000).
fn validate_cpu_weight(s: &str) -> Result<()> {
    let v: u64 = s.parse().map_err(|_| {
        anyhow::anyhow!("invalid --cpu-weight value '{s}': expected integer 1–10000")
    })?;
    if !(1..=10000).contains(&v) {
        bail!("--cpu-weight must be 1–10000, got {v}");
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
        assert_eq!(content, "[Service]\nMemoryMax=2G\n");
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
