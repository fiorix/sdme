pub mod config;
pub mod containers;
pub mod import;
pub mod names;
pub mod rootfs;
pub mod system_check;
pub mod systemd;

use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{bail, Context, Result};

pub static INTERRUPTED: AtomicBool = AtomicBool::new(false);

pub fn check_interrupted() -> Result<()> {
    if INTERRUPTED.load(Ordering::Relaxed) {
        bail!("interrupted");
    }
    Ok(())
}

pub fn install_interrupt_handler() {
    let _ = ctrlc::set_handler(|| {
        INTERRUPTED.store(true, Ordering::Relaxed);
    });
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

pub struct State {
    entries: BTreeMap<String, String>,
}

impl State {
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.entries.insert(key.into(), value.into());
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries.get(key).map(|s| s.as_str())
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
        fs::write(path, content).with_context(|| format!("failed to write {}", path.display()))
    }

    pub fn read_from(path: &Path) -> Result<Self> {
        let content =
            fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
        Self::parse(&content)
    }
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
}
