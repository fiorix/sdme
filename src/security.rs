//! Security configuration for containers.
//!
//! Controls capability restrictions, seccomp filtering, privilege escalation,
//! read-only rootfs, and AppArmor profile selection. Configuration is stored in
//! the container's state file and converted to systemd-nspawn flags (or systemd
//! unit directives) at start time.

use anyhow::{bail, Result};

use crate::State;

/// Known Linux capability names accepted by systemd-nspawn.
const KNOWN_CAPS: &[&str] = &[
    "CAP_AUDIT_CONTROL",
    "CAP_AUDIT_READ",
    "CAP_AUDIT_WRITE",
    "CAP_BLOCK_SUSPEND",
    "CAP_BPF",
    "CAP_CHECKPOINT_RESTORE",
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_DAC_READ_SEARCH",
    "CAP_FOWNER",
    "CAP_FSETID",
    "CAP_IPC_LOCK",
    "CAP_IPC_OWNER",
    "CAP_KILL",
    "CAP_LEASE",
    "CAP_LINUX_IMMUTABLE",
    "CAP_MAC_ADMIN",
    "CAP_MAC_OVERRIDE",
    "CAP_MKNOD",
    "CAP_NET_ADMIN",
    "CAP_NET_BIND_SERVICE",
    "CAP_NET_BROADCAST",
    "CAP_NET_RAW",
    "CAP_PERFMON",
    "CAP_SETFCAP",
    "CAP_SETGID",
    "CAP_SETPCAP",
    "CAP_SETUID",
    "CAP_SYS_ADMIN",
    "CAP_SYS_BOOT",
    "CAP_SYS_CHROOT",
    "CAP_SYS_MODULE",
    "CAP_SYS_NICE",
    "CAP_SYS_PACCT",
    "CAP_SYS_PTRACE",
    "CAP_SYS_RAWIO",
    "CAP_SYS_RESOURCE",
    "CAP_SYS_TIME",
    "CAP_SYS_TTY_CONFIG",
    "CAP_SYSLOG",
    "CAP_WAKE_ALARM",
];

/// Security configuration for containers.
///
/// All fields are optional; unset fields mean "use nspawn defaults".
#[derive(Debug, Default, Clone, PartialEq)]
pub struct SecurityConfig {
    /// Capabilities to drop (e.g. `CAP_SYS_PTRACE`).
    pub drop_caps: Vec<String>,
    /// Capabilities to add back (e.g. `CAP_NET_ADMIN`).
    pub add_caps: Vec<String>,
    /// Prevent gaining privileges via setuid/file capabilities.
    pub no_new_privileges: bool,
    /// Mount the rootfs read-only.
    pub read_only: bool,
    /// Seccomp system call filter (e.g. `@system-service`, `~@mount`).
    pub system_call_filter: Vec<String>,
    /// AppArmor profile name (applied as systemd unit directive).
    pub apparmor_profile: Option<String>,
}

impl SecurityConfig {
    /// Returns true if no security options are set.
    pub fn is_empty(&self) -> bool {
        self.drop_caps.is_empty()
            && self.add_caps.is_empty()
            && !self.no_new_privileges
            && !self.read_only
            && self.system_call_filter.is_empty()
            && self.apparmor_profile.is_none()
    }

    /// Read security config from a container's state file.
    pub fn from_state(state: &State) -> Self {
        Self {
            drop_caps: state
                .get("DROP_CAPS")
                .filter(|s| !s.is_empty())
                .map(|s| s.split(',').map(String::from).collect())
                .unwrap_or_default(),
            add_caps: state
                .get("ADD_CAPS")
                .filter(|s| !s.is_empty())
                .map(|s| s.split(',').map(String::from).collect())
                .unwrap_or_default(),
            no_new_privileges: state.is_yes("NO_NEW_PRIVS"),
            read_only: state.is_yes("READ_ONLY"),
            system_call_filter: state
                .get("SYSCALL_FILTER")
                .filter(|s| !s.is_empty())
                .map(|s| s.split(',').map(String::from).collect())
                .unwrap_or_default(),
            apparmor_profile: state
                .get("APPARMOR_PROFILE")
                .filter(|s| !s.is_empty())
                .map(String::from),
        }
    }

    /// Write security config into a container's state file.
    pub fn write_to_state(&self, state: &mut State) {
        if self.drop_caps.is_empty() {
            state.remove("DROP_CAPS");
        } else {
            state.set("DROP_CAPS", self.drop_caps.join(","));
        }

        if self.add_caps.is_empty() {
            state.remove("ADD_CAPS");
        } else {
            state.set("ADD_CAPS", self.add_caps.join(","));
        }

        if self.no_new_privileges {
            state.set("NO_NEW_PRIVS", "yes");
        } else {
            state.remove("NO_NEW_PRIVS");
        }

        if self.read_only {
            state.set("READ_ONLY", "yes");
        } else {
            state.remove("READ_ONLY");
        }

        if self.system_call_filter.is_empty() {
            state.remove("SYSCALL_FILTER");
        } else {
            state.set("SYSCALL_FILTER", self.system_call_filter.join(","));
        }

        match &self.apparmor_profile {
            Some(p) => state.set("APPARMOR_PROFILE", p.as_str()),
            None => state.remove("APPARMOR_PROFILE"),
        }
    }

    /// Generate systemd-nspawn arguments for security options.
    ///
    /// Does NOT include AppArmor — that goes into the systemd unit drop-in
    /// as `AppArmorProfile=`, not as an nspawn flag.
    pub fn to_nspawn_args(&self) -> Vec<String> {
        let mut args = Vec::new();

        for cap in &self.drop_caps {
            args.push(format!("--drop-capability={cap}"));
        }

        for cap in &self.add_caps {
            args.push(format!("--capability={cap}"));
        }

        if self.no_new_privileges {
            args.push("--no-new-privileges=yes".to_string());
        }

        if self.read_only {
            args.push("--read-only".to_string());
        }

        for filter in &self.system_call_filter {
            args.push(format!("--system-call-filter={filter}"));
        }

        args
    }

    /// Validate all security settings.
    pub fn validate(&self) -> Result<()> {
        for cap in &self.drop_caps {
            validate_capability(cap)?;
        }
        for cap in &self.add_caps {
            validate_capability(cap)?;
        }

        // Check for contradictions: same cap in both add and drop.
        for cap in &self.add_caps {
            if self.drop_caps.contains(cap) {
                bail!("capability {cap} appears in both --capability and --drop-capability");
            }
        }

        for filter in &self.system_call_filter {
            validate_syscall_filter(filter)?;
        }

        if let Some(profile) = &self.apparmor_profile {
            validate_apparmor_profile(profile)?;
        }

        Ok(())
    }
}

/// Validate a capability name.
///
/// Accepts names with or without the `CAP_` prefix (normalizes to `CAP_`).
pub fn validate_capability(cap: &str) -> Result<()> {
    let normalized = normalize_cap(cap);
    if !KNOWN_CAPS.contains(&normalized.as_str()) {
        bail!("unknown capability: {cap}");
    }
    Ok(())
}

/// Normalize a capability name to include the `CAP_` prefix.
pub fn normalize_cap(cap: &str) -> String {
    let upper = cap.to_ascii_uppercase();
    if upper.starts_with("CAP_") {
        upper
    } else {
        format!("CAP_{upper}")
    }
}

/// Validate a seccomp syscall filter specification.
///
/// Accepts `@group-name` (allowlist) or `~@group-name` (denylist).
fn validate_syscall_filter(filter: &str) -> Result<()> {
    if filter.is_empty() {
        bail!("system call filter cannot be empty");
    }
    let spec = filter.strip_prefix('~').unwrap_or(filter);
    if !spec.starts_with('@') {
        bail!(
            "system call filter must start with @ (or ~@ for deny): {filter}\n\
             examples: @system-service, ~@mount, ~@raw-io"
        );
    }
    // Validate the group name: alphanumeric and hyphens only.
    let group = &spec[1..];
    if group.is_empty() {
        bail!("system call filter group name cannot be empty: {filter}");
    }
    for ch in group.chars() {
        if !ch.is_ascii_alphanumeric() && ch != '-' {
            bail!("invalid character '{ch}' in system call filter group: {filter}");
        }
    }
    Ok(())
}

/// Validate an AppArmor profile name.
///
/// Profile names must be non-empty and contain only safe characters.
fn validate_apparmor_profile(profile: &str) -> Result<()> {
    if profile.is_empty() {
        bail!("AppArmor profile name cannot be empty");
    }
    for ch in profile.chars() {
        if !ch.is_ascii_alphanumeric() && ch != '-' && ch != '_' && ch != '.' {
            bail!(
                "invalid character '{ch}' in AppArmor profile name: {profile}\n\
                 allowed: letters, digits, hyphens, underscores, dots"
            );
        }
    }
    Ok(())
}

/// Capabilities dropped by `--hardened`.
pub const HARDENED_DROP_CAPS: &[&str] = &[
    "CAP_SYS_PTRACE",
    "CAP_NET_RAW",
    "CAP_SYS_RAWIO",
    "CAP_SYS_BOOT",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_is_empty() {
        let sec = SecurityConfig::default();
        assert!(sec.is_empty());
        assert!(sec.to_nspawn_args().is_empty());
    }

    #[test]
    fn test_validate_known_caps() {
        assert!(validate_capability("CAP_SYS_PTRACE").is_ok());
        assert!(validate_capability("CAP_NET_RAW").is_ok());
        assert!(validate_capability("CAP_SYS_ADMIN").is_ok());
    }

    #[test]
    fn test_validate_cap_without_prefix() {
        assert!(validate_capability("SYS_PTRACE").is_ok());
        assert!(validate_capability("net_raw").is_ok());
    }

    #[test]
    fn test_validate_unknown_cap() {
        assert!(validate_capability("CAP_DOES_NOT_EXIST").is_err());
        assert!(validate_capability("BOGUS").is_err());
    }

    #[test]
    fn test_normalize_cap() {
        assert_eq!(normalize_cap("SYS_PTRACE"), "CAP_SYS_PTRACE");
        assert_eq!(normalize_cap("CAP_NET_RAW"), "CAP_NET_RAW");
        assert_eq!(normalize_cap("net_raw"), "CAP_NET_RAW");
    }

    #[test]
    fn test_validate_contradictory_caps() {
        let sec = SecurityConfig {
            drop_caps: vec!["CAP_NET_RAW".to_string()],
            add_caps: vec!["CAP_NET_RAW".to_string()],
            ..Default::default()
        };
        assert!(sec.validate().is_err());
    }

    #[test]
    fn test_validate_syscall_filter_ok() {
        assert!(validate_syscall_filter("@system-service").is_ok());
        assert!(validate_syscall_filter("~@mount").is_ok());
        assert!(validate_syscall_filter("~@raw-io").is_ok());
        assert!(validate_syscall_filter("@basic-io").is_ok());
    }

    #[test]
    fn test_validate_syscall_filter_bad() {
        assert!(validate_syscall_filter("").is_err());
        assert!(validate_syscall_filter("mount").is_err());
        assert!(validate_syscall_filter("@").is_err());
        assert!(validate_syscall_filter("@foo/bar").is_err());
    }

    #[test]
    fn test_validate_apparmor_profile_ok() {
        assert!(validate_apparmor_profile("sdme-container").is_ok());
        assert!(validate_apparmor_profile("my_profile.v2").is_ok());
    }

    #[test]
    fn test_validate_apparmor_profile_bad() {
        assert!(validate_apparmor_profile("").is_err());
        assert!(validate_apparmor_profile("foo bar").is_err());
        assert!(validate_apparmor_profile("foo/bar").is_err());
    }

    #[test]
    fn test_to_nspawn_args() {
        let sec = SecurityConfig {
            drop_caps: vec!["CAP_SYS_PTRACE".to_string(), "CAP_NET_RAW".to_string()],
            add_caps: vec!["CAP_NET_ADMIN".to_string()],
            no_new_privileges: true,
            read_only: true,
            system_call_filter: vec!["@system-service".to_string(), "~@mount".to_string()],
            apparmor_profile: Some("sdme-container".to_string()),
        };
        let args = sec.to_nspawn_args();
        assert_eq!(
            args,
            vec![
                "--drop-capability=CAP_SYS_PTRACE",
                "--drop-capability=CAP_NET_RAW",
                "--capability=CAP_NET_ADMIN",
                "--no-new-privileges=yes",
                "--read-only",
                "--system-call-filter=@system-service",
                "--system-call-filter=~@mount",
            ]
        );
        // AppArmor should NOT be in nspawn args.
        assert!(!args.iter().any(|a| a.contains("apparmor")));
    }

    #[test]
    fn test_state_roundtrip() {
        let sec = SecurityConfig {
            drop_caps: vec!["CAP_SYS_PTRACE".to_string()],
            add_caps: vec!["CAP_NET_ADMIN".to_string()],
            no_new_privileges: true,
            read_only: true,
            system_call_filter: vec!["~@mount".to_string()],
            apparmor_profile: Some("sdme-default".to_string()),
        };

        let mut state = State::new();
        state.set("NAME", "test");
        sec.write_to_state(&mut state);

        let serialized = state.serialize();
        let parsed = State::parse(&serialized).unwrap();
        let restored = SecurityConfig::from_state(&parsed);

        assert_eq!(restored, sec);
    }

    #[test]
    fn test_state_roundtrip_empty() {
        let sec = SecurityConfig::default();

        let mut state = State::new();
        state.set("NAME", "test");
        // Pre-set some values to verify they get cleaned up.
        state.set("DROP_CAPS", "CAP_NET_RAW");
        state.set("NO_NEW_PRIVS", "yes");
        sec.write_to_state(&mut state);

        let serialized = state.serialize();
        let parsed = State::parse(&serialized).unwrap();
        let restored = SecurityConfig::from_state(&parsed);

        assert!(restored.is_empty());
    }

    #[test]
    fn test_hardened_drop_caps_are_valid() {
        for cap in HARDENED_DROP_CAPS {
            assert!(
                validate_capability(cap).is_ok(),
                "hardened cap should be valid: {cap}"
            );
        }
    }
}
