//! Security configuration for containers.
//!
//! Controls capability restrictions, seccomp filtering, privilege escalation,
//! read-only rootfs, and AppArmor profile selection. Configuration is stored in
//! the container's state file and converted to systemd-nspawn flags (or systemd
//! unit directives) at start time.

use std::io::Write;

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
    /// Enable user namespace isolation (`--private-users=pick`).
    pub userns: bool,
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
        !self.userns
            && self.drop_caps.is_empty()
            && self.add_caps.is_empty()
            && !self.no_new_privileges
            && !self.read_only
            && self.system_call_filter.is_empty()
            && self.apparmor_profile.is_none()
    }

    /// Read security config from a container's state file.
    pub fn from_state(state: &State) -> Self {
        Self {
            userns: state.is_yes("USERNS"),
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
        if self.userns {
            state.set("USERNS", "yes");
        } else {
            state.remove("USERNS");
        }

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

        if self.userns {
            args.push("--private-users=pick".to_string());
            args.push("--private-users-ownership=auto".to_string());
        }

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

/// Check that an AppArmor profile is loaded in the kernel.
///
/// Reads `/sys/kernel/security/apparmor/profiles` and verifies the named
/// profile appears. Returns an error with installation instructions if
/// the profile is not found, or if AppArmor is not available.
pub fn check_apparmor_loaded(profile: &str) -> Result<()> {
    let profiles_path = "/sys/kernel/security/apparmor/profiles";
    let content = match std::fs::read_to_string(profiles_path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            bail!(
                "AppArmor is not available on this system (no {profiles_path}).\n\
                 The container is configured with --apparmor-profile {profile},\n\
                 which requires AppArmor to be enabled in the kernel.\n\
                 Install AppArmor: apt install apparmor"
            );
        }
        Err(e) => {
            bail!("failed to read {profiles_path}: {e}");
        }
    };

    // Each line is: "profile_name (mode)" e.g. "sdme-default (enforce)"
    let found = content
        .lines()
        .any(|line| line.starts_with(profile) && line[profile.len()..].starts_with(" ("));

    if !found {
        bail!(
            "AppArmor profile '{profile}' is not loaded.\n\
             Install and load it with:\n\
             \n\
             \x20 sdme apparmor-profile > /etc/apparmor.d/{profile}\n\
             \x20 apparmor_parser -r /etc/apparmor.d/{profile}\n\
             \n\
             See: sdme apparmor-profile --help"
        );
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

/// Capabilities dropped by `--strict`.
///
/// `--strict` implies `--hardened` and adds Docker-equivalent cap drops.
/// Retains only the ~14 capabilities Docker grants plus `CAP_SYS_ADMIN`
/// (required for systemd init inside nspawn). Everything else is dropped,
/// including `CAP_NET_RAW` (which Docker retains but `--hardened` drops).
///
/// Docker's default retained set:
///   AUDIT_WRITE, CHOWN, DAC_OVERRIDE, FOWNER, FSETID, KILL,
///   MKNOD, NET_BIND_SERVICE, NET_RAW, SETFCAP, SETGID, SETPCAP,
///   SETUID, SYS_CHROOT
///
/// sdme additionally retains CAP_SYS_ADMIN for nspawn/systemd but
/// drops CAP_NET_RAW (carried over from --hardened).
pub const STRICT_DROP_CAPS: &[&str] = &[
    "CAP_AUDIT_CONTROL",
    "CAP_AUDIT_READ",
    "CAP_BLOCK_SUSPEND",
    "CAP_BPF",
    "CAP_CHECKPOINT_RESTORE",
    "CAP_DAC_READ_SEARCH",
    "CAP_IPC_LOCK",
    "CAP_IPC_OWNER",
    "CAP_LEASE",
    "CAP_LINUX_IMMUTABLE",
    "CAP_MAC_ADMIN",
    "CAP_MAC_OVERRIDE",
    "CAP_NET_ADMIN",
    "CAP_NET_BROADCAST",
    "CAP_NET_RAW",
    "CAP_PERFMON",
    "CAP_SYS_BOOT",
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

/// Seccomp syscall filter groups applied by `--strict`.
///
/// These deny groups layer on top of nspawn's built-in seccomp filter.
/// Matches Docker's restrictions where possible without breaking systemd.
pub const STRICT_SYSCALL_FILTERS: &[&str] =
    &["~@cpu-emulation", "~@debug", "~@obsolete", "~@raw-io"];

/// Default AppArmor profile name used by `--strict`.
pub const STRICT_APPARMOR_PROFILE: &str = "sdme-default";

/// Default AppArmor profile for sdme containers.
///
/// This profile is designed for systemd-nspawn system containers running a
/// full init (systemd). It allows the operations required for systemd boot
/// and container services while denying dangerous host-level access.
///
/// The profile is intentionally more permissive than Docker's docker-default
/// profile because sdme containers run a full init system that requires
/// mount, pivot_root, and other operations Docker containers don't need.
pub const APPARMOR_PROFILE: &str = r#"# AppArmor profile for sdme systemd-nspawn containers.
#
# This profile confines containers started with:
#   sdme create mybox --apparmor-profile sdme-default
#   sdme create mybox --strict
#
# Install:
#   sdme apparmor-profile > /etc/apparmor.d/sdme-default
#   apparmor_parser -r /etc/apparmor.d/sdme-default
#
# The profile is applied via AppArmorProfile= in the systemd service
# unit drop-in, confining the nspawn process and all its children.

abi <abi/4.0>,

include <tunables/global>

profile sdme-default flags=(attach_disconnected,mediate_deleted) {
  include <abstractions/base>
  include <abstractions/nameservice>

  # Allow most filesystem operations inside the container's overlayfs.
  # The container has its own mount namespace so these are scoped.
  /** rwlkix,

  # Allow mount/umount inside the container's mount namespace.
  # Required for systemd to set up /proc, /sys, tmpfs mounts at boot.
  mount,
  umount,
  pivot_root,

  # Allow signal delivery within the container.
  signal,

  # Allow ptrace within the container (for systemd-logind, etc.).
  # --strict drops CAP_SYS_PTRACE so this is capability-gated.
  ptrace,

  # Allow unix socket communication (D-Bus, journald, etc.).
  unix,

  # Allow network operations (scoped by network namespace).
  network,

  # Deny writes to /proc and /sys that could affect the host.
  # nspawn already mounts most of these read-only, but this adds
  # MAC-level enforcement.
  deny /proc/sys/kernel/modprobe w,
  deny /proc/sys/kernel/core_pattern w,
  deny /proc/sys/kernel/hostname w,
  deny /proc/sys/kernel/domainname w,
  deny /proc/sys/kernel/shmmax w,
  deny /proc/sysrq-trigger w,
  deny /proc/kcore r,

  # Deny access to host hardware and raw devices.
  deny /dev/sd* rw,
  deny /dev/nvme* rw,
  deny /dev/vd* rw,
  deny /dev/loop* rw,
  deny /dev/mem rw,
  deny /dev/kmem rw,
  deny /dev/port rw,

  # Deny loading kernel modules.
  deny /lib/modules/** w,
  deny /usr/lib/modules/** w,

  # Allow reading /proc and /sys for systemd and monitoring.
  @{PROC}/** r,
  @{sys}/** r,

  # Allow dbus communication.
  dbus,

  # Capabilities: allow the set that nspawn grants.
  # Individual capabilities are further restricted by the bounding set
  # configured via --drop-capability / --strict / --hardened.
  capability,
}
"#;

/// Print the default AppArmor profile to stdout.
pub fn print_apparmor_profile() -> Result<()> {
    std::io::stdout()
        .write_all(APPARMOR_PROFILE.as_bytes())
        .map_err(|e| anyhow::anyhow!("failed to write profile: {e}"))
}

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
            userns: true,
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
                "--private-users=pick",
                "--private-users-ownership=auto",
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
            userns: true,
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

    #[test]
    fn test_strict_drop_caps_are_valid() {
        for cap in STRICT_DROP_CAPS {
            assert!(
                validate_capability(cap).is_ok(),
                "strict cap should be valid: {cap}"
            );
        }
    }

    #[test]
    fn test_strict_drop_caps_excludes_sys_admin() {
        // CAP_SYS_ADMIN must NOT be in the drop list (nspawn needs it).
        assert!(
            !STRICT_DROP_CAPS.contains(&"CAP_SYS_ADMIN"),
            "CAP_SYS_ADMIN must not be dropped by --strict"
        );
    }

    #[test]
    fn test_strict_drop_caps_is_superset_of_hardened() {
        // Every cap in HARDENED_DROP_CAPS should also be in STRICT_DROP_CAPS.
        for cap in HARDENED_DROP_CAPS {
            assert!(
                STRICT_DROP_CAPS.contains(cap),
                "hardened cap {cap} should be in strict drop list"
            );
        }
        // And strict drops more caps overall.
        assert!(STRICT_DROP_CAPS.len() > HARDENED_DROP_CAPS.len());
    }

    #[test]
    fn test_strict_syscall_filters_are_valid() {
        for filter in STRICT_SYSCALL_FILTERS {
            assert!(
                validate_syscall_filter(filter).is_ok(),
                "strict filter should be valid: {filter}"
            );
        }
    }

    #[test]
    fn test_strict_apparmor_profile_is_valid() {
        assert!(validate_apparmor_profile(STRICT_APPARMOR_PROFILE).is_ok());
    }

    #[test]
    fn test_apparmor_profile_contains_profile_name() {
        assert!(APPARMOR_PROFILE.contains("profile sdme-default"));
    }
}
