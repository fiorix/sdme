//! OCI app setup: user resolution, service unit generation, and app image building.

use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};

use super::registry::OciContainerConfig;
use crate::copy::make_removable;
use crate::import::shell_join;
use crate::validate_name;

// --- OCI user resolution ---

/// Resolved numeric identity for an OCI container user.
#[derive(Debug)]
pub(crate) struct ResolvedUser {
    pub(crate) uid: u32,
    pub(crate) gid: u32,
}

/// Parse an `/etc/passwd`-format file and look up a user by name or numeric UID.
///
/// Returns `(uid, primary_gid)` on match. The `user` argument may be a name
/// (matched against field 0) or a numeric string (matched against field 2).
fn lookup_passwd(passwd_path: &Path, user: &str) -> Option<(u32, u32)> {
    let content = fs::read_to_string(passwd_path).ok()?;
    let is_numeric = user.parse::<u32>().is_ok();
    for line in content.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 4 {
            continue;
        }
        let matched = if is_numeric {
            fields[2] == user
        } else {
            fields[0] == user
        };
        if matched {
            let uid: u32 = fields[2].parse().ok()?;
            let gid: u32 = fields[3].parse().ok()?;
            return Some((uid, gid));
        }
    }
    None
}

/// Parse an `/etc/group`-format file and look up a group by name.
///
/// Returns the numeric GID on match.
fn lookup_group(group_path: &Path, group: &str) -> Option<u32> {
    let content = fs::read_to_string(group_path).ok()?;
    for line in content.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 3 {
            continue;
        }
        if fields[0] == group {
            return fields[2].parse().ok();
        }
    }
    None
}

/// Resolve the OCI `User` field to numeric uid:gid.
///
/// The User field can be:
/// - `""` or `"root"` or `"0"` → root (uid=0, gid=0)
/// - `"name"` → look up in etc/passwd
/// - `"uid"` → use directly; look up primary GID from etc/passwd if found
/// - `"name:group"` or `"uid:gid"` → resolve both parts
///
/// Returns `None` for root users (uid=0), since they don't need privilege dropping.
pub(crate) fn resolve_oci_user(oci_root: &Path, user: &str) -> Result<Option<ResolvedUser>> {
    // Empty or literal "root": no privilege dropping needed.
    // Note: "root:somegroup" is treated as plain root (group ignored). This
    // differs from "0:somegroup" which goes through full resolution. The
    // early return is intentional: it avoids requiring etc/passwd to exist
    // just to resolve the well-known "root" name.
    // Split on `:` for user and optional group.
    let (user_part, group_part) = match user.split_once(':') {
        Some((u, g)) => (u, Some(g)),
        None => (user, None),
    };

    if user_part.is_empty() || user_part == "root" {
        return Ok(None);
    }

    // Determine UID and default GID from user part.
    let passwd_path = oci_root.join("etc/passwd");
    let (uid, default_gid) = if let Ok(numeric_uid) = user_part.parse::<u32>() {
        // Numeric UID: look up primary GID from passwd if possible.
        let primary_gid = lookup_passwd(&passwd_path, user_part)
            .map(|(_, gid)| gid)
            .unwrap_or(numeric_uid);
        (numeric_uid, primary_gid)
    } else {
        // Name: must resolve from passwd.
        match lookup_passwd(&passwd_path, user_part) {
            Some((uid, gid)) => (uid, gid),
            None => bail!(
                "OCI User '{}' not found in {}",
                user_part,
                passwd_path.display()
            ),
        }
    };

    // Root user (uid=0 without explicit group): no privilege dropping needed.
    if uid == 0 && group_part.is_none() {
        return Ok(None);
    }

    // Resolve explicit group if given.
    let gid = match group_part {
        Some(g) => {
            if let Ok(numeric_gid) = g.parse::<u32>() {
                numeric_gid
            } else {
                let group_path = oci_root.join("etc/group");
                match lookup_group(&group_path, g) {
                    Some(gid) => gid,
                    None => bail!("OCI group '{}' not found in {}", g, group_path.display()),
                }
            }
        }
        None => default_gid,
    };

    // Root user with explicit root group: still no privilege dropping needed.
    if uid == 0 && gid == 0 {
        return Ok(None);
    }

    Ok(Some(ResolvedUser { uid, gid }))
}

/// Resolve the first word of an exec command to an absolute path.
///
/// The isolate binary uses raw `execve()` which requires
/// absolute paths. OCI images sometimes specify entrypoints as bare names
/// (e.g. `docker-entrypoint.sh`) that rely on PATH resolution.
///
/// If the command already starts with `/`, it is returned unchanged.
/// Otherwise, common PATH directories inside the app root are searched.
fn resolve_exec_command(app_root: &Path, exec_start: &str) -> String {
    let (cmd, rest) = match exec_start.split_once(' ') {
        Some((c, r)) => (c, Some(r)),
        None => (exec_start, None),
    };

    if cmd.starts_with('/') {
        return exec_start.to_string();
    }

    const SEARCH_DIRS: &[&str] = &[
        "usr/local/sbin",
        "usr/local/bin",
        "usr/sbin",
        "usr/bin",
        "sbin",
        "bin",
    ];

    for dir in SEARCH_DIRS {
        let candidate = app_root.join(dir).join(cmd);
        if candidate.exists() {
            let abs = format!("/{dir}/{cmd}");
            return match rest {
                Some(r) => format!("{abs} {r}"),
                None => abs,
            };
        }
    }

    // Not found -- return as-is; execve will fail with a clear error.
    exec_start.to_string()
}

// --- OCI service security ---

/// Security overrides for an OCI app's systemd service unit.
///
/// When provided, these modify the default hardened baseline defined by
/// `OCI_DEFAULT_CAPS` and the fixed directives in `build_hardening_block()`.
pub(crate) struct OciServiceSecurity {
    /// Capabilities to add to the default bounding set.
    pub add_caps: Vec<String>,
    /// Capabilities to drop from the default bounding set.
    /// `"ALL"` drops everything (then only `add_caps` + `CAP_SYS_ADMIN` remain).
    pub drop_caps: Vec<String>,
    /// If `Some(true)`, sets `NoNewPrivileges=no`. Default baseline is `yes`.
    pub allow_privilege_escalation: Option<bool>,
    /// Add `ReadOnlyPaths=/` to the unit.
    pub read_only_root_filesystem: bool,
    /// `SystemCallFilter=` lines (e.g. `~@raw-io`).
    pub syscall_filters: Vec<String>,
    /// `AppArmorProfile=` value.
    pub apparmor_profile: Option<String>,
}

/// Build the hardening directives block for an OCI app service unit.
///
/// Computes the capability bounding set, `NoNewPrivileges`, fixed protection
/// directives, and optional seccomp/AppArmor/read-only overrides.
///
/// `CAP_SYS_ADMIN` is always included because the isolate binary needs it
/// for `unshare()`+`mount()` before dropping it via `prctl(PR_CAPBSET_DROP)`.
fn build_hardening_block(security: Option<&OciServiceSecurity>) -> String {
    use crate::security::OCI_DEFAULT_CAPS;

    // 1. Compute bounding set.
    let mut caps: Vec<String> = match security {
        Some(sec) if sec.drop_caps.iter().any(|c| c == "ALL") => {
            // "ALL" drops everything; start with only CAP_SYS_ADMIN.
            vec!["CAP_SYS_ADMIN".to_string()]
        }
        Some(sec) => {
            let mut set: Vec<String> = OCI_DEFAULT_CAPS
                .iter()
                .filter(|c| !sec.drop_caps.iter().any(|d| d == **c))
                .map(|c| c.to_string())
                .collect();
            // Ensure CAP_SYS_ADMIN is present even if someone tried to drop it.
            if !set.iter().any(|c| c == "CAP_SYS_ADMIN") {
                set.push("CAP_SYS_ADMIN".to_string());
            }
            set
        }
        None => OCI_DEFAULT_CAPS.iter().map(|c| c.to_string()).collect(),
    };

    // Add requested caps.
    if let Some(sec) = security {
        for cap in &sec.add_caps {
            if !caps.iter().any(|c| c == cap) {
                caps.push(cap.clone());
            }
        }
    }

    let caps_line = format!("CapabilityBoundingSet={}\n", caps.join(" "));

    // 2. NoNewPrivileges: yes unless allow_privilege_escalation == Some(true).
    let nnp = match security.and_then(|s| s.allow_privilege_escalation) {
        Some(true) => "NoNewPrivileges=no\n",
        _ => "NoNewPrivileges=yes\n",
    };

    // 3. Fixed protection directives.
    let fixed = "\
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
RestrictSUIDSGID=yes
LockPersonality=yes
ProtectProc=invisible
ProcSubset=pid
";

    // 4. Optional read-only root filesystem.
    let read_only = if security.is_some_and(|s| s.read_only_root_filesystem) {
        "ReadOnlyPaths=/\n"
    } else {
        ""
    };

    // 5. Optional syscall filters.
    let syscall = match security {
        Some(sec) if !sec.syscall_filters.is_empty() => sec
            .syscall_filters
            .iter()
            .map(|f| format!("SystemCallFilter={f}\n"))
            .collect::<String>(),
        _ => String::new(),
    };

    // 6. Optional AppArmor profile.
    let apparmor = match security.and_then(|s| s.apparmor_profile.as_deref()) {
        Some(p) => format!("AppArmorProfile={p}\n"),
        None => String::new(),
    };

    format!("{caps_line}{nnp}{fixed}{read_only}{syscall}{apparmor}")
}

// --- OCI application image support ---

/// Configuration for setting up an OCI app inside a combined rootfs.
///
/// Shared by `setup_app_image()` (single-app import) and kube's
/// `setup_kube_container()`. Each app lives under `/oci/apps/{name}/`.
pub(crate) struct OciAppSetup<'a> {
    /// App name (e.g. "nginx", "redis").
    pub name: &'a str,
    /// Combined rootfs being built (for unit dir paths).
    pub staging_dir: &'a Path,
    /// App directory: `/oci/apps/{name}` within staging.
    pub app_dir: &'a Path,
    /// App root: `/oci/apps/{name}/root` within staging.
    pub app_root: &'a Path,
    /// Pre-built ExecStart command string.
    pub exec_start: &'a str,
    /// Working directory inside the app root.
    pub working_dir: &'a str,
    /// User spec from the OCI config (e.g. "root", "nginx", "101:101").
    pub user: &'a str,
    /// Pre-merged environment lines (`KEY=VALUE`).
    pub env_lines: Vec<String>,
    /// OCI config (for ports, volumes, stop_signal).
    pub config: &'a OciContainerConfig,
    /// Image reference string for unit file comments.
    pub image_ref: &'a str,
    /// Restart policy for systemd unit (None = omit `Restart=` line).
    pub restart_policy: Option<&'a str>,
    /// Extra `BindPaths=`/`BindReadOnlyPaths=` lines for the service unit.
    pub bind_paths: Vec<String>,
    /// Extra units to add `After=` and `Requires=` dependencies on.
    pub extra_after: Vec<String>,
    /// Verbose output.
    pub verbose: bool,
    /// Timeout for stopping the service (maps to `TimeoutStopSec=`).
    pub timeout_stop_sec: Option<u32>,
    /// Extra systemd resource control lines (e.g. `MemoryMax=256M`).
    pub resource_lines: Vec<String>,
    /// Unit type override (e.g. "oneshot" for init containers). Default: "exec".
    pub unit_type: Option<&'a str>,
    /// Whether to add `RemainAfterExit=yes` (for oneshot init containers).
    pub remain_after_exit: bool,
    /// `After=` dependencies for the [Unit] section.
    pub after_units: Vec<String>,
    /// `Requires=` dependencies for the [Unit] section.
    pub requires_units: Vec<String>,
    /// `ExecStartPost=` command for readiness checks.
    pub readiness_exec: Option<String>,
    /// Per-service security overrides from K8s `securityContext`.
    pub security: Option<OciServiceSecurity>,
}

/// Set up a single OCI app inside a combined rootfs.
///
/// Creates the service unit, env/ports/volumes files, deploys devfd shim
/// and isolate binary. Common logic shared by `setup_app_image()` and
/// kube's `setup_kube_container()`.
pub(crate) fn setup_oci_app(opts: &OciAppSetup) -> Result<()> {
    // 1. Ensure essential runtime directories.
    for (dir, mode) in [
        ("tmp", 0o1777),
        ("run", 0o755),
        ("var/run", 0o755),
        ("var/tmp", 0o1777),
    ] {
        use std::os::unix::fs::DirBuilderExt;
        let path = opts.app_root.join(dir);
        if !path.exists() {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("failed to create {}", parent.display()))?;
            }
            fs::DirBuilder::new()
                .mode(mode)
                .create(&path)
                .with_context(|| format!("failed to create {}", path.display()))?;
        }
    }

    // 2. Deploy devfd shim.
    let arch = match std::env::consts::ARCH {
        "x86_64" => crate::elf::Arch::X86_64,
        "aarch64" => crate::elf::Arch::Aarch64,
        other => bail!("unsupported architecture: {other}"),
    };
    let shim_bytes = crate::devfd_shim::generate(arch);
    let shim_path = opts.app_root.join(".sdme-devfd-shim.so");
    fs::write(&shim_path, &shim_bytes)
        .with_context(|| format!("failed to write {}", shim_path.display()))?;
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&shim_path, fs::Permissions::from_mode(0o444))
        .with_context(|| format!("failed to set permissions on {}", shim_path.display()))?;
    if opts.verbose {
        eprintln!("wrote devfd shim: {}", shim_path.display());
    }

    // 3. Resolve user, deploy .sdme-isolate binary.
    // Always use isolate for all OCI apps (root and non-root). The isolate
    // binary creates PID/IPC namespaces, remounts /proc, drops CAP_SYS_ADMIN,
    // and optionally drops privileges; strictly more correct and secure than
    // running without namespace isolation.
    let resolved_user = resolve_oci_user(opts.app_root, opts.user)?;
    let elf_bytes = crate::isolate::generate(arch);
    let isolate_path = opts.app_root.join(".sdme-isolate");
    fs::write(&isolate_path, &elf_bytes)
        .with_context(|| format!("failed to write {}", isolate_path.display()))?;
    fs::set_permissions(&isolate_path, fs::Permissions::from_mode(0o111))
        .with_context(|| format!("failed to set permissions on {}", isolate_path.display()))?;
    if opts.verbose {
        let user_info = if let Some(ref ru) = resolved_user {
            format!(" for uid={} gid={}", ru.uid, ru.gid)
        } else {
            String::new()
        };
        eprintln!(
            "wrote isolate binary{}: {}",
            user_info,
            isolate_path.display()
        );
    }

    // 4. Write env file.
    if !opts.env_lines.is_empty() {
        let env_path = opts.app_dir.join("env");
        let content = opts.env_lines.join("\n") + "\n";
        fs::write(&env_path, &content)
            .with_context(|| format!("failed to write {}", env_path.display()))?;
    }

    // 5. Write ports file.
    if let Some(ref ports) = opts.config.exposed_ports {
        if !ports.is_empty() {
            let content = super::sorted_keys_joined(ports, "\n") + "\n";
            fs::write(opts.app_dir.join("ports"), &content)
                .context("failed to write ports file")?;
        }
    }

    // 6. Write volumes file.
    if let Some(ref vols) = opts.config.volumes {
        if !vols.is_empty() {
            let content = super::sorted_keys_joined(vols, "\n") + "\n";
            fs::write(opts.app_dir.join("volumes"), &content)
                .context("failed to write volumes file")?;
        }
    }

    // 7. Build the [Service] section.
    let bind_paths_section = if opts.bind_paths.is_empty() {
        String::new()
    } else {
        opts.bind_paths.join("\n") + "\n"
    };

    let stop_signal_line = opts
        .config
        .stop_signal
        .as_ref()
        .map(|sig| format!("KillSignal={sig}\n"))
        .unwrap_or_default();

    // Always use .sdme-isolate for all users (root and non-root).
    // The isolate binary handles PID/IPC namespace creation, /proc remount,
    // CAP_SYS_ADMIN drop, and optional privilege dropping.
    let (uid, gid) = if let Some(ref ru) = resolved_user {
        (ru.uid, ru.gid)
    } else {
        (0, 0) // root: isolate still creates namespaces
    };
    // The isolate binary uses raw execve which requires absolute paths.
    // Resolve relative command names against the app root's PATH dirs.
    let exec_start = resolve_exec_command(opts.app_root, opts.exec_start);
    let isolate_exec = format!(
        "/.sdme-isolate {} {} {} {}",
        uid, gid, opts.working_dir, exec_start
    );
    let service_section = format!(
        "\
RootDirectory=/oci/apps/{name}/root
MountAPIVFS=yes
Environment=LD_PRELOAD=/.sdme-devfd-shim.so
EnvironmentFile=-/oci/apps/{name}/env
ExecStart={isolate_exec}
{stop_signal_line}{bind_paths_section}",
        name = opts.name
    );

    let restart_line = match opts.restart_policy {
        Some(policy) if opts.unit_type != Some("oneshot") => format!("Restart={policy}\n"),
        _ => String::new(),
    };

    let unit_type = opts.unit_type.unwrap_or("exec");

    let remain_after_exit_line = if opts.remain_after_exit {
        "RemainAfterExit=yes\n"
    } else {
        ""
    };

    let timeout_stop_line = opts
        .timeout_stop_sec
        .map(|t| format!("TimeoutStopSec={t}s\n"))
        .unwrap_or_default();

    let resource_section = if opts.resource_lines.is_empty() {
        String::new()
    } else {
        opts.resource_lines.join("\n") + "\n"
    };

    let readiness_line = opts
        .readiness_exec
        .as_ref()
        .map(|cmd| format!("ExecStartPost={cmd}\n"))
        .unwrap_or_default();

    // Hardening directives: always applied since all OCI apps use isolate.
    // CAP_SYS_ADMIN is kept in the bounding set because the isolate binary
    // needs it for unshare() and mount(); the binary drops it via
    // prctl(PR_CAPBSET_DROP) before exec'ing the workload.
    let isolate_hardening = build_hardening_block(opts.security.as_ref());

    // Build [Unit] section dependencies.
    // Merge extra_after (e.g. volume service) into after_units/requires_units.
    let mut all_after = opts.after_units.clone();
    all_after.extend(opts.extra_after.iter().cloned());
    let mut all_requires = opts.requires_units.clone();
    all_requires.extend(opts.extra_after.iter().cloned());

    let mut unit_after = "After=network.target".to_string();
    for u in &all_after {
        unit_after.push_str(&format!(" {u}"));
    }
    let unit_requires = if all_requires.is_empty() {
        String::new()
    } else {
        format!("Requires={}\n", all_requires.join(" "))
    };

    let service_name = format!("sdme-oci-{}.service", opts.name);
    let unit_content = format!(
        r#"# Generated by sdme from image: {image_ref}
[Unit]
Description=OCI app: {name} ({image_ref})
{unit_after}
{unit_requires}
[Service]
Type={unit_type}
{remain_after_exit_line}{service_section}{restart_line}{timeout_stop_line}{resource_section}{isolate_hardening}{readiness_line}
[Install]
WantedBy=multi-user.target
"#,
        image_ref = opts.image_ref,
        name = opts.name,
    );

    let unit_dir = opts.staging_dir.join("etc/systemd/system");
    fs::create_dir_all(&unit_dir)
        .with_context(|| format!("failed to create {}", unit_dir.display()))?;
    let unit_path = unit_dir.join(&service_name);
    fs::write(&unit_path, &unit_content)
        .with_context(|| format!("failed to write {}", unit_path.display()))?;

    // 8. Enable via symlink.
    let wants_dir = unit_dir.join("multi-user.target.wants");
    fs::create_dir_all(&wants_dir)
        .with_context(|| format!("failed to create {}", wants_dir.display()))?;
    let symlink_path = wants_dir.join(&service_name);
    std::os::unix::fs::symlink(format!("../{service_name}"), &symlink_path)
        .with_context(|| format!("failed to create symlink {}", symlink_path.display()))?;

    if opts.verbose {
        eprintln!("wrote unit file: {}", unit_path.display());
    }

    Ok(())
}

/// Set up an application image by combining a base rootfs with the OCI rootfs.
///
/// The OCI rootfs (already extracted in staging_dir) is moved to
/// `/oci/apps/{app_name}/root` inside a copy of the base rootfs. A systemd
/// unit is generated to chroot into the OCI rootfs and run the application's
/// entrypoint/cmd.
#[allow(clippy::too_many_arguments)]
pub(crate) fn setup_app_image(
    datadir: &Path,
    staging_dir: &Path,
    rootfs_dir: &Path,
    name: &str,
    base_name: &str,
    app_name: &str,
    config: &OciContainerConfig,
    image_ref: &str,
    verbose: bool,
) -> Result<()> {
    validate_name(base_name)?;

    let base_dir = datadir.join("fs").join(base_name);
    if !base_dir.is_dir() {
        bail!("base rootfs not found: {base_name}");
    }

    // Build the ExecStart command from entrypoint + cmd.
    let mut exec_args: Vec<String> = Vec::new();
    if let Some(ref ep) = config.entrypoint {
        exec_args.extend(ep.iter().cloned());
    }
    if let Some(ref cmd) = config.cmd {
        exec_args.extend(cmd.iter().cloned());
    }
    if exec_args.is_empty() {
        bail!("OCI image has no Entrypoint or Cmd; cannot generate service unit");
    }
    let exec_start = shell_join(&exec_args);

    let working_dir = config.working_dir.as_deref().unwrap_or("/");
    let user = config.user.as_deref().unwrap_or("root");

    if verbose {
        eprintln!("setting up application image with base '{base_name}'");
    }

    // 1. Rename staging_dir (OCI rootfs) to a temp location.
    let oci_tmp = rootfs_dir.join(format!(".{name}.oci-tmp"));
    if oci_tmp.exists() {
        let _ = make_removable(&oci_tmp);
        fs::remove_dir_all(&oci_tmp)
            .with_context(|| format!("failed to remove {}", oci_tmp.display()))?;
    }
    fs::rename(staging_dir, &oci_tmp).with_context(|| {
        format!(
            "failed to rename {} to {}",
            staging_dir.display(),
            oci_tmp.display()
        )
    })?;

    // 2. Copy the base rootfs to staging_dir.
    if verbose {
        eprintln!("copying base rootfs '{base_name}' to staging directory");
    }
    fs::create_dir_all(staging_dir)
        .with_context(|| format!("failed to create {}", staging_dir.display()))?;
    crate::copy::copy_tree(&base_dir, staging_dir, verbose)
        .with_context(|| format!("failed to copy base rootfs from {}", base_dir.display()))?;

    // 3. Move OCI rootfs contents into staging_dir/oci/apps/{app_name}/root/.
    let app_dir = staging_dir.join("oci/apps").join(app_name);
    let app_root = app_dir.join("root");
    fs::create_dir_all(&app_root)
        .with_context(|| format!("failed to create {}", app_root.display()))?;

    if verbose {
        eprintln!("moving OCI rootfs to {}", app_root.display());
    }
    for entry in
        fs::read_dir(&oci_tmp).with_context(|| format!("failed to read {}", oci_tmp.display()))?
    {
        let entry = entry?;
        let dest = app_root.join(entry.file_name());
        fs::rename(entry.path(), &dest).with_context(|| {
            format!(
                "failed to move {} to {}",
                entry.path().display(),
                dest.display()
            )
        })?;
    }

    // 4. Set up the OCI app (common logic).
    let env_lines = config.env.clone().unwrap_or_default();
    setup_oci_app(&OciAppSetup {
        name: app_name,
        staging_dir,
        app_dir: &app_dir,
        app_root: &app_root,
        exec_start: &exec_start,
        working_dir,
        user,
        env_lines,
        config,
        image_ref,
        restart_policy: None,
        bind_paths: Vec::new(),
        extra_after: vec![],
        verbose,
        timeout_stop_sec: None,
        resource_lines: Vec::new(),
        unit_type: None,
        remain_after_exit: false,
        after_units: Vec::new(),
        requires_units: Vec::new(),
        readiness_exec: None,
        security: None,
    })?;

    // 5. Clean up temp OCI dir.
    let _ = make_removable(&oci_tmp);
    fs::remove_dir_all(&oci_tmp)
        .with_context(|| format!("failed to remove {}", oci_tmp.display()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn make_oci_root(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sdme-test-oci-user-{}-{:?}-{name}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("etc")).unwrap();
        dir
    }

    #[test]
    fn test_resolve_oci_user_root() {
        let root = make_oci_root("resolve-root");
        assert!(resolve_oci_user(&root, "").unwrap().is_none());
        assert!(resolve_oci_user(&root, "root").unwrap().is_none());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn test_resolve_oci_user_root_explicit_group() {
        let root = make_oci_root("resolve-root-grp");
        // "root:somegroup" returns None (early return for literal "root").
        assert!(resolve_oci_user(&root, "root:somegroup").unwrap().is_none());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn test_resolve_oci_user_named() {
        let root = make_oci_root("resolve-named");
        fs::write(
            root.join("etc/passwd"),
            "root:x:0:0:root:/root:/bin/bash\nnginx:x:101:101:nginx:/nonexistent:/sbin/nologin\n",
        )
        .unwrap();
        let ru = resolve_oci_user(&root, "nginx").unwrap().unwrap();
        assert_eq!(ru.uid, 101);
        assert_eq!(ru.gid, 101);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn test_resolve_oci_user_numeric() {
        let root = make_oci_root("resolve-numeric");
        fs::write(
            root.join("etc/passwd"),
            "root:x:0:0:root:/root:/bin/bash\nnginx:x:101:101:nginx:/nonexistent:/sbin/nologin\n",
        )
        .unwrap();
        // Numeric UID found in passwd: uses primary GID from passwd.
        let ru = resolve_oci_user(&root, "101").unwrap().unwrap();
        assert_eq!(ru.uid, 101);
        assert_eq!(ru.gid, 101);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn test_resolve_oci_user_numeric_not_in_passwd() {
        let root = make_oci_root("resolve-numeric-missing");
        // No passwd file: falls back to uid==gid.
        let ru = resolve_oci_user(&root, "1000").unwrap().unwrap();
        assert_eq!(ru.uid, 1000);
        assert_eq!(ru.gid, 1000);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn test_resolve_oci_user_with_explicit_group() {
        let root = make_oci_root("resolve-group");
        fs::write(
            root.join("etc/passwd"),
            "nginx:x:101:101:nginx:/nonexistent:/sbin/nologin\n",
        )
        .unwrap();
        fs::write(root.join("etc/group"), "www-data:x:33:\n").unwrap();
        let ru = resolve_oci_user(&root, "nginx:www-data").unwrap().unwrap();
        assert_eq!(ru.uid, 101);
        assert_eq!(ru.gid, 33);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn test_resolve_oci_user_with_numeric_group() {
        let root = make_oci_root("resolve-numgroup");
        fs::write(
            root.join("etc/passwd"),
            "nginx:x:101:101:nginx:/nonexistent:/sbin/nologin\n",
        )
        .unwrap();
        let ru = resolve_oci_user(&root, "nginx:42").unwrap().unwrap();
        assert_eq!(ru.uid, 101);
        assert_eq!(ru.gid, 42);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn test_resolve_oci_user_named_not_found() {
        let root = make_oci_root("resolve-notfound");
        fs::write(root.join("etc/passwd"), "root:x:0:0:root:/root:/bin/bash\n").unwrap();
        let err = resolve_oci_user(&root, "missing").unwrap_err();
        assert!(err.to_string().contains("not found"), "unexpected: {err}");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn test_resolve_oci_user_group_not_found() {
        let root = make_oci_root("resolve-group-notfound");
        fs::write(
            root.join("etc/passwd"),
            "nginx:x:101:101:nginx:/nonexistent:/sbin/nologin\n",
        )
        .unwrap();
        fs::write(root.join("etc/group"), "root:x:0:\n").unwrap();
        let err = resolve_oci_user(&root, "nginx:missing").unwrap_err();
        assert!(err.to_string().contains("not found"), "unexpected: {err}");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn test_build_hardening_block_default() {
        let block = build_hardening_block(None);
        assert!(
            block.contains("CAP_SYS_ADMIN"),
            "must include CAP_SYS_ADMIN"
        );
        assert!(block.contains("CAP_NET_RAW"), "must include CAP_NET_RAW");
        assert!(
            block.contains("NoNewPrivileges=yes"),
            "default NoNewPrivileges should be yes"
        );
        assert!(
            block.contains("ProtectKernelModules=yes"),
            "should have fixed directives"
        );
        assert!(
            !block.contains("ReadOnlyPaths"),
            "should not be read-only by default"
        );
        assert!(
            !block.contains("SystemCallFilter"),
            "no syscall filters by default"
        );
        assert!(!block.contains("AppArmorProfile"), "no apparmor by default");
    }

    #[test]
    fn test_build_hardening_block_add_caps() {
        let sec = OciServiceSecurity {
            add_caps: vec!["CAP_NET_ADMIN".to_string()],
            drop_caps: vec![],
            allow_privilege_escalation: None,
            read_only_root_filesystem: false,
            syscall_filters: vec![],
            apparmor_profile: None,
        };
        let block = build_hardening_block(Some(&sec));
        assert!(block.contains("CAP_NET_ADMIN"), "should add CAP_NET_ADMIN");
        assert!(block.contains("CAP_SYS_ADMIN"), "must keep CAP_SYS_ADMIN");
    }

    #[test]
    fn test_build_hardening_block_drop_caps() {
        let sec = OciServiceSecurity {
            add_caps: vec![],
            drop_caps: vec!["CAP_NET_RAW".to_string()],
            allow_privilege_escalation: None,
            read_only_root_filesystem: false,
            syscall_filters: vec![],
            apparmor_profile: None,
        };
        let block = build_hardening_block(Some(&sec));
        assert!(
            !block.contains("CAP_NET_RAW"),
            "CAP_NET_RAW should be dropped"
        );
        assert!(block.contains("CAP_SYS_ADMIN"), "must keep CAP_SYS_ADMIN");
    }

    #[test]
    fn test_build_hardening_block_drop_all() {
        let sec = OciServiceSecurity {
            add_caps: vec!["CAP_CHOWN".to_string()],
            drop_caps: vec!["ALL".to_string()],
            allow_privilege_escalation: None,
            read_only_root_filesystem: false,
            syscall_filters: vec![],
            apparmor_profile: None,
        };
        let block = build_hardening_block(Some(&sec));
        // Only CAP_SYS_ADMIN (always) and CAP_CHOWN (explicitly added) should remain.
        assert!(
            block.contains("CAP_SYS_ADMIN"),
            "must preserve CAP_SYS_ADMIN"
        );
        assert!(block.contains("CAP_CHOWN"), "should include added cap");
        assert!(
            !block.contains("CAP_NET_RAW"),
            "should not include defaults after ALL drop"
        );
        assert!(
            !block.contains("CAP_SETUID"),
            "should not include defaults after ALL drop"
        );
    }

    #[test]
    fn test_build_hardening_block_drop_all_preserves_sys_admin() {
        let sec = OciServiceSecurity {
            add_caps: vec![],
            drop_caps: vec!["ALL".to_string()],
            allow_privilege_escalation: None,
            read_only_root_filesystem: false,
            syscall_filters: vec![],
            apparmor_profile: None,
        };
        let block = build_hardening_block(Some(&sec));
        // Even dropping ALL, CAP_SYS_ADMIN must be present.
        assert!(
            block.contains("CAP_SYS_ADMIN"),
            "CAP_SYS_ADMIN must survive drop ALL"
        );
    }

    #[test]
    fn test_build_hardening_block_allow_privilege_escalation() {
        let sec = OciServiceSecurity {
            add_caps: vec![],
            drop_caps: vec![],
            allow_privilege_escalation: Some(true),
            read_only_root_filesystem: false,
            syscall_filters: vec![],
            apparmor_profile: None,
        };
        let block = build_hardening_block(Some(&sec));
        assert!(
            block.contains("NoNewPrivileges=no"),
            "should set NoNewPrivileges=no"
        );
    }

    #[test]
    fn test_build_hardening_block_read_only() {
        let sec = OciServiceSecurity {
            add_caps: vec![],
            drop_caps: vec![],
            allow_privilege_escalation: None,
            read_only_root_filesystem: true,
            syscall_filters: vec![],
            apparmor_profile: None,
        };
        let block = build_hardening_block(Some(&sec));
        assert!(
            block.contains("ReadOnlyPaths=/"),
            "should add ReadOnlyPaths"
        );
    }

    #[test]
    fn test_build_hardening_block_syscall_filters() {
        let sec = OciServiceSecurity {
            add_caps: vec![],
            drop_caps: vec![],
            allow_privilege_escalation: None,
            read_only_root_filesystem: false,
            syscall_filters: vec!["~@raw-io".to_string(), "~@debug".to_string()],
            apparmor_profile: None,
        };
        let block = build_hardening_block(Some(&sec));
        assert!(
            block.contains("SystemCallFilter=~@raw-io"),
            "should have syscall filter"
        );
        assert!(
            block.contains("SystemCallFilter=~@debug"),
            "should have syscall filter"
        );
    }

    #[test]
    fn test_build_hardening_block_apparmor() {
        let sec = OciServiceSecurity {
            add_caps: vec![],
            drop_caps: vec![],
            allow_privilege_escalation: None,
            read_only_root_filesystem: false,
            syscall_filters: vec![],
            apparmor_profile: Some("sdme-default".to_string()),
        };
        let block = build_hardening_block(Some(&sec));
        assert!(
            block.contains("AppArmorProfile=sdme-default"),
            "should have AppArmor profile"
        );
    }
}
