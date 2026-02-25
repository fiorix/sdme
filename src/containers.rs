//! Internal API for container filesystem, state, and runtime management.
//!
//! Each container gets an overlayfs directory tree (`upper/work/merged/shared`)
//! under the configured data directory and a KEY=VALUE state file that tracks
//! its metadata. All mutating operations follow a transaction-style pattern:
//! work is performed step-by-step and, on failure, partially-created artifacts
//! are cleaned up before the error is returned. New implementations and changes
//! should conform to this pattern.

use std::ffi::CString;
use std::fs::{self, OpenOptions};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};

use crate::{BindConfig, EnvConfig, NetworkConfig, ResourceLimits, State, names, rootfs, systemd, validate_name};

pub struct CreateOptions {
    pub name: Option<String>,
    pub rootfs: Option<String>,
    pub limits: ResourceLimits,
    pub network: NetworkConfig,
    pub opaque_dirs: Vec<String>,
    pub binds: BindConfig,
    pub envs: EnvConfig,
}

/// Read the current process umask. There is no "get umask" syscall, so
/// we set it to 0, read the old value, and restore it immediately.
fn get_umask() -> u32 {
    let old = unsafe { libc::umask(0) };
    unsafe { libc::umask(old) };
    old as u32
}

pub fn create(datadir: &Path, opts: &CreateOptions, verbose: bool) -> Result<String> {
    let umask = get_umask();
    if umask & 0o005 != 0 {
        bail!(
            "current umask ({:04o}) strips read/execute from 'other', which would \
             prevent services inside the container from accessing the filesystem. \
             Set a more permissive umask (e.g. umask 022) before running this command."
            , umask
        );
    }

    let name = match &opts.name {
        Some(n) => n.clone(),
        None => names::generate_name(datadir)?,
    };
    validate_name(&name)?;
    if verbose {
        eprintln!("container name: {name}");
    }
    check_conflicts(datadir, &name)?;
    if verbose {
        eprintln!("no conflicts found");
    }
    let rootfs = resolve_rootfs(datadir, opts.rootfs.as_deref())?;
    if verbose {
        eprintln!("rootfs: {}", rootfs.display());
    }

    let opaque_dirs = validate_opaque_dirs(&opts.opaque_dirs)?;

    // Atomically claim the name by creating the state file with O_CREAT|O_EXCL.
    // This prevents a TOCTOU race where two concurrent creates pass check_conflicts().
    let state_dir = datadir.join("state");
    fs::create_dir_all(&state_dir)
        .with_context(|| format!("failed to create {}", state_dir.display()))?;
    set_dir_permissions(datadir, 0o700)?;
    set_dir_permissions(&state_dir, 0o700)?;

    let state_path = state_dir.join(&name);
    let _lock_file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&state_path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            bail!("state file already exists for: {name} (concurrent create?)");
        }
        Err(e) => {
            return Err(e).with_context(|| format!("failed to create {}", state_path.display()));
        }
    };

    if verbose {
        eprintln!("claimed state file: {}", state_path.display());
    }

    match do_create(datadir, &name, &rootfs, opts, &opaque_dirs, verbose) {
        Ok(()) => Ok(name),
        Err(e) => {
            let container_dir = datadir.join("containers").join(&name);
            let _ = fs::remove_dir_all(&container_dir);
            let _ = fs::remove_file(&state_path);
            Err(e)
        }
    }
}

fn do_create(datadir: &Path, name: &str, rootfs: &Path, opts: &CreateOptions, opaque_dirs: &[String], verbose: bool) -> Result<()> {
    let container_dir = datadir.join("containers").join(name);
    let containers_dir = datadir.join("containers");
    fs::create_dir_all(&containers_dir)
        .with_context(|| format!("failed to create {}", containers_dir.display()))?;
    set_dir_permissions(&containers_dir, 0o700)?;

    // The upper directory becomes the root of the overlayfs merged view, so it
    // must be world-readable (0o755) — otherwise non-root services inside the
    // container (e.g. dbus-daemon running as messagebus) cannot traverse the
    // filesystem. The merged mount point also needs 0o755. The work directory
    // is overlayfs-internal and can stay restricted.
    for (sub, mode) in &[
        ("upper", 0o755),
        ("work", 0o700),
        ("merged", 0o755),
        ("shared", 0o755),
    ] {
        let dir = container_dir.join(sub);
        fs::create_dir_all(&dir)
            .with_context(|| format!("failed to create {}", dir.display()))?;
        set_dir_permissions(&dir, *mode)?;
    }

    if verbose {
        eprintln!("created container directory: {}", container_dir.display());
    }

    // Set up opaque directories in the upper layer. Setting the
    // trusted.overlay.opaque xattr to "y" on a directory makes overlayfs
    // hide all lower-layer contents, so the directory starts empty.
    let upper = container_dir.join("upper");
    for dir in opaque_dirs {
        let rel = dir.strip_prefix('/').unwrap_or(dir);
        let target = upper.join(rel);
        fs::create_dir_all(&target)
            .with_context(|| format!("failed to create opaque dir {}", target.display()))?;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755))
            .with_context(|| format!("failed to set permissions on {}", target.display()))?;
        set_opaque_xattr(&target)
            .with_context(|| format!("failed to set opaque xattr on {}", target.display()))?;
        if verbose {
            eprintln!("set opaque: {dir}");
        }
    }

    let etc_dir = container_dir.join("upper").join("etc");
    fs::create_dir_all(&etc_dir)
        .with_context(|| format!("failed to create {}", etc_dir.display()))?;

    let hostname_path = etc_dir.join("hostname");
    fs::write(&hostname_path, format!("{name}\n"))
        .with_context(|| format!("failed to write {}", hostname_path.display()))?;

    let hosts_path = etc_dir.join("hosts");
    fs::write(
        &hosts_path,
        format!("127.0.0.1 localhost {name}\n::1 localhost\n"),
    )
    .with_context(|| format!("failed to write {}", hosts_path.display()))?;

    // Mask systemd-resolved in the container. When a container shares the
    // host's network namespace (the default, no --private-network), the
    // container's own systemd-resolved cannot bind 127.0.0.53 (already owned
    // by the host) and ends up with no upstream DNS servers. The NSS "resolve"
    // module then intercepts all lookups, gets SERVFAIL from the broken
    // resolved, and the [!UNAVAIL=return] action in nsswitch.conf prevents
    // fallback to the "dns" module. Masking the service makes NSS skip the
    // resolve module (UNAVAIL) and fall through to "dns", which reads
    // /etc/resolv.conf and queries the host's resolver.
    let systemd_unit_dir = etc_dir.join("systemd").join("system");
    fs::create_dir_all(&systemd_unit_dir)
        .with_context(|| format!("failed to create {}", systemd_unit_dir.display()))?;

    // For host-rootfs containers, mask host-specific .mount and .swap
    // units from /etc/systemd/system/ so they don't leak through overlayfs.
    // These units reference block devices and paths (e.g. /data) that don't
    // exist inside the container, causing "Failed to isolate default target"
    // when systemd can't resolve their dependencies at boot.
    if rootfs == Path::new("/") {
        mask_host_mount_units(&systemd_unit_dir, verbose)?;
    }

    let resolved_mask = systemd_unit_dir.join("systemd-resolved.service");
    symlink("/dev/null", &resolved_mask)
        .with_context(|| format!("failed to mask systemd-resolved at {}", resolved_mask.display()))?;

    // Write a placeholder /etc/resolv.conf as a regular file so that
    // systemd-nspawn's --resolv-conf=auto can overwrite it with the host's
    // DNS configuration. Many rootfs images (e.g. Debian) ship resolv.conf as
    // a symlink to ../run/systemd/resolve/stub-resolv.conf; the auto mode's
    // copy variant won't overwrite a symlink, leaving DNS broken. A regular
    // file in the overlayfs upper layer shadows the lower layer's symlink.
    let resolv_path = etc_dir.join("resolv.conf");
    fs::write(&resolv_path, "# placeholder — replaced by systemd-nspawn at boot\n")
        .with_context(|| format!("failed to write {}", resolv_path.display()))?;

    // Write an empty /etc/machine-id so the container gets a unique
    // transient machine ID at boot instead of inheriting the host's.
    // When host and container share the same machine-id, systemd-nspawn
    // refuses to link journals and systemd inside the container may
    // behave unexpectedly. An empty file tells systemd to generate a
    // transient ID during early boot (ConditionFirstBoot / systemd-machine-id-setup).
    let machine_id_path = etc_dir.join("machine-id");
    fs::write(&machine_id_path, "")
        .with_context(|| format!("failed to write {}", machine_id_path.display()))?;

    // Write a minimal /etc/fstab so systemd-fstab-generator inside the
    // container does not create mount units from the host's fstab. When
    // the lower layer is the host rootfs, the host's fstab entries (e.g.
    // /data) leak through overlayfs and the container's systemd tries to
    // mount them, failing with "Unit data.mount not found" and preventing
    // boot.
    let fstab_path = etc_dir.join("fstab");
    fs::write(&fstab_path, "# empty — host mounts not applicable in container\n")
        .with_context(|| format!("failed to write {}", fstab_path.display()))?;

    if verbose {
        eprintln!("wrote hostname, hosts, resolv.conf, machine-id, and fstab files; masked systemd-resolved");
    }

    let rootfs_value = if rootfs == Path::new("/") {
        String::new()
    } else {
        rootfs
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default()
    };

    let mut state = State::new();
    state.set("CREATED", unix_timestamp().to_string());
    state.set("NAME", name);
    state.set("ROOTFS", rootfs_value);
    opts.limits.write_to_state(&mut state);
    opts.network.write_to_state(&mut state);
    opts.binds.write_to_state(&mut state);
    opts.envs.write_to_state(&mut state);
    if !opaque_dirs.is_empty() {
        state.set("OPAQUE_DIRS", opaque_dirs.join(","));
    }

    // State file was already created atomically by create(); write content to it.
    let state_path = datadir.join("state").join(name);
    state.write_to(&state_path)?;

    if verbose {
        eprintln!("wrote state file: {}", state_path.display());
    }

    Ok(())
}

/// Validate and normalize opaque directory paths.
///
/// Each path must be absolute, must not contain `..` components, and must
/// not be empty. Trailing slashes are stripped and duplicates are rejected.
pub fn validate_opaque_dirs(dirs: &[String]) -> Result<Vec<String>> {
    let mut seen = std::collections::HashSet::new();
    let mut result = Vec::with_capacity(dirs.len());
    for raw in dirs {
        if raw.is_empty() {
            bail!("opaque directory path cannot be empty");
        }
        let path = Path::new(raw);
        if !path.is_absolute() {
            bail!("opaque directory must be an absolute path: {raw}");
        }
        for comp in path.components() {
            if comp == Component::ParentDir {
                bail!("opaque directory must not contain '..': {raw}");
            }
        }
        // Normalize: rebuild from components (strips trailing slashes).
        let normalized: PathBuf = path.components().collect();
        let s = normalized.to_string_lossy().to_string();
        if !seen.insert(s.clone()) {
            bail!("duplicate opaque directory: {s}");
        }
        result.push(s);
    }
    Ok(result)
}

/// Set the `trusted.overlay.opaque` extended attribute on a directory.
fn set_opaque_xattr(path: &Path) -> Result<()> {
    let c_path = CString::new(path.as_os_str().as_encoded_bytes())
        .context("path contains null byte")?;
    let c_name = CString::new("trusted.overlay.opaque").unwrap();
    let value = b"y";
    let ret = unsafe {
        libc::lsetxattr(
            c_path.as_ptr(),
            c_name.as_ptr(),
            value.as_ptr() as *const libc::c_void,
            value.len(),
            0,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error())
            .context("lsetxattr failed");
    }
    Ok(())
}

fn check_conflicts(datadir: &Path, name: &str) -> Result<()> {
    let container_dir = datadir.join("containers").join(name);
    if container_dir.exists() {
        bail!("container already exists: {name}");
    }
    let state_file = datadir.join("state").join(name);
    if state_file.exists() {
        bail!("state file already exists for: {name}");
    }
    let machines_dir = Path::new("/var/lib/machines").join(name);
    if machines_dir.exists() {
        bail!("conflicting machine found in /var/lib/machines: {name}");
    }
    Ok(())
}

// NOTE: "rootfs" is the internal name; the CLI command is "fs" and the
// on-disk path is {datadir}/fs/.
fn resolve_rootfs(datadir: &Path, rootfs: Option<&str>) -> Result<PathBuf> {
    match rootfs {
        None => Ok(PathBuf::from("/")),
        Some(name) => {
            validate_name(name)
                .context("invalid rootfs name")?;
            let path = datadir.join("fs").join(name);
            if !path.exists() {
                bail!("fs not found: {}", path.display());
            }
            Ok(path)
        }
    }
}

/// Resolve a (possibly abbreviated) container name to the full name.
///
/// Exact matches take priority. If `input` is not an exact match, all
/// container names that start with `input` are collected. A single match
/// is returned; zero or multiple matches produce an error.
pub fn resolve_name(datadir: &Path, input: &str) -> Result<String> {
    if input.is_empty() {
        bail!("container name must not be empty");
    }
    let state_dir = datadir.join("state");
    if !state_dir.is_dir() {
        bail!("no container found matching '{input}'");
    }
    let mut names: Vec<String> = Vec::new();
    for entry in fs::read_dir(&state_dir)
        .with_context(|| format!("failed to read {}", state_dir.display()))?
    {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            if let Some(name) = entry.file_name().to_str() {
                names.push(name.to_string());
            }
        }
    }
    // Exact match — return immediately.
    if names.iter().any(|n| n == input) {
        return Ok(input.to_string());
    }
    let mut matches: Vec<&String> = names.iter().filter(|n| n.starts_with(input)).collect();
    match matches.len() {
        0 => bail!("no container found matching '{input}'"),
        1 => Ok(matches.remove(0).clone()),
        _ => {
            matches.sort();
            let list = matches.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ");
            bail!("ambiguous name '{input}', could match: {list}");
        }
    }
}

pub fn ensure_exists(datadir: &Path, name: &str) -> Result<()> {
    let state_file = datadir.join("state").join(name);
    if !state_file.exists() {
        bail!("container does not exist: {name}");
    }
    let container_dir = datadir.join("containers").join(name);
    if !container_dir.exists() {
        bail!("container '{name}' state file exists but directory is missing");
    }
    Ok(())
}

/// Fix directory permissions on containers created before the 0o755 fix.
///
/// Called from `systemd::start()` before writing the env file so that
/// old containers work without requiring manual intervention or recreation.
pub fn ensure_permissions(datadir: &Path, name: &str) -> Result<()> {
    let container_dir = datadir.join("containers").join(name);
    for (sub, mode) in &[("upper", 0o755), ("merged", 0o755), ("shared", 0o755)] {
        let dir = container_dir.join(sub);
        if dir.exists() {
            set_dir_permissions(&dir, *mode)?;
        }
    }
    Ok(())
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs()
}

fn set_dir_permissions(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("failed to set permissions on {}", path.display()))
}

/// Mask host-specific .mount and .swap units from `/etc/systemd/system/`
/// by creating `/dev/null` symlinks in the overlayfs upper layer.
///
/// Scans the host's `/etc/systemd/system/` for regular files ending in
/// `.mount`, `.swap`, or `.automount` and masks each one. Masking a unit
/// makes systemd skip it even if it appears in a target's Wants/Requires.
fn mask_host_mount_units(upper_systemd_dir: &Path, verbose: bool) -> Result<()> {
    let host_dir = Path::new("/etc/systemd/system");
    if !host_dir.is_dir() {
        return Ok(());
    }
    let entries = fs::read_dir(host_dir)
        .with_context(|| format!("failed to read {}", host_dir.display()))?;
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = match name.to_str() {
            Some(s) => s,
            None => continue,
        };
        // Only mask mount/swap/automount unit files (not symlinks or directories).
        let dominated = name_str.ends_with(".mount")
            || name_str.ends_with(".swap")
            || name_str.ends_with(".automount");
        if !dominated {
            continue;
        }
        let ft = entry.file_type()?;
        if !ft.is_file() {
            continue;
        }
        let mask_path = upper_systemd_dir.join(name_str);
        symlink("/dev/null", &mask_path)
            .with_context(|| format!("failed to mask {name_str}"))?;
        if verbose {
            eprintln!("masked host unit: {name_str}");
        }
    }
    Ok(())
}

pub fn remove(datadir: &Path, name: &str, verbose: bool) -> Result<()> {
    ensure_exists(datadir, name)?;

    if systemd::is_active(name)? {
        if verbose {
            eprintln!("stopping container '{name}'");
        }
        stop(name, verbose)?;
    }

    let container_dir = datadir.join("containers").join(name);
    if container_dir.exists() {
        fs::remove_dir_all(&container_dir)
            .with_context(|| format!("failed to remove {}", container_dir.display()))?;
        if verbose {
            eprintln!("removed {}", container_dir.display());
        }
    }

    let state_file = datadir.join("state").join(name);
    if state_file.exists() {
        fs::remove_file(&state_file)
            .with_context(|| format!("failed to remove {}", state_file.display()))?;
        if verbose {
            eprintln!("removed {}", state_file.display());
        }
    }

    systemd::remove_limits_dropin(name, verbose)?;

    Ok(())
}

pub struct ContainerInfo {
    pub name: String,
    pub status: String,
    pub health: String,
    pub os: String,
    pub shared: PathBuf,
}

pub fn list(datadir: &Path) -> Result<Vec<ContainerInfo>> {
    let state_dir = datadir.join("state");
    if !state_dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut entries: Vec<String> = Vec::new();
    for entry in fs::read_dir(&state_dir)
        .with_context(|| format!("failed to read {}", state_dir.display()))?
    {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            if let Some(name) = entry.file_name().to_str() {
                entries.push(name.to_string());
            }
        }
    }
    entries.sort();

    let mut result = Vec::new();
    for name in &entries {
        let container_dir = datadir.join("containers").join(name);
        let shared = container_dir.join("shared");

        // Health checks.
        let mut problems = Vec::new();
        if !container_dir.exists() {
            problems.push("missing container dir");
        }
        let state_path = state_dir.join(name);
        let state = State::read_from(&state_path);
        match &state {
            Ok(s) => {
                let rootfs_name = s.rootfs();
                if !rootfs_name.is_empty() && !datadir.join("fs").join(rootfs_name).exists() {
                    problems.push("missing fs");
                }
            }
            Err(_) => {
                problems.push("unreadable state file");
            }
        }

        let health = if problems.is_empty() {
            "ok".to_string()
        } else {
            problems.join(", ")
        };

        // OS detection from rootfs.
        let os = match &state {
            Ok(s) => {
                let rootfs_name = s.rootfs();
                if rootfs_name.is_empty() {
                    String::new()
                } else {
                    let rootfs_path = datadir.join("fs").join(rootfs_name);
                    rootfs::detect_distro(&rootfs_path)
                }
            }
            Err(_) => String::new(),
        };

        // Status (running/stopped).
        let status = if container_dir.exists() {
            match systemd::is_active(name) {
                Ok(true) => "running",
                _ => "stopped",
            }
        } else {
            "stopped"
        };

        result.push(ContainerInfo {
            name: name.clone(),
            status: status.to_string(),
            health,
            os,
            shared,
        });
    }
    Ok(result)
}

pub fn join(
    datadir: &Path,
    name: &str,
    command: &[String],
    join_as_sudo_user: bool,
    verbose: bool,
) -> Result<()> {
    ensure_exists(datadir, name)?;

    if !systemd::is_active(name)? {
        bail!("container '{name}' is not running");
    }

    machinectl_shell(datadir, name, command, join_as_sudo_user, verbose)
}

pub fn exec(
    datadir: &Path,
    name: &str,
    command: &[String],
    join_as_sudo_user: bool,
    verbose: bool,
) -> Result<()> {
    ensure_exists(datadir, name)?;

    if !systemd::is_active(name)? {
        bail!("container '{name}' is not running");
    }

    machinectl_shell(datadir, name, command, join_as_sudo_user, verbose)
}

fn machinectl_shell(
    datadir: &Path,
    name: &str,
    command: &[String],
    join_as_sudo_user: bool,
    verbose: bool,
) -> Result<()> {
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
                        eprintln!("host rootfs container: joining as user '{}' with opaque dirs {dirs}", su.name);
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
        eprintln!("exec: machinectl {}",
            cmd.get_args()
                .map(|a| a.to_string_lossy())
                .collect::<Vec<_>>()
                .join(" ")
        );
    }
    let err = cmd.exec();
    bail!("failed to exec machinectl: {err}");
}

/// Update resource limits on an existing container.
///
/// Reads the current state file, merges the new limits, writes it back,
/// and regenerates the systemd drop-in. If the container is running,
/// prints a note that a restart is needed.
pub fn set_limits(datadir: &Path, name: &str, limits: &ResourceLimits, verbose: bool) -> Result<()> {
    ensure_exists(datadir, name)?;

    let state_path = datadir.join("state").join(name);
    let mut state = State::read_from(&state_path)?;
    limits.write_to_state(&mut state);
    state.write_to(&state_path)?;

    if verbose {
        eprintln!("updated state file: {}", state_path.display());
    }

    systemd::write_limits_dropin(name, limits, verbose)?;

    if systemd::is_active(name)? {
        eprintln!("note: container '{name}' is running; restart for limits to take effect");
    }

    Ok(())
}

pub fn stop(name: &str, verbose: bool) -> Result<()> {
    if verbose {
        eprintln!("terminating machine '{name}'");
    }
    systemd::terminate_machine(name)?;
    systemd::wait_for_shutdown(name, std::time::Duration::from_secs(30), verbose)
}



#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDataDir;

    fn tmp() -> TempDataDir {
        TempDataDir::new("containers")
    }

    #[test]
    fn test_validate_name_ok() {
        assert!(validate_name("mycontainer").is_ok());
        assert!(validate_name("test123").is_ok());
        assert!(validate_name("a").is_ok());
        assert!(validate_name("my-container").is_ok());
    }

    #[test]
    fn test_validate_name_invalid() {
        assert!(validate_name("").is_err());
        assert!(validate_name("MyContainer").is_err());
        assert!(validate_name("has space").is_err());
        assert!(validate_name("1startsdigit").is_err());
        assert!(validate_name("-startshyphen").is_err());
    }

    #[test]
    fn test_state_roundtrip() {
        let mut state = State::new();
        state.set("NAME", "test");
        state.set("CREATED", "1234567890");
        state.set("ROOTFS", "");

        let serialized = state.serialize();
        let parsed = State::parse(&serialized).unwrap();

        assert_eq!(parsed.get("NAME"), Some("test"));
        assert_eq!(parsed.get("CREATED"), Some("1234567890"));
        assert_eq!(parsed.get("ROOTFS"), Some(""));
    }

    #[test]
    fn test_state_parse_value_with_equals() {
        let content = "KEY=val=ue\n";
        let state = State::parse(content).unwrap();
        assert_eq!(state.get("KEY"), Some("val=ue"));
    }

    #[test]
    fn test_create_default() {
        let tmp = tmp();
        let opts = CreateOptions {
            name: None,
            rootfs: None,
            limits: Default::default(),
            network: Default::default(),
            opaque_dirs: vec![],
            binds: Default::default(),
            envs: Default::default(),
        };
        let name = create(tmp.path(), &opts, false).unwrap();
        assert!(validate_name(&name).is_ok());

        // Verify directories.
        let container_dir = tmp.path().join("containers").join(&name);
        assert!(container_dir.join("upper").is_dir());
        assert!(container_dir.join("work").is_dir());
        assert!(container_dir.join("merged").is_dir());
        assert!(container_dir.join("shared").is_dir());

        // Verify hostname.
        let hostname = fs::read_to_string(container_dir.join("upper/etc/hostname")).unwrap();
        assert_eq!(hostname, format!("{name}\n"));

        // Verify hosts.
        let hosts = fs::read_to_string(container_dir.join("upper/etc/hosts")).unwrap();
        assert_eq!(hosts, format!("127.0.0.1 localhost {name}\n::1 localhost\n"));

        // Verify state file.
        let state = State::read_from(&tmp.path().join("state").join(&name)).unwrap();
        assert_eq!(state.get("NAME"), Some(name.as_str()));
        assert_eq!(state.get("ROOTFS"), Some(""));
        assert!(state.get("CREATED").is_some());
    }

    #[test]
    fn test_create_with_name() {
        let tmp = tmp();
        let opts = CreateOptions {
            name: Some("hello".to_string()),
            rootfs: None,
            limits: Default::default(),
            network: Default::default(),
            opaque_dirs: vec![],
            binds: Default::default(),
            envs: Default::default(),
        };
        let name = create(tmp.path(), &opts, false).unwrap();
        assert_eq!(name, "hello");

        let hostname = fs::read_to_string(
            tmp.path()
                .join("containers/hello/upper/etc/hostname"),
        )
        .unwrap();
        assert_eq!(hostname, "hello\n");

        let hosts = fs::read_to_string(
            tmp.path()
                .join("containers/hello/upper/etc/hosts"),
        )
        .unwrap();
        assert_eq!(hosts, "127.0.0.1 localhost hello\n::1 localhost\n");

        let state = State::read_from(&tmp.path().join("state/hello")).unwrap();
        assert_eq!(state.get("NAME"), Some("hello"));
    }

    #[test]
    fn test_create_duplicate_name() {
        let tmp = tmp();
        let opts = CreateOptions {
            name: Some("dup".to_string()),
            rootfs: None,
            limits: Default::default(),
            network: Default::default(),
            opaque_dirs: vec![],
            binds: Default::default(),
            envs: Default::default(),
        };
        create(tmp.path(), &opts, false).unwrap();
        let err = create(tmp.path(), &opts, false).unwrap_err();
        assert!(
            err.to_string().contains("already exists"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_create_with_rootfs_missing() {
        let tmp = tmp();
        let opts = CreateOptions {
            name: Some("test".to_string()),
            rootfs: Some("nonexistent".to_string()),
            limits: Default::default(),
            network: Default::default(),
            opaque_dirs: vec![],
            binds: Default::default(),
            envs: Default::default(),
        };
        let err = create(tmp.path(), &opts, false).unwrap_err();
        assert!(
            err.to_string().contains("fs not found"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_create_with_rootfs_exists() {
        let tmp = tmp();
        let rootfs_dir = tmp.path().join("fs/myroot");
        fs::create_dir_all(&rootfs_dir).unwrap();

        let opts = CreateOptions {
            name: Some("test".to_string()),
            rootfs: Some("myroot".to_string()),
            limits: Default::default(),
            network: Default::default(),
            opaque_dirs: vec![],
            binds: Default::default(),
            envs: Default::default(),
        };
        let name = create(tmp.path(), &opts, false).unwrap();
        assert_eq!(name, "test");

        let state = State::read_from(&tmp.path().join("state/test")).unwrap();
        assert_eq!(state.get("ROOTFS"), Some("myroot"));
    }

    #[test]
    fn test_create_cleanup_on_failure() {
        let tmp = tmp();
        // Block state dir by placing a file where the directory should be created.
        let state_path = tmp.path().join("state");
        fs::write(&state_path, "blocker").unwrap();

        let opts = CreateOptions {
            name: Some("fail".to_string()),
            rootfs: None,
            limits: Default::default(),
            network: Default::default(),
            opaque_dirs: vec![],
            binds: Default::default(),
            envs: Default::default(),
        };
        let err = create(tmp.path(), &opts, false);
        assert!(err.is_err());

        // Container dir should have been cleaned up.
        assert!(!tmp.path().join("containers/fail").exists());
    }

    #[test]
    fn test_ensure_exists_ok() {
        let tmp = tmp();
        let opts = CreateOptions {
            name: Some("mybox".to_string()),
            rootfs: None,
            limits: Default::default(),
            network: Default::default(),
            opaque_dirs: vec![],
            binds: Default::default(),
            envs: Default::default(),
        };
        create(tmp.path(), &opts, false).unwrap();
        assert!(ensure_exists(tmp.path(), "mybox").is_ok());
    }

    #[test]
    fn test_ensure_exists_missing() {
        let tmp = tmp();
        let err = ensure_exists(tmp.path(), "nonexistent").unwrap_err();
        assert!(
            err.to_string().contains("does not exist"),
            "unexpected error: {err}"
        );
    }

    fn create_dummy_container(tmp: &TempDataDir, name: &str) {
        let state_dir = tmp.path().join("state");
        fs::create_dir_all(&state_dir).unwrap();
        fs::write(state_dir.join(name), format!("NAME={name}\n")).unwrap();
        let container_dir = tmp.path().join("containers").join(name);
        fs::create_dir_all(container_dir.join("upper")).unwrap();
        fs::create_dir_all(container_dir.join("work")).unwrap();
        fs::create_dir_all(container_dir.join("merged")).unwrap();
        fs::create_dir_all(container_dir.join("shared")).unwrap();
    }

    #[test]
    fn test_resolve_name_exact_match() {
        let tmp = tmp();
        create_dummy_container(&tmp, "foo");
        create_dummy_container(&tmp, "foobar");
        assert_eq!(resolve_name(tmp.path(), "foo").unwrap(), "foo");
    }

    #[test]
    fn test_resolve_name_unique_prefix() {
        let tmp = tmp();
        create_dummy_container(&tmp, "ubuntu-dev");
        assert_eq!(resolve_name(tmp.path(), "ub").unwrap(), "ubuntu-dev");
    }

    #[test]
    fn test_resolve_name_ambiguous() {
        let tmp = tmp();
        create_dummy_container(&tmp, "ubuntu-dev");
        create_dummy_container(&tmp, "ubuntu-prod");
        let err = resolve_name(tmp.path(), "ub").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("ambiguous"), "unexpected error: {msg}");
        assert!(msg.contains("ubuntu-dev"), "unexpected error: {msg}");
        assert!(msg.contains("ubuntu-prod"), "unexpected error: {msg}");
    }

    #[test]
    fn test_resolve_name_no_match() {
        let tmp = tmp();
        create_dummy_container(&tmp, "foo");
        let err = resolve_name(tmp.path(), "xyz").unwrap_err();
        assert!(err.to_string().contains("no container found"), "unexpected error: {err}");
    }

    #[test]
    fn test_resolve_name_empty() {
        let tmp = tmp();
        let err = resolve_name(tmp.path(), "").unwrap_err();
        assert!(err.to_string().contains("must not be empty"), "unexpected error: {err}");
    }

    #[test]
    fn test_ensure_exists_orphan_state() {
        let tmp = tmp();
        let state_dir = tmp.path().join("state");
        fs::create_dir_all(&state_dir).unwrap();
        fs::write(state_dir.join("orphan"), "NAME=orphan\n").unwrap();

        let err = ensure_exists(tmp.path(), "orphan").unwrap_err();
        assert!(
            err.to_string().contains("directory is missing"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_create_with_limits() {
        let tmp = tmp();
        let limits = crate::ResourceLimits {
            memory: Some("2G".to_string()),
            cpus: Some("4".to_string()),
            cpu_weight: None,
        };
        let opts = CreateOptions {
            name: Some("limited".to_string()),
            rootfs: None,
            limits,
            network: Default::default(),
            opaque_dirs: vec![],
            binds: Default::default(),
            envs: Default::default(),
        };
        let name = create(tmp.path(), &opts, false).unwrap();
        assert_eq!(name, "limited");

        let state = State::read_from(&tmp.path().join("state/limited")).unwrap();
        assert_eq!(state.get("MEMORY"), Some("2G"));
        assert_eq!(state.get("CPUS"), Some("4"));
        assert_eq!(state.get("CPU_WEIGHT"), None);
    }

    #[test]
    fn test_create_rejects_restrictive_umask() {
        // Set a restrictive umask, attempt create, then restore.
        let old = unsafe { libc::umask(0o077) };
        let tmp = tmp();
        let opts = CreateOptions {
            name: Some("umasktest".to_string()),
            rootfs: None,
            limits: Default::default(),
            network: Default::default(),
            opaque_dirs: vec![],
            binds: Default::default(),
            envs: Default::default(),
        };
        let err = create(tmp.path(), &opts, false);
        unsafe { libc::umask(old) };

        let err = err.unwrap_err();
        assert!(
            err.to_string().contains("umask"),
            "unexpected error: {err}"
        );
    }

    // --- validate_opaque_dirs tests ---

    #[test]
    fn test_validate_opaque_dirs_ok() {
        let dirs = vec!["/var".to_string(), "/opt".to_string(), "/tmp".to_string()];
        let result = validate_opaque_dirs(&dirs).unwrap();
        assert_eq!(result, vec!["/var", "/opt", "/tmp"]);
    }

    #[test]
    fn test_validate_opaque_dirs_rejects_relative() {
        let dirs = vec!["var/log".to_string()];
        let err = validate_opaque_dirs(&dirs).unwrap_err();
        assert!(err.to_string().contains("absolute"), "unexpected error: {err}");
    }

    #[test]
    fn test_validate_opaque_dirs_rejects_dotdot() {
        let dirs = vec!["/var/../etc".to_string()];
        let err = validate_opaque_dirs(&dirs).unwrap_err();
        assert!(err.to_string().contains(".."), "unexpected error: {err}");
    }

    #[test]
    fn test_validate_opaque_dirs_normalizes() {
        let dirs = vec!["/var/".to_string(), "/opt///".to_string()];
        let result = validate_opaque_dirs(&dirs).unwrap();
        assert_eq!(result, vec!["/var", "/opt"]);
    }

    #[test]
    fn test_validate_opaque_dirs_rejects_duplicates() {
        let dirs = vec!["/var".to_string(), "/var/".to_string()];
        let err = validate_opaque_dirs(&dirs).unwrap_err();
        assert!(err.to_string().contains("duplicate"), "unexpected error: {err}");
    }

    #[test]
    fn test_validate_opaque_dirs_rejects_empty() {
        let dirs = vec!["".to_string()];
        let err = validate_opaque_dirs(&dirs).unwrap_err();
        assert!(err.to_string().contains("empty"), "unexpected error: {err}");
    }

    #[test]
    fn test_validate_opaque_dirs_empty_list_ok() {
        let dirs: Vec<String> = vec![];
        let result = validate_opaque_dirs(&dirs).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_create_with_opaque_dirs() {
        // Setting trusted.* xattrs requires root; skip if not root.
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skipping test_create_with_opaque_dirs: requires root");
            return;
        }
        let tmp = tmp();
        let opts = CreateOptions {
            name: Some("opaquebox".to_string()),
            rootfs: None,
            limits: Default::default(),
            network: Default::default(),
            opaque_dirs: vec!["/var".to_string(), "/opt/data".to_string()],
            binds: Default::default(),
            envs: Default::default(),
        };
        let name = create(tmp.path(), &opts, false).unwrap();
        assert_eq!(name, "opaquebox");

        // Verify directories were created in the upper layer.
        let upper = tmp.path().join("containers/opaquebox/upper");
        assert!(upper.join("var").is_dir());
        assert!(upper.join("opt/data").is_dir());

        // Verify the trusted.overlay.opaque xattr is set.
        for dir in &["var", "opt/data"] {
            let path = upper.join(dir);
            let c_path = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
            let c_name = CString::new("trusted.overlay.opaque").unwrap();
            let mut buf = [0u8; 16];
            let size = unsafe {
                libc::lgetxattr(
                    c_path.as_ptr(),
                    c_name.as_ptr(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                )
            };
            assert!(size > 0, "lgetxattr failed for {}", path.display());
            assert_eq!(&buf[..size as usize], b"y", "xattr value mismatch for {dir}");
        }
    }

    #[test]
    fn test_create_opaque_dirs_state() {
        // Setting trusted.* xattrs requires root; skip if not root.
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skipping test_create_opaque_dirs_state: requires root");
            return;
        }
        let tmp = tmp();
        let opts = CreateOptions {
            name: Some("statebox".to_string()),
            rootfs: None,
            limits: Default::default(),
            network: Default::default(),
            opaque_dirs: vec!["/var".to_string(), "/opt".to_string()],
            binds: Default::default(),
            envs: Default::default(),
        };
        create(tmp.path(), &opts, false).unwrap();

        let state = State::read_from(&tmp.path().join("state/statebox")).unwrap();
        assert_eq!(state.get("OPAQUE_DIRS"), Some("/var,/opt"));
    }
}
