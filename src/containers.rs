//! Internal API for container filesystem, state, and runtime management.
//!
//! Each container gets an overlayfs directory tree (`upper/work/merged/shared`)
//! under the configured data directory and a KEY=VALUE state file that tracks
//! its metadata. All mutating operations follow a transaction-style pattern:
//! work is performed step-by-step and, on failure, partially-created artifacts
//! are cleaned up before the error is returned. New implementations and changes
//! should conform to this pattern.

use std::fs::{self, OpenOptions};
use std::os::unix::fs::{OpenOptionsExt, symlink};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};

use crate::{State, names, rootfs, systemd, validate_name};

pub struct CreateOptions {
    pub name: Option<String>,
    pub rootfs: Option<String>,
}

pub fn create(datadir: &Path, opts: &CreateOptions, verbose: bool) -> Result<String> {
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

    match do_create(datadir, &name, &rootfs, verbose) {
        Ok(()) => Ok(name),
        Err(e) => {
            let container_dir = datadir.join("containers").join(&name);
            let _ = fs::remove_dir_all(&container_dir);
            let _ = fs::remove_file(&state_path);
            Err(e)
        }
    }
}

fn do_create(datadir: &Path, name: &str, rootfs: &Path, verbose: bool) -> Result<()> {
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

    if verbose {
        eprintln!("wrote hostname, hosts, and resolv.conf files; masked systemd-resolved");
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

    // State file was already created atomically by create(); write content to it.
    let state_path = datadir.join("state").join(name);
    state.write_to(&state_path)?;

    if verbose {
        eprintln!("wrote state file: {}", state_path.display());
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
                let rootfs_name = s.get("ROOTFS").unwrap_or("");
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
                let rootfs_name = s.get("ROOTFS").unwrap_or("");
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
                    if verbose {
                        eprintln!("host rootfs container: joining as user '{}'", su.name);
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

    struct TempDataDir {
        dir: PathBuf,
    }

    impl TempDataDir {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "sdme-test-containers-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            Self { dir }
        }

        fn path(&self) -> &Path {
            &self.dir
        }
    }

    impl Drop for TempDataDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
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
        let tmp = TempDataDir::new();
        let opts = CreateOptions {
            name: None,
            rootfs: None,
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
        let tmp = TempDataDir::new();
        let opts = CreateOptions {
            name: Some("hello".to_string()),
            rootfs: None,
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
        let tmp = TempDataDir::new();
        let opts = CreateOptions {
            name: Some("dup".to_string()),
            rootfs: None,
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
        let tmp = TempDataDir::new();
        let opts = CreateOptions {
            name: Some("test".to_string()),
            rootfs: Some("nonexistent".to_string()),
        };
        let err = create(tmp.path(), &opts, false).unwrap_err();
        assert!(
            err.to_string().contains("fs not found"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_create_with_rootfs_exists() {
        let tmp = TempDataDir::new();
        let rootfs_dir = tmp.path().join("fs/myroot");
        fs::create_dir_all(&rootfs_dir).unwrap();

        let opts = CreateOptions {
            name: Some("test".to_string()),
            rootfs: Some("myroot".to_string()),
        };
        let name = create(tmp.path(), &opts, false).unwrap();
        assert_eq!(name, "test");

        let state = State::read_from(&tmp.path().join("state/test")).unwrap();
        assert_eq!(state.get("ROOTFS"), Some("myroot"));
    }

    #[test]
    fn test_create_cleanup_on_failure() {
        let tmp = TempDataDir::new();
        // Block state dir by placing a file where the directory should be created.
        let state_path = tmp.path().join("state");
        fs::write(&state_path, "blocker").unwrap();

        let opts = CreateOptions {
            name: Some("fail".to_string()),
            rootfs: None,
        };
        let err = create(tmp.path(), &opts, false);
        assert!(err.is_err());

        // Container dir should have been cleaned up.
        assert!(!tmp.path().join("containers/fail").exists());
    }

    #[test]
    fn test_ensure_exists_ok() {
        let tmp = TempDataDir::new();
        let opts = CreateOptions {
            name: Some("mybox".to_string()),
            rootfs: None,
        };
        create(tmp.path(), &opts, false).unwrap();
        assert!(ensure_exists(tmp.path(), "mybox").is_ok());
    }

    #[test]
    fn test_ensure_exists_missing() {
        let tmp = TempDataDir::new();
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
        let tmp = TempDataDir::new();
        create_dummy_container(&tmp, "foo");
        create_dummy_container(&tmp, "foobar");
        assert_eq!(resolve_name(tmp.path(), "foo").unwrap(), "foo");
    }

    #[test]
    fn test_resolve_name_unique_prefix() {
        let tmp = TempDataDir::new();
        create_dummy_container(&tmp, "ubuntu-dev");
        assert_eq!(resolve_name(tmp.path(), "ub").unwrap(), "ubuntu-dev");
    }

    #[test]
    fn test_resolve_name_ambiguous() {
        let tmp = TempDataDir::new();
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
        let tmp = TempDataDir::new();
        create_dummy_container(&tmp, "foo");
        let err = resolve_name(tmp.path(), "xyz").unwrap_err();
        assert!(err.to_string().contains("no container found"), "unexpected error: {err}");
    }

    #[test]
    fn test_resolve_name_empty() {
        let tmp = TempDataDir::new();
        let err = resolve_name(tmp.path(), "").unwrap_err();
        assert!(err.to_string().contains("must not be empty"), "unexpected error: {err}");
    }

    #[test]
    fn test_ensure_exists_orphan_state() {
        let tmp = TempDataDir::new();
        let state_dir = tmp.path().join("state");
        fs::create_dir_all(&state_dir).unwrap();
        fs::write(state_dir.join("orphan"), "NAME=orphan\n").unwrap();

        let err = ensure_exists(tmp.path(), "orphan").unwrap_err();
        assert!(
            err.to_string().contains("directory is missing"),
            "unexpected error: {err}"
        );
    }
}
