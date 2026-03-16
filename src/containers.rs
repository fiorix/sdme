//! Internal API for container filesystem, state, and runtime management.
//!
//! Each container gets an overlayfs directory tree (`upper/work/merged`)
//! under the configured data directory and a KEY=VALUE state file that tracks
//! its metadata. All mutating operations follow a transaction-style pattern:
//! work is performed step-by-step and, on failure, partially-created artifacts
//! are cleaned up before the error is returned. New implementations and changes
//! should conform to this pattern.

use std::ffi::CString;
use std::fs::{self, OpenOptions};
use std::os::unix::fs::{symlink, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::ExitStatus;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};

use crate::{
    names, rootfs, systemd, validate_name, BindConfig, EnvConfig, NetworkConfig, ResourceLimits,
    SecurityConfig, State,
};

/// Options for creating a new container.
#[derive(Default)]
pub struct CreateOptions {
    /// Container name; auto-generated if `None`.
    pub name: Option<String>,
    /// Imported rootfs name; `None` means host rootfs.
    pub rootfs: Option<String>,
    /// Resource limits (memory, CPU).
    pub limits: ResourceLimits,
    /// Network configuration (private network, ports).
    pub network: NetworkConfig,
    /// Directories to mark as overlayfs opaque.
    pub opaque_dirs: Vec<String>,
    /// Pod to join (shared network namespace via nspawn flag).
    pub pod: Option<String>,
    /// Pod to join (OCI app service only, via inner netns).
    pub oci_pod: Option<String>,
    /// Bind mount configuration.
    pub binds: BindConfig,
    /// Environment variable configuration.
    pub envs: EnvConfig,
    /// Security hardening configuration.
    pub security: SecurityConfig,
    /// OCI volume mount paths from the image.
    pub oci_volumes: Vec<String>,
    /// OCI environment variables from the image.
    pub oci_envs: Vec<String>,
}

/// Read the current process umask. There is no "get umask" syscall, so
/// we set it to 0, read the old value, and restore it immediately.
fn get_umask() -> u32 {
    let old = unsafe { libc::umask(0) };
    unsafe { libc::umask(old) };
    old as u32
}

/// Create a new container with the given options, returning its name.
pub fn create(datadir: &Path, opts: &CreateOptions, verbose: bool) -> Result<String> {
    let umask = get_umask();
    if umask & 0o005 != 0 {
        bail!(
            "current umask ({:04o}) strips read/execute from 'other', which would \
             prevent services inside the container from accessing the filesystem. \
             Set a more permissive umask (e.g. umask 022) before running this command.",
            umask
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

fn do_create(
    datadir: &Path,
    name: &str,
    rootfs: &Path,
    opts: &CreateOptions,
    opaque_dirs: &[String],
    verbose: bool,
) -> Result<()> {
    let container_dir = datadir.join("containers").join(name);
    let containers_dir = datadir.join("containers");
    fs::create_dir_all(&containers_dir)
        .with_context(|| format!("failed to create {}", containers_dir.display()))?;
    set_dir_permissions(&containers_dir, 0o700)?;

    // The upper directory becomes the root of the overlayfs merged view, so it
    // must be world-readable (0o755); otherwise non-root services inside the
    // container (e.g. dbus-daemon running as messagebus) cannot traverse the
    // filesystem. The merged mount point also needs 0o755. The work directory
    // is overlayfs-internal and can stay restricted.
    for (sub, mode) in &[("upper", 0o755), ("work", 0o700), ("merged", 0o755)] {
        let dir = container_dir.join(sub);
        fs::create_dir_all(&dir).with_context(|| format!("failed to create {}", dir.display()))?;
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
        format!("127.0.0.1 localhost {name}\n::1 localhost {name}\n"),
    )
    .with_context(|| format!("failed to write {}", hosts_path.display()))?;

    let systemd_unit_dir = etc_dir.join("systemd").join("system");
    fs::create_dir_all(&systemd_unit_dir)
        .with_context(|| format!("failed to create {}", systemd_unit_dir.display()))?;

    // For host-rootfs containers, mask host-specific .mount and .swap
    // units from /etc/systemd/system/ so they don't leak through overlayfs.
    // These units reference block devices and paths (e.g. /data) that don't
    // exist inside the container, causing "Failed to isolate default target"
    // when systemd can't resolve their dependencies at boot.
    //
    // Also mask systemd-resolved: when a container shares the host's network
    // namespace (the default), the container's resolved cannot bind 127.0.0.53
    // (already owned by the host) and ends up with no upstream DNS servers.
    // Masking makes NSS skip the resolve module and fall through to "dns",
    // which queries the host's resolver via /etc/resolv.conf.
    //
    // For imported rootfs these patches are applied at import time
    // (see import/mod.rs::patch_rootfs_services).
    if rootfs == Path::new("/") {
        mask_host_mount_units(&systemd_unit_dir, verbose)?;

        let resolved_mask = systemd_unit_dir.join("systemd-resolved.service");
        symlink("/dev/null", &resolved_mask).with_context(|| {
            format!(
                "failed to mask systemd-resolved at {}",
                resolved_mask.display()
            )
        })?;
    }

    // When /etc/systemd/system is opaque, the dbus.service alias from the
    // lower layer is hidden. dbus.service is typically a symlink to the
    // actual D-Bus implementation (dbus-broker.service or dbus-daemon.service).
    // Without it, dbus.socket has no service to activate, D-Bus never starts,
    // logind crash-loops (it needs D-Bus), and dbus.socket hits its start
    // rate limit, leaving the container without a system bus.
    if opaque_dirs.iter().any(|d| d == "/etc/systemd/system") {
        let host_dbus = rootfs.join("etc/systemd/system/dbus.service");
        if let Ok(target) = fs::read_link(&host_dbus) {
            let upper_dbus = systemd_unit_dir.join("dbus.service");
            symlink(&target, &upper_dbus).with_context(|| {
                format!(
                    "failed to preserve dbus.service symlink at {}",
                    upper_dbus.display()
                )
            })?;
            if verbose {
                eprintln!("preserved dbus.service -> {}", target.display());
            }
        }
    }

    // Write a placeholder /etc/resolv.conf as a regular file so that
    // systemd-nspawn's --resolv-conf=auto can overwrite it with the host's
    // DNS configuration. Many rootfs images (e.g. Debian) ship resolv.conf as
    // a symlink to ../run/systemd/resolve/stub-resolv.conf; the auto mode's
    // copy variant won't overwrite a symlink, leaving DNS broken. A regular
    // file in the overlayfs upper layer shadows the lower layer's symlink.
    let resolv_path = etc_dir.join("resolv.conf");
    fs::write(
        &resolv_path,
        "# placeholder, replaced by systemd-nspawn at boot\n",
    )
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
    fs::write(
        &fstab_path,
        "# empty, host mounts not applicable in container\n",
    )
    .with_context(|| format!("failed to write {}", fstab_path.display()))?;

    // When --network-veth is used, enable systemd-networkd inside the
    // container so the container-side veth interface (host0) gets an IP
    // via DHCP from the host's networkd DHCP server.
    if opts.network.network_veth {
        let networkd_unit = rootfs.join("usr/lib/systemd/system/systemd-networkd.service");
        if networkd_unit.exists() {
            let wants_dir = systemd_unit_dir.join("multi-user.target.wants");
            fs::create_dir_all(&wants_dir)
                .with_context(|| format!("failed to create {}", wants_dir.display()))?;
            let link = wants_dir.join("systemd-networkd.service");
            if !link.exists() {
                symlink(
                    "/usr/lib/systemd/system/systemd-networkd.service",
                    &link,
                )
                .with_context(|| {
                    format!("failed to enable systemd-networkd at {}", link.display())
                })?;
                if verbose {
                    eprintln!("enabled systemd-networkd for --network-veth");
                }
            }
        }
    }

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

    // Auto-wire OCI volume bind mounts. For each declared volume, create
    // a host-side directory and add a bind entry unless the user already
    // supplied one targeting the same container path.
    let mut binds = opts.binds.clone();
    if !opts.oci_volumes.is_empty() {
        let oci_app = crate::oci::rootfs::detect_oci_app_name(rootfs);
        let vol_base = volumes_dir(datadir, name);
        let oci_app = oci_app.as_deref().with_context(|| {
            "OCI volumes require an OCI app rootfs (no /oci/apps/ directory found)"
        })?;
        for vol_path in &opts.oci_volumes {
            let container_path = format!("/oci/apps/{oci_app}/root{vol_path}");
            // Skip if user already binds to this container path.
            // Bind format is "host:container:mode".
            let already_bound = binds
                .binds
                .iter()
                .any(|b| b.split(':').nth(1).is_some_and(|cp| cp == container_path));
            if already_bound {
                continue;
            }
            let safe_name = crate::oci::rootfs::sanitize_volume_name(vol_path);
            let host_dir = vol_base.join(&safe_name);
            fs::create_dir_all(&host_dir)
                .with_context(|| format!("failed to create volume dir {}", host_dir.display()))?;
            fs::set_permissions(&host_dir, fs::Permissions::from_mode(0o755))
                .with_context(|| format!("failed to set permissions on {}", host_dir.display()))?;
            if verbose {
                eprintln!(
                    "created volume dir: {} -> {container_path}",
                    host_dir.display()
                );
            }
            binds
                .binds
                .push(format!("{}:{container_path}:rw", host_dir.display()));
        }
        state.set("OCI_VOLUMES", opts.oci_volumes.join(","));
    }
    binds.write_to_state(&mut state);
    opts.envs.write_to_state(&mut state);
    if let Some(pod) = &opts.pod {
        state.set("POD", pod.as_str());
    }
    if let Some(pod) = &opts.oci_pod {
        state.set("OCI_POD", pod.as_str());

        // Write a systemd drop-in inside the overlayfs upper layer so the
        // OCI app service runs in the pod's network namespace.
        // At start time, the pod's netns is bind-mounted into the container
        // at /run/sdme/oci-pod-netns via --bind-ro=.
        let app_names = crate::oci::rootfs::detect_all_oci_app_names(rootfs);
        let app_names = if app_names.is_empty() {
            vec!["app".to_string()]
        } else {
            app_names
        };
        for oci_app_name in &app_names {
            let dropin_dir = container_dir.join(format!(
                "upper/etc/systemd/system/sdme-oci-{oci_app_name}.service.d"
            ));
            fs::create_dir_all(&dropin_dir)
                .with_context(|| format!("failed to create {}", dropin_dir.display()))?;
            let dropin_path = dropin_dir.join("oci-pod-netns.conf");
            fs::write(
                &dropin_path,
                "[Service]\nNetworkNamespacePath=/run/sdme/oci-pod-netns\n",
            )
            .with_context(|| format!("failed to write {}", dropin_path.display()))?;
            if verbose {
                eprintln!("wrote oci-pod netns drop-in: {}", dropin_path.display());
            }
        }
    }
    // When the container's security config drops capabilities that appear in
    // the OCI service unit's default CapabilityBoundingSet, write a systemd
    // drop-in to adjust the bounding set. Without this, the inner service
    // claims capabilities the container doesn't have, which causes boot
    // failures on distros where systemd enforces the mismatch (e.g. SUSE).
    if !opts.security.drop_caps.is_empty() {
        let app_names = crate::oci::rootfs::detect_all_oci_app_names(rootfs);
        if !app_names.is_empty() {
            use std::collections::HashSet;

            use crate::security::OCI_DEFAULT_CAPS;

            let drop_set: HashSet<&str> =
                opts.security.drop_caps.iter().map(|s| s.as_str()).collect();
            let caps: Vec<&str> = OCI_DEFAULT_CAPS
                .iter()
                .copied()
                .filter(|c| !drop_set.contains(c))
                .collect();

            // Always keep CAP_SYS_ADMIN for the isolate binary.
            let mut caps_line = caps.join(" ");
            if !caps.contains(&"CAP_SYS_ADMIN") {
                caps_line.push_str(" CAP_SYS_ADMIN");
            }

            let dropin_content =
                format!("[Service]\nCapabilityBoundingSet=\nCapabilityBoundingSet={caps_line}\n");

            for oci_app_name in &app_names {
                let dropin_dir = container_dir.join(format!(
                    "upper/etc/systemd/system/sdme-oci-{oci_app_name}.service.d"
                ));
                fs::create_dir_all(&dropin_dir)
                    .with_context(|| format!("failed to create {}", dropin_dir.display()))?;
                let dropin_path = dropin_dir.join("hardening.conf");
                fs::write(&dropin_path, &dropin_content)
                    .with_context(|| format!("failed to write {}", dropin_path.display()))?;
                if verbose {
                    eprintln!("wrote security drop-in: {}", dropin_path.display());
                }
            }
        }
    }

    opts.security.write_to_state(&mut state);
    if !opaque_dirs.is_empty() {
        state.set("OPAQUE_DIRS", opaque_dirs.join(","));
    }

    // Write OCI env vars to the overlayfs upper layer. This copies the
    // lower layer's env file (if it exists) and appends the user-supplied
    // vars, so each container gets its own env file independent of the
    // shared rootfs.
    if !opts.oci_envs.is_empty() {
        let oci_app_for_env =
            crate::oci::rootfs::detect_oci_app_name(rootfs).with_context(|| {
                "--oci-env requires an OCI app rootfs (no /oci/apps/ directory found)"
            })?;
        let lower_env = rootfs.join(format!("oci/apps/{oci_app_for_env}/env"));
        if lower_env.exists() {
            let upper_oci = container_dir.join(format!("upper/oci/apps/{oci_app_for_env}"));
            fs::create_dir_all(&upper_oci)
                .with_context(|| format!("failed to create {}", upper_oci.display()))?;
            let upper_env = upper_oci.join("env");
            let mut content = fs::read_to_string(&lower_env)
                .with_context(|| format!("failed to read {}", lower_env.display()))?;
            for var in &opts.oci_envs {
                content.push_str(var);
                content.push('\n');
            }
            fs::write(&upper_env, &content)
                .with_context(|| format!("failed to write {}", upper_env.display()))?;
            if verbose {
                eprintln!(
                    "wrote {} OCI env var(s) to {}",
                    opts.oci_envs.len(),
                    upper_env.display()
                );
            }
        } else {
            bail!("--oci-env requires an OCI app rootfs (no env file found in rootfs)");
        }
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
    let c_path =
        CString::new(path.as_os_str().as_encoded_bytes()).context("path contains null byte")?;
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
        return Err(std::io::Error::last_os_error()).context("lsetxattr failed");
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

/// Resolve a rootfs name to its on-disk path; `None` means host rootfs.
// NOTE: "rootfs" is the internal name; the CLI command is "fs" and the
// on-disk path is {datadir}/fs/.
pub fn resolve_rootfs(datadir: &Path, rootfs: Option<&str>) -> Result<PathBuf> {
    match rootfs {
        None => Ok(PathBuf::from("/")),
        Some(name) => {
            validate_name(name).context("invalid rootfs name")?;
            let path = datadir.join("fs").join(name);
            if !path.exists() {
                bail!("fs not found: {}", path.display());
            }
            Ok(path)
        }
    }
}

/// Return the volume storage directory for a container.
pub fn volumes_dir(datadir: &Path, name: &str) -> PathBuf {
    datadir.join("volumes").join(name)
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
    // Exact match; return immediately.
    if names.iter().any(|n| n == input) {
        return Ok(input.to_string());
    }
    let mut matches: Vec<&String> = names.iter().filter(|n| n.starts_with(input)).collect();
    match matches.len() {
        0 => bail!("no container found matching '{input}'"),
        1 => Ok(matches.remove(0).clone()),
        _ => {
            matches.sort();
            let list = matches
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            bail!("ambiguous name '{input}', could match: {list}");
        }
    }
}

/// Verify that a container's state file and directory exist.
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
    for (sub, mode) in &[("upper", 0o755), ("merged", 0o755)] {
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
    let entries =
        fs::read_dir(host_dir).with_context(|| format!("failed to read {}", host_dir.display()))?;
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
        symlink("/dev/null", &mask_path).with_context(|| format!("failed to mask {name_str}"))?;
        if verbose {
            eprintln!("masked host unit: {name_str}");
        }
    }
    Ok(())
}

/// Stop a container if running, then delete its state file and overlayfs directories.
pub fn remove(datadir: &Path, name: &str, verbose: bool) -> Result<()> {
    ensure_exists(datadir, name)?;

    // Read state before removal to check for OCI volumes and enabled state.
    let state_file = datadir.join("state").join(name);
    let (has_oci_volumes, is_enabled) = if state_file.exists() {
        State::read_from(&state_file)
            .ok()
            .map(|s| {
                let oci = s.get("OCI_VOLUMES").map(|v| !v.is_empty()).unwrap_or(false);
                let enabled = s.is_yes("ENABLED");
                (oci, enabled)
            })
            .unwrap_or((false, false))
    } else {
        (false, false)
    };

    // Disable the unit if it was enabled (best-effort).
    if is_enabled {
        if verbose {
            eprintln!("disabling unit for '{name}'");
        }
        let _ = systemd::disable_unit_only(name);
    }

    if systemd::is_active(name)? {
        if verbose {
            eprintln!("stopping container '{name}'");
        }
        stop(name, StopMode::Terminate, verbose)?;
    }

    let container_dir = datadir.join("containers").join(name);
    if container_dir.exists() {
        crate::copy::safe_remove_dir(&container_dir)?;
        if verbose {
            eprintln!("removed {}", container_dir.display());
        }
    }

    if state_file.exists() {
        fs::remove_file(&state_file)
            .with_context(|| format!("failed to remove {}", state_file.display()))?;
        if verbose {
            eprintln!("removed {}", state_file.display());
        }
    }

    systemd::remove_limits_dropin(name, verbose)?;

    if has_oci_volumes {
        let vol_dir = volumes_dir(datadir, name);
        if vol_dir.exists() {
            eprintln!("volume data retained at {}", vol_dir.display());
        }
    }

    Ok(())
}

/// Status information for a single container, as shown by `sdme ps`.
pub struct ContainerInfo {
    /// Container name.
    pub name: String,
    /// Systemd unit status (e.g. "running", "stopped").
    pub status: String,
    /// Health status (e.g. "ok", "broken").
    pub health: String,
    /// OS name from os-release, if detected.
    pub os: String,
    /// Pod name (nspawn-level), if any.
    pub pod: String,
    /// Pod name (OCI app-level), if any.
    pub oci_pod: String,
    /// Whether user namespace isolation is enabled.
    pub userns: bool,
    /// Whether auto-start on boot is enabled.
    pub enabled: bool,
    /// Raw bind mount specs from the state file.
    pub binds: String,
    /// Kube container names, if this is a kube container.
    pub kube: String,
}

impl ContainerInfo {
    /// Format bind mounts for display in `sdme ps`.
    ///
    /// Shows container-side mount points with `(ro)` suffix for read-only binds.
    /// Example: `/mnt/data,/etc/app(ro)`
    pub fn binds_display(&self) -> String {
        if self.binds.is_empty() {
            return String::new();
        }
        self.binds
            .split('|')
            .filter_map(|spec| {
                let parts: Vec<&str> = spec.split(':').collect();
                if parts.len() < 3 {
                    return None;
                }
                let container = parts[1];
                let mode = parts[2];
                if mode == "ro" {
                    Some(format!("{container}(ro)"))
                } else {
                    Some(container.to_string())
                }
            })
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// Check readiness probe files for a kube container with probes.
///
/// Looks for `probe-ready` files under `/oci/apps/{name}/` in the container's
/// overlayfs (merged when running, upper when stopped). Returns "ready" if all
/// apps with probe-ready files report "ready", "not-ready" if any report
/// "not-ready", or "ok" if no probe-ready files exist.
fn probe_readiness_health(container_dir: &Path, state: &State) -> String {
    // Determine which apps to check from KUBE_CONTAINERS or OCI_APP.
    let app_names: Vec<&str> = if let Some(kc) = state.get("KUBE_CONTAINERS") {
        kc.split(',').collect()
    } else if let Some(app) = state.get("OCI_APP") {
        vec![app]
    } else {
        return "ok".to_string();
    };

    // Check merged first (running), then upper (stopped).
    let bases = [container_dir.join("merged"), container_dir.join("upper")];

    let mut found_any = false;
    let mut all_ready = true;
    for name in &app_names {
        for base in &bases {
            let probe_file = base.join("oci/apps").join(name).join("probe-ready");
            if let Ok(content) = fs::read_to_string(&probe_file) {
                let trimmed = content.trim();
                found_any = true;
                if trimmed != "ready" {
                    all_ready = false;
                }
                break; // Found in this base, no need to check the other.
            }
        }
    }

    if !found_any {
        "ok".to_string()
    } else if all_ready {
        "ready".to_string()
    } else {
        "not-ready".to_string()
    }
}

/// List all containers with their status, health, OS, and metadata.
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

        // Health checks.
        let mut problems = Vec::new();
        if !container_dir.exists() {
            problems.push("missing container dir");
        }
        let state_path = state_dir.join(name);
        let state = State::read_from(&state_path);

        // Extract all state-dependent fields at once.
        let (rootfs_name, pod, oci_pod, userns, enabled, binds, kube) = match &state {
            Ok(s) => {
                let kube = if s.is_yes("KUBE") {
                    format!("kube:{}", s.get("KUBE_CONTAINERS").unwrap_or(""))
                } else {
                    String::new()
                };
                (
                    s.rootfs().to_string(),
                    s.get("POD").unwrap_or("").to_string(),
                    s.get("OCI_POD").unwrap_or("").to_string(),
                    s.is_yes("USERNS"),
                    s.is_yes("ENABLED"),
                    s.get("BINDS").unwrap_or("").to_string(),
                    kube,
                )
            }
            Err(_) => {
                problems.push("unreadable state file");
                (
                    String::new(),
                    String::new(),
                    String::new(),
                    false,
                    false,
                    String::new(),
                    String::new(),
                )
            }
        };

        if !rootfs_name.is_empty() && !datadir.join("fs").join(&rootfs_name).exists() {
            problems.push("missing fs");
        }

        let health = if !problems.is_empty() {
            problems.join(", ")
        } else if let Ok(ref s) = state {
            // For kube containers with readiness probes, check the probe-ready
            // file in the container's overlayfs to report ready/not-ready.
            if s.is_yes("HAS_PROBES") {
                probe_readiness_health(&container_dir, s)
            } else {
                "ok".to_string()
            }
        } else {
            "ok".to_string()
        };

        // OS detection: prefer the container's overlayfs view (merged when
        // running, upper when stopped), fall back to the imported rootfs.
        let os = {
            let merged = container_dir.join("merged");
            let upper = container_dir.join("upper");
            let detected = [&merged, &upper]
                .iter()
                .map(|p| rootfs::detect_distro(p))
                .find(|d| !d.is_empty())
                .unwrap_or_else(|| {
                    if !rootfs_name.is_empty() {
                        rootfs::detect_distro(&datadir.join("fs").join(&rootfs_name))
                    } else {
                        // Host-rootfs container with overlayfs not mounted
                        // (stopped): the lower layer is the host's /.
                        rootfs::detect_distro(Path::new("/"))
                    }
                });
            if detected.is_empty() {
                "unknown".to_string()
            } else {
                detected
            }
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
            pod,
            oci_pod,
            userns,
            enabled,
            binds,
            kube,
        });
    }
    Ok(result)
}

/// Verify that a container exists and is currently running.
fn ensure_running(datadir: &Path, name: &str) -> Result<()> {
    ensure_exists(datadir, name)?;
    if !systemd::is_active(name)? {
        bail!("container '{name}' is not running");
    }
    Ok(())
}

/// Enter a running container via `machinectl shell`.
pub fn join(
    datadir: &Path,
    name: &str,
    command: &[String],
    join_as_sudo_user: bool,
    verbose: bool,
) -> Result<ExitStatus> {
    ensure_running(datadir, name)?;
    machinectl_shell(datadir, name, command, join_as_sudo_user, verbose)
}

/// Run a one-off command in a running container via `machinectl shell`.
pub fn exec(
    datadir: &Path,
    name: &str,
    command: &[String],
    join_as_sudo_user: bool,
    verbose: bool,
) -> Result<ExitStatus> {
    ensure_running(datadir, name)?;
    machinectl_shell(datadir, name, command, join_as_sudo_user, verbose)
}

/// Candidate inner cgroup paths under a container's cgroup.
/// systemd-nspawn organizes its cgroup subtree differently depending on
/// the version and configuration; we try each one.
const CGROUP_INNER_PATHS: &[&str] = &[
    "init.scope/system.slice",
    "payload/system.slice",
    "system.slice",
];

/// Locate the cgroup directory for the OCI app's systemd service inside
/// the container's cgroup hierarchy (cgroups v2).
///
/// Tries two cgroup root patterns:
/// - `sdme@{name}.service` (systemd < 257, template unit cgroup)
/// - `machine-{escaped}.scope` (systemd >= 257, machine scope cgroup)
fn find_oci_service_cgroup(name: &str, app_name: &str) -> Result<PathBuf> {
    let service_name = format!("sdme-oci-{app_name}.service");
    let machine_slice = PathBuf::from("/sys/fs/cgroup/machine.slice");

    // systemd >= 257 uses machine-{name}.scope with hyphens escaped as \x2d.
    // systemd >= 259 registers the scope directly as {name}.scope.
    let escaped_name = name.replace('-', "\\x2d");
    let cgroup_roots = [
        machine_slice.join(format!("{name}.scope")),
        machine_slice.join(format!("sdme@{name}.service")),
        machine_slice.join(format!("machine-{escaped_name}.scope")),
    ];

    // Retry briefly: the cgroup directory may not be visible on the
    // filesystem immediately after systemd reports the unit as active.
    let mut attempts = 0;
    loop {
        for root in &cgroup_roots {
            for inner in CGROUP_INNER_PATHS {
                let candidate = root.join(inner).join(&service_name);
                if candidate.is_dir() {
                    return Ok(candidate);
                }
            }
        }
        attempts += 1;
        if attempts >= 30 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    bail!(
        "cgroup for {service_name} not found under {}",
        machine_slice.display()
    )
}

/// Parse the `NSpid:` line from `/proc/{pid}/status` content.
/// Returns the list of namespace PIDs (host PID first, then inner PIDs).
fn parse_nspid(status_content: &str) -> Option<Vec<u32>> {
    for line in status_content.lines() {
        if let Some(rest) = line.strip_prefix("NSpid:") {
            let pids: Vec<u32> = rest
                .split_whitespace()
                .filter_map(|s| s.parse().ok())
                .collect();
            if !pids.is_empty() {
                return Some(pids);
            }
        }
    }
    None
}

/// Find the host PID of the OCI app process by reading `cgroup.procs` and
/// checking each process's `NSpid:` line for one that is PID 1 in the
/// innermost (isolate) PID namespace.
fn find_app_pid(service_cgroup: &Path, app_name: &str) -> Result<u32> {
    let procs_path = service_cgroup.join("cgroup.procs");
    let content = fs::read_to_string(&procs_path)
        .with_context(|| format!("failed to read {}", procs_path.display()))?;

    for line in content.lines() {
        let pid: u32 = match line.trim().parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let status_path = format!("/proc/{pid}/status");
        let status = match fs::read_to_string(&status_path) {
            Ok(s) => s,
            Err(_) => continue, // process may have exited
        };
        if let Some(nspids) = parse_nspid(&status) {
            // The app process (inside the isolate namespace) has NSpid with
            // 3+ entries where the last one is 1:
            //   NSpid: <host_pid> <container_pid> 1
            // The isolate parent only has 2 entries (host + container).
            if nspids.len() >= 3 && nspids[nspids.len() - 1] == 1 {
                return Ok(pid);
            }
        }
    }

    bail!(
        "could not find PID 1 process for OCI app '{}' in {}",
        app_name,
        service_cgroup.display()
    )
}

/// Run a command inside a container's OCI app namespaces using `nsenter`.
///
/// Discovers the app's host PID via its cgroup, then enters its PID, IPC,
/// and mount namespaces so that `ps` shows only the app's processes.
pub fn exec_oci(
    datadir: &Path,
    name: &str,
    app_name: &str,
    command: &[String],
    verbose: bool,
) -> Result<ExitStatus> {
    ensure_running(datadir, name)?;

    crate::system_check::find_program("nsenter")
        .context("nsenter is required for exec --oci (install util-linux)")?;

    let service_cgroup = find_oci_service_cgroup(name, app_name)?;
    let app_pid = find_app_pid(&service_cgroup, app_name)?;

    let pid_str = app_pid.to_string();
    let mut cmd = std::process::Command::new("nsenter");
    cmd.args(["-t", &pid_str, "--pid", "--ipc", "--mount", "--"]);
    cmd.args(command);

    if verbose {
        eprintln!(
            "exec: nsenter {}",
            cmd.get_args()
                .map(|a| a.to_string_lossy())
                .collect::<Vec<_>>()
                .join(" ")
        );
    }

    let status = cmd.status().context("failed to run nsenter")?;
    Ok(status)
}

fn machinectl_shell(
    datadir: &Path,
    name: &str,
    command: &[String],
    join_as_sudo_user: bool,
    verbose: bool,
) -> Result<ExitStatus> {
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
                        eprintln!(
                            "host rootfs container: joining as user '{}' with opaque dirs {dirs}",
                            su.name
                        );
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
        eprintln!(
            "exec: machinectl {}",
            cmd.get_args()
                .map(|a| a.to_string_lossy())
                .collect::<Vec<_>>()
                .join(" ")
        );
    }
    let status = cmd.status().context("failed to run machinectl")?;
    Ok(status)
}

/// Update resource limits on an existing container.
///
/// Reads the current state file, merges the new limits, writes it back,
/// and regenerates the systemd drop-in. If the container is running,
/// prints a note that a restart is needed.
pub fn set_limits(
    datadir: &Path,
    name: &str,
    limits: &ResourceLimits,
    verbose: bool,
) -> Result<()> {
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

/// Controls how `stop()` shuts down a container.
#[derive(Debug, Clone, Copy)]
pub enum StopMode {
    /// Send SIGRTMIN+4 to the container leader (graceful poweroff).
    Graceful,
    /// Call TerminateMachine (SIGTERM to nspawn leader).
    Terminate,
    /// Send SIGKILL to all processes in the container.
    Kill,
}

/// Stop a container using the specified mode (graceful, terminate, or kill).
pub fn stop(name: &str, mode: StopMode, verbose: bool) -> Result<()> {
    match mode {
        StopMode::Graceful => {
            if verbose {
                eprintln!("powering off machine '{name}'");
            }
            let signal = libc::SIGRTMIN() + 4;
            systemd::kill_machine(name, "leader", signal)?;
            systemd::wait_for_shutdown(name, std::time::Duration::from_secs(90), verbose)
                .with_context(|| {
                    format!(
                        "hint: the container may be stuck during shutdown; \
                         try 'sdme stop --kill {name}' to force-kill it"
                    )
                })
        }
        StopMode::Terminate => {
            if verbose {
                eprintln!("terminating machine '{name}'");
            }
            systemd::terminate_machine(name)?;
            systemd::wait_for_shutdown(name, std::time::Duration::from_secs(30), verbose)
                .with_context(|| {
                    format!(
                        "hint: the container may be stuck; \
                         try 'sdme stop --kill {name}' to force-kill it"
                    )
                })
        }
        StopMode::Kill => {
            if verbose {
                eprintln!("killing machine '{name}'");
            }
            systemd::kill_machine(name, "all", libc::SIGKILL)?;
            systemd::wait_for_shutdown(name, std::time::Duration::from_secs(15), verbose)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDataDir;
    use std::sync::Mutex;

    /// umask is process-global; tests that call create() or manipulate the umask
    /// must hold this lock to avoid racing each other.
    static UMASK_LOCK: Mutex<()> = Mutex::new(());

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
        let _lock = UMASK_LOCK.lock().unwrap();
        let tmp = tmp();
        let opts = CreateOptions {
            ..Default::default()
        };
        let name = create(tmp.path(), &opts, false).unwrap();
        assert!(validate_name(&name).is_ok());

        // Verify directories.
        let container_dir = tmp.path().join("containers").join(&name);
        assert!(container_dir.join("upper").is_dir());
        assert!(container_dir.join("work").is_dir());
        assert!(container_dir.join("merged").is_dir());

        // Verify hostname.
        let hostname = fs::read_to_string(container_dir.join("upper/etc/hostname")).unwrap();
        assert_eq!(hostname, format!("{name}\n"));

        // Verify hosts.
        let hosts = fs::read_to_string(container_dir.join("upper/etc/hosts")).unwrap();
        assert_eq!(
            hosts,
            format!("127.0.0.1 localhost {name}\n::1 localhost {name}\n")
        );

        // Verify state file.
        let state = State::read_from(&tmp.path().join("state").join(&name)).unwrap();
        assert_eq!(state.get("NAME"), Some(name.as_str()));
        assert_eq!(state.get("ROOTFS"), Some(""));
        assert!(state.get("CREATED").is_some());
    }

    #[test]
    fn test_create_with_name() {
        let _lock = UMASK_LOCK.lock().unwrap();
        let tmp = tmp();
        let opts = CreateOptions {
            name: Some("hello".to_string()),
            ..Default::default()
        };
        let name = create(tmp.path(), &opts, false).unwrap();
        assert_eq!(name, "hello");

        let hostname =
            fs::read_to_string(tmp.path().join("containers/hello/upper/etc/hostname")).unwrap();
        assert_eq!(hostname, "hello\n");

        let hosts =
            fs::read_to_string(tmp.path().join("containers/hello/upper/etc/hosts")).unwrap();
        assert_eq!(hosts, "127.0.0.1 localhost hello\n::1 localhost hello\n");

        let state = State::read_from(&tmp.path().join("state/hello")).unwrap();
        assert_eq!(state.get("NAME"), Some("hello"));
    }

    #[test]
    fn test_create_duplicate_name() {
        let _lock = UMASK_LOCK.lock().unwrap();
        let tmp = tmp();
        let opts = CreateOptions {
            name: Some("dup".to_string()),
            ..Default::default()
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
        let _lock = UMASK_LOCK.lock().unwrap();
        let tmp = tmp();
        let opts = CreateOptions {
            name: Some("test".to_string()),
            rootfs: Some("nonexistent".to_string()),
            ..Default::default()
        };
        let err = create(tmp.path(), &opts, false).unwrap_err();
        assert!(
            err.to_string().contains("fs not found"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_create_with_rootfs_exists() {
        let _lock = UMASK_LOCK.lock().unwrap();
        let tmp = tmp();
        let rootfs_dir = tmp.path().join("fs/myroot");
        fs::create_dir_all(&rootfs_dir).unwrap();

        let opts = CreateOptions {
            name: Some("test".to_string()),
            rootfs: Some("myroot".to_string()),
            ..Default::default()
        };
        let name = create(tmp.path(), &opts, false).unwrap();
        assert_eq!(name, "test");

        let state = State::read_from(&tmp.path().join("state/test")).unwrap();
        assert_eq!(state.get("ROOTFS"), Some("myroot"));
    }

    #[test]
    fn test_create_cleanup_on_failure() {
        let _lock = UMASK_LOCK.lock().unwrap();
        let tmp = tmp();
        // Block state dir by placing a file where the directory should be created.
        let state_path = tmp.path().join("state");
        fs::write(&state_path, "blocker").unwrap();

        let opts = CreateOptions {
            name: Some("fail".to_string()),
            ..Default::default()
        };
        let err = create(tmp.path(), &opts, false);
        assert!(err.is_err());

        // Container dir should have been cleaned up.
        assert!(!tmp.path().join("containers/fail").exists());
    }

    #[test]
    fn test_ensure_exists_ok() {
        let _lock = UMASK_LOCK.lock().unwrap();
        let tmp = tmp();
        let opts = CreateOptions {
            name: Some("mybox".to_string()),
            ..Default::default()
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
    }

    fn create_dummy_container_with_rootfs(tmp: &TempDataDir, name: &str, rootfs_name: &str) {
        let state_dir = tmp.path().join("state");
        fs::create_dir_all(&state_dir).unwrap();
        fs::write(
            state_dir.join(name),
            format!("NAME={name}\nROOTFS={rootfs_name}\n"),
        )
        .unwrap();
        let container_dir = tmp.path().join("containers").join(name);
        fs::create_dir_all(container_dir.join("upper")).unwrap();
        fs::create_dir_all(container_dir.join("work")).unwrap();
        fs::create_dir_all(container_dir.join("merged")).unwrap();
    }

    fn write_os_release(rootfs: &Path, content: &str) {
        let etc = rootfs.join("etc");
        fs::create_dir_all(&etc).unwrap();
        fs::write(etc.join("os-release"), content).unwrap();
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
        assert!(
            err.to_string().contains("no container found"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_resolve_name_empty() {
        let tmp = tmp();
        let err = resolve_name(tmp.path(), "").unwrap_err();
        assert!(
            err.to_string().contains("must not be empty"),
            "unexpected error: {err}"
        );
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
        let _lock = UMASK_LOCK.lock().unwrap();
        let tmp = tmp();
        let limits = crate::ResourceLimits {
            memory: Some("2G".to_string()),
            cpus: Some("4".to_string()),
            cpu_weight: None,
        };
        let opts = CreateOptions {
            name: Some("limited".to_string()),
            limits,
            ..Default::default()
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
        let _lock = UMASK_LOCK.lock().unwrap();
        // Set a restrictive umask, attempt create, then restore.
        let old = unsafe { libc::umask(0o077) };
        let tmp = tmp();
        let opts = CreateOptions {
            name: Some("umasktest".to_string()),
            ..Default::default()
        };
        let err = create(tmp.path(), &opts, false);
        unsafe { libc::umask(old) };

        let err = err.unwrap_err();
        assert!(err.to_string().contains("umask"), "unexpected error: {err}");
    }

    #[test]
    fn test_create_with_userns() {
        let _lock = UMASK_LOCK.lock().unwrap();
        let tmp = tmp();
        let opts = CreateOptions {
            name: Some("usernsbox".to_string()),
            security: crate::SecurityConfig {
                userns: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let name = create(tmp.path(), &opts, false).unwrap();
        assert_eq!(name, "usernsbox");

        let state = State::read_from(&tmp.path().join("state/usernsbox")).unwrap();
        assert_eq!(state.get("USERNS"), Some("yes"));
    }

    #[test]
    fn test_create_without_userns() {
        let _lock = UMASK_LOCK.lock().unwrap();
        let tmp = tmp();
        let opts = CreateOptions {
            name: Some("nouserns".to_string()),
            ..Default::default()
        };
        create(tmp.path(), &opts, false).unwrap();

        let state = State::read_from(&tmp.path().join("state/nouserns")).unwrap();
        assert_eq!(state.get("USERNS"), None);
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
        assert!(
            err.to_string().contains("absolute"),
            "unexpected error: {err}"
        );
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
        assert!(
            err.to_string().contains("duplicate"),
            "unexpected error: {err}"
        );
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
        let _lock = UMASK_LOCK.lock().unwrap();
        // Setting trusted.* xattrs requires root; skip if not root.
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skipping test_create_with_opaque_dirs: requires root");
            return;
        }
        let tmp = tmp();
        let opts = CreateOptions {
            name: Some("opaquebox".to_string()),
            opaque_dirs: vec!["/var".to_string(), "/opt/data".to_string()],
            ..Default::default()
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
            assert_eq!(
                &buf[..size as usize],
                b"y",
                "xattr value mismatch for {dir}"
            );
        }
    }

    #[test]
    fn test_create_with_security() {
        let _lock = UMASK_LOCK.lock().unwrap();
        let tmp = tmp();
        let security = crate::SecurityConfig {
            drop_caps: vec!["CAP_SYS_PTRACE".to_string()],
            no_new_privileges: true,
            read_only: true,
            system_call_filter: vec!["~@mount".to_string()],
            apparmor_profile: Some("sdme-container".to_string()),
            ..Default::default()
        };
        let opts = CreateOptions {
            name: Some("sectest".to_string()),
            security,
            ..Default::default()
        };
        let name = create(tmp.path(), &opts, false).unwrap();
        assert_eq!(name, "sectest");

        let state = State::read_from(&tmp.path().join("state/sectest")).unwrap();
        assert_eq!(state.get("DROP_CAPS"), Some("CAP_SYS_PTRACE"));
        assert_eq!(state.get("NO_NEW_PRIVS"), Some("yes"));
        assert_eq!(state.get("READ_ONLY"), Some("yes"));
        assert_eq!(state.get("SYSCALL_FILTER"), Some("~@mount"));
        assert_eq!(state.get("APPARMOR_PROFILE"), Some("sdme-container"));
        // ADD_CAPS not set: should not appear.
        assert_eq!(state.get("ADD_CAPS"), None);
    }

    #[test]
    fn test_create_opaque_dirs_state() {
        let _lock = UMASK_LOCK.lock().unwrap();
        // Setting trusted.* xattrs requires root; skip if not root.
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skipping test_create_opaque_dirs_state: requires root");
            return;
        }
        let tmp = tmp();
        let opts = CreateOptions {
            name: Some("statebox".to_string()),
            opaque_dirs: vec!["/var".to_string(), "/opt".to_string()],
            ..Default::default()
        };
        create(tmp.path(), &opts, false).unwrap();

        let state = State::read_from(&tmp.path().join("state/statebox")).unwrap();
        assert_eq!(state.get("OPAQUE_DIRS"), Some("/var,/opt"));
    }

    // --- volumes_dir test ---

    #[test]
    fn test_volumes_dir() {
        let datadir = Path::new("/var/lib/sdme");
        let dir = volumes_dir(datadir, "mycontainer");
        assert_eq!(dir, PathBuf::from("/var/lib/sdme/volumes/mycontainer"));
    }

    // --- OCI volumes wiring in create ---

    #[test]
    fn test_create_with_oci_volumes() {
        let _lock = UMASK_LOCK.lock().unwrap();
        let tmp = tmp();
        // Create a rootfs with oci/apps/app/volumes
        let rootfs_dir = tmp.path().join("fs/myoci");
        fs::create_dir_all(rootfs_dir.join("oci/apps/app")).unwrap();
        fs::write(
            rootfs_dir.join("oci/apps/app/volumes"),
            "/var/lib/mysql\n/data\n",
        )
        .unwrap();

        let opts = CreateOptions {
            name: Some("voltest".to_string()),
            rootfs: Some("myoci".to_string()),
            oci_volumes: vec!["/var/lib/mysql".to_string(), "/data".to_string()],
            ..Default::default()
        };
        let name = create(tmp.path(), &opts, false).unwrap();
        assert_eq!(name, "voltest");

        // Check state has OCI_VOLUMES
        let state = State::read_from(&tmp.path().join("state/voltest")).unwrap();
        assert_eq!(state.get("OCI_VOLUMES"), Some("/var/lib/mysql,/data"));

        // Check bind entries were added
        let binds_str = state.get("BINDS").expect("BINDS should be set");
        assert!(binds_str.contains("/oci/apps/app/root/var/lib/mysql:rw"));
        assert!(binds_str.contains("/oci/apps/app/root/data:rw"));

        // Check volume directories were created
        let vol_base = tmp.path().join("volumes/voltest");
        assert!(vol_base.join("var-lib-mysql").exists());
        assert!(vol_base.join("data").exists());
    }

    #[test]
    fn test_create_oci_env_merge() {
        let _lock = UMASK_LOCK.lock().unwrap();
        let tmp = tmp();
        // Create a rootfs with oci/apps/app/env containing an existing var.
        let rootfs_dir = tmp.path().join("fs/envoci");
        fs::create_dir_all(rootfs_dir.join("oci/apps/app")).unwrap();
        fs::write(rootfs_dir.join("oci/apps/app/env"), "EXISTING=value\n").unwrap();

        let opts = CreateOptions {
            name: Some("envtest".to_string()),
            rootfs: Some("envoci".to_string()),
            oci_envs: vec!["NEW_VAR=hello".to_string(), "OTHER=world".to_string()],
            ..Default::default()
        };
        let name = create(tmp.path(), &opts, false).unwrap();
        assert_eq!(name, "envtest");

        // Verify upper/oci/apps/app/env has both original and new vars.
        let upper_env = tmp.path().join("containers/envtest/upper/oci/apps/app/env");
        let content = fs::read_to_string(&upper_env).unwrap();
        assert!(content.contains("EXISTING=value"));
        assert!(content.contains("NEW_VAR=hello"));
        assert!(content.contains("OTHER=world"));
    }

    #[test]
    fn test_create_oci_env_no_oci_rootfs() {
        let _lock = UMASK_LOCK.lock().unwrap();
        let tmp = tmp();
        // Create a rootfs without oci/env.
        let rootfs_dir = tmp.path().join("fs/plainfs");
        fs::create_dir_all(&rootfs_dir).unwrap();

        let opts = CreateOptions {
            name: Some("nooci".to_string()),
            rootfs: Some("plainfs".to_string()),
            oci_envs: vec!["FOO=bar".to_string()],
            ..Default::default()
        };
        let result = create(tmp.path(), &opts, false);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("--oci-env requires an OCI app rootfs"),
            "unexpected error: {msg}"
        );
    }

    // --- parse_nspid tests ---

    #[test]
    fn test_parse_nspid_app_process() {
        // App process inside isolate: host PID 12345, container PID 67, nested PID 1
        let status = "Name:\tredis-server\nNSpid:\t12345\t67\t1\nPPid:\t12300\n";
        let result = parse_nspid(status).unwrap();
        assert_eq!(result, vec![12345, 67, 1]);
    }

    #[test]
    fn test_parse_nspid_isolate_parent() {
        // Isolate parent: host PID 12300, container PID 55 (only 2 entries)
        let status = "Name:\tsdme-isolate\nNSpid:\t12300\t55\nPPid:\t1\n";
        let result = parse_nspid(status).unwrap();
        assert_eq!(result, vec![12300, 55]);
    }

    #[test]
    fn test_parse_nspid_missing() {
        let status = "Name:\tinit\nPid:\t1\nPPid:\t0\n";
        assert!(parse_nspid(status).is_none());
    }

    #[test]
    fn test_parse_nspid_single_pid() {
        // Host-level process with a single NSpid entry
        let status = "Name:\tbash\nNSpid:\t9999\nPPid:\t1\n";
        let result = parse_nspid(status).unwrap();
        assert_eq!(result, vec![9999]);
    }

    // --- find_app_pid tests (using mock cgroup/proc data) ---

    #[test]
    fn test_find_app_pid_selects_nested_pid1() {
        let tmp = tmp();
        let cgroup_dir = tmp.path().join("cgroup");
        fs::create_dir_all(&cgroup_dir).unwrap();

        // Two PIDs in the cgroup: the isolate parent and the app process.
        // We use fake /proc entries under a temp dir, but find_app_pid reads
        // real /proc, so we test parse_nspid logic directly here and verify
        // the selection logic.
        //
        // Isolate parent: NSpid has 2 entries (host + container)
        let isolate_status = "Name:\tsdme-isolate\nNSpid:\t100\t50\nPPid:\t1\n";
        // App process: NSpid has 3 entries, last is 1
        let app_status = "Name:\tredis-server\nNSpid:\t101\t51\t1\nPPid:\t100\n";

        // Verify our selection logic: only the app has 3+ entries with last == 1
        let isolate_nspids = parse_nspid(isolate_status).unwrap();
        assert_eq!(isolate_nspids.len(), 2);
        assert_ne!(*isolate_nspids.last().unwrap(), 1u32);

        let app_nspids = parse_nspid(app_status).unwrap();
        assert!(app_nspids.len() >= 3);
        assert_eq!(*app_nspids.last().unwrap(), 1u32);
    }

    // --- OS detection tests ---

    #[test]
    fn test_list_os_host_rootfs_fallback() {
        // Stopped host-rootfs container with no os-release in merged/ or upper/.
        // Cascade falls to detect_distro(Path::new("/")) — the host's os-release.
        // On hosts without os-release (rare but possible), falls back to "unknown".
        let tmp = tmp();
        create_dummy_container(&tmp, "hostbox");
        let infos = list(tmp.path()).unwrap();
        let info = infos.iter().find(|i| i.name == "hostbox").unwrap();
        assert!(!info.os.is_empty(), "os should never be empty");
    }

    #[test]
    fn test_list_os_unknown_when_no_os_release() {
        // Imported rootfs container with no os-release anywhere — should show "unknown".
        let tmp = tmp();
        create_dummy_container_with_rootfs(&tmp, "bare", "emptyfs");
        // Create the rootfs dir but don't write os-release.
        fs::create_dir_all(tmp.path().join("fs/emptyfs")).unwrap();
        let infos = list(tmp.path()).unwrap();
        let info = infos.iter().find(|i| i.name == "bare").unwrap();
        assert_eq!(info.os, "unknown");
    }

    #[test]
    fn test_list_os_merged_takes_priority() {
        // os-release in merged/ should win over upper/ and rootfs.
        let tmp = tmp();
        create_dummy_container(&tmp, "mergedbox");
        let merged = tmp.path().join("containers/mergedbox/merged");
        write_os_release(&merged, "PRETTY_NAME=\"Merged Distro\"\n");
        let upper = tmp.path().join("containers/mergedbox/upper");
        write_os_release(&upper, "PRETTY_NAME=\"Upper Distro\"\n");

        let infos = list(tmp.path()).unwrap();
        let info = infos.iter().find(|i| i.name == "mergedbox").unwrap();
        assert_eq!(info.os, "Merged Distro");
    }

    #[test]
    fn test_list_os_imported_rootfs_distros() {
        let tmp = tmp();

        let distros = [
            (
                "deb",
                "mydebian",
                "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"",
            ),
            ("ubu", "myubuntu", "PRETTY_NAME=\"Ubuntu 24.04 LTS\""),
            ("fed", "myfedora", "PRETTY_NAME=\"Fedora Linux 41\""),
            ("cos", "mycentos", "PRETTY_NAME=\"CentOS Stream 9\""),
            ("alm", "myalma", "PRETTY_NAME=\"AlmaLinux 9.3\""),
            ("arc", "myarch", "PRETTY_NAME=\"Arch Linux\""),
            ("cch", "mycachyos", "PRETTY_NAME=\"CachyOS\""),
        ];

        for (cname, rootfs_name, os_release) in &distros {
            create_dummy_container_with_rootfs(&tmp, cname, rootfs_name);
            let rootfs_dir = tmp.path().join("fs").join(rootfs_name);
            write_os_release(&rootfs_dir, &format!("{os_release}\n"));
        }

        let infos = list(tmp.path()).unwrap();
        for (cname, _, os_release) in &distros {
            let info = infos.iter().find(|i| i.name == *cname).unwrap();
            // Extract the value from PRETTY_NAME="..."
            let expected = os_release
                .strip_prefix("PRETTY_NAME=\"")
                .unwrap()
                .strip_suffix('"')
                .unwrap();
            assert_eq!(info.os, expected, "os mismatch for container {cname}");
        }
    }

    #[test]
    fn test_list_os_cascade_priority() {
        let tmp = tmp();
        let rootfs_name = "testfs";
        create_dummy_container_with_rootfs(&tmp, "cascade", rootfs_name);

        let merged = tmp.path().join("containers/cascade/merged");
        let upper = tmp.path().join("containers/cascade/upper");
        let rootfs_dir = tmp.path().join("fs").join(rootfs_name);

        write_os_release(&merged, "PRETTY_NAME=\"Merged OS\"\n");
        write_os_release(&upper, "PRETTY_NAME=\"Upper OS\"\n");
        write_os_release(&rootfs_dir, "PRETTY_NAME=\"Rootfs OS\"\n");

        // merged/ wins
        let infos = list(tmp.path()).unwrap();
        let info = infos.iter().find(|i| i.name == "cascade").unwrap();
        assert_eq!(info.os, "Merged OS");

        // Remove merged os-release — upper/ wins
        fs::remove_file(merged.join("etc/os-release")).unwrap();
        let infos = list(tmp.path()).unwrap();
        let info = infos.iter().find(|i| i.name == "cascade").unwrap();
        assert_eq!(info.os, "Upper OS");

        // Remove upper os-release — rootfs wins
        fs::remove_file(upper.join("etc/os-release")).unwrap();
        let infos = list(tmp.path()).unwrap();
        let info = infos.iter().find(|i| i.name == "cascade").unwrap();
        assert_eq!(info.os, "Rootfs OS");
    }
}
