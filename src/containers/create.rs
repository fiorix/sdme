//! Container creation with overlayfs directory setup.

use std::ffi::CString;
use std::fs::{self, OpenOptions};
use std::os::unix::fs::{symlink, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::storage::{self, Backend};
use crate::{
    names, rootfs, systemd, validate_name, BindConfig, EnvConfig, NetworkConfig, ResourceLimits,
    SecurityConfig, State,
};

use super::{get_umask, resolve_rootfs, set_dir_permissions, unix_timestamp, volumes_dir};

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
    /// Systemd services to mask in the overlayfs upper layer at create time.
    pub masked_services: Vec<String>,
    /// Storage backend for the container root (overlay or btrfs).
    pub backend: Backend,
    /// Mode B btrfs pool image size (from config). Empty falls back to the
    /// built-in default. Ignored for the overlay backend.
    pub pool_size: String,
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

    // Warn if systemd-networkd is not running on the host when using
    // networking modes that depend on it for bridge management and DHCP.
    let uses_private_networking = opts.network.network_veth
        || opts.network.network_zone.is_some()
        || opts.network.network_bridge.is_some();
    if uses_private_networking && !systemd::is_unit_active("systemd-networkd.service") {
        eprintln!(
            "warning: systemd-networkd is not running on the host; \
             the zone bridge, veth, and DHCP will not work, \
             and containers will not get network connectivity\n\
             hint: sudo systemctl enable --now systemd-networkd"
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

    // The btrfs backend snapshots an imported rootfs into a subvolume; there is
    // no cheap, correct way to snapshot the live host root, so host-rootfs
    // containers stay on overlay.
    if opts.backend == Backend::Btrfs && opts.rootfs.is_none() {
        bail!(
            "btrfs storage requires an imported rootfs (-r NAME); \
             host-rootfs containers use the overlay backend"
        );
    }

    // Hold shared lock on rootfs to prevent deletion during container creation.
    let _rootfs_lock = match &opts.rootfs {
        Some(r) => Some(
            crate::lock::lock_shared(datadir, "fs", r)
                .with_context(|| format!("cannot lock rootfs '{r}' for reading"))?,
        ),
        None => None,
    };

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
            // A btrfs container root is a subvolume, which cannot be removed by
            // remove_dir_all; delete it first (best effort).
            if opts.backend == Backend::Btrfs {
                let _ = storage::btrfs::teardown(datadir, &name, verbose);
            }
            let container_dir = datadir.join("containers").join(&name);
            let _ = fs::remove_dir_all(&container_dir);
            let _ = fs::remove_file(&state_path);
            Err(e)
        }
    }
}

/// Reject a btrfs container whose base snapshot would redirect a customization
/// write through a symlink. sdme writes /etc (and OCI) customization directly
/// into the subvolume, so if any component of `rel` under `root` is an
/// image-supplied symlink (e.g. `/var/lib` -> `/etc`, or `etc` itself), those
/// writes/removals could escape the subvolume onto the host. The overlay
/// backend is immune because it writes into a fresh, empty upper layer. Only
/// applied for the btrfs backend.
fn reject_symlinked_path(root: &Path, rel: &str) -> Result<()> {
    let mut cur = root.to_path_buf();
    for part in rel.split('/').filter(|s| !s.is_empty()) {
        cur.push(part);
        if let Ok(m) = fs::symlink_metadata(&cur) {
            if m.file_type().is_symlink() {
                bail!(
                    "refusing btrfs container: {} is a symlink in the base rootfs; a \
                     malformed or hostile image could redirect customization writes onto \
                     the host filesystem",
                    cur.display()
                );
            }
        }
    }
    Ok(())
}

/// Remove a leaf path if it is a symlink, so a subsequent write creates a real
/// file inside the subvolume rather than following the base image's symlink
/// (e.g. a Debian `/etc/resolv.conf` -> systemd stub, or an absolute symlink
/// that would escape onto the host). Mirrors how the overlay upper layer
/// shadows a lower-layer symlink with a real file. Only applied for btrfs.
fn shadow_symlink(path: &Path) -> Result<()> {
    if let Ok(m) = fs::symlink_metadata(path) {
        if m.file_type().is_symlink() {
            fs::remove_file(path)
                .with_context(|| format!("failed to replace symlink {}", path.display()))?;
        }
    }
    Ok(())
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

    // Provision the writable root and resolve `root_dir`: the directory where
    // per-container customization (hostname, /etc, masked units, OCI drop-ins)
    // is written. Overlay writes into the `upper` layer; btrfs writes directly
    // into the container's subvolume.
    let root_dir = match opts.backend {
        Backend::Overlay => {
            // The upper directory becomes the root of the overlayfs merged
            // view, so it must be world-readable (0o755); otherwise non-root
            // services inside the container (e.g. dbus-daemon running as
            // messagebus) cannot traverse the filesystem. The merged mount
            // point also needs 0o755. The work directory is overlayfs-internal
            // and can stay restricted.
            for (sub, mode) in &[("upper", 0o755), ("work", 0o700), ("merged", 0o755)] {
                let dir = container_dir.join(sub);
                fs::create_dir_all(&dir)
                    .with_context(|| format!("failed to create {}", dir.display()))?;
                set_dir_permissions(&dir, *mode)?;
            }
            container_dir.join("upper")
        }
        Backend::Btrfs => {
            // Keep the bookkeeping dir (volumes, state anchoring); the actual
            // root is a CoW subvolume snapshot of the base rootfs under the
            // btrfs pool. The subvolume itself must be world-traversable.
            fs::create_dir_all(&container_dir)
                .with_context(|| format!("failed to create {}", container_dir.display()))?;
            set_dir_permissions(&container_dir, 0o755)?;
            let base_name = rootfs
                .file_name()
                .and_then(|n| n.to_str())
                .context("btrfs backend requires a named rootfs")?;
            let pool_size = if opts.pool_size.is_empty() {
                storage::pool::DEFAULT_POOL_SIZE
            } else {
                opts.pool_size.as_str()
            };
            storage::btrfs::provision(datadir, name, base_name, rootfs, pool_size, verbose)?
        }
    };

    if verbose {
        eprintln!("container root: {}", root_dir.display());
    }

    // btrfs writes customization directly into the (untrusted) base snapshot,
    // so an image-supplied symlink at a customization ancestor could redirect
    // create_dir_all / remove_dir_all / write onto the host. Reject such images
    // up front. Overlay writes into a fresh empty upper layer and is immune.
    if opts.backend == Backend::Btrfs {
        reject_symlinked_path(&root_dir, "etc/systemd/system")?;
        for dir in opaque_dirs {
            reject_symlinked_path(&root_dir, dir.strip_prefix('/').unwrap_or(dir))?;
        }
    }

    // Set up opaque directories so they start empty. For overlay, the
    // trusted.overlay.opaque xattr hides all lower-layer contents. For btrfs
    // there is no lower layer, so the subvolume already holds the base tree;
    // emptying the directory reproduces the same "starts empty" semantics.
    for dir in opaque_dirs {
        let rel = dir.strip_prefix('/').unwrap_or(dir);
        let target = root_dir.join(rel);
        if opts.backend == Backend::Btrfs && target.exists() {
            fs::remove_dir_all(&target)
                .with_context(|| format!("failed to clear opaque dir {}", target.display()))?;
        }
        fs::create_dir_all(&target)
            .with_context(|| format!("failed to create opaque dir {}", target.display()))?;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755))
            .with_context(|| format!("failed to set permissions on {}", target.display()))?;
        if opts.backend == Backend::Overlay {
            set_opaque_xattr(&target)
                .with_context(|| format!("failed to set opaque xattr on {}", target.display()))?;
        }
        if verbose {
            eprintln!("set opaque: {dir}");
        }
    }

    let etc_dir = root_dir.join("etc");
    fs::create_dir_all(&etc_dir)
        .with_context(|| format!("failed to create {}", etc_dir.display()))?;

    // btrfs: the base snapshot may ship these as symlinks (e.g. Debian's
    // resolv.conf -> systemd stub). Replace them with real files so the writes
    // below stay inside the subvolume, matching how the overlay upper layer
    // shadows a lower-layer symlink. Overlay's upper starts empty, so no-op there.
    if opts.backend == Backend::Btrfs {
        for f in ["hostname", "hosts", "resolv.conf", "machine-id", "fstab"] {
            shadow_symlink(&etc_dir.join(f))?;
        }
    }

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
    if rootfs == Path::new("/") {
        mask_host_mount_units(&systemd_unit_dir, verbose)?;
    }

    // Mask configurable systemd services in the overlayfs upper layer.
    // Skipped for NixOS rootfs because NixOS activation replaces
    // /etc/systemd/system with an immutable symlink to the Nix store.
    let family = rootfs::detect_distro_family(rootfs);
    if family != rootfs::DistroFamily::NixOS {
        for svc in &opts.masked_services {
            let mask_path = systemd_unit_dir.join(svc);
            // Use atomic symlink creation to avoid TOCTOU race between
            // exists() check and symlink() call.
            match symlink("/dev/null", &mask_path) {
                Ok(()) => {
                    if verbose {
                        eprintln!("masked service: {svc}");
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => {
                    return Err(e).with_context(|| {
                        format!("failed to mask {} at {}", svc, mask_path.display())
                    });
                }
            }
        }
    } else if verbose && !opts.masked_services.is_empty() {
        eprintln!("skipping service masking for NixOS rootfs");
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
            // Validate the symlink target from the rootfs: reject absolute
            // paths and path traversal to prevent a malicious imported rootfs
            // from pointing outside the systemd unit directory.
            let target_str = target.to_string_lossy();
            if target.is_absolute() || target_str.contains("..") {
                if verbose {
                    eprintln!(
                        "skipping dbus.service symlink with unsafe target: {}",
                        target.display()
                    );
                }
            } else {
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
    }

    // Set up /etc/resolv.conf in the overlayfs upper layer:
    //
    // For containers with a network interface (veth, zone, bridge):
    // symlink to the systemd-resolved stub so resolved manages DNS.
    // nspawn's --resolv-conf=auto detects this symlink and leaves
    // resolved in control.
    //
    // For all other containers: write a placeholder regular file so
    // systemd-nspawn's --resolv-conf=auto can overwrite it with the host's
    // DNS configuration. Many rootfs images (e.g. Debian) ship resolv.conf as
    // a symlink to ../run/systemd/resolve/stub-resolv.conf; the auto mode's
    // copy variant won't overwrite a symlink, leaving DNS broken. A regular
    // file in the overlayfs upper layer shadows the lower layer's symlink.
    let resolv_path = etc_dir.join("resolv.conf");
    let has_interface = opts.network.has_interface();
    let resolved_active = has_interface
        && !opts
            .masked_services
            .iter()
            .any(|s| s == "systemd-resolved.service");
    if resolved_active {
        // Remove any existing regular file before creating the symlink.
        let _ = fs::remove_file(&resolv_path);
        symlink("../run/systemd/resolve/stub-resolv.conf", &resolv_path)
    } else {
        fs::write(
            &resolv_path,
            "# placeholder, replaced by systemd-nspawn at boot\n",
        )
    }
    .with_context(|| format!("failed to write {}", resolv_path.display()))?;

    // Enable LLMNR in systemd-resolved for zone containers so containers
    // on the same zone bridge can discover each other by hostname. Some
    // distros (Ubuntu) compile resolved with LLMNR=no by default.
    // This is zone-specific; veth and bridge don't need LLMNR.
    let is_zone_with_resolved = opts.network.network_zone.is_some() && resolved_active;
    if is_zone_with_resolved {
        let dropin_dir = etc_dir.join("systemd/resolved.conf.d");
        fs::create_dir_all(&dropin_dir)
            .with_context(|| format!("failed to create {}", dropin_dir.display()))?;
        let dropin = dropin_dir.join("zone-llmnr.conf");
        fs::write(&dropin, "[Resolve]\nLLMNR=yes\nMulticastDNS=yes\n")
            .with_context(|| format!("failed to write {}", dropin.display()))?;
        if verbose {
            eprintln!("enabled LLMNR/mDNS for zone networking");
        }
    }

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

    // When --network-veth, --network-zone, or --network-bridge is used,
    // enable systemd-networkd inside the container so the container-side
    // veth interface (host0) gets an IP via DHCP, and enable systemd-resolved
    // so DNS works (and LLMNR for zone hostname discovery).
    if opts.network.network_veth
        || opts.network.network_zone.is_some()
        || opts.network.network_bridge.is_some()
    {
        let wants_dir = systemd_unit_dir.join("multi-user.target.wants");
        fs::create_dir_all(&wants_dir)
            .with_context(|| format!("failed to create {}", wants_dir.display()))?;

        let networkd_unit = rootfs.join("usr/lib/systemd/system/systemd-networkd.service");
        if networkd_unit.exists() {
            let link = wants_dir.join("systemd-networkd.service");
            if !link.exists() {
                symlink("/usr/lib/systemd/system/systemd-networkd.service", &link).with_context(
                    || format!("failed to enable systemd-networkd at {}", link.display()),
                )?;
                if verbose {
                    eprintln!("enabled systemd-networkd for private networking");
                }
            }
        }

        if resolved_active {
            let resolved_unit = rootfs.join("usr/lib/systemd/system/systemd-resolved.service");
            if resolved_unit.exists() {
                let link = wants_dir.join("systemd-resolved.service");
                if !link.exists() {
                    symlink("/usr/lib/systemd/system/systemd-resolved.service", &link)
                        .with_context(|| {
                            format!("failed to enable systemd-resolved at {}", link.display())
                        })?;
                    if verbose {
                        eprintln!("enabled systemd-resolved for DNS");
                    }
                }
            }
        }
    }

    if verbose {
        eprintln!("wrote hostname, hosts, resolv.conf, machine-id, and fstab files");
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
    if opts.backend != Backend::Overlay {
        state.set("STORAGE", opts.backend.as_str());
    }
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
        let unit_rel = crate::oci::app::systemd_unit_dir(rootfs);
        for oci_app_name in &app_names {
            let dropin_rel = format!("{unit_rel}/sdme-oci-{oci_app_name}.service.d");
            if opts.backend == Backend::Btrfs {
                reject_symlinked_path(&root_dir, &dropin_rel)?;
            }
            let dropin_dir = root_dir.join(&dropin_rel);
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

            let unit_rel = crate::oci::app::systemd_unit_dir(rootfs);
            for oci_app_name in &app_names {
                let dropin_rel = format!("{unit_rel}/sdme-oci-{oci_app_name}.service.d");
                if opts.backend == Backend::Btrfs {
                    reject_symlinked_path(&root_dir, &dropin_rel)?;
                }
                let dropin_dir = root_dir.join(&dropin_rel);
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
    if !opts.masked_services.is_empty() {
        state.set("MASKED_SERVICES", opts.masked_services.join(","));
    }
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
            let oci_rel = format!("oci/apps/{oci_app_for_env}");
            if opts.backend == Backend::Btrfs {
                reject_symlinked_path(&root_dir, &oci_rel)?;
            }
            let upper_oci = root_dir.join(&oci_rel);
            fs::create_dir_all(&upper_oci)
                .with_context(|| format!("failed to create {}", upper_oci.display()))?;
            let upper_env = upper_oci.join("env");
            if opts.backend == Backend::Btrfs {
                shadow_symlink(&upper_env)?;
            }
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
    let c_name = CString::new("trusted.overlay.opaque").expect("static string literal");
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
