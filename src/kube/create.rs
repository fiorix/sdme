//! Kube pod creation and deletion orchestration.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};

use super::plan::*;
use crate::copy::make_removable;
use crate::import::shell_join;
use crate::oci::registry::OciContainerConfig;
use crate::{check_interrupted, validate_name, State};

/// Embedded `sdme-kube-probe` binary for Kubernetes probes.
///
/// Built separately via `cargo build --features probe --bin sdme-kube-probe`.
/// If the probe binary wasn't built, this is an empty slice and probe
/// creation will fail with a clear error message.
const PROBE_BINARY: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/sdme-kube-probe"));

/// Set ownership of a path to the given uid:gid.
fn chown_path(path: &Path, uid: u32, gid: u32) -> Result<()> {
    if uid == 0 && gid == 0 {
        return Ok(());
    }
    use std::ffi::CString;
    let c_path = CString::new(path.as_os_str().as_encoded_bytes())
        .with_context(|| format!("invalid path: {}", path.display()))?;
    let ret = unsafe { libc::lchown(c_path.as_ptr(), uid, gid) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        anyhow::bail!("failed to chown {}: {err}", path.display());
    }
    Ok(())
}

/// Create a kube pod: parse YAML, pull images, build combined rootfs, create container.
///
/// Returns the container name on success.
#[allow(clippy::too_many_arguments)]
pub fn kube_create(
    datadir: &Path,
    yaml_content: &str,
    base_fs: &str,
    docker_credentials: Option<(&str, &str)>,
    cache: &crate::oci::cache::BlobCache,
    pod: Option<&str>,
    oci_pod: Option<&str>,
    verbose: bool,
    http: &crate::config::HttpConfig,
) -> Result<String> {
    validate_name(base_fs)?;
    let base_dir = datadir.join("fs").join(base_fs);
    if !base_dir.is_dir() {
        bail!("base rootfs not found: {base_fs}");
    }

    let (pod_name, spec) = parse_yaml(yaml_content)?;
    let mut plan = validate_and_plan(&pod_name, spec)?;

    let rootfs_name = format!("kube-{}", plan.pod_name);
    let rootfs_dir = datadir.join("fs");
    let final_dir = rootfs_dir.join(&rootfs_name);
    let staging_name = format!(".{rootfs_name}.importing");
    let staging_dir = rootfs_dir.join(&staging_name);

    // If a kube pod already exists with this name, delete it first (idempotent apply).
    if final_dir.exists() {
        let state_path = datadir.join("state").join(&plan.pod_name);
        if state_path.exists() {
            let state = State::read_from(&state_path)?;
            if state.is_yes("KUBE") {
                eprintln!("replacing existing kube pod '{}'", plan.pod_name);
                kube_delete(datadir, &plan.pod_name, false, verbose)?;
            } else {
                bail!(
                    "rootfs already exists: {rootfs_name}; \
                     a non-kube container '{}' owns it (use --force with kube delete)",
                    plan.pod_name
                );
            }
        } else {
            bail!(
                "rootfs already exists: {rootfs_name}; \
                 no matching container found, remove it manually with: sdme fs rm {rootfs_name}"
            );
        }
    }

    // Clean up any leftover staging dir.
    if staging_dir.exists() {
        let _ = make_removable(&staging_dir);
        fs::remove_dir_all(&staging_dir)
            .with_context(|| format!("failed to remove {}", staging_dir.display()))?;
    }

    // 1. Copy base rootfs to staging dir.
    eprintln!("copying base rootfs '{base_fs}' to staging directory");
    fs::create_dir_all(&staging_dir)
        .with_context(|| format!("failed to create {}", staging_dir.display()))?;
    crate::copy::copy_tree(&base_dir, &staging_dir, verbose)
        .with_context(|| format!("failed to copy base rootfs from {}", base_dir.display()))?;

    // 2. Create /oci/apps/ and /oci/volumes/ directories.
    let apps_dir = staging_dir.join("oci/apps");
    fs::create_dir_all(&apps_dir)
        .with_context(|| format!("failed to create {}", apps_dir.display()))?;
    let volumes_dir = staging_dir.join("oci/volumes");
    fs::create_dir_all(&volumes_dir)
        .with_context(|| format!("failed to create {}", volumes_dir.display()))?;

    // Resolve the pod-level owner for volume directories. When runAsUser is
    // set, volumes must be owned by that user so the app process can read/write.
    let vol_uid = plan.run_as_user.unwrap_or(0);
    let vol_gid = plan.run_as_group.unwrap_or(vol_uid);

    // Create emptyDir volumes.
    for vol in &plan.volumes {
        if matches!(vol.kind, KubeVolumeKind::EmptyDir) {
            let vol_path = volumes_dir.join(&vol.name);
            fs::create_dir_all(&vol_path)
                .with_context(|| format!("failed to create volume dir {}", vol_path.display()))?;
            chown_path(&vol_path, vol_uid, vol_gid)?;
        }
    }

    // Populate secret volumes.
    for vol in &plan.volumes {
        if let KubeVolumeKind::Secret {
            ref secret_name,
            ref items,
            default_mode,
        } = vol.kind
        {
            let data = super::secret::read_data(datadir, secret_name).with_context(|| {
                format!(
                    "volume '{}': failed to read secret '{secret_name}'",
                    vol.name
                )
            })?;
            populate_volume_data(
                &volumes_dir,
                &vol.name,
                "secret",
                secret_name,
                items,
                default_mode,
                data,
            )?;
        }
    }

    // Populate configMap volumes.
    for vol in &plan.volumes {
        if let KubeVolumeKind::ConfigMap {
            ref configmap_name,
            ref items,
            default_mode,
        } = vol.kind
        {
            let data = super::configmap::read_data(datadir, configmap_name).with_context(|| {
                format!(
                    "volume '{}': failed to read configmap '{configmap_name}'",
                    vol.name
                )
            })?;
            populate_volume_data(
                &volumes_dir,
                &vol.name,
                "configmap",
                configmap_name,
                items,
                default_mode,
                data,
            )?;
        }
    }

    // Handle PVC volumes: create host-side directories and add bind mounts.
    for vol in &plan.volumes {
        if let KubeVolumeKind::Pvc(ref claim_name) = vol.kind {
            let host_dir = datadir.join("volumes").join(claim_name);
            fs::create_dir_all(&host_dir)
                .with_context(|| format!("failed to create {}", host_dir.display()))?;
            chown_path(&host_dir, vol_uid, vol_gid)?;
            let vol_path = volumes_dir.join(&vol.name);
            fs::create_dir_all(&vol_path)
                .with_context(|| format!("failed to create volume dir {}", vol_path.display()))?;
            plan.host_binds.push((
                host_dir.to_string_lossy().to_string(),
                format!("/oci/volumes/{}", vol.name),
            ));
        }
    }

    // 3. Pull each container image and set up its app directory.
    let unit_dir = staging_dir.join("etc/systemd/system");
    fs::create_dir_all(&unit_dir)
        .with_context(|| format!("failed to create {}", unit_dir.display()))?;
    let wants_dir = unit_dir.join("multi-user.target.wants");
    fs::create_dir_all(&wants_dir)
        .with_context(|| format!("failed to create {}", wants_dir.display()))?;

    // Collect init container names for dependency ordering.
    let init_container_names: Vec<String> = plan
        .init_containers
        .iter()
        .map(|c| c.name.clone())
        .collect();

    // Process init containers first, then regular containers.
    let all_containers: Vec<(&KubeContainer, bool)> = plan
        .init_containers
        .iter()
        .map(|c| (c, true))
        .chain(plan.containers.iter().map(|c| (c, false)))
        .collect();

    for (kc, is_init) in &all_containers {
        check_interrupted()?;

        let app_dir = apps_dir.join(&kc.name);
        let app_root = app_dir.join("root");
        fs::create_dir_all(&app_root)
            .with_context(|| format!("failed to create {}", app_root.display()))?;

        // Check imagePullPolicy before pulling.
        let should_pull = match kc.image_pull_policy.as_str() {
            "Never" => {
                eprintln!(
                    "skipping image pull for '{}' (imagePullPolicy: Never)",
                    kc.name
                );
                false
            }
            "IfNotPresent" => {
                let has_content = app_root.read_dir().is_ok_and(|mut d| d.next().is_some());
                if has_content {
                    eprintln!(
                        "skipping image pull for '{}' (imagePullPolicy: IfNotPresent, app root not empty)",
                        kc.name
                    );
                    false
                } else {
                    true
                }
            }
            _ => true, // "Always" or default
        };

        // Pull the image.
        let oci_config = if should_pull {
            crate::oci::registry::import_registry_image(
                &kc.image_ref,
                &app_root,
                docker_credentials,
                cache,
                verbose,
                http,
            )
            .with_context(|| format!("failed to pull image for container '{}'", kc.name))?
        } else {
            None
        };

        // Set up the app.
        setup_kube_container(
            datadir,
            &staging_dir,
            &app_dir,
            kc,
            oci_config.as_ref(),
            &plan.restart_policy,
            &plan.volumes,
            &plan,
            *is_init,
            &init_container_names,
            verbose,
        )
        .with_context(|| format!("failed to set up container '{}'", kc.name))?;
    }

    // 3b. Deploy probe binary if any containers have probes.
    let has_probes = plan
        .init_containers
        .iter()
        .chain(plan.containers.iter())
        .any(|kc| {
            kc.probes.startup.is_some()
                || kc.probes.liveness.is_some()
                || kc.probes.readiness.is_some()
        });
    if has_probes {
        if PROBE_BINARY.is_empty() {
            bail!(
                "probe binary not available; build with: \
                 cargo build --features probe --bin sdme-kube-probe"
            );
        }
        let probe_path = staging_dir.join("oci/.sdme-kube-probe");
        fs::write(&probe_path, PROBE_BINARY)
            .with_context(|| format!("failed to write {}", probe_path.display()))?;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&probe_path, fs::Permissions::from_mode(0o755))
            .with_context(|| format!("failed to set permissions on {}", probe_path.display()))?;
        if verbose {
            eprintln!(
                "deployed probe binary ({} bytes): {}",
                PROBE_BINARY.len(),
                probe_path.display()
            );
        }
    }

    // 4. Generate sdme-kube-volumes.service for shared volume mounts.
    //
    // This oneshot service runs `mount --bind` in the container's PID 1 mount
    // namespace so all OCI app services see the same shared directories.
    let has_volume_mounts = plan
        .init_containers
        .iter()
        .chain(plan.containers.iter())
        .any(|kc| !kc.volume_mounts.is_empty());
    if has_volume_mounts {
        let mut exec_lines = Vec::new();
        for kc in plan.init_containers.iter().chain(plan.containers.iter()) {
            for vm in &kc.volume_mounts {
                let src = format!("/oci/volumes/{}", vm.volume_name);
                let dst = format!("/oci/apps/{}/root{}", kc.name, vm.mount_path);
                exec_lines.push(format!("ExecStart=/bin/mount --bind {src} {dst}"));
                if vm.read_only {
                    exec_lines.push(format!("ExecStart=/bin/mount -o remount,ro,bind {dst}"));
                }
            }
        }
        let vol_unit = format!(
            "\
# Generated by sdme kube
[Unit]
Description=Kube volume mounts
DefaultDependencies=no
After=local-fs.target

[Service]
Type=oneshot
RemainAfterExit=yes
{}

[Install]
WantedBy=multi-user.target
",
            exec_lines.join("\n")
        );
        let vol_unit_path = unit_dir.join("sdme-kube-volumes.service");
        fs::write(&vol_unit_path, &vol_unit)
            .with_context(|| format!("failed to write {}", vol_unit_path.display()))?;
        // Enable via symlink.
        let symlink_path = wants_dir.join("sdme-kube-volumes.service");
        std::os::unix::fs::symlink(
            "/etc/systemd/system/sdme-kube-volumes.service",
            &symlink_path,
        )
        .with_context(|| format!("failed to symlink {}", symlink_path.display()))?;
    }

    // 5. Atomic rename.
    fs::rename(&staging_dir, &final_dir).with_context(|| {
        format!(
            "failed to rename {} to {}",
            staging_dir.display(),
            final_dir.display()
        )
    })?;

    eprintln!("created rootfs: {rootfs_name}");

    // 5. Create the sdme container.
    let yaml_hash = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(yaml_content.as_bytes());
        format!("{:x}", hasher.finalize())
    };

    let container_names: Vec<&str> = plan
        .init_containers
        .iter()
        .chain(plan.containers.iter())
        .map(|c| c.name.as_str())
        .collect();

    // Build bind mounts for hostPath volumes only.
    let bind_strings: Vec<String> = plan
        .host_binds
        .iter()
        .map(|(host_path, container_path)| format!("{host_path}:{container_path}:rw"))
        .collect();
    let binds = crate::BindConfig {
        binds: bind_strings,
    };

    // Build port forwarding.
    let mut network = crate::NetworkConfig::default();
    if !plan.ports.is_empty() {
        network.private_network = true;
        for p in &plan.ports {
            let proto = p.protocol.as_deref().unwrap_or("tcp").to_lowercase();
            let port_str = format!("{proto}:{0}:{0}", p.container_port);
            network.ports.push(port_str);
        }
    }

    // --oci-pod requires private network for CAP_NET_ADMIN.
    if oci_pod.is_some() {
        network.private_network = true;
    }

    let opts = crate::containers::CreateOptions {
        name: Some(plan.pod_name.clone()),
        rootfs: Some(rootfs_name.clone()),
        network,
        binds,
        pod: pod.map(String::from),
        oci_pod: oci_pod.map(String::from),
        ..Default::default()
    };
    let name = crate::containers::create(datadir, &opts, verbose)?;

    // Write kube-specific state fields.
    let state_path = datadir.join("state").join(&name);
    let mut state = State::read_from(&state_path)?;
    state.set("KUBE", "yes");
    state.set("KUBE_CONTAINERS", container_names.join(","));
    state.set("KUBE_YAML_HASH", &yaml_hash);
    if has_probes {
        state.set("HAS_PROBES", "yes");
    }
    state.write_to(&state_path)?;

    Ok(name)
}

/// Delete a kube pod: stop container, remove container, remove rootfs.
pub fn kube_delete(datadir: &Path, name: &str, force: bool, verbose: bool) -> Result<()> {
    validate_name(name)?;

    let state_path = datadir.join("state").join(name);
    if !state_path.exists() {
        bail!("container not found: {name}");
    }

    let state = State::read_from(&state_path)?;
    if !state.is_yes("KUBE") && !force {
        bail!("container '{name}' is not a kube pod; use --force to delete anyway");
    }

    let rootfs_name = state.rootfs().to_string();

    // Stop and remove the container.
    crate::containers::remove(datadir, name, verbose)?;

    // Remove the rootfs.
    if !rootfs_name.is_empty() {
        let rootfs_path = datadir.join("fs").join(&rootfs_name);
        if rootfs_path.exists() {
            eprintln!("removing rootfs: {rootfs_name}");
            let _ = make_removable(&rootfs_path);
            fs::remove_dir_all(&rootfs_path)
                .with_context(|| format!("failed to remove {}", rootfs_path.display()))?;
        }
    }

    Ok(())
}

// --- Per-container setup ---

/// Set up a single container app inside the combined rootfs.
///
/// Builds the K8s command/args overrides, merges env vars, constructs volume
/// bind paths, then delegates to `setup_oci_app()` for the common logic.
#[allow(clippy::too_many_arguments)]
pub(crate) fn setup_kube_container(
    datadir: &Path,
    staging_dir: &Path,
    app_dir: &Path,
    kc: &KubeContainer,
    oci_config: Option<&OciContainerConfig>,
    restart_policy: &str,
    _volumes: &[KubeVolume],
    plan: &KubePlan,
    is_init: bool,
    init_container_names: &[String],
    verbose: bool,
) -> Result<()> {
    let app_root = app_dir.join("root");
    let default_config = OciContainerConfig::default();
    let config = oci_config.unwrap_or(&default_config);

    // Build ExecStart from command/args overrides per K8s semantics:
    // - K8s `command` replaces Docker ENTRYPOINT
    // - K8s `args` replaces Docker CMD
    // - If only `args`, keep original ENTRYPOINT
    let mut exec_args: Vec<String> = Vec::new();
    if let Some(ref cmd_override) = kc.command_override {
        exec_args.extend(cmd_override.iter().cloned());
    } else if let Some(ref ep) = config.entrypoint {
        exec_args.extend(ep.iter().cloned());
    }
    if let Some(ref args_override) = kc.args_override {
        exec_args.extend(args_override.iter().cloned());
    } else if kc.command_override.is_none() {
        if let Some(ref cmd) = config.cmd {
            exec_args.extend(cmd.iter().cloned());
        }
    }
    if exec_args.is_empty() {
        bail!(
            "container '{}': no command to run (no entrypoint/cmd in image and no command/args override)",
            kc.name
        );
    }
    let exec_start = shell_join(&exec_args);

    // Use workingDir override from YAML, then OCI config, then "/".
    let working_dir = kc
        .working_dir_override
        .as_deref()
        .or(config.working_dir.as_deref())
        .unwrap_or("/");

    // Use container-level securityContext user override, then pod-level, then OCI config.
    let user_override;
    let user = if let Some(uid) = kc.run_as_user.or(plan.run_as_user) {
        let gid = kc.run_as_group.or(plan.run_as_group).unwrap_or(uid);
        user_override = format!("{uid}:{gid}");
        &user_override
    } else {
        config.user.as_deref().unwrap_or("root")
    };

    // Merge env: OCI image env + K8s env overrides (by key).
    let mut env_lines: Vec<String> = Vec::new();
    if let Some(ref image_env) = config.env {
        env_lines.extend(image_env.iter().cloned());
    }
    let mut seen_keys: HashMap<String, usize> = HashMap::new();
    for (i, line) in env_lines.iter().enumerate() {
        if let Some(key) = line.split('=').next() {
            seen_keys.insert(key.to_string(), i);
        }
    }
    for (key, env_val) in &kc.env {
        // envFrom variants expand into multiple key-value pairs.
        let pairs: Vec<(String, String)> = match env_val {
            KubeEnvValue::Literal(v) => vec![(key.clone(), v.clone())],
            KubeEnvValue::SecretKeyRef { name, key: k } => {
                let data = super::secret::read_data(datadir, name)
                    .with_context(|| format!("env '{key}': failed to read secret '{name}'"))?;
                let (_, contents) = data
                    .iter()
                    .find(|(dk, _)| dk == k)
                    .with_context(|| format!("env '{key}': secret '{name}' has no key '{k}'"))?;
                let value = String::from_utf8(contents.clone()).with_context(|| {
                    format!("env '{key}': secret '{name}' key '{k}' is not valid UTF-8")
                })?;
                vec![(key.clone(), value)]
            }
            KubeEnvValue::ConfigMapKeyRef { name, key: k } => {
                let data = super::configmap::read_data(datadir, name)
                    .with_context(|| format!("env '{key}': failed to read configmap '{name}'"))?;
                let (_, contents) = data
                    .iter()
                    .find(|(dk, _)| dk == k)
                    .with_context(|| format!("env '{key}': configmap '{name}' has no key '{k}'"))?;
                let value = String::from_utf8(contents.clone()).with_context(|| {
                    format!("env '{key}': configmap '{name}' key '{k}' is not valid UTF-8")
                })?;
                vec![(key.clone(), value)]
            }
            KubeEnvValue::SecretRef { name, prefix } => {
                let data = super::secret::read_data(datadir, name)
                    .with_context(|| format!("envFrom: failed to read secret '{name}'"))?;
                data.into_iter()
                    .map(|(k, v)| {
                        let value = String::from_utf8(v).with_context(|| {
                            format!("envFrom: secret '{name}' key '{k}' is not valid UTF-8")
                        })?;
                        Ok((format!("{prefix}{k}"), value))
                    })
                    .collect::<Result<Vec<_>>>()?
            }
            KubeEnvValue::ConfigMapRef { name, prefix } => {
                let data = super::configmap::read_data(datadir, name)
                    .with_context(|| format!("envFrom: failed to read configmap '{name}'"))?;
                data.into_iter()
                    .map(|(k, v)| {
                        let value = String::from_utf8(v).with_context(|| {
                            format!("envFrom: configmap '{name}' key '{k}' is not valid UTF-8")
                        })?;
                        Ok((format!("{prefix}{k}"), value))
                    })
                    .collect::<Result<Vec<_>>>()?
            }
        };
        for (k, v) in pairs {
            let line = format!("{k}={v}");
            if let Some(&idx) = seen_keys.get(&k) {
                env_lines[idx] = line;
            } else {
                seen_keys.insert(k, env_lines.len());
                env_lines.push(line);
            }
        }
    }

    // Create mount point directories inside the app root (needed as bind targets
    // for sdme-kube-volumes.service). Owned by the container's effective user so
    // the app process can access them.
    let mount_uid = kc.run_as_user.or(plan.run_as_user).unwrap_or(0);
    let mount_gid = kc.run_as_group.or(plan.run_as_group).unwrap_or(mount_uid);
    for vm in &kc.volume_mounts {
        let mount_dir = app_root.join(vm.mount_path.trim_start_matches('/'));
        fs::create_dir_all(&mount_dir)
            .with_context(|| format!("failed to create mount point {}", mount_dir.display()))?;
        chown_path(&mount_dir, mount_uid, mount_gid)?;
    }

    // If there are volume mounts, add ordering dependency on the volume mount service.
    let extra_after = if kc.volume_mounts.is_empty() {
        vec![]
    } else {
        vec!["sdme-kube-volumes.service".to_string()]
    };

    // Build unit ordering dependencies for regular containers:
    // they depend on all init containers.
    let (after_units, requires_units) = if !is_init && !init_container_names.is_empty() {
        let after: Vec<String> = init_container_names
            .iter()
            .map(|n| format!("sdme-oci-{n}.service"))
            .collect();
        (after.clone(), after)
    } else {
        (Vec::new(), Vec::new())
    };

    // Build per-service security overrides from merged pod+container security context.
    let security = {
        // Seccomp: container overrides pod. If the container explicitly set a
        // seccomp profile (even Unconfined with empty filters), use the container's
        // filters and skip the pod-level fallback.
        let syscall_filters = if kc.has_seccomp_profile {
            kc.syscall_filters.clone()
        } else if let Some(ref spt) = plan.seccomp_profile_type {
            match spt.as_str() {
                "RuntimeDefault" => crate::security::STRICT_SYSCALL_FILTERS
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
                _ => Vec::new(), // Unconfined
            }
        } else {
            Vec::new()
        };

        // AppArmor: container overrides pod.
        let apparmor_profile = if kc.apparmor_profile.is_some() {
            kc.apparmor_profile.clone()
        } else {
            plan.apparmor_profile.clone()
        };
        // Filter out empty string (Unconfined resolved to "").
        let apparmor_profile = apparmor_profile.filter(|s| !s.is_empty());

        let has_overrides = !kc.add_caps.is_empty()
            || !kc.drop_caps.is_empty()
            || kc.allow_privilege_escalation.is_some()
            || kc.read_only_root_filesystem
            || !syscall_filters.is_empty()
            || apparmor_profile.is_some();

        if has_overrides {
            Some(crate::oci::app::OciServiceSecurity {
                add_caps: kc.add_caps.clone(),
                drop_caps: kc.drop_caps.clone(),
                allow_privilege_escalation: kc.allow_privilege_escalation,
                read_only_root_filesystem: kc.read_only_root_filesystem,
                syscall_filters,
                apparmor_profile,
            })
        } else {
            None
        }
    };

    crate::oci::app::setup_oci_app(&crate::oci::app::OciAppSetup {
        name: &kc.name,
        staging_dir,
        app_dir,
        app_root: &app_root,
        exec_start: &exec_start,
        working_dir,
        user,
        env_lines,
        config,
        image_ref: &kc.image,
        restart_policy: Some(restart_policy),
        bind_paths: vec![],
        extra_after,
        verbose,
        timeout_stop_sec: plan.termination_grace_period,
        resource_lines: kc.resource_lines.clone(),
        unit_type: if is_init { Some("oneshot") } else { None },
        remain_after_exit: is_init,
        after_units,
        requires_units,
        readiness_exec: None,
        probes: Some(kc.probes.clone()),
        security,
    })
}

/// Write key-value data into a volume directory, applying file permissions.
///
/// Used by both secret and configMap volume population. When `items` is empty,
/// all keys are written; otherwise only the projected key→path pairs.
fn populate_volume_data(
    volumes_dir: &Path,
    vol_name: &str,
    source_noun: &str,
    source_name: &str,
    items: &[(String, String)],
    default_mode: u32,
    data: Vec<(String, Vec<u8>)>,
) -> Result<()> {
    let vol_path = volumes_dir.join(vol_name);
    fs::create_dir_all(&vol_path)
        .with_context(|| format!("failed to create volume dir {}", vol_path.display()))?;

    if items.is_empty() {
        for (key, contents) in &data {
            let file_path = vol_path.join(key);
            fs::write(&file_path, contents)
                .with_context(|| format!("failed to write {}", file_path.display()))?;
            set_file_mode(&file_path, default_mode)?;
        }
    } else {
        let data_map: HashMap<&str, &[u8]> = data
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_slice()))
            .collect();
        for (key, path) in items {
            let contents = data_map.get(key.as_str()).with_context(|| {
                format!("volume '{vol_name}': {source_noun} '{source_name}' has no key '{key}'")
            })?;
            let file_path = vol_path.join(path);
            if let Some(parent) = file_path.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("failed to create {}", parent.display()))?;
            }
            fs::write(&file_path, contents)
                .with_context(|| format!("failed to write {}", file_path.display()))?;
            set_file_mode(&file_path, default_mode)?;
        }
    }
    Ok(())
}

/// Set file permissions to the given mode.
fn set_file_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("failed to set permissions on {}", path.display()))
}
