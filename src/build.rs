//! Build root filesystems from a Dockerfile-like configuration.
//!
//! Parses a build config with FROM, COPY, and RUN directives, creates a
//! temporary staging container, executes build operations sequentially,
//! then captures the resulting merged filesystem as a new rootfs.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use sha2::{Digest, Sha256};

use crate::copy::sanitize_dest_path;
use crate::{check_interrupted, containers, copy, lock, rootfs, systemd, validate_name, State};

// --- Config types ---

#[derive(Debug)]
struct BuildConfig {
    path: PathBuf,
    rootfs: String,
    ops: Vec<BuildOp>,
}

/// Source location for a COPY directive.
#[derive(Debug)]
enum CopySource {
    /// Host filesystem path (no prefix): `COPY /host/path /dst`
    Host(PathBuf),
    /// Another container: `COPY container-name:/path /dst`
    Container { name: String, path: PathBuf },
    /// Imported rootfs: `COPY fs:name:/path /dst`
    Rootfs { name: String, path: PathBuf },
}

#[derive(Debug)]
enum BuildOp {
    Copy {
        src: CopySource,
        dst: PathBuf,
        lineno: usize,
    },
    Run {
        command: String,
        lineno: usize,
    },
}

// --- Parser ---

fn parse_copy_source(src: &str, config_path: &Path, lineno: usize) -> Result<CopySource> {
    if let Some(rest) = src.strip_prefix("fs:") {
        // fs:name:/path
        let (name, path) = rest.split_once(':').ok_or_else(|| {
            anyhow::anyhow!(
                "{}:{}: COPY fs: source requires fs:name:/path format",
                config_path.display(),
                lineno
            )
        })?;
        if name.is_empty() {
            bail!(
                "{}:{}: COPY fs: source name is empty",
                config_path.display(),
                lineno
            );
        }
        validate_name(name).with_context(|| {
            format!(
                "{}:{}: invalid COPY fs source name",
                config_path.display(),
                lineno
            )
        })?;
        if path.is_empty() || !path.starts_with('/') {
            bail!(
                "{}:{}: COPY fs: source path must be absolute",
                config_path.display(),
                lineno
            );
        }
        Ok(CopySource::Rootfs {
            name: name.to_string(),
            path: PathBuf::from(path),
        })
    } else if let Some((maybe_name, path)) = src.split_once(':') {
        // container-name:/path (only if the part before : is a valid name)
        if validate_name(maybe_name).is_ok() {
            if path.is_empty() || !path.starts_with('/') {
                bail!(
                    "{}:{}: COPY container source path must be absolute",
                    config_path.display(),
                    lineno
                );
            }
            Ok(CopySource::Container {
                name: maybe_name.to_string(),
                path: PathBuf::from(path),
            })
        } else {
            // Not a valid container name, treat as a host path (e.g. /path:with:colons)
            Ok(CopySource::Host(PathBuf::from(src)))
        }
    } else {
        Ok(CopySource::Host(PathBuf::from(src)))
    }
}

fn parse_build_config(path: &Path) -> Result<BuildConfig> {
    let content =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;

    let mut rootfs: Option<String> = None;
    let mut ops = Vec::new();

    // Join backslash-continued lines into logical lines, tracking
    // the starting line number (1-based) of each logical line.
    let mut logical_lines: Vec<(usize, String)> = Vec::new();
    let mut current: Option<(usize, String)> = None;

    for (i, raw) in content.lines().enumerate() {
        let trimmed = raw.trim_end();
        let (text, continues) = match trimmed.strip_suffix('\\') {
            Some(before) => (before.trim_end(), true),
            None => (trimmed, false),
        };
        if let Some((_, ref mut buf)) = current {
            buf.push(' ');
            buf.push_str(text.trim_start());
            if !continues {
                logical_lines.push(current.take().unwrap());
            }
        } else if continues {
            current = Some((i + 1, text.to_string()));
        } else {
            logical_lines.push((i + 1, text.to_string()));
        }
    }
    if let Some(pending) = current {
        logical_lines.push(pending);
    }

    for &(lineno, ref raw) in &logical_lines {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let (directive, rest) = match line.split_once(char::is_whitespace) {
            Some((d, r)) => (d, r.trim()),
            None => (line, ""),
        };

        match directive {
            "FROM" => {
                if rootfs.is_some() {
                    bail!("{}:{}: duplicate FROM directive", path.display(), lineno);
                }
                if rest.is_empty() {
                    bail!("{}:{}: FROM requires a rootfs name", path.display(), lineno);
                }
                // Support both `FROM ubuntu` and `FROM fs:ubuntu`.
                let rootfs_name = rest.strip_prefix("fs:").unwrap_or(rest);
                validate_name(rootfs_name).with_context(|| {
                    format!("{}:{}: invalid FROM rootfs name", path.display(), lineno)
                })?;
                rootfs = Some(rootfs_name.to_string());
            }
            "COPY" => {
                if rootfs.is_none() {
                    bail!(
                        "{}:{}: FROM must be the first directive",
                        path.display(),
                        lineno
                    );
                }
                let (src, dst) = rest.split_once(char::is_whitespace).ok_or_else(|| {
                    anyhow::anyhow!(
                        "{}:{}: COPY requires two arguments: COPY <src> <dst>",
                        path.display(),
                        lineno
                    )
                })?;
                let dst = dst.trim();
                if dst.is_empty() {
                    bail!(
                        "{}:{}: COPY requires two arguments: COPY <src> <dst>",
                        path.display(),
                        lineno
                    );
                }
                let copy_src = parse_copy_source(src, path, lineno)?;
                ops.push(BuildOp::Copy {
                    src: copy_src,
                    dst: PathBuf::from(dst),
                    lineno,
                });
            }
            "RUN" => {
                if rootfs.is_none() {
                    bail!(
                        "{}:{}: FROM must be the first directive",
                        path.display(),
                        lineno
                    );
                }
                if rest.is_empty() {
                    bail!("{}:{}: RUN requires a command", path.display(), lineno);
                }
                ops.push(BuildOp::Run {
                    command: rest.to_string(),
                    lineno,
                });
            }
            _ => {
                bail!(
                    "{}:{}: unknown directive: {directive}",
                    path.display(),
                    lineno
                );
            }
        }
    }

    let rootfs =
        rootfs.ok_or_else(|| anyhow::anyhow!("{}: missing FROM directive", path.display()))?;

    Ok(BuildConfig {
        path: path.to_path_buf(),
        rootfs,
        ops,
    })
}

// --- Source resolution ---

struct ResolvedSource {
    path: PathBuf,
    /// If we temporarily mounted overlayfs, this guard handles unmount on drop.
    _mount_guard: Option<containers::OverlayGuard>,
    /// Resource lock held for the duration of the copy.
    _lock: Option<lock::ResourceLock>,
}

fn resolve_copy_source(datadir: &Path, src: &CopySource, verbose: bool) -> Result<ResolvedSource> {
    match src {
        CopySource::Host(path) => Ok(ResolvedSource {
            path: path.clone(),
            _mount_guard: None,
            _lock: None,
        }),
        CopySource::Rootfs { name, path } => {
            validate_name(name)?;
            let rootfs_dir = datadir.join("fs").join(name);
            if !rootfs_dir.is_dir() {
                bail!("COPY source fs not found: {name}");
            }
            let lock = lock::lock_shared(datadir, "fs", name)
                .with_context(|| format!("cannot read-lock rootfs '{name}' for COPY"))?;
            let full_path = rootfs_dir.join(path.strip_prefix("/").unwrap_or(path));
            Ok(ResolvedSource {
                path: full_path,
                _mount_guard: None,
                _lock: Some(lock),
            })
        }
        CopySource::Container { name, path } => {
            containers::ensure_exists(datadir, name)?;
            let lock = lock::lock_shared(datadir, "containers", name)
                .with_context(|| format!("cannot read-lock container '{name}' for COPY"))?;
            let container_dir = datadir.join("containers").join(name);

            let (guard, resolved_path) = if systemd::is_active(name)? {
                eprintln!(
                    "warning: copying from running container '{name}'; \
                     data may be inconsistent"
                );
                let full_path = container_dir
                    .join("merged")
                    .join(path.strip_prefix("/").unwrap_or(path));
                (None, full_path)
            } else {
                // Stopped: mount a read-only overlay view.
                let state_path = datadir.join("state").join(name);
                let state = State::read_from(&state_path)?;
                let rootfs_name = state.rootfs();
                let rootfs_dir = if rootfs_name.is_empty() {
                    PathBuf::from("/")
                } else {
                    datadir.join("fs").join(rootfs_name)
                };
                if verbose {
                    eprintln!("mounting read-only overlay for container '{name}'");
                }
                containers::mount_overlay_ro(&rootfs_dir, &container_dir)?;
                let full_path = container_dir
                    .join("merged")
                    .join(path.strip_prefix("/").unwrap_or(path));
                (
                    Some(containers::OverlayGuard {
                        container_dir: container_dir.clone(),
                    }),
                    full_path,
                )
            };

            Ok(ResolvedSource {
                path: resolved_path,
                _mount_guard: guard,
                _lock: Some(lock),
            })
        }
    }
}

// --- Execution engine ---

fn run_in_container(name: &str, command: &str, verbose: bool) -> Result<()> {
    if verbose {
        eprintln!("run: {command}");
    }
    let status = std::process::Command::new("systemd-run")
        .args([
            "--machine",
            name,
            "--pipe",
            "--wait",
            "--quiet",
            "/bin/sh",
            "-c",
            command,
        ])
        .status()
        .context("failed to run systemd-run")?;
    crate::check_interrupted()?;
    if !status.success() {
        bail!(
            "command failed with exit code {}",
            status.code().unwrap_or(-1)
        );
    }
    Ok(())
}

/// Directories that systemd mounts tmpfs over at boot, hiding any files
/// written to the overlayfs upper layer underneath.
#[cfg(test)]
const SHADOWED_DIRS: &[&str] = &["/tmp", "/run", "/dev/shm"];

/// Shadowed directories for build context: /tmp is excluded because
/// build containers bind-mount upper/tmp over nspawn's tmpfs, making /tmp persistent.
const BUILD_SHADOWED_DIRS: &[&str] = &["/run", "/dev/shm"];

/// Check if `dst` falls under a directory that is shadowed by a tmpfs
/// mount at boot or marked as overlayfs-opaque, meaning files written
/// to the upper layer would be invisible in the running container.
fn check_shadowed_dest(dst: &Path, shadowed: &[&str], opaque_dirs: &[String]) -> Result<()> {
    let dst_str = dst.to_string_lossy();
    for dir in shadowed {
        if dst_str == *dir || dst_str.starts_with(&format!("{dir}/")) {
            bail!(
                "COPY to {dst_str} is not supported: systemd mounts tmpfs over {dir} at boot, \
                 hiding files in the overlayfs upper layer; use a different destination"
            );
        }
    }
    for dir in opaque_dirs {
        if dst_str == *dir || dst_str.starts_with(&format!("{dir}/")) {
            bail!(
                "COPY to {dst_str} is not supported: {dir} is an overlayfs opaque directory, \
                 hiding lower-layer contents; use a different destination"
            );
        }
    }
    Ok(())
}

/// Context for COPY operations during a build, shared across all copy steps.
struct CopyContext<'a> {
    upper_dir: &'a Path,
    check_dir: &'a Path,
    shadowed: &'a [&'a str],
    opaque_dirs: &'a [String],
    verbose: bool,
}

fn do_copy(ctx: &CopyContext, src: &Path, dst: &Path) -> Result<()> {
    check_shadowed_dest(dst, ctx.shadowed, ctx.opaque_dirs)?;
    let rel_dst = sanitize_dest_path(dst)?;
    let mut target = ctx.upper_dir.join(&rel_dst);

    let meta =
        fs::symlink_metadata(src).with_context(|| format!("failed to stat {}", src.display()))?;

    // Check whether dst resolves to a directory in either layer.
    let dst_is_dir = target.is_dir() || ctx.check_dir.join(&rel_dst).is_dir();

    // Check whether dst resolves to a file in either layer.
    let dst_is_file = (!dst_is_dir) && (target.is_file() || ctx.check_dir.join(&rel_dst).is_file());

    // Cannot copy a directory onto an existing file.
    if meta.is_dir() && dst_is_file {
        bail!(
            "cannot copy directory {} to existing file {}",
            src.display(),
            dst.display()
        );
    }

    // When dst is an existing directory, adjust the target:
    // - If src has a file_name (file or named dir), copy INTO the directory.
    // - If src has no file_name (bare "."), copy contents directly into dst.
    if dst_is_dir {
        if let Some(file_name) = src.file_name() {
            target = target.join(file_name);
        }
    }

    if ctx.verbose {
        eprintln!("copy: {} -> {}", src.display(), target.display());
    }

    // Create parent directories in the upper layer.
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    if meta.is_dir() {
        fs::create_dir_all(&target)
            .with_context(|| format!("failed to create {}", target.display()))?;
        copy::copy_tree(src, &target, ctx.verbose)
            .with_context(|| format!("failed to copy directory {}", src.display()))?;
    } else {
        copy::copy_entry(src, &target, ctx.verbose)
            .with_context(|| format!("failed to copy {}", src.display()))?;
    }

    Ok(())
}

struct ExecuteBuildContext<'a> {
    container_name: &'a str,
    config: &'a BuildConfig,
    opaque_dirs: &'a [String],
    boot_timeout: u64,
    tasks_max: u32,
    /// Number of ops to skip (already completed in a previous run).
    skip_ops: usize,
    verbose: bool,
}

fn execute_build(datadir: &Path, ctx: &ExecuteBuildContext<'_>) -> Result<()> {
    let mut container_running = false;
    let timeout = std::time::Duration::from_secs(ctx.boot_timeout);
    let total = ctx.config.ops.len();
    let state_path = datadir.join("state").join(ctx.container_name);

    // Eagerly start the container before any ops. This ensures:
    // 1. systemd-tmpfiles cleanup of /tmp has finished before any COPY
    // 2. The merged overlayfs view is available for dst existence checks
    // Without this, COPY to /tmp before the first RUN would write to
    // upper/tmp, but systemd-tmpfiles cleans /tmp during boot and
    // deletes the file.
    if !ctx.config.ops.is_empty() {
        eprintln!("starting build container '{}'", ctx.container_name);
        systemd::start(&systemd::ServiceConfig {
            datadir,
            name: ctx.container_name,
            tasks_max: ctx.tasks_max,
            boot_timeout: ctx.boot_timeout,
            verbose: ctx.verbose,
        })?;
        match systemd::await_boot(ctx.container_name, timeout, ctx.verbose) {
            systemd::BootOutcome::Ready => {}
            systemd::BootOutcome::TimedOut(e) | systemd::BootOutcome::Exited(e) => return Err(e),
        }
        container_running = true;
    }

    for (i, op) in ctx.config.ops.iter().enumerate() {
        check_interrupted()?;

        let step = format!("[{}/{}]", i + 1, total);
        let summary = op_summary(op);

        if i < ctx.skip_ops {
            eprintln!("{step} {summary} (cached)");
            continue;
        }

        eprintln!("{step} {summary}");

        match op {
            BuildOp::Run { command, lineno } => {
                run_in_container(ctx.container_name, command, ctx.verbose)
                    .with_context(|| format!("{}:{}", ctx.config.path.display(), lineno))?;
            }
            BuildOp::Copy { src, dst, lineno } => {
                // Hot COPY: container stays running. Files are written through
                // the merged overlayfs mount so the kernel properly updates
                // its dcache and the changes are immediately visible inside
                // the container. Writing directly to upper/ while overlayfs
                // is mounted is undefined behavior per the kernel docs.
                let resolved = resolve_copy_source(datadir, src, ctx.verbose)?;
                let container_dir = datadir.join("containers").join(ctx.container_name);
                let (write_dir, check_dir) = if container_running {
                    // Write through merged overlayfs; check against merged view.
                    let merged = container_dir.join("merged");
                    (merged.clone(), merged)
                } else {
                    // Container stopped: write to upper, check against rootfs.
                    (
                        container_dir.join("upper"),
                        datadir.join("fs").join(&ctx.config.rootfs),
                    )
                };
                let copy_ctx = CopyContext {
                    upper_dir: &write_dir,
                    check_dir: &check_dir,
                    shadowed: BUILD_SHADOWED_DIRS,
                    opaque_dirs: ctx.opaque_dirs,
                    verbose: ctx.verbose,
                };
                do_copy(&copy_ctx, &resolved.path, dst)
                    .with_context(|| format!("{}:{}", ctx.config.path.display(), lineno))?;
            }
        }

        // Mark this op as completed in the state file.
        let mut state = State::read_from(&state_path)?;
        state.set("BUILD_LAST_COMPLETED_OP", i.to_string());
        state.write_to(&state_path)?;
    }

    // Ensure container is stopped; overlayfs must be unmounted for merged layer copy.
    if container_running {
        eprintln!("stopping build container '{}'", ctx.container_name);
        containers::stop(
            ctx.container_name,
            containers::StopMode::Terminate,
            30,
            ctx.verbose,
        )?;
    }

    Ok(())
}

// --- Hashing ---

/// Compute SHA-256 hex digest of a file's contents.
fn config_hash(path: &Path) -> Result<String> {
    let data = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let hash = Sha256::digest(&data);
    Ok(format!("{hash:x}"))
}

/// Return a short summary of a build op for progress output.
fn op_summary(op: &BuildOp) -> String {
    match op {
        BuildOp::Run { command, .. } => {
            if command.len() > 60 {
                format!("RUN {}...", &command[..60])
            } else {
                format!("RUN {command}")
            }
        }
        BuildOp::Copy { src, dst, .. } => {
            let src_str = match src {
                CopySource::Host(p) => p.display().to_string(),
                CopySource::Container { name, path } => format!("{name}:{}", path.display()),
                CopySource::Rootfs { name, path } => format!("fs:{name}:{}", path.display()),
            };
            format!("COPY {src_str} {}", dst.display())
        }
    }
}

// --- Main entry point ---

/// Options for building a root filesystem from a configuration file.
pub struct BuildOptions<'a> {
    /// Name for the output rootfs.
    pub name: &'a str,
    /// Path to the build configuration file.
    pub config_path: &'a Path,
    /// Timeout in seconds for container boot during RUN steps.
    pub boot_timeout: u64,
    /// Maximum number of tasks for the build container.
    pub tasks_max: u32,
    /// Overwrite existing rootfs if it already exists.
    pub force: bool,
    /// Automatically clean up stale transactions before building.
    pub auto_gc: bool,
    /// Do not resume from a previous failed build.
    pub no_cache: bool,
    /// Enable verbose output.
    pub verbose: bool,
}

/// Build a root filesystem from a Dockerfile-like configuration file.
pub fn build(datadir: &Path, opts: &BuildOptions<'_>) -> Result<()> {
    let name = opts.name;
    let verbose = opts.verbose;
    validate_name(name)?;

    let fs_dir = datadir.join("fs");
    let final_dir = fs_dir.join(name);
    if final_dir.exists() {
        if !opts.force {
            bail!("fs already exists: {name}\nhint: use 'sdme fs build -f' to overwrite or 'sdme fs rm {name}' to remove it first");
        }
        eprintln!("removing existing fs '{name}'");
        rootfs::remove(datadir, name, opts.auto_gc, verbose)?;
    }

    let config = parse_build_config(opts.config_path)?;

    // Verify the FROM rootfs exists.
    let rootfs_dir = fs_dir.join(&config.rootfs);
    if !rootfs_dir.is_dir() {
        bail!("fs not found: {}", config.rootfs);
    }

    // Acquire locks: shared on FROM rootfs, exclusive on output rootfs and build container.
    let staging_name = format!("build-{name}");
    let _from_lock = lock::lock_shared(datadir, "fs", &config.rootfs)
        .with_context(|| format!("cannot lock FROM rootfs '{}'", config.rootfs))?;
    let _output_lock = lock::lock_exclusive(datadir, "fs", name)
        .with_context(|| format!("cannot lock output rootfs '{name}'"))?;

    // Compute config hash for resume detection.
    let hash = config_hash(opts.config_path)?;

    // Check for an existing build container and decide whether to resume.
    let state_path = datadir.join("state").join(&staging_name);
    let mut skip_ops = 0usize;
    let create_opts = containers::CreateOptions {
        name: Some(staging_name.clone()),
        rootfs: Some(config.rootfs.clone()),
        ..Default::default()
    };

    if state_path.exists() {
        if systemd::is_active(&staging_name)? {
            bail!(
                "build container '{staging_name}' is already running; \
                 is another build in progress?"
            );
        }

        if opts.no_cache {
            eprintln!("removing build container '{staging_name}' (--no-cache)");
            containers::remove(datadir, &staging_name, verbose)?;
        } else {
            // Check if config hash matches for resume.
            let state = State::read_from(&state_path)?;
            let saved_hash = state.get("BUILD_CONFIG_HASH").unwrap_or("");
            if saved_hash == hash {
                if let Some(last_op) = state.get("BUILD_LAST_COMPLETED_OP") {
                    if let Ok(idx) = last_op.parse::<usize>() {
                        skip_ops = idx + 1;
                        let total = config.ops.len();
                        eprintln!(
                            "resuming build '{staging_name}' from step {}/{total}",
                            skip_ops + 1
                        );
                    }
                }
            } else {
                eprintln!("config changed, removing build container '{staging_name}'");
                containers::remove(datadir, &staging_name, verbose)?;
            }
        }
    }

    // Create a fresh build container if one doesn't exist (removed above or never existed).
    let state_path = datadir.join("state").join(&staging_name);
    if !state_path.exists() {
        eprintln!("creating build container '{staging_name}'");
        containers::create(datadir, &create_opts, verbose)?;

        // Make /tmp persistent across RUN and COPY steps by bind-mounting
        // upper/tmp into the container. systemd-nspawn mounts tmpfs on /tmp
        // before systemd starts (masking tmp.mount doesn't prevent this), so
        // we bind-mount over the tmpfs to get a persistent /tmp backed by
        // the overlayfs upper layer.
        let upper_tmp = datadir
            .join("containers")
            .join(&staging_name)
            .join("upper/tmp");
        if !upper_tmp.exists() {
            fs::create_dir(&upper_tmp)
                .with_context(|| format!("failed to create {}", upper_tmp.display()))?;
        }
        fs::set_permissions(&upper_tmp, fs::Permissions::from_mode(0o1777))
            .with_context(|| format!("failed to set permissions on {}", upper_tmp.display()))?;

        // Add the /tmp bind mount and config hash to the container's state file.
        let mut state = State::read_from(&state_path)?;
        let bind_spec = format!("{}:/tmp:rw", upper_tmp.display());
        let existing_binds = state.get("BINDS").unwrap_or("").to_string();
        if existing_binds.is_empty() {
            state.set("BINDS", &bind_spec);
        } else {
            state.set("BINDS", format!("{existing_binds}|{bind_spec}"));
        }
        state.set("BUILD_CONFIG_HASH", &hash);
        state.write_to(&state_path)?;
    }

    // Execute all build operations; clean up on failure.
    if let Err(e) = execute_build(
        datadir,
        &ExecuteBuildContext {
            container_name: &staging_name,
            config: &config,
            opaque_dirs: &create_opts.opaque_dirs,
            boot_timeout: opts.boot_timeout,
            tasks_max: opts.tasks_max,
            skip_ops,
            verbose,
        },
    ) {
        let _guard = crate::InterruptGuard::save_and_reset();
        eprintln!("build failed, stopping '{staging_name}'");
        let _ = containers::stop(&staging_name, containers::StopMode::Terminate, 30, verbose);
        return Err(e);
    }

    // Capture the merged filesystem as the new rootfs.
    let container_dir = datadir.join("containers").join(&staging_name);
    let merged_dir = container_dir.join("merged");

    // Mount overlayfs to get the merged view (container is stopped, so we mount manually).
    if let Err(e) = containers::mount_overlay(&rootfs_dir, &container_dir) {
        eprintln!("build failed (mount), removing '{staging_name}'");
        let _ = containers::remove(datadir, &staging_name, verbose);
        return Err(e.context("failed to mount overlayfs for final copy"));
    }

    // Copy merged to staging rootfs, then atomic rename.
    let mut txn = crate::txn::Txn::new(
        &fs_dir,
        name,
        crate::txn::TxnKind::Build,
        opts.auto_gc,
        verbose,
    );
    txn.prepare()?;
    let staging_rootfs = txn.path().to_path_buf();

    let copy_result = (|| -> Result<()> {
        copy::copy_metadata(&merged_dir, &staging_rootfs)?;
        copy::copy_xattrs(&merged_dir, &staging_rootfs)?;
        if verbose {
            eprintln!(
                "copying {} -> {}",
                merged_dir.display(),
                staging_rootfs.display()
            );
        }
        copy::copy_tree(&merged_dir, &staging_rootfs, verbose)
    })();

    // Unmount regardless of copy result.
    containers::unmount_overlay(&container_dir);

    copy_result.context("failed to copy merged filesystem")?;

    // Atomic rename to final location.
    txn.commit(&final_dir)?;

    // Write distro metadata sidecar.
    let distro = rootfs::detect_distro(&final_dir);
    if !distro.is_empty() {
        let meta_path = fs_dir.join(format!(".{name}.meta"));
        let mut state = State::new();
        state.set("DISTRO", &distro);
        state.write_to(&meta_path)?;
    }

    // Clean up the staging container.
    eprintln!("removing build container '{staging_name}'");
    let _ = containers::remove(datadir, &staging_name, verbose);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "sdme-test-build-{name}-{:?}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir_all(&path).unwrap();
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn write_config(dir: &Path, content: &str) -> PathBuf {
        let path = dir.join("build.conf");
        fs::write(&path, content).unwrap();
        path
    }

    // --- Parser tests ---

    #[test]
    fn test_parse_basic() {
        let tmp = TempDir::new("basic");
        let path = write_config(
            tmp.path(),
            "FROM ubuntu\nRUN apt-get update\nCOPY /etc/hostname /etc/build-host\n",
        );
        let config = parse_build_config(&path).unwrap();
        assert_eq!(config.rootfs, "ubuntu");
        assert_eq!(config.ops.len(), 2);
        match &config.ops[0] {
            BuildOp::Run { command, lineno } => {
                assert_eq!(command, "apt-get update");
                assert_eq!(*lineno, 2);
            }
            _ => panic!("expected Run"),
        }
        match &config.ops[1] {
            BuildOp::Copy { src, dst, lineno } => {
                match src {
                    CopySource::Host(p) => assert_eq!(p, Path::new("/etc/hostname")),
                    _ => panic!("expected Host source"),
                }
                assert_eq!(dst, Path::new("/etc/build-host"));
                assert_eq!(*lineno, 3);
            }
            _ => panic!("expected Copy"),
        }
    }

    #[test]
    fn test_parse_comments_and_blanks() {
        let tmp = TempDir::new("comments");
        let path = write_config(
            tmp.path(),
            "# this is a comment\n\nFROM debian\n\n# another comment\nRUN echo hello\n",
        );
        let config = parse_build_config(&path).unwrap();
        assert_eq!(config.rootfs, "debian");
        assert_eq!(config.ops.len(), 1);
    }

    #[test]
    fn test_parse_missing_from() {
        let tmp = TempDir::new("missing-from");
        let path = write_config(tmp.path(), "RUN echo hello\n");
        let err = parse_build_config(&path).unwrap_err();
        assert!(
            err.to_string().contains("FROM must be the first directive"),
            "got: {err}"
        );
    }

    #[test]
    fn test_parse_duplicate_from() {
        let tmp = TempDir::new("dup-from");
        let path = write_config(tmp.path(), "FROM ubuntu\nFROM debian\n");
        let err = parse_build_config(&path).unwrap_err();
        assert!(err.to_string().contains("duplicate FROM"), "got: {err}");
    }

    #[test]
    fn test_parse_from_not_first() {
        let tmp = TempDir::new("from-not-first");
        let path = write_config(tmp.path(), "RUN echo hello\nFROM ubuntu\n");
        let err = parse_build_config(&path).unwrap_err();
        assert!(
            err.to_string().contains("FROM must be the first directive"),
            "got: {err}"
        );
    }

    #[test]
    fn test_parse_unknown_directive() {
        let tmp = TempDir::new("unknown");
        let path = write_config(tmp.path(), "FROM ubuntu\nINSTALL foo\n");
        let err = parse_build_config(&path).unwrap_err();
        assert!(
            err.to_string().contains("unknown directive: INSTALL"),
            "got: {err}"
        );
    }

    #[test]
    fn test_parse_empty_ops() {
        let tmp = TempDir::new("empty-ops");
        let path = write_config(tmp.path(), "FROM ubuntu\n");
        let config = parse_build_config(&path).unwrap();
        assert_eq!(config.rootfs, "ubuntu");
        assert!(config.ops.is_empty());
    }

    #[test]
    fn test_parse_missing_copy_args() {
        let tmp = TempDir::new("copy-args");
        let path = write_config(tmp.path(), "FROM ubuntu\nCOPY /etc/hostname\n");
        let err = parse_build_config(&path).unwrap_err();
        assert!(
            err.to_string().contains("COPY requires two arguments"),
            "got: {err}"
        );
    }

    #[test]
    fn test_parse_empty_from() {
        let tmp = TempDir::new("empty-from");
        let path = write_config(tmp.path(), "FROM\n");
        let err = parse_build_config(&path).unwrap_err();
        assert!(
            err.to_string().contains("FROM requires a rootfs name"),
            "got: {err}"
        );
    }

    #[test]
    fn test_parse_empty_run() {
        let tmp = TempDir::new("empty-run");
        let path = write_config(tmp.path(), "FROM ubuntu\nRUN\n");
        let err = parse_build_config(&path).unwrap_err();
        assert!(
            err.to_string().contains("RUN requires a command"),
            "got: {err}"
        );
    }

    #[test]
    fn test_parse_no_from() {
        let tmp = TempDir::new("no-from");
        let path = write_config(tmp.path(), "# just a comment\n");
        let err = parse_build_config(&path).unwrap_err();
        assert!(
            err.to_string().contains("missing FROM directive"),
            "got: {err}"
        );
    }

    #[test]
    fn test_parse_run_with_pipes() {
        let tmp = TempDir::new("pipes");
        let path = write_config(
            tmp.path(),
            "FROM ubuntu\nRUN echo hello | grep hello && echo done\n",
        );
        let config = parse_build_config(&path).unwrap();
        match &config.ops[0] {
            BuildOp::Run { command, .. } => {
                assert_eq!(command, "echo hello | grep hello && echo done");
            }
            _ => panic!("expected Run"),
        }
    }

    // --- Backslash continuation tests ---

    #[test]
    fn test_parse_run_continuation() {
        let tmp = TempDir::new("run-continuation");
        let path = write_config(
            tmp.path(),
            "FROM ubuntu\nRUN apt-get update && \\\n    apt-get install -y curl\n",
        );
        let config = parse_build_config(&path).unwrap();
        assert_eq!(config.ops.len(), 1);
        match &config.ops[0] {
            BuildOp::Run { command, .. } => {
                assert_eq!(command, "apt-get update && apt-get install -y curl");
            }
            _ => panic!("expected Run"),
        }
    }

    #[test]
    fn test_parse_run_multi_continuation() {
        let tmp = TempDir::new("run-multi-cont");
        let path = write_config(
            tmp.path(),
            "FROM ubuntu\nRUN apt-get install -y \\\n    curl \\\n    wget \\\n    git\n",
        );
        let config = parse_build_config(&path).unwrap();
        assert_eq!(config.ops.len(), 1);
        match &config.ops[0] {
            BuildOp::Run { command, .. } => {
                assert_eq!(command, "apt-get install -y curl wget git");
            }
            _ => panic!("expected Run"),
        }
    }

    #[test]
    fn test_parse_run_continuation_lineno() {
        let tmp = TempDir::new("run-cont-lineno");
        let path = write_config(
            tmp.path(),
            "FROM ubuntu\n# comment\nRUN echo \\\n    hello\nCOPY ./a /b\n",
        );
        let config = parse_build_config(&path).unwrap();
        assert_eq!(config.ops.len(), 2);
        match &config.ops[0] {
            BuildOp::Run { lineno, .. } => {
                // RUN starts on line 3 (after FROM on 1 and comment on 2).
                assert_eq!(*lineno, 3);
            }
            _ => panic!("expected Run"),
        }
        match &config.ops[1] {
            BuildOp::Copy { lineno, .. } => {
                assert_eq!(*lineno, 5);
            }
            _ => panic!("expected Copy"),
        }
    }

    #[test]
    fn test_parse_trailing_backslash_last_line() {
        let tmp = TempDir::new("trailing-backslash");
        let path = write_config(tmp.path(), "FROM ubuntu\nRUN echo hello\\");
        let config = parse_build_config(&path).unwrap();
        assert_eq!(config.ops.len(), 1);
        match &config.ops[0] {
            BuildOp::Run { command, .. } => {
                assert_eq!(command, "echo hello");
            }
            _ => panic!("expected Run"),
        }
    }

    // --- FROM fs: prefix tests ---

    #[test]
    fn test_parse_from_with_fs_prefix() {
        let tmp = TempDir::new("from-fs-prefix");
        let path = write_config(tmp.path(), "FROM fs:ubuntu\nRUN echo hi\n");
        let config = parse_build_config(&path).unwrap();
        assert_eq!(config.rootfs, "ubuntu");
    }

    // --- COPY source prefix tests ---

    #[test]
    fn test_parse_copy_container_source() {
        let tmp = TempDir::new("copy-container");
        let path = write_config(
            tmp.path(),
            "FROM ubuntu\nCOPY my-container:/etc/foo /etc/foo\n",
        );
        let config = parse_build_config(&path).unwrap();
        match &config.ops[0] {
            BuildOp::Copy { src, dst, .. } => {
                match src {
                    CopySource::Container { name, path } => {
                        assert_eq!(name, "my-container");
                        assert_eq!(path, Path::new("/etc/foo"));
                    }
                    _ => panic!("expected Container source"),
                }
                assert_eq!(dst, Path::new("/etc/foo"));
            }
            _ => panic!("expected Copy"),
        }
    }

    #[test]
    fn test_parse_copy_rootfs_source() {
        let tmp = TempDir::new("copy-rootfs");
        let path = write_config(
            tmp.path(),
            "FROM ubuntu\nCOPY fs:fedora:/etc/os-release /tmp/os-release\n",
        );
        let config = parse_build_config(&path).unwrap();
        match &config.ops[0] {
            BuildOp::Copy { src, .. } => match src {
                CopySource::Rootfs { name, path } => {
                    assert_eq!(name, "fedora");
                    assert_eq!(path, Path::new("/etc/os-release"));
                }
                _ => panic!("expected Rootfs source"),
            },
            _ => panic!("expected Copy"),
        }
    }

    #[test]
    fn test_parse_copy_rootfs_missing_colon() {
        let tmp = TempDir::new("copy-rootfs-no-colon");
        let path = write_config(tmp.path(), "FROM ubuntu\nCOPY fs:ubuntu /dst\n");
        let err = parse_build_config(&path).unwrap_err();
        assert!(err.to_string().contains("fs:name:/path"), "got: {err}");
    }

    #[test]
    fn test_parse_copy_container_relative_path() {
        let tmp = TempDir::new("copy-container-rel");
        let path = write_config(tmp.path(), "FROM ubuntu\nCOPY my-container:relative /dst\n");
        let err = parse_build_config(&path).unwrap_err();
        assert!(err.to_string().contains("absolute"), "got: {err}");
    }

    #[test]
    fn test_parse_copy_host_path_with_colon() {
        // A host path starting with / should not be parsed as a container source
        // even if it contains a colon.
        let tmp = TempDir::new("copy-host-colon");
        let path = write_config(tmp.path(), "FROM ubuntu\nCOPY /path:with:colons /dst\n");
        let config = parse_build_config(&path).unwrap();
        match &config.ops[0] {
            BuildOp::Copy { src, .. } => match src {
                CopySource::Host(p) => assert_eq!(p, Path::new("/path:with:colons")),
                _ => panic!("expected Host source, got {src:?}"),
            },
            _ => panic!("expected Copy"),
        }
    }

    // --- do_copy tests ---

    /// Mutex to serialize tests that change the working directory.
    static CWD_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Helper: create upper and check dirs for do_copy tests.
    fn make_layers(name: &str) -> (TempDir, PathBuf, PathBuf) {
        let tmp = TempDir::new(name);
        let upper = tmp.path().join("upper");
        let lower = tmp.path().join("lower");
        fs::create_dir_all(&upper).unwrap();
        fs::create_dir_all(&lower).unwrap();
        (tmp, upper, lower)
    }

    #[test]
    fn test_do_copy_file_to_dir_in_upper() {
        let (_tmp, upper, lower) = make_layers("file-to-dir-upper");
        // dst dir exists in upper layer.
        fs::create_dir_all(upper.join("usr/local/bin")).unwrap();
        // Create source file.
        let src_dir = _tmp.path().join("src");
        fs::create_dir_all(&src_dir).unwrap();
        let src_file = src_dir.join("sdme");
        fs::write(&src_file, "binary").unwrap();

        let ctx = CopyContext {
            upper_dir: &upper,
            check_dir: &lower,
            shadowed: SHADOWED_DIRS,
            opaque_dirs: &[],
            verbose: false,
        };
        do_copy(&ctx, &src_file, Path::new("/usr/local/bin")).unwrap();
        assert!(upper.join("usr/local/bin/sdme").is_file());
        assert_eq!(
            fs::read_to_string(upper.join("usr/local/bin/sdme")).unwrap(),
            "binary"
        );
    }

    #[test]
    fn test_do_copy_file_to_dir_in_lower() {
        let (_tmp, upper, lower) = make_layers("file-to-dir-lower");
        // dst dir exists in lower layer only.
        fs::create_dir_all(lower.join("usr/local/bin")).unwrap();
        // Create source file.
        let src_dir = _tmp.path().join("src");
        fs::create_dir_all(&src_dir).unwrap();
        let src_file = src_dir.join("sdme");
        fs::write(&src_file, "binary").unwrap();

        let ctx = CopyContext {
            upper_dir: &upper,
            check_dir: &lower,
            shadowed: SHADOWED_DIRS,
            opaque_dirs: &[],
            verbose: false,
        };
        do_copy(&ctx, &src_file, Path::new("/usr/local/bin")).unwrap();
        assert!(upper.join("usr/local/bin/sdme").is_file());
        assert_eq!(
            fs::read_to_string(upper.join("usr/local/bin/sdme")).unwrap(),
            "binary"
        );
    }

    #[test]
    fn test_do_copy_file_to_nonexistent() {
        let (_tmp, upper, lower) = make_layers("file-to-nonexistent");
        // Create source file.
        let src_dir = _tmp.path().join("src");
        fs::create_dir_all(&src_dir).unwrap();
        let src_file = src_dir.join("mybin");
        fs::write(&src_file, "content").unwrap();

        // dst doesn't exist in either layer; file created at exact path.
        let ctx = CopyContext {
            upper_dir: &upper,
            check_dir: &lower,
            shadowed: SHADOWED_DIRS,
            opaque_dirs: &[],
            verbose: false,
        };
        do_copy(&ctx, &src_file, Path::new("/opt/mybin")).unwrap();
        assert!(upper.join("opt/mybin").is_file());
    }

    #[test]
    fn test_do_copy_file_to_dir_trailing_slash() {
        let (_tmp, upper, lower) = make_layers("file-trailing-slash");
        // dst dir exists in lower layer.
        fs::create_dir_all(lower.join("usr/local/bin")).unwrap();
        // Create source file.
        let src_dir = _tmp.path().join("src");
        fs::create_dir_all(&src_dir).unwrap();
        let src_file = src_dir.join("sdme");
        fs::write(&src_file, "binary").unwrap();

        // Trailing slash on dst.
        let ctx = CopyContext {
            upper_dir: &upper,
            check_dir: &lower,
            shadowed: SHADOWED_DIRS,
            opaque_dirs: &[],
            verbose: false,
        };
        do_copy(&ctx, &src_file, Path::new("/usr/local/bin/")).unwrap();
        assert!(upper.join("usr/local/bin/sdme").is_file());
    }

    #[test]
    fn test_do_copy_named_dir_to_dir() {
        let (_tmp, upper, lower) = make_layers("named-dir-to-dir");
        // dst dir exists in lower.
        fs::create_dir_all(lower.join("opt")).unwrap();
        // Create source directory with contents.
        let src_dir = _tmp.path().join("myapp");
        fs::create_dir_all(&src_dir).unwrap();
        fs::write(src_dir.join("app.bin"), "app").unwrap();

        let ctx = CopyContext {
            upper_dir: &upper,
            check_dir: &lower,
            shadowed: SHADOWED_DIRS,
            opaque_dirs: &[],
            verbose: false,
        };
        do_copy(&ctx, &src_dir, Path::new("/opt")).unwrap();
        // Named dir should be placed inside: /opt/myapp/app.bin
        assert!(upper.join("opt/myapp").is_dir());
        assert!(upper.join("opt/myapp/app.bin").is_file());
    }

    #[test]
    fn test_do_copy_dot_to_dir() {
        let _lock = CWD_LOCK.lock().unwrap();
        let (_tmp, upper, lower) = make_layers("dot-to-dir");
        // dst dir exists in lower.
        fs::create_dir_all(lower.join("srv")).unwrap();
        // Create source directory with contents.
        let src_dir = _tmp.path().join("dotdir");
        fs::create_dir_all(&src_dir).unwrap();
        fs::write(src_dir.join("hello.txt"), "hi").unwrap();

        let dot_path = PathBuf::from(".");

        // We need to run from src_dir so "." resolves there.
        let orig_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&src_dir).unwrap();

        let ctx = CopyContext {
            upper_dir: &upper,
            check_dir: &lower,
            shadowed: SHADOWED_DIRS,
            opaque_dirs: &[],
            verbose: false,
        };
        let result = do_copy(&ctx, &dot_path, Path::new("/srv"));
        std::env::set_current_dir(&orig_dir).unwrap();
        result.unwrap();

        // Contents should be directly in /srv, not /srv/./
        assert!(upper.join("srv/hello.txt").is_file());
    }

    #[test]
    fn test_do_copy_dot_to_nonexistent() {
        let _lock = CWD_LOCK.lock().unwrap();
        let (_tmp, upper, lower) = make_layers("dot-to-nonexist");
        // Create source directory with contents.
        let src_dir = _tmp.path().join("dotdir2");
        fs::create_dir_all(&src_dir).unwrap();
        fs::write(src_dir.join("data.txt"), "data").unwrap();

        let dot_path = PathBuf::from(".");

        let orig_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&src_dir).unwrap();

        let ctx = CopyContext {
            upper_dir: &upper,
            check_dir: &lower,
            shadowed: SHADOWED_DIRS,
            opaque_dirs: &[],
            verbose: false,
        };
        let result = do_copy(&ctx, &dot_path, Path::new("/newdir"));
        std::env::set_current_dir(&orig_dir).unwrap();
        result.unwrap();

        // /newdir should be created with contents inside.
        assert!(upper.join("newdir").is_dir());
        assert!(upper.join("newdir/data.txt").is_file());
    }

    #[test]
    fn test_do_copy_dir_to_existing_file() {
        let (_tmp, upper, lower) = make_layers("dir-to-file");
        // dst is a file in lower layer.
        fs::create_dir_all(lower.join("opt")).unwrap();
        fs::write(lower.join("opt/target"), "existing file").unwrap();
        // Create source directory.
        let src_dir = _tmp.path().join("mydir");
        fs::create_dir_all(&src_dir).unwrap();
        fs::write(src_dir.join("a.txt"), "a").unwrap();

        let ctx = CopyContext {
            upper_dir: &upper,
            check_dir: &lower,
            shadowed: SHADOWED_DIRS,
            opaque_dirs: &[],
            verbose: false,
        };
        let err = do_copy(&ctx, &src_dir, Path::new("/opt/target")).unwrap_err();
        assert!(
            err.to_string().contains("cannot copy directory"),
            "got: {err}"
        );
    }

    #[test]
    fn test_do_copy_rejects_path_traversal() {
        let (_tmp, upper, lower) = make_layers("path-traversal");
        let src_dir = _tmp.path().join("src");
        fs::create_dir_all(&src_dir).unwrap();
        let src_file = src_dir.join("evil");
        fs::write(&src_file, "payload").unwrap();

        let ctx = CopyContext {
            upper_dir: &upper,
            check_dir: &lower,
            shadowed: SHADOWED_DIRS,
            opaque_dirs: &[],
            verbose: false,
        };

        // Absolute path with .. components.
        let err = do_copy(&ctx, &src_file, Path::new("/opt/../../etc/shadow")).unwrap_err();
        assert!(
            err.to_string().contains(".."),
            "should reject '..' in dst path, got: {err}"
        );

        // Relative path with .. components.
        let err = do_copy(&ctx, &src_file, Path::new("../escape")).unwrap_err();
        assert!(
            err.to_string().contains(".."),
            "should reject '..' in dst path, got: {err}"
        );

        // Valid paths should still work.
        do_copy(&ctx, &src_file, Path::new("/opt/safe")).unwrap();
        assert!(upper.join("opt/safe").is_file());
    }

    #[test]
    fn test_do_copy_rejects_shadowed_dirs() {
        let (_tmp, upper, lower) = make_layers("shadowed");
        let src_dir = _tmp.path().join("src");
        fs::create_dir_all(&src_dir).unwrap();
        let src_file = src_dir.join("data");
        fs::write(&src_file, "payload").unwrap();

        let ctx = CopyContext {
            upper_dir: &upper,
            check_dir: &lower,
            shadowed: SHADOWED_DIRS,
            opaque_dirs: &[],
            verbose: false,
        };

        // /tmp is shadowed by systemd tmpfs at boot.
        let err = do_copy(&ctx, &src_file, Path::new("/tmp/data")).unwrap_err();
        assert!(
            err.to_string().contains("tmpfs"),
            "should reject /tmp as shadowed, got: {err}"
        );

        // /run is also shadowed.
        let err = do_copy(&ctx, &src_file, Path::new("/run/foo")).unwrap_err();
        assert!(
            err.to_string().contains("tmpfs"),
            "should reject /run as shadowed, got: {err}"
        );

        // /dev/shm is also shadowed.
        let err = do_copy(&ctx, &src_file, Path::new("/dev/shm/bar")).unwrap_err();
        assert!(
            err.to_string().contains("tmpfs"),
            "should reject /dev/shm as shadowed, got: {err}"
        );

        // Exact match on shadowed dir.
        let err = do_copy(&ctx, &src_file, Path::new("/tmp")).unwrap_err();
        assert!(
            err.to_string().contains("tmpfs"),
            "should reject /tmp exact match, got: {err}"
        );
    }

    #[test]
    fn test_do_copy_rejects_opaque_dirs() {
        let (_tmp, upper, lower) = make_layers("opaque");
        let src_dir = _tmp.path().join("src");
        fs::create_dir_all(&src_dir).unwrap();
        let src_file = src_dir.join("unit");
        fs::write(&src_file, "payload").unwrap();

        let opaque = vec!["/etc/systemd/system".to_string()];

        let ctx = CopyContext {
            upper_dir: &upper,
            check_dir: &lower,
            shadowed: SHADOWED_DIRS,
            opaque_dirs: &opaque,
            verbose: false,
        };

        let err = do_copy(
            &ctx,
            &src_file,
            Path::new("/etc/systemd/system/foo.service"),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("opaque"),
            "should reject opaque dir destination, got: {err}"
        );

        // Non-opaque path should still work.
        do_copy(&ctx, &src_file, Path::new("/etc/foo.conf")).unwrap();
        assert!(upper.join("etc/foo.conf").is_file());
    }

    // --- Build-context shadowed dirs test ---

    #[test]
    fn test_do_copy_build_shadowed_allows_tmp() {
        let (_tmp, upper, lower) = make_layers("build-shadowed");
        let src_dir = _tmp.path().join("src");
        fs::create_dir_all(&src_dir).unwrap();
        let src_file = src_dir.join("data");
        fs::write(&src_file, "payload").unwrap();

        let ctx = CopyContext {
            upper_dir: &upper,
            check_dir: &lower,
            shadowed: BUILD_SHADOWED_DIRS,
            opaque_dirs: &[],
            verbose: false,
        };

        // In build context, /tmp is allowed.
        do_copy(&ctx, &src_file, Path::new("/tmp/data")).unwrap();
        assert!(upper.join("tmp/data").is_file());

        // /run is still rejected.
        let err = do_copy(&ctx, &src_file, Path::new("/run/foo")).unwrap_err();
        assert!(
            err.to_string().contains("tmpfs"),
            "should reject /run in build context, got: {err}"
        );

        // /dev/shm is still rejected.
        let err = do_copy(&ctx, &src_file, Path::new("/dev/shm/bar")).unwrap_err();
        assert!(
            err.to_string().contains("tmpfs"),
            "should reject /dev/shm in build context, got: {err}"
        );
    }
}
