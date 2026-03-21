//! Build root filesystems from a Dockerfile-like configuration.
//!
//! Parses a build config with FROM, COPY, and RUN directives, creates a
//! temporary staging container, executes build operations sequentially,
//! then captures the resulting merged filesystem as a new rootfs.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

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
        // container-name:/path — only if the part before : is a valid name
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

    for (lineno, raw) in content.lines().enumerate() {
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
                    bail!(
                        "{}:{}: duplicate FROM directive",
                        path.display(),
                        lineno + 1
                    );
                }
                if rest.is_empty() {
                    bail!(
                        "{}:{}: FROM requires a rootfs name",
                        path.display(),
                        lineno + 1
                    );
                }
                // Support both `FROM ubuntu` and `FROM fs:ubuntu`.
                let rootfs_name = rest.strip_prefix("fs:").unwrap_or(rest);
                validate_name(rootfs_name).with_context(|| {
                    format!(
                        "{}:{}: invalid FROM rootfs name",
                        path.display(),
                        lineno + 1
                    )
                })?;
                rootfs = Some(rootfs_name.to_string());
            }
            "COPY" => {
                if rootfs.is_none() {
                    bail!(
                        "{}:{}: FROM must be the first directive",
                        path.display(),
                        lineno + 1
                    );
                }
                let (src, dst) = rest.split_once(char::is_whitespace).ok_or_else(|| {
                    anyhow::anyhow!(
                        "{}:{}: COPY requires two arguments: COPY <src> <dst>",
                        path.display(),
                        lineno + 1
                    )
                })?;
                let dst = dst.trim();
                if dst.is_empty() {
                    bail!(
                        "{}:{}: COPY requires two arguments: COPY <src> <dst>",
                        path.display(),
                        lineno + 1
                    );
                }
                let copy_src = parse_copy_source(src, path, lineno + 1)?;
                ops.push(BuildOp::Copy {
                    src: copy_src,
                    dst: PathBuf::from(dst),
                    lineno: lineno + 1,
                });
            }
            "RUN" => {
                if rootfs.is_none() {
                    bail!(
                        "{}:{}: FROM must be the first directive",
                        path.display(),
                        lineno + 1
                    );
                }
                if rest.is_empty() {
                    bail!("{}:{}: RUN requires a command", path.display(), lineno + 1);
                }
                ops.push(BuildOp::Run {
                    command: rest.to_string(),
                    lineno: lineno + 1,
                });
            }
            _ => {
                bail!(
                    "{}:{}: unknown directive: {directive}",
                    path.display(),
                    lineno + 1
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

/// RAII guard that unmounts overlayfs on drop.
struct OverlayGuard {
    container_dir: PathBuf,
}

impl Drop for OverlayGuard {
    fn drop(&mut self) {
        containers::unmount_overlay(&self.container_dir);
    }
}

struct ResolvedSource {
    path: PathBuf,
    /// If we temporarily mounted overlayfs, this guard handles unmount on drop.
    _mount_guard: Option<OverlayGuard>,
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
                    Some(OverlayGuard {
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

fn do_copy(
    upper_dir: &Path,
    check_dir: &Path,
    src: &Path,
    dst: &Path,
    shadowed: &[&str],
    opaque_dirs: &[String],
    verbose: bool,
) -> Result<()> {
    check_shadowed_dest(dst, shadowed, opaque_dirs)?;
    let rel_dst = sanitize_dest_path(dst)?;
    let mut target = upper_dir.join(&rel_dst);

    let meta =
        fs::symlink_metadata(src).with_context(|| format!("failed to stat {}", src.display()))?;

    // Check whether dst resolves to a directory in either layer.
    let dst_is_dir = target.is_dir() || check_dir.join(&rel_dst).is_dir();

    // Check whether dst resolves to a file in either layer.
    let dst_is_file = (!dst_is_dir) && (target.is_file() || check_dir.join(&rel_dst).is_file());

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

    if verbose {
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
        copy::copy_tree(src, &target, verbose)
            .with_context(|| format!("failed to copy directory {}", src.display()))?;
    } else {
        copy::copy_entry(src, &target, verbose)
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
    verbose: bool,
}

fn execute_build(datadir: &Path, ctx: &ExecuteBuildContext<'_>) -> Result<()> {
    let mut container_running = false;
    let timeout = std::time::Duration::from_secs(ctx.boot_timeout);

    // Eagerly start the container before any ops. This ensures:
    // 1. systemd-tmpfiles cleanup of /tmp has finished before any COPY
    // 2. The merged overlayfs view is available for dst existence checks
    // Without this, COPY to /tmp before the first RUN would write to
    // upper/tmp, but systemd-tmpfiles cleans /tmp during boot and
    // deletes the file.
    if !ctx.config.ops.is_empty() {
        eprintln!("starting build container '{}'", ctx.container_name);
        systemd::start(
            datadir,
            ctx.container_name,
            ctx.tasks_max,
            ctx.boot_timeout,
            ctx.verbose,
        )?;
        systemd::await_boot(ctx.container_name, timeout, ctx.verbose)?;
        container_running = true;
    }

    for op in &ctx.config.ops {
        check_interrupted()?;

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
                do_copy(
                    &write_dir,
                    &check_dir,
                    &resolved.path,
                    dst,
                    BUILD_SHADOWED_DIRS,
                    ctx.opaque_dirs,
                    ctx.verbose,
                )
                .with_context(|| format!("{}:{}", ctx.config.path.display(), lineno))?;
            }
        }
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
            bail!("fs already exists: {name}");
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

    // Clean up leftover build container from a prior interrupted build.
    let state_path = datadir.join("state").join(&staging_name);
    if state_path.exists() {
        if systemd::is_active(&staging_name)? {
            bail!(
                "build container '{staging_name}' is already running; \
                 is another build in progress?"
            );
        }
        eprintln!("removing stale build container '{staging_name}'");
        containers::remove(datadir, &staging_name, verbose)?;
    }

    eprintln!("creating build container '{staging_name}'");
    let create_opts = containers::CreateOptions {
        name: Some(staging_name.clone()),
        rootfs: Some(config.rootfs.clone()),
        ..Default::default()
    };
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

    // Add the /tmp bind mount to the container's state file.
    let state_path = datadir.join("state").join(&staging_name);
    let mut state = State::read_from(&state_path)?;
    let bind_spec = format!("{}:/tmp:rw", upper_tmp.display());
    let existing_binds = state.get("BINDS").unwrap_or("").to_string();
    if existing_binds.is_empty() {
        state.set("BINDS", &bind_spec);
    } else {
        state.set("BINDS", format!("{existing_binds}|{bind_spec}"));
    }
    state.write_to(&state_path)?;

    // Execute all build operations; clean up on failure.
    if let Err(e) = execute_build(
        datadir,
        &ExecuteBuildContext {
            container_name: &staging_name,
            config: &config,
            opaque_dirs: &create_opts.opaque_dirs,
            boot_timeout: opts.boot_timeout,
            tasks_max: opts.tasks_max,
            verbose,
        },
    ) {
        let (was, sig) = crate::save_and_reset_interrupt();
        eprintln!("build failed, stopping '{staging_name}'");
        let _ = containers::stop(&staging_name, containers::StopMode::Terminate, 30, verbose);
        crate::restore_interrupt(was, sig);
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

        do_copy(
            &upper,
            &lower,
            &src_file,
            Path::new("/usr/local/bin"),
            SHADOWED_DIRS,
            &[],
            false,
        )
        .unwrap();
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

        do_copy(
            &upper,
            &lower,
            &src_file,
            Path::new("/usr/local/bin"),
            SHADOWED_DIRS,
            &[],
            false,
        )
        .unwrap();
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
        do_copy(
            &upper,
            &lower,
            &src_file,
            Path::new("/opt/mybin"),
            SHADOWED_DIRS,
            &[],
            false,
        )
        .unwrap();
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
        do_copy(
            &upper,
            &lower,
            &src_file,
            Path::new("/usr/local/bin/"),
            SHADOWED_DIRS,
            &[],
            false,
        )
        .unwrap();
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

        do_copy(
            &upper,
            &lower,
            &src_dir,
            Path::new("/opt"),
            SHADOWED_DIRS,
            &[],
            false,
        )
        .unwrap();
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

        let result = do_copy(
            &upper,
            &lower,
            &dot_path,
            Path::new("/srv"),
            SHADOWED_DIRS,
            &[],
            false,
        );
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

        let result = do_copy(
            &upper,
            &lower,
            &dot_path,
            Path::new("/newdir"),
            SHADOWED_DIRS,
            &[],
            false,
        );
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

        let err = do_copy(
            &upper,
            &lower,
            &src_dir,
            Path::new("/opt/target"),
            SHADOWED_DIRS,
            &[],
            false,
        )
        .unwrap_err();
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

        // Absolute path with .. components.
        let err = do_copy(
            &upper,
            &lower,
            &src_file,
            Path::new("/opt/../../etc/shadow"),
            SHADOWED_DIRS,
            &[],
            false,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains(".."),
            "should reject '..' in dst path, got: {err}"
        );

        // Relative path with .. components.
        let err = do_copy(
            &upper,
            &lower,
            &src_file,
            Path::new("../escape"),
            SHADOWED_DIRS,
            &[],
            false,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains(".."),
            "should reject '..' in dst path, got: {err}"
        );

        // Valid paths should still work.
        do_copy(
            &upper,
            &lower,
            &src_file,
            Path::new("/opt/safe"),
            SHADOWED_DIRS,
            &[],
            false,
        )
        .unwrap();
        assert!(upper.join("opt/safe").is_file());
    }

    #[test]
    fn test_do_copy_rejects_shadowed_dirs() {
        let (_tmp, upper, lower) = make_layers("shadowed");
        let src_dir = _tmp.path().join("src");
        fs::create_dir_all(&src_dir).unwrap();
        let src_file = src_dir.join("data");
        fs::write(&src_file, "payload").unwrap();

        // /tmp is shadowed by systemd tmpfs at boot.
        let err = do_copy(
            &upper,
            &lower,
            &src_file,
            Path::new("/tmp/data"),
            SHADOWED_DIRS,
            &[],
            false,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("tmpfs"),
            "should reject /tmp as shadowed, got: {err}"
        );

        // /run is also shadowed.
        let err = do_copy(
            &upper,
            &lower,
            &src_file,
            Path::new("/run/foo"),
            SHADOWED_DIRS,
            &[],
            false,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("tmpfs"),
            "should reject /run as shadowed, got: {err}"
        );

        // /dev/shm is also shadowed.
        let err = do_copy(
            &upper,
            &lower,
            &src_file,
            Path::new("/dev/shm/bar"),
            SHADOWED_DIRS,
            &[],
            false,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("tmpfs"),
            "should reject /dev/shm as shadowed, got: {err}"
        );

        // Exact match on shadowed dir.
        let err = do_copy(
            &upper,
            &lower,
            &src_file,
            Path::new("/tmp"),
            SHADOWED_DIRS,
            &[],
            false,
        )
        .unwrap_err();
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

        let err = do_copy(
            &upper,
            &lower,
            &src_file,
            Path::new("/etc/systemd/system/foo.service"),
            SHADOWED_DIRS,
            &opaque,
            false,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("opaque"),
            "should reject opaque dir destination, got: {err}"
        );

        // Non-opaque path should still work.
        do_copy(
            &upper,
            &lower,
            &src_file,
            Path::new("/etc/foo.conf"),
            SHADOWED_DIRS,
            &opaque,
            false,
        )
        .unwrap();
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

        // In build context, /tmp is allowed.
        do_copy(
            &upper,
            &lower,
            &src_file,
            Path::new("/tmp/data"),
            BUILD_SHADOWED_DIRS,
            &[],
            false,
        )
        .unwrap();
        assert!(upper.join("tmp/data").is_file());

        // /run is still rejected.
        let err = do_copy(
            &upper,
            &lower,
            &src_file,
            Path::new("/run/foo"),
            BUILD_SHADOWED_DIRS,
            &[],
            false,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("tmpfs"),
            "should reject /run in build context, got: {err}"
        );

        // /dev/shm is still rejected.
        let err = do_copy(
            &upper,
            &lower,
            &src_file,
            Path::new("/dev/shm/bar"),
            BUILD_SHADOWED_DIRS,
            &[],
            false,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("tmpfs"),
            "should reject /dev/shm in build context, got: {err}"
        );
    }
}
