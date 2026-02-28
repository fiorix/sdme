//! Build root filesystems from a Dockerfile-like configuration.
//!
//! Parses a build config with FROM, COPY, and RUN directives, creates a
//! temporary staging container, executes build operations sequentially,
//! then captures the resulting merged filesystem as a new rootfs.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::copy::sanitize_dest_path;
use crate::{check_interrupted, containers, copy, rootfs, systemd, validate_name, State};

// --- Config types ---

#[derive(Debug)]
struct BuildConfig {
    path: PathBuf,
    rootfs: String,
    ops: Vec<BuildOp>,
}

#[derive(Debug)]
enum BuildOp {
    Copy {
        src: PathBuf,
        dst: PathBuf,
        lineno: usize,
    },
    Run {
        command: String,
        lineno: usize,
    },
}

// --- Parser ---

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
                validate_name(rest).with_context(|| {
                    format!(
                        "{}:{}: invalid FROM rootfs name",
                        path.display(),
                        lineno + 1
                    )
                })?;
                rootfs = Some(rest.to_string());
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
                ops.push(BuildOp::Copy {
                    src: PathBuf::from(src),
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

// --- Execution engine ---

fn run_in_container(name: &str, command: &str, verbose: bool) -> Result<()> {
    if verbose {
        eprintln!("run: {command}");
    }
    let status = std::process::Command::new("machinectl")
        .args(["shell", name, "/bin/sh", "-c", command])
        .status()
        .context("failed to run machinectl shell")?;
    if !status.success() {
        bail!(
            "command failed with exit code {}",
            status.code().unwrap_or(-1)
        );
    }
    Ok(())
}

/// Directories that systemd mounts tmpfs over at boot, hiding any files
/// written to the overlayfs upper layer underneath. COPY into these
/// destinations would silently lose data.
const SHADOWED_DIRS: &[&str] = &["/tmp", "/run", "/dev/shm"];

/// Check if `dst` falls under a directory that is shadowed by a tmpfs
/// mount at boot or marked as overlayfs-opaque, meaning files written
/// to the upper layer would be invisible in the running container.
fn check_shadowed_dest(dst: &Path, opaque_dirs: &[String]) -> Result<()> {
    let dst_str = dst.to_string_lossy();
    for dir in SHADOWED_DIRS {
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
    lower_dir: &Path,
    src: &Path,
    dst: &Path,
    opaque_dirs: &[String],
    verbose: bool,
) -> Result<()> {
    check_shadowed_dest(dst, opaque_dirs)?;
    let rel_dst = sanitize_dest_path(dst)?;
    let mut target = upper_dir.join(&rel_dst);

    let meta =
        fs::symlink_metadata(src).with_context(|| format!("failed to stat {}", src.display()))?;

    // Check whether dst resolves to a directory in either layer.
    let dst_is_dir = target.is_dir() || lower_dir.join(&rel_dst).is_dir();

    // Check whether dst resolves to a file in either layer.
    let dst_is_file = (!dst_is_dir) && (target.is_file() || lower_dir.join(&rel_dst).is_file());

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

fn execute_build(
    datadir: &Path,
    container_name: &str,
    rootfs: &str,
    config: &BuildConfig,
    opaque_dirs: &[String],
    boot_timeout: u64,
    verbose: bool,
) -> Result<()> {
    let mut container_running = false;
    let timeout = std::time::Duration::from_secs(boot_timeout);

    for op in &config.ops {
        check_interrupted()?;

        match op {
            BuildOp::Run { command, lineno } => {
                if !container_running {
                    eprintln!("starting build container '{container_name}'");
                    systemd::start(datadir, container_name, verbose)?;
                    systemd::await_boot(container_name, timeout, verbose)?;
                    container_running = true;
                }
                run_in_container(container_name, command, verbose)
                    .with_context(|| format!("{}:{}", config.path.display(), lineno))?;
            }
            BuildOp::Copy { src, dst, lineno } => {
                if container_running {
                    eprintln!("stopping build container '{container_name}'");
                    containers::stop(container_name, containers::StopMode::Terminate, verbose)?;
                    container_running = false;
                }
                let upper_dir = datadir
                    .join("containers")
                    .join(container_name)
                    .join("upper");
                let lower_dir = datadir.join("fs").join(rootfs);
                do_copy(&upper_dir, &lower_dir, src, dst, opaque_dirs, verbose)
                    .with_context(|| format!("{}:{}", config.path.display(), lineno))?;
            }
        }
    }

    // Ensure container is stopped; overlayfs must be unmounted for merged layer copy.
    if container_running {
        eprintln!("stopping build container '{container_name}'");
        containers::stop(container_name, containers::StopMode::Terminate, verbose)?;
    }

    Ok(())
}

// --- Main entry point ---

pub fn build(
    datadir: &Path,
    name: &str,
    config_path: &Path,
    boot_timeout: u64,
    force: bool,
    verbose: bool,
) -> Result<()> {
    validate_name(name)?;

    let fs_dir = datadir.join("fs");
    let final_dir = fs_dir.join(name);
    if final_dir.exists() {
        if !force {
            bail!("fs already exists: {name}");
        }
        eprintln!("removing existing fs '{name}'");
        rootfs::remove(datadir, name, verbose)?;
    }

    let config = parse_build_config(config_path)?;

    // Verify the FROM rootfs exists.
    let rootfs_dir = fs_dir.join(&config.rootfs);
    if !rootfs_dir.is_dir() {
        bail!("fs not found: {}", config.rootfs);
    }

    // Create a staging container.
    let staging_name = format!("build-{name}");
    eprintln!("creating build container '{staging_name}'");
    // Staging container runs as root for package installation and file copying.
    let create_opts = containers::CreateOptions {
        name: Some(staging_name.clone()),
        rootfs: Some(config.rootfs.clone()),
        ..Default::default()
    };
    containers::create(datadir, &create_opts, verbose)?;

    // Execute all build operations; clean up on failure.
    if let Err(e) = execute_build(
        datadir,
        &staging_name,
        &config.rootfs,
        &config,
        &create_opts.opaque_dirs,
        boot_timeout,
        verbose,
    ) {
        crate::reset_interrupt();
        eprintln!("build failed, removing '{staging_name}'");
        let _ = containers::remove(datadir, &staging_name, verbose);
        return Err(e);
    }

    // Capture the merged filesystem as the new rootfs.
    let merged_dir = datadir
        .join("containers")
        .join(&staging_name)
        .join("merged");

    // Mount overlayfs to get the merged view (container is stopped, so we mount manually).
    let upper_dir = datadir.join("containers").join(&staging_name).join("upper");
    let work_dir = datadir.join("containers").join(&staging_name).join("work");

    let mount_opts = format!(
        "lowerdir={},upperdir={},workdir={}",
        rootfs_dir.display(),
        upper_dir.display(),
        work_dir.display()
    );

    let mount_status = std::process::Command::new("mount")
        .args(["-t", "overlay", "overlay", "-o", &mount_opts])
        .arg(&merged_dir)
        .status()
        .context("failed to run mount")?;

    if !mount_status.success() {
        eprintln!("build failed (mount), removing '{staging_name}'");
        let _ = containers::remove(datadir, &staging_name, verbose);
        bail!("failed to mount overlayfs for final copy");
    }

    // Copy merged to staging rootfs, then atomic rename.
    let staging_rootfs = fs_dir.join(format!(".{name}.importing"));
    let copy_result = (|| -> Result<()> {
        fs::create_dir_all(&staging_rootfs)
            .with_context(|| format!("failed to create {}", staging_rootfs.display()))?;
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
    let _ = std::process::Command::new("umount")
        .arg(&merged_dir)
        .status();

    if let Err(e) = copy_result {
        let _ = copy::make_removable(&staging_rootfs);
        let _ = fs::remove_dir_all(&staging_rootfs);
        let _ = containers::remove(datadir, &staging_name, verbose);
        return Err(e).context("failed to copy merged filesystem");
    }

    // Atomic rename to final location.
    if let Err(e) = fs::rename(&staging_rootfs, &final_dir) {
        let _ = copy::make_removable(&staging_rootfs);
        let _ = fs::remove_dir_all(&staging_rootfs);
        let _ = containers::remove(datadir, &staging_name, verbose);
        return Err(e).with_context(|| {
            format!(
                "failed to rename {} to {}",
                staging_rootfs.display(),
                final_dir.display()
            )
        });
    }

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
                assert_eq!(src, Path::new("/etc/hostname"));
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

    // --- do_copy tests ---

    /// Mutex to serialize tests that change the working directory.
    static CWD_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Helper: create upper and lower dirs for do_copy tests.
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

        do_copy(&upper, &lower, &src_dir, Path::new("/opt"), &[], false).unwrap();
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

        let result = do_copy(&upper, &lower, &dot_path, Path::new("/srv"), &[], false);
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

        let result = do_copy(&upper, &lower, &dot_path, Path::new("/newdir"), &[], false);
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
            &[],
            false,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("tmpfs"),
            "should reject /tmp as shadowed, got: {err}"
        );

        // /run is also shadowed.
        let err =
            do_copy(&upper, &lower, &src_file, Path::new("/run/foo"), &[], false).unwrap_err();
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
            &[],
            false,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("tmpfs"),
            "should reject /dev/shm as shadowed, got: {err}"
        );

        // Exact match on shadowed dir.
        let err = do_copy(&upper, &lower, &src_file, Path::new("/tmp"), &[], false).unwrap_err();
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
            &opaque,
            false,
        )
        .unwrap();
        assert!(upper.join("etc/foo.conf").is_file());
    }
}
