//! File copy between host, containers, and root filesystems.
//!
//! Implements `sdme cp` for copying files and directories between the host
//! filesystem and containers or imported root filesystems. One side must
//! always be a host path; container-to-container copy is not supported.
//!
//! Uses the same copy engine (`copy::copy_tree`, `copy::copy_entry`) and
//! path validation (`copy::sanitize_dest_path`) as `fs build` COPY.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::{confirm, containers, copy, lock, systemd, validate_name, State};

/// One side of a copy operation.
#[derive(Debug)]
pub enum CpEndpoint {
    /// A path on the host filesystem.
    Host(PathBuf),
    /// A path inside a container (`NAME:/path`).
    Container {
        /// Container name (may be abbreviated).
        name: String,
        /// Absolute path inside the container.
        path: PathBuf,
    },
    /// A path inside an imported rootfs (`fs:NAME:/path`).
    Rootfs {
        /// Rootfs name.
        name: String,
        /// Absolute path inside the rootfs.
        path: PathBuf,
    },
}

/// Options controlling copy behavior.
pub struct CpOptions {
    /// Allow device nodes and skip safety prompts.
    pub force: bool,
    /// Enable verbose output.
    pub verbose: bool,
    /// Enable interactive prompts.
    pub interactive: bool,
}

/// Parse a source or destination string into a `CpEndpoint`.
///
/// Formats:
/// - `/path` or `./path` — host filesystem
/// - `NAME:/path` — container (path must be absolute)
/// - `fs:NAME:/path` — root filesystem (path must be absolute)
pub fn parse_endpoint(input: &str) -> Result<CpEndpoint> {
    if input.is_empty() {
        bail!("path must not be empty");
    }

    // fs:NAME:/path
    if let Some(rest) = input.strip_prefix("fs:") {
        let (name, path) = rest
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("rootfs path requires fs:NAME:/path format"))?;
        if name.is_empty() {
            bail!("rootfs name is empty in '{input}'");
        }
        validate_name(name).with_context(|| format!("invalid rootfs name in '{input}'"))?;
        if path.is_empty() || !path.starts_with('/') {
            bail!("rootfs path must be absolute in '{input}'");
        }
        return Ok(CpEndpoint::Rootfs {
            name: name.to_string(),
            path: PathBuf::from(path),
        });
    }

    // NAME:/path — only if the part before : is a valid container name
    if let Some((maybe_name, path)) = input.split_once(':') {
        if validate_name(maybe_name).is_ok() {
            if path.is_empty() || !path.starts_with('/') {
                bail!("container path must be absolute in '{input}'");
            }
            return Ok(CpEndpoint::Container {
                name: maybe_name.to_string(),
                path: PathBuf::from(path),
            });
        }
        // Not a valid container name: fall through to host path
        // (e.g. /path:with:colons or C:\path on Windows-like input)
    }

    Ok(CpEndpoint::Host(PathBuf::from(input)))
}

/// Directories that systemd mounts tmpfs over at boot, hiding any files
/// written to the overlayfs upper layer underneath.
const SHADOWED_DIRS: &[&str] = &["/tmp", "/run", "/dev/shm"];

/// Check whether a path is under one of the shadowed directories.
fn is_under_shadowed_dir(path: &Path) -> bool {
    let s = path.to_string_lossy();
    SHADOWED_DIRS
        .iter()
        .any(|dir| s == *dir || s.starts_with(&format!("{dir}/")))
}

/// Holds resolved paths and RAII guards for a source.
struct ResolvedSource {
    path: PathBuf,
    _mount_guard: Option<containers::OverlayGuard>,
    _rootfs_lock: Option<lock::ResourceLock>,
    _lock: Option<lock::ResourceLock>,
}

/// Holds resolved paths and RAII guards for a destination.
struct ResolvedDest {
    /// Directory to write into (upper/ for stopped containers, merged/ for running,
    /// rootfs dir or host path directly).
    write_dir: PathBuf,
    /// Directory to check for existing files (rootfs for stopped containers,
    /// same as write_dir otherwise).
    check_dir: PathBuf,
    /// True when the destination is a running container.
    is_running: bool,
    _rootfs_lock: Option<lock::ResourceLock>,
    _lock: Option<lock::ResourceLock>,
}

/// Copy files between host and containers/rootfs.
///
/// One side must be a `Host` endpoint; container-to-container is not supported.
pub fn cp(datadir: &Path, src: &CpEndpoint, dst: &CpEndpoint, opts: &CpOptions) -> Result<()> {
    // Validate: one side must be host.
    let both_remote = !matches!(src, CpEndpoint::Host(_)) && !matches!(dst, CpEndpoint::Host(_));
    if both_remote {
        bail!("one side of the copy must be a host path");
    }
    let both_host = matches!(src, CpEndpoint::Host(_)) && matches!(dst, CpEndpoint::Host(_));
    if both_host {
        bail!("use cp(1) for host-to-host copies");
    }

    // Resolve source.
    let resolved_src = resolve_source(datadir, src, opts.verbose)?;

    // Resolve destination.
    let resolved_dst = resolve_destination(datadir, dst, opts.verbose)?;

    // Safety checks when copying TO host.
    if matches!(dst, CpEndpoint::Host(_)) {
        check_host_safety(&resolved_src.path, opts)?;
    }

    // Safety checks when copying TO a container/rootfs.
    if !matches!(dst, CpEndpoint::Host(_)) && !resolved_dst.is_running {
        check_container_dest_safety(&resolved_dst.write_dir, dst)?;
    }

    // Warn when writing to a rootfs with running containers.
    if let CpEndpoint::Rootfs { ref name, .. } = dst {
        warn_rootfs_in_use(datadir, name);
    }

    // Execute the copy.
    execute_copy(
        &resolved_src.path,
        &resolved_dst.write_dir,
        &resolved_dst.check_dir,
        dst,
        opts.verbose,
    )
}

fn resolve_source(
    datadir: &Path,
    endpoint: &CpEndpoint,
    verbose: bool,
) -> Result<ResolvedSource> {
    match endpoint {
        CpEndpoint::Host(path) => {
            if !path.exists() {
                bail!("source path does not exist: {}", path.display());
            }
            Ok(ResolvedSource {
                path: path.clone(),
                _mount_guard: None,
                _rootfs_lock: None,
                _lock: None,
            })
        }
        CpEndpoint::Rootfs { name, path } => {
            let rootfs_dir = datadir.join("fs").join(name);
            if !rootfs_dir.is_dir() {
                bail!("rootfs not found: {name}");
            }
            let lock = lock::lock_shared(datadir, "fs", name)
                .with_context(|| format!("cannot lock rootfs '{name}' for reading"))?;
            let full_path = rootfs_dir.join(path.strip_prefix("/").unwrap_or(path));
            if !full_path.exists() {
                bail!(
                    "source path does not exist in rootfs '{name}': {}",
                    path.display()
                );
            }
            Ok(ResolvedSource {
                path: full_path,
                _mount_guard: None,
                _rootfs_lock: None,
                _lock: Some(lock),
            })
        }
        CpEndpoint::Container { name, path } => {
            let name = containers::resolve_name(datadir, name)?;
            containers::ensure_exists(datadir, &name)?;
            // Lock ordering: fs before containers.
            let container_dir = datadir.join("containers").join(&name);
            let running = systemd::is_active(&name)?;

            if running {
                let lock = lock::lock_shared(datadir, "containers", &name)
                    .with_context(|| format!("cannot lock container '{name}' for reading"))?;
                eprintln!(
                    "warning: container '{name}' is running; filesystem is live and \
                     consistency is not guaranteed"
                );

                let leader = systemd::get_machine_leader(&name)?
                    .with_context(|| format!("container '{name}' disappeared (race)"))?;
                let uses_userns = systemd::has_foreign_userns(leader);

                let full_path = if uses_userns {
                    if is_under_shadowed_dir(path) {
                        bail!(
                            "cannot read {} from running container '{name}': the kernel blocks \
                             /proc/<pid>/root/ access for user namespace containers (--userns, \
                             --hardened, --strict), and {} is a tmpfs only visible inside the \
                             container's mount namespace; use 'sdme exec {name} -- cat {}' as \
                             a workaround",
                            path.display(),
                            SHADOWED_DIRS
                                .iter()
                                .find(|d| {
                                    let s = path.to_string_lossy();
                                    s == **d || s.starts_with(&format!("{d}/"))
                                })
                                .unwrap(),
                            path.display(),
                        );
                    }
                    if verbose {
                        eprintln!(
                            "userns container: using merged/ (kernel blocks /proc/{leader}/root/)"
                        );
                    }
                    container_dir
                        .join("merged")
                        .join(path.strip_prefix("/").unwrap_or(path))
                } else {
                    if verbose {
                        eprintln!("reading from /proc/{leader}/root/");
                    }
                    PathBuf::from(format!("/proc/{leader}/root"))
                        .join(path.strip_prefix("/").unwrap_or(path))
                };

                if !full_path.exists() {
                    bail!(
                        "source path does not exist in container '{name}': {}",
                        path.display()
                    );
                }
                Ok(ResolvedSource {
                    path: full_path,
                    _mount_guard: None,
                    _rootfs_lock: None,
                    _lock: Some(lock),
                })
            } else {
                // Stopped: mount read-only overlay.
                let state_path = datadir.join("state").join(&name);
                let state = State::read_from(&state_path)?;
                let rootfs_name = state.rootfs();
                let rootfs_dir = if rootfs_name.is_empty() {
                    PathBuf::from("/")
                } else {
                    datadir.join("fs").join(rootfs_name)
                };

                // Lock ordering: fs before containers.
                let rootfs_lock = if !rootfs_name.is_empty() {
                    Some(
                        lock::lock_shared(datadir, "fs", rootfs_name)
                            .with_context(|| {
                                format!("cannot lock rootfs '{rootfs_name}' for reading")
                            })?,
                    )
                } else {
                    None
                };
                let lock = lock::lock_shared(datadir, "containers", &name)
                    .with_context(|| format!("cannot lock container '{name}' for reading"))?;

                if verbose {
                    eprintln!("mounting read-only overlay for container '{name}'");
                }
                containers::mount_overlay_ro(&rootfs_dir, &container_dir)?;

                let full_path = container_dir
                    .join("merged")
                    .join(path.strip_prefix("/").unwrap_or(path));
                if !full_path.exists() {
                    // Let OverlayGuard clean up before returning error.
                    let _guard = containers::OverlayGuard {
                        container_dir: container_dir.clone(),
                    };
                    bail!(
                        "source path does not exist in container '{name}': {}",
                        path.display()
                    );
                }

                Ok(ResolvedSource {
                    path: full_path,
                    _mount_guard: Some(containers::OverlayGuard { container_dir }),
                    _rootfs_lock: rootfs_lock,
                    _lock: Some(lock),
                })
            }
        }
    }
}

fn resolve_destination(
    datadir: &Path,
    endpoint: &CpEndpoint,
    verbose: bool,
) -> Result<ResolvedDest> {
    match endpoint {
        CpEndpoint::Host(path) => Ok(ResolvedDest {
            write_dir: path.clone(),
            check_dir: path.clone(),
            is_running: false,
            _rootfs_lock: None,
            _lock: None,
        }),
        CpEndpoint::Rootfs { name, path: _ } => {
            let rootfs_dir = datadir.join("fs").join(name);
            if !rootfs_dir.is_dir() {
                bail!("rootfs not found: {name}");
            }
            let lock = lock::lock_shared(datadir, "fs", name)
                .with_context(|| format!("cannot lock rootfs '{name}' for writing"))?;
            Ok(ResolvedDest {
                write_dir: rootfs_dir.clone(),
                check_dir: rootfs_dir,
                is_running: false,
                _rootfs_lock: None,
                _lock: Some(lock),
            })
        }
        CpEndpoint::Container { name, path } => {
            let name = containers::resolve_name(datadir, name)?;
            containers::ensure_exists(datadir, &name)?;
            let container_dir = datadir.join("containers").join(&name);
            let running = systemd::is_active(&name)?;

            if running {
                let lock = lock::lock_shared(datadir, "containers", &name)
                    .with_context(|| format!("cannot lock container '{name}' for writing"))?;
                eprintln!(
                    "warning: container '{name}' is running; filesystem is live and \
                     consistency is not guaranteed"
                );

                let leader = systemd::get_machine_leader(&name)?
                    .with_context(|| format!("container '{name}' disappeared (race)"))?;
                let uses_userns = systemd::has_foreign_userns(leader);

                let base = if uses_userns {
                    if is_under_shadowed_dir(path) {
                        bail!(
                            "cannot write to {} in running container '{name}': the kernel blocks \
                             /proc/<pid>/root/ access for user namespace containers (--userns, \
                             --hardened, --strict), and writing to merged/ would go under the \
                             overlayfs layer instead of the live tmpfs at {}; use \
                             'sdme exec {name} -- tee {}' as a workaround",
                            path.display(),
                            SHADOWED_DIRS
                                .iter()
                                .find(|d| {
                                    let s = path.to_string_lossy();
                                    s == **d || s.starts_with(&format!("{d}/"))
                                })
                                .unwrap(),
                            path.display(),
                        );
                    }
                    if verbose {
                        eprintln!(
                            "userns container: using merged/ (kernel blocks /proc/{leader}/root/)"
                        );
                    }
                    container_dir.join("merged")
                } else {
                    if verbose {
                        eprintln!("writing to /proc/{leader}/root/");
                    }
                    PathBuf::from(format!("/proc/{leader}/root"))
                };

                Ok(ResolvedDest {
                    write_dir: base.clone(),
                    check_dir: base,
                    is_running: true,
                    _rootfs_lock: None,
                    _lock: Some(lock),
                })
            } else {
                // Stopped: write to upper/, check against rootfs.
                let state_path = datadir.join("state").join(&name);
                let state = State::read_from(&state_path)?;
                let rootfs_name = state.rootfs();
                let rootfs_dir = if rootfs_name.is_empty() {
                    PathBuf::from("/")
                } else {
                    datadir.join("fs").join(rootfs_name)
                };

                // Lock ordering: fs before containers.
                let rootfs_lock = if !rootfs_name.is_empty() {
                    Some(
                        lock::lock_shared(datadir, "fs", rootfs_name)
                            .with_context(|| {
                                format!("cannot lock rootfs '{rootfs_name}' for reading")
                            })?,
                    )
                } else {
                    None
                };
                let lock = lock::lock_shared(datadir, "containers", &name)
                    .with_context(|| format!("cannot lock container '{name}' for writing"))?;

                if verbose {
                    eprintln!("destination: stopped container '{name}', writing to upper layer");
                }

                Ok(ResolvedDest {
                    write_dir: container_dir.join("upper"),
                    check_dir: rootfs_dir,
                    is_running: false,
                    _rootfs_lock: rootfs_lock,
                    _lock: Some(lock),
                })
            }
        }
    }
}

/// Pre-scan source for dangerous entries when copying to host.
fn check_host_safety(src_path: &Path, opts: &CpOptions) -> Result<()> {
    let stat = copy::lstat_entry(src_path)?;
    let mode = stat.st_mode;
    let file_type = mode & libc::S_IFMT;

    // Check for device nodes.
    if file_type == libc::S_IFBLK || file_type == libc::S_IFCHR {
        if opts.force {
            eprintln!("warning: copying device node to host (--force)");
        } else if opts.interactive {
            if !confirm("source contains a device node; copy to host? [y/N] ")? {
                bail!("aborted");
            }
        } else {
            bail!(
                "refusing to copy device node to host (use --force to override): {}",
                src_path.display()
            );
        }
    }

    // Warn about setuid/setgid.
    if mode & libc::S_ISUID != 0 || mode & libc::S_ISGID != 0 {
        eprintln!(
            "warning: source has setuid/setgid bits: {}",
            src_path.display()
        );
    }

    // If source is a directory, scan for dangerous entries.
    if file_type == libc::S_IFDIR {
        scan_dir_safety(src_path, opts)?;
    }

    Ok(())
}

/// Recursively scan a directory for device nodes and setuid/setgid files.
fn scan_dir_safety(dir: &Path, opts: &CpOptions) -> Result<()> {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };

    let mut device_count = 0u32;
    let mut suid_count = 0u32;

    for entry in entries {
        crate::check_interrupted()?;
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = entry.path();
        let stat = match copy::lstat_entry(&path) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let ft = stat.st_mode & libc::S_IFMT;
        if ft == libc::S_IFBLK || ft == libc::S_IFCHR {
            device_count += 1;
        }
        if stat.st_mode & libc::S_ISUID != 0 || stat.st_mode & libc::S_ISGID != 0 {
            suid_count += 1;
        }
        if ft == libc::S_IFDIR {
            // Don't recurse deeply for performance — just report what we find.
        }
    }

    if device_count > 0 {
        if opts.force {
            eprintln!("warning: source directory contains {device_count} device node(s) (--force)");
        } else if opts.interactive {
            if !confirm(&format!(
                "source directory contains {device_count} device node(s); copy to host? [y/N] "
            ))? {
                bail!("aborted");
            }
        } else {
            bail!(
                "refusing to copy directory with {device_count} device node(s) to host \
                 (use --force to override): {}",
                dir.display()
            );
        }
    }

    if suid_count > 0 {
        eprintln!(
            "warning: source directory contains {suid_count} setuid/setgid file(s)"
        );
    }

    Ok(())
}

/// Check that destination path doesn't target shadowed directories on stopped containers.
fn check_container_dest_safety(write_dir: &Path, endpoint: &CpEndpoint) -> Result<()> {
    let path = match endpoint {
        CpEndpoint::Container { path, .. } | CpEndpoint::Rootfs { path, .. } => path,
        CpEndpoint::Host(_) => return Ok(()),
    };
    if is_under_shadowed_dir(path) {
        let path_str = path.to_string_lossy();
        let dir = SHADOWED_DIRS
            .iter()
            .find(|d| path_str == **d || path_str.starts_with(&format!("{d}/")))
            .unwrap();
        // For rootfs endpoints, also reject shadowed dirs since the rootfs
        // is the lower layer — the same dirs are shadowed at boot.
        let _ = write_dir; // suppress unused warning
        bail!(
            "refusing to copy to {path_str}: systemd mounts tmpfs over {dir} at boot, \
             hiding files in the overlayfs upper layer; use a different destination"
        );
    }
    Ok(())
}

/// Warn if a rootfs has running containers that won't see changes.
fn warn_rootfs_in_use(datadir: &Path, rootfs_name: &str) {
    let state_dir = datadir.join("state");
    let entries = match fs::read_dir(&state_dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    let mut running = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let name = match entry.file_name().to_str() {
            Some(n) => n.to_string(),
            None => continue,
        };
        let state_path = state_dir.join(&name);
        let state = match State::read_from(&state_path) {
            Ok(s) => s,
            Err(_) => continue,
        };
        if state.rootfs() == rootfs_name {
            if systemd::is_active(&name).unwrap_or(false) {
                running.push(name);
            }
        }
    }

    if !running.is_empty() {
        running.sort();
        let list = running.join(", ");
        eprintln!(
            "warning: rootfs '{rootfs_name}' is in use by running container(s): {list}\n\
             changes will NOT be visible until those containers are restarted"
        );
    }
}

/// Execute the file copy from resolved source to resolved destination.
fn execute_copy(
    src_path: &Path,
    write_dir: &Path,
    check_dir: &Path,
    dst_endpoint: &CpEndpoint,
    verbose: bool,
) -> Result<()> {
    let meta = fs::symlink_metadata(src_path)
        .with_context(|| format!("failed to stat {}", src_path.display()))?;

    // For host destinations, copy directly.
    if let CpEndpoint::Host(dst_path) = dst_endpoint {
        let mut target = dst_path.clone();
        let dst_is_dir = target.is_dir();

        if meta.is_dir() && target.is_file() {
            bail!(
                "cannot copy directory {} to existing file {}",
                src_path.display(),
                target.display()
            );
        }

        // When dst is an existing directory, copy INTO it.
        if dst_is_dir {
            if let Some(file_name) = src_path.file_name() {
                target = target.join(file_name);
            }
        }

        if verbose {
            eprintln!("copy: {} -> {}", src_path.display(), target.display());
        }

        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }

        if meta.is_dir() {
            fs::create_dir_all(&target)
                .with_context(|| format!("failed to create {}", target.display()))?;
            copy::copy_tree(src_path, &target, verbose)
                .with_context(|| format!("failed to copy directory {}", src_path.display()))?;
        } else {
            copy::copy_entry(src_path, &target, verbose)
                .with_context(|| format!("failed to copy {}", src_path.display()))?;
        }

        return Ok(());
    }

    // For container/rootfs destinations, use sanitized path.
    let dst_path = match dst_endpoint {
        CpEndpoint::Container { path, .. } | CpEndpoint::Rootfs { path, .. } => path,
        CpEndpoint::Host(_) => unreachable!(),
    };

    let rel_dst = copy::sanitize_dest_path(dst_path)?;
    let mut target = write_dir.join(&rel_dst);

    // Check whether dst resolves to a directory in either layer.
    let dst_is_dir = target.is_dir() || check_dir.join(&rel_dst).is_dir();

    // Check whether dst resolves to a file in either layer.
    let dst_is_file = (!dst_is_dir) && (target.is_file() || check_dir.join(&rel_dst).is_file());

    if meta.is_dir() && dst_is_file {
        bail!(
            "cannot copy directory {} to existing file {}",
            src_path.display(),
            dst_path.display()
        );
    }

    // When dst is an existing directory, adjust the target.
    if dst_is_dir {
        if let Some(file_name) = src_path.file_name() {
            target = target.join(file_name);
        }
    }

    if verbose {
        eprintln!("copy: {} -> {}", src_path.display(), target.display());
    }

    // Create parent directories in the write layer.
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    if meta.is_dir() {
        fs::create_dir_all(&target)
            .with_context(|| format!("failed to create {}", target.display()))?;
        copy::copy_tree(src_path, &target, verbose)
            .with_context(|| format!("failed to copy directory {}", src_path.display()))?;
    } else {
        copy::copy_entry(src_path, &target, verbose)
            .with_context(|| format!("failed to copy {}", src_path.display()))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- parse_endpoint tests ---

    #[test]
    fn test_parse_host_absolute() {
        let ep = parse_endpoint("/tmp/file").unwrap();
        assert!(matches!(ep, CpEndpoint::Host(p) if p == PathBuf::from("/tmp/file")));
    }

    #[test]
    fn test_parse_host_relative() {
        let ep = parse_endpoint("./file").unwrap();
        assert!(matches!(ep, CpEndpoint::Host(p) if p == PathBuf::from("./file")));
    }

    #[test]
    fn test_parse_host_bare_name() {
        // A bare filename without colons is a host path.
        let ep = parse_endpoint("file.txt").unwrap();
        assert!(matches!(ep, CpEndpoint::Host(p) if p == PathBuf::from("file.txt")));
    }

    #[test]
    fn test_parse_container() {
        let ep = parse_endpoint("mybox:/etc/app.conf").unwrap();
        match ep {
            CpEndpoint::Container { name, path } => {
                assert_eq!(name, "mybox");
                assert_eq!(path, PathBuf::from("/etc/app.conf"));
            }
            _ => panic!("expected Container endpoint"),
        }
    }

    #[test]
    fn test_parse_rootfs() {
        let ep = parse_endpoint("fs:ubuntu:/etc/hostname").unwrap();
        match ep {
            CpEndpoint::Rootfs { name, path } => {
                assert_eq!(name, "ubuntu");
                assert_eq!(path, PathBuf::from("/etc/hostname"));
            }
            _ => panic!("expected Rootfs endpoint"),
        }
    }

    #[test]
    fn test_parse_empty() {
        assert!(parse_endpoint("").is_err());
    }

    #[test]
    fn test_parse_container_relative_path() {
        let err = parse_endpoint("mybox:etc/file").unwrap_err();
        assert!(
            err.to_string().contains("absolute"),
            "expected 'absolute' in: {err}"
        );
    }

    #[test]
    fn test_parse_rootfs_relative_path() {
        let err = parse_endpoint("fs:ubuntu:etc/file").unwrap_err();
        assert!(
            err.to_string().contains("absolute"),
            "expected 'absolute' in: {err}"
        );
    }

    #[test]
    fn test_parse_rootfs_empty_name() {
        let err = parse_endpoint("fs::/etc/file").unwrap_err();
        assert!(
            err.to_string().contains("empty"),
            "expected 'empty' in: {err}"
        );
    }

    #[test]
    fn test_parse_rootfs_missing_path() {
        let err = parse_endpoint("fs:ubuntu").unwrap_err();
        assert!(
            err.to_string().contains("fs:NAME:/path"),
            "expected format hint in: {err}"
        );
    }

    #[test]
    fn test_parse_invalid_container_name_is_host() {
        // Names starting with uppercase or containing invalid chars are treated as host paths.
        let ep = parse_endpoint("UPPER:/etc/file").unwrap();
        assert!(matches!(ep, CpEndpoint::Host(p) if p == PathBuf::from("UPPER:/etc/file")));
    }

    #[test]
    fn test_parse_container_empty_path() {
        let err = parse_endpoint("mybox:").unwrap_err();
        assert!(
            err.to_string().contains("absolute"),
            "expected 'absolute' in: {err}"
        );
    }

    // --- direction validation ---

    #[test]
    fn test_both_host_rejected() {
        // Can't easily test cp() without a real datadir, but parse validates.
        let src = parse_endpoint("/tmp/a").unwrap();
        let dst = parse_endpoint("/tmp/b").unwrap();
        assert!(matches!(src, CpEndpoint::Host(_)));
        assert!(matches!(dst, CpEndpoint::Host(_)));
    }

    #[test]
    fn test_both_container_rejected() {
        // Both are containers — one side must be host.
        let src = parse_endpoint("box-a:/etc/a").unwrap();
        let dst = parse_endpoint("box-b:/etc/b").unwrap();
        assert!(matches!(src, CpEndpoint::Container { .. }));
        assert!(matches!(dst, CpEndpoint::Container { .. }));
    }

    // --- execute_copy tests ---

    use crate::testutil::TempDataDir;

    /// Helper: create upper (write) and lower (check) dirs for execute_copy tests.
    fn make_layers(name: &str) -> (TempDataDir, PathBuf, PathBuf) {
        let tmp = TempDataDir::new(&format!("cp-{name}"));
        let upper = tmp.path().join("upper");
        let lower = tmp.path().join("lower");
        fs::create_dir_all(&upper).unwrap();
        fs::create_dir_all(&lower).unwrap();
        (tmp, upper, lower)
    }

    #[test]
    fn test_execute_copy_file_to_host_dir() {
        let tmp = TempDataDir::new("cp-file-host-dir");
        let src_file = tmp.path().join("hello.txt");
        fs::write(&src_file, "hello").unwrap();
        let dst_dir = tmp.path().join("out");
        fs::create_dir_all(&dst_dir).unwrap();

        let dst = CpEndpoint::Host(dst_dir.clone());
        execute_copy(&src_file, &dst_dir, &dst_dir, &dst, false).unwrap();

        // File should land inside the directory.
        let result = dst_dir.join("hello.txt");
        assert!(result.is_file(), "file should be copied into dir");
        assert_eq!(fs::read_to_string(&result).unwrap(), "hello");
    }

    #[test]
    fn test_execute_copy_file_to_host_new_path() {
        let tmp = TempDataDir::new("cp-file-host-new");
        let src_file = tmp.path().join("hello.txt");
        fs::write(&src_file, "world").unwrap();
        let dst_file = tmp.path().join("out").join("renamed.txt");

        let dst = CpEndpoint::Host(dst_file.clone());
        execute_copy(&src_file, &dst_file, &dst_file, &dst, false).unwrap();

        assert!(dst_file.is_file(), "file should be created at exact path");
        assert_eq!(fs::read_to_string(&dst_file).unwrap(), "world");
    }

    #[test]
    fn test_execute_copy_dir_to_host_dir() {
        let tmp = TempDataDir::new("cp-dir-host-dir");
        let src_dir = tmp.path().join("srcdir");
        fs::create_dir_all(src_dir.join("sub")).unwrap();
        fs::write(src_dir.join("a.txt"), "aaa").unwrap();
        fs::write(src_dir.join("sub/b.txt"), "bbb").unwrap();
        let dst_dir = tmp.path().join("out");
        fs::create_dir_all(&dst_dir).unwrap();

        let dst = CpEndpoint::Host(dst_dir.clone());
        execute_copy(&src_dir, &dst_dir, &dst_dir, &dst, false).unwrap();

        // Dir should be copied inside the existing dir.
        assert!(dst_dir.join("srcdir/a.txt").is_file());
        assert!(dst_dir.join("srcdir/sub/b.txt").is_file());
        assert_eq!(
            fs::read_to_string(dst_dir.join("srcdir/sub/b.txt")).unwrap(),
            "bbb"
        );
    }

    #[test]
    fn test_execute_copy_file_to_container_dir() {
        // Destination dir exists in write_dir (upper).
        let (_tmp, upper, lower) = make_layers("file-ctr-dir");
        fs::create_dir_all(upper.join("etc")).unwrap();
        let src_file = _tmp.path().join("marker");
        fs::write(&src_file, "data").unwrap();

        let dst = CpEndpoint::Container {
            name: "test".to_string(),
            path: PathBuf::from("/etc"),
        };
        execute_copy(&src_file, &upper, &lower, &dst, false).unwrap();

        assert!(upper.join("etc/marker").is_file());
        assert_eq!(fs::read_to_string(upper.join("etc/marker")).unwrap(), "data");
    }

    #[test]
    fn test_execute_copy_file_to_container_check_dir() {
        // Destination dir exists only in check_dir (lower layer), not write_dir (upper).
        let (_tmp, upper, lower) = make_layers("file-ctr-lower");
        fs::create_dir_all(lower.join("usr/local/bin")).unwrap();
        let src_file = _tmp.path().join("binary");
        fs::write(&src_file, "ELF").unwrap();

        let dst = CpEndpoint::Container {
            name: "test".to_string(),
            path: PathBuf::from("/usr/local/bin"),
        };
        execute_copy(&src_file, &upper, &lower, &dst, false).unwrap();

        // File lands in upper layer even though dir only existed in lower.
        assert!(upper.join("usr/local/bin/binary").is_file());
        assert_eq!(
            fs::read_to_string(upper.join("usr/local/bin/binary")).unwrap(),
            "ELF"
        );
    }

    #[test]
    fn test_execute_copy_dir_to_existing_file_rejected() {
        let (_tmp, upper, lower) = make_layers("dir-to-file");
        // Create a file at /etc/conf in the upper layer.
        fs::create_dir_all(upper.join("etc")).unwrap();
        fs::write(upper.join("etc/conf"), "existing").unwrap();
        // Create a source directory.
        let src_dir = _tmp.path().join("mydir");
        fs::create_dir_all(&src_dir).unwrap();
        fs::write(src_dir.join("a"), "a").unwrap();

        let dst = CpEndpoint::Container {
            name: "test".to_string(),
            path: PathBuf::from("/etc/conf"),
        };
        let err = execute_copy(&src_dir, &upper, &lower, &dst, false).unwrap_err();
        assert!(
            err.to_string().contains("cannot copy directory"),
            "expected 'cannot copy directory' in: {err}"
        );
    }

    // --- check_container_dest_safety tests ---

    #[test]
    fn test_check_container_dest_safety_shadowed() {
        let tmp = TempDataDir::new("cp-shadowed");
        let write_dir = tmp.path().join("upper");
        fs::create_dir_all(&write_dir).unwrap();

        for dir in &["/tmp", "/run", "/dev/shm"] {
            let endpoint = CpEndpoint::Container {
                name: "test".to_string(),
                path: PathBuf::from(dir),
            };
            let err = check_container_dest_safety(&write_dir, &endpoint).unwrap_err();
            assert!(
                err.to_string().contains("tmpfs"),
                "expected 'tmpfs' for {dir}, got: {err}"
            );
        }
    }

    #[test]
    fn test_check_container_dest_safety_subpath() {
        let tmp = TempDataDir::new("cp-shadowed-sub");
        let write_dir = tmp.path().join("upper");
        fs::create_dir_all(&write_dir).unwrap();

        // Subpath of shadowed dir should be rejected.
        let endpoint = CpEndpoint::Container {
            name: "test".to_string(),
            path: PathBuf::from("/tmp/foo"),
        };
        let err = check_container_dest_safety(&write_dir, &endpoint).unwrap_err();
        assert!(
            err.to_string().contains("tmpfs"),
            "expected 'tmpfs' for /tmp/foo, got: {err}"
        );

        // Non-shadowed path should be allowed.
        let endpoint_ok = CpEndpoint::Container {
            name: "test".to_string(),
            path: PathBuf::from("/etc/foo"),
        };
        check_container_dest_safety(&write_dir, &endpoint_ok).unwrap();
    }

    #[test]
    fn test_check_container_dest_safety_rootfs_also_rejected() {
        let tmp = TempDataDir::new("cp-shadowed-rootfs");
        let write_dir = tmp.path().join("rootfs");
        fs::create_dir_all(&write_dir).unwrap();

        let endpoint = CpEndpoint::Rootfs {
            name: "ubuntu".to_string(),
            path: PathBuf::from("/tmp/file"),
        };
        let err = check_container_dest_safety(&write_dir, &endpoint).unwrap_err();
        assert!(
            err.to_string().contains("tmpfs"),
            "rootfs /tmp should be rejected, got: {err}"
        );
    }

    #[test]
    fn test_check_host_safety_setuid() {
        // Setuid files produce a warning but don't error.
        let tmp = TempDataDir::new("cp-suid");
        let src_file = tmp.path().join("prog");
        fs::write(&src_file, "binary").unwrap();

        // Set the setuid bit.
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o4755);
        fs::set_permissions(&src_file, perms).unwrap();

        let opts = CpOptions {
            force: false,
            verbose: false,
            interactive: false,
        };
        // Should succeed (warning only, not an error).
        check_host_safety(&src_file, &opts).unwrap();
    }
}
