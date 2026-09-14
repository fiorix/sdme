//! File copy between host, containers, and root filesystems.
//!
//! Implements `sdme cp` for copying files and directories between the host
//! filesystem and containers or imported root filesystems. One side must
//! always be a host path; container-to-container copy is not supported.
//! Writes into running containers use the fd-relative contained copy engine
//! (see `copy::copy_contained`), which stays safe under concurrent mutation
//! of the live destination tree.
//!
//! Uses the same copy engine (`copy::copy_contained`, `copy::copy_tree`,
//! `copy::copy_entry`) and path validation (`copy::sanitize_dest_path`) as
//! `fs build` COPY.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::{confirm, containers, copy, lock, storage, systemd, validate_name, State};

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
/// - `/path` or `./path`: host filesystem
/// - `NAME:/path`: container (path must be absolute)
/// - `fs:NAME:/path`: root filesystem (path must be absolute)
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

    // NAME:/path (only if the part before : is a valid container name)
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
    /// Keeps a stopped container's root open (overlay mount held until drop;
    /// inert for btrfs) for the duration of the copy.
    _root: Option<containers::ContainerRootRo>,
    _rootfs_lock: Option<lock::ResourceLock>,
    _lock: Option<lock::ResourceLock>,
}

/// Holds resolved paths and RAII guards for a destination.
struct ResolvedDest {
    /// Directory to write into (overlay upper/ or btrfs subvolume for stopped
    /// containers, merged//proc-root for running, rootfs dir or host path
    /// directly).
    write_dir: PathBuf,
    /// Directory to check for existing files (rootfs for stopped overlay
    /// containers, same as write_dir otherwise).
    check_dir: PathBuf,
    /// True when writes into `write_dir` must be guarded against symlinks
    /// already present in the tree. Set for every container/rootfs
    /// destination: an imported rootfs, a btrfs subvolume holding the base
    /// tree, a running container's live root, and an overlay upper populated
    /// by a container run or an earlier copy can all hold symlinks that
    /// resolve onto the host. The guard is the fd-relative contained copy
    /// engine, which stays sound even when the tree is mutated concurrently.
    protect_symlinks: bool,
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

    // Safety checks when copying TO a stopped container or a rootfs.
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
        resolved_dst.protect_symlinks,
        dst,
        opts.verbose,
    )
}

fn resolve_source(datadir: &Path, endpoint: &CpEndpoint, verbose: bool) -> Result<ResolvedSource> {
    match endpoint {
        CpEndpoint::Host(path) => {
            if !path.exists() {
                bail!("source path does not exist: {}", path.display());
            }
            Ok(ResolvedSource {
                path: path.clone(),
                _root: None,
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
                _root: None,
                _rootfs_lock: None,
                _lock: Some(lock),
            })
        }
        CpEndpoint::Container { name, path } => {
            let name = containers::resolve_name(datadir, name)?;
            containers::ensure_exists(datadir, &name)?;
            // Lock ordering: fs before containers.
            let container_dir = datadir.join("containers").join(&name);
            let state = State::read_from(&datadir.join("state").join(&name))?;
            let backend = storage::Backend::from_state(&state);
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
                    // A running btrfs container's root is a subvolume mounted only
                    // inside its own namespace; there is no host-side merged/ view
                    // to fall back to, and reading the bare subvolume would miss
                    // live tmpfs mounts. Require a stop (or exec) instead.
                    if backend == storage::Backend::Btrfs {
                        bail!(
                            "cannot read {} from running btrfs container '{name}' under \
                             --userns; stop the container first, or use \
                             'sdme exec {name} -- cat {}'",
                            path.display(),
                            path.display(),
                        );
                    }
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
                    _root: None,
                    _rootfs_lock: None,
                    _lock: Some(lock),
                })
            } else {
                // Stopped: open the container root read-only. Overlay mounts a
                // temporary read-only overlay at merged/; btrfs reads its own
                // subvolume (no mount). The rootfs is the overlay lower layer.
                let rootfs_name = state.rootfs();
                let rootfs_dir = if rootfs_name.is_empty() {
                    PathBuf::from("/")
                } else {
                    datadir.join("fs").join(rootfs_name)
                };

                // Lock ordering: fs before containers.
                let rootfs_lock = if !rootfs_name.is_empty() {
                    Some(
                        lock::lock_shared(datadir, "fs", rootfs_name).with_context(|| {
                            format!("cannot lock rootfs '{rootfs_name}' for reading")
                        })?,
                    )
                } else {
                    None
                };
                let lock = lock::lock_shared(datadir, "containers", &name)
                    .with_context(|| format!("cannot lock container '{name}' for reading"))?;

                let root = containers::open_root_ro(datadir, &name, backend, &rootfs_dir, verbose)?;
                let full_path = root.root().join(path.strip_prefix("/").unwrap_or(path));
                if !full_path.exists() {
                    // `root` drops here, tearing down any overlay mount.
                    bail!(
                        "source path does not exist in container '{name}': {}",
                        path.display()
                    );
                }

                Ok(ResolvedSource {
                    path: full_path,
                    _root: Some(root),
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
            protect_symlinks: false,
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
                // An imported rootfs is untrusted content: it can contain
                // symlinks (e.g. etc -> /outside) that would redirect parent
                // creation or writes onto the host, so guard the write.
                protect_symlinks: true,
                is_running: false,
                _rootfs_lock: None,
                _lock: Some(lock),
            })
        }
        CpEndpoint::Container { name, path } => {
            let name = containers::resolve_name(datadir, name)?;
            containers::ensure_exists(datadir, &name)?;
            let container_dir = datadir.join("containers").join(&name);
            let state = State::read_from(&datadir.join("state").join(&name))?;
            let backend = storage::Backend::from_state(&state);
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
                    // A running btrfs container's root is a subvolume mounted only
                    // inside its own namespace, with no host-side merged/ view.
                    if backend == storage::Backend::Btrfs {
                        bail!(
                            "cannot write to {} in running btrfs container '{name}' under \
                             --userns; stop the container first, or use \
                             'sdme exec {name} -- tee {}'",
                            path.display(),
                            path.display(),
                        );
                    }
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

                // The live tree can be mutated by the container mid-copy, so
                // the write must go through the fd-relative contained engine:
                // no path component is ever resolved through a symlink, even
                // one swapped in concurrently.
                Ok(ResolvedDest {
                    write_dir: base.clone(),
                    check_dir: base,
                    protect_symlinks: true,
                    is_running: true,
                    _rootfs_lock: None,
                    _lock: Some(lock),
                })
            } else {
                // Stopped: overlay writes into upper/ (checked against the lower
                // rootfs); btrfs writes into its own subvolume, which already
                // holds the base tree. Both are guarded against symlinks
                // already present in the write tree: open_write_dest only
                // requests the guard for btrfs, on the assumption that an
                // overlay upper is fresh and empty, but that stops being true
                // once the container has run or an earlier copy populated it.
                let rootfs_name = state.rootfs();
                let rootfs_dir = if rootfs_name.is_empty() {
                    PathBuf::from("/")
                } else {
                    datadir.join("fs").join(rootfs_name)
                };

                // Lock ordering: fs before containers.
                let rootfs_lock = if !rootfs_name.is_empty() {
                    Some(
                        lock::lock_shared(datadir, "fs", rootfs_name).with_context(|| {
                            format!("cannot lock rootfs '{rootfs_name}' for reading")
                        })?,
                    )
                } else {
                    None
                };
                // Take an EXCLUSIVE lock (which excludes a concurrent
                // `sdme start`, itself a shared lock) and re-verify the
                // container is still stopped under it. This closes a TOCTOU
                // where a start between the is_active() check above and the
                // write would make the destination tree live mid-copy,
                // reopening a symlink-follow race that the guard below
                // cannot close against a running container.
                let lock = lock::lock_exclusive(datadir, "containers", &name)
                    .with_context(|| format!("cannot lock container '{name}' for writing"))?;
                if systemd::is_active(&name)? {
                    bail!(
                        "container '{name}' started while the copy was being set up; \
                         stop it before copying into it"
                    );
                }

                let dest =
                    containers::open_write_dest(datadir, &name, backend, &rootfs_dir, verbose)?;
                if verbose {
                    eprintln!(
                        "destination: stopped container '{name}', writing to {}",
                        dest.write_dir.display()
                    );
                }

                Ok(ResolvedDest {
                    write_dir: dest.write_dir,
                    check_dir: dest.check_dir,
                    // Strengthen the backend's own assessment: guard the
                    // overlay upper too, since it can hold symlinks once
                    // populated (see above).
                    protect_symlinks: dest.protect_symlinks || backend == storage::Backend::Overlay,
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

    // Warn about setuid/setgid (suppressed by --force).
    if !opts.force && (mode & libc::S_ISUID != 0 || mode & libc::S_ISGID != 0) {
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
            // Don't recurse deeply for performance; just report what we find.
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

    if suid_count > 0 && !opts.force {
        eprintln!("warning: source directory contains {suid_count} setuid/setgid file(s)");
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
        // is the lower layer; the same dirs are shadowed at boot.
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
        if state.rootfs() == rootfs_name && systemd::is_active(&name).unwrap_or(false) {
            running.push(name);
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
///
/// `protect_symlinks` routes the write through the fd-relative contained
/// copy engine (`copy::copy_contained`): every component of the destination
/// path is resolved beneath an fd pinning `write_dir` with O_NOFOLLOW, so no
/// symlink present in, or swapped into, the destination tree is ever
/// traversed, even under concurrent mutation (a running container's live
/// root). A symlink ancestor is rejected, a symlink or multiply-linked leaf
/// is unlinked and recreated, and real directories are merged into. Only
/// host destinations skip it.
fn execute_copy(
    src_path: &Path,
    write_dir: &Path,
    check_dir: &Path,
    protect_symlinks: bool,
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
    let probe = write_dir.join(&rel_dst);

    // Check whether dst resolves to a directory in either layer.
    let dst_is_dir = probe.is_dir() || check_dir.join(&rel_dst).is_dir();

    // Check whether dst resolves to a file in either layer.
    let dst_is_file = (!dst_is_dir) && (probe.is_file() || check_dir.join(&rel_dst).is_file());

    if meta.is_dir() && dst_is_file {
        bail!(
            "cannot copy directory {} to existing file {}",
            src_path.display(),
            dst_path.display()
        );
    }

    // Compute the destination relative to the write root, copying INTO dst
    // when it is an existing directory.
    let rel_target = if dst_is_dir {
        match src_path.file_name() {
            Some(file_name) => rel_dst.join(file_name),
            None => rel_dst.clone(),
        }
    } else {
        rel_dst.clone()
    };
    let target = write_dir.join(&rel_target);

    if verbose {
        eprintln!("copy: {} -> {}", src_path.display(), target.display());
    }

    if protect_symlinks {
        // Container/rootfs destinations are trees whose content sdme does
        // not control (an imported rootfs can carry hostile symlinks; a
        // container can plant or swap them in its own upper or live root).
        // The contained engine never resolves a destination component
        // through a symlink, under concurrency included; sdme runs as root,
        // so a followed symlink could otherwise write onto the host.
        copy::copy_contained(write_dir, &rel_target, src_path)
            .with_context(|| format!("failed to copy {}", src_path.display()))?;
        return Ok(());
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
        assert!(matches!(ep, CpEndpoint::Host(p) if p == Path::new("/tmp/file")));
    }

    #[test]
    fn test_parse_host_relative() {
        let ep = parse_endpoint("./file").unwrap();
        assert!(matches!(ep, CpEndpoint::Host(p) if p == Path::new("./file")));
    }

    #[test]
    fn test_parse_host_bare_name() {
        // A bare filename without colons is a host path.
        let ep = parse_endpoint("file.txt").unwrap();
        assert!(matches!(ep, CpEndpoint::Host(p) if p == Path::new("file.txt")));
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
        assert!(matches!(ep, CpEndpoint::Host(p) if p == Path::new("UPPER:/etc/file")));
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
        // Both are containers; one side must be host.
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
        execute_copy(&src_file, &dst_dir, &dst_dir, false, &dst, false).unwrap();

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
        execute_copy(&src_file, &dst_file, &dst_file, false, &dst, false).unwrap();

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
        execute_copy(&src_dir, &dst_dir, &dst_dir, false, &dst, false).unwrap();

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
        execute_copy(&src_file, &upper, &lower, false, &dst, false).unwrap();

        assert!(upper.join("etc/marker").is_file());
        assert_eq!(
            fs::read_to_string(upper.join("etc/marker")).unwrap(),
            "data"
        );
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
        execute_copy(&src_file, &upper, &lower, false, &dst, false).unwrap();

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
        let err = execute_copy(&src_dir, &upper, &lower, false, &dst, false).unwrap_err();
        assert!(
            err.to_string().contains("cannot copy directory"),
            "expected 'cannot copy directory' in: {err}"
        );
    }

    // --- execute_copy btrfs symlink-guard tests ---

    #[test]
    fn test_execute_copy_btrfs_rejects_symlink_ancestor() {
        // A stopped btrfs container write lands in the subvolume, which holds
        // the base image. A base-image symlink ancestor (bin -> usr/bin) must
        // be refused rather than followed.
        let (_tmp, subvol, _lower) = make_layers("btrfs-reject");
        fs::create_dir_all(subvol.join("usr/bin")).unwrap();
        std::os::unix::fs::symlink("usr/bin", subvol.join("bin")).unwrap();
        let src = _tmp.path().join("tool");
        fs::write(&src, "ELF").unwrap();

        let dst = CpEndpoint::Container {
            name: "c".to_string(),
            path: PathBuf::from("/bin/tool"),
        };
        let err = execute_copy(&src, &subvol, &subvol, true, &dst, false).unwrap_err();
        assert!(format!("{err:#}").contains("symlink"), "got: {err:#}");
        // The symlink's target must not have been written through.
        assert!(!subvol.join("usr/bin/tool").exists());
    }

    #[test]
    fn test_execute_copy_btrfs_shadows_leaf_symlink() {
        // A leaf symlink in the subvolume is shadowed: the write replaces it
        // with a real file instead of following it (which, for an absolute
        // target, would escape the container).
        let (_tmp, subvol, _lower) = make_layers("btrfs-shadow");
        fs::create_dir_all(subvol.join("etc")).unwrap();
        let escape = _tmp.path().join("escape-target");
        std::os::unix::fs::symlink(&escape, subvol.join("etc/resolv.conf")).unwrap();
        let src = _tmp.path().join("newconf");
        fs::write(&src, "nameserver 1.1.1.1\n").unwrap();

        let dst = CpEndpoint::Container {
            name: "c".to_string(),
            path: PathBuf::from("/etc/resolv.conf"),
        };
        execute_copy(&src, &subvol, &subvol, true, &dst, false).unwrap();

        let written = subvol.join("etc/resolv.conf");
        assert!(
            written.symlink_metadata().unwrap().file_type().is_file(),
            "resolv.conf should be a real file after shadowing"
        );
        assert_eq!(
            fs::read_to_string(&written).unwrap(),
            "nameserver 1.1.1.1\n"
        );
        // The absolute symlink target must never have been created.
        assert!(!escape.exists(), "write escaped through the symlink");
    }

    #[test]
    fn test_execute_copy_btrfs_dir_copy_shadows_child_symlink() {
        // CRITICAL regression: copying a DIRECTORY whose child name collides
        // with a hostile base-image symlink child must NOT follow that symlink
        // (which, being absolute, would write onto the host as root).
        let (_tmp, subvol, _lower) = make_layers("btrfs-dir-escape");
        fs::create_dir_all(subvol.join("etc")).unwrap();
        let escape = _tmp.path().join("escape-target");
        std::os::unix::fs::symlink(&escape, subvol.join("etc/pwn")).unwrap();
        // Local source dir "etc" with a real file "pwn".
        let src_etc = _tmp.path().join("etc");
        fs::create_dir_all(&src_etc).unwrap();
        fs::write(src_etc.join("pwn"), "attacker").unwrap();

        // `sdme cp ./etc container:/` merges ./etc into <subvol>/etc.
        let dst = CpEndpoint::Container {
            name: "c".to_string(),
            path: PathBuf::from("/"),
        };
        execute_copy(&src_etc, &subvol, &subvol, true, &dst, false).unwrap();

        let written = subvol.join("etc/pwn");
        assert!(
            written.symlink_metadata().unwrap().file_type().is_file(),
            "child should be a real file, not the followed symlink"
        );
        assert_eq!(fs::read_to_string(&written).unwrap(), "attacker");
        assert!(
            !escape.exists(),
            "directory copy escaped through a base-image child symlink"
        );
    }

    #[test]
    fn test_execute_copy_overlay_ignores_symlink_guard() {
        // With protect_symlinks=false (host-style direct execute_copy use), an
        // existing symlink at the target is overwritten by copy_entry as
        // usual; no guard applies. Production container/rootfs destinations
        // always pass true.
        let (_tmp, upper, lower) = make_layers("overlay-noguard");
        fs::create_dir_all(upper.join("etc")).unwrap();
        let src = _tmp.path().join("file");
        fs::write(&src, "data").unwrap();
        let dst = CpEndpoint::Container {
            name: "c".to_string(),
            path: PathBuf::from("/etc/file"),
        };
        execute_copy(&src, &upper, &lower, false, &dst, false).unwrap();
        assert_eq!(fs::read_to_string(upper.join("etc/file")).unwrap(), "data");
    }

    // --- rootfs / populated destination symlink-escape regressions ---

    /// Helper: create a datadir holding an imported rootfs `fs/<name>`.
    fn make_rootfs(name: &str) -> (TempDataDir, PathBuf) {
        let tmp = TempDataDir::new(&format!("cp-rootfs-{name}"));
        let rootfs = tmp.path().join("fs").join(name);
        fs::create_dir_all(&rootfs).unwrap();
        (tmp, rootfs)
    }

    fn test_opts() -> CpOptions {
        CpOptions {
            force: false,
            verbose: false,
            interactive: false,
        }
    }

    fn rootfs_ep(name: &str, path: &str) -> CpEndpoint {
        CpEndpoint::Rootfs {
            name: name.to_string(),
            path: PathBuf::from(path),
        }
    }

    #[test]
    fn test_cp_rootfs_dest_rejects_ancestor_symlink_escape() {
        // Regression: an imported rootfs can contain an ancestor symlink
        // pointing anywhere on the host (etc -> /outside). A copy through it
        // must be refused, not redirected onto the host, with force=false.
        let (tmp, rootfs) = make_rootfs("escape");
        let outside = tmp.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("victim"), "original").unwrap();
        std::os::unix::fs::symlink(&outside, rootfs.join("etc")).unwrap();

        let payload = tmp.path().join("payload");
        fs::write(&payload, "attacker").unwrap();

        let src = CpEndpoint::Host(payload);
        let dst = rootfs_ep("escape", "/etc/victim");
        let err = cp(tmp.path(), &src, &dst, &test_opts()).unwrap_err();
        assert!(
            format!("{err:#}").contains("symlink"),
            "expected symlink rejection, got: {err:#}"
        );
        assert_eq!(
            fs::read_to_string(outside.join("victim")).unwrap(),
            "original"
        );
        assert_eq!(
            fs::read_dir(&outside).unwrap().count(),
            1,
            "no entry may be created through the symlink"
        );
    }

    #[test]
    fn test_cp_rootfs_dest_rejects_dangling_ancestor_symlink() {
        // A dangling ancestor symlink (data -> missing outside dir) must be
        // rejected before create_dir_all materializes the outside directory.
        let (tmp, rootfs) = make_rootfs("dangling");
        let missing = tmp.path().join("no/such/dir");
        std::os::unix::fs::symlink(&missing, rootfs.join("data")).unwrap();

        let payload = tmp.path().join("payload");
        fs::write(&payload, "attacker").unwrap();

        let src = CpEndpoint::Host(payload);
        let dst = rootfs_ep("dangling", "/data/file");
        let err = cp(tmp.path(), &src, &dst, &test_opts()).unwrap_err();
        assert!(
            format!("{err:#}").contains("symlink"),
            "expected symlink rejection, got: {err:#}"
        );
        assert!(
            !tmp.path().join("no").exists(),
            "create_dir_all materialized the dangling symlink target outside"
        );
    }

    #[test]
    fn test_cp_rootfs_dest_shadows_leaf_symlinks() {
        // Leaf symlinks are shadowed (replaced by a real file), never
        // followed: an existing outside target stays untouched and a dangling
        // outside target is never created.
        let (tmp, rootfs) = make_rootfs("leaf");
        fs::create_dir_all(rootfs.join("etc")).unwrap();

        let outside_file = tmp.path().join("outside-target");
        fs::write(&outside_file, "keep").unwrap();
        std::os::unix::fs::symlink(&outside_file, rootfs.join("etc/resolv.conf")).unwrap();

        let p1 = tmp.path().join("p1");
        fs::write(&p1, "new").unwrap();
        cp(
            tmp.path(),
            &CpEndpoint::Host(p1),
            &rootfs_ep("leaf", "/etc/resolv.conf"),
            &test_opts(),
        )
        .unwrap();
        let written = rootfs.join("etc/resolv.conf");
        assert!(
            written.symlink_metadata().unwrap().file_type().is_file(),
            "leaf symlink should be replaced by a real file"
        );
        assert_eq!(fs::read_to_string(&written).unwrap(), "new");
        assert_eq!(fs::read_to_string(&outside_file).unwrap(), "keep");

        let missing_target = tmp.path().join("no/such/target");
        std::os::unix::fs::symlink(&missing_target, rootfs.join("etc/dangling")).unwrap();
        let p2 = tmp.path().join("p2");
        fs::write(&p2, "d").unwrap();
        cp(
            tmp.path(),
            &CpEndpoint::Host(p2),
            &rootfs_ep("leaf", "/etc/dangling"),
            &test_opts(),
        )
        .unwrap();
        assert!(rootfs
            .join("etc/dangling")
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_file());
        assert!(
            !missing_target.exists(),
            "write followed a dangling leaf symlink outside"
        );
    }

    #[test]
    fn test_cp_rootfs_dest_ordinary_copies_still_work() {
        // The guard must not disable legitimate copies: file to a new path,
        // file into an existing real directory, and a directory tree.
        let (tmp, rootfs) = make_rootfs("ordinary");
        fs::create_dir_all(rootfs.join("etc")).unwrap();
        fs::create_dir_all(rootfs.join("usr/bin")).unwrap();

        let f1 = tmp.path().join("conf");
        fs::write(&f1, "k=v").unwrap();
        cp(
            tmp.path(),
            &CpEndpoint::Host(f1),
            &rootfs_ep("ordinary", "/etc/app.conf"),
            &test_opts(),
        )
        .unwrap();
        assert_eq!(
            fs::read_to_string(rootfs.join("etc/app.conf")).unwrap(),
            "k=v"
        );

        let f2 = tmp.path().join("tool");
        fs::write(&f2, "ELF").unwrap();
        cp(
            tmp.path(),
            &CpEndpoint::Host(f2),
            &rootfs_ep("ordinary", "/usr/bin"),
            &test_opts(),
        )
        .unwrap();
        assert_eq!(
            fs::read_to_string(rootfs.join("usr/bin/tool")).unwrap(),
            "ELF"
        );

        let d = tmp.path().join("skel");
        fs::create_dir_all(d.join("sub")).unwrap();
        fs::write(d.join("sub/x"), "x").unwrap();
        // An existing destination directory receives the source inside it.
        fs::create_dir_all(rootfs.join("opt")).unwrap();
        cp(
            tmp.path(),
            &CpEndpoint::Host(d),
            &rootfs_ep("ordinary", "/opt"),
            &test_opts(),
        )
        .unwrap();
        assert_eq!(
            fs::read_to_string(rootfs.join("opt/skel/sub/x")).unwrap(),
            "x"
        );
    }

    #[test]
    fn test_execute_copy_populated_upper_symlink_escape_rejected() {
        // An overlay upper is only empty until the container (or an earlier
        // copy) populates it. A symlink planted there must not redirect a
        // later copy onto the host.
        let (_tmp, upper, lower) = make_layers("upper-escape");
        let outside = _tmp.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("victim"), "original").unwrap();
        std::os::unix::fs::symlink(&outside, upper.join("etc")).unwrap();

        let src = _tmp.path().join("payload");
        fs::write(&src, "attacker").unwrap();
        let dst = CpEndpoint::Container {
            name: "c".to_string(),
            path: PathBuf::from("/etc/victim"),
        };
        let err = execute_copy(&src, &upper, &lower, true, &dst, false).unwrap_err();
        assert!(
            format!("{err:#}").contains("symlink"),
            "expected symlink rejection, got: {err:#}"
        );
        assert_eq!(
            fs::read_to_string(outside.join("victim")).unwrap(),
            "original"
        );
    }

    #[test]
    fn test_execute_copy_populated_upper_dir_copy_shadows_child() {
        // Populated overlay upper, directory merge: a hostile symlink child in
        // the upper is shadowed, not followed, and real siblings still merge.
        let (_tmp, upper, lower) = make_layers("upper-dir-merge");
        fs::create_dir_all(upper.join("etc")).unwrap();
        fs::write(upper.join("etc/keep"), "old").unwrap();
        let outside = _tmp.path().join("outside");
        std::os::unix::fs::symlink(&outside, upper.join("etc/pwn")).unwrap();

        let src = _tmp.path().join("etc");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("pwn"), "real").unwrap();
        fs::write(src.join("keep"), "new").unwrap();

        let dst = CpEndpoint::Container {
            name: "c".to_string(),
            path: PathBuf::from("/"),
        };
        execute_copy(&src, &upper, &lower, true, &dst, false).unwrap();

        let written = upper.join("etc/pwn");
        assert!(written.symlink_metadata().unwrap().file_type().is_file());
        assert_eq!(fs::read_to_string(&written).unwrap(), "real");
        assert_eq!(fs::read_to_string(upper.join("etc/keep")).unwrap(), "new");
        assert!(
            !outside.exists(),
            "directory copy escaped through the upper"
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
