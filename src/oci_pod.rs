//! OCI pod network namespace management.
//!
//! An OCI pod is a shared network namespace that multiple OCI app containers
//! can join, so their applications see the same localhost. This enables
//! patterns like "database :5432 + app :8080, reachable via 127.0.0.1".
//!
//! **State (persistent):** `/var/lib/sdme/oci-pods/{name}` — KEY=VALUE file.
//! **Runtime (volatile):** `/run/sdme/oci-pods/{name}` — bind-mount of the
//! network namespace fd. Disappears on reboot; lazily recreated by
//! [`ensure_runtime`] when a container references the pod.

use std::ffi::CString;
use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::{validate_name, State};

/// Persistent state directory for OCI pods.
const STATE_SUBDIR: &str = "oci-pods";

/// Runtime directory for netns bind-mounts (volatile, under /run).
const RUNTIME_DIR: &str = "/run/sdme/oci-pods";

/// Information about a listed OCI pod.
pub struct PodInfo {
    pub name: String,
    pub created: String,
    pub active: bool,
}

/// Create a new OCI pod: allocate a network namespace with loopback up,
/// bind-mount it to the runtime path, and write the persistent state file.
pub fn create(datadir: &Path, name: &str, verbose: bool) -> Result<()> {
    validate_name(name)?;

    // Ensure persistent state directory exists.
    let state_dir = datadir.join(STATE_SUBDIR);
    fs::create_dir_all(&state_dir)
        .with_context(|| format!("failed to create {}", state_dir.display()))?;

    let state_path = state_dir.join(name);
    if state_path.exists() {
        bail!("oci-pod already exists: {name}");
    }

    // Create the network namespace and bind-mount it.
    create_netns(name, verbose)?;

    // Write persistent state.
    let mut state = State::new();
    let created = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs();
    state.set("CREATED", created.to_string());
    state.write_to(&state_path)?;

    if verbose {
        eprintln!("wrote state: {}", state_path.display());
    }

    Ok(())
}

/// List all OCI pods.
pub fn list(datadir: &Path) -> Result<Vec<PodInfo>> {
    let state_dir = datadir.join(STATE_SUBDIR);
    if !state_dir.is_dir() {
        return Ok(Vec::new());
    }

    let mut entries = Vec::new();
    for entry in fs::read_dir(&state_dir)
        .with_context(|| format!("failed to read {}", state_dir.display()))?
    {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = match entry.file_name().to_str() {
            Some(s) => s.to_string(),
            None => continue,
        };

        let state_path = state_dir.join(&name);
        let created = match State::read_from(&state_path) {
            Ok(s) => s.get("CREATED").unwrap_or("").to_string(),
            Err(_) => String::new(),
        };

        let runtime_path = Path::new(RUNTIME_DIR).join(&name);
        let active = runtime_path.exists();

        entries.push(PodInfo {
            name,
            created,
            active,
        });
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(entries)
}

/// Remove one or more OCI pods.
///
/// Unmounts the runtime netns, removes the runtime file, and deletes the
/// persistent state file. Errors if any container still references this pod
/// unless `force` is true.
pub fn remove(datadir: &Path, name: &str, force: bool, verbose: bool) -> Result<()> {
    let state_path = datadir.join(STATE_SUBDIR).join(name);
    if !state_path.exists() {
        bail!("oci-pod not found: {name}");
    }

    // Check for containers referencing this pod.
    if !force {
        let state_dir = datadir.join("state");
        if state_dir.is_dir() {
            for entry in fs::read_dir(&state_dir)? {
                let entry = entry?;
                if !entry.file_type()?.is_file() {
                    continue;
                }
                let ct_name = entry.file_name().to_string_lossy().to_string();
                let ct_state_path = state_dir.join(&ct_name);
                if let Ok(state) = State::read_from(&ct_state_path) {
                    if state.get("OCI_POD") == Some(name) {
                        bail!(
                            "oci-pod '{name}' is referenced by container '{ct_name}'; \
                             remove the container first or use --force"
                        );
                    }
                }
            }
        }
    }

    // Unmount and remove runtime file.
    let runtime_path = Path::new(RUNTIME_DIR).join(name);
    if runtime_path.exists() {
        unmount_netns(&runtime_path, verbose)?;
    }

    // Remove persistent state.
    fs::remove_file(&state_path)
        .with_context(|| format!("failed to remove {}", state_path.display()))?;
    if verbose {
        eprintln!("removed state: {}", state_path.display());
    }

    Ok(())
}

/// Ensure the runtime netns bind-mount exists for a pod.
///
/// Called at container start time. If the runtime file is missing (e.g. after
/// reboot) but the persistent state exists, the netns is recreated.
pub fn ensure_runtime(datadir: &Path, name: &str, verbose: bool) -> Result<()> {
    let state_path = datadir.join(STATE_SUBDIR).join(name);
    if !state_path.exists() {
        bail!("oci-pod not found: {name}");
    }

    let runtime_path = Path::new(RUNTIME_DIR).join(name);
    if runtime_path.exists() {
        if verbose {
            eprintln!("oci-pod '{name}' runtime netns already exists");
        }
        return Ok(());
    }

    if verbose {
        eprintln!("recreating runtime netns for oci-pod '{name}'");
    }
    create_netns(name, verbose)
}

/// Check that a pod exists in the catalogue (state file present).
pub fn exists(datadir: &Path, name: &str) -> bool {
    datadir.join(STATE_SUBDIR).join(name).exists()
}

/// Return the runtime path for a pod's netns bind-mount.
pub fn runtime_path(name: &str) -> String {
    format!("{RUNTIME_DIR}/{name}")
}

// ---------------------------------------------------------------------------
// Network namespace syscall helpers
// ---------------------------------------------------------------------------

/// Create a new network namespace with loopback up and bind-mount it
/// to `/run/sdme/oci-pods/{name}`.
fn create_netns(name: &str, verbose: bool) -> Result<()> {
    // 1. Save current netns fd.
    let saved_fd = {
        let path = CString::new("/proc/self/ns/net").unwrap();
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to open /proc/self/ns/net");
        }
        fd
    };

    // 2. unshare(CLONE_NEWNET) — create new network namespace.
    let ret = unsafe { libc::unshare(libc::CLONE_NEWNET) };
    if ret != 0 {
        unsafe { libc::close(saved_fd) };
        return Err(std::io::Error::last_os_error()).context("unshare(CLONE_NEWNET) failed");
    }

    // 3. Bring up loopback in the new netns.
    let lo_result = bring_up_loopback();

    // Steps 4-6: bind-mount the new netns, then restore original netns.
    // We must restore even on failure.
    let mount_result = match lo_result {
        Ok(()) => bind_mount_netns(name, verbose),
        Err(e) => Err(e),
    };

    // 7. Restore original netns.
    let ret = unsafe { libc::setns(saved_fd, libc::CLONE_NEWNET) };
    unsafe { libc::close(saved_fd) };
    if ret != 0 {
        // This is critical — we can't leave the process in the wrong netns.
        let err = std::io::Error::last_os_error();
        eprintln!("FATAL: failed to restore network namespace: {err}");
        std::process::exit(1);
    }

    mount_result
}

/// Bring up the loopback interface in the current network namespace.
fn bring_up_loopback() -> Result<()> {
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to create socket for loopback");
    }

    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    let lo_name = b"lo\0";
    for (i, &b) in lo_name.iter().enumerate() {
        ifr.ifr_name[i] = b as _;
    }

    // Get current flags.
    let ret = unsafe { libc::ioctl(sock, libc::SIOCGIFFLAGS as libc::c_ulong, &mut ifr) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(sock) };
        return Err(err).context("ioctl SIOCGIFFLAGS failed on lo");
    }

    // Set IFF_UP.
    unsafe { ifr.ifr_ifru.ifru_flags |= libc::IFF_UP as i16 };

    let ret = unsafe { libc::ioctl(sock, libc::SIOCSIFFLAGS as libc::c_ulong, &ifr) };
    let err = std::io::Error::last_os_error();
    unsafe { libc::close(sock) };
    if ret != 0 {
        return Err(err).context("ioctl SIOCSIFFLAGS failed on lo");
    }

    Ok(())
}

/// Bind-mount `/proc/self/ns/net` to `/run/sdme/oci-pods/{name}`.
fn bind_mount_netns(name: &str, verbose: bool) -> Result<()> {
    let runtime_dir = Path::new(RUNTIME_DIR);
    fs::create_dir_all(runtime_dir)
        .with_context(|| format!("failed to create {}", runtime_dir.display()))?;

    let target = runtime_dir.join(name);

    // Create empty file as mount point.
    fs::write(&target, "").with_context(|| format!("failed to create {}", target.display()))?;

    let source = CString::new("/proc/self/ns/net").unwrap();
    let c_target =
        CString::new(target.as_os_str().as_encoded_bytes()).context("path contains null byte")?;

    let ret = unsafe {
        libc::mount(
            source.as_ptr(),
            c_target.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        let _ = fs::remove_file(&target);
        return Err(err).context("failed to bind-mount network namespace");
    }

    if verbose {
        eprintln!("bind-mounted netns: {}", target.display());
    }

    Ok(())
}

/// Unmount a netns bind-mount and remove the file.
fn unmount_netns(path: &Path, verbose: bool) -> Result<()> {
    let c_path =
        CString::new(path.as_os_str().as_encoded_bytes()).context("path contains null byte")?;

    let ret = unsafe { libc::umount2(c_path.as_ptr(), 0) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        // EINVAL means not mounted (already cleaned up); not a hard error.
        if err.raw_os_error() != Some(libc::EINVAL) {
            return Err(err).with_context(|| format!("failed to unmount {}", path.display()));
        }
    }

    let _ = fs::remove_file(path);

    if verbose {
        eprintln!("unmounted netns: {}", path.display());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDataDir;

    fn tmp() -> TempDataDir {
        TempDataDir::new("oci-pod")
    }

    #[test]
    fn test_create_rejects_invalid_name() {
        let tmp = tmp();
        let err = create(tmp.path(), "INVALID", false).unwrap_err();
        assert!(
            err.to_string().contains("lowercase"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_create_rejects_duplicate() {
        let tmp = tmp();
        // Manually create state file to simulate existing pod.
        let state_dir = tmp.path().join(STATE_SUBDIR);
        fs::create_dir_all(&state_dir).unwrap();
        fs::write(state_dir.join("mypod"), "CREATED=1234\n").unwrap();

        let err = create(tmp.path(), "mypod", false).unwrap_err();
        assert!(
            err.to_string().contains("already exists"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_list_empty() {
        let tmp = tmp();
        let pods = list(tmp.path()).unwrap();
        assert!(pods.is_empty());
    }

    #[test]
    fn test_list_with_entries() {
        let tmp = tmp();
        let state_dir = tmp.path().join(STATE_SUBDIR);
        fs::create_dir_all(&state_dir).unwrap();
        fs::write(state_dir.join("alpha"), "CREATED=1000\n").unwrap();
        fs::write(state_dir.join("beta"), "CREATED=2000\n").unwrap();

        let pods = list(tmp.path()).unwrap();
        assert_eq!(pods.len(), 2);
        assert_eq!(pods[0].name, "alpha");
        assert_eq!(pods[0].created, "1000");
        assert_eq!(pods[1].name, "beta");
        assert_eq!(pods[1].created, "2000");
        // Runtime files don't exist in tests.
        assert!(!pods[0].active);
        assert!(!pods[1].active);
    }

    #[test]
    fn test_remove_not_found() {
        let tmp = tmp();
        let err = remove(tmp.path(), "nonexistent", false, false).unwrap_err();
        assert!(
            err.to_string().contains("not found"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_remove_blocked_by_container() {
        let tmp = tmp();
        // Create pod state.
        let pod_dir = tmp.path().join(STATE_SUBDIR);
        fs::create_dir_all(&pod_dir).unwrap();
        fs::write(pod_dir.join("mypod"), "CREATED=1234\n").unwrap();

        // Create container state referencing the pod.
        let ct_dir = tmp.path().join("state");
        fs::create_dir_all(&ct_dir).unwrap();
        fs::write(
            ct_dir.join("mycontainer"),
            "NAME=mycontainer\nOCI_POD=mypod\n",
        )
        .unwrap();

        let err = remove(tmp.path(), "mypod", false, false).unwrap_err();
        assert!(
            err.to_string().contains("referenced by container"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_remove_force_ignores_references() {
        let tmp = tmp();
        // Create pod state.
        let pod_dir = tmp.path().join(STATE_SUBDIR);
        fs::create_dir_all(&pod_dir).unwrap();
        fs::write(pod_dir.join("mypod"), "CREATED=1234\n").unwrap();

        // Create container state referencing the pod.
        let ct_dir = tmp.path().join("state");
        fs::create_dir_all(&ct_dir).unwrap();
        fs::write(
            ct_dir.join("mycontainer"),
            "NAME=mycontainer\nOCI_POD=mypod\n",
        )
        .unwrap();

        // Force remove succeeds (no runtime file to unmount).
        remove(tmp.path(), "mypod", true, false).unwrap();
        assert!(!pod_dir.join("mypod").exists());
    }

    #[test]
    fn test_exists() {
        let tmp = tmp();
        assert!(!exists(tmp.path(), "mypod"));

        let state_dir = tmp.path().join(STATE_SUBDIR);
        fs::create_dir_all(&state_dir).unwrap();
        fs::write(state_dir.join("mypod"), "CREATED=1234\n").unwrap();

        assert!(exists(tmp.path(), "mypod"));
    }

    #[test]
    fn test_runtime_path() {
        assert_eq!(runtime_path("mypod"), "/run/sdme/oci-pods/mypod");
    }

    #[test]
    fn test_ensure_runtime_not_found() {
        let tmp = tmp();
        let err = ensure_runtime(tmp.path(), "nonexistent", false).unwrap_err();
        assert!(
            err.to_string().contains("not found"),
            "unexpected error: {err}"
        );
    }
}
