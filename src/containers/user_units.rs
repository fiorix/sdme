//! Hide the host users' systemd user units from host-rootfs containers.
//!
//! The lower layer of a host-rootfs container is the live host `/`, so the
//! units the host's users run under `systemd --user` would also start in the
//! container as soon as a user session begins there (for example `sdme join`
//! as `$SUDO_USER`), with the host's network, ports and paths. The
//! system-wide user configuration, `/etc/systemd/user`, is hidden by the
//! default `host_rootfs_opaque_dirs`. Each user's own configuration lives in
//! their home directory and cannot be named in that setting, so this module
//! makes it opaque at create time.

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Per-user unit configuration directories, relative to the home directory:
/// unit files and `systemctl --user enable` symlinks, and the persistent
/// drop-ins of `systemctl --user set-property`. Units installed under
/// `~/.local/share/systemd/user` stay visible, like the vendor units under
/// `/usr/lib/systemd`, but nothing enables them.
const USER_UNIT_CONFIG_DIRS: &[&str] = &[".config/systemd/user", ".config/systemd/user.control"];

/// Make each host user's systemd user unit configuration directories opaque
/// in the container's upper layers, so the container starts without them.
///
/// Homes are those in `/etc/passwd` plus `$SUDO_USER`'s, which may come
/// from NSS instead. A directory on a mount the container does not overlay
/// (autofs, NFS) is not visible inside the container and is skipped; homes
/// are checked against the mount table before the filesystem is touched, so
/// an automounted home is not mounted by the check.
pub(super) fn hide_host_user_units(container_dir: &Path, verbose: bool) -> Result<()> {
    let mountinfo = fs::read_to_string("/proc/self/mountinfo")
        .context("failed to read /proc/self/mountinfo")?;
    let submounts = crate::submounts::host_submounts()?;

    let mut homes = passwd_homes(&fs::read_to_string("/etc/passwd").unwrap_or_default());
    if let Some(user) = crate::sudo_user() {
        homes.push(user.home);
    }
    homes.sort();
    homes.dedup();

    let mut hidden: Vec<PathBuf> = Vec::new();
    for home in &homes {
        let home_mount = crate::submounts::containing_mount_point(home, &mountinfo);
        if overlay_upper(container_dir, &home_mount, &submounts).is_none() {
            continue;
        }
        for rel in USER_UNIT_CONFIG_DIRS {
            // A symlinked home or ~/.config leads elsewhere; hide the
            // directory where it really is.
            let Ok(real) = fs::canonicalize(home.join(rel)) else {
                continue;
            };
            if !real.is_dir() || hidden.contains(&real) {
                continue;
            }
            let mount = crate::submounts::containing_mount_point(&real, &mountinfo);
            let Some(upper) = overlay_upper(container_dir, &mount, &submounts) else {
                continue;
            };
            if let Ok(rel_mount) = mount.strip_prefix("/") {
                if !rel_mount.as_os_str().is_empty() {
                    let rel_mount = rel_mount.to_string_lossy().into_owned();
                    crate::submounts::ensure_submount_dirs(container_dir, &[rel_mount])?;
                }
            }
            let inner = real
                .strip_prefix(&mount)
                .expect("the containing mount point is an ancestor");
            create_opaque_dir(&upper, &mount, inner)
                .with_context(|| format!("failed to hide {}", real.display()))?;
            if verbose {
                eprintln!("hid host user units: {}", real.display());
            }
            hidden.push(real);
        }
    }
    Ok(())
}

/// The upper layer holding paths under `mount` in a host-rootfs container:
/// the root overlay's for `/`, a submount overlay's for a detected submount,
/// and `None` for any other mount, which the container does not see.
fn overlay_upper(container_dir: &Path, mount: &Path, submounts: &[String]) -> Option<PathBuf> {
    if mount == Path::new("/") {
        return Some(container_dir.join("upper"));
    }
    let rel = mount.strip_prefix("/").ok()?.to_str()?;
    submounts
        .iter()
        .any(|s| s == rel)
        .then(|| container_dir.join("submounts").join(rel).join("upper"))
}

/// Home directories in an `/etc/passwd`-format file, skipping `/` and
/// anything that is not an absolute path.
fn passwd_homes(content: &str) -> Vec<PathBuf> {
    content
        .lines()
        .filter_map(|line| line.split(':').nth(5))
        .filter(|home| home.starts_with('/') && *home != "/")
        .map(PathBuf::from)
        .collect()
}

/// Create `inner` under `upper` and mark it opaque.
///
/// For a directory present in both layers, overlayfs shows the upper copy's
/// owner and mode, so each component the upper layer lacks is created with
/// the owner and mode of the same path under `lower`. A home therefore
/// keeps its owner and permissions in the container.
fn create_opaque_dir(upper: &Path, lower: &Path, inner: &Path) -> Result<()> {
    let mut upper_path = upper.to_path_buf();
    let mut lower_path = lower.to_path_buf();
    for component in inner.components() {
        upper_path.push(component);
        lower_path.push(component);
        if fs::symlink_metadata(&upper_path).is_ok() {
            continue;
        }
        let meta = fs::metadata(&lower_path)
            .with_context(|| format!("failed to stat {}", lower_path.display()))?;
        fs::create_dir(&upper_path)
            .with_context(|| format!("failed to create {}", upper_path.display()))?;
        std::os::unix::fs::chown(&upper_path, Some(meta.uid()), Some(meta.gid()))
            .with_context(|| format!("failed to chown {}", upper_path.display()))?;
        fs::set_permissions(
            &upper_path,
            fs::Permissions::from_mode(meta.mode() & 0o7777),
        )
        .with_context(|| format!("failed to set permissions on {}", upper_path.display()))?;
    }
    super::create::set_opaque_xattr(&upper_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDataDir;

    #[test]
    fn passwd_homes_skips_root_and_relative() {
        let passwd = "\
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/:/sbin/nologin
alice:x:1000:1000::/home/alice:/bin/bash
broken:x:1001:1001::relative:/bin/sh
short:x:1002
";
        assert_eq!(
            passwd_homes(passwd),
            vec![PathBuf::from("/root"), PathBuf::from("/home/alice")]
        );
    }

    #[test]
    fn overlay_upper_maps_root_and_submounts_only() {
        let dir = Path::new("/var/lib/sdme/containers/box");
        let subs = vec!["home".to_string(), "data/deep".to_string()];
        assert_eq!(
            overlay_upper(dir, Path::new("/"), &subs),
            Some(dir.join("upper"))
        );
        assert_eq!(
            overlay_upper(dir, Path::new("/home"), &subs),
            Some(dir.join("submounts/home/upper"))
        );
        assert_eq!(
            overlay_upper(dir, Path::new("/data/deep"), &subs),
            Some(dir.join("submounts/data/deep/upper"))
        );
        // An autofs or NFS mount is not overlaid: the container does not see it.
        assert_eq!(overlay_upper(dir, Path::new("/home/nfs"), &subs), None);
    }

    #[test]
    fn create_opaque_dir_copies_owner_and_mode() {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skipping create_opaque_dir_copies_owner_and_mode: requires root");
            return;
        }
        let tmp = TempDataDir::new("user-units");
        let lower = tmp.path().join("lower");
        let upper = tmp.path().join("upper");
        let home = lower.join("home/alice");
        fs::create_dir_all(home.join(".config/systemd/user")).unwrap();
        fs::create_dir_all(&upper).unwrap();
        fs::set_permissions(&home, fs::Permissions::from_mode(0o710)).unwrap();
        for path in [
            home.clone(),
            home.join(".config"),
            home.join(".config/systemd"),
            home.join(".config/systemd/user"),
        ] {
            std::os::unix::fs::chown(&path, Some(1234), Some(5678)).unwrap();
        }
        // An existing upper directory is left as it is.
        fs::create_dir_all(upper.join("home")).unwrap();

        create_opaque_dir(&upper, &lower, Path::new("home/alice/.config/systemd/user")).unwrap();

        let up_home = fs::metadata(upper.join("home/alice")).unwrap();
        assert_eq!((up_home.uid(), up_home.gid()), (1234, 5678));
        assert_eq!(up_home.mode() & 0o7777, 0o710);
        let user_dir = upper.join("home/alice/.config/systemd/user");
        assert_eq!(fs::metadata(&user_dir).unwrap().uid(), 1234);
        let mut value = [0u8; 1];
        let c_path = std::ffi::CString::new(user_dir.as_os_str().as_encoded_bytes()).unwrap();
        let n = unsafe {
            libc::getxattr(
                c_path.as_ptr(),
                c"trusted.overlay.opaque".as_ptr(),
                value.as_mut_ptr().cast(),
                value.len(),
            )
        };
        assert_eq!((n, value[0]), (1, b'y'));
    }
}
