//! Detection and diagnostics for running inside a user-namespaced container.
//!
//! When sdme itself runs inside a container created with `--userns` ("nested"),
//! its data root lives on a filesystem whose superblock is owned by the initial
//! user namespace. Some operations lose privilege there: btrfs tree-search
//! ioctls, subvolume destroy on mounts without `user_subvol_rm_allowed`, and
//! mknod under an outer container's syscall filter. This module detects the
//! nested context and provides the preflight checks and warnings that keep
//! such failures early and explicit instead of surfacing as opaque boot
//! timeouts or corrupted state.

use std::fs;
use std::path::Path;
use std::sync::Once;

use anyhow::{bail, Context, Result};

use crate::userns;

/// Returns `true` when sdme runs inside a non-initial user namespace.
///
/// A nested context has a non-identity `/proc/self/uid_map`, meaning the
/// filesystem superblocks of its mounts may be owned by an ancestor user
/// namespace rather than by sdme itself.
pub fn is_nested() -> bool {
    !userns::is_initial_user_namespace()
}

/// Fail fast on nested-boot blockers that are outside sdme's control, and warn
/// on configurations known not to boot. No-op outside nested contexts.
///
/// `userns_enabled` is the container's `--userns` flag. In a nested context a
/// container created without it additionally needs the outer container's
/// `/run` superblock to be owned by this context (it is host-mounted in
/// practice), so we recommend `--userns`.
pub fn preflight_create(datadir: &Path, userns_enabled: bool, verbose: bool) -> Result<()> {
    if !is_nested() {
        return Ok(());
    }
    probe_mknod(datadir, verbose)?;
    if !userns_enabled {
        eprintln!(
            "warning: creating a container without --userns inside a user-namespaced \
             container usually fails to boot: nspawn remounts its /run/host/incoming \
             export read-only, which requires owning the outer /run superblock. \
             Use --userns for nested containers."
        );
    }
    Ok(())
}

/// Probe mknod on a scratch tmpfs under `datadir`.
///
/// A tmpfs mounted here is owned by the current user namespace, so mknod
/// fails only when the outer container's syscall filter blocks device-node
/// creation (observed with `--system-call-filter bpf`). Without the probe,
/// that condition surfaces as nspawn's `Failed to mknod(.../dev/null)` after
/// a full boot-timeout wait; failing fast names the actual cause. Probe setup
/// failures are inconclusive and never block the create.
fn probe_mknod(datadir: &Path, verbose: bool) -> Result<()> {
    let probe_dir = datadir.join(format!(".mknod-probe-{}", std::process::id()));
    fs::create_dir_all(&probe_dir)
        .with_context(|| format!("failed to create {}", probe_dir.display()))?;
    let result = probe_mknod_on_tmpfs(&probe_dir, verbose);
    let _ = crate::system_check::umount(&probe_dir);
    let _ = fs::remove_dir(&probe_dir);
    result
}

/// Mount a scratch tmpfs and try to create a device node on it.
fn probe_mknod_on_tmpfs(probe_dir: &Path, verbose: bool) -> Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_target = CString::new(probe_dir.as_os_str().as_bytes())
        .context("probe path contains interior NUL")?;
    let rc = unsafe {
        libc::mount(
            c"tmpfs".as_ptr(),
            c_target.as_ptr(),
            c"tmpfs".as_ptr(),
            0,
            c"mode=0700".as_ptr().cast(),
        )
    };
    if rc != 0 {
        // Cannot even stage the probe (e.g. the outer context forbids tmpfs
        // mounts); the boot itself may still work, so do not block.
        if verbose {
            eprintln!(
                "note: mknod probe skipped: tmpfs mount failed: {}",
                std::io::Error::last_os_error()
            );
        }
        return Ok(());
    }
    let node = probe_dir.join("null");
    let c_node = CString::new(node.as_os_str().as_bytes()).context("probe path contains NUL")?;
    // /dev/null, the first node nspawn creates in the container's /dev.
    let rc = unsafe { libc::mknod(c_node.as_ptr(), libc::S_IFCHR | 0o666, libc::makedev(1, 3)) };
    if rc == 0 {
        return Ok(());
    }
    let err = std::io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::EPERM) {
        bail!(
            "cannot create device nodes here: mknod is not permitted (EPERM). \
             The kernel requires CAP_MKNOD in the initial user namespace, which a \
             nested (user-namespaced) context does not have, and the outer \
             container's syscall filter may block it too. Nested containers \
             cannot set up /dev, so booting would fail after the full boot \
             timeout. If the outer container sets a SystemCallFilter, allow \
             mknod there (the @file-system group covers it); the kernel \
             restriction itself cannot be lifted from inside."
        );
    }
    // Any other failure is not the condition this probe looks for.
    if verbose {
        eprintln!("note: mknod probe returned {err}; continuing");
    }
    Ok(())
}

/// Warn once when a nested context's btrfs data root mount lacks
/// `user_subvol_rm_allowed`.
///
/// Without that mount option, destroying a subvolume requires CAP_SYS_ADMIN in
/// the initial user namespace, which a nested context does not have; deletion
/// then falls back to parking subvolumes in `.trash` (see `storage::btrfs`).
/// The option can only be added on the host, so the warning names the exact
/// mount option. No-op outside nested contexts and on non-btrfs data roots.
pub fn warn_subvol_rm_allowed(datadir: &Path) {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        if !is_nested() {
            return;
        }
        if let Some((source, fstype, opts)) = mount_options_for(datadir) {
            if fstype == "btrfs" && !opts.split(',').any(|o| o == "user_subvol_rm_allowed") {
                eprintln!(
                    "warning: btrfs mount {source} lacks the user_subvol_rm_allowed option;\n\
                     nested subvolume deletion will park subvolumes in .trash instead of \
                     destroying them.\n\
                     hint: add the option on the host, e.g. \
                     mount -o remount,user_subvol_rm_allowed <mountpoint>"
                );
            }
        }
    });
}

/// Mount info for the mount covering `path`: (source, fs type, super options).
fn mount_options_for(path: &Path) -> Option<(String, String, String)> {
    let content = fs::read_to_string("/proc/self/mountinfo").ok()?;
    parse_mountinfo_for(&content, path)
}

/// Find the mount covering `path` in mountinfo content: the entry whose mount
/// point is the longest boundary-aware prefix of `path`. Returns (source,
/// fstype, super options); super options (after the " - " separator) are where
/// btrfs reports options such as `user_subvol_rm_allowed`.
fn parse_mountinfo_for(content: &str, path: &Path) -> Option<(String, String, String)> {
    let path_str = path.to_str()?;
    let mut best: Option<(usize, String, String, String)> = None;
    for line in content.lines() {
        let Some((pre, post)) = line.split_once(" - ") else {
            continue;
        };
        let pre_fields: Vec<&str> = pre.split_whitespace().collect();
        if pre_fields.len() < 6 {
            continue;
        }
        let mount_point = unescape_mountinfo(pre_fields[4]);
        let mut post_fields = post.split_whitespace();
        let (Some(fstype), Some(source)) = (post_fields.next(), post_fields.next()) else {
            continue;
        };
        let super_opts = post_fields.next().unwrap_or("");
        let is_prefix = path_str == mount_point
            || (path_str.starts_with(&mount_point)
                && (mount_point.ends_with('/')
                    || path_str.as_bytes().get(mount_point.len()) == Some(&b'/')));
        if !is_prefix {
            continue;
        }
        if best
            .as_ref()
            .is_none_or(|(len, _, _, _)| mount_point.len() > *len)
        {
            best = Some((
                mount_point.len(),
                source.to_string(),
                fstype.to_string(),
                super_opts.to_string(),
            ));
        }
    }
    best.map(|(_, source, fstype, opts)| (source, fstype, opts))
}

/// Decode octal escapes in mountinfo path fields (`\040` space, `\011` tab,
/// `\012` newline, `\134` backslash). Non-escape sequences pass through.
fn unescape_mountinfo(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            let seq: String = chars.by_ref().take(3).collect();
            if seq.len() == 3 && seq.bytes().all(|b| b.is_ascii_digit()) {
                if let Ok(code) = u8::from_str_radix(&seq, 8) {
                    out.push(code as char);
                    continue;
                }
            }
            out.push(c);
            out.push_str(&seq);
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const MOUNTINFO: &str = "\
25 1 0:22 / / rw,relatime shared:1 - ext4 /dev/sda1 rw,errors=remount-ro
133 25 0:35 / /var/lib/sdme ro,noatime shared:43 - btrfs /dev/loop0 ro,discard=async,subvolid=5,subvol=/
140 25 0:40 / /var/lib/sdme\\040backup rw shared:50 - btrfs /dev/loop1 rw,user_subvol_rm_allowed,subvolid=5,subvol=/
";

    #[test]
    fn parse_mountinfo_longest_prefix_wins() {
        let (source, fstype, opts) =
            parse_mountinfo_for(MOUNTINFO, Path::new("/var/lib/sdme/pool/fs")).unwrap();
        assert_eq!(source, "/dev/loop0");
        assert_eq!(fstype, "btrfs");
        assert!(!opts.split(',').any(|o| o == "user_subvol_rm_allowed"));
    }

    #[test]
    fn parse_mountinfo_finds_option_when_present() {
        let (_, fstype, opts) =
            parse_mountinfo_for(MOUNTINFO, Path::new("/var/lib/sdme backup/x")).unwrap();
        assert_eq!(fstype, "btrfs");
        assert!(opts.split(',').any(|o| o == "user_subvol_rm_allowed"));
    }

    #[test]
    fn parse_mountinfo_boundary_aware() {
        // "/var/lib" must not match the "/var/lib/sdme" mount.
        let (_, fstype, _) = parse_mountinfo_for(MOUNTINFO, Path::new("/var/lib")).unwrap();
        assert_eq!(fstype, "ext4");
    }

    #[test]
    fn parse_mountinfo_missing_path() {
        assert!(parse_mountinfo_for(MOUNTINFO, Path::new("/nonexistent")).is_some());
        // Root mount covers everything with an absolute path; relative is None.
        assert!(parse_mountinfo_for(MOUNTINFO, Path::new("relative/path")).is_none());
    }

    #[test]
    fn unescape_decodes_octal() {
        assert_eq!(unescape_mountinfo("/a\\040b"), "/a b");
        assert_eq!(unescape_mountinfo("/a\\134b"), "/a\\b");
        assert_eq!(unescape_mountinfo("/plain"), "/plain");
        // Truncated or non-octal sequences pass through unchanged.
        assert_eq!(unescape_mountinfo("/a\\04"), "/a\\04");
    }
}
