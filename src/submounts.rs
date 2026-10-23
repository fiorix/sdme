//! Mountinfo parsing and per-submount overlayfs helpers.
//!
//! Provides utilities for parsing `/proc/self/mountinfo`, detecting host
//! submounts (btrfs subvolumes, separate partitions), and creating the
//! per-submount overlay directory structure.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Real filesystem types that warrant per-submount overlayfs layers.
const REAL_FS_TYPES: &[&str] = &[
    "ext4", "ext3", "ext2", "btrfs", "xfs", "zfs", "f2fs", "bcachefs", "reiserfs", "jfs", "ntfs",
    "ntfs3", "vfat", "exfat",
];

/// Path prefixes to skip: virtual filesystems and directories that
/// systemd-nspawn manages itself.
const SKIP_PREFIXES: &[&str] = &[
    "/proc", "/sys", "/dev", "/run", "/tmp", "/var/log", "/var/tmp",
];

/// Decode octal escape sequences (`\NNN`) in mountinfo fields.
///
/// The kernel escapes space (040), tab (011), newline (012), and backslash
/// (134) in mount-point strings. This function reverses those escapes so the
/// returned string matches the actual filesystem path.
pub(crate) fn unescape_mountinfo(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            let oct: String = chars.clone().take(3).collect();
            if oct.len() == 3 && oct.chars().all(|c| c.is_ascii_digit()) {
                if let Ok(byte) = u8::from_str_radix(&oct, 8) {
                    out.push(byte as char);
                    for _ in 0..3 {
                        chars.next();
                    }
                    continue;
                }
            }
            out.push(c);
        } else {
            out.push(c);
        }
    }
    out
}

/// Read `/proc/self/mountinfo` and return mount points under `dir`,
/// sorted deepest-first for safe unmounting.
pub(crate) fn find_mounts_under(dir: &Path) -> Result<Vec<PathBuf>> {
    let mountinfo = fs::read_to_string("/proc/self/mountinfo")
        .context("failed to read /proc/self/mountinfo")?;

    let dir_str = format!("{}/", dir.display());

    let mut mounts: Vec<PathBuf> = mountinfo
        .lines()
        .filter_map(|line| {
            // mountinfo format: id parent major:minor root mount_point options ...
            let mut fields = line.split_whitespace();
            let mount_point = unescape_mountinfo(fields.nth(4)?);
            // Match mounts strictly under dir (not dir itself).
            if mount_point.starts_with(&dir_str) {
                Some(PathBuf::from(mount_point))
            } else {
                None
            }
        })
        .collect();

    // Sort by path length descending (deepest first) for unmounting.
    mounts.sort_by_key(|b| std::cmp::Reverse(b.as_os_str().len()));
    Ok(mounts)
}

/// Discover host submounts that need per-submount overlayfs layers.
///
/// Reads `/proc/self/mountinfo` and returns relative paths (e.g. `"home"`)
/// for real-filesystem mounts under `/`, excluding virtual filesystems and
/// nspawn-managed directories. Results are sorted shallowest-first.
pub(crate) fn host_submounts() -> Result<Vec<String>> {
    let content = fs::read_to_string("/proc/self/mountinfo")
        .context("failed to read /proc/self/mountinfo")?;
    Ok(parse_submounts(&content))
}

/// Pure parser for testability. Filters mountinfo lines by fs type allowlist
/// and path exclusions, returning relative paths sorted shallowest-first.
fn parse_submounts(content: &str) -> Vec<String> {
    let mut submounts: Vec<String> = content
        .lines()
        .filter_map(|line| {
            // mountinfo format:
            //   id parent major:minor root mount_point options shared:N - fstype source super_options
            let fields: Vec<&str> = line.split_whitespace().collect();

            // Find the separator "-" to locate fstype.
            let sep_idx = fields.iter().position(|&f| f == "-")?;
            let fstype = *fields.get(sep_idx + 1)?;

            if !REAL_FS_TYPES.contains(&fstype) {
                return None;
            }

            let mount_point = unescape_mountinfo(fields.get(4)?);

            // Skip the root mount itself.
            if mount_point == "/" {
                return None;
            }

            // Must be an absolute path under /.
            if !mount_point.starts_with('/') {
                return None;
            }

            // Reject paths that could cause issues in mount options or path traversal.
            if mount_point.contains("..") || mount_point.contains(',') {
                return None;
            }

            // Skip virtual/nspawn-managed directories.
            if SKIP_PREFIXES
                .iter()
                .any(|p| mount_point == *p || mount_point.starts_with(&format!("{p}/")))
            {
                return None;
            }

            // Return relative path (strip leading /).
            Some(mount_point[1..].to_string())
        })
        .collect();

    // Sort shallowest-first (by component count, then alphabetically).
    submounts.sort_by(|a, b| {
        let depth_a = a.matches('/').count();
        let depth_b = b.matches('/').count();
        depth_a.cmp(&depth_b).then(a.cmp(b))
    });

    // Deduplicate (btrfs can have multiple mounts at the same point).
    submounts.dedup();

    submounts
}

/// Create per-submount upper/work directories under a container directory.
///
/// For each submount path (e.g. `"home"`), creates:
///   `container_dir/submounts/home/upper` (0o755)
///   `container_dir/submounts/home/work`  (0o700)
/// Return the mount point that holds `path`: the deepest mount point in
/// `mountinfo` (the contents of `/proc/self/mountinfo`) that is `path` or one
/// of its ancestors. Purely lexical, so it never touches the filesystem
/// (which would trigger an automount).
pub(crate) fn containing_mount_point(path: &Path, mountinfo: &str) -> PathBuf {
    mountinfo
        .lines()
        .filter_map(|line| line.split_whitespace().nth(4))
        .map(|mount_point| PathBuf::from(unescape_mountinfo(mount_point)))
        .filter(|mount_point| path.starts_with(mount_point))
        .max_by_key(|mount_point| mount_point.components().count())
        .unwrap_or_else(|| PathBuf::from("/"))
}

pub(crate) fn ensure_submount_dirs(container_dir: &Path, submounts: &[String]) -> Result<()> {
    for rel in submounts {
        let base = container_dir.join("submounts").join(rel);
        let upper = base.join("upper");
        let work = base.join("work");
        fs::create_dir_all(&upper)
            .with_context(|| format!("failed to create {}", upper.display()))?;
        fs::set_permissions(&upper, fs::Permissions::from_mode(0o755))
            .with_context(|| format!("failed to set permissions on {}", upper.display()))?;
        fs::create_dir_all(&work)
            .with_context(|| format!("failed to create {}", work.display()))?;
        fs::set_permissions(&work, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("failed to set permissions on {}", work.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_containing_mount_point() {
        let mountinfo = "\
22 1 0:21 / / rw - btrfs /dev/md0 rw
30 22 0:31 / /home rw - autofs systemd-1 rw
31 30 0:44 / /home/fiorix rw - nfs4 filer:/fiorix rw
32 22 0:45 / /data\\040disk rw - ext4 /dev/sdb1 rw
";
        let at = |p: &str| containing_mount_point(Path::new(p), mountinfo);
        assert_eq!(at("/root/.config/systemd/user"), PathBuf::from("/"));
        assert_eq!(at("/home/alice/.config"), PathBuf::from("/home"));
        assert_eq!(at("/home/fiorix/.config"), PathBuf::from("/home/fiorix"));
        assert_eq!(at("/home/fiorixx"), PathBuf::from("/home"));
        assert_eq!(at("/data disk/u"), PathBuf::from("/data disk"));
        assert_eq!(at("/data"), PathBuf::from("/"));
    }

    #[test]
    fn test_unescape_plain() {
        assert_eq!(unescape_mountinfo("/home/user"), "/home/user");
    }

    #[test]
    fn test_unescape_space() {
        // Space is octal 040.
        assert_eq!(unescape_mountinfo("/mnt/my\\040drive"), "/mnt/my drive");
    }

    #[test]
    fn test_unescape_backslash() {
        // Backslash is octal 134.
        assert_eq!(
            unescape_mountinfo("/mnt/back\\134slash"),
            "/mnt/back\\slash"
        );
    }

    #[test]
    fn test_unescape_tab() {
        // Tab is octal 011.
        assert_eq!(unescape_mountinfo("/mnt/has\\011tab"), "/mnt/has\ttab");
    }

    #[test]
    fn test_parse_submounts_btrfs() {
        let content = "\
36 1 259:2 / / rw,relatime shared:1 - btrfs /dev/nvme0n1p2 rw,ssd
37 36 259:2 /@home /home rw,relatime shared:2 - btrfs /dev/nvme0n1p2 rw,ssd
38 36 259:2 /@var /var rw,relatime shared:3 - btrfs /dev/nvme0n1p2 rw,ssd
39 36 0:21 / /proc rw,nosuid,nodev,noexec,relatime shared:4 - proc proc rw
40 36 0:22 / /sys rw,nosuid,nodev,noexec,relatime shared:5 - sysfs sysfs rw
41 36 0:5 / /dev rw,nosuid,relatime shared:6 - devtmpfs devtmpfs rw
42 36 0:30 / /run rw,nosuid,nodev shared:7 - tmpfs tmpfs rw
43 36 0:31 / /tmp rw,nosuid,nodev shared:8 - tmpfs tmpfs rw";

        let result = parse_submounts(content);
        assert_eq!(result, vec!["home", "var"]);
    }

    #[test]
    fn test_parse_submounts_filters_pseudo_fs() {
        let content = "\
36 1 259:2 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
39 36 0:21 / /proc rw shared:4 - proc proc rw
40 36 0:22 / /sys rw shared:5 - sysfs sysfs rw
41 36 0:5 / /dev rw shared:6 - devtmpfs devtmpfs rw
42 36 0:30 / /run rw shared:7 - tmpfs tmpfs rw
43 36 0:31 / /tmp rw shared:8 - tmpfs tmpfs rw";

        let result = parse_submounts(content);
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_submounts_sorted_by_depth() {
        let content = "\
36 1 259:2 / / rw shared:1 - btrfs /dev/sda rw
37 36 259:2 /@data /data/deep/nested rw shared:2 - btrfs /dev/sda rw
38 36 259:2 /@home /home rw shared:3 - btrfs /dev/sda rw
39 36 259:2 /@data /data rw shared:4 - btrfs /dev/sda rw";

        let result = parse_submounts(content);
        assert_eq!(result, vec!["data", "home", "data/deep/nested"]);
    }

    #[test]
    fn test_parse_submounts_empty() {
        let result = parse_submounts("");
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_submounts_skips_nspawn_managed() {
        let content = "\
36 1 259:2 / / rw shared:1 - ext4 /dev/sda1 rw
37 36 259:2 / /home rw shared:2 - ext4 /dev/sda2 rw
38 36 259:2 / /var/log rw shared:3 - ext4 /dev/sda3 rw
39 36 259:2 / /var/tmp rw shared:4 - ext4 /dev/sda4 rw
40 36 259:2 / /var/cache rw shared:5 - ext4 /dev/sda5 rw";

        let result = parse_submounts(content);
        // /var/log and /var/tmp are nspawn-managed, should be skipped
        assert_eq!(result, vec!["home", "var/cache"]);
    }

    #[test]
    fn test_parse_submounts_deep_nesting() {
        let content = "\
36 1 259:2 / / rw shared:1 - btrfs /dev/sda rw
37 36 259:2 /a /a/b/c/d/e rw shared:2 - btrfs /dev/sda rw
38 36 259:2 /b /a rw shared:3 - btrfs /dev/sda rw
39 36 259:2 /c /a/b rw shared:4 - btrfs /dev/sda rw";

        let result = parse_submounts(content);
        assert_eq!(result, vec!["a", "a/b", "a/b/c/d/e"]);
    }

    #[test]
    fn test_parse_submounts_rejects_traversal() {
        let content = "\
36 1 259:2 / / rw shared:1 - btrfs /dev/sda rw
37 36 259:2 /x /home/../etc rw shared:2 - btrfs /dev/sda rw
38 36 259:2 /y /mnt/a,b rw shared:3 - btrfs /dev/sda rw
39 36 259:2 /z /data rw shared:4 - btrfs /dev/sda rw";

        let result = parse_submounts(content);
        assert_eq!(result, vec!["data"]);
    }
}
