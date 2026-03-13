//! OCI rootfs helpers: app name detection, port/volume reading from OCI metadata files.

use std::fs;
use std::path::{Component, Path};

/// Detect the OCI app name from a rootfs by scanning `/oci/apps/`.
///
/// Returns `None` if no `/oci/apps/` directory exists or it's empty.
/// For single-app rootfs, returns the one app name. For kube rootfs
/// with multiple apps, returns the first entry found.
pub fn detect_oci_app_name(rootfs: &Path) -> Option<String> {
    let apps_dir = rootfs.join("oci/apps");
    let entries = fs::read_dir(&apps_dir).ok()?;
    for entry in entries {
        let entry = entry.ok()?;
        if entry.file_type().ok()?.is_dir() {
            return Some(entry.file_name().to_string_lossy().to_string());
        }
    }
    None
}

/// Detect all OCI app names from a rootfs by listing `/oci/apps/` subdirectories.
pub fn detect_all_oci_app_names(rootfs: &Path) -> Vec<String> {
    let apps_dir = rootfs.join("oci/apps");
    let Ok(entries) = fs::read_dir(&apps_dir) else {
        return Vec::new();
    };
    entries
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().ok().is_some_and(|ft| ft.is_dir()))
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect()
}

/// Read OCI ports from a rootfs and return port forwarding rules.
///
/// Scans `/oci/apps/{name}/ports` for the OCI app. Each line in the
/// file is `PORT/PROTO` (e.g. `80/tcp`). Returns `"PROTO:PORT:PORT"`
/// entries suitable for systemd-nspawn `--port=`.
/// Returns an empty vec if no OCI app or ports file exists.
pub fn read_oci_ports(rootfs: &Path) -> Vec<String> {
    let app_name = match detect_oci_app_name(rootfs) {
        Some(name) => name,
        None => return Vec::new(),
    };
    let ports_path = rootfs.join(format!("oci/apps/{app_name}/ports"));
    let content = match fs::read_to_string(&ports_path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let mut result = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Expect "PORT/PROTO" format
        let (port_str, proto) = match line.split_once('/') {
            Some((p, proto)) => (p, proto),
            None => {
                eprintln!("warning: invalid OCI port entry (no protocol): {line}");
                continue;
            }
        };
        let port: u16 = match port_str.parse() {
            Ok(p) if p > 0 => p,
            _ => {
                eprintln!("warning: invalid OCI port number: {line}");
                continue;
            }
        };
        // Map same port on host and container: proto:host:container
        result.push(format!("{proto}:{port}:{port}"));
    }
    result
}

/// Read OCI volumes from a rootfs and return volume paths.
///
/// Scans `/oci/apps/{name}/volumes` for the OCI app. Each line in the
/// file is an absolute path (e.g. `/var/lib/mysql`).
/// Returns an empty vec if no OCI app or volumes file exists.
pub fn read_oci_volumes(rootfs: &Path) -> Vec<String> {
    let app_name = match detect_oci_app_name(rootfs) {
        Some(name) => name,
        None => return Vec::new(),
    };
    let volumes_path = rootfs.join(format!("oci/apps/{app_name}/volumes"));
    let content = match fs::read_to_string(&volumes_path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let mut result = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let path = Path::new(line);
        if !path.is_absolute() {
            eprintln!("warning: invalid OCI volume path (not absolute): {line}");
            continue;
        }
        if path.components().any(|c| c == Component::ParentDir) {
            eprintln!("warning: invalid OCI volume path (contains ..): {line}");
            continue;
        }
        result.push(line.to_string());
    }
    result
}

/// Convert an OCI volume path to a directory-safe name.
///
/// Strips the leading `/` and replaces remaining `/` with `-`.
/// E.g. `/var/lib/mysql` → `var-lib-mysql`.
pub(crate) fn sanitize_volume_name(path: &str) -> String {
    let stripped = path.strip_prefix('/').unwrap_or(path);
    stripped.replace('/', "-")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn tmp() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sdme-test-oci-rootfs-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    // --- read_oci_ports tests ---

    #[test]
    fn test_read_oci_ports_missing_file() {
        let tmp = tmp();
        let rootfs = tmp.join("fs/nonexistent");
        assert!(read_oci_ports(&rootfs).is_empty());
    }

    #[test]
    fn test_read_oci_ports_empty_file() {
        let tmp = tmp();
        let rootfs = tmp.join("fs/myroot");
        fs::create_dir_all(rootfs.join("oci/apps/app")).unwrap();
        fs::write(rootfs.join("oci/apps/app/ports"), "").unwrap();
        assert!(read_oci_ports(&rootfs).is_empty());
    }

    #[test]
    fn test_read_oci_ports_valid() {
        let tmp = tmp();
        let rootfs = tmp.join("fs/myroot");
        fs::create_dir_all(rootfs.join("oci/apps/app")).unwrap();
        fs::write(rootfs.join("oci/apps/app/ports"), "80/tcp\n3306/tcp\n").unwrap();
        let ports = read_oci_ports(&rootfs);
        assert_eq!(ports, vec!["tcp:80:80", "tcp:3306:3306"]);
    }

    #[test]
    fn test_read_oci_ports_skips_invalid() {
        let tmp = tmp();
        let rootfs = tmp.join("fs/myroot");
        fs::create_dir_all(rootfs.join("oci/apps/app")).unwrap();
        fs::write(
            rootfs.join("oci/apps/app/ports"),
            "80/tcp\nbadline\n0/tcp\n443/tcp\n",
        )
        .unwrap();
        let ports = read_oci_ports(&rootfs);
        assert_eq!(ports, vec!["tcp:80:80", "tcp:443:443"]);
    }

    #[test]
    fn test_read_oci_ports_udp() {
        let tmp = tmp();
        let rootfs = tmp.join("fs/myroot");
        fs::create_dir_all(rootfs.join("oci/apps/app")).unwrap();
        fs::write(rootfs.join("oci/apps/app/ports"), "53/udp\n").unwrap();
        let ports = read_oci_ports(&rootfs);
        assert_eq!(ports, vec!["udp:53:53"]);
    }

    // --- read_oci_volumes tests ---

    #[test]
    fn test_read_oci_volumes_missing_file() {
        let tmp = tmp();
        let rootfs = tmp.join("fs/nonexistent");
        assert!(read_oci_volumes(&rootfs).is_empty());
    }

    #[test]
    fn test_read_oci_volumes_empty_file() {
        let tmp = tmp();
        let rootfs = tmp.join("fs/myroot");
        fs::create_dir_all(rootfs.join("oci/apps/app")).unwrap();
        fs::write(rootfs.join("oci/apps/app/volumes"), "").unwrap();
        assert!(read_oci_volumes(&rootfs).is_empty());
    }

    #[test]
    fn test_read_oci_volumes_valid() {
        let tmp = tmp();
        let rootfs = tmp.join("fs/myroot");
        fs::create_dir_all(rootfs.join("oci/apps/app")).unwrap();
        fs::write(
            rootfs.join("oci/apps/app/volumes"),
            "/var/lib/mysql\n/data\n",
        )
        .unwrap();
        let vols = read_oci_volumes(&rootfs);
        assert_eq!(vols, vec!["/var/lib/mysql", "/data"]);
    }

    #[test]
    fn test_read_oci_volumes_skips_invalid() {
        let tmp = tmp();
        let rootfs = tmp.join("fs/myroot");
        fs::create_dir_all(rootfs.join("oci/apps/app")).unwrap();
        fs::write(
            rootfs.join("oci/apps/app/volumes"),
            "/var/lib/mysql\nrelative/path\n/ok/../bad\n/good\n",
        )
        .unwrap();
        let vols = read_oci_volumes(&rootfs);
        assert_eq!(vols, vec!["/var/lib/mysql", "/good"]);
    }

    // --- sanitize_volume_name tests ---

    #[test]
    fn test_sanitize_volume_name() {
        assert_eq!(sanitize_volume_name("/var/lib/mysql"), "var-lib-mysql");
        assert_eq!(sanitize_volume_name("/data"), "data");
        assert_eq!(sanitize_volume_name("/a/b/c"), "a-b-c");
    }
}
