//! OCI rootfs helpers: app name detection, port/volume reading from OCI metadata files.

use std::fs;
use std::path::{Component, Path};

/// Information about a single OCI app, as read from `/oci/apps/{name}/`.
#[derive(serde::Serialize)]
pub struct OciAppInfo {
    /// App name (directory name under `/oci/apps/`).
    pub name: String,
    /// Environment variables from the env file (`KEY=VALUE` per line).
    pub env: Vec<String>,
    /// Exposed ports from the ports file (`PORT/PROTO` per line).
    pub ports: Vec<String>,
    /// Volume paths from the volumes file (absolute paths).
    pub volumes: Vec<String>,
}

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

/// Parse a `PORT/PROTO` line, returning `(port, proto)` if valid.
///
/// Rejects lines without a `/` separator and port numbers that are
/// zero or non-numeric.
fn parse_port_line(line: &str) -> Option<(u16, &str)> {
    let (port_str, proto) = line.split_once('/')?;
    let port: u16 = port_str.parse().ok().filter(|&p| p > 0)?;
    Some((port, proto))
}

/// Check whether a volume path line is a valid absolute path without `..`.
fn is_valid_volume_path(line: &str) -> bool {
    let path = Path::new(line);
    path.is_absolute() && !path.components().any(|c| c == Component::ParentDir)
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
        match parse_port_line(line) {
            Some((port, proto)) => result.push(format!("{proto}:{port}:{port}")),
            None => eprintln!("warning: invalid OCI port entry: {line}"),
        }
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
        if is_valid_volume_path(line) {
            result.push(line.to_string());
        } else {
            eprintln!("warning: invalid OCI volume path: {line}");
        }
    }
    result
}

/// Read environment variables for a specific OCI app.
///
/// Returns each non-empty line from `/oci/apps/{app_name}/env` as a
/// `KEY=VALUE` string. Returns an empty vec if the file does not exist.
pub fn read_oci_app_env(rootfs: &Path, app_name: &str) -> Vec<String> {
    let env_path = rootfs.join(format!("oci/apps/{app_name}/env"));
    let content = match fs::read_to_string(&env_path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect()
}

/// Read exposed ports for a specific OCI app in raw `PORT/PROTO` format.
///
/// Returns each valid line from `/oci/apps/{app_name}/ports`.
/// Uses the same validation as [`read_oci_ports`] but returns the
/// original format instead of nspawn's `PROTO:PORT:PORT`.
pub fn read_oci_app_ports_raw(rootfs: &Path, app_name: &str) -> Vec<String> {
    let ports_path = rootfs.join(format!("oci/apps/{app_name}/ports"));
    let content = match fs::read_to_string(&ports_path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && parse_port_line(l).is_some())
        .map(String::from)
        .collect()
}

/// Read volume paths for a specific OCI app.
///
/// Returns each valid absolute path from `/oci/apps/{app_name}/volumes`.
/// Uses the same validation as [`read_oci_volumes`].
pub fn read_oci_app_volumes(rootfs: &Path, app_name: &str) -> Vec<String> {
    let volumes_path = rootfs.join(format!("oci/apps/{app_name}/volumes"));
    let content = match fs::read_to_string(&volumes_path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && is_valid_volume_path(l))
        .map(String::from)
        .collect()
}

/// Read all OCI apps from a rootfs, returning their metadata.
///
/// Scans `/oci/apps/` for app directories, then reads env, ports, and
/// volumes for each. Returns entries sorted by name.
pub fn read_all_oci_apps(rootfs: &Path) -> Vec<OciAppInfo> {
    let mut names = detect_all_oci_app_names(rootfs);
    names.sort();
    names
        .into_iter()
        .map(|name| {
            let env = read_oci_app_env(rootfs, &name);
            let ports = read_oci_app_ports_raw(rootfs, &name);
            let volumes = read_oci_app_volumes(rootfs, &name);
            OciAppInfo {
                name,
                env,
                ports,
                volumes,
            }
        })
        .collect()
}

/// Convert an OCI volume path to a directory-safe name.
///
/// Strips the leading `/` and replaces remaining `/` with `-`.
/// E.g. `/var/lib/mysql` becomes `var-lib-mysql`.
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

    // --- read_oci_app_env tests ---

    #[test]
    fn test_read_oci_app_env_missing() {
        let tmp = tmp();
        assert!(read_oci_app_env(&tmp, "noapp").is_empty());
    }

    #[test]
    fn test_read_oci_app_env_valid() {
        let tmp = tmp();
        let rootfs = tmp.join("fs/myroot");
        fs::create_dir_all(rootfs.join("oci/apps/app")).unwrap();
        fs::write(rootfs.join("oci/apps/app/env"), "PORT=8080\nDEBUG=false\n").unwrap();
        let env = read_oci_app_env(&rootfs, "app");
        assert_eq!(env, vec!["PORT=8080", "DEBUG=false"]);
    }

    #[test]
    fn test_read_oci_app_env_skips_empty_lines() {
        let tmp = tmp();
        let rootfs = tmp.join("fs/myroot");
        fs::create_dir_all(rootfs.join("oci/apps/app")).unwrap();
        fs::write(rootfs.join("oci/apps/app/env"), "A=1\n\n  \nB=2\n").unwrap();
        let env = read_oci_app_env(&rootfs, "app");
        assert_eq!(env, vec!["A=1", "B=2"]);
    }

    // --- read_oci_app_ports_raw tests ---

    #[test]
    fn test_read_oci_app_ports_raw_missing() {
        let tmp = tmp();
        assert!(read_oci_app_ports_raw(&tmp, "noapp").is_empty());
    }

    #[test]
    fn test_read_oci_app_ports_raw_valid() {
        let tmp = tmp();
        let rootfs = tmp.join("fs/myroot");
        fs::create_dir_all(rootfs.join("oci/apps/app")).unwrap();
        fs::write(
            rootfs.join("oci/apps/app/ports"),
            "80/tcp\n443/tcp\n53/udp\n",
        )
        .unwrap();
        let ports = read_oci_app_ports_raw(&rootfs, "app");
        assert_eq!(ports, vec!["80/tcp", "443/tcp", "53/udp"]);
    }

    #[test]
    fn test_read_oci_app_ports_raw_skips_invalid() {
        let tmp = tmp();
        let rootfs = tmp.join("fs/myroot");
        fs::create_dir_all(rootfs.join("oci/apps/app")).unwrap();
        fs::write(
            rootfs.join("oci/apps/app/ports"),
            "80/tcp\nbadline\n0/tcp\n443/tcp\n",
        )
        .unwrap();
        let ports = read_oci_app_ports_raw(&rootfs, "app");
        assert_eq!(ports, vec!["80/tcp", "443/tcp"]);
    }

    // --- read_oci_app_volumes tests ---

    #[test]
    fn test_read_oci_app_volumes_missing() {
        let tmp = tmp();
        assert!(read_oci_app_volumes(&tmp, "noapp").is_empty());
    }

    #[test]
    fn test_read_oci_app_volumes_valid() {
        let tmp = tmp();
        let rootfs = tmp.join("fs/myroot");
        fs::create_dir_all(rootfs.join("oci/apps/app")).unwrap();
        fs::write(
            rootfs.join("oci/apps/app/volumes"),
            "/var/lib/mysql\n/data\n",
        )
        .unwrap();
        let vols = read_oci_app_volumes(&rootfs, "app");
        assert_eq!(vols, vec!["/var/lib/mysql", "/data"]);
    }

    #[test]
    fn test_read_oci_app_volumes_skips_invalid() {
        let tmp = tmp();
        let rootfs = tmp.join("fs/myroot");
        fs::create_dir_all(rootfs.join("oci/apps/app")).unwrap();
        fs::write(
            rootfs.join("oci/apps/app/volumes"),
            "/ok\nrelative\n/ok/../bad\n/good\n",
        )
        .unwrap();
        let vols = read_oci_app_volumes(&rootfs, "app");
        assert_eq!(vols, vec!["/ok", "/good"]);
    }

    // --- read_all_oci_apps tests ---

    #[test]
    fn test_read_all_oci_apps_empty() {
        let tmp = tmp();
        assert!(read_all_oci_apps(&tmp).is_empty());
    }

    #[test]
    fn test_read_all_oci_apps_single() {
        let tmp = tmp();
        let rootfs = tmp.join("fs/myroot");
        fs::create_dir_all(rootfs.join("oci/apps/nginx")).unwrap();
        fs::write(rootfs.join("oci/apps/nginx/env"), "PORT=80\n").unwrap();
        fs::write(rootfs.join("oci/apps/nginx/ports"), "80/tcp\n").unwrap();
        fs::write(rootfs.join("oci/apps/nginx/volumes"), "/var/www\n").unwrap();
        let apps = read_all_oci_apps(&rootfs);
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].name, "nginx");
        assert_eq!(apps[0].env, vec!["PORT=80"]);
        assert_eq!(apps[0].ports, vec!["80/tcp"]);
        assert_eq!(apps[0].volumes, vec!["/var/www"]);
    }

    #[test]
    fn test_read_all_oci_apps_multi_sorted() {
        let tmp = tmp();
        let rootfs = tmp.join("fs/myroot");
        fs::create_dir_all(rootfs.join("oci/apps/redis")).unwrap();
        fs::create_dir_all(rootfs.join("oci/apps/nginx")).unwrap();
        fs::write(rootfs.join("oci/apps/redis/ports"), "6379/tcp\n").unwrap();
        fs::write(rootfs.join("oci/apps/nginx/ports"), "80/tcp\n").unwrap();
        let apps = read_all_oci_apps(&rootfs);
        assert_eq!(apps.len(), 2);
        assert_eq!(apps[0].name, "nginx");
        assert_eq!(apps[1].name, "redis");
    }

    #[test]
    fn test_read_all_oci_apps_no_metadata_files() {
        let tmp = tmp();
        let rootfs = tmp.join("fs/myroot");
        fs::create_dir_all(rootfs.join("oci/apps/myapp")).unwrap();
        let apps = read_all_oci_apps(&rootfs);
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].name, "myapp");
        assert!(apps[0].env.is_empty());
        assert!(apps[0].ports.is_empty());
        assert!(apps[0].volumes.is_empty());
    }

    // --- sanitize_volume_name tests ---

    #[test]
    fn test_sanitize_volume_name() {
        assert_eq!(sanitize_volume_name("/var/lib/mysql"), "var-lib-mysql");
        assert_eq!(sanitize_volume_name("/data"), "data");
        assert_eq!(sanitize_volume_name("/a/b/c"), "a-b-c");
    }
}
