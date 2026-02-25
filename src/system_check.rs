use std::path::PathBuf;

use anyhow::{bail, Result};

use crate::systemd;

fn parse_systemd_version(version: &str) -> Result<u32> {
    let digits: String = version.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        bail!("cannot parse systemd version: {version:?}");
    }
    digits
        .parse::<u32>()
        .map_err(|e| anyhow::anyhow!("cannot parse systemd version: {e}"))
}

/// Check that systemd is >= min_version.
/// Reads the "Version" property from org.freedesktop.systemd1.Manager via D-Bus.
pub fn check_systemd_version(min_version: u32) -> Result<()> {
    let version_str = systemd::systemd_version()?;
    let version = parse_systemd_version(&version_str)?;
    if version < min_version {
        bail!("systemd {min_version} or later is required (found {version})");
    }
    Ok(())
}

/// Find a program in PATH, returning its full path.
///
/// Checks that the candidate is a regular file and has at least one
/// execute bit set (user, group, or other).
pub fn find_program(name: &str) -> Result<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let path_var = std::env::var("PATH").unwrap_or_default();
    for dir in path_var.split(':') {
        let candidate = PathBuf::from(dir).join(name);
        if let Ok(meta) = std::fs::metadata(&candidate) {
            if meta.is_file() && (meta.permissions().mode() & 0o111 != 0) {
                return Ok(candidate);
            }
        }
    }
    bail!("{name} not found in PATH")
}

/// Check that all required external programs are available.
///
/// `programs` is a slice of `(binary_name, package_hint)` pairs.
/// With `verbose`, prints the resolved path for each program.
pub fn check_dependencies(programs: &[(&str, &str)], verbose: bool) -> Result<()> {
    for (name, hint) in programs {
        match find_program(name) {
            Ok(path) => {
                if verbose {
                    eprintln!("found {name}: {}", path.display());
                }
            }
            Err(_) => {
                bail!("{name} not found; install it with: {hint}");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_systemd_version_plain() {
        assert_eq!(parse_systemd_version("259").unwrap(), 259);
    }

    #[test]
    fn test_parse_systemd_version_with_suffix() {
        assert_eq!(parse_systemd_version("255-1ubuntu1").unwrap(), 255);
    }

    #[test]
    fn test_parse_systemd_version_empty() {
        assert!(parse_systemd_version("").is_err());
    }
}
