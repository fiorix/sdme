//! Tarball extraction and OCI detection.

use anyhow::{Context, Result};
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

use crate::check_interrupted;
use crate::copy::make_removable;

use super::oci::{import_oci_layout, is_oci_layout};
use super::{detect_compression, get_decoder};

/// Unpack a tar archive from a reader into a destination directory.
pub(super) fn unpack_tar<R: Read>(reader: R, dest: &Path) -> Result<()> {
    let mut archive = tar::Archive::new(reader);
    archive.set_preserve_permissions(true);
    archive.set_preserve_ownerships(true);
    archive.set_unpack_xattrs(true);
    for entry in archive
        .entries()
        .with_context(|| format!("failed to extract tarball to {}", dest.display()))?
    {
        check_interrupted()?;
        let mut entry =
            entry.with_context(|| format!("failed to extract tarball to {}", dest.display()))?;
        entry
            .unpack_in(dest)
            .with_context(|| format!("failed to extract tarball to {}", dest.display()))?;
    }
    Ok(())
}

/// Extract a tarball into the staging directory using native Rust crates.
///
/// After extraction, checks if the result is an OCI image layout and
/// processes it accordingly.
pub(super) fn import_tarball(tarball: &Path, staging_dir: &Path, verbose: bool) -> Result<()> {
    let compression = detect_compression(tarball)?;

    fs::create_dir_all(staging_dir)
        .with_context(|| format!("failed to create staging dir {}", staging_dir.display()))?;

    if verbose {
        eprintln!(
            "extracting {} -> {}",
            tarball.display(),
            staging_dir.display()
        );
    }

    let file =
        File::open(tarball).with_context(|| format!("failed to open {}", tarball.display()))?;

    unpack_tar(get_decoder(file, &compression)?, staging_dir)?;

    // Check if the extracted content is an OCI image layout.
    if is_oci_layout(staging_dir) {
        if verbose {
            eprintln!("detected OCI image layout");
        }
        let mut oci_name = staging_dir.file_name().unwrap().to_os_string();
        oci_name.push(".oci");
        let oci_dir = staging_dir.with_file_name(oci_name);
        fs::rename(staging_dir, &oci_dir)?;
        let result = import_oci_layout(&oci_dir, staging_dir, verbose);
        let _ = make_removable(&oci_dir);
        let _ = fs::remove_dir_all(&oci_dir);
        return result;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    use crate::import::tests::{test_run, tmp, InterruptGuard, TempSourceDir};

    #[test]
    fn test_import_tarball_basic() {
        let tmp = tmp();
        let src = TempSourceDir::new("tarball-gz");

        // Create source files.
        fs::write(src.path().join("hello.txt"), "hello world\n").unwrap();
        fs::create_dir(src.path().join("subdir")).unwrap();
        fs::write(src.path().join("subdir/nested.txt"), "nested\n").unwrap();

        // Create a gzipped tarball using tar::Builder.
        let tarball = std::env::temp_dir().join(format!(
            "sdme-test-tarball-{}-{:?}.tar.gz",
            std::process::id(),
            std::thread::current().id()
        ));
        let file = File::create(&tarball).unwrap();
        let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        let mut builder = tar::Builder::new(encoder);
        builder.append_dir_all(".", src.path()).unwrap();
        let encoder = builder.into_inner().unwrap();
        encoder.finish().unwrap();

        test_run(tmp.path(), tarball.to_str().unwrap(), "tgz", false, true).unwrap();

        let rootfs = tmp.path().join("fs/tgz");
        assert!(rootfs.is_dir());
        assert_eq!(
            fs::read_to_string(rootfs.join("hello.txt")).unwrap(),
            "hello world\n"
        );
        assert!(rootfs.join("subdir").is_dir());
        assert_eq!(
            fs::read_to_string(rootfs.join("subdir/nested.txt")).unwrap(),
            "nested\n"
        );

        let _ = fs::remove_file(&tarball);
    }

    #[test]
    fn test_import_tarball_uncompressed() {
        let tmp = tmp();
        let src = TempSourceDir::new("tarball-plain");

        fs::write(src.path().join("file.txt"), "content\n").unwrap();

        // Create an uncompressed tarball using tar::Builder.
        let tarball = std::env::temp_dir().join(format!(
            "sdme-test-tarball-plain-{}-{:?}.tar",
            std::process::id(),
            std::thread::current().id()
        ));
        let file = File::create(&tarball).unwrap();
        let mut builder = tar::Builder::new(file);
        builder.append_dir_all(".", src.path()).unwrap();
        builder.finish().unwrap();

        test_run(tmp.path(), tarball.to_str().unwrap(), "plain", false, true).unwrap();

        let rootfs = tmp.path().join("fs/plain");
        assert_eq!(
            fs::read_to_string(rootfs.join("file.txt")).unwrap(),
            "content\n"
        );

        let _ = fs::remove_file(&tarball);
    }

    #[test]
    fn test_import_tarball_invalid_file() {
        let tmp = tmp();
        let file_path = std::env::temp_dir().join(format!(
            "sdme-test-bad-tarball-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        fs::write(&file_path, "this is not a tarball").unwrap();

        let err =
            test_run(tmp.path(), file_path.to_str().unwrap(), "bad", false, false).unwrap_err();
        assert!(
            err.to_string().contains("extract"),
            "unexpected error: {err}"
        );

        // Staging dir should be cleaned up.
        assert!(!tmp.path().join("fs/.bad.importing").exists());

        let _ = fs::remove_file(&file_path);
    }

    #[test]
    fn test_unpack_tar_interrupted() {
        let _guard = InterruptGuard::new();
        let src = TempSourceDir::new("int-tar-src");
        fs::write(src.path().join("file.txt"), "data").unwrap();

        // Build a small tarball.
        let tarball_path = std::env::temp_dir().join(format!(
            "sdme-test-int-tar-{}-{:?}.tar",
            std::process::id(),
            std::thread::current().id()
        ));
        let file = File::create(&tarball_path).unwrap();
        let mut builder = tar::Builder::new(file);
        builder.append_dir_all(".", src.path()).unwrap();
        builder.finish().unwrap();

        let dest = std::env::temp_dir().join(format!(
            "sdme-test-int-tar-dst-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dest);
        fs::create_dir_all(&dest).unwrap();

        let file = File::open(&tarball_path).unwrap();
        let err = unpack_tar(file, &dest).unwrap_err();
        assert!(
            err.to_string().contains("interrupted"),
            "unexpected error: {err}"
        );

        let _ = fs::remove_dir_all(&dest);
        let _ = fs::remove_file(&tarball_path);
    }
}
