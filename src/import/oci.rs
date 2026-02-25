//! OCI container image import.

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use anyhow::{bail, Context, Result};
use serde::Deserialize;

use crate::check_interrupted;
use crate::copy::{make_removable, sanitize_dest_path};

use super::{detect_compression_magic, get_decoder};

#[derive(Deserialize)]
pub(super) struct OciLayout {
    #[serde(rename = "imageLayoutVersion")]
    pub(super) image_layout_version: String,
}

#[derive(Deserialize)]
pub(super) struct OciIndex {
    pub(super) manifests: Vec<OciDescriptor>,
}

#[derive(Deserialize)]
pub(super) struct OciDescriptor {
    pub(super) digest: String,
    #[serde(rename = "mediaType")]
    #[allow(dead_code)]
    pub(super) media_type: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct OciManifest {
    pub(super) layers: Vec<OciDescriptor>,
}

/// Check if a directory contains an OCI image layout (has an `oci-layout` file).
pub(super) fn is_oci_layout(dir: &Path) -> bool {
    dir.join("oci-layout").is_file()
}

/// Read and deserialize a JSON file.
fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let content =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_str(&content)
        .with_context(|| format!("failed to parse JSON from {}", path.display()))
}

/// Resolve a blob path from an OCI digest like `sha256:abc123`.
fn resolve_blob(oci_dir: &Path, digest: &str) -> Result<PathBuf> {
    let (algo, hash) = digest
        .split_once(':')
        .with_context(|| format!("invalid OCI digest format: {digest}"))?;
    // Validate algo and hash contain only safe characters to prevent path traversal.
    // OCI spec: algorithm is alphanumeric+separator, digest is hex. We allow
    // [a-zA-Z0-9_-] for algo and [a-fA-F0-9] for hash (the latter covers all
    // standard digest algorithms including sha256 and sha512).
    if algo.is_empty()
        || !algo
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        bail!("invalid OCI digest algorithm: {algo}");
    }
    if hash.is_empty() || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("invalid OCI digest hash: {hash}");
    }
    let blob_path = oci_dir.join("blobs").join(algo).join(hash);
    if !blob_path.exists() {
        bail!("OCI blob not found: {}", blob_path.display());
    }
    Ok(blob_path)
}

/// Import an OCI image layout by reading the manifest chain and extracting layers.
pub(super) fn import_oci_layout(oci_dir: &Path, staging_dir: &Path, verbose: bool) -> Result<()> {
    // Validate oci-layout version.
    let layout: OciLayout = read_json(&oci_dir.join("oci-layout"))?;
    if layout.image_layout_version != "1.0.0" {
        bail!(
            "unsupported OCI image layout version: {}",
            layout.image_layout_version
        );
    }

    // Read index.json to find the manifest.
    let index: OciIndex = read_json(&oci_dir.join("index.json"))?;
    if index.manifests.is_empty() {
        bail!("OCI index.json contains no manifests");
    }

    let manifest_blob = resolve_blob(oci_dir, &index.manifests[0].digest)?;

    // The index may point to an image manifest or a manifest index.
    // Use serde_json::Value to check which one it is.
    let manifest_value: serde_json::Value = read_json(&manifest_blob)?;

    let manifest: OciManifest = if manifest_value.get("layers").is_some() {
        // Direct image manifest.
        serde_json::from_value(manifest_value)
            .context("failed to parse OCI image manifest")?
    } else if manifest_value.get("manifests").is_some() {
        // Manifest index — follow one level of indirection.
        let sub_index: OciIndex = serde_json::from_value(manifest_value)
            .context("failed to parse OCI manifest index")?;
        if sub_index.manifests.is_empty() {
            bail!("OCI manifest index contains no manifests");
        }
        let sub_blob = resolve_blob(oci_dir, &sub_index.manifests[0].digest)?;
        read_json(&sub_blob)?
    } else {
        bail!("OCI manifest has neither 'layers' nor 'manifests' field");
    };

    if manifest.layers.is_empty() {
        bail!("OCI manifest contains no layers");
    }

    fs::create_dir_all(staging_dir)
        .with_context(|| format!("failed to create staging dir {}", staging_dir.display()))?;

    // Extract layers in order.
    for (i, layer) in manifest.layers.iter().enumerate() {
        check_interrupted()?;
        let blob_path = resolve_blob(oci_dir, &layer.digest)?;
        if verbose {
            eprintln!(
                "extracting layer {}/{}: {}",
                i + 1,
                manifest.layers.len(),
                layer.digest
            );
        }

        // Detect compression from magic bytes of the blob.
        let mut blob_file = File::open(&blob_path)
            .with_context(|| format!("failed to open blob {}", blob_path.display()))?;
        let mut magic = [0u8; 6];
        let n = blob_file.read(&mut magic)?;
        // Seek back to the start.
        drop(blob_file);
        let blob_file = File::open(&blob_path)?;

        let compression = detect_compression_magic(&magic[..n])?;
        unpack_oci_layer(get_decoder(blob_file, &compression)?, staging_dir)?;
    }

    Ok(())
}


/// Check whether a path resolves to a location inside `dest` after following symlinks.
/// Returns `false` if the canonical path escapes `dest` or canonicalization fails.
fn is_inside_dest(path: &Path, dest: &Path) -> bool {
    let Ok(canonical) = fs::canonicalize(path) else {
        return false;
    };
    let Ok(canonical_dest) = fs::canonicalize(dest) else {
        return false;
    };
    canonical.starts_with(&canonical_dest)
}

/// Unpack an OCI layer tar archive, handling OCI whiteout markers.
///
/// OCI whiteouts:
/// - `.wh..wh..opq` in a directory means "clear existing contents of this directory"
/// - `.wh.<name>` means "delete <name> from the destination"
fn unpack_oci_layer<R: Read>(reader: R, dest: &Path) -> Result<()> {
    let mut archive = tar::Archive::new(reader);
    archive.set_preserve_permissions(true);
    archive.set_preserve_ownerships(true);
    archive.set_unpack_xattrs(true);

    for entry in archive.entries().context("failed to read tar entries")? {
        check_interrupted()?;
        let mut entry = entry.context("failed to read tar entry")?;
        let raw_path = entry.path().context("failed to read entry path")?.into_owned();

        // Sanitize: strip leading '/' and reject paths with '..' components
        // to prevent path traversal in whiteout handling below.
        let path = sanitize_dest_path(&raw_path)?;

        let file_name: String = match path.file_name() {
            Some(name) => name.to_string_lossy().into_owned(),
            None => {
                // Root directory entry — just ensure it exists.
                entry.unpack_in(dest).with_context(|| {
                    format!("failed to unpack entry {}", path.display())
                })?;
                continue;
            }
        };

        if file_name == ".wh..wh..opq" {
            // Opaque whiteout: clear existing contents of the parent directory.
            let parent = path.parent().unwrap_or(Path::new(""));
            let abs_parent = dest.join(parent);
            if abs_parent.is_dir() {
                // Verify the parent resolves inside dest after following symlinks.
                if !is_inside_dest(&abs_parent, dest) {
                    eprintln!(
                        "warning: skipping opaque whiteout that escapes destination: {}",
                        path.display()
                    );
                    continue;
                }
                for child in fs::read_dir(&abs_parent)
                    .with_context(|| format!("failed to read dir {}", abs_parent.display()))?
                {
                    let child = child?;
                    let child_path = child.path();
                    if child.file_type()?.is_dir() {
                        let _ = make_removable(&child_path);
                        fs::remove_dir_all(&child_path).ok();
                    } else {
                        fs::remove_file(&child_path).ok();
                    }
                }
            }
            continue;
        }

        if let Some(target_name) = file_name.strip_prefix(".wh.") {
            // Regular whiteout: delete the target file/dir.
            let parent = path.parent().unwrap_or(Path::new(""));
            let target = dest.join(parent).join(target_name);
            // Verify the target resolves inside dest after following symlinks.
            if !is_inside_dest(&target, dest) {
                eprintln!(
                    "warning: skipping whiteout that escapes destination: {}",
                    path.display()
                );
                continue;
            }
            if target.is_dir() {
                let _ = make_removable(&target);
                fs::remove_dir_all(&target).ok();
            } else if target.exists() || target.symlink_metadata().is_ok() {
                fs::remove_file(&target).ok();
            }
            continue;
        }

        // Normal entry — unpack into destination.
        entry
            .unpack_in(dest)
            .with_context(|| format!("failed to unpack entry {}", path.display()))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs as unix_fs;

    use crate::import::tests::{INTERRUPT_LOCK, test_run, tmp};

    /// Helper to build an OCI image tarball programmatically.
    ///
    /// Constructs a valid OCI image layout with the given layers, each
    /// specified as a list of (path, content) pairs for regular files.
    /// Returns the path to the gzipped tarball.
    fn build_oci_tarball(
        name: &str,
        layers: &[Vec<(&str, &[u8])>],
        use_manifest_index: bool,
    ) -> PathBuf {
        use sha2::{Digest, Sha256};


        let work_dir = std::env::temp_dir().join(format!(
            "sdme-test-oci-build-{}-{:?}-{name}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&work_dir);
        fs::create_dir_all(work_dir.join("blobs/sha256")).unwrap();

        // Write oci-layout.
        fs::write(
            work_dir.join("oci-layout"),
            r#"{"imageLayoutVersion":"1.0.0"}"#,
        )
        .unwrap();

        // Build layer blobs.
        let mut layer_descriptors = Vec::new();
        for layer_files in layers {
            let mut layer_tar = Vec::new();
            {
                let encoder =
                    flate2::write::GzEncoder::new(&mut layer_tar, flate2::Compression::default());
                let mut builder = tar::Builder::new(encoder);
                for (path, content) in layer_files {
                    let mut header = tar::Header::new_ustar();
                    header.set_path(path).unwrap();
                    header.set_size(content.len() as u64);
                    header.set_mode(0o644);
                    header.set_uid(unsafe { libc::getuid() } as u64);
                    header.set_gid(unsafe { libc::getgid() } as u64);
                    header.set_cksum();
                    builder.append(&header, *content).unwrap();
                }
                let encoder = builder.into_inner().unwrap();
                encoder.finish().unwrap();
            }

            let hash = {
                let mut hasher = Sha256::new();
                hasher.update(&layer_tar);
                format!("{:x}", hasher.finalize())
            };

            fs::write(work_dir.join("blobs/sha256").join(&hash), &layer_tar).unwrap();
            layer_descriptors.push(serde_json::json!({
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": format!("sha256:{hash}"),
                "size": layer_tar.len()
            }));
        }

        // Build config blob (minimal).
        let config_json = b"{}";
        let config_hash = {
            let mut hasher = Sha256::new();
            hasher.update(config_json);
            format!("{:x}", hasher.finalize())
        };
        fs::write(
            work_dir.join("blobs/sha256").join(&config_hash),
            config_json,
        )
        .unwrap();

        // Build image manifest.
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": format!("sha256:{config_hash}"),
                "size": config_json.len()
            },
            "layers": layer_descriptors
        });
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        let manifest_hash = {
            let mut hasher = Sha256::new();
            hasher.update(&manifest_bytes);
            format!("{:x}", hasher.finalize())
        };
        fs::write(
            work_dir.join("blobs/sha256").join(&manifest_hash),
            &manifest_bytes,
        )
        .unwrap();

        // Build index.json.
        let index = if use_manifest_index {
            // Wrap in a manifest index (one level of indirection).
            let manifest_index = serde_json::json!({
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": [{
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": format!("sha256:{manifest_hash}"),
                    "size": manifest_bytes.len()
                }]
            });
            let mi_bytes = serde_json::to_vec(&manifest_index).unwrap();
            let mi_hash = {
                let mut hasher = Sha256::new();
                hasher.update(&mi_bytes);
                format!("{:x}", hasher.finalize())
            };
            fs::write(work_dir.join("blobs/sha256").join(&mi_hash), &mi_bytes).unwrap();

            serde_json::json!({
                "schemaVersion": 2,
                "manifests": [{
                    "mediaType": "application/vnd.oci.image.index.v1+json",
                    "digest": format!("sha256:{mi_hash}"),
                    "size": mi_bytes.len()
                }]
            })
        } else {
            serde_json::json!({
                "schemaVersion": 2,
                "manifests": [{
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": format!("sha256:{manifest_hash}"),
                    "size": manifest_bytes.len()
                }]
            })
        };
        fs::write(
            work_dir.join("index.json"),
            serde_json::to_vec_pretty(&index).unwrap(),
        )
        .unwrap();

        // Pack everything into a gzipped tarball.
        let tarball_path = std::env::temp_dir().join(format!(
            "sdme-test-oci-{}-{:?}-{name}.tar.gz",
            std::process::id(),
            std::thread::current().id()
        ));
        let file = File::create(&tarball_path).unwrap();
        let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        let mut builder = tar::Builder::new(encoder);
        builder.append_dir_all(".", &work_dir).unwrap();
        let encoder = builder.into_inner().unwrap();
        encoder.finish().unwrap();

        let _ = fs::remove_dir_all(&work_dir);
        tarball_path
    }

    /// Helper to build an OCI layer tarball with whiteout markers.
    fn build_oci_tarball_with_whiteouts(
        name: &str,
        base_files: Vec<(&str, &[u8])>,
        whiteout_entries: Vec<&str>,
    ) -> PathBuf {
        use sha2::{Digest, Sha256};


        let work_dir = std::env::temp_dir().join(format!(
            "sdme-test-oci-wh-build-{}-{:?}-{name}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&work_dir);
        fs::create_dir_all(work_dir.join("blobs/sha256")).unwrap();

        fs::write(
            work_dir.join("oci-layout"),
            r#"{"imageLayoutVersion":"1.0.0"}"#,
        )
        .unwrap();

        let mut layer_descriptors = Vec::new();

        // Base layer with files.
        {
            let mut layer_tar = Vec::new();
            {
                let encoder =
                    flate2::write::GzEncoder::new(&mut layer_tar, flate2::Compression::default());
                let mut builder = tar::Builder::new(encoder);
                for (path, content) in &base_files {
                    let mut header = tar::Header::new_ustar();
                    header.set_path(path).unwrap();
                    header.set_size(content.len() as u64);
                    header.set_mode(0o644);
                    header.set_uid(unsafe { libc::getuid() } as u64);
                    header.set_gid(unsafe { libc::getgid() } as u64);
                    header.set_cksum();
                    builder.append(&header, *content).unwrap();
                }
                let encoder = builder.into_inner().unwrap();
                encoder.finish().unwrap();
            }
            let hash = {
                let mut hasher = Sha256::new();
                hasher.update(&layer_tar);
                format!("{:x}", hasher.finalize())
            };
            fs::write(work_dir.join("blobs/sha256").join(&hash), &layer_tar).unwrap();
            layer_descriptors.push(serde_json::json!({
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": format!("sha256:{hash}"),
                "size": layer_tar.len()
            }));
        }

        // Whiteout layer.
        {
            let mut layer_tar = Vec::new();
            {
                let encoder =
                    flate2::write::GzEncoder::new(&mut layer_tar, flate2::Compression::default());
                let mut builder = tar::Builder::new(encoder);
                for entry_path in &whiteout_entries {
                    let mut header = tar::Header::new_ustar();
                    header.set_path(entry_path).unwrap();
                    header.set_size(0);
                    header.set_mode(0o644);
                    header.set_uid(unsafe { libc::getuid() } as u64);
                    header.set_gid(unsafe { libc::getgid() } as u64);
                    header.set_cksum();
                    builder.append(&header, &b""[..]).unwrap();
                }
                let encoder = builder.into_inner().unwrap();
                encoder.finish().unwrap();
            }
            let hash = {
                let mut hasher = Sha256::new();
                hasher.update(&layer_tar);
                format!("{:x}", hasher.finalize())
            };
            fs::write(work_dir.join("blobs/sha256").join(&hash), &layer_tar).unwrap();
            layer_descriptors.push(serde_json::json!({
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": format!("sha256:{hash}"),
                "size": layer_tar.len()
            }));
        }

        // Config + manifest + index (same pattern as build_oci_tarball).
        let config_json = b"{}";
        let config_hash = {
            let mut hasher = Sha256::new();
            hasher.update(config_json);
            format!("{:x}", hasher.finalize())
        };
        fs::write(
            work_dir.join("blobs/sha256").join(&config_hash),
            config_json,
        )
        .unwrap();

        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": format!("sha256:{config_hash}"),
                "size": config_json.len()
            },
            "layers": layer_descriptors
        });
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        let manifest_hash = {
            let mut hasher = Sha256::new();
            hasher.update(&manifest_bytes);
            format!("{:x}", hasher.finalize())
        };
        fs::write(
            work_dir.join("blobs/sha256").join(&manifest_hash),
            &manifest_bytes,
        )
        .unwrap();

        let index = serde_json::json!({
            "schemaVersion": 2,
            "manifests": [{
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": format!("sha256:{manifest_hash}"),
                "size": manifest_bytes.len()
            }]
        });
        fs::write(
            work_dir.join("index.json"),
            serde_json::to_vec_pretty(&index).unwrap(),
        )
        .unwrap();

        let tarball_path = std::env::temp_dir().join(format!(
            "sdme-test-oci-wh-{}-{:?}-{name}.tar.gz",
            std::process::id(),
            std::thread::current().id()
        ));
        let file = File::create(&tarball_path).unwrap();
        let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        let mut builder = tar::Builder::new(encoder);
        builder.append_dir_all(".", &work_dir).unwrap();
        let encoder = builder.into_inner().unwrap();
        encoder.finish().unwrap();

        let _ = fs::remove_dir_all(&work_dir);
        tarball_path
    }

    #[test]
    fn test_is_oci_layout() {
        let dir = std::env::temp_dir().join(format!(
            "sdme-test-oci-detect-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        // No oci-layout file.
        assert!(!is_oci_layout(&dir));

        // Create oci-layout file.
        fs::write(dir.join("oci-layout"), r#"{"imageLayoutVersion":"1.0.0"}"#).unwrap();
        assert!(is_oci_layout(&dir));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_import_oci_basic() {
        let tmp = tmp();
        let tarball = build_oci_tarball(
            "basic",
            &[vec![
                ("etc/os-release", b"PRETTY_NAME=\"TestOS 1.0\"\n"),
                ("hello.txt", b"hello from OCI\n"),
            ]],
            false,
        );

        test_run(
            tmp.path(),
            tarball.to_str().unwrap(),
            "ocibasic",
            false,
            true,
        )
        .unwrap();

        let rootfs = tmp.path().join("fs/ocibasic");
        assert!(rootfs.is_dir());
        assert_eq!(
            fs::read_to_string(rootfs.join("hello.txt")).unwrap(),
            "hello from OCI\n"
        );
        assert_eq!(
            fs::read_to_string(rootfs.join("etc/os-release")).unwrap(),
            "PRETTY_NAME=\"TestOS 1.0\"\n"
        );

        let _ = fs::remove_file(&tarball);
    }

    #[test]
    fn test_import_oci_multilayer() {
        let tmp = tmp();
        let tarball = build_oci_tarball(
            "multi",
            &[
                vec![
                    ("base.txt", b"from layer 1\n"),
                    ("shared.txt", b"layer 1 version\n"),
                ],
                vec![
                    ("overlay.txt", b"from layer 2\n"),
                    ("shared.txt", b"layer 2 version\n"),
                ],
            ],
            false,
        );

        test_run(
            tmp.path(),
            tarball.to_str().unwrap(),
            "ocimulti",
            false,
            true,
        )
        .unwrap();

        let rootfs = tmp.path().join("fs/ocimulti");
        assert_eq!(
            fs::read_to_string(rootfs.join("base.txt")).unwrap(),
            "from layer 1\n"
        );
        assert_eq!(
            fs::read_to_string(rootfs.join("overlay.txt")).unwrap(),
            "from layer 2\n"
        );
        // Layer 2 should overwrite layer 1's version.
        assert_eq!(
            fs::read_to_string(rootfs.join("shared.txt")).unwrap(),
            "layer 2 version\n"
        );

        let _ = fs::remove_file(&tarball);
    }

    #[test]
    fn test_import_oci_whiteout() {
        let tmp = tmp();
        let tarball = build_oci_tarball_with_whiteouts(
            "whiteout",
            vec![
                ("keep.txt", b"keep me\n"),
                ("delete-me.txt", b"delete me\n"),
                ("subdir/also-delete.txt", b"also delete\n"),
                ("subdir/keep-this.txt", b"keep this\n"),
            ],
            vec![".wh.delete-me.txt", "subdir/.wh.also-delete.txt"],
        );

        test_run(
            tmp.path(),
            tarball.to_str().unwrap(),
            "ociwhiteout",
            false,
            true,
        )
        .unwrap();

        let rootfs = tmp.path().join("fs/ociwhiteout");
        assert_eq!(
            fs::read_to_string(rootfs.join("keep.txt")).unwrap(),
            "keep me\n"
        );
        assert!(
            !rootfs.join("delete-me.txt").exists(),
            "whiteout should have deleted delete-me.txt"
        );
        assert!(
            !rootfs.join("subdir/also-delete.txt").exists(),
            "whiteout should have deleted subdir/also-delete.txt"
        );
        assert_eq!(
            fs::read_to_string(rootfs.join("subdir/keep-this.txt")).unwrap(),
            "keep this\n"
        );

        let _ = fs::remove_file(&tarball);
    }

    #[test]
    fn test_oci_whiteout_symlink_escape() {
        // Hold the interrupt lock so concurrent InterruptGuard tests don't
        // set INTERRUPTED while unpack_oci_layer calls check_interrupted().
        let _lock = INTERRUPT_LOCK.lock().unwrap();

        // Layer 1: a symlink "escape" pointing outside dest.
        // Layer 2: a whiteout "escape/.wh.target" that should NOT follow the symlink.
        let dest = std::env::temp_dir().join(format!(
            "sdme-test-wh-escape-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let outside = std::env::temp_dir().join(format!(
            "sdme-test-wh-outside-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dest);
        let _ = fs::remove_dir_all(&outside);
        fs::create_dir_all(&dest).unwrap();
        fs::create_dir_all(&outside).unwrap();

        // Create a file outside dest that should survive.
        fs::write(outside.join("target"), "do not delete\n").unwrap();

        // Create a symlink inside dest that points outside.
        unix_fs::symlink(&outside, dest.join("escape")).unwrap();

        // Build a tar with a regular whiteout targeting escape/target.
        let mut layer_tar = Vec::new();
        {
            let encoder =
                flate2::write::GzEncoder::new(&mut layer_tar, flate2::Compression::default());
            let mut builder = tar::Builder::new(encoder);
            // Whiteout entry: escape/.wh.target
            let mut header = tar::Header::new_ustar();
            header.set_path("escape/.wh.target").unwrap();
            header.set_size(0);
            header.set_mode(0o644);
            header.set_uid(0);
            header.set_gid(0);
            header.set_cksum();
            builder.append(&header, &b""[..]).unwrap();
            let encoder = builder.into_inner().unwrap();
            encoder.finish().unwrap();
        }

        let reader = flate2::read::GzDecoder::new(&layer_tar[..]);
        unpack_oci_layer(reader, &dest).unwrap();

        // The file outside dest must NOT have been deleted.
        assert!(
            outside.join("target").exists(),
            "whiteout should not follow symlink outside dest"
        );

        let _ = fs::remove_dir_all(&dest);
        let _ = fs::remove_dir_all(&outside);
    }

    #[test]
    fn test_import_oci_manifest_index() {
        let tmp = tmp();
        let tarball = build_oci_tarball(
            "index",
            &[vec![("from-index.txt", b"via manifest index\n")]],
            true, // Use manifest index indirection.
        );

        test_run(
            tmp.path(),
            tarball.to_str().unwrap(),
            "ociindex",
            false,
            true,
        )
        .unwrap();

        let rootfs = tmp.path().join("fs/ociindex");
        assert_eq!(
            fs::read_to_string(rootfs.join("from-index.txt")).unwrap(),
            "via manifest index\n"
        );

        let _ = fs::remove_file(&tarball);
    }
}
