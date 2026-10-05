//! Tarball export: create compressed tar archives from rootfs.

use std::fs::{self, File};
use std::path::Path;

use anyhow::{bail, Context, Result};

use super::{ExportFormat, ExportOptions};
use crate::{check_interrupted, copy};

/// Export by creating a tar archive, optionally compressed.
///
/// On error, removes the partially-written output file.
pub(super) fn export_to_tar(src: &Path, output: &Path, opts: &ExportOptions) -> Result<()> {
    if output.exists() {
        if opts.force {
            fs::remove_file(output)
                .with_context(|| format!("failed to remove {}", output.display()))?;
        } else {
            bail!("destination already exists: {}", output.display());
        }
    }
    if opts.verbose {
        eprintln!("creating tarball: {}", output.display());
    }

    let file =
        File::create(output).with_context(|| format!("failed to create {}", output.display()))?;

    let result = (|| -> Result<()> {
        match opts.format {
            ExportFormat::Tar => {
                write_tar(file, src, opts.verbose, opts.timezone)?;
            }
            ExportFormat::TarGz => {
                let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
                let encoder = write_tar(encoder, src, opts.verbose, opts.timezone)?;
                encoder.finish()?;
            }
            ExportFormat::TarBz2 => {
                let encoder = bzip2::write::BzEncoder::new(file, bzip2::Compression::default());
                let encoder = write_tar(encoder, src, opts.verbose, opts.timezone)?;
                encoder.finish()?;
            }
            ExportFormat::TarXz => {
                let encoder = xz2::write::XzEncoder::new(file, 6);
                let encoder = write_tar(encoder, src, opts.verbose, opts.timezone)?;
                encoder.finish()?;
            }
            ExportFormat::TarZst => {
                let encoder = zstd::stream::write::Encoder::new(file, 0)?;
                let encoder = write_tar(encoder, src, opts.verbose, opts.timezone)?;
                encoder.finish()?;
            }
            _ => unreachable!(),
        }
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(output);
    }
    result
}

/// Build a tar archive from a source directory into the given writer.
/// Returns the writer so callers can finalize compression encoders.
fn write_tar<W: std::io::Write>(
    writer: W,
    src: &Path,
    verbose: bool,
    timezone: Option<&str>,
) -> Result<W> {
    let mut builder = tar::Builder::new(writer);
    builder.follow_symlinks(false);
    let mut hardlinks = copy::HardLinkMap::new();
    append_dir_recursive(&mut builder, src, src, verbose, &mut hardlinks)?;

    if let Some(tz) = timezone {
        // Add /etc/localtime symlink.
        let target = format!("../usr/share/zoneinfo/{tz}");
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mode(0o777);
        builder.append_link(&mut header, "etc/localtime", &target)?;

        // Add /etc/timezone file.
        let tz_data = format!("{tz}\n");
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(tz_data.len() as u64);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mode(0o644);
        builder.append_data(&mut header, "etc/timezone", tz_data.as_bytes())?;
    }

    Ok(builder.into_inner()?)
}

/// Recursively append directory entries to a tar builder, preserving
/// ownership, permission bits, modification times, special file types and
/// their device numbers, hard links, and xattrs.
fn append_dir_recursive<W: std::io::Write>(
    builder: &mut tar::Builder<W>,
    root: &Path,
    dir: &Path,
    verbose: bool,
    hardlinks: &mut copy::HardLinkMap,
) -> Result<()> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    let entries =
        fs::read_dir(dir).with_context(|| format!("failed to read directory {}", dir.display()))?;

    for entry in entries {
        check_interrupted()?;
        let entry = entry.with_context(|| format!("failed to read entry in {}", dir.display()))?;
        let path = entry.path();
        let rel = path
            .strip_prefix(root)
            .with_context(|| format!("failed to strip prefix from {}", path.display()))?;

        if verbose {
            eprintln!("  {}", rel.display());
        }

        let meta = fs::symlink_metadata(&path)
            .with_context(|| format!("failed to stat {}", path.display()))?;

        let mut header = tar::Header::new_gnu();
        header.set_metadata_in_mode(&meta, tar::HeaderMode::Complete);
        // Complete mode stores the raw st_mode, file type bits included; a
        // tar header carries the permission bits only.
        header.set_mode(meta.mode() & 0o7777);
        // A pre-epoch mtime would wrap in the header's unsigned field.
        header.set_mtime(meta.mtime().max(0) as u64);
        // The tar crate leaves device numbers at zero, which would turn every
        // exported device node into 0:0 (an overlayfs whiteout).
        let file_type = meta.file_type();
        if file_type.is_char_device() || file_type.is_block_device() {
            header.set_device_major(libc::major(meta.rdev()))?;
            header.set_device_minor(libc::minor(meta.rdev()))?;
        }

        if meta.is_dir() {
            append_pax_xattrs(builder, &path)?;
            builder.append_data(&mut header, rel, &[] as &[u8])?;
            append_dir_recursive(builder, root, &path, verbose, hardlinks)?;
        } else if meta.is_symlink() {
            append_pax_xattrs(builder, &path)?;
            let target = fs::read_link(&path)
                .with_context(|| format!("failed to read symlink {}", path.display()))?;
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            builder.append_link(&mut header, rel, &target)?;
        } else if meta.is_file() {
            // Hard link detection.
            if meta.nlink() > 1 {
                let key = (meta.dev(), meta.ino());
                if let Some(first) = hardlinks.get(&key) {
                    header.set_entry_type(tar::EntryType::Link);
                    header.set_size(0);
                    builder.append_link(&mut header, rel, first)?;
                    continue;
                }
                hardlinks.insert(key, rel.to_path_buf());
            }
            append_pax_xattrs(builder, &path)?;
            let file =
                File::open(&path).with_context(|| format!("failed to open {}", path.display()))?;
            builder.append_data(&mut header, rel, file)?;
        } else {
            // Block/char devices, fifos, sockets: append header only.
            append_pax_xattrs(builder, &path)?;
            header.set_size(0);
            builder.append_data(&mut header, rel, &[] as &[u8])?;
        }
    }
    Ok(())
}

/// Write xattrs as PAX extended headers (`SCHILY.xattr.*`) before the entry.
fn append_pax_xattrs<W: std::io::Write>(builder: &mut tar::Builder<W>, path: &Path) -> Result<()> {
    let xattrs = copy::read_xattrs(path)?;
    if xattrs.is_empty() {
        return Ok(());
    }
    let pax: Vec<(String, &[u8])> = xattrs
        .iter()
        .map(|(name, val)| {
            (
                format!("SCHILY.xattr.{}", name.to_string_lossy()),
                val.as_slice(),
            )
        })
        .collect();
    builder
        .append_pax_extensions(pax.iter().map(|(k, v)| (k.as_str(), *v)))
        .context("failed to write PAX xattr extensions")?;
    Ok(())
}
