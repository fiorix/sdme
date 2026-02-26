//! QCOW2 and raw disk image import.

use anyhow::{bail, Context, Result};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::check_interrupted;

use super::dir::do_import;
use super::{detect_compression, get_decoder, Compression};

/// RAII guard for an NBD device connection. Disconnects on drop.
struct NbdGuard {
    device: PathBuf,
    active: bool,
}

impl NbdGuard {
    fn new() -> Self {
        Self {
            device: PathBuf::new(),
            active: false,
        }
    }

    fn set_active(&mut self, device: PathBuf) {
        self.device = device;
        self.active = true;
    }

    fn disconnect(&mut self) {
        if self.active {
            let _ = Command::new("qemu-nbd")
                .args(["--disconnect"])
                .arg(&self.device)
                .status();
            self.active = false;
        }
    }
}

impl Drop for NbdGuard {
    fn drop(&mut self) {
        self.disconnect();
    }
}

/// RAII guard for a mount point. Unmounts and removes the directory on drop.
struct MountGuard {
    path: PathBuf,
    mounted: bool,
}

impl MountGuard {
    fn new() -> Self {
        Self {
            path: PathBuf::new(),
            mounted: false,
        }
    }

    fn set_mounted(&mut self, path: PathBuf) {
        self.path = path;
        self.mounted = true;
    }

    fn unmount(&mut self) {
        if self.mounted {
            let _ = Command::new("umount").arg(&self.path).status();
            let _ = fs::remove_dir(&self.path);
            self.mounted = false;
        }
    }
}

impl Drop for MountGuard {
    fn drop(&mut self) {
        self.unmount();
    }
}

/// Import a QCOW2 disk image by mounting it via qemu-nbd and copying the filesystem tree.
///
/// Steps:
/// 1. Load the `nbd` kernel module
/// 2. Find a free `/dev/nbdN` device
/// 3. Connect the qcow2 image via `qemu-nbd`
/// 4. Discover and mount the root partition
/// 5. Copy the mounted tree to the staging directory
/// 6. Clean up (unmount, disconnect)
pub(super) fn import_qcow2(image: &Path, staging_dir: &Path, verbose: bool) -> Result<()> {
    crate::system_check::check_dependencies(&[("qemu-nbd", "apt install qemu-utils")], verbose)?;

    if !verbose {
        eprintln!("warning: qcow2 imports can be slow; use -v to see progress");
    } else {
        eprintln!("importing qcow2 image: {}", image.display());
    }

    // Load the nbd kernel module.
    let status = Command::new("modprobe")
        .args(["nbd", "max_part=16"])
        .status()
        .context("failed to run modprobe nbd")?;
    if !status.success() {
        bail!("modprobe nbd failed (is the nbd kernel module available?)");
    }

    // Find a free /dev/nbdN device.
    let nbd_dev = find_free_nbd_device()?;
    if verbose {
        eprintln!("using nbd device: {}", nbd_dev.display());
    }

    let mut nbd_guard = NbdGuard::new();
    let mut mount_guard = MountGuard::new();

    // Connect the image. The guard ensures disconnect on any exit path.
    let status = Command::new("qemu-nbd")
        .args(["--read-only", "--connect"])
        .arg(&nbd_dev)
        .arg(image)
        .status()
        .context("failed to run qemu-nbd")?;
    if !status.success() {
        bail!("qemu-nbd --connect failed for {}", image.display());
    }
    nbd_guard.set_active(nbd_dev.clone());

    check_interrupted()?;

    // Wait for the kernel to scan partitions.
    let status = Command::new("partprobe").arg(&nbd_dev).status();
    // partprobe is optional; if missing, the kernel usually scans automatically.
    if let Ok(s) = status {
        if !s.success() && verbose {
            eprintln!("partprobe failed (non-fatal)");
        }
    }

    // Small delay for partition devices to appear.
    std::thread::sleep(std::time::Duration::from_millis(500));

    check_interrupted()?;

    // Find the root partition device.
    let part_dev = find_root_partition(&nbd_dev, verbose)?;
    if verbose {
        eprintln!("mounting partition: {}", part_dev.display());
    }

    // Create a temporary mount point.
    let mount_dir = staging_dir.with_file_name(format!(
        ".{}.qcow2-mount",
        staging_dir.file_name().unwrap().to_string_lossy()
    ));
    fs::create_dir_all(&mount_dir)
        .with_context(|| format!("failed to create mount point {}", mount_dir.display()))?;

    // Mount the partition read-only.
    let status = Command::new("mount")
        .args(["-o", "ro"])
        .arg(&part_dev)
        .arg(&mount_dir)
        .status()
        .context("failed to run mount")?;
    if !status.success() {
        let _ = fs::remove_dir(&mount_dir);
        bail!("mount failed for {}", part_dev.display());
    }
    mount_guard.set_mounted(mount_dir);

    // Copy the tree. Guards handle cleanup on error or interruption.
    let result = do_import(&mount_guard.path, staging_dir, verbose);

    // Explicit cleanup in order (mount before nbd disconnect).
    mount_guard.unmount();
    nbd_guard.disconnect();

    result
}

/// Find a free `/dev/nbdN` device by checking which ones have zero size.
fn find_free_nbd_device() -> Result<PathBuf> {
    for i in 0..16 {
        let dev = PathBuf::from(format!("/dev/nbd{i}"));
        if !dev.exists() {
            continue;
        }
        let size_path = PathBuf::from(format!("/sys/block/nbd{i}/size"));
        if let Ok(content) = fs::read_to_string(&size_path) {
            if content.trim() == "0" {
                return Ok(dev);
            }
        }
    }
    bail!("no free nbd device found (all /dev/nbd0..15 are in use)")
}

/// Find the root partition on a block device (nbd or loop).
///
/// Looks for partition devices (`/dev/{dev}pM`) and picks the largest one,
/// which is typically the root filesystem. If no partitions are found,
/// tries the whole device (for unpartitioned disk images).
fn find_root_partition(block_dev: &Path, verbose: bool) -> Result<PathBuf> {
    let dev_name = block_dev
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();

    // Look for partition devices in /sys/block/nbdN/.
    let sys_dir = PathBuf::from(format!("/sys/block/{dev_name}"));
    let mut partitions: Vec<(PathBuf, u64)> = Vec::new();

    if let Ok(entries) = fs::read_dir(&sys_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.starts_with(&format!("{dev_name}p")) {
                continue;
            }
            let size_path = entry.path().join("size");
            if let Ok(content) = fs::read_to_string(&size_path) {
                if let Ok(size) = content.trim().parse::<u64>() {
                    if size > 0 {
                        let part_dev = PathBuf::from(format!("/dev/{name}"));
                        if verbose {
                            eprintln!("found partition: {} ({} sectors)", part_dev.display(), size);
                        }
                        partitions.push((part_dev, size));
                    }
                }
            }
        }
    }

    if partitions.is_empty() {
        // No partitions found; try the whole device (unpartitioned image).
        if verbose {
            eprintln!("no partitions found, trying whole device");
        }
        return Ok(block_dev.to_path_buf());
    }

    // Pick the largest partition (usually the root filesystem).
    partitions.sort_by(|a, b| b.1.cmp(&a.1));
    Ok(partitions[0].0.clone())
}

/// RAII guard for a loop device. Detaches on drop.
struct LoopGuard {
    device: PathBuf,
    active: bool,
}

impl LoopGuard {
    fn new() -> Self {
        Self {
            device: PathBuf::new(),
            active: false,
        }
    }

    fn set_active(&mut self, device: PathBuf) {
        self.device = device;
        self.active = true;
    }

    fn detach(&mut self) {
        if self.active {
            let _ = Command::new("losetup")
                .args(["--detach"])
                .arg(&self.device)
                .status();
            self.active = false;
        }
    }
}

impl Drop for LoopGuard {
    fn drop(&mut self) {
        self.detach();
    }
}

/// Decompress a file in-place if it is compressed, returning the path to the
/// uncompressed file. For uncompressed files, returns the original path unchanged.
/// For compressed files, decompresses to a `.decompressed` sibling file and returns
/// that path.
fn decompress_if_needed(path: &Path, verbose: bool) -> Result<PathBuf> {
    let compression = detect_compression(path)?;
    match compression {
        Compression::None => Ok(path.to_path_buf()),
        _ => {
            let decompressed = path.with_extension("decompressed");
            if verbose {
                eprintln!("decompressing {} ({:?})", path.display(), compression,);
            }
            let input =
                File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
            let mut output = File::create(&decompressed)
                .with_context(|| format!("failed to create {}", decompressed.display()))?;

            let mut reader = get_decoder(input, &compression)?;

            let mut buf = [0u8; 65536];
            loop {
                check_interrupted()?;
                let n = reader
                    .read(&mut buf)
                    .context("failed to read during decompression")?;
                if n == 0 {
                    break;
                }
                std::io::Write::write_all(&mut output, &buf[..n])
                    .context("failed to write during decompression")?;
            }

            if verbose {
                let meta = fs::metadata(&decompressed)?;
                eprintln!(
                    "decompressed to {} ({} bytes)",
                    decompressed.display(),
                    meta.len()
                );
            }
            Ok(decompressed)
        }
    }
}

/// Import a raw disk image by mounting it via a loop device and copying the filesystem tree.
///
/// Steps:
/// 1. Decompress the image if compressed
/// 2. Attach via `losetup --partscan --read-only --find --show`
/// 3. Discover and mount the root partition
/// 4. Copy the mounted tree to the staging directory
/// 5. Clean up (unmount, detach loop, remove temp files)
pub(super) fn import_raw(image: &Path, staging_dir: &Path, verbose: bool) -> Result<()> {
    if !verbose {
        eprintln!("warning: raw image imports can be slow; use -v to see progress");
    } else {
        eprintln!("importing raw disk image: {}", image.display());
    }

    // Decompress if needed.
    let decompressed = decompress_if_needed(image, verbose)?;
    let cleanup_decompressed = decompressed != image;

    let result = (|| -> Result<()> {
        // Attach the image as a loop device.
        let output = Command::new("losetup")
            .args(["--partscan", "--read-only", "--find", "--show"])
            .arg(&decompressed)
            .output()
            .context("failed to run losetup")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("losetup failed: {stderr}");
        }
        let loop_dev = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim().to_string());

        let mut loop_guard = LoopGuard::new();
        loop_guard.set_active(loop_dev.clone());

        if verbose {
            eprintln!("attached loop device: {}", loop_dev.display());
        }

        check_interrupted()?;

        // Small delay for partition devices to appear.
        std::thread::sleep(std::time::Duration::from_millis(500));

        check_interrupted()?;

        // Find the root partition device.
        let part_dev = find_root_partition(&loop_dev, verbose)?;
        if verbose {
            eprintln!("mounting partition: {}", part_dev.display());
        }

        // Create a temporary mount point.
        let mut mount_guard = MountGuard::new();
        let mount_dir = staging_dir.with_file_name(format!(
            ".{}.raw-mount",
            staging_dir.file_name().unwrap().to_string_lossy()
        ));
        fs::create_dir_all(&mount_dir)
            .with_context(|| format!("failed to create mount point {}", mount_dir.display()))?;

        // Mount the partition read-only.
        let status = Command::new("mount")
            .args(["-o", "ro"])
            .arg(&part_dev)
            .arg(&mount_dir)
            .status()
            .context("failed to run mount")?;
        if !status.success() {
            let _ = fs::remove_dir(&mount_dir);
            bail!("mount failed for {}", part_dev.display());
        }
        mount_guard.set_mounted(mount_dir);

        // Copy the tree. Guards handle cleanup on error or interruption.
        let result = do_import(&mount_guard.path, staging_dir, verbose);

        // Explicit cleanup in order (unmount before loop detach).
        mount_guard.unmount();
        loop_guard.detach();

        result
    })();

    // Clean up decompressed temp file.
    if cleanup_decompressed {
        let _ = fs::remove_file(&decompressed);
    }

    result
}
