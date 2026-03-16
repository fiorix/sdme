//! Rootfs export: directory copy, tarball creation, raw disk image.
//!
//! Exports an imported rootfs or a container's merged overlayfs view
//! to a directory, compressed tarball, or bare ext4/btrfs raw disk image.

use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::import::InstallPackages;
use crate::rootfs::DistroFamily;
use crate::{check_interrupted, containers, copy, system_check, systemd, validate_name, State};

/// Options for preparing a raw disk image for VM boot.
pub struct VmOptions {
    pub hostname: String,
    pub nameservers: Vec<String>,
    pub net_ifaces: u32,
    pub root_password: Option<String>,
    pub ssh_key: Option<String>,
    pub install_packages: InstallPackages,
    pub interactive: bool,
}

/// Filesystem type for raw disk image export.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum RawFs {
    #[default]
    Ext4,
    Btrfs,
}

impl std::fmt::Display for RawFs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RawFs::Ext4 => write!(f, "ext4"),
            RawFs::Btrfs => write!(f, "btrfs"),
        }
    }
}

/// Output format for rootfs export.
#[derive(Debug, Clone, PartialEq)]
pub enum ExportFormat {
    /// Plain directory copy.
    Dir,
    /// Uncompressed tar archive.
    Tar,
    /// Gzip-compressed tar archive.
    TarGz,
    /// Bzip2-compressed tar archive.
    TarBz2,
    /// XZ-compressed tar archive.
    TarXz,
    /// Zstandard-compressed tar archive.
    TarZst,
    /// Bare filesystem in a raw disk image (no partition table).
    Raw(RawFs),
}

/// Detect the export format from the output path extension, with an
/// optional override string.
pub fn detect_format(output: &str, format_override: Option<&str>) -> Result<ExportFormat> {
    if let Some(fmt) = format_override {
        return match fmt {
            "dir" => Ok(ExportFormat::Dir),
            "tar" => Ok(ExportFormat::Tar),
            "tar.gz" => Ok(ExportFormat::TarGz),
            "tar.bz2" => Ok(ExportFormat::TarBz2),
            "tar.xz" => Ok(ExportFormat::TarXz),
            "tar.zst" => Ok(ExportFormat::TarZst),
            "raw" => Ok(ExportFormat::Raw(RawFs::Ext4)),
            _ => bail!("unknown format '{fmt}': expected dir, tar, tar.gz, tar.bz2, tar.xz, tar.zst, or raw"),
        };
    }

    let lower = output.to_ascii_lowercase();
    if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") {
        Ok(ExportFormat::TarGz)
    } else if lower.ends_with(".tar.bz2") || lower.ends_with(".tbz2") {
        Ok(ExportFormat::TarBz2)
    } else if lower.ends_with(".tar.xz") || lower.ends_with(".txz") {
        Ok(ExportFormat::TarXz)
    } else if lower.ends_with(".tar.zst") || lower.ends_with(".tzst") {
        Ok(ExportFormat::TarZst)
    } else if lower.ends_with(".tar") {
        Ok(ExportFormat::Tar)
    } else if lower.ends_with(".img") || lower.ends_with(".raw") {
        Ok(ExportFormat::Raw(RawFs::Ext4))
    } else {
        Ok(ExportFormat::Dir)
    }
}

/// Export an imported rootfs to the given output path.
pub fn export_rootfs(
    datadir: &Path,
    name: &str,
    output: &Path,
    format: &ExportFormat,
    size: Option<&str>,
    vm_opts: Option<&VmOptions>,
    verbose: bool,
) -> Result<()> {
    validate_name(name).context("invalid rootfs name")?;
    let rootfs_dir = datadir.join("fs").join(name);
    if !rootfs_dir.is_dir() {
        bail!("rootfs not found: {name}");
    }
    export_from_dir(&rootfs_dir, output, format, size, vm_opts, verbose)
}

/// Export a container's merged rootfs to the given output path.
///
/// If the container is running, exports directly from the live `merged/`
/// directory (with a warning about consistency). If stopped, temporarily
/// mounts overlayfs for the export.
pub fn export_container(
    datadir: &Path,
    name: &str,
    output: &Path,
    format: &ExportFormat,
    size: Option<&str>,
    vm_opts: Option<&VmOptions>,
    verbose: bool,
) -> Result<()> {
    validate_name(name)?;
    containers::ensure_exists(datadir, name)?;

    let container_dir = datadir.join("containers").join(name);
    let merged_dir = container_dir.join("merged");

    let running = systemd::is_active(name)?;
    if running {
        eprintln!(
            "warning: container '{name}' is running; filesystem is live and \
             consistency is not guaranteed"
        );
        export_from_dir(&merged_dir, output, format, size, vm_opts, verbose)
    } else {
        // Read state to find the rootfs.
        let state_file = datadir.join("state").join(name);
        let state = State::read_from(&state_file)?;
        let rootfs_name = state.rootfs();
        let rootfs_dir = containers::resolve_rootfs(
            datadir,
            if rootfs_name.is_empty() {
                None
            } else {
                Some(rootfs_name)
            },
        )?;

        mount_overlay(&rootfs_dir, &container_dir)?;
        let result = export_from_dir(&merged_dir, output, format, size, vm_opts, verbose);
        unmount_overlay(&container_dir);
        result
    }
}

/// Core dispatcher: export from a source directory to the output in the
/// requested format.
fn export_from_dir(
    src: &Path,
    output: &Path,
    format: &ExportFormat,
    size: Option<&str>,
    vm_opts: Option<&VmOptions>,
    verbose: bool,
) -> Result<()> {
    match format {
        ExportFormat::Dir => export_to_dir(src, output, verbose),
        ExportFormat::Tar
        | ExportFormat::TarGz
        | ExportFormat::TarBz2
        | ExportFormat::TarXz
        | ExportFormat::TarZst => export_to_tar(src, output, format, verbose),
        ExportFormat::Raw(fs_type) => export_to_raw(src, output, *fs_type, size, vm_opts, verbose),
    }
}

/// Export by copying the source directory tree to the destination.
fn export_to_dir(src: &Path, dst: &Path, verbose: bool) -> Result<()> {
    if dst.exists() {
        bail!("destination already exists: {}", dst.display());
    }
    fs::create_dir_all(dst).with_context(|| format!("failed to create {}", dst.display()))?;
    copy::copy_metadata(src, dst)?;
    copy::copy_xattrs(src, dst)?;
    copy::copy_tree(src, dst, verbose)
        .with_context(|| format!("failed to copy {} to {}", src.display(), dst.display()))
}

/// Export by creating a tar archive, optionally compressed.
fn export_to_tar(src: &Path, output: &Path, format: &ExportFormat, verbose: bool) -> Result<()> {
    if output.exists() {
        bail!("destination already exists: {}", output.display());
    }
    if verbose {
        eprintln!("creating tarball: {}", output.display());
    }

    match format {
        ExportFormat::Tar => {
            let file = File::create(output)
                .with_context(|| format!("failed to create {}", output.display()))?;
            let mut builder = tar::Builder::new(file);
            builder.follow_symlinks(false);
            append_dir_recursive(&mut builder, src, src, verbose)?;
            builder.finish()?;
        }
        ExportFormat::TarGz => {
            let file = File::create(output)
                .with_context(|| format!("failed to create {}", output.display()))?;
            let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
            let mut builder = tar::Builder::new(encoder);
            builder.follow_symlinks(false);
            append_dir_recursive(&mut builder, src, src, verbose)?;
            let encoder = builder.into_inner()?;
            encoder.finish()?;
        }
        ExportFormat::TarBz2 => {
            let file = File::create(output)
                .with_context(|| format!("failed to create {}", output.display()))?;
            let encoder = bzip2::write::BzEncoder::new(file, bzip2::Compression::default());
            let mut builder = tar::Builder::new(encoder);
            builder.follow_symlinks(false);
            append_dir_recursive(&mut builder, src, src, verbose)?;
            let encoder = builder.into_inner()?;
            encoder.finish()?;
        }
        ExportFormat::TarXz => {
            let file = File::create(output)
                .with_context(|| format!("failed to create {}", output.display()))?;
            let encoder = xz2::write::XzEncoder::new(file, 6);
            let mut builder = tar::Builder::new(encoder);
            builder.follow_symlinks(false);
            append_dir_recursive(&mut builder, src, src, verbose)?;
            let encoder = builder.into_inner()?;
            encoder.finish()?;
        }
        ExportFormat::TarZst => {
            let file = File::create(output)
                .with_context(|| format!("failed to create {}", output.display()))?;
            let encoder = zstd::stream::write::Encoder::new(file, 0)?;
            let mut builder = tar::Builder::new(encoder);
            builder.follow_symlinks(false);
            append_dir_recursive(&mut builder, src, src, verbose)?;
            let encoder = builder.into_inner()?;
            encoder.finish()?;
        }
        _ => unreachable!(),
    }

    Ok(())
}

/// Recursively append directory entries to a tar builder, preserving
/// ownership, permissions, and special file types.
fn append_dir_recursive<W: std::io::Write>(
    builder: &mut tar::Builder<W>,
    root: &Path,
    dir: &Path,
    verbose: bool,
) -> Result<()> {
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
        header.set_metadata_in_mode(&meta, tar::HeaderMode::Deterministic);
        // Restore actual uid/gid (Deterministic mode zeros them).
        header.set_uid(meta_uid(&meta));
        header.set_gid(meta_gid(&meta));

        if meta.is_dir() {
            builder.append_data(&mut header, rel, &[] as &[u8])?;
            append_dir_recursive(builder, root, &path, verbose)?;
        } else if meta.is_symlink() {
            let target = fs::read_link(&path)
                .with_context(|| format!("failed to read symlink {}", path.display()))?;
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            builder.append_link(&mut header, rel, &target)?;
        } else if meta.is_file() {
            let file =
                File::open(&path).with_context(|| format!("failed to open {}", path.display()))?;
            builder.append_data(&mut header, rel, file)?;
        } else {
            // Block/char devices, fifos, sockets — append header only.
            header.set_size(0);
            builder.append_data(&mut header, rel, &[] as &[u8])?;
        }
    }
    Ok(())
}

/// Extract uid from metadata (Unix-specific).
fn meta_uid(meta: &fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    meta.uid() as u64
}

/// Extract gid from metadata (Unix-specific).
fn meta_gid(meta: &fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    meta.gid() as u64
}

/// Export by creating a raw disk image with the specified filesystem.
fn export_to_raw(
    src: &Path,
    output: &Path,
    fs_type: RawFs,
    size: Option<&str>,
    vm_opts: Option<&VmOptions>,
    verbose: bool,
) -> Result<()> {
    if output.exists() {
        bail!("destination already exists: {}", output.display());
    }

    let (mkfs_bin, mkfs_pkg) = match fs_type {
        RawFs::Ext4 => ("mkfs.ext4", "e2fsprogs"),
        RawFs::Btrfs => ("mkfs.btrfs", "btrfs-progs"),
    };
    system_check::check_dependencies(&[(mkfs_bin, mkfs_pkg)], verbose)?;

    // Calculate or parse image size.
    let image_size = match size {
        Some(s) => crate::parse_size(s)?,
        None => {
            let total = dir_size(src)?;
            // At least 256 MiB, otherwise 150% of content for filesystem
            // metadata overhead.
            let min_size = 256 * 1024 * 1024;
            let padded = (total as f64 * 1.5) as u64;
            std::cmp::max(min_size, padded)
        }
    };

    if verbose {
        eprintln!(
            "creating {fs_type} raw image: {} ({} bytes)",
            output.display(),
            image_size
        );
    }

    // Create sparse file.
    let file =
        File::create(output).with_context(|| format!("failed to create {}", output.display()))?;
    file.set_len(image_size)
        .with_context(|| format!("failed to set file size for {}", output.display()))?;
    drop(file);

    // Format the image. For VM exports, force 1K block size on ext4 so that
    // the superblock (at byte 1024) is in its own block and doesn't share a
    // page with sector 0. Cloud-hypervisor blocks sector 0 writes on raw
    // images, which causes a kernel panic when ext4 with 4K blocks tries to
    // write the superblock page that spans bytes 0-4095.
    let (mkfs_args, mkfs_err): (&[&str], &str) = match fs_type {
        RawFs::Ext4 if vm_opts.is_some() => (
            &["-q", "-F", "-b", "1024", "-O", "^orphan_file"] as &[&str],
            "mkfs.ext4 failed",
        ),
        RawFs::Ext4 => (&["-q", "-F"], "mkfs.ext4 failed"),
        RawFs::Btrfs => (&["-q", "-f"], "mkfs.btrfs failed"),
    };
    let status = std::process::Command::new(mkfs_bin)
        .args(mkfs_args)
        .arg(output)
        .status()
        .with_context(|| format!("failed to run {mkfs_bin}"))?;
    if !status.success() {
        let _ = fs::remove_file(output);
        bail!("{mkfs_err}");
    }

    // Mount, copy, unmount.
    let mount_dir = std::env::temp_dir().join(format!("sdme-export-mount-{}", std::process::id()));
    fs::create_dir_all(&mount_dir)
        .with_context(|| format!("failed to create mount point {}", mount_dir.display()))?;

    let mount_status = std::process::Command::new("mount")
        .args(["-o", "loop"])
        .arg(output)
        .arg(&mount_dir)
        .status()
        .context("failed to run mount")?;

    if !mount_status.success() {
        let _ = fs::remove_dir(&mount_dir);
        let _ = fs::remove_file(output);
        bail!("failed to mount raw image");
    }

    // Remove lost+found created by mkfs.ext4 (btrfs doesn't create one).
    if fs_type == RawFs::Ext4 {
        let lost_found = mount_dir.join("lost+found");
        if lost_found.exists() {
            let _ = fs::remove_dir(&lost_found);
        }
    }

    let copy_result = (|| -> Result<()> {
        copy::copy_metadata(src, &mount_dir)?;
        copy::copy_tree(src, &mount_dir, verbose)?;
        if let Some(opts) = vm_opts {
            prep_vm_rootfs(&mount_dir, fs_type, opts, verbose)?;
        }
        Ok(())
    })();

    // Always unmount.
    let _ = std::process::Command::new("umount")
        .arg(&mount_dir)
        .status();
    let _ = fs::remove_dir(&mount_dir);

    if let Err(e) = copy_result {
        let _ = fs::remove_file(output);
        return Err(e).context("failed to copy to raw image");
    }

    // Align to 512-byte sector boundary (benefits all raw exports).
    align_disk_image(output)?;

    Ok(())
}

/// Recursively walk a directory tree summing regular file sizes.
fn dir_size(path: &Path) -> Result<u64> {
    let mut total: u64 = 0;
    let entries = fs::read_dir(path)
        .with_context(|| format!("failed to read directory {}", path.display()))?;
    for entry in entries {
        check_interrupted()?;
        let entry = entry.with_context(|| format!("failed to read entry in {}", path.display()))?;
        let meta = entry
            .metadata()
            .with_context(|| format!("failed to stat {}", entry.path().display()))?;
        if meta.is_dir() {
            total += dir_size(&entry.path())?;
        } else {
            total += meta.len();
        }
    }
    Ok(total)
}

/// Mount overlayfs on a stopped container's `merged/` directory.
fn mount_overlay(rootfs_dir: &Path, container_dir: &Path) -> Result<()> {
    let upper_dir = container_dir.join("upper");
    let work_dir = container_dir.join("work");
    let merged_dir = container_dir.join("merged");

    let mount_opts = format!(
        "lowerdir={},upperdir={},workdir={}",
        rootfs_dir.display(),
        upper_dir.display(),
        work_dir.display()
    );

    let status = std::process::Command::new("mount")
        .args(["-t", "overlay", "overlay", "-o", &mount_opts])
        .arg(&merged_dir)
        .status()
        .context("failed to run mount")?;

    if !status.success() {
        bail!("failed to mount overlayfs for export");
    }
    Ok(())
}

/// Unmount overlayfs from a container's `merged/` directory.
fn unmount_overlay(container_dir: &Path) {
    let merged_dir = container_dir.join("merged");
    let _ = std::process::Command::new("umount")
        .arg(&merged_dir)
        .status();
}

/// Align a raw disk image to a 512-byte sector boundary.
fn align_disk_image(path: &Path) -> Result<()> {
    let size = fs::metadata(path)
        .with_context(|| format!("failed to stat {}", path.display()))?
        .len();
    let remainder = size % 512;
    if remainder != 0 {
        let aligned = size + (512 - remainder);
        fs::OpenOptions::new()
            .write(true)
            .open(path)
            .with_context(|| format!("failed to open {} for alignment", path.display()))?
            .set_len(aligned)
            .with_context(|| format!("failed to align {}", path.display()))?;
    }
    Ok(())
}

/// Ensure /sbin/init exists so the kernel can find systemd as PID 1.
///
/// On merged-usr systems `/sbin` is a symlink to `usr/sbin`, so the actual
/// file is created at `usr/sbin/init` as a relative symlink to the systemd
/// binary.
fn ensure_init_symlink(mount: &Path) -> Result<()> {
    let sbin_init = mount.join("sbin/init");
    if sbin_init.exists() {
        return Ok(());
    }

    // Find the systemd binary.
    let (systemd_path, rel_target) = if mount.join("lib/systemd/systemd").exists() {
        ("lib/systemd/systemd", "../../lib/systemd/systemd")
    } else if mount.join("usr/lib/systemd/systemd").exists() {
        ("usr/lib/systemd/systemd", "../lib/systemd/systemd")
    } else {
        bail!(
            "systemd binary not found in rootfs (checked lib/systemd/systemd \
             and usr/lib/systemd/systemd) — image cannot boot as a VM"
        );
    };

    // Determine where to create the symlink. On merged-usr, /sbin -> usr/sbin,
    // so create usr/sbin/init. Otherwise create sbin/init directly.
    let sbin_meta = mount.join("sbin").symlink_metadata();
    let init_path = if sbin_meta
        .as_ref()
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
    {
        // merged-usr: /sbin -> usr/sbin
        let usr_sbin = mount.join("usr/sbin");
        fs::create_dir_all(&usr_sbin)
            .with_context(|| format!("failed to create {}", usr_sbin.display()))?;
        mount.join("usr/sbin/init")
    } else {
        let sbin = mount.join("sbin");
        fs::create_dir_all(&sbin)
            .with_context(|| format!("failed to create {}", sbin.display()))?;
        mount.join("sbin/init")
    };

    std::os::unix::fs::symlink(rel_target, &init_path).with_context(|| {
        format!(
            "failed to symlink {} -> {}",
            init_path.display(),
            rel_target
        )
    })?;

    eprintln!(
        "created init symlink: {} -> {}",
        init_path.strip_prefix(mount).unwrap_or(&init_path).display(),
        systemd_path,
    );

    Ok(())
}

/// Patch an nspawn-imported rootfs so it can boot as a standalone VM.
///
/// Container rootfs images are imported for systemd-nspawn which provides its
/// own device tree, network, and init discovery. A bare VM kernel needs all of
/// that configured on disk. This function makes the following modifications:
///
/// # Files created or modified
///
/// | What | Path(s) | Why |
/// |------|---------|-----|
/// | udev install | (via chroot) | Container rootfs images lack udev; installed if `--install-packages` allows |
/// | init symlink | `/usr/sbin/init` → `../../lib/systemd/systemd` | Kernel needs `/sbin/init`; nspawn finds systemd directly |
/// | serial-getty template | `/etc/systemd/system/serial-getty@.service` | Copy of distro template with `BindsTo=dev-%i.device` removed (no udev) |
/// | serial-getty enable | `/etc/systemd/system/getty.target.wants/serial-getty@ttyS0.service` | Explicit enable for ttyS0 |
/// | multi-user drop-in | `/etc/systemd/system/multi-user.target.d/wants-getty.conf` | `Wants=serial-getty@ttyS0.service` — container images omit getty.target |
/// | fstab | `/etc/fstab` | `/dev/vda / {ext4,btrfs} defaults 0 1` |
/// | resolved unmask | `/etc/systemd/system/systemd-resolved.service` | Remove mask symlink (nspawn import masks it) |
/// | resolv.conf | `/etc/resolv.conf` | Nameserver entries (VM has no host resolver) |
/// | networkd units | `/etc/systemd/network/20-sdme-en.network` | DHCP on `en*` interfaces; enables `systemd-networkd.service` |
/// | hostname | `/etc/hostname` | VM hostname (defaults to rootfs/container name) |
/// | root password | `/etc/shadow` | Direct hash write (no chpasswd dependency) |
/// | SSH key | `/root/.ssh/authorized_keys` | Optional authorized_keys for root |
///
/// # Known limitations
///
/// - **ext4 block size**: VM exports force 1K block size (`-b 1024`) and
///   disable `orphan_file` (`-O ^orphan_file`) on ext4. Cloud-hypervisor
///   blocks sector 0 writes on auto-detected raw images; with 4K blocks the
///   superblock (at byte 1024) shares a page with sector 0, causing a kernel
///   panic. 1K blocks put the superblock in its own block. The `orphan_file`
///   feature is incompatible with 1K blocks on large filesystems.
///
/// - **Serial console on AlmaLinux / RHEL 10 (systemd 257)**: the serial
///   getty starts and login works, but the interactive console is unreliable
///   (characters lost, partial commands executed). This appears to be a
///   cloud-hypervisor serial (`--serial tty`) interaction issue with the
///   distro's bash/readline configuration. `init=/bin/sh` works fine on the
///   same image. Workaround: use `--serial pty` and connect with
///   `screen /dev/pts/N`, or use SSH instead of the serial console.
///
/// - **No udev**: container-imported rootfs images typically lack
///   `systemd-udevd`. Use `--install-packages=yes` to install udev into the
///   rootfs during export. The serial-getty template is patched to remove the
///   `BindsTo=dev-%i.device` dependency regardless, so the serial console
///   works even without udev.
///
/// - **NixOS**: VM export works with NixOS rootfs built via
///   `sdme fs import --install-packages=yes` from the `nixos/nix` OCI image,
///   but NixOS support is more limited than other distros. The NixOS
///   activation system manages `/etc/systemd/system` as an immutable symlink,
///   so VM prep files written there may be overwritten on first boot.
///
/// # TODO: package these modifications
///
/// All the above are direct file writes into the rootfs. Ideally each concern
/// should be an installable package (e.g. `sdme-vm-serial`, `sdme-vm-network`)
/// built for the distro's package manager so users can:
///
/// - `dnf remove sdme-vm-serial` to revert the serial console changes
/// - inspect what was modified via `rpm -ql` / `dpkg -L`
/// - layer their own overrides on top cleanly
///
/// Similarly, the OCI app setup (`/oci/apps/`, sdme-oci-*.service units, the
/// isolate binary, volume mounts) should be its own package so it can be
/// cleanly removed or inspected inside a running container.
fn prep_vm_rootfs(mount: &Path, fs_type: RawFs, opts: &VmOptions, verbose: bool) -> Result<()> {
    // Install udev first — ChrootGuard copies host resolv.conf for DNS,
    // and cleanup restores the original. The later write_resolv_conf()
    // writes the final VM nameservers.
    install_udev_if_needed(mount, opts, verbose)?;

    ensure_init_symlink(mount)?;

    enable_serial_console(mount)?;
    if verbose {
        eprintln!("enabled serial-getty@ttyS0.service");
    }

    write_vm_fstab(mount, fs_type)?;
    if verbose {
        eprintln!("wrote /etc/fstab");
    }

    unmask_resolved(mount)?;
    if verbose {
        eprintln!("unmasked systemd-resolved");
    }

    write_resolv_conf(mount, &opts.nameservers)?;
    if verbose {
        eprintln!("wrote /etc/resolv.conf");
    }

    if opts.net_ifaces > 0 {
        configure_networkd(mount, opts.net_ifaces)?;
        if verbose {
            eprintln!("configured systemd-networkd with DHCP");
        }
    }

    write_hostname(mount, &opts.hostname)?;
    if verbose {
        eprintln!("wrote /etc/hostname: {}", opts.hostname);
    }

    if let Some(password) = &opts.root_password {
        set_root_password(mount, password)?;
        if verbose {
            if password.is_empty() {
                eprintln!("set passwordless root login");
            } else {
                eprintln!("set root password");
            }
        }
    }

    if let Some(key) = &opts.ssh_key {
        install_ssh_key(mount, key)?;
        if verbose {
            eprintln!("installed SSH authorized key for root");
        }
    }

    Ok(())
}

/// Write /etc/hostname with the given hostname.
fn write_hostname(mount: &Path, hostname: &str) -> Result<()> {
    let path = mount.join("etc/hostname");
    fs::write(&path, format!("{hostname}\n"))
        .with_context(|| format!("failed to write {}", path.display()))
}

/// Check whether udev (systemd-udevd) is present in the rootfs.
fn detect_udev_presence(mount: &Path) -> bool {
    mount.join("usr/lib/systemd/systemd-udevd").exists()
        || mount.join("lib/systemd/systemd-udevd").exists()
        || mount.join("usr/bin/udevd").exists()
}

/// Return the chroot commands to install udev for the given distro family.
fn udev_install_commands(family: &DistroFamily) -> Vec<String> {
    use crate::import::APT_NO_SANDBOX;
    match *family {
        DistroFamily::Debian => vec![format!(
            "apt-get update -qq {APT_NO_SANDBOX} && apt-get install -y {APT_NO_SANDBOX} udev"
        )],
        DistroFamily::Fedora => vec!["dnf install -y systemd-udevd".to_string()],
        DistroFamily::Arch => vec!["pacman -Sy --noconfirm systemd".to_string()],
        DistroFamily::Suse => vec!["zypper --non-interactive install udev".to_string()],
        _ => vec![],
    }
}

/// Install udev into the rootfs if it is missing, respecting the
/// `--install-packages` policy (Auto/Yes/No).
fn install_udev_if_needed(mount: &Path, opts: &VmOptions, verbose: bool) -> Result<()> {
    if detect_udev_presence(mount) {
        if verbose {
            eprintln!("udev already present, skipping install");
        }
        return Ok(());
    }

    match opts.install_packages {
        InstallPackages::No => {
            if verbose {
                eprintln!("udev not found; skipping install (--install-packages=no)");
            }
            return Ok(());
        }
        InstallPackages::Auto => {
            if opts.interactive {
                let proceed = crate::confirm_default_yes(
                    "udev not found in rootfs; install it for VM boot? [Y/n] ",
                )?;
                if !proceed {
                    eprintln!("skipping udev install");
                    return Ok(());
                }
            } else {
                bail!(
                    "udev not found in rootfs and cannot prompt in non-interactive mode; \
                     use --install-packages=yes to install or --install-packages=no to skip"
                );
            }
        }
        InstallPackages::Yes => {}
    }

    let family = crate::rootfs::detect_distro_family(mount);
    let commands = udev_install_commands(&family);
    if commands.is_empty() {
        eprintln!(
            "warning: udev not found but no install commands for distro family {:?}; skipping",
            family
        );
        return Ok(());
    }

    eprintln!("installing udev into rootfs...");
    let mut guard = crate::import::ChrootGuard::setup(mount, verbose)?;
    let result = crate::import::run_chroot_commands(mount, &commands, verbose);
    guard.cleanup();
    result?;
    eprintln!("udev installed successfully");

    Ok(())
}

/// Enable serial console login via serial-getty@ttyS0.service.
///
/// The upstream `serial-getty@.service` template has `BindsTo=dev-%i.device`,
/// which requires udev to tag the device before the getty starts. Rootfs
/// images imported for nspawn use typically lack `systemd-udevd`, so the
/// device unit never activates and boot hangs. We replace the template at
/// `/etc/systemd/system/` (highest priority) with a copy that drops the
/// device dependency, and explicitly enable the ttyS0 instance.
fn enable_serial_console(mount: &Path) -> Result<()> {
    let unit_dir = mount.join("etc/systemd/system");
    fs::create_dir_all(&unit_dir)
        .with_context(|| format!("failed to create {}", unit_dir.display()))?;

    // Copy the distro's serial-getty@ template and strip the BindsTo=dev-%i
    // dependency. Container-imported rootfs images lack udev, so the device
    // unit never activates and boot hangs. Copying preserves the distro's
    // agetty flags, TERM handling, and credential imports (systemd 257+).
    let src_template = mount.join("lib/systemd/system/serial-getty@.service");
    let src_template = if src_template.is_file() {
        src_template
    } else {
        mount.join("usr/lib/systemd/system/serial-getty@.service")
    };
    let dst_template = unit_dir.join("serial-getty@.service");

    if src_template.is_file() {
        let content = fs::read_to_string(&src_template)
            .with_context(|| format!("failed to read {}", src_template.display()))?;
        let patched: String = content
            .lines()
            .filter(|line| {
                // Remove BindsTo=dev-*.device entirely.
                !line.trim().starts_with("BindsTo=dev-")
            })
            .map(|line| {
                // Strip dev-*.device tokens from After= lines, keep the rest.
                if line.trim().starts_with("After=") && line.contains("dev-") {
                    let (key, vals) = line.split_once('=').unwrap();
                    let filtered: Vec<&str> = vals
                        .split_whitespace()
                        .filter(|v| !v.starts_with("dev-"))
                        .collect();
                    if filtered.is_empty() {
                        String::new()
                    } else {
                        format!("{key}={}", filtered.join(" "))
                    }
                } else {
                    line.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(&dst_template, patched.as_bytes())
            .with_context(|| format!("failed to write {}", dst_template.display()))?;
    } else {
        // Fallback: write a minimal template if the distro doesn't ship one.
        fs::write(
            &dst_template,
            "\
[Unit]
Description=Serial Getty on %I
After=systemd-user-sessions.service plymouth-quit-wait.service getty-pre.target
Before=getty.target
IgnoreOnIsolate=yes

[Service]
ExecStart=-/sbin/agetty -o '-- \\\\u' --noreset --noclear --keep-baud 115200,57600,38400,9600 - $TERM
Type=idle
Restart=always
UtmpIdentifier=%I
StandardInput=tty
StandardOutput=tty
TTYPath=/dev/%I
TTYReset=yes
TTYVHangup=yes
IgnoreSIGPIPE=no
SendSIGHUP=yes

[Install]
WantedBy=getty.target
",
        )
        .with_context(|| format!("failed to write {}", dst_template.display()))?;
    }

    // Explicitly enable serial-getty@ttyS0 so it starts even if the getty
    // generator is absent or non-functional.
    let wants_dir = unit_dir.join("getty.target.wants");
    fs::create_dir_all(&wants_dir)
        .with_context(|| format!("failed to create {}", wants_dir.display()))?;

    let link = wants_dir.join("serial-getty@ttyS0.service");
    if !link.symlink_metadata().is_ok() {
        std::os::unix::fs::symlink(
            "/etc/systemd/system/serial-getty@.service",
            &link,
        )
        .with_context(|| format!("failed to create symlink {}", link.display()))?;
    }

    // Ensure serial-getty@ttyS0 is pulled in by multi-user.target. Container
    // images often omit getty.target from multi-user.target.wants/ since
    // containers don't need login gettys. Going through getty.target via
    // drop-ins doesn't work reliably on all systemd versions (e.g. systemd 257
    // on AlmaLinux 10 ignores drop-in Wants=getty.target). Directly wanting
    // the serial-getty instance from multi-user.target bypasses that entirely.
    let dropin_dir = unit_dir.join("multi-user.target.d");
    fs::create_dir_all(&dropin_dir)
        .with_context(|| format!("failed to create {}", dropin_dir.display()))?;

    let dropin = dropin_dir.join("wants-getty.conf");
    fs::write(
        &dropin,
        "[Unit]\nWants=serial-getty@ttyS0.service\n",
    )
    .with_context(|| format!("failed to write {}", dropin.display()))?;

    Ok(())
}

/// Write /etc/fstab with the root device entry.
fn write_vm_fstab(mount: &Path, fs_type: RawFs) -> Result<()> {
    let fstab = mount.join("etc/fstab");
    let content = format!("/dev/vda / {fs_type} defaults 0 1\n");
    fs::write(&fstab, content)
        .with_context(|| format!("failed to write {}", fstab.display()))
}

/// Unmask systemd-resolved if it is masked (symlink to /dev/null).
fn unmask_resolved(mount: &Path) -> Result<()> {
    let resolved = mount.join("etc/systemd/system/systemd-resolved.service");
    if resolved.exists() || resolved.symlink_metadata().is_ok() {
        // Check if it's a symlink to /dev/null (masked).
        if let Ok(target) = fs::read_link(&resolved) {
            if target.to_str() == Some("/dev/null") {
                fs::remove_file(&resolved).with_context(|| {
                    format!("failed to unmask systemd-resolved at {}", resolved.display())
                })?;
            }
        }
    }
    Ok(())
}

/// Write /etc/resolv.conf with the given nameservers.
fn write_resolv_conf(mount: &Path, nameservers: &[String]) -> Result<()> {
    let resolv = mount.join("etc/resolv.conf");
    // Remove if it's a symlink (e.g. to ../run/systemd/resolve/stub-resolv.conf).
    if resolv.symlink_metadata().is_ok() {
        let _ = fs::remove_file(&resolv);
    }
    let content: String = nameservers
        .iter()
        .map(|ns| format!("nameserver {ns}\n"))
        .collect();
    fs::write(&resolv, content)
        .with_context(|| format!("failed to write {}", resolv.display()))
}

/// Configure systemd-networkd for DHCP on network interfaces.
fn configure_networkd(mount: &Path, net_ifaces: u32) -> Result<()> {
    let network_dir = mount.join("etc/systemd/network");
    fs::create_dir_all(&network_dir)
        .with_context(|| format!("failed to create {}", network_dir.display()))?;

    let match_names = if net_ifaces == 1 {
        "en* eth*".to_string()
    } else {
        // For multiple interfaces, match all common names.
        "en* eth*".to_string()
    };

    let content = format!(
        "[Match]\nName={match_names}\n\n[Network]\nDHCP=yes\n"
    );
    let network_file = network_dir.join("80-vm-dhcp.network");
    fs::write(&network_file, content)
        .with_context(|| format!("failed to write {}", network_file.display()))?;

    // Enable systemd-networkd.service via symlink.
    let system_dir = mount.join("etc/systemd/system");
    fs::create_dir_all(&system_dir)?;

    let wants_dir = system_dir.join("multi-user.target.wants");
    fs::create_dir_all(&wants_dir)?;

    let link = wants_dir.join("systemd-networkd.service");
    if !link.exists() {
        std::os::unix::fs::symlink(
            "/lib/systemd/system/systemd-networkd.service",
            &link,
        )
        .with_context(|| format!("failed to enable systemd-networkd at {}", link.display()))?;
    }

    Ok(())
}

/// Set the root password in /etc/shadow.
fn set_root_password(mount: &Path, password: &str) -> Result<()> {
    let shadow = mount.join("etc/shadow");
    let content = fs::read_to_string(&shadow)
        .with_context(|| format!("failed to read {}", shadow.display()))?;

    let hash = if password.is_empty() {
        String::new()
    } else {
        sha512_crypt(password)?
    };

    let mut found = false;
    let new_content: String = content
        .lines()
        .map(|line| {
            if line.starts_with("root:") {
                let parts: Vec<&str> = line.splitn(3, ':').collect();
                found = true;
                if parts.len() >= 3 {
                    format!("root:{hash}:{}", parts[2])
                } else {
                    format!("root:{hash}:")
                }
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    if !found {
        bail!("root entry not found in {}", shadow.display());
    }

    // Preserve trailing newline.
    let new_content = if content.ends_with('\n') && !new_content.ends_with('\n') {
        new_content + "\n"
    } else {
        new_content
    };

    fs::write(&shadow, new_content)
        .with_context(|| format!("failed to write {}", shadow.display()))
}

/// Install an SSH public key for root.
fn install_ssh_key(mount: &Path, key: &str) -> Result<()> {
    let ssh_dir = mount.join("root/.ssh");
    fs::create_dir_all(&ssh_dir)
        .with_context(|| format!("failed to create {}", ssh_dir.display()))?;
    fs::set_permissions(&ssh_dir, fs::Permissions::from_mode(0o700))?;

    let auth_keys = ssh_dir.join("authorized_keys");
    let content = if key.ends_with('\n') {
        key.to_string()
    } else {
        format!("{key}\n")
    };
    fs::write(&auth_keys, content)
        .with_context(|| format!("failed to write {}", auth_keys.display()))?;
    fs::set_permissions(&auth_keys, fs::Permissions::from_mode(0o600))?;

    Ok(())
}

// --- SHA-512 crypt implementation ($6$) ---

/// Compute a SHA-512 crypt hash ($6$salt$hash) for the given password.
fn sha512_crypt(password: &str) -> Result<String> {
    let mut salt_bytes = [0u8; 16];
    let mut f = File::open("/dev/urandom").context("failed to open /dev/urandom")?;
    f.read_exact(&mut salt_bytes)?;

    // Encode salt using the crypt base64 alphabet.
    let salt: String = salt_bytes
        .iter()
        .map(|b| CRYPT_B64_CHARS[(*b as usize) % CRYPT_B64_CHARS.len()] as char)
        .collect();

    let hash = sha512_crypt_hash(password.as_bytes(), salt.as_bytes(), 5000);
    Ok(format!("$6${salt}${hash}"))
}

const CRYPT_B64_CHARS: &[u8] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// Core SHA-512 crypt algorithm (Drepper specification, 5000 default rounds).
fn sha512_crypt_hash(password: &[u8], salt: &[u8], rounds: u32) -> String {
    use sha2::{Digest, Sha512};

    // Compute digest B: sha512(password + salt + password)
    let mut ctx_b = Sha512::new();
    ctx_b.update(password);
    ctx_b.update(salt);
    ctx_b.update(password);
    let digest_b = ctx_b.finalize();

    // Compute digest A: sha512(password + salt + <bytes from B based on password length>)
    let mut ctx_a = Sha512::new();
    ctx_a.update(password);
    ctx_a.update(salt);

    // Add bytes from digest B, password.len() bytes total.
    let mut n = password.len();
    while n >= 64 {
        ctx_a.update(&digest_b[..]);
        n -= 64;
    }
    if n > 0 {
        ctx_a.update(&digest_b[..n]);
    }

    // Process password length bits.
    let mut length = password.len();
    while length > 0 {
        if length & 1 != 0 {
            ctx_a.update(&digest_b[..]);
        } else {
            ctx_a.update(password);
        }
        length >>= 1;
    }

    let mut digest_a = ctx_a.finalize();

    // Compute digest P: sha512(password repeated password.len() times)
    let mut ctx_p = Sha512::new();
    for _ in 0..password.len() {
        ctx_p.update(password);
    }
    let digest_p = ctx_p.finalize();

    // Produce P-string: password.len() bytes from digest_p.
    let mut p_bytes = Vec::with_capacity(password.len());
    let mut remaining = password.len();
    while remaining >= 64 {
        p_bytes.extend_from_slice(&digest_p[..]);
        remaining -= 64;
    }
    if remaining > 0 {
        p_bytes.extend_from_slice(&digest_p[..remaining]);
    }

    // Compute digest S: sha512(salt repeated (16 + digest_a[0]) times)
    let mut ctx_s = Sha512::new();
    let repeat_count = 16 + (digest_a[0] as usize);
    for _ in 0..repeat_count {
        ctx_s.update(salt);
    }
    let digest_s = ctx_s.finalize();

    // Produce S-string: salt.len() bytes from digest_s.
    let mut s_bytes = Vec::with_capacity(salt.len());
    let mut remaining = salt.len();
    while remaining >= 64 {
        s_bytes.extend_from_slice(&digest_s[..]);
        remaining -= 64;
    }
    if remaining > 0 {
        s_bytes.extend_from_slice(&digest_s[..remaining]);
    }

    // Rounds.
    for i in 0..rounds {
        let mut ctx = Sha512::new();
        if i & 1 != 0 {
            ctx.update(&p_bytes);
        } else {
            ctx.update(&digest_a[..]);
        }
        if i % 3 != 0 {
            ctx.update(&s_bytes);
        }
        if i % 7 != 0 {
            ctx.update(&p_bytes);
        }
        if i & 1 != 0 {
            ctx.update(&digest_a[..]);
        } else {
            ctx.update(&p_bytes);
        }
        digest_a = ctx.finalize();
    }

    // Encode the final digest with crypt-specific base64 and SHA-512 byte reordering.
    crypt_b64_encode(&digest_a)
}

/// Encode 64 bytes of SHA-512 digest using crypt-specific base64 with
/// the SHA-512 byte reordering from the Drepper specification.
fn crypt_b64_encode(hash: &[u8]) -> String {
    let mut out = String::with_capacity(86);

    // SHA-512 crypt byte reordering: groups of 3 bytes (with specific indices).
    let groups: [(usize, usize, usize); 21] = [
        (0, 21, 42),
        (22, 43, 1),
        (44, 2, 23),
        (3, 24, 45),
        (25, 46, 4),
        (47, 5, 26),
        (6, 27, 48),
        (28, 49, 7),
        (50, 8, 29),
        (9, 30, 51),
        (31, 52, 10),
        (53, 11, 32),
        (12, 33, 54),
        (34, 55, 13),
        (56, 14, 35),
        (15, 36, 57),
        (37, 58, 16),
        (59, 17, 38),
        (18, 39, 60),
        (40, 61, 19),
        (62, 20, 41),
    ];

    for (a, b, c) in groups {
        let v = ((hash[a] as u32) << 16) | ((hash[b] as u32) << 8) | (hash[c] as u32);
        for i in 0..4 {
            out.push(CRYPT_B64_CHARS[((v >> (i * 6)) & 0x3f) as usize] as char);
        }
    }

    // Final byte (index 63), only 2 characters.
    let v = hash[63] as u32;
    for i in 0..2 {
        out.push(CRYPT_B64_CHARS[((v >> (i * 6)) & 0x3f) as usize] as char);
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    /// Acquire the interrupt lock and clear the INTERRUPTED flag.
    /// Returns a guard that holds the lock, preventing other tests from
    /// setting INTERRUPTED while our test is running.
    fn lock_and_clear_interrupted() -> std::sync::MutexGuard<'static, ()> {
        let guard = crate::import::tests::INTERRUPT_LOCK.lock().unwrap();
        crate::INTERRUPTED.store(false, Ordering::Relaxed);
        guard
    }

    // --- detect_format tests ---

    #[test]
    fn test_detect_format_from_extension() {
        assert_eq!(detect_format("foo.tar", None).unwrap(), ExportFormat::Tar);
        assert_eq!(
            detect_format("foo.tar.gz", None).unwrap(),
            ExportFormat::TarGz
        );
        assert_eq!(detect_format("foo.tgz", None).unwrap(), ExportFormat::TarGz);
        assert_eq!(
            detect_format("foo.tar.bz2", None).unwrap(),
            ExportFormat::TarBz2
        );
        assert_eq!(
            detect_format("foo.tbz2", None).unwrap(),
            ExportFormat::TarBz2
        );
        assert_eq!(
            detect_format("foo.tar.xz", None).unwrap(),
            ExportFormat::TarXz
        );
        assert_eq!(detect_format("foo.txz", None).unwrap(), ExportFormat::TarXz);
        assert_eq!(
            detect_format("foo.tar.zst", None).unwrap(),
            ExportFormat::TarZst
        );
        assert_eq!(
            detect_format("foo.tzst", None).unwrap(),
            ExportFormat::TarZst
        );
        assert_eq!(
            detect_format("foo.img", None).unwrap(),
            ExportFormat::Raw(RawFs::Ext4)
        );
        assert_eq!(
            detect_format("foo.raw", None).unwrap(),
            ExportFormat::Raw(RawFs::Ext4)
        );
        assert_eq!(detect_format("foo", None).unwrap(), ExportFormat::Dir);
        assert_eq!(
            detect_format("/tmp/mydir", None).unwrap(),
            ExportFormat::Dir
        );
    }

    #[test]
    fn test_detect_format_override() {
        assert_eq!(
            detect_format("foo.tar", Some("dir")).unwrap(),
            ExportFormat::Dir
        );
        assert_eq!(
            detect_format("foo", Some("tar.gz")).unwrap(),
            ExportFormat::TarGz
        );
        assert_eq!(
            detect_format("foo", Some("raw")).unwrap(),
            ExportFormat::Raw(RawFs::Ext4)
        );
    }

    #[test]
    fn test_detect_format_unknown_override() {
        assert!(detect_format("foo", Some("zip")).is_err());
    }

    #[test]
    fn test_detect_format_case_insensitive() {
        assert_eq!(
            detect_format("FOO.TAR.GZ", None).unwrap(),
            ExportFormat::TarGz
        );
        assert_eq!(
            detect_format("FOO.IMG", None).unwrap(),
            ExportFormat::Raw(RawFs::Ext4)
        );
    }

    // --- dir_size tests ---

    #[test]
    fn test_dir_size_empty() {
        let tmp = crate::testutil::TempDataDir::new("export-dirsize-empty");
        assert_eq!(dir_size(tmp.path()).unwrap(), 0);
    }

    #[test]
    fn test_dir_size_with_files() {
        let _guard = lock_and_clear_interrupted();
        let tmp = crate::testutil::TempDataDir::new("export-dirsize-files");
        fs::write(tmp.path().join("a"), "hello").unwrap(); // 5 bytes
        fs::create_dir(tmp.path().join("sub")).unwrap();
        fs::write(tmp.path().join("sub/b"), "world!").unwrap(); // 6 bytes
        assert_eq!(dir_size(tmp.path()).unwrap(), 11);
    }

    // --- export_to_dir tests ---

    #[test]
    fn test_export_to_dir_creates_copy() {
        let _guard = lock_and_clear_interrupted();
        let src = crate::testutil::TempDataDir::new("export-dir-src");
        fs::write(src.path().join("hello.txt"), "hi").unwrap();
        fs::create_dir(src.path().join("sub")).unwrap();
        fs::write(src.path().join("sub/nested.txt"), "nested").unwrap();

        let dst_parent = crate::testutil::TempDataDir::new("export-dir-dst");
        let dst = dst_parent.path().join("output");

        export_to_dir(src.path(), &dst, false).unwrap();

        assert!(dst.join("hello.txt").is_file());
        assert_eq!(fs::read_to_string(dst.join("hello.txt")).unwrap(), "hi");
        assert!(dst.join("sub/nested.txt").is_file());
    }

    #[test]
    fn test_export_to_dir_rejects_existing() {
        let src = crate::testutil::TempDataDir::new("export-dir-exist-src");
        let dst = crate::testutil::TempDataDir::new("export-dir-exist-dst");

        let err = export_to_dir(src.path(), dst.path(), false).unwrap_err();
        assert!(err.to_string().contains("already exists"), "got: {err}");
    }

    // --- export_to_tar tests ---

    #[test]
    fn test_export_to_tar_uncompressed() {
        let _guard = lock_and_clear_interrupted();
        let src = crate::testutil::TempDataDir::new("export-tar-src");
        fs::write(src.path().join("file.txt"), "content").unwrap();

        let dst = crate::testutil::TempDataDir::new("export-tar-dst");
        let tarball = dst.path().join("out.tar");

        export_to_tar(src.path(), &tarball, &ExportFormat::Tar, false).unwrap();
        assert!(tarball.exists());
        assert!(fs::metadata(&tarball).unwrap().len() > 0);

        // Verify contents by reading the tarball.
        let file = File::open(&tarball).unwrap();
        let mut archive = tar::Archive::new(file);
        let entries: Vec<String> = archive
            .entries()
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path().unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(entries.contains(&"file.txt".to_string()));
    }

    #[test]
    fn test_export_to_tar_gz() {
        let _guard = lock_and_clear_interrupted();
        let src = crate::testutil::TempDataDir::new("export-targz-src");
        fs::write(src.path().join("data"), "compressed").unwrap();

        let dst = crate::testutil::TempDataDir::new("export-targz-dst");
        let tarball = dst.path().join("out.tar.gz");

        export_to_tar(src.path(), &tarball, &ExportFormat::TarGz, false).unwrap();
        assert!(tarball.exists());

        // Verify by decompressing and reading.
        let file = File::open(&tarball).unwrap();
        let decoder = flate2::read::GzDecoder::new(file);
        let mut archive = tar::Archive::new(decoder);
        let entries: Vec<String> = archive
            .entries()
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path().unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(entries.contains(&"data".to_string()));
    }

    #[test]
    fn test_export_to_tar_rejects_existing() {
        let src = crate::testutil::TempDataDir::new("export-tar-exist-src");
        let dst = crate::testutil::TempDataDir::new("export-tar-exist-dst");
        let tarball = dst.path().join("out.tar");
        fs::write(&tarball, "existing").unwrap();

        let err = export_to_tar(src.path(), &tarball, &ExportFormat::Tar, false).unwrap_err();
        assert!(err.to_string().contains("already exists"), "got: {err}");
    }

    // --- export_rootfs tests ---

    #[test]
    fn test_export_rootfs_not_found() {
        let tmp = crate::testutil::TempDataDir::new("export-rootfs-notfound");
        fs::create_dir_all(tmp.path().join("fs")).unwrap();
        let output = tmp.path().join("out");

        let err = export_rootfs(
            tmp.path(),
            "nonexistent",
            &output,
            &ExportFormat::Dir,
            None,
            None,
            false,
        )
        .unwrap_err();
        assert!(err.to_string().contains("rootfs not found"), "got: {err}");
    }

    #[test]
    fn test_export_rootfs_invalid_name() {
        let tmp = crate::testutil::TempDataDir::new("export-rootfs-badname");
        let output = tmp.path().join("out");

        let err = export_rootfs(
            tmp.path(),
            "../escape",
            &output,
            &ExportFormat::Dir,
            None,
            None,
            false,
        )
        .unwrap_err();
        assert!(err.to_string().contains("name"), "got: {err}");
    }

    #[test]
    fn test_export_rootfs_to_dir() {
        let _guard = lock_and_clear_interrupted();
        let tmp = crate::testutil::TempDataDir::new("export-rootfs-dir");
        let rootfs_dir = tmp.path().join("fs/myfs");
        fs::create_dir_all(&rootfs_dir).unwrap();
        fs::write(rootfs_dir.join("hello"), "world").unwrap();

        let output = tmp.path().join("exported");
        export_rootfs(
            tmp.path(),
            "myfs",
            &output,
            &ExportFormat::Dir,
            None,
            None,
            false,
        )
        .unwrap();

        assert!(output.join("hello").is_file());
        assert_eq!(fs::read_to_string(output.join("hello")).unwrap(), "world");
    }

    // --- write_hostname tests ---

    #[test]
    fn test_write_hostname() {
        let tmp = crate::testutil::TempDataDir::new("export-vm-hostname");
        fs::create_dir_all(tmp.path().join("etc")).unwrap();

        write_hostname(tmp.path(), "myvm").unwrap();

        let content = fs::read_to_string(tmp.path().join("etc/hostname")).unwrap();
        assert_eq!(content, "myvm\n");
    }

    // --- detect_udev_presence tests ---

    #[test]
    fn test_detect_udev_presence_found() {
        let tmp = crate::testutil::TempDataDir::new("export-vm-udev-found");
        fs::create_dir_all(tmp.path().join("usr/lib/systemd")).unwrap();
        fs::write(tmp.path().join("usr/lib/systemd/systemd-udevd"), "fake").unwrap();

        assert!(detect_udev_presence(tmp.path()));
    }

    #[test]
    fn test_detect_udev_presence_not_found() {
        let tmp = crate::testutil::TempDataDir::new("export-vm-udev-missing");
        assert!(!detect_udev_presence(tmp.path()));
    }

    // --- udev_install_commands tests ---

    #[test]
    fn test_udev_install_commands_per_distro() {
        use crate::rootfs::DistroFamily;

        let cmds = udev_install_commands(&DistroFamily::Debian);
        assert_eq!(cmds.len(), 1);
        assert!(cmds[0].contains("apt-get"), "got: {}", cmds[0]);
        assert!(cmds[0].contains("udev"), "got: {}", cmds[0]);

        let cmds = udev_install_commands(&DistroFamily::Fedora);
        assert_eq!(cmds.len(), 1);
        assert!(cmds[0].contains("dnf"), "got: {}", cmds[0]);
        assert!(cmds[0].contains("systemd-udevd"), "got: {}", cmds[0]);

        let cmds = udev_install_commands(&DistroFamily::Arch);
        assert_eq!(cmds.len(), 1);
        assert!(cmds[0].contains("pacman"), "got: {}", cmds[0]);

        let cmds = udev_install_commands(&DistroFamily::Suse);
        assert_eq!(cmds.len(), 1);
        assert!(cmds[0].contains("zypper"), "got: {}", cmds[0]);

        assert!(udev_install_commands(&DistroFamily::NixOS).is_empty());
        assert!(udev_install_commands(&DistroFamily::Unknown).is_empty());
    }

    // --- sha512_crypt tests ---

    #[test]
    fn test_sha512_crypt_format() {
        let result = sha512_crypt("test").unwrap();
        assert!(result.starts_with("$6$"), "expected $6$ prefix, got: {result}");
        let parts: Vec<&str> = result.split('$').collect();
        // parts: ["", "6", salt, hash]
        assert_eq!(parts.len(), 4, "expected 4 parts, got: {parts:?}");
        assert_eq!(parts[1], "6");
        assert_eq!(parts[2].len(), 16, "salt should be 16 chars");
        assert_eq!(parts[3].len(), 86, "hash should be 86 chars");
    }

    #[test]
    fn test_sha512_crypt_known_vector() {
        // Known test vector from the Drepper spec.
        let hash = sha512_crypt_hash(b"Hello world!", b"saltstring", 5000);
        let expected = "svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJu\
                        esI68u4OTLiBFdcbYEdFCoEOfaS35inz1";
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_sha512_crypt_known_vector_rounds() {
        // Known vector from the Drepper spec with 10000 rounds.
        // Salt truncated to 16 chars: "saltstringsaltst".
        let hash = sha512_crypt_hash(b"Hello world!", b"saltstringsaltst", 10000);
        let expected = "OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp\
                        8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v.";
        assert_eq!(hash, expected);
    }

    // --- align_disk_image tests ---

    #[test]
    fn test_align_disk_image_not_aligned() {
        let tmp = crate::testutil::TempDataDir::new("export-align-unaligned");
        let img = tmp.path().join("test.raw");
        // Create a file with non-aligned size (1000 bytes).
        let file = File::create(&img).unwrap();
        file.set_len(1000).unwrap();
        drop(file);

        align_disk_image(&img).unwrap();
        let size = fs::metadata(&img).unwrap().len();
        assert_eq!(size, 1024); // Next 512-byte boundary.
        assert_eq!(size % 512, 0);
    }

    #[test]
    fn test_align_disk_image_already_aligned() {
        let tmp = crate::testutil::TempDataDir::new("export-align-aligned");
        let img = tmp.path().join("test.raw");
        let file = File::create(&img).unwrap();
        file.set_len(2048).unwrap();
        drop(file);

        align_disk_image(&img).unwrap();
        let size = fs::metadata(&img).unwrap().len();
        assert_eq!(size, 2048); // Unchanged.
    }

    // --- enable_serial_console tests ---

    #[test]
    fn test_enable_serial_console_copies_distro_template() {
        let tmp = crate::testutil::TempDataDir::new("export-vm-serial-copy");

        // Simulate a distro template with BindsTo=dev-%i.device.
        let src_dir = tmp.path().join("usr/lib/systemd/system");
        fs::create_dir_all(&src_dir).unwrap();
        fs::write(
            src_dir.join("serial-getty@.service"),
            "\
[Unit]
Description=Serial Getty on %I
BindsTo=dev-%i.device
After=dev-%i.device systemd-user-sessions.service
Before=getty.target

[Service]
ExecStart=-/sbin/agetty -o '-- \\u' --noreset --noclear --keep-baud 115200 - $TERM
Type=idle
Restart=always
TTYPath=/dev/%I

[Install]
WantedBy=getty.target
",
        )
        .unwrap();

        enable_serial_console(tmp.path()).unwrap();

        // Patched template should exist without BindsTo or After=dev-.
        let template = tmp
            .path()
            .join("etc/systemd/system/serial-getty@.service");
        assert!(template.is_file());
        let content = fs::read_to_string(&template).unwrap();
        assert!(content.contains("TTYPath=/dev/%I"), "got: {content}");
        assert!(!content.contains("BindsTo"), "got: {content}");
        assert!(!content.contains("After=dev-"), "got: {content}");
        // The rest of the After= line should be preserved.
        assert!(
            content.contains("After="),
            "non-device After= lines should be kept: {content}"
        );

        // ttyS0 instance should be explicitly enabled.
        let link = tmp
            .path()
            .join("etc/systemd/system/getty.target.wants/serial-getty@ttyS0.service");
        assert!(link.symlink_metadata().unwrap().file_type().is_symlink());

        // multi-user.target drop-in should pull in serial-getty@ttyS0 directly.
        let dropin = tmp
            .path()
            .join("etc/systemd/system/multi-user.target.d/wants-getty.conf");
        assert!(dropin.is_file());
        let content = fs::read_to_string(&dropin).unwrap();
        assert!(
            content.contains("Wants=serial-getty@ttyS0.service"),
            "got: {content}"
        );
    }

    #[test]
    fn test_enable_serial_console_fallback_template() {
        let tmp = crate::testutil::TempDataDir::new("export-vm-serial-fallback");

        // No distro template — should write the fallback.
        enable_serial_console(tmp.path()).unwrap();

        let template = tmp
            .path()
            .join("etc/systemd/system/serial-getty@.service");
        assert!(template.is_file());
        let content = fs::read_to_string(&template).unwrap();
        assert!(content.contains("TTYPath=/dev/%I"), "got: {content}");
        assert!(!content.contains("BindsTo"), "got: {content}");
    }

    // --- ensure_init_symlink tests ---

    #[test]
    fn test_ensure_init_symlink_creates_missing() {
        let tmp = crate::testutil::TempDataDir::new("export-vm-init-create");
        // Set up merged-usr layout: /sbin -> usr/sbin, /lib/systemd/systemd exists.
        let root = tmp.path();
        fs::create_dir_all(root.join("usr/sbin")).unwrap();
        std::os::unix::fs::symlink("usr/sbin", root.join("sbin")).unwrap();
        fs::create_dir_all(root.join("lib/systemd")).unwrap();
        fs::write(root.join("lib/systemd/systemd"), "fake-systemd").unwrap();

        ensure_init_symlink(root).unwrap();

        // The symlink should be at usr/sbin/init (since sbin -> usr/sbin).
        let init = root.join("usr/sbin/init");
        assert!(init.symlink_metadata().unwrap().file_type().is_symlink());
        let target = fs::read_link(&init).unwrap();
        assert_eq!(target.to_str().unwrap(), "../../lib/systemd/systemd");
        // Following the chain: sbin/init -> usr/sbin/init -> ../../lib/systemd/systemd
        assert!(root.join("sbin/init").exists());
    }

    #[test]
    fn test_ensure_init_symlink_already_exists() {
        let tmp = crate::testutil::TempDataDir::new("export-vm-init-exists");
        let root = tmp.path();
        fs::create_dir_all(root.join("usr/sbin")).unwrap();
        std::os::unix::fs::symlink("usr/sbin", root.join("sbin")).unwrap();
        fs::create_dir_all(root.join("lib/systemd")).unwrap();
        fs::write(root.join("lib/systemd/systemd"), "fake-systemd").unwrap();
        // Pre-create /usr/sbin/init.
        fs::write(root.join("usr/sbin/init"), "existing-init").unwrap();

        ensure_init_symlink(root).unwrap();

        // Should not be overwritten — still a regular file with original content.
        assert!(root.join("usr/sbin/init").is_file());
        assert_eq!(
            fs::read_to_string(root.join("usr/sbin/init")).unwrap(),
            "existing-init"
        );
    }

    #[test]
    fn test_ensure_init_symlink_usr_lib_fallback() {
        let tmp = crate::testutil::TempDataDir::new("export-vm-init-usrlib");
        let root = tmp.path();
        fs::create_dir_all(root.join("sbin")).unwrap();
        // systemd only in /usr/lib/systemd/systemd (no /lib/systemd/systemd).
        fs::create_dir_all(root.join("usr/lib/systemd")).unwrap();
        fs::write(root.join("usr/lib/systemd/systemd"), "fake-systemd").unwrap();

        ensure_init_symlink(root).unwrap();

        let init = root.join("sbin/init");
        assert!(init.symlink_metadata().unwrap().file_type().is_symlink());
        let target = fs::read_link(&init).unwrap();
        assert_eq!(target.to_str().unwrap(), "../lib/systemd/systemd");
    }

    #[test]
    fn test_ensure_init_symlink_no_systemd() {
        let tmp = crate::testutil::TempDataDir::new("export-vm-init-nosystemd");
        let root = tmp.path();
        fs::create_dir_all(root.join("sbin")).unwrap();

        let err = ensure_init_symlink(root).unwrap_err();
        assert!(
            err.to_string().contains("systemd binary not found"),
            "got: {err}"
        );
    }

    // --- write_vm_fstab tests ---

    #[test]
    fn test_write_vm_fstab_ext4() {
        let tmp = crate::testutil::TempDataDir::new("export-vm-fstab-ext4");
        fs::create_dir_all(tmp.path().join("etc")).unwrap();

        write_vm_fstab(tmp.path(), RawFs::Ext4).unwrap();

        let content = fs::read_to_string(tmp.path().join("etc/fstab")).unwrap();
        assert_eq!(content, "/dev/vda / ext4 defaults 0 1\n");
    }

    #[test]
    fn test_write_vm_fstab_btrfs() {
        let tmp = crate::testutil::TempDataDir::new("export-vm-fstab-btrfs");
        fs::create_dir_all(tmp.path().join("etc")).unwrap();

        write_vm_fstab(tmp.path(), RawFs::Btrfs).unwrap();

        let content = fs::read_to_string(tmp.path().join("etc/fstab")).unwrap();
        assert_eq!(content, "/dev/vda / btrfs defaults 0 1\n");
    }

    // --- unmask_resolved tests ---

    #[test]
    fn test_unmask_resolved_masked() {
        let tmp = crate::testutil::TempDataDir::new("export-vm-unmask-resolved");
        let unit_dir = tmp.path().join("etc/systemd/system");
        fs::create_dir_all(&unit_dir).unwrap();
        let resolved = unit_dir.join("systemd-resolved.service");
        std::os::unix::fs::symlink("/dev/null", &resolved).unwrap();

        unmask_resolved(tmp.path()).unwrap();
        assert!(!resolved.exists());
        assert!(resolved.symlink_metadata().is_err());
    }

    #[test]
    fn test_unmask_resolved_not_masked() {
        let tmp = crate::testutil::TempDataDir::new("export-vm-unmask-noop");
        let unit_dir = tmp.path().join("etc/systemd/system");
        fs::create_dir_all(&unit_dir).unwrap();
        // No symlink present — should be a no-op.
        unmask_resolved(tmp.path()).unwrap();
    }

    #[test]
    fn test_unmask_resolved_not_devnull() {
        let tmp = crate::testutil::TempDataDir::new("export-vm-unmask-other");
        let unit_dir = tmp.path().join("etc/systemd/system");
        fs::create_dir_all(&unit_dir).unwrap();
        let resolved = unit_dir.join("systemd-resolved.service");
        // Symlink to something other than /dev/null — should NOT be removed.
        std::os::unix::fs::symlink("/lib/systemd/system/systemd-resolved.service", &resolved)
            .unwrap();

        unmask_resolved(tmp.path()).unwrap();
        assert!(resolved.symlink_metadata().is_ok());
    }

    // --- write_resolv_conf tests ---

    #[test]
    fn test_write_resolv_conf() {
        let tmp = crate::testutil::TempDataDir::new("export-vm-resolv");
        fs::create_dir_all(tmp.path().join("etc")).unwrap();

        write_resolv_conf(
            tmp.path(),
            &["1.1.1.1".to_string(), "8.8.8.8".to_string()],
        )
        .unwrap();

        let content = fs::read_to_string(tmp.path().join("etc/resolv.conf")).unwrap();
        assert_eq!(content, "nameserver 1.1.1.1\nnameserver 8.8.8.8\n");
    }

    #[test]
    fn test_write_resolv_conf_replaces_symlink() {
        let tmp = crate::testutil::TempDataDir::new("export-vm-resolv-symlink");
        fs::create_dir_all(tmp.path().join("etc")).unwrap();
        let resolv = tmp.path().join("etc/resolv.conf");
        std::os::unix::fs::symlink("../run/systemd/resolve/stub-resolv.conf", &resolv).unwrap();

        write_resolv_conf(tmp.path(), &["9.9.9.9".to_string()]).unwrap();

        assert!(resolv.is_file());
        assert!(!resolv.symlink_metadata().unwrap().file_type().is_symlink());
        let content = fs::read_to_string(&resolv).unwrap();
        assert_eq!(content, "nameserver 9.9.9.9\n");
    }

    // --- configure_networkd tests ---

    #[test]
    fn test_configure_networkd() {
        let tmp = crate::testutil::TempDataDir::new("export-vm-networkd");
        fs::create_dir_all(tmp.path().join("etc/systemd/system")).unwrap();

        configure_networkd(tmp.path(), 1).unwrap();

        let network = tmp.path().join("etc/systemd/network/80-vm-dhcp.network");
        assert!(network.is_file());
        let content = fs::read_to_string(&network).unwrap();
        assert!(content.contains("[Match]"));
        assert!(content.contains("Name=en* eth*"));
        assert!(content.contains("DHCP=yes"));

        let link = tmp
            .path()
            .join("etc/systemd/system/multi-user.target.wants/systemd-networkd.service");
        assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
    }

    // --- set_root_password tests ---

    #[test]
    fn test_set_root_password_hash() {
        let tmp = crate::testutil::TempDataDir::new("export-vm-shadow-hash");
        fs::create_dir_all(tmp.path().join("etc")).unwrap();
        fs::write(
            tmp.path().join("etc/shadow"),
            "root:!locked:19000:0:99999:7:::\nnobody:*:19000:0:99999:7:::\n",
        )
        .unwrap();

        set_root_password(tmp.path(), "secret").unwrap();

        let content = fs::read_to_string(tmp.path().join("etc/shadow")).unwrap();
        assert!(content.starts_with("root:$6$"), "got: {content}");
        assert!(content.contains("nobody:*:"));
    }

    #[test]
    fn test_set_root_password_empty() {
        let tmp = crate::testutil::TempDataDir::new("export-vm-shadow-empty");
        fs::create_dir_all(tmp.path().join("etc")).unwrap();
        fs::write(
            tmp.path().join("etc/shadow"),
            "root:!locked:19000:0:99999:7:::\n",
        )
        .unwrap();

        set_root_password(tmp.path(), "").unwrap();

        let content = fs::read_to_string(tmp.path().join("etc/shadow")).unwrap();
        assert!(content.starts_with("root::19000"), "got: {content}");
    }

    // --- install_ssh_key tests ---

    #[test]
    fn test_install_ssh_key() {
        let tmp = crate::testutil::TempDataDir::new("export-vm-ssh");

        install_ssh_key(tmp.path(), "ssh-ed25519 AAAA... user@host").unwrap();

        let ssh_dir = tmp.path().join("root/.ssh");
        let mode = fs::metadata(&ssh_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);

        let auth_keys = ssh_dir.join("authorized_keys");
        let content = fs::read_to_string(&auth_keys).unwrap();
        assert_eq!(content, "ssh-ed25519 AAAA... user@host\n");

        let mode = fs::metadata(&auth_keys).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
