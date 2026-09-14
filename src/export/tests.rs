use super::*;

use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::atomic::Ordering;

use crate::copy;

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
    assert_eq!(raw::dir_size(tmp.path()).unwrap(), 0);
}

#[test]
fn test_dir_size_with_files() {
    let _guard = lock_and_clear_interrupted();
    let tmp = crate::testutil::TempDataDir::new("export-dirsize-files");
    fs::write(tmp.path().join("a"), "hello").unwrap(); // 5 bytes -> 4096
    fs::create_dir(tmp.path().join("sub")).unwrap();
    fs::write(tmp.path().join("sub/b"), "world!").unwrap(); // 6 bytes -> 4096
    assert_eq!(raw::dir_size(tmp.path()).unwrap(), 8192);
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

    dir::export_to_dir(src.path(), &dst, false, false).unwrap();

    assert!(dst.join("hello.txt").is_file());
    assert_eq!(fs::read_to_string(dst.join("hello.txt")).unwrap(), "hi");
    assert!(dst.join("sub/nested.txt").is_file());
}

#[test]
fn test_export_to_dir_rejects_existing() {
    let src = crate::testutil::TempDataDir::new("export-dir-exist-src");
    let dst = crate::testutil::TempDataDir::new("export-dir-exist-dst");

    let err = dir::export_to_dir(src.path(), dst.path(), false, false).unwrap_err();
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

    let opts = ExportOptions {
        format: &ExportFormat::Tar,
        size: None,
        free_space: 0,
        vm_opts: None,
        verbose: false,
        force: false,
        timezone: None,
    };
    tar::export_to_tar(src.path(), &tarball, &opts).unwrap();
    assert!(tarball.exists());
    assert!(fs::metadata(&tarball).unwrap().len() > 0);

    // Verify contents by reading the tarball.
    let file = File::open(&tarball).unwrap();
    let mut archive = ::tar::Archive::new(file);
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

    let opts = ExportOptions {
        format: &ExportFormat::TarGz,
        size: None,
        free_space: 0,
        vm_opts: None,
        verbose: false,
        force: false,
        timezone: None,
    };
    tar::export_to_tar(src.path(), &tarball, &opts).unwrap();
    assert!(tarball.exists());

    // Verify by decompressing and reading.
    let file = File::open(&tarball).unwrap();
    let decoder = flate2::read::GzDecoder::new(file);
    let mut archive = ::tar::Archive::new(decoder);
    let entries: Vec<String> = archive
        .entries()
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path().unwrap().to_string_lossy().into_owned())
        .collect();
    assert!(entries.contains(&"data".to_string()));
}

#[test]
fn test_export_compression_roundtrip_and_truncation() {
    use std::io::Read;

    let _guard = lock_and_clear_interrupted();
    let src = crate::testutil::TempDataDir::new("export-compression-src");
    let dst = crate::testutil::TempDataDir::new("export-compression-dst");
    let content: Vec<u8> = (0..131_072).map(|i| (i % 251) as u8).collect();
    fs::write(src.path().join("payload"), &content).unwrap();
    fs::write(src.path().join("empty"), []).unwrap();

    for format in [ExportFormat::TarBz2, ExportFormat::TarZst] {
        let output = dst.path().join(format!("{format:?}"));
        let opts = ExportOptions {
            format: &format,
            size: None,
            free_space: 0,
            vm_opts: None,
            verbose: false,
            force: false,
            timezone: None,
        };
        tar::export_to_tar(src.path(), &output, &opts).unwrap();
        let compressed = fs::read(&output).unwrap();
        let decode = |bytes: Vec<u8>| -> Box<dyn Read> {
            let reader = std::io::Cursor::new(bytes);
            match format {
                ExportFormat::TarBz2 => Box::new(bzip2::read::BzDecoder::new(reader)),
                ExportFormat::TarZst => Box::new(zstd::stream::read::Decoder::new(reader).unwrap()),
                _ => unreachable!(),
            }
        };
        let mut decoded = Vec::new();
        decode(compressed.clone())
            .read_to_end(&mut decoded)
            .unwrap();
        let mut archive = ::tar::Archive::new(decoded.as_slice());
        let mut names = Vec::new();
        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            let name = entry.path().unwrap().into_owned();
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).unwrap();
            match name.to_str().unwrap() {
                "payload" => assert_eq!(bytes, content),
                "empty" => assert!(bytes.is_empty()),
                other => panic!("unexpected archive entry: {other}"),
            }
            names.push(name);
        }
        names.sort();
        assert_eq!(names, [Path::new("empty"), Path::new("payload")]);

        let truncated = compressed[..compressed.len() / 2].to_vec();
        assert!(decode(truncated).read_to_end(&mut Vec::new()).is_err());
    }
}

#[test]
fn test_export_to_tar_rejects_existing() {
    let src = crate::testutil::TempDataDir::new("export-tar-exist-src");
    let dst = crate::testutil::TempDataDir::new("export-tar-exist-dst");
    let tarball = dst.path().join("out.tar");
    fs::write(&tarball, "existing").unwrap();

    let opts = ExportOptions {
        format: &ExportFormat::Tar,
        size: None,
        free_space: 0,
        vm_opts: None,
        verbose: false,
        force: false,
        timezone: None,
    };
    let err = tar::export_to_tar(src.path(), &tarball, &opts).unwrap_err();
    assert!(err.to_string().contains("already exists"), "got: {err}");
}

// --- export_rootfs tests ---

#[test]
fn test_export_rootfs_not_found() {
    let tmp = crate::testutil::TempDataDir::new("export-rootfs-notfound");
    fs::create_dir_all(tmp.path().join("fs")).unwrap();
    let output = tmp.path().join("out");

    let opts = ExportOptions {
        format: &ExportFormat::Dir,
        size: None,
        free_space: 0,
        vm_opts: None,
        verbose: false,
        force: false,
        timezone: None,
    };
    let err = export_rootfs(tmp.path(), "nonexistent", &output, &opts).unwrap_err();
    assert!(err.to_string().contains("rootfs not found"), "got: {err}");
}

#[test]
fn test_export_rootfs_invalid_name() {
    let tmp = crate::testutil::TempDataDir::new("export-rootfs-badname");
    let output = tmp.path().join("out");

    let opts = ExportOptions {
        format: &ExportFormat::Dir,
        size: None,
        free_space: 0,
        vm_opts: None,
        verbose: false,
        force: false,
        timezone: None,
    };
    let err = export_rootfs(tmp.path(), "../escape", &output, &opts).unwrap_err();
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
    let opts = ExportOptions {
        format: &ExportFormat::Dir,
        size: None,
        free_space: 0,
        vm_opts: None,
        verbose: false,
        force: false,
        timezone: None,
    };
    export_rootfs(tmp.path(), "myfs", &output, &opts).unwrap();

    assert!(output.join("hello").is_file());
    assert_eq!(fs::read_to_string(output.join("hello")).unwrap(), "world");
}

// --- write_hostname tests ---

#[test]
fn test_write_hostname() {
    let tmp = crate::testutil::TempDataDir::new("export-vm-hostname");
    fs::create_dir_all(tmp.path().join("etc")).unwrap();

    vm::write_hostname(tmp.path(), "myvm").unwrap();

    let content = fs::read_to_string(tmp.path().join("etc/hostname")).unwrap();
    assert_eq!(content, "myvm\n");
}

// --- builtin_export_prehook tests ---

#[test]
fn test_builtin_export_prehook_per_distro() {
    use crate::rootfs::DistroFamily;

    assert!(builtin_export_prehook(&DistroFamily::Debian).is_empty());
    assert!(builtin_export_prehook(&DistroFamily::Fedora).is_empty());
    assert!(builtin_export_prehook(&DistroFamily::Arch).is_empty());

    let cmds = builtin_export_prehook(&DistroFamily::Suse);
    assert_eq!(cmds.len(), 2);
    assert!(cmds[0].contains("newuidmap"), "got: {}", cmds[0]);
    assert!(cmds[1].contains("newgidmap"), "got: {}", cmds[1]);

    assert!(builtin_export_prehook(&DistroFamily::NixOS).is_empty());
    assert!(builtin_export_prehook(&DistroFamily::Unknown).is_empty());
}

// --- builtin_export_vm_prehook tests ---

#[test]
fn test_builtin_export_vm_prehook_per_distro() {
    use crate::rootfs::DistroFamily;

    let cmds = builtin_export_vm_prehook(&DistroFamily::Debian);
    assert!(cmds.len() >= 2);
    assert!(
        cmds[0].contains("apt-get") && cmds[0].contains("update"),
        "got: {}",
        cmds[0]
    );
    assert!(cmds[1].contains("udev"), "got: {}", cmds[1]);
    assert!(cmds.iter().any(|c| c.contains("clean")), "missing cleanup");

    let cmds = builtin_export_vm_prehook(&DistroFamily::Fedora);
    assert!(cmds.len() >= 2);
    assert!(cmds[0].contains("dnf"), "got: {}", cmds[0]);
    assert!(cmds[0].contains("systemd-udevd"), "got: {}", cmds[0]);
    assert!(cmds.iter().any(|c| c.contains("clean")), "missing cleanup");

    let cmds = builtin_export_vm_prehook(&DistroFamily::Arch);
    assert!(cmds.len() >= 2);
    assert!(cmds[0].contains("pacman"), "got: {}", cmds[0]);
    assert!(cmds.iter().any(|c| c.contains("-Scc")), "missing cleanup");

    let cmds = builtin_export_vm_prehook(&DistroFamily::Suse);
    assert!(cmds.len() >= 2);
    assert!(cmds[0].contains("zypper"), "got: {}", cmds[0]);
    assert!(cmds.iter().any(|c| c.contains("clean")), "missing cleanup");

    assert!(builtin_export_vm_prehook(&DistroFamily::NixOS).is_empty());
    assert!(builtin_export_vm_prehook(&DistroFamily::Unknown).is_empty());
}

// --- sha512_crypt tests ---

#[test]
fn test_sha512_crypt_format() {
    let result = vm::sha512_crypt("test").unwrap();
    assert!(
        result.starts_with("$6$"),
        "expected $6$ prefix, got: {result}"
    );
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
    let hash = vm::sha512_crypt_hash(b"Hello world!", b"saltstring", 5000);
    let expected = "svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJu\
                    esI68u4OTLiBFdcbYEdFCoEOfaS35inz1";
    assert_eq!(hash, expected);
}

#[test]
fn test_sha512_crypt_known_vector_rounds() {
    // Known vector from the Drepper spec with 10000 rounds.
    // Salt truncated to 16 chars: "saltstringsaltst".
    let hash = vm::sha512_crypt_hash(b"Hello world!", b"saltstringsaltst", 10000);
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

    raw::align_disk_image(&img).unwrap();
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

    raw::align_disk_image(&img).unwrap();
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

    vm::enable_serial_console(tmp.path()).unwrap();

    // Patched template should exist without BindsTo or After=dev-.
    let template = tmp.path().join("etc/systemd/system/serial-getty@.service");
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

    // No distro template: should write the fallback.
    vm::enable_serial_console(tmp.path()).unwrap();

    let template = tmp.path().join("etc/systemd/system/serial-getty@.service");
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

    vm::ensure_init_symlink(root).unwrap();

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

    vm::ensure_init_symlink(root).unwrap();

    // Should not be overwritten, still a regular file with original content.
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

    vm::ensure_init_symlink(root).unwrap();

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

    let err = vm::ensure_init_symlink(root).unwrap_err();
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

    vm::write_vm_fstab(tmp.path(), RawFs::Ext4, 0).unwrap();

    let content = fs::read_to_string(tmp.path().join("etc/fstab")).unwrap();
    assert_eq!(content, "/dev/vda1 / ext4 defaults 0 1\n");
}

#[test]
fn test_write_vm_fstab_btrfs() {
    let tmp = crate::testutil::TempDataDir::new("export-vm-fstab-btrfs");
    fs::create_dir_all(tmp.path().join("etc")).unwrap();

    vm::write_vm_fstab(tmp.path(), RawFs::Btrfs, 0).unwrap();

    let content = fs::read_to_string(tmp.path().join("etc/fstab")).unwrap();
    assert_eq!(content, "/dev/vda1 / btrfs defaults 0 1\n");
}

#[test]
fn test_write_vm_fstab_with_swap() {
    let tmp = crate::testutil::TempDataDir::new("export-vm-fstab-swap");
    fs::create_dir_all(tmp.path().join("etc")).unwrap();

    vm::write_vm_fstab(tmp.path(), RawFs::Ext4, 512 * 1024 * 1024).unwrap();

    let content = fs::read_to_string(tmp.path().join("etc/fstab")).unwrap();
    assert_eq!(
        content,
        "/dev/vda1 / ext4 defaults 0 1\n/dev/vda2 none swap sw 0 0\n"
    );
}

// --- unmask_resolved tests ---

#[test]
fn test_unmask_resolved_masked() {
    let tmp = crate::testutil::TempDataDir::new("export-vm-unmask-resolved");
    let unit_dir = tmp.path().join("etc/systemd/system");
    fs::create_dir_all(&unit_dir).unwrap();
    let resolved = unit_dir.join("systemd-resolved.service");
    std::os::unix::fs::symlink("/dev/null", &resolved).unwrap();

    vm::unmask_resolved(tmp.path()).unwrap();
    assert!(!resolved.exists());
    assert!(resolved.symlink_metadata().is_err());
}

#[test]
fn test_unmask_resolved_not_masked() {
    let tmp = crate::testutil::TempDataDir::new("export-vm-unmask-noop");
    let unit_dir = tmp.path().join("etc/systemd/system");
    fs::create_dir_all(&unit_dir).unwrap();
    // No symlink present: should be a no-op.
    vm::unmask_resolved(tmp.path()).unwrap();
}

#[test]
fn test_unmask_resolved_not_devnull() {
    let tmp = crate::testutil::TempDataDir::new("export-vm-unmask-other");
    let unit_dir = tmp.path().join("etc/systemd/system");
    fs::create_dir_all(&unit_dir).unwrap();
    let resolved = unit_dir.join("systemd-resolved.service");
    // Symlink to something other than /dev/null: should NOT be removed.
    std::os::unix::fs::symlink("/lib/systemd/system/systemd-resolved.service", &resolved).unwrap();

    vm::unmask_resolved(tmp.path()).unwrap();
    assert!(resolved.symlink_metadata().is_ok());
}

// --- write_resolv_conf tests ---

#[test]
fn test_write_resolv_conf() {
    let tmp = crate::testutil::TempDataDir::new("export-vm-resolv");
    fs::create_dir_all(tmp.path().join("etc")).unwrap();

    vm::write_resolv_conf(tmp.path(), &["1.1.1.1".to_string(), "8.8.8.8".to_string()]).unwrap();

    let content = fs::read_to_string(tmp.path().join("etc/resolv.conf")).unwrap();
    assert_eq!(content, "nameserver 1.1.1.1\nnameserver 8.8.8.8\n");
}

#[test]
fn test_write_resolv_conf_replaces_symlink() {
    let tmp = crate::testutil::TempDataDir::new("export-vm-resolv-symlink");
    fs::create_dir_all(tmp.path().join("etc")).unwrap();
    let resolv = tmp.path().join("etc/resolv.conf");
    std::os::unix::fs::symlink("../run/systemd/resolve/stub-resolv.conf", &resolv).unwrap();

    vm::write_resolv_conf(tmp.path(), &["9.9.9.9".to_string()]).unwrap();

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

    vm::configure_networkd(tmp.path(), 1).unwrap();

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

    vm::set_root_password(tmp.path(), "secret").unwrap();

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

    vm::set_root_password(tmp.path(), "").unwrap();

    let content = fs::read_to_string(tmp.path().join("etc/shadow")).unwrap();
    assert!(content.starts_with("root::19000"), "got: {content}");
}

// --- install_ssh_key tests ---

#[test]
fn test_install_ssh_key() {
    let tmp = crate::testutil::TempDataDir::new("export-vm-ssh");

    vm::install_ssh_key(tmp.path(), "ssh-ed25519 AAAA... user@host").unwrap();

    let ssh_dir = tmp.path().join("root/.ssh");
    let mode = fs::metadata(&ssh_dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);

    let auth_keys = ssh_dir.join("authorized_keys");
    let content = fs::read_to_string(&auth_keys).unwrap();
    assert_eq!(content, "ssh-ed25519 AAAA... user@host\n");

    let mode = fs::metadata(&auth_keys).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

// --- validate_timezone_format tests ---

#[test]
fn test_validate_timezone_format_valid() {
    assert!(validate_timezone_format("UTC").is_ok());
    assert!(validate_timezone_format("America/New_York").is_ok());
    assert!(validate_timezone_format("Europe/London").is_ok());
    assert!(validate_timezone_format("Asia/Kolkata").is_ok());
}

#[test]
fn test_validate_timezone_format_empty() {
    let err = validate_timezone_format("").unwrap_err();
    assert!(err.to_string().contains("empty"), "got: {err}");
}

#[test]
fn test_validate_timezone_format_dotdot() {
    let err = validate_timezone_format("../etc/passwd").unwrap_err();
    assert!(err.to_string().contains(".."), "got: {err}");
}

#[test]
fn test_validate_timezone_format_leading_slash() {
    let err = validate_timezone_format("/UTC").unwrap_err();
    assert!(err.to_string().contains("'/'"), "got: {err}");
}

#[test]
fn test_validate_timezone_format_null() {
    let err = validate_timezone_format("UTC\0").unwrap_err();
    assert!(err.to_string().contains("null"), "got: {err}");
}

#[test]
fn test_validate_timezone_format_whitespace() {
    let err = validate_timezone_format("America/ New_York").unwrap_err();
    assert!(err.to_string().contains("whitespace"), "got: {err}");
}

// --- validate_timezone_in_rootfs tests ---

#[test]
fn test_validate_timezone_in_rootfs_found() {
    let tmp = crate::testutil::TempDataDir::new("export-tz-found");
    let zi_dir = tmp.path().join("usr/share/zoneinfo/America");
    fs::create_dir_all(&zi_dir).unwrap();
    fs::write(zi_dir.join("New_York"), "fake").unwrap();

    assert!(validate_timezone_in_rootfs(tmp.path(), "America/New_York").is_ok());
}

#[test]
fn test_validate_timezone_in_rootfs_not_found() {
    let tmp = crate::testutil::TempDataDir::new("export-tz-notfound");
    let err = validate_timezone_in_rootfs(tmp.path(), "Fake/Zone").unwrap_err();
    assert!(err.to_string().contains("not found"), "got: {err}");
}

// --- set_timezone tests ---

#[test]
fn test_set_timezone_creates_files() {
    let tmp = crate::testutil::TempDataDir::new("export-tz-set");
    fs::create_dir_all(tmp.path().join("etc")).unwrap();

    set_timezone(tmp.path(), "America/New_York").unwrap();

    let localtime = tmp.path().join("etc/localtime");
    assert!(localtime
        .symlink_metadata()
        .unwrap()
        .file_type()
        .is_symlink());
    let target = fs::read_link(&localtime).unwrap();
    assert_eq!(
        target.to_str().unwrap(),
        "../usr/share/zoneinfo/America/New_York"
    );

    let tz_content = fs::read_to_string(tmp.path().join("etc/timezone")).unwrap();
    assert_eq!(tz_content, "America/New_York\n");
}

#[test]
fn test_set_timezone_replaces_existing() {
    let tmp = crate::testutil::TempDataDir::new("export-tz-replace");
    let etc = tmp.path().join("etc");
    fs::create_dir_all(&etc).unwrap();
    fs::write(etc.join("localtime"), "old content").unwrap();

    set_timezone(tmp.path(), "UTC").unwrap();

    let localtime = etc.join("localtime");
    assert!(localtime
        .symlink_metadata()
        .unwrap()
        .file_type()
        .is_symlink());
    let target = fs::read_link(&localtime).unwrap();
    assert_eq!(target.to_str().unwrap(), "../usr/share/zoneinfo/UTC");
}

// --- export_rootfs with timezone validation ---

#[test]
fn test_export_rootfs_timezone_not_in_rootfs() {
    let tmp = crate::testutil::TempDataDir::new("export-tz-rootfs-missing");
    let rootfs_dir = tmp.path().join("fs/myfs");
    fs::create_dir_all(&rootfs_dir).unwrap();

    let output = tmp.path().join("out");
    let opts = ExportOptions {
        format: &ExportFormat::Dir,
        size: None,
        free_space: 0,
        vm_opts: None,
        verbose: false,
        force: false,
        timezone: Some("Fake/Zone"),
    };
    let err = export_rootfs(tmp.path(), "myfs", &output, &opts).unwrap_err();
    assert!(err.to_string().contains("not found"), "got: {err}");
}

// --- export_to_tar with timezone ---

#[test]
fn test_export_to_tar_with_timezone() {
    let _guard = lock_and_clear_interrupted();
    let src = crate::testutil::TempDataDir::new("export-tar-tz-src");
    // Create a fake zoneinfo file so the source is valid.
    let zi = src.path().join("usr/share/zoneinfo");
    fs::create_dir_all(&zi).unwrap();
    fs::write(zi.join("UTC"), "fake").unwrap();
    fs::create_dir_all(src.path().join("etc")).unwrap();
    fs::write(src.path().join("etc/hello"), "world").unwrap();

    let dst = crate::testutil::TempDataDir::new("export-tar-tz-dst");
    let tarball = dst.path().join("out.tar");

    let opts = ExportOptions {
        format: &ExportFormat::Tar,
        size: None,
        free_space: 0,
        vm_opts: None,
        verbose: false,
        force: false,
        timezone: Some("UTC"),
    };
    tar::export_to_tar(src.path(), &tarball, &opts).unwrap();

    // Read tarball and verify timezone entries exist.
    let file = File::open(&tarball).unwrap();
    let mut archive = ::tar::Archive::new(file);
    let mut found_localtime = false;
    let mut found_timezone = false;
    for entry in archive.entries().unwrap() {
        let entry = entry.unwrap();
        let path = entry.path().unwrap().to_string_lossy().into_owned();
        if path == "etc/localtime" {
            found_localtime = true;
            assert_eq!(entry.header().entry_type(), ::tar::EntryType::Symlink);
            let link = entry.link_name().unwrap().unwrap();
            assert_eq!(link.to_str().unwrap(), "../usr/share/zoneinfo/UTC");
        }
        if path == "etc/timezone" {
            found_timezone = true;
            assert_eq!(entry.header().entry_type(), ::tar::EntryType::Regular);
        }
    }
    assert!(found_localtime, "etc/localtime not found in tarball");
    assert!(found_timezone, "etc/timezone not found in tarball");
}

// --- ExportSource tests ---

#[test]
fn test_export_source_rootfs_invalid_name() {
    let tmp = crate::testutil::TempDataDir::new("export-src-rootfs-inv");
    let source = ExportSource::Rootfs("INVALID".to_string());
    let opts = ExportOptions {
        format: &ExportFormat::Dir,
        size: None,
        free_space: 0,
        vm_opts: None,
        verbose: false,
        force: false,
        timezone: None,
    };
    let err = export(tmp.path(), &source, Path::new("/tmp/nope"), &opts, false).unwrap_err();
    assert!(
        err.to_string().contains("invalid rootfs name"),
        "got: {err}"
    );
}

#[test]
fn test_export_source_rootfs_not_found() {
    let tmp = crate::testutil::TempDataDir::new("export-src-rootfs-nf");
    let source = ExportSource::Rootfs("noexist".to_string());
    let opts = ExportOptions {
        format: &ExportFormat::Dir,
        size: None,
        free_space: 0,
        vm_opts: None,
        verbose: false,
        force: false,
        timezone: None,
    };
    let err = export(tmp.path(), &source, Path::new("/tmp/nope"), &opts, false).unwrap_err();
    assert!(err.to_string().contains("rootfs not found"), "got: {err}");
}

#[test]
fn test_export_source_container_not_found() {
    let tmp = crate::testutil::TempDataDir::new("export-src-ctr-nf");
    let source = ExportSource::Container("noexist".to_string());
    let opts = ExportOptions {
        format: &ExportFormat::Dir,
        size: None,
        free_space: 0,
        vm_opts: None,
        verbose: false,
        force: false,
        timezone: None,
    };
    let err = export(tmp.path(), &source, Path::new("/tmp/nope"), &opts, false).unwrap_err();
    assert!(err.to_string().contains("does not exist"), "got: {err}");
}

#[test]
fn test_dir_size_skips_symlinks() {
    let _guard = lock_and_clear_interrupted();
    let tmp = crate::testutil::TempDataDir::new("export-dirsize-symlinks");
    let dir = tmp.path().join("root");
    fs::create_dir(&dir).unwrap();
    // Regular file: 100 bytes -> 4096 after block alignment.
    fs::write(dir.join("file.txt"), vec![0u8; 100]).unwrap();
    // Symlink to a file: should not add to size.
    std::os::unix::fs::symlink(dir.join("file.txt"), dir.join("link.txt")).unwrap();
    // Symlink cycle: must not cause infinite recursion.
    std::os::unix::fs::symlink(&dir, dir.join("cycle")).unwrap();
    let size = raw::dir_size(&dir).unwrap();
    assert_eq!(size, 4096, "expected one block-aligned file, got {size}");
}

#[test]
fn test_write_resolv_conf_validates_nameservers() {
    let tmp = crate::testutil::TempDataDir::new("export-resolv-validate");
    let mount = tmp.path();
    fs::create_dir_all(mount.join("etc")).unwrap();
    // Valid IPs should succeed.
    vm::write_resolv_conf(mount, &["8.8.8.8".into(), "2001:4860:4860::8888".into()]).unwrap();
    // Invalid nameserver should fail.
    let err = vm::write_resolv_conf(mount, &["1.1.1.1\noptions attempts:1".into()]).unwrap_err();
    assert!(
        err.to_string().contains("invalid DNS nameserver"),
        "got: {err}"
    );
    let err = vm::write_resolv_conf(mount, &["not-an-ip".into()]).unwrap_err();
    assert!(
        err.to_string().contains("invalid DNS nameserver"),
        "got: {err}"
    );
}

// --- hard link tests ---

#[test]
fn test_tar_export_preserves_hard_links() {
    let _guard = lock_and_clear_interrupted();
    let src = crate::testutil::TempDataDir::new("export-tar-hl-src");
    fs::write(src.path().join("original"), "hardlink-data").unwrap();
    fs::hard_link(src.path().join("original"), src.path().join("link")).unwrap();

    let dst = crate::testutil::TempDataDir::new("export-tar-hl-dst");
    let tarball = dst.path().join("out.tar");

    let opts = ExportOptions {
        format: &ExportFormat::Tar,
        size: None,
        free_space: 0,
        vm_opts: None,
        verbose: false,
        force: false,
        timezone: None,
    };
    tar::export_to_tar(src.path(), &tarball, &opts).unwrap();

    let file = File::open(&tarball).unwrap();
    let mut archive = ::tar::Archive::new(file);
    let mut found_link = false;
    for entry in archive.entries().unwrap() {
        let entry = entry.unwrap();
        if entry.header().entry_type() == ::tar::EntryType::Link {
            found_link = true;
            // The link target should point to the first occurrence.
            let link_name = entry.header().link_name().unwrap().unwrap();
            let path = entry.path().unwrap();
            // One of them is the link, the other is the original.
            assert!(
                (path.to_str() == Some("link") && link_name.to_str() == Some("original"))
                    || (path.to_str() == Some("original") && link_name.to_str() == Some("link")),
                "unexpected link: {} -> {}",
                path.display(),
                link_name.display()
            );
        }
    }
    assert!(found_link, "no hard link entry found in tar");
}

#[test]
fn test_tar_export_no_hardlink_for_nlink_1() {
    let _guard = lock_and_clear_interrupted();
    let src = crate::testutil::TempDataDir::new("export-tar-nohl-src");
    fs::write(src.path().join("single"), "no-hardlink").unwrap();

    let dst = crate::testutil::TempDataDir::new("export-tar-nohl-dst");
    let tarball = dst.path().join("out.tar");

    let opts = ExportOptions {
        format: &ExportFormat::Tar,
        size: None,
        free_space: 0,
        vm_opts: None,
        verbose: false,
        force: false,
        timezone: None,
    };
    tar::export_to_tar(src.path(), &tarball, &opts).unwrap();

    let file = File::open(&tarball).unwrap();
    let mut archive = ::tar::Archive::new(file);
    for entry in archive.entries().unwrap() {
        let entry = entry.unwrap();
        assert_ne!(
            entry.header().entry_type(),
            ::tar::EntryType::Link,
            "nlink=1 file should not produce a Link entry"
        );
    }
}

// --- xattr tests ---

/// Helper: try setting a user xattr. Returns false if the filesystem
/// doesn't support user.* xattrs (e.g. tmpfs in some configs).
fn can_set_user_xattr(path: &Path) -> bool {
    let c_path = copy::path_to_cstring(path).unwrap();
    let name = std::ffi::CString::new("user.test").unwrap();
    let val = b"probe";
    let ret = unsafe {
        libc::lsetxattr(
            c_path.as_ptr(),
            name.as_ptr(),
            val.as_ptr() as *const libc::c_void,
            val.len(),
            0,
        )
    };
    if ret == 0 {
        // Clean up.
        unsafe { libc::lremovexattr(c_path.as_ptr(), name.as_ptr()) };
        true
    } else {
        false
    }
}

#[test]
fn test_tar_export_preserves_xattrs() {
    let _guard = lock_and_clear_interrupted();
    let src = crate::testutil::TempDataDir::new("export-tar-xattr-src");
    let file_path = src.path().join("with-xattr");
    fs::write(&file_path, "xattr-data").unwrap();

    if !can_set_user_xattr(&file_path) {
        eprintln!("skipping xattr test: filesystem does not support user.* xattrs");
        return;
    }

    // Set a user xattr.
    let c_path = copy::path_to_cstring(&file_path).unwrap();
    let name = std::ffi::CString::new("user.test").unwrap();
    let val = b"hello";
    let ret = unsafe {
        libc::lsetxattr(
            c_path.as_ptr(),
            name.as_ptr(),
            val.as_ptr() as *const libc::c_void,
            val.len(),
            0,
        )
    };
    assert_eq!(ret, 0, "lsetxattr failed");

    let dst = crate::testutil::TempDataDir::new("export-tar-xattr-dst");
    let tarball = dst.path().join("out.tar");

    let opts = ExportOptions {
        format: &ExportFormat::Tar,
        size: None,
        free_space: 0,
        vm_opts: None,
        verbose: false,
        force: false,
        timezone: None,
    };
    tar::export_to_tar(src.path(), &tarball, &opts).unwrap();

    // Read the tar and look for PAX xattr headers.
    let file = File::open(&tarball).unwrap();
    let mut archive = ::tar::Archive::new(file);
    let mut found_xattr = false;
    for entry in archive.entries().unwrap() {
        let mut entry = entry.unwrap();
        if let Some(pax) = entry.pax_extensions().unwrap() {
            for ext in pax {
                let ext = ext.unwrap();
                if ext.key_bytes() == b"SCHILY.xattr.user.test" {
                    assert_eq!(ext.value_bytes(), b"hello");
                    found_xattr = true;
                }
            }
        }
    }
    assert!(found_xattr, "SCHILY.xattr.user.test not found in tar");
}

#[test]
fn test_tar_export_xattrs_on_directory() {
    let _guard = lock_and_clear_interrupted();
    let src = crate::testutil::TempDataDir::new("export-tar-xattr-dir-src");
    let dir_path = src.path().join("mydir");
    fs::create_dir(&dir_path).unwrap();

    if !can_set_user_xattr(&dir_path) {
        eprintln!("skipping xattr test: filesystem does not support user.* xattrs");
        return;
    }

    let c_path = copy::path_to_cstring(&dir_path).unwrap();
    let name = std::ffi::CString::new("user.dirattr").unwrap();
    let val = b"dirvalue";
    let ret = unsafe {
        libc::lsetxattr(
            c_path.as_ptr(),
            name.as_ptr(),
            val.as_ptr() as *const libc::c_void,
            val.len(),
            0,
        )
    };
    assert_eq!(ret, 0, "lsetxattr failed");

    let dst = crate::testutil::TempDataDir::new("export-tar-xattr-dir-dst");
    let tarball = dst.path().join("out.tar");

    let opts = ExportOptions {
        format: &ExportFormat::Tar,
        size: None,
        free_space: 0,
        vm_opts: None,
        verbose: false,
        force: false,
        timezone: None,
    };
    tar::export_to_tar(src.path(), &tarball, &opts).unwrap();

    let file = File::open(&tarball).unwrap();
    let mut archive = ::tar::Archive::new(file);
    let mut found_xattr = false;
    for entry in archive.entries().unwrap() {
        let mut entry = entry.unwrap();
        if let Some(pax) = entry.pax_extensions().unwrap() {
            for ext in pax {
                let ext = ext.unwrap();
                if ext.key_bytes() == b"SCHILY.xattr.user.dirattr" {
                    assert_eq!(ext.value_bytes(), b"dirvalue");
                    found_xattr = true;
                }
            }
        }
    }
    assert!(found_xattr, "SCHILY.xattr.user.dirattr not found in tar");
}

#[test]
fn test_tar_export_hardlink_skips_xattrs() {
    let _guard = lock_and_clear_interrupted();
    let src = crate::testutil::TempDataDir::new("export-tar-hl-xattr-src");
    let file_path = src.path().join("original");
    fs::write(&file_path, "hl-xattr-data").unwrap();

    let has_xattr = can_set_user_xattr(&file_path);
    if has_xattr {
        let c_path = copy::path_to_cstring(&file_path).unwrap();
        let name = std::ffi::CString::new("user.hltest").unwrap();
        let val = b"first";
        unsafe {
            libc::lsetxattr(
                c_path.as_ptr(),
                name.as_ptr(),
                val.as_ptr() as *const libc::c_void,
                val.len(),
                0,
            );
        }
    }

    fs::hard_link(src.path().join("original"), src.path().join("link")).unwrap();

    let dst = crate::testutil::TempDataDir::new("export-tar-hl-xattr-dst");
    let tarball = dst.path().join("out.tar");

    let opts = ExportOptions {
        format: &ExportFormat::Tar,
        size: None,
        free_space: 0,
        vm_opts: None,
        verbose: false,
        force: false,
        timezone: None,
    };
    tar::export_to_tar(src.path(), &tarball, &opts).unwrap();

    // Verify: the Link entry should NOT have its own PAX xattr block.
    let file = File::open(&tarball).unwrap();
    let mut archive = ::tar::Archive::new(file);
    for entry in archive.entries().unwrap() {
        let mut entry = entry.unwrap();
        if entry.header().entry_type() == ::tar::EntryType::Link {
            // Hard link entries should not have PAX xattr extensions.
            if let Some(pax) = entry.pax_extensions().unwrap() {
                for ext in pax {
                    let ext = ext.unwrap();
                    let key = String::from_utf8_lossy(ext.key_bytes());
                    assert!(
                        !key.starts_with("SCHILY.xattr."),
                        "hard link entry should not have xattr PAX headers, found: {key}"
                    );
                }
            }
        }
    }
}
