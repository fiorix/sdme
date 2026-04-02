use std::ffi::CString;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::testutil::TempDataDir;
use crate::{validate_name, State};

use super::*;

/// umask is process-global; tests that call create() or manipulate the umask
/// must hold this lock to avoid racing each other.
static UMASK_LOCK: Mutex<()> = Mutex::new(());

fn tmp() -> TempDataDir {
    TempDataDir::new("containers")
}

#[test]
fn test_validate_name_ok() {
    assert!(validate_name("mycontainer").is_ok());
    assert!(validate_name("test123").is_ok());
    assert!(validate_name("a").is_ok());
    assert!(validate_name("my-container").is_ok());
}

#[test]
fn test_validate_name_invalid() {
    assert!(validate_name("").is_err());
    assert!(validate_name("MyContainer").is_err());
    assert!(validate_name("has space").is_err());
    assert!(validate_name("1startsdigit").is_err());
    assert!(validate_name("-startshyphen").is_err());
}

#[test]
fn test_state_roundtrip() {
    let mut state = State::new();
    state.set("NAME", "test");
    state.set("CREATED", "1234567890");
    state.set("ROOTFS", "");

    let serialized = state.serialize();
    let parsed = State::parse(&serialized).unwrap();

    assert_eq!(parsed.get("NAME"), Some("test"));
    assert_eq!(parsed.get("CREATED"), Some("1234567890"));
    assert_eq!(parsed.get("ROOTFS"), Some(""));
}

#[test]
fn test_state_parse_value_with_equals() {
    let content = "KEY=val=ue\n";
    let state = State::parse(content).unwrap();
    assert_eq!(state.get("KEY"), Some("val=ue"));
}

#[test]
fn test_create_default() {
    let _lock = UMASK_LOCK.lock().unwrap();
    let tmp = tmp();
    let opts = CreateOptions {
        ..Default::default()
    };
    let name = create(tmp.path(), &opts, false).unwrap();
    assert!(validate_name(&name).is_ok());

    // Verify directories.
    let container_dir = tmp.path().join("containers").join(&name);
    assert!(container_dir.join("upper").is_dir());
    assert!(container_dir.join("work").is_dir());
    assert!(container_dir.join("merged").is_dir());

    // Verify hostname.
    let hostname = fs::read_to_string(container_dir.join("upper/etc/hostname")).unwrap();
    assert_eq!(hostname, format!("{name}\n"));

    // Verify hosts.
    let hosts = fs::read_to_string(container_dir.join("upper/etc/hosts")).unwrap();
    assert_eq!(
        hosts,
        format!("127.0.0.1 localhost {name}\n::1 localhost {name}\n")
    );

    // Verify state file.
    let state = State::read_from(&tmp.path().join("state").join(&name)).unwrap();
    assert_eq!(state.get("NAME"), Some(name.as_str()));
    assert_eq!(state.get("ROOTFS"), Some(""));
    assert!(state.get("CREATED").is_some());
}

#[test]
fn test_create_with_name() {
    let _lock = UMASK_LOCK.lock().unwrap();
    let tmp = tmp();
    let opts = CreateOptions {
        name: Some("hello".to_string()),
        ..Default::default()
    };
    let name = create(tmp.path(), &opts, false).unwrap();
    assert_eq!(name, "hello");

    let hostname =
        fs::read_to_string(tmp.path().join("containers/hello/upper/etc/hostname")).unwrap();
    assert_eq!(hostname, "hello\n");

    let hosts = fs::read_to_string(tmp.path().join("containers/hello/upper/etc/hosts")).unwrap();
    assert_eq!(hosts, "127.0.0.1 localhost hello\n::1 localhost hello\n");

    let state = State::read_from(&tmp.path().join("state/hello")).unwrap();
    assert_eq!(state.get("NAME"), Some("hello"));
}

#[test]
fn test_create_duplicate_name() {
    let _lock = UMASK_LOCK.lock().unwrap();
    let tmp = tmp();
    let opts = CreateOptions {
        name: Some("dup".to_string()),
        ..Default::default()
    };
    create(tmp.path(), &opts, false).unwrap();
    let err = create(tmp.path(), &opts, false).unwrap_err();
    assert!(
        err.to_string().contains("already exists"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_create_with_rootfs_missing() {
    let _lock = UMASK_LOCK.lock().unwrap();
    let tmp = tmp();
    let opts = CreateOptions {
        name: Some("test".to_string()),
        rootfs: Some("nonexistent".to_string()),
        ..Default::default()
    };
    let err = create(tmp.path(), &opts, false).unwrap_err();
    assert!(
        err.to_string().contains("fs not found"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_create_with_rootfs_exists() {
    let _lock = UMASK_LOCK.lock().unwrap();
    let tmp = tmp();
    let rootfs_dir = tmp.path().join("fs/myroot");
    fs::create_dir_all(&rootfs_dir).unwrap();

    let opts = CreateOptions {
        name: Some("test".to_string()),
        rootfs: Some("myroot".to_string()),
        ..Default::default()
    };
    let name = create(tmp.path(), &opts, false).unwrap();
    assert_eq!(name, "test");

    let state = State::read_from(&tmp.path().join("state/test")).unwrap();
    assert_eq!(state.get("ROOTFS"), Some("myroot"));
}

#[test]
fn test_create_cleanup_on_failure() {
    let _lock = UMASK_LOCK.lock().unwrap();
    let tmp = tmp();
    // Block state dir by placing a file where the directory should be created.
    let state_path = tmp.path().join("state");
    fs::write(&state_path, "blocker").unwrap();

    let opts = CreateOptions {
        name: Some("fail".to_string()),
        ..Default::default()
    };
    let err = create(tmp.path(), &opts, false);
    assert!(err.is_err());

    // Container dir should have been cleaned up.
    assert!(!tmp.path().join("containers/fail").exists());
}

#[test]
fn test_ensure_exists_ok() {
    let _lock = UMASK_LOCK.lock().unwrap();
    let tmp = tmp();
    let opts = CreateOptions {
        name: Some("mybox".to_string()),
        ..Default::default()
    };
    create(tmp.path(), &opts, false).unwrap();
    assert!(ensure_exists(tmp.path(), "mybox").is_ok());
}

#[test]
fn test_ensure_exists_missing() {
    let tmp = tmp();
    let err = ensure_exists(tmp.path(), "nonexistent").unwrap_err();
    assert!(
        err.to_string().contains("does not exist"),
        "unexpected error: {err}"
    );
}

fn create_dummy_container(tmp: &TempDataDir, name: &str) {
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(state_dir.join(name), format!("NAME={name}\n")).unwrap();
    let container_dir = tmp.path().join("containers").join(name);
    fs::create_dir_all(container_dir.join("upper")).unwrap();
    fs::create_dir_all(container_dir.join("work")).unwrap();
    fs::create_dir_all(container_dir.join("merged")).unwrap();
}

fn create_dummy_container_with_rootfs(tmp: &TempDataDir, name: &str, rootfs_name: &str) {
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(
        state_dir.join(name),
        format!("NAME={name}\nROOTFS={rootfs_name}\n"),
    )
    .unwrap();
    let container_dir = tmp.path().join("containers").join(name);
    fs::create_dir_all(container_dir.join("upper")).unwrap();
    fs::create_dir_all(container_dir.join("work")).unwrap();
    fs::create_dir_all(container_dir.join("merged")).unwrap();
}

fn write_os_release(rootfs: &Path, content: &str) {
    let etc = rootfs.join("etc");
    fs::create_dir_all(&etc).unwrap();
    fs::write(etc.join("os-release"), content).unwrap();
}

#[test]
fn test_resolve_name_exact_match() {
    let tmp = tmp();
    create_dummy_container(&tmp, "foo");
    create_dummy_container(&tmp, "foobar");
    assert_eq!(resolve_name(tmp.path(), "foo").unwrap(), "foo");
}

#[test]
fn test_resolve_name_unique_prefix() {
    let tmp = tmp();
    create_dummy_container(&tmp, "ubuntu-dev");
    assert_eq!(resolve_name(tmp.path(), "ub").unwrap(), "ubuntu-dev");
}

#[test]
fn test_resolve_name_ambiguous() {
    let tmp = tmp();
    create_dummy_container(&tmp, "ubuntu-dev");
    create_dummy_container(&tmp, "ubuntu-prod");
    let err = resolve_name(tmp.path(), "ub").unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("ambiguous"), "unexpected error: {msg}");
    assert!(msg.contains("ubuntu-dev"), "unexpected error: {msg}");
    assert!(msg.contains("ubuntu-prod"), "unexpected error: {msg}");
}

#[test]
fn test_resolve_name_no_match() {
    let tmp = tmp();
    create_dummy_container(&tmp, "foo");
    let err = resolve_name(tmp.path(), "xyz").unwrap_err();
    assert!(
        err.to_string().contains("no container found"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_resolve_name_empty() {
    let tmp = tmp();
    let err = resolve_name(tmp.path(), "").unwrap_err();
    assert!(
        err.to_string().contains("must not be empty"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_ensure_exists_orphan_state() {
    let tmp = tmp();
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(state_dir.join("orphan"), "NAME=orphan\n").unwrap();

    let err = ensure_exists(tmp.path(), "orphan").unwrap_err();
    assert!(
        err.to_string().contains("directory is missing"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_create_with_limits() {
    let _lock = UMASK_LOCK.lock().unwrap();
    let tmp = tmp();
    let limits = crate::ResourceLimits {
        memory: Some("2G".to_string()),
        cpus: Some("4".to_string()),
        cpu_weight: None,
    };
    let opts = CreateOptions {
        name: Some("limited".to_string()),
        limits,
        ..Default::default()
    };
    let name = create(tmp.path(), &opts, false).unwrap();
    assert_eq!(name, "limited");

    let state = State::read_from(&tmp.path().join("state/limited")).unwrap();
    assert_eq!(state.get("MEMORY"), Some("2G"));
    assert_eq!(state.get("CPUS"), Some("4"));
    assert_eq!(state.get("CPU_WEIGHT"), None);
}

#[test]
fn test_create_rejects_restrictive_umask() {
    let _lock = UMASK_LOCK.lock().unwrap();
    // Set a restrictive umask, attempt create, then restore.
    let old = unsafe { libc::umask(0o077) };
    let tmp = tmp();
    let opts = CreateOptions {
        name: Some("umasktest".to_string()),
        ..Default::default()
    };
    let err = create(tmp.path(), &opts, false);
    unsafe { libc::umask(old) };

    let err = err.unwrap_err();
    assert!(err.to_string().contains("umask"), "unexpected error: {err}");
}

#[test]
fn test_create_with_userns() {
    let _lock = UMASK_LOCK.lock().unwrap();
    let tmp = tmp();
    let opts = CreateOptions {
        name: Some("usernsbox".to_string()),
        security: crate::SecurityConfig {
            userns: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let name = create(tmp.path(), &opts, false).unwrap();
    assert_eq!(name, "usernsbox");

    let state = State::read_from(&tmp.path().join("state/usernsbox")).unwrap();
    assert_eq!(state.get("USERNS"), Some("yes"));
}

#[test]
fn test_create_without_userns() {
    let _lock = UMASK_LOCK.lock().unwrap();
    let tmp = tmp();
    let opts = CreateOptions {
        name: Some("nouserns".to_string()),
        ..Default::default()
    };
    create(tmp.path(), &opts, false).unwrap();

    let state = State::read_from(&tmp.path().join("state/nouserns")).unwrap();
    assert_eq!(state.get("USERNS"), None);
}

// --- validate_opaque_dirs tests ---

#[test]
fn test_validate_opaque_dirs_ok() {
    let dirs = vec!["/var".to_string(), "/opt".to_string(), "/tmp".to_string()];
    let result = validate_opaque_dirs(&dirs).unwrap();
    assert_eq!(result, vec!["/var", "/opt", "/tmp"]);
}

#[test]
fn test_validate_opaque_dirs_rejects_relative() {
    let dirs = vec!["var/log".to_string()];
    let err = validate_opaque_dirs(&dirs).unwrap_err();
    assert!(
        err.to_string().contains("absolute"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_validate_opaque_dirs_rejects_dotdot() {
    let dirs = vec!["/var/../etc".to_string()];
    let err = validate_opaque_dirs(&dirs).unwrap_err();
    assert!(err.to_string().contains(".."), "unexpected error: {err}");
}

#[test]
fn test_validate_opaque_dirs_normalizes() {
    let dirs = vec!["/var/".to_string(), "/opt///".to_string()];
    let result = validate_opaque_dirs(&dirs).unwrap();
    assert_eq!(result, vec!["/var", "/opt"]);
}

#[test]
fn test_validate_opaque_dirs_rejects_duplicates() {
    let dirs = vec!["/var".to_string(), "/var/".to_string()];
    let err = validate_opaque_dirs(&dirs).unwrap_err();
    assert!(
        err.to_string().contains("duplicate"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_validate_opaque_dirs_rejects_empty() {
    let dirs = vec!["".to_string()];
    let err = validate_opaque_dirs(&dirs).unwrap_err();
    assert!(err.to_string().contains("empty"), "unexpected error: {err}");
}

#[test]
fn test_validate_opaque_dirs_empty_list_ok() {
    let dirs: Vec<String> = vec![];
    let result = validate_opaque_dirs(&dirs).unwrap();
    assert!(result.is_empty());
}

#[test]
fn test_create_with_opaque_dirs() {
    let _lock = UMASK_LOCK.lock().unwrap();
    // Setting trusted.* xattrs requires root; skip if not root.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipping test_create_with_opaque_dirs: requires root");
        return;
    }
    let tmp = tmp();
    let opts = CreateOptions {
        name: Some("opaquebox".to_string()),
        opaque_dirs: vec!["/var".to_string(), "/opt/data".to_string()],
        ..Default::default()
    };
    let name = create(tmp.path(), &opts, false).unwrap();
    assert_eq!(name, "opaquebox");

    // Verify directories were created in the upper layer.
    let upper = tmp.path().join("containers/opaquebox/upper");
    assert!(upper.join("var").is_dir());
    assert!(upper.join("opt/data").is_dir());

    // Verify the trusted.overlay.opaque xattr is set.
    for dir in &["var", "opt/data"] {
        let path = upper.join(dir);
        let c_path = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        let c_name = CString::new("trusted.overlay.opaque").expect("static string literal");
        let mut buf = [0u8; 16];
        let size = unsafe {
            libc::lgetxattr(
                c_path.as_ptr(),
                c_name.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            )
        };
        assert!(size > 0, "lgetxattr failed for {}", path.display());
        assert_eq!(
            &buf[..size as usize],
            b"y",
            "xattr value mismatch for {dir}"
        );
    }
}

#[test]
fn test_create_with_security() {
    let _lock = UMASK_LOCK.lock().unwrap();
    let tmp = tmp();
    let security = crate::SecurityConfig {
        drop_caps: vec!["CAP_SYS_PTRACE".to_string()],
        no_new_privileges: true,
        read_only: true,
        system_call_filter: vec!["~@mount".to_string()],
        apparmor_profile: Some("sdme-container".to_string()),
        ..Default::default()
    };
    let opts = CreateOptions {
        name: Some("sectest".to_string()),
        security,
        ..Default::default()
    };
    let name = create(tmp.path(), &opts, false).unwrap();
    assert_eq!(name, "sectest");

    let state = State::read_from(&tmp.path().join("state/sectest")).unwrap();
    assert_eq!(state.get("DROP_CAPS"), Some("CAP_SYS_PTRACE"));
    assert_eq!(state.get("NO_NEW_PRIVS"), Some("yes"));
    assert_eq!(state.get("READ_ONLY"), Some("yes"));
    assert_eq!(state.get("SYSCALL_FILTER"), Some("~@mount"));
    assert_eq!(state.get("APPARMOR_PROFILE"), Some("sdme-container"));
    // ADD_CAPS not set: should not appear.
    assert_eq!(state.get("ADD_CAPS"), None);
}

#[test]
fn test_create_opaque_dirs_state() {
    let _lock = UMASK_LOCK.lock().unwrap();
    // Setting trusted.* xattrs requires root; skip if not root.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipping test_create_opaque_dirs_state: requires root");
        return;
    }
    let tmp = tmp();
    let opts = CreateOptions {
        name: Some("statebox".to_string()),
        opaque_dirs: vec!["/var".to_string(), "/opt".to_string()],
        ..Default::default()
    };
    create(tmp.path(), &opts, false).unwrap();

    let state = State::read_from(&tmp.path().join("state/statebox")).unwrap();
    assert_eq!(state.get("OPAQUE_DIRS"), Some("/var,/opt"));
}

// --- volumes_dir test ---

#[test]
fn test_volumes_dir() {
    let datadir = Path::new("/var/lib/sdme");
    let dir = volumes_dir(datadir, "mycontainer");
    assert_eq!(dir, PathBuf::from("/var/lib/sdme/volumes/mycontainer"));
}

// --- OCI volumes wiring in create ---

#[test]
fn test_create_with_oci_volumes() {
    let _lock = UMASK_LOCK.lock().unwrap();
    let tmp = tmp();
    // Create a rootfs with oci/apps/app/volumes
    let rootfs_dir = tmp.path().join("fs/myoci");
    fs::create_dir_all(rootfs_dir.join("oci/apps/app")).unwrap();
    fs::write(
        rootfs_dir.join("oci/apps/app/volumes"),
        "/var/lib/mysql\n/data\n",
    )
    .unwrap();

    let opts = CreateOptions {
        name: Some("voltest".to_string()),
        rootfs: Some("myoci".to_string()),
        oci_volumes: vec!["/var/lib/mysql".to_string(), "/data".to_string()],
        ..Default::default()
    };
    let name = create(tmp.path(), &opts, false).unwrap();
    assert_eq!(name, "voltest");

    // Check state has OCI_VOLUMES
    let state = State::read_from(&tmp.path().join("state/voltest")).unwrap();
    assert_eq!(state.get("OCI_VOLUMES"), Some("/var/lib/mysql,/data"));

    // Check bind entries were added
    let binds_str = state.get("BINDS").expect("BINDS should be set");
    assert!(binds_str.contains("/oci/apps/app/root/var/lib/mysql:rw"));
    assert!(binds_str.contains("/oci/apps/app/root/data:rw"));

    // Check volume directories were created
    let vol_base = tmp.path().join("volumes/voltest");
    assert!(vol_base.join("var-lib-mysql").exists());
    assert!(vol_base.join("data").exists());
}

#[test]
fn test_create_oci_env_merge() {
    let _lock = UMASK_LOCK.lock().unwrap();
    let tmp = tmp();
    // Create a rootfs with oci/apps/app/env containing an existing var.
    let rootfs_dir = tmp.path().join("fs/envoci");
    fs::create_dir_all(rootfs_dir.join("oci/apps/app")).unwrap();
    fs::write(rootfs_dir.join("oci/apps/app/env"), "EXISTING=value\n").unwrap();

    let opts = CreateOptions {
        name: Some("envtest".to_string()),
        rootfs: Some("envoci".to_string()),
        oci_envs: vec!["NEW_VAR=hello".to_string(), "OTHER=world".to_string()],
        ..Default::default()
    };
    let name = create(tmp.path(), &opts, false).unwrap();
    assert_eq!(name, "envtest");

    // Verify upper/oci/apps/app/env has both original and new vars.
    let upper_env = tmp.path().join("containers/envtest/upper/oci/apps/app/env");
    let content = fs::read_to_string(&upper_env).unwrap();
    assert!(content.contains("EXISTING=value"));
    assert!(content.contains("NEW_VAR=hello"));
    assert!(content.contains("OTHER=world"));
}

#[test]
fn test_create_oci_env_no_oci_rootfs() {
    let _lock = UMASK_LOCK.lock().unwrap();
    let tmp = tmp();
    // Create a rootfs without oci/env.
    let rootfs_dir = tmp.path().join("fs/plainfs");
    fs::create_dir_all(&rootfs_dir).unwrap();

    let opts = CreateOptions {
        name: Some("nooci".to_string()),
        rootfs: Some("plainfs".to_string()),
        oci_envs: vec!["FOO=bar".to_string()],
        ..Default::default()
    };
    let result = create(tmp.path(), &opts, false);
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("--oci-env requires an OCI app rootfs"),
        "unexpected error: {msg}"
    );
}

// --- parse_nspid tests ---

#[test]
fn test_parse_nspid_app_process() {
    // App process inside isolate: host PID 12345, container PID 67, nested PID 1
    let status = "Name:\tredis-server\nNSpid:\t12345\t67\t1\nPPid:\t12300\n";
    let result = exec::parse_nspid_public(status).unwrap();
    assert_eq!(result, vec![12345, 67, 1]);
}

#[test]
fn test_parse_nspid_isolate_parent() {
    // Isolate parent: host PID 12300, container PID 55 (only 2 entries)
    let status = "Name:\tsdme-isolate\nNSpid:\t12300\t55\nPPid:\t1\n";
    let result = exec::parse_nspid_public(status).unwrap();
    assert_eq!(result, vec![12300, 55]);
}

#[test]
fn test_parse_nspid_missing() {
    let status = "Name:\tinit\nPid:\t1\nPPid:\t0\n";
    assert!(exec::parse_nspid_public(status).is_none());
}

#[test]
fn test_parse_nspid_single_pid() {
    // Host-level process with a single NSpid entry
    let status = "Name:\tbash\nNSpid:\t9999\nPPid:\t1\n";
    let result = exec::parse_nspid_public(status).unwrap();
    assert_eq!(result, vec![9999]);
}

// --- find_app_pid tests (using mock cgroup/proc data) ---

#[test]
fn test_find_app_pid_selects_nested_pid1() {
    let tmp = tmp();
    let cgroup_dir = tmp.path().join("cgroup");
    fs::create_dir_all(&cgroup_dir).unwrap();

    // Two PIDs in the cgroup: the isolate parent and the app process.
    // We use fake /proc entries under a temp dir, but find_app_pid reads
    // real /proc, so we test parse_nspid logic directly here and verify
    // the selection logic.
    //
    // Isolate parent: NSpid has 2 entries (host + container)
    let isolate_status = "Name:\tsdme-isolate\nNSpid:\t100\t50\nPPid:\t1\n";
    // App process: NSpid has 3 entries, last is 1
    let app_status = "Name:\tredis-server\nNSpid:\t101\t51\t1\nPPid:\t100\n";

    // Verify our selection logic: only the app has 3+ entries with last == 1
    let isolate_nspids = exec::parse_nspid_public(isolate_status).unwrap();
    assert_eq!(isolate_nspids.len(), 2);
    assert_ne!(*isolate_nspids.last().unwrap(), 1u32);

    let app_nspids = exec::parse_nspid_public(app_status).unwrap();
    assert!(app_nspids.len() >= 3);
    assert_eq!(*app_nspids.last().unwrap(), 1u32);
}

// --- OS detection tests ---

#[test]
fn test_list_os_host_rootfs_fallback() {
    // Stopped host-rootfs container with no os-release in merged/ or upper/.
    // Cascade falls to detect_distro(Path::new("/")), the host's os-release.
    // On hosts without os-release (rare but possible), falls back to "unknown".
    let tmp = tmp();
    create_dummy_container(&tmp, "hostbox");
    let infos = list(tmp.path()).unwrap();
    let info = infos.iter().find(|i| i.name == "hostbox").unwrap();
    assert!(!info.os.is_empty(), "os should never be empty");
}

#[test]
fn test_list_os_unknown_when_no_os_release() {
    // Imported rootfs container with no os-release anywhere: should show "unknown".
    let tmp = tmp();
    create_dummy_container_with_rootfs(&tmp, "bare", "emptyfs");
    // Create the rootfs dir but don't write os-release.
    fs::create_dir_all(tmp.path().join("fs/emptyfs")).unwrap();
    let infos = list(tmp.path()).unwrap();
    let info = infos.iter().find(|i| i.name == "bare").unwrap();
    assert_eq!(info.os, "unknown");
}

#[test]
fn test_list_os_merged_takes_priority() {
    // os-release in merged/ should win over upper/ and rootfs.
    let tmp = tmp();
    create_dummy_container(&tmp, "mergedbox");
    let merged = tmp.path().join("containers/mergedbox/merged");
    write_os_release(&merged, "PRETTY_NAME=\"Merged Distro\"\n");
    let upper = tmp.path().join("containers/mergedbox/upper");
    write_os_release(&upper, "PRETTY_NAME=\"Upper Distro\"\n");

    let infos = list(tmp.path()).unwrap();
    let info = infos.iter().find(|i| i.name == "mergedbox").unwrap();
    assert_eq!(info.os, "Merged Distro");
}

#[test]
fn test_list_os_imported_rootfs_distros() {
    let tmp = tmp();

    let distros = [
        (
            "deb",
            "mydebian",
            "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"",
        ),
        ("ubu", "myubuntu", "PRETTY_NAME=\"Ubuntu 24.04 LTS\""),
        ("fed", "myfedora", "PRETTY_NAME=\"Fedora Linux 41\""),
        ("cos", "mycentos", "PRETTY_NAME=\"CentOS Stream 9\""),
        ("alm", "myalma", "PRETTY_NAME=\"AlmaLinux 9.3\""),
        ("arc", "myarch", "PRETTY_NAME=\"Arch Linux\""),
        ("cch", "mycachyos", "PRETTY_NAME=\"CachyOS\""),
    ];

    for (cname, rootfs_name, os_release) in &distros {
        create_dummy_container_with_rootfs(&tmp, cname, rootfs_name);
        let rootfs_dir = tmp.path().join("fs").join(rootfs_name);
        write_os_release(&rootfs_dir, &format!("{os_release}\n"));
    }

    let infos = list(tmp.path()).unwrap();
    for (cname, _, os_release) in &distros {
        let info = infos.iter().find(|i| i.name == *cname).unwrap();
        // Extract the value from PRETTY_NAME="..."
        let expected = os_release
            .strip_prefix("PRETTY_NAME=\"")
            .unwrap()
            .strip_suffix('"')
            .unwrap();
        assert_eq!(info.os, expected, "os mismatch for container {cname}");
    }
}

#[test]
fn test_list_os_cascade_priority() {
    let tmp = tmp();
    let rootfs_name = "testfs";
    create_dummy_container_with_rootfs(&tmp, "cascade", rootfs_name);

    let merged = tmp.path().join("containers/cascade/merged");
    let upper = tmp.path().join("containers/cascade/upper");
    let rootfs_dir = tmp.path().join("fs").join(rootfs_name);

    write_os_release(&merged, "PRETTY_NAME=\"Merged OS\"\n");
    write_os_release(&upper, "PRETTY_NAME=\"Upper OS\"\n");
    write_os_release(&rootfs_dir, "PRETTY_NAME=\"Rootfs OS\"\n");

    // merged/ wins
    let infos = list(tmp.path()).unwrap();
    let info = infos.iter().find(|i| i.name == "cascade").unwrap();
    assert_eq!(info.os, "Merged OS");

    // Remove merged os-release, upper/ wins
    fs::remove_file(merged.join("etc/os-release")).unwrap();
    let infos = list(tmp.path()).unwrap();
    let info = infos.iter().find(|i| i.name == "cascade").unwrap();
    assert_eq!(info.os, "Upper OS");

    // Remove upper os-release, rootfs wins
    fs::remove_file(upper.join("etc/os-release")).unwrap();
    let infos = list(tmp.path()).unwrap();
    let info = infos.iter().find(|i| i.name == "cascade").unwrap();
    assert_eq!(info.os, "Rootfs OS");
}
