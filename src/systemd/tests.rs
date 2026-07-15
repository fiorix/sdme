use std::path::PathBuf;

use super::*;
use crate::containers::{create, CreateOptions};
use crate::testutil::TempDataDir;
use crate::SecurityConfig;

fn tmp() -> TempDataDir {
    TempDataDir::new("systemd")
}

#[test]
fn test_service_name() {
    assert_eq!(service_name("mybox"), "sdme@mybox.service");
}

fn test_paths() -> UnitPaths {
    UnitPaths {
        nspawn: PathBuf::from("/usr/bin/systemd-nspawn"),
        mount: PathBuf::from("/usr/bin/mount"),
        umount: PathBuf::from("/usr/bin/umount"),
        nsenter: PathBuf::from("/usr/bin/nsenter"),
    }
}

#[test]
fn test_unit_template() {
    // systemd 259: DelegateSubgroup= is supported and should be emitted.
    let template = unit_template(16384, 60, 259);
    assert!(template.contains("Description=sdme container %i"));
    assert!(template.contains("Type=notify"));
    assert!(!template.contains("Type=simple"));
    assert!(template.contains("RestartForceExitStatus=133"));
    assert!(template.contains("SuccessExitStatus=133"));
    assert!(template.contains("TimeoutStartSec=90s"));
    assert!(template.contains("ExecStart=/bin/false"));
    assert!(template.contains("KillMode=mixed"));
    assert!(template.contains("Delegate=yes"));
    assert!(template.contains("TasksMax=16384"));
    assert!(template.contains("DevicePolicy=closed"));
    assert!(template.contains("DeviceAllow=/dev/net/tun rwm"));
    assert!(template.contains("DeviceAllow=char-pts rw"));
    // --keep-unit places the container in this service unit's cgroup, so the
    // unit is grouped under machine.slice with a supervisor subgroup (256+).
    assert!(template.contains("Slice=machine.slice"));
    assert!(template.contains("DelegateSubgroup=supervisor"));
    // Ordering hygiene: container starts after its registration dependencies.
    assert!(template
        .contains("After=network.target local-fs.target systemd-machined.service dbus.service"));
    assert!(template.contains("Wants=systemd-machined.service"));
    // Restart policy is opt-in per container (Stage C), never in the template,
    // and the start-rate limiter is never disabled.
    assert!(!template.contains("StartLimitIntervalSec"));
    assert!(!template.contains("\nRestart="));
    // Template should NOT contain per-container details.
    assert!(!template.contains("EnvironmentFile"));
    assert!(!template.contains("systemd-nspawn"));
    assert!(!template.contains("overlay"));
}

#[test]
fn test_unit_template_custom_boot_timeout() {
    let template = unit_template(16384, 300, 259);
    // 300 + 30 = 330
    assert!(template.contains("TimeoutStartSec=330s"));
}

#[test]
fn test_unit_template_old_systemd_omits_delegate_subgroup() {
    // systemd 255 predates DelegateSubgroup=; it must not be emitted, but the
    // rest of the keep-unit layout (Slice=machine.slice) still applies.
    let template = unit_template(16384, 60, 255);
    assert!(template.contains("Slice=machine.slice"));
    assert!(!template.contains("DelegateSubgroup"));
}

#[test]
fn test_restart_directives() {
    // on-failure is the only supported policy; it emits Restart= + RestartSec=.
    assert_eq!(
        units::restart_directives(Some("on-failure"), 2),
        vec![
            "Restart=on-failure".to_string(),
            "RestartSec=2s".to_string()
        ]
    );
    assert_eq!(
        units::restart_directives(Some("on-failure"), 5),
        vec![
            "Restart=on-failure".to_string(),
            "RestartSec=5s".to_string()
        ]
    );
    // Default, unset, unsupported (always), and tampered tokens emit nothing
    // (whitelist guards against a hand-edited state file injecting arbitrary
    // [Service] directives and against the stop-unsafe `always` policy).
    assert!(units::restart_directives(Some("no"), 2).is_empty());
    assert!(units::restart_directives(Some("always"), 2).is_empty());
    assert!(units::restart_directives(None, 2).is_empty());
    assert!(units::restart_directives(Some("on-failure\nExecStart=/evil"), 2).is_empty());
}

#[test]
fn test_nspawn_dropin_host_rootfs() {
    let paths = test_paths();
    let args = vec!["--resolv-conf=auto".to_string()];
    let content = nspawn_dropin(&DropinConfig {
        backend: crate::storage::Backend::Overlay,
        datadir: "/var/lib/sdme",
        name: "mybox",
        root_dir: "/var/lib/sdme/containers/mybox/merged",
        pool_mount: None,
        lowerdir: "/",
        paths: &paths,
        nspawn_args: &args,
        service_directives: &[],
        submounts: &[],
        pod_netns: None,
    });
    assert!(content.contains("[Service]"));
    assert!(content.contains("ExecStart=\n"));
    assert!(content.contains("lowerdir=/,upperdir=/var/lib/sdme/containers/mybox/upper"));
    assert!(content.contains("workdir=/var/lib/sdme/containers/mybox/work"));
    assert!(content.contains("/var/lib/sdme/containers/mybox/merged"));
    assert!(content.contains("--machine=mybox"));
    assert!(content.contains("--keep-unit"));
    assert!(content.contains("--resolv-conf=auto"));
    assert!(content.contains("--boot"));
    assert!(content.contains("/usr/bin/systemd-nspawn"));
    assert!(content.contains("/usr/bin/mount"));
    assert!(content.contains("/usr/bin/umount"));
}

#[test]
fn test_nspawn_dropin_with_userns() {
    let paths = test_paths();
    let args = vec![
        "--resolv-conf=auto".to_string(),
        "--private-users=pick".to_string(),
        "--private-users-ownership=auto".to_string(),
    ];
    let content = nspawn_dropin(&DropinConfig {
        backend: crate::storage::Backend::Overlay,
        datadir: "/var/lib/sdme",
        name: "mybox",
        root_dir: "/var/lib/sdme/containers/mybox/merged",
        pool_mount: None,
        lowerdir: "/",
        paths: &paths,
        nspawn_args: &args,
        service_directives: &[],
        submounts: &[],
        pod_netns: None,
    });
    assert!(content.contains("--private-users=pick"));
    assert!(content.contains("--private-users-ownership=auto"));
    assert!(content.contains("--boot"));
}

#[test]
fn test_nspawn_dropin_with_pod_netns() {
    let paths = test_paths();
    let args = vec![
        "--resolv-conf=auto".to_string(),
        "--private-users=pick".to_string(),
        "--private-users-ownership=auto".to_string(),
    ];
    let content = nspawn_dropin(&DropinConfig {
        backend: crate::storage::Backend::Overlay,
        datadir: "/var/lib/sdme",
        name: "podbox",
        root_dir: "/var/lib/sdme/containers/podbox/merged",
        pool_mount: None,
        lowerdir: "/",
        paths: &paths,
        nspawn_args: &args,
        service_directives: &[],
        submounts: &[],
        pod_netns: Some("/run/sdme/pods/mypod/ns/net"),
    });
    // nsenter should prefix the nspawn command.
    assert!(content.contains(
        "ExecStart=/usr/bin/nsenter --net=/run/sdme/pods/mypod/ns/net -- /usr/bin/systemd-nspawn"
    ));
    // userns flags should still be present.
    assert!(content.contains("--private-users=pick"));
    assert!(content.contains("--boot"));
    // --network-namespace-path should NOT appear.
    assert!(!content.contains("--network-namespace-path"));
}

#[test]
fn test_nspawn_dropin_without_pod_netns() {
    let paths = test_paths();
    let args = vec!["--resolv-conf=auto".to_string()];
    let content = nspawn_dropin(&DropinConfig {
        backend: crate::storage::Backend::Overlay,
        datadir: "/var/lib/sdme",
        name: "mybox",
        root_dir: "/var/lib/sdme/containers/mybox/merged",
        pool_mount: None,
        lowerdir: "/",
        paths: &paths,
        nspawn_args: &args,
        service_directives: &[],
        submounts: &[],
        pod_netns: None,
    });
    // Without a pod netns, nspawn is launched directly (no nsenter).
    assert!(!content.contains("nsenter"));
    assert!(content.contains("ExecStart=/usr/bin/systemd-nspawn"));
}

#[test]
fn test_nspawn_dropin_explicit_rootfs() {
    let paths = test_paths();
    let args = vec!["--resolv-conf=auto".to_string()];
    let content = nspawn_dropin(&DropinConfig {
        backend: crate::storage::Backend::Overlay,
        datadir: "/var/lib/sdme",
        name: "ubox",
        root_dir: "/var/lib/sdme/containers/ubox/merged",
        pool_mount: None,
        lowerdir: "/var/lib/sdme/fs/ubuntu",
        paths: &paths,
        nspawn_args: &args,
        service_directives: &[],
        submounts: &[],
        pod_netns: None,
    });
    assert!(content
        .contains("lowerdir=/var/lib/sdme/fs/ubuntu,upperdir=/var/lib/sdme/containers/ubox/upper"));
}

#[test]
fn test_nspawn_dropin_with_binds_and_envs() {
    let paths = test_paths();
    let args = vec![
        "--resolv-conf=auto".to_string(),
        "--bind=/data:/data".to_string(),
        "--bind-ro=/logs:/logs".to_string(),
        "--setenv=FOO=bar".to_string(),
    ];
    let content = nspawn_dropin(&DropinConfig {
        backend: crate::storage::Backend::Overlay,
        datadir: "/var/lib/sdme",
        name: "mybox",
        root_dir: "/var/lib/sdme/containers/mybox/merged",
        pool_mount: None,
        lowerdir: "/",
        paths: &paths,
        nspawn_args: &args,
        service_directives: &[],
        submounts: &[],
        pod_netns: None,
    });
    assert!(content.contains("    --bind=/data:/data \\\n"));
    assert!(content.contains("    --bind-ro=/logs:/logs \\\n"));
    assert!(content.contains("    --setenv=FOO=bar \\\n"));
}

#[test]
fn test_nspawn_dropin_escapes_spaces() {
    let paths = test_paths();
    let args = vec![
        "--resolv-conf=auto".to_string(),
        "--setenv=MSG=hello world".to_string(),
    ];
    let content = nspawn_dropin(&DropinConfig {
        backend: crate::storage::Backend::Overlay,
        datadir: "/var/lib/sdme",
        name: "mybox",
        root_dir: "/var/lib/sdme/containers/mybox/merged",
        pool_mount: None,
        lowerdir: "/",
        paths: &paths,
        nspawn_args: &args,
        service_directives: &[],
        submounts: &[],
        pod_netns: None,
    });
    assert!(content.contains("\"--setenv=MSG=hello world\""));
}

#[test]
fn test_nspawn_dropin_btrfs() {
    let paths = test_paths();
    let args = vec!["--resolv-conf=auto".to_string()];
    let content = nspawn_dropin(&DropinConfig {
        backend: crate::storage::Backend::Btrfs,
        datadir: "/var/lib/sdme",
        name: "btrbox",
        root_dir: "/var/lib/sdme/pool/containers/btrbox",
        pool_mount: Some("/var/lib/sdme/pool"),
        lowerdir: "/var/lib/sdme/fs/debian",
        paths: &paths,
        nspawn_args: &args,
        service_directives: &[],
        submounts: &[],
        pod_netns: None,
    });
    // btrfs uses no overlay root mount and no ExecStartPre/ExecStopPost.
    assert!(!content.contains("-t overlay"));
    assert!(!content.contains("ExecStartPre="));
    assert!(!content.contains("ExecStopPost="));
    // nspawn boots the subvolume directly, after the pool mount.
    assert!(content.contains("--directory=/var/lib/sdme/pool/containers/btrbox \\"));
    assert!(content.contains("RequiresMountsFor=/var/lib/sdme/pool"));
}

#[test]
fn test_escape_exec_arg_safe() {
    assert_eq!(units::escape_exec_arg("--boot"), "--boot");
    assert_eq!(units::escape_exec_arg("--bind=/a:/b"), "--bind=/a:/b");
}

#[test]
fn test_escape_exec_arg_spaces() {
    assert_eq!(
        units::escape_exec_arg("--setenv=FOO=hello world"),
        "\"--setenv=FOO=hello world\""
    );
}

#[test]
fn test_escape_exec_arg_quotes_and_backslashes() {
    assert_eq!(
        units::escape_exec_arg("--setenv=MSG=say \"hi\""),
        "\"--setenv=MSG=say \\\"hi\\\"\""
    );
    assert_eq!(
        units::escape_exec_arg("--setenv=PATH=C:\\foo"),
        "\"--setenv=PATH=C:\\\\foo\""
    );
}

#[test]
fn test_dropin_dir_path() {
    let dir = units::dropin_dir("mybox");
    assert_eq!(
        dir,
        PathBuf::from("/etc/systemd/system/sdme@mybox.service.d")
    );
}

#[test]
fn test_create_with_limits_state() {
    let tmp = tmp();
    let limits = crate::ResourceLimits {
        memory: Some("1G".to_string()),
        cpus: Some("2".to_string()),
        cpu_weight: Some("50".to_string()),
        disk: None,
    };
    let opts = CreateOptions {
        name: Some("limitbox".to_string()),
        limits,
        ..Default::default()
    };
    create(tmp.path(), &opts, false).unwrap();

    // Verify limits are persisted in state file.
    let state = crate::State::read_from(&tmp.path().join("state/limitbox")).unwrap();
    let restored = crate::ResourceLimits::from_state(&state);
    assert_eq!(restored.memory.as_deref(), Some("1G"));
    assert_eq!(restored.cpus.as_deref(), Some("2"));
    assert_eq!(restored.cpu_weight.as_deref(), Some("50"));
}

#[test]
fn test_nspawn_dropin_with_security() {
    let paths = test_paths();
    let args = vec![
        "--resolv-conf=auto".to_string(),
        "--drop-capability=CAP_SYS_PTRACE".to_string(),
        "--drop-capability=CAP_NET_RAW".to_string(),
        "--no-new-privileges=yes".to_string(),
        "--read-only".to_string(),
        "--system-call-filter=@system-service".to_string(),
        "--system-call-filter=~@mount".to_string(),
    ];
    let content = nspawn_dropin(&DropinConfig {
        backend: crate::storage::Backend::Overlay,
        datadir: "/var/lib/sdme",
        name: "secbox",
        root_dir: "/var/lib/sdme/containers/secbox/merged",
        pool_mount: None,
        lowerdir: "/",
        paths: &paths,
        nspawn_args: &args,
        service_directives: &[],
        submounts: &[],
        pod_netns: None,
    });
    assert!(content.contains("--drop-capability=CAP_SYS_PTRACE"));
    assert!(content.contains("--drop-capability=CAP_NET_RAW"));
    assert!(content.contains("--no-new-privileges=yes"));
    assert!(content.contains("--read-only"));
    assert!(content.contains("--system-call-filter=@system-service"));
    assert!(content.contains("--system-call-filter=~@mount"));
    // AppArmor should NOT appear in nspawn args.
    assert!(!content.contains("AppArmor"));
}

#[test]
fn test_nspawn_dropin_with_apparmor() {
    let paths = test_paths();
    let args = vec!["--resolv-conf=auto".to_string()];
    let service_directives = vec!["AppArmorProfile=sdme-default".to_string()];
    let content = nspawn_dropin(&DropinConfig {
        backend: crate::storage::Backend::Overlay,
        datadir: "/var/lib/sdme",
        name: "aabox",
        root_dir: "/var/lib/sdme/containers/aabox/merged",
        pool_mount: None,
        lowerdir: "/",
        paths: &paths,
        nspawn_args: &args,
        service_directives: &service_directives,
        submounts: &[],
        pod_netns: None,
    });
    // AppArmor directive should appear in the [Service] section.
    assert!(content.contains("AppArmorProfile=sdme-default"));
    // It should be before ExecStart=.
    let aa_pos = content.find("AppArmorProfile=sdme-default").unwrap();
    let exec_pos = content.find("ExecStart=\n").unwrap();
    assert!(
        aa_pos < exec_pos,
        "AppArmorProfile should appear before ExecStart="
    );
}

#[test]
fn test_nspawn_dropin_with_submounts() {
    let paths = test_paths();
    let args = vec!["--resolv-conf=auto".to_string()];
    let submounts = vec![
        "home".to_string(),
        "data".to_string(),
        "data/deep".to_string(),
    ];
    let content = nspawn_dropin(&DropinConfig {
        backend: crate::storage::Backend::Overlay,
        datadir: "/var/lib/sdme",
        name: "mybox",
        root_dir: "/var/lib/sdme/containers/mybox/merged",
        pool_mount: None,
        lowerdir: "/",
        paths: &paths,
        nspawn_args: &args,
        service_directives: &[],
        submounts: &submounts,
        pod_netns: None,
    });

    // Root overlay is still present.
    assert!(content.contains("lowerdir=/,upperdir=/var/lib/sdme/containers/mybox/upper"));

    // Per-submount overlays appear after root mount.
    assert!(content.contains("ExecStartPre=-/usr/bin/mount -t overlay overlay \\\n    -o lowerdir=/home,upperdir=/var/lib/sdme/containers/mybox/submounts/home/upper,workdir=/var/lib/sdme/containers/mybox/submounts/home/work \\\n    /var/lib/sdme/containers/mybox/merged/home\n"));
    assert!(content.contains("ExecStartPre=-/usr/bin/mount -t overlay overlay \\\n    -o lowerdir=/data,upperdir=/var/lib/sdme/containers/mybox/submounts/data/upper,workdir=/var/lib/sdme/containers/mybox/submounts/data/work \\\n    /var/lib/sdme/containers/mybox/merged/data\n"));
    assert!(content.contains(
        "lowerdir=/data/deep,upperdir=/var/lib/sdme/containers/mybox/submounts/data/deep/upper"
    ));

    // Submount unmounts in reverse order (deepest first), before root unmount.
    let stop_section: Vec<&str> = content
        .lines()
        .filter(|l| l.starts_with("ExecStopPost"))
        .collect();
    assert_eq!(stop_section.len(), 4); // 3 submounts + 1 root
    assert!(stop_section[0].contains("merged/data/deep"));
    assert!(stop_section[1].contains("merged/data"));
    assert!(stop_section[2].contains("merged/home"));
    assert!(stop_section[3].ends_with("merged"));
}

#[test]
fn test_create_with_security_state() {
    let tmp = tmp();
    let security = SecurityConfig {
        drop_caps: vec!["CAP_SYS_PTRACE".to_string(), "CAP_NET_RAW".to_string()],
        add_caps: vec!["CAP_NET_ADMIN".to_string()],
        no_new_privileges: true,
        read_only: true,
        system_call_filter: vec!["@system-service".to_string(), "~@mount".to_string()],
        apparmor_profile: Some("sdme-default".to_string()),
        ..Default::default()
    };
    let opts = CreateOptions {
        name: Some("secbox".to_string()),
        security,
        ..Default::default()
    };
    create(tmp.path(), &opts, false).unwrap();

    let state = crate::State::read_from(&tmp.path().join("state/secbox")).unwrap();
    let restored = SecurityConfig::from_state(&state);
    assert_eq!(restored.drop_caps, vec!["CAP_SYS_PTRACE", "CAP_NET_RAW"]);
    assert_eq!(restored.add_caps, vec!["CAP_NET_ADMIN"]);
    assert!(restored.no_new_privileges);
    assert!(restored.read_only);
    assert_eq!(
        restored.system_call_filter,
        vec!["@system-service", "~@mount"]
    );
    assert_eq!(restored.apparmor_profile.as_deref(), Some("sdme-default"));
}
