//! Transient unit properties for ephemeral containers.
//!
//! An ephemeral container's service carries the same settings as the
//! `sdme@.service` template plus the per-container drop-ins, expressed
//! as D-Bus properties for `StartTransientUnit`. Differences from the
//! template are deliberate and noted inline.

use zbus::zvariant::Value;

use super::dbus::UnitProperty;
use super::units::{start_timeout_secs, ExecCommand, NspawnPlan};
use crate::ephemeral::HealthCheck;
use crate::ResourceLimits;

const USEC_PER_SEC: u64 = 1_000_000;

/// Inputs for an ephemeral container's transient service.
pub(super) struct ServiceSpec<'a> {
    pub name: &'a str,
    pub plan: &'a NspawnPlan,
    pub limits: &'a ResourceLimits,
    pub tasks_max: u32,
    /// Boot timeout in seconds.
    pub boot_timeout: u64,
    /// Host systemd major version (gates `DelegateSubgroup=`).
    pub systemd_version: u32,
    /// Teardown command appended to `ExecStopPost`.
    pub teardown: ExecCommand,
    /// Session scope the service is bound to (session trigger).
    pub session_scope: Option<&'a str>,
}

fn exec_value(cmds: &[ExecCommand]) -> Value<'static> {
    let v: Vec<(String, Vec<String>, bool)> = cmds
        .iter()
        .map(|c| (c.path().to_string(), c.argv(), c.ignore_failure))
        .collect();
    Value::from(v)
}

fn strings(v: &[&str]) -> Value<'static> {
    Value::from(v.iter().map(|s| s.to_string()).collect::<Vec<_>>())
}

/// Properties for `sdme-ephemeral@NAME.service`.
pub(super) fn service_properties(spec: &ServiceSpec<'_>) -> Vec<UnitProperty> {
    let plan = spec.plan;
    let exec = plan.exec();
    let mut stop_post = exec.stop_post;
    // Runs after the unmounts: teardown refuses to delete while the root
    // is still mounted.
    stop_post.push(spec.teardown.clone());

    let mut after = vec![
        "network.target",
        "local-fs.target",
        "systemd-machined.service",
        "dbus.service",
    ];
    if let Some(scope) = spec.session_scope {
        after.push(scope);
    }

    // Mirrors unit_template() and the drop-in, minus two things:
    // RestartForceExitStatus=133 and the restart policy. Teardown runs in
    // ExecStopPost, so a restart (including a reboot inside the container)
    // cannot bring the container back and ends it instead.
    let mut props: Vec<UnitProperty> = vec![
        (
            "Description",
            Value::from(format!("sdme ephemeral container {}", spec.name)),
        ),
        ("After", strings(&after)),
        ("Wants", strings(&["systemd-machined.service"])),
        ("Type", Value::from("notify")),
        (
            "SuccessExitStatus",
            Value::from((vec![133i32], Vec::<i32>::new())),
        ),
        ("KillMode", Value::from("mixed")),
        // nspawn runs with --keep-unit, so the container lives in this
        // unit's cgroup; place it under machine.slice like the template.
        ("Slice", Value::from("machine.slice")),
        ("Delegate", Value::from(true)),
        ("TasksMax", Value::from(spec.tasks_max as u64)),
        ("DevicePolicy", Value::from("closed")),
        (
            "DeviceAllow",
            Value::from(vec![
                ("/dev/net/tun".to_string(), "rwm".to_string()),
                ("char-pts".to_string(), "rw".to_string()),
            ]),
        ),
        (
            "TimeoutStartUSec",
            Value::from(start_timeout_secs(spec.boot_timeout) * USEC_PER_SEC),
        ),
        // A failed transient unit would otherwise linger and block a new
        // container with the same name.
        ("CollectMode", Value::from("inactive-or-failed")),
        ("ExecStartPre", exec_value(&exec.start_pre)),
        ("ExecStart", exec_value(std::slice::from_ref(&exec.start))),
        ("ExecStopPost", exec_value(&stop_post)),
    ];
    if spec.systemd_version >= 256 {
        props.push(("DelegateSubgroup", Value::from("supervisor")));
    }
    if let Some(scope) = spec.session_scope {
        props.push(("BindsTo", strings(&[scope])));
    }
    if let Some(pool) = &plan.pool_mount {
        props.push(("RequiresMountsFor", strings(&[pool])));
    }
    if let Some(stop) = plan.stop_timeout {
        props.push(("TimeoutStopUSec", Value::from(stop * USEC_PER_SEC)));
    }
    if let Some(level) = &plan.systemd_log_level {
        props.push((
            "Environment",
            Value::from(vec![format!("SYSTEMD_LOG_LEVEL={level}")]),
        ));
    }
    if let Some(profile) = &plan.apparmor_profile {
        props.push(("AppArmorProfile", Value::from((false, profile.clone()))));
    }
    for (key, value) in spec.limits.transient_properties() {
        props.push((key, Value::from(value)));
    }
    props
}

/// Properties for the session scope holding the `sdme new` client.
pub(super) fn session_scope_properties(name: &str, pid: u32) -> Vec<UnitProperty> {
    vec![
        (
            "Description",
            Value::from(format!("sdme session for ephemeral container {name}")),
        ),
        ("PIDs", Value::from(vec![pid])),
        ("CollectMode", Value::from("inactive-or-failed")),
    ]
}

/// Properties for `sdme-health@NAME.timer`.
///
/// The first check runs one interval after the start period, then every
/// interval. The timer is bound to the container unit, so it goes away
/// with the container. Timer bases are named `On*Sec` when set, even
/// though `systemctl show` prints them as `On*USec`.
pub(super) fn health_timer_properties(
    name: &str,
    container_unit: &str,
    check: &HealthCheck,
) -> Vec<UnitProperty> {
    let first = (check.start_period + check.interval) * USEC_PER_SEC;
    let every = check.interval * USEC_PER_SEC;
    vec![
        (
            "Description",
            Value::from(format!("sdme health check timer for {name}")),
        ),
        ("BindsTo", strings(&[container_unit])),
        ("After", strings(&[container_unit])),
        (
            "TimersMonotonic",
            Value::from(vec![
                ("OnActiveSec".to_string(), first),
                ("OnUnitActiveSec".to_string(), every),
            ]),
        ),
        ("AccuracyUSec", Value::from(USEC_PER_SEC)),
        ("RemainAfterElapse", Value::from(false)),
        ("CollectMode", Value::from("inactive-or-failed")),
    ]
}

/// Properties for the oneshot `sdme-health@NAME.service`.
pub(super) fn health_service_properties(name: &str, check: ExecCommand) -> Vec<UnitProperty> {
    vec![
        (
            "Description",
            Value::from(format!("sdme health check for {name}")),
        ),
        ("Type", Value::from("oneshot")),
        ("ExecStart", exec_value(&[check])),
        ("CollectMode", Value::from("inactive-or-failed")),
    ]
}
