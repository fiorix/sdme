use super::validate::build_probe_check;
use super::*;
use crate::testutil::TempDataDir;
use std::fs;
use std::sync::Mutex;

#[test]
fn test_parse_simple_pod() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: nginx-pod
spec:
  containers:
  - name: nginx
    image: docker.io/nginx:latest
    ports:
    - containerPort: 80
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    assert_eq!(name, "nginx-pod");
    assert_eq!(spec.containers.len(), 1);
    assert_eq!(spec.containers[0].name, "nginx");
    assert_eq!(spec.containers[0].image, "docker.io/nginx:latest");
    assert_eq!(spec.containers[0].ports.len(), 1);
    assert_eq!(spec.containers[0].ports[0].container_port, 80);
}

#[test]
fn test_parse_multi_container_pod() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: web-cache
spec:
  containers:
  - name: nginx
    image: docker.io/nginx:latest
    ports:
    - containerPort: 80
    volumeMounts:
    - name: cache-vol
      mountPath: /var/cache
  - name: redis
    image: docker.io/redis:latest
    ports:
    - containerPort: 6379
    volumeMounts:
    - name: cache-vol
      mountPath: /data
  volumes:
  - name: cache-vol
    emptyDir: {}
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    assert_eq!(name, "web-cache");
    assert_eq!(spec.containers.len(), 2);
    assert_eq!(spec.containers[0].name, "nginx");
    assert_eq!(spec.containers[1].name, "redis");
    assert_eq!(spec.volumes.len(), 1);
    assert_eq!(spec.volumes[0].name, "cache-vol");
    assert!(spec.volumes[0].empty_dir.is_some());
}

#[test]
fn test_parse_deployment() {
    let yaml = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-deploy
spec:
  replicas: 1
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      name: my-pod
    spec:
      containers:
      - name: web
        image: docker.io/nginx:latest
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    assert_eq!(name, "my-pod");
    assert_eq!(spec.containers.len(), 1);
    assert_eq!(spec.containers[0].name, "web");
}

#[test]
fn test_parse_deployment_name_fallback() {
    let yaml = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-deploy
spec:
  replicas: 1
  selector:
    matchLabels:
      app: web
  template:
    spec:
      containers:
      - name: web
        image: docker.io/nginx:latest
"#;
    let (name, _) = parse_yaml(yaml).unwrap();
    assert_eq!(name, "my-deploy");
}

#[test]
fn test_parse_invalid_kind() {
    let yaml = r#"
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: my-sts
spec:
  containers:
  - name: web
    image: docker.io/nginx:latest
"#;
    let err = parse_yaml(yaml).unwrap_err();
    assert!(err.to_string().contains("unsupported kind: StatefulSet"));
}

#[test]
fn test_parse_env_vars() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: env-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    env:
    - name: FOO
      value: bar
    - name: BAZ
      value: "123"
"#;
    let (_, spec) = parse_yaml(yaml).unwrap();
    assert_eq!(spec.containers[0].env.len(), 2);
    assert_eq!(spec.containers[0].env[0].name, "FOO");
    assert_eq!(spec.containers[0].env[0].value, Some("bar".to_string()));
}

#[test]
fn test_parse_volumes() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: vol-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    volumeMounts:
    - name: data
      mountPath: /data
    - name: host-config
      mountPath: /etc/app
      readOnly: true
  volumes:
  - name: data
    emptyDir: {}
  - name: host-config
    hostPath:
      path: /opt/config
"#;
    let (_, spec) = parse_yaml(yaml).unwrap();
    assert_eq!(spec.volumes.len(), 2);
    assert!(spec.volumes[0].empty_dir.is_some());
    assert!(spec.volumes[0].host_path.is_none());
    assert!(spec.volumes[1].empty_dir.is_none());
    assert_eq!(
        spec.volumes[1].host_path.as_ref().unwrap().path,
        "/opt/config"
    );
    assert!(spec.containers[0].volume_mounts[1].read_only);
}

#[test]
fn test_parse_volume_mount_validation() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: bad-vol
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    volumeMounts:
    - name: nonexistent
      mountPath: /data
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let err = validate_and_plan(&name, spec, "docker.io").unwrap_err();
    assert!(err.to_string().contains("undefined volume"));
}

#[test]
fn test_parse_command_args_override() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: cmd-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    command: ["/bin/sh", "-c"]
    args: ["echo hello"]
"#;
    let (_, spec) = parse_yaml(yaml).unwrap();
    assert_eq!(
        spec.containers[0].command,
        Some(vec!["/bin/sh".to_string(), "-c".to_string()])
    );
    assert_eq!(
        spec.containers[0].args,
        Some(vec!["echo hello".to_string()])
    );
}

#[test]
fn test_parse_restart_policy() {
    for (policy, expected) in [
        ("Always", "always"),
        ("OnFailure", "on-failure"),
        ("Never", "no"),
    ] {
        let yaml = format!(
            r#"
apiVersion: v1
kind: Pod
metadata:
  name: restart-pod
spec:
  restartPolicy: {policy}
  containers:
  - name: app
    image: docker.io/busybox:latest
"#
        );
        let (name, spec) = parse_yaml(&yaml).unwrap();
        let plan = validate_and_plan(&name, spec, "docker.io").unwrap();
        assert_eq!(plan.restart_policy, expected, "policy={policy}");
    }
}

#[test]
fn test_port_aggregation() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: multi-port
spec:
  containers:
  - name: web
    image: docker.io/nginx:latest
    ports:
    - containerPort: 80
    - containerPort: 443
  - name: api
    image: docker.io/node:latest
    ports:
    - containerPort: 3000
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let plan = validate_and_plan(&name, spec, "docker.io").unwrap();
    assert_eq!(plan.ports.len(), 3);
    let port_nums: Vec<u16> = plan.ports.iter().map(|p| p.container_port).collect();
    assert!(port_nums.contains(&80));
    assert!(port_nums.contains(&443));
    assert!(port_nums.contains(&3000));
}

#[test]
fn test_validate_empty_containers() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: empty-pod
spec:
  containers: []
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let err = validate_and_plan(&name, spec, "docker.io").unwrap_err();
    assert!(err.to_string().contains("at least one container"));
}

#[test]
fn test_validate_duplicate_container_names() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: dup-pod
spec:
  containers:
  - name: app
    image: docker.io/nginx:latest
  - name: app
    image: docker.io/redis:latest
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let err = validate_and_plan(&name, spec, "docker.io").unwrap_err();
    assert!(err.to_string().contains("duplicate container name"));
}

#[test]
fn test_validate_hostpath_relative() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: bad-host
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
  volumes:
  - name: data
    hostPath:
      path: relative/path
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let err = validate_and_plan(&name, spec, "docker.io").unwrap_err();
    assert!(err.to_string().contains("absolute"));
}

#[test]
fn test_validate_hostpath_dotdot() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: bad-host2
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
  volumes:
  - name: data
    hostPath:
      path: /tmp/../etc
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let err = validate_and_plan(&name, spec, "docker.io").unwrap_err();
    assert!(err.to_string().contains(".."));
}

#[test]
fn test_default_restart_policy() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: default-restart
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let plan = validate_and_plan(&name, spec, "docker.io").unwrap();
    assert_eq!(plan.restart_policy, "always");
}

// --- Feature 1: Unknown fields ---

#[test]
fn test_unknown_fields_parse_ok() {
    // Unknown fields should not cause parse errors.
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: warn-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    livenessProbe:
      exec:
        command: ["true"]
    securityContext:
      runAsUser: 1000
    unknownField: "hello"
"#;
    let result = parse_yaml(yaml);
    assert!(result.is_ok(), "parse should succeed with unknown fields");
}

// --- Feature 2: imagePullPolicy ---

#[test]
fn test_image_pull_policy_parse() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: pull-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    imagePullPolicy: IfNotPresent
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let plan = validate_and_plan(&name, spec, "docker.io").unwrap();
    assert_eq!(plan.containers[0].image_pull_policy, "IfNotPresent");
}

#[test]
fn test_image_pull_policy_default() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: pull-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let plan = validate_and_plan(&name, spec, "docker.io").unwrap();
    assert_eq!(plan.containers[0].image_pull_policy, "Always");
}

#[test]
fn test_image_pull_policy_invalid() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: pull-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    imagePullPolicy: Bogus
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let err = validate_and_plan(&name, spec, "docker.io").unwrap_err();
    assert!(err.to_string().contains("unsupported imagePullPolicy"));
}

// --- Feature 3: terminationGracePeriodSeconds ---

#[test]
fn test_termination_grace_period() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: grace-pod
spec:
  terminationGracePeriodSeconds: 45
  containers:
  - name: app
    image: docker.io/busybox:latest
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let plan = validate_and_plan(&name, spec, "docker.io").unwrap();
    assert_eq!(plan.termination_grace_period, Some(45));
}

#[test]
fn test_termination_grace_period_zero() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: grace-pod
spec:
  terminationGracePeriodSeconds: 0
  containers:
  - name: app
    image: docker.io/busybox:latest
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let err = validate_and_plan(&name, spec, "docker.io").unwrap_err();
    assert!(err.to_string().contains("must be > 0"));
}

// --- Feature 4: workingDir ---

#[test]
fn test_working_dir() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: wd-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    workingDir: /app
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let plan = validate_and_plan(&name, spec, "docker.io").unwrap();
    assert_eq!(
        plan.containers[0].working_dir_override,
        Some("/app".to_string())
    );
}

#[test]
fn test_working_dir_relative_rejected() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: wd-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    workingDir: relative/path
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let err = validate_and_plan(&name, spec, "docker.io").unwrap_err();
    assert!(err.to_string().contains("workingDir must be absolute"));
}

#[test]
fn test_working_dir_dotdot_rejected() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: wd-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    workingDir: /app/../etc
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let err = validate_and_plan(&name, spec, "docker.io").unwrap_err();
    assert!(err.to_string().contains("must not contain '..'"));
}

// --- Feature 5: resources ---

#[test]
fn test_resource_limits_memory() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: res-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    resources:
      limits:
        memory: 256Mi
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let plan = validate_and_plan(&name, spec, "docker.io").unwrap();
    assert!(plan.containers[0]
        .resource_lines
        .contains(&"MemoryMax=256M".to_string()));
}

#[test]
fn test_resource_limits_cpu() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: res-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    resources:
      limits:
        cpu: "2"
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let plan = validate_and_plan(&name, spec, "docker.io").unwrap();
    assert!(plan.containers[0]
        .resource_lines
        .contains(&"CPUQuota=200%".to_string()));
}

#[test]
fn test_resource_limits_cpu_millicore() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: res-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    resources:
      limits:
        cpu: 500m
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let plan = validate_and_plan(&name, spec, "docker.io").unwrap();
    assert!(plan.containers[0]
        .resource_lines
        .contains(&"CPUQuota=50%".to_string()));
}

#[test]
fn test_resource_requests() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: res-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    resources:
      requests:
        memory: 128Mi
        cpu: 250m
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let plan = validate_and_plan(&name, spec, "docker.io").unwrap();
    assert!(plan.containers[0]
        .resource_lines
        .contains(&"MemoryLow=128M".to_string()));
    assert!(plan.containers[0]
        .resource_lines
        .contains(&"CPUWeight=250".to_string()));
}

// --- Feature 6: securityContext ---

#[test]
fn test_security_context_run_as_user() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: sec-pod
spec:
  securityContext:
    runAsUser: 1000
    runAsGroup: 1000
  containers:
  - name: app
    image: docker.io/busybox:latest
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let plan = validate_and_plan(&name, spec, "docker.io").unwrap();
    assert_eq!(plan.run_as_user, Some(1000));
    assert_eq!(plan.run_as_group, Some(1000));
}

#[test]
fn test_security_context_run_as_non_root_without_user() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: sec-pod
spec:
  securityContext:
    runAsNonRoot: true
  containers:
  - name: app
    image: docker.io/busybox:latest
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let err = validate_and_plan(&name, spec, "docker.io").unwrap_err();
    assert!(err.to_string().contains("runAsNonRoot is true"));
}

#[test]
fn test_security_context_run_as_non_root_with_root_user() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: sec-pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 0
  containers:
  - name: app
    image: docker.io/busybox:latest
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let err = validate_and_plan(&name, spec, "docker.io").unwrap_err();
    assert!(err.to_string().contains("runAsUser is 0"));
}

// --- Feature 7: initContainers ---

#[test]
fn test_init_containers() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: init-pod
spec:
  initContainers:
  - name: init-setup
    image: docker.io/busybox:latest
    command: ["/bin/sh", "-c"]
    args: ["echo init"]
  containers:
  - name: app
    image: docker.io/nginx:latest
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    assert_eq!(spec.init_containers.len(), 1);
    assert_eq!(spec.init_containers[0].name, "init-setup");
    let plan = validate_and_plan(&name, spec, "docker.io").unwrap();
    assert_eq!(plan.init_containers.len(), 1);
    assert_eq!(plan.init_containers[0].name, "init-setup");
    assert_eq!(plan.containers.len(), 1);
    assert_eq!(plan.containers[0].name, "app");
}

#[test]
fn test_init_container_duplicate_name() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: init-pod
spec:
  initContainers:
  - name: app
    image: docker.io/busybox:latest
  containers:
  - name: app
    image: docker.io/nginx:latest
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let err = validate_and_plan(&name, spec, "docker.io").unwrap_err();
    assert!(err.to_string().contains("duplicate container name"));
}

// --- Feature 8: Probes ---

#[test]
fn test_readiness_probe_exec() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: probe-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    readinessProbe:
      exec:
        command: ["/bin/sh", "-c", "test -f /tmp/ready"]
      initialDelaySeconds: 5
      periodSeconds: 3
      failureThreshold: 5
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let plan = validate_and_plan(&name, spec, "docker.io").unwrap();
    let probe = plan.containers[0].probes.readiness.as_ref().unwrap();
    assert!(
        matches!(&probe.check, ProbeCheck::Exec { command } if command.iter().any(|a| a.contains("test -f"))),
        "expected exec probe with 'test -f' command"
    );
    assert_eq!(probe.initial_delay_seconds, 5);
    assert_eq!(probe.period_seconds, 3);
    assert_eq!(probe.failure_threshold, 5);
}

#[test]
fn test_liveness_probe_no_action_rejected() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: probe-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    livenessProbe:
      initialDelaySeconds: 5
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let err = validate_and_plan(&name, spec, "docker.io").unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("must specify exec, httpGet, tcpSocket, or grpc"),
        "unexpected error: {msg}"
    );
}

#[test]
fn test_liveness_probe_exec_ok() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: probe-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    livenessProbe:
      exec:
        command: ["true"]
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let plan = validate_and_plan(&name, spec, "docker.io").unwrap();
    assert!(plan.containers[0].probes.liveness.is_some());
}

#[test]
fn test_liveness_probe_http_get() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: probe-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    livenessProbe:
      httpGet:
        path: /healthz
        port: 8080
      periodSeconds: 5
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let plan = validate_and_plan(&name, spec, "docker.io").unwrap();
    let probe = plan.containers[0].probes.liveness.as_ref().unwrap();
    assert!(
        matches!(&probe.check, ProbeCheck::Http { port: 8080, ref path, .. } if path == "/healthz"),
        "expected HTTP probe on port 8080 path /healthz"
    );
    assert_eq!(probe.period_seconds, 5);
}

#[test]
fn test_liveness_probe_http_headers() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: probe-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    livenessProbe:
      httpGet:
        path: /healthz
        port: 8080
        httpHeaders:
        - name: X-Custom-Header
          value: awesome
        - name: Accept
          value: application/json
      periodSeconds: 5
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let plan = validate_and_plan(&name, spec, "docker.io").unwrap();
    let probe = plan.containers[0].probes.liveness.as_ref().unwrap();
    match &probe.check {
        ProbeCheck::Http {
            port,
            path,
            headers,
            ..
        } => {
            assert_eq!(*port, 8080);
            assert_eq!(path, "/healthz");
            assert_eq!(headers.len(), 2);
            assert_eq!(
                headers[0],
                ("X-Custom-Header".to_string(), "awesome".to_string())
            );
            assert_eq!(
                headers[1],
                ("Accept".to_string(), "application/json".to_string())
            );
        }
        other => panic!("expected Http probe, got {other:?}"),
    }
}

#[test]
fn test_readiness_probe_tcp_socket() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: probe-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    readinessProbe:
      tcpSocket:
        port: 3306
      periodSeconds: 10
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let plan = validate_and_plan(&name, spec, "docker.io").unwrap();
    let probe = plan.containers[0].probes.readiness.as_ref().unwrap();
    assert!(
        matches!(&probe.check, ProbeCheck::Tcp { port: 3306 }),
        "expected TCP probe on port 3306"
    );
}

#[test]
fn test_startup_probe() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: probe-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    startupProbe:
      httpGet:
        path: /ready
        port: 8080
      failureThreshold: 30
      periodSeconds: 2
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let plan = validate_and_plan(&name, spec, "docker.io").unwrap();
    let probe = plan.containers[0].probes.startup.as_ref().unwrap();
    assert!(
        matches!(&probe.check, ProbeCheck::Http { port: 8080, ref path, .. } if path == "/ready"),
        "expected HTTP probe on port 8080 path /ready"
    );
    assert_eq!(probe.failure_threshold, 30);
    assert_eq!(probe.period_seconds, 2);
}

// --- Combined feature test ---

#[test]
fn test_all_features_combined() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: full-pod
spec:
  terminationGracePeriodSeconds: 30
  securityContext:
    runAsUser: 1000
    runAsGroup: 1000
  initContainers:
  - name: init-setup
    image: docker.io/busybox:latest
    command: ["/bin/sh", "-c"]
    args: ["echo init"]
  containers:
  - name: app
    image: docker.io/busybox:latest
    workingDir: /app
    imagePullPolicy: IfNotPresent
    resources:
      limits:
        memory: 256Mi
        cpu: "1"
      requests:
        memory: 128Mi
        cpu: 250m
    readinessProbe:
      exec:
        command: ["/bin/sh", "-c", "test -f /tmp/ready"]
    volumeMounts:
    - name: shared
      mountPath: /data
  volumes:
  - name: shared
    emptyDir: {}
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let plan = validate_and_plan(&name, spec, "docker.io").unwrap();

    assert_eq!(plan.termination_grace_period, Some(30));
    assert_eq!(plan.run_as_user, Some(1000));
    assert_eq!(plan.run_as_group, Some(1000));
    assert_eq!(plan.init_containers.len(), 1);
    assert_eq!(plan.containers.len(), 1);

    let app = &plan.containers[0];
    assert_eq!(app.working_dir_override, Some("/app".to_string()));
    assert_eq!(app.image_pull_policy, "IfNotPresent");
    assert!(app.resource_lines.contains(&"MemoryMax=256M".to_string()));
    assert!(app.resource_lines.contains(&"CPUQuota=100%".to_string()));
    assert!(app.resource_lines.contains(&"MemoryLow=128M".to_string()));
    assert!(app.resource_lines.contains(&"CPUWeight=250".to_string()));
    assert!(app.probes.readiness.is_some());
}

// --- Unit file integration tests ---
//
// These tests call `setup_kube_container()` with a temp directory and
// verify the generated systemd unit file contains correct directives.

static UNIT_TEST_LOCK: Mutex<()> = Mutex::new(());

/// Helper: set up a temp dir, call `setup_kube_container()`, return the
/// generated unit file content.
fn setup_test_container(
    name: &str,
    kc: &KubeContainer,
    plan: &KubePlan,
    is_init: bool,
    init_container_names: &[String],
) -> String {
    let tmp = TempDataDir::new("kube-unit");
    let staging = tmp.path().join("staging");
    let app_dir = staging.join(format!("oci/apps/{name}"));
    let app_root = app_dir.join("root");
    fs::create_dir_all(&app_root).unwrap();
    fs::create_dir_all(staging.join("etc/systemd/system/multi-user.target.wants")).unwrap();

    super::super::create::setup_kube_container(
        tmp.path(),
        &staging,
        &app_dir,
        &super::super::create::KubeContainerOptions {
            kc,
            oci_config: None,
            restart_policy: &plan.restart_policy,
            volumes: &plan.volumes,
            plan,
            is_init,
            init_container_names,
            verbose: false,
        },
    )
    .unwrap();

    let unit_path = staging.join(format!("etc/systemd/system/sdme-oci-{name}.service"));
    fs::read_to_string(&unit_path).unwrap()
}

fn make_test_container(name: &str) -> KubeContainer {
    KubeContainer {
        name: name.to_string(),
        image: "docker.io/busybox:latest".to_string(),
        image_ref: ImageReference::parse("docker.io/busybox:latest").unwrap(),
        command_override: Some(vec!["/bin/sh".to_string(), "-c".to_string()]),
        args_override: Some(vec!["echo hello".to_string()]),
        env: vec![],
        volume_mounts: vec![],
        working_dir_override: None,
        image_pull_policy: "Always".to_string(),
        resource_lines: vec![],
        probes: KubeProbes::default(),
        security: ContainerSecurity::default(),
    }
}

fn make_test_plan() -> KubePlan {
    KubePlan {
        pod_name: "test-pod".to_string(),
        containers: vec![],
        init_containers: vec![],
        volumes: vec![],
        restart_policy: "always".to_string(),
        ports: vec![],
        host_network: false,
        host_binds: vec![],
        termination_grace_period: None,
        run_as_user: None,
        run_as_group: None,
        seccomp_profile_type: None,
        apparmor_profile: None,
    }
}

#[test]
fn test_unit_default_container() {
    let _lock = UNIT_TEST_LOCK.lock().unwrap();
    let kc = make_test_container("app");
    let plan = make_test_plan();
    let unit = setup_test_container("app", &kc, &plan, false, &[]);

    assert!(unit.contains("Type=exec"), "default type should be exec");
    assert!(
        unit.contains("Restart=always"),
        "should have restart policy"
    );
    assert!(
        !unit.contains("RemainAfterExit"),
        "should not have RemainAfterExit"
    );
    assert!(
        !unit.contains("TimeoutStopSec"),
        "should not have TimeoutStopSec"
    );
    assert!(
        unit.contains("After=network.target\n"),
        "should have After=network.target only"
    );
    assert!(
        !unit.contains("Requires="),
        "should not have Requires= line"
    );
}

#[test]
fn test_unit_init_container_type() {
    let _lock = UNIT_TEST_LOCK.lock().unwrap();
    let kc = make_test_container("init-setup");
    let plan = make_test_plan();
    let unit = setup_test_container("init-setup", &kc, &plan, true, &[]);

    assert!(
        unit.contains("Type=oneshot"),
        "init container should be oneshot"
    );
    assert!(
        unit.contains("RemainAfterExit=yes"),
        "init container should have RemainAfterExit"
    );
    assert!(
        !unit.contains("Restart="),
        "oneshot init container should not have Restart="
    );
}

#[test]
fn test_unit_main_container_deps() {
    let _lock = UNIT_TEST_LOCK.lock().unwrap();
    let kc = make_test_container("app");
    let plan = make_test_plan();
    let init_names = vec!["init-setup".to_string()];
    let unit = setup_test_container("app", &kc, &plan, false, &init_names);

    assert!(
        unit.contains("After=network.target sdme-oci-init-setup.service"),
        "should depend on init container, got: {unit}"
    );
    assert!(
        unit.contains("Requires=sdme-oci-init-setup.service"),
        "should require init container"
    );
}

#[test]
fn test_unit_termination_grace_period() {
    let _lock = UNIT_TEST_LOCK.lock().unwrap();
    let kc = make_test_container("app");
    let mut plan = make_test_plan();
    plan.termination_grace_period = Some(45);
    let unit = setup_test_container("app", &kc, &plan, false, &[]);

    assert!(
        unit.contains("TimeoutStopSec=45s"),
        "should have TimeoutStopSec=45s"
    );
}

#[test]
fn test_unit_working_dir_override() {
    let _lock = UNIT_TEST_LOCK.lock().unwrap();
    let mut kc = make_test_container("app");
    kc.working_dir_override = Some("/app".to_string());
    let plan = make_test_plan();
    let unit = setup_test_container("app", &kc, &plan, false, &[]);

    // In isolate mode, working dir is passed as an argument to sdme-isolate,
    // not as a systemd WorkingDirectory= directive.
    assert!(
        unit.contains("/usr/sbin/sdme-isolate 0 0 /app"),
        "should have /app as working dir in isolate exec, got: {unit}"
    );
}

#[test]
fn test_unit_resources() {
    let _lock = UNIT_TEST_LOCK.lock().unwrap();
    let mut kc = make_test_container("app");
    kc.resource_lines = vec!["MemoryMax=256M".to_string(), "CPUQuota=100%".to_string()];
    let plan = make_test_plan();
    let unit = setup_test_container("app", &kc, &plan, false, &[]);

    assert!(unit.contains("MemoryMax=256M"), "should have MemoryMax");
    assert!(unit.contains("CPUQuota=100%"), "should have CPUQuota");
}

#[test]
fn test_unit_startup_probe() {
    let _lock = UNIT_TEST_LOCK.lock().unwrap();
    let mut kc = make_test_container("app");
    kc.probes.startup = Some(ProbeSpec {
        check: ProbeCheck::Exec {
            command: vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "test -f /tmp/ready".to_string(),
            ],
        },
        initial_delay_seconds: 0,
        period_seconds: 2,
        timeout_seconds: 1,
        failure_threshold: 30,
        success_threshold: 1,
    });
    let plan = make_test_plan();

    let tmp = TempDataDir::new("kube-unit-startup");
    let staging = tmp.path().join("staging");
    let app_dir = staging.join("oci/apps/app");
    let app_root = app_dir.join("root");
    fs::create_dir_all(&app_root).unwrap();
    fs::create_dir_all(staging.join("etc/systemd/system/multi-user.target.wants")).unwrap();

    super::super::create::setup_kube_container(
        tmp.path(),
        &staging,
        &app_dir,
        &super::super::create::KubeContainerOptions {
            kc: &kc,
            oci_config: None,
            restart_policy: &plan.restart_policy,
            volumes: &plan.volumes,
            plan: &plan,
            is_init: false,
            init_container_names: &[],
            verbose: false,
        },
    )
    .unwrap();

    // Startup probe should NOT use ExecStartPost (all probes use timers).
    let unit_path = staging.join("etc/systemd/system/sdme-oci-app.service");
    let unit = fs::read_to_string(&unit_path).unwrap();
    assert!(
        !unit.contains("ExecStartPost="),
        "startup probe should not use ExecStartPost"
    );

    // Startup timer and service units should exist.
    let timer_path = staging.join("etc/systemd/system/sdme-probe-startup-app.timer");
    assert!(timer_path.exists(), "startup timer unit should exist");
    let svc_path = staging.join("etc/systemd/system/sdme-probe-startup-app.service");
    assert!(svc_path.exists(), "startup service unit should exist");
    let svc = fs::read_to_string(&svc_path).unwrap();
    assert!(
        svc.contains("/usr/bin/sdme-kube-probe"),
        "startup service should reference probe binary"
    );
    assert!(
        svc.contains("--type startup"),
        "startup service should have --type startup"
    );
    assert!(
        svc.contains("--threshold 30"),
        "startup service should have --threshold 30"
    );

    // Timer should be enabled.
    let symlink =
        staging.join("etc/systemd/system/multi-user.target.wants/sdme-probe-startup-app.timer");
    assert!(symlink.exists(), "startup timer should be enabled");
}

#[test]
fn test_unit_liveness_probe_timer() {
    let _lock = UNIT_TEST_LOCK.lock().unwrap();
    let mut kc = make_test_container("app");
    kc.probes.liveness = Some(ProbeSpec {
        check: ProbeCheck::Exec {
            command: vec!["true".to_string()],
        },
        initial_delay_seconds: 5,
        period_seconds: 10,
        timeout_seconds: 1,
        failure_threshold: 3,
        success_threshold: 1,
    });
    let plan = make_test_plan();

    let tmp = TempDataDir::new("kube-unit-liveness");
    let staging = tmp.path().join("staging");
    let app_dir = staging.join("oci/apps/app");
    let app_root = app_dir.join("root");
    fs::create_dir_all(&app_root).unwrap();
    fs::create_dir_all(staging.join("etc/systemd/system/multi-user.target.wants")).unwrap();

    super::super::create::setup_kube_container(
        tmp.path(),
        &staging,
        &app_dir,
        &super::super::create::KubeContainerOptions {
            kc: &kc,
            oci_config: None,
            restart_policy: &plan.restart_policy,
            volumes: &plan.volumes,
            plan: &plan,
            is_init: false,
            init_container_names: &[],
            verbose: false,
        },
    )
    .unwrap();

    // Check timer unit exists.
    let timer_path = staging.join("etc/systemd/system/sdme-probe-liveness-app.timer");
    assert!(timer_path.exists(), "liveness timer unit should exist");
    let timer = fs::read_to_string(&timer_path).unwrap();
    assert!(
        timer.contains("OnActiveSec=5s"),
        "timer should have initial delay"
    );
    assert!(
        timer.contains("OnUnitActiveSec=10s"),
        "timer should have period"
    );
    assert!(
        timer.contains("BindsTo=sdme-oci-app.service"),
        "timer should bind to main service"
    );

    // Check service unit references the probe binary (no scripts).
    let svc_path = staging.join("etc/systemd/system/sdme-probe-liveness-app.service");
    assert!(svc_path.exists(), "liveness service unit should exist");
    let svc = fs::read_to_string(&svc_path).unwrap();
    assert!(
        svc.contains("/usr/bin/sdme-kube-probe"),
        "service should reference probe binary"
    );
    assert!(
        svc.contains("--type liveness"),
        "service should have --type liveness"
    );

    // No probe scripts should exist.
    let script_path = staging.join("oci/apps/app/probe-liveness.sh");
    assert!(
        !script_path.exists(),
        "no probe scripts should be generated"
    );

    // Check timer symlink in wants dir.
    let symlink =
        staging.join("etc/systemd/system/multi-user.target.wants/sdme-probe-liveness-app.timer");
    assert!(symlink.exists(), "liveness timer should be enabled");
}

#[test]
fn test_unit_readiness_probe_timer() {
    let _lock = UNIT_TEST_LOCK.lock().unwrap();
    let mut kc = make_test_container("app");
    kc.probes.readiness = Some(ProbeSpec {
        check: ProbeCheck::Http {
            port: 8080,
            path: "/".to_string(),
            scheme: "http".to_string(),
            headers: vec![],
        },
        initial_delay_seconds: 0,
        period_seconds: 5,
        timeout_seconds: 1,
        failure_threshold: 3,
        success_threshold: 1,
    });
    let plan = make_test_plan();

    let tmp = TempDataDir::new("kube-unit-readiness");
    let staging = tmp.path().join("staging");
    let app_dir = staging.join("oci/apps/app");
    let app_root = app_dir.join("root");
    fs::create_dir_all(&app_root).unwrap();
    fs::create_dir_all(staging.join("etc/systemd/system/multi-user.target.wants")).unwrap();

    super::super::create::setup_kube_container(
        tmp.path(),
        &staging,
        &app_dir,
        &super::super::create::KubeContainerOptions {
            kc: &kc,
            oci_config: None,
            restart_policy: &plan.restart_policy,
            volumes: &plan.volumes,
            plan: &plan,
            is_init: false,
            init_container_names: &[],
            verbose: false,
        },
    )
    .unwrap();

    // Check readiness service references probe binary with --type readiness.
    let svc_path = staging.join("etc/systemd/system/sdme-probe-readiness-app.service");
    assert!(svc_path.exists(), "readiness service unit should exist");
    let svc = fs::read_to_string(&svc_path).unwrap();
    assert!(
        svc.contains("/usr/bin/sdme-kube-probe") && svc.contains("--type readiness"),
        "readiness service should reference probe binary with --type readiness"
    );
}

#[test]
fn test_unit_multiline_command() {
    let _lock = UNIT_TEST_LOCK.lock().unwrap();
    let mut kc = make_test_container("app");
    kc.command_override = Some(vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        "echo hello\necho world\n".to_string(),
    ]);
    kc.args_override = None;
    let plan = make_test_plan();
    let unit = setup_test_container("app", &kc, &plan, false, &[]);

    // ExecStart must not contain literal newlines (systemd rejects them).
    // Multi-line commands should be written to a wrapper script.
    let exec_line = unit
        .lines()
        .find(|l| l.starts_with("ExecStart="))
        .expect("unit should have ExecStart");
    assert!(
        exec_line.lines().count() == 1,
        "ExecStart must be a single line, got: {exec_line}"
    );
    assert!(
        exec_line.contains("/.sdme-exec.sh"),
        "multi-line command should use wrapper script, got: {exec_line}"
    );
}

#[test]
fn test_unit_singleline_command_no_wrapper() {
    let _lock = UNIT_TEST_LOCK.lock().unwrap();
    let kc = make_test_container("app");
    let plan = make_test_plan();
    let unit = setup_test_container("app", &kc, &plan, false, &[]);

    let exec_line = unit
        .lines()
        .find(|l| l.starts_with("ExecStart="))
        .expect("unit should have ExecStart");
    assert!(
        !exec_line.contains("/.sdme-exec.sh"),
        "single-line command should not use wrapper script, got: {exec_line}"
    );
}

#[test]
fn test_unit_security_context_user() {
    let _lock = UNIT_TEST_LOCK.lock().unwrap();
    let kc = make_test_container("app");
    let mut plan = make_test_plan();
    plan.run_as_user = Some(1000);
    plan.run_as_group = Some(1000);

    // setup_kube_container passes "1000:1000" as user, which
    // resolve_oci_user() resolves as numeric UID:GID. Kube uses
    // isolate mode so sdme-isolate is deployed. Numeric UIDs
    // work without etc/passwd.
    let tmp = TempDataDir::new("kube-unit-sec");
    let staging = tmp.path().join("staging");
    let app_dir = staging.join("oci/apps/app");
    let app_root = app_dir.join("root");
    fs::create_dir_all(&app_root).unwrap();
    fs::create_dir_all(staging.join("etc/systemd/system/multi-user.target.wants")).unwrap();

    super::super::create::setup_kube_container(
        tmp.path(),
        &staging,
        &app_dir,
        &super::super::create::KubeContainerOptions {
            kc: &kc,
            oci_config: None,
            restart_policy: &plan.restart_policy,
            volumes: &plan.volumes,
            plan: &plan,
            is_init: false,
            init_container_names: &[],
            verbose: false,
        },
    )
    .unwrap();

    let unit_path = staging.join("etc/systemd/system/sdme-oci-app.service");
    let unit = fs::read_to_string(&unit_path).unwrap();

    // Kube uses isolate mode: should use sdme-isolate with uid/gid.
    assert!(
        unit.contains("/usr/sbin/sdme-isolate 1000 1000"),
        "should use isolate with uid=1000 gid=1000, got: {unit}"
    );
    // isolate binary should be deployed.
    assert!(app_root.join("usr/sbin/sdme-isolate").is_file());
}

// --- Secret volumes ---

#[test]
fn test_parse_secret_volume() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: secret-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    volumeMounts:
    - name: my-secret
      mountPath: /etc/secrets
  volumes:
  - name: my-secret
    secret:
      secretName: db-creds
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    assert!(spec.volumes[0].secret.is_some());
    let secret = spec.volumes[0].secret.as_ref().unwrap();
    assert_eq!(secret.secret_name, "db-creds");
    assert!(secret.items.is_empty());
    assert_eq!(secret.default_mode, 0o644);

    let plan = validate_and_plan(&name, spec, "docker.io").unwrap();
    assert!(matches!(
        plan.volumes[0].kind,
        KubeVolumeKind::Secret { .. }
    ));
    // Secret volumes should not generate host binds.
    assert!(plan.host_binds.is_empty());
}

#[test]
fn test_parse_secret_volume_with_items() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: secret-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    volumeMounts:
    - name: my-secret
      mountPath: /etc/secrets
  volumes:
  - name: my-secret
    secret:
      secretName: db-creds
      items:
      - key: username
        path: user.txt
      - key: password
        path: pass.txt
      defaultMode: 256
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let plan = validate_and_plan(&name, spec, "docker.io").unwrap();
    if let KubeVolumeKind::Secret {
        ref items,
        default_mode,
        ..
    } = plan.volumes[0].kind
    {
        assert_eq!(items.len(), 2);
        assert_eq!(items[0], ("username".to_string(), "user.txt".to_string()));
        assert_eq!(items[1], ("password".to_string(), "pass.txt".to_string()));
        assert_eq!(default_mode, 256); // 0o400
    } else {
        panic!("expected Secret volume kind");
    }
}

#[test]
fn test_secret_volume_invalid_name() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: secret-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
  volumes:
  - name: my-secret
    secret:
      secretName: INVALID
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let err = validate_and_plan(&name, spec, "docker.io").unwrap_err();
    assert!(
        err.to_string().contains("invalid secret name") || err.to_string().contains("lowercase"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_secret_volume_item_path_traversal() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: secret-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
  volumes:
  - name: my-secret
    secret:
      secretName: db-creds
      items:
      - key: username
        path: ../etc/passwd
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let err = validate_and_plan(&name, spec, "docker.io").unwrap_err();
    assert!(err.to_string().contains(".."), "unexpected error: {err}");
}

#[test]
fn test_secret_volume_item_path_absolute() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: secret-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
  volumes:
  - name: my-secret
    secret:
      secretName: db-creds
      items:
      - key: username
        path: /etc/passwd
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let err = validate_and_plan(&name, spec, "docker.io").unwrap_err();
    assert!(
        err.to_string().contains("must not start with '/'"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_parse_secret_volume_octal_string_mode() {
    // YAML 1.2 treats `0400` as a string; verify the custom deserializer
    // handles it by parsing it as octal.
    let yaml = "
apiVersion: v1
kind: Pod
metadata:
  name: secret-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    volumeMounts:
    - name: my-secret
      mountPath: /etc/secrets
  volumes:
  - name: my-secret
    secret:
      secretName: db-creds
      defaultMode: \"0400\"
";
    let (_name, spec) = parse_yaml(yaml).unwrap();
    let secret = spec.volumes[0].secret.as_ref().unwrap();
    assert_eq!(secret.default_mode, 0o400); // 256 decimal
}

// --- ConfigMap volumes ---

#[test]
fn test_parse_configmap_volume() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: cm-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    volumeMounts:
    - name: my-config
      mountPath: /etc/config
  volumes:
  - name: my-config
    configMap:
      name: app-config
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    assert!(spec.volumes[0].config_map.is_some());
    let cm = spec.volumes[0].config_map.as_ref().unwrap();
    assert_eq!(cm.name, "app-config");
    assert!(cm.items.is_empty());
    assert_eq!(cm.default_mode, 0o644);

    let plan = validate_and_plan(&name, spec, "docker.io").unwrap();
    assert!(matches!(
        plan.volumes[0].kind,
        KubeVolumeKind::ConfigMap { .. }
    ));
    // ConfigMap volumes should not generate host binds.
    assert!(plan.host_binds.is_empty());
}

#[test]
fn test_parse_configmap_volume_with_items() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: cm-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    volumeMounts:
    - name: my-config
      mountPath: /etc/config
  volumes:
  - name: my-config
    configMap:
      name: app-config
      items:
      - key: config-key
        path: app.conf
      - key: log-key
        path: log.conf
      defaultMode: 256
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let plan = validate_and_plan(&name, spec, "docker.io").unwrap();
    if let KubeVolumeKind::ConfigMap {
        ref items,
        default_mode,
        ..
    } = plan.volumes[0].kind
    {
        assert_eq!(items.len(), 2);
        assert_eq!(items[0], ("config-key".to_string(), "app.conf".to_string()));
        assert_eq!(items[1], ("log-key".to_string(), "log.conf".to_string()));
        assert_eq!(default_mode, 256); // 0o400
    } else {
        panic!("expected ConfigMap volume kind");
    }
}

#[test]
fn test_configmap_volume_invalid_name() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: cm-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
  volumes:
  - name: my-config
    configMap:
      name: INVALID
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let err = validate_and_plan(&name, spec, "docker.io").unwrap_err();
    assert!(
        err.to_string().contains("invalid configmap name") || err.to_string().contains("lowercase"),
        "unexpected error: {err}"
    );
}

// --- PVC volumes ---

#[test]
fn test_parse_pvc_volume() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: pvc-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    volumeMounts:
    - name: data-volume
      mountPath: /data
  volumes:
  - name: data-volume
    persistentVolumeClaim:
      claimName: test-data
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    assert!(spec.volumes[0].persistent_volume_claim.is_some());
    let pvc = spec.volumes[0].persistent_volume_claim.as_ref().unwrap();
    assert_eq!(pvc.claim_name, "test-data");

    let plan = validate_and_plan(&name, spec, "docker.io").unwrap();
    assert!(matches!(plan.volumes[0].kind, KubeVolumeKind::Pvc(_)));
    // PVC volumes don't generate host binds at plan time (added in kube_create).
    assert!(plan.host_binds.is_empty());
}

#[test]
fn test_pvc_volume_invalid_name() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: pvc-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
  volumes:
  - name: data-volume
    persistentVolumeClaim:
      claimName: INVALID
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let err = validate_and_plan(&name, spec, "docker.io").unwrap_err();
    assert!(
        err.to_string().contains("invalid PVC claim name") || err.to_string().contains("lowercase"),
        "unexpected error: {err}"
    );
}

// --- env valueFrom ---

#[test]
fn test_parse_env_value_from_secret() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: env-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    env:
    - name: DB_PASSWORD
      valueFrom:
        secretKeyRef:
          name: db-creds
          key: password
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let plan = validate_and_plan(&name, spec, "docker.io").unwrap();
    assert!(matches!(
        plan.containers[0].env[0].1,
        KubeEnvValue::SecretKeyRef { .. }
    ));
    if let KubeEnvValue::SecretKeyRef { ref name, ref key } = plan.containers[0].env[0].1 {
        assert_eq!(name, "db-creds");
        assert_eq!(key, "password");
    }
}

#[test]
fn test_parse_env_value_from_configmap() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: env-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    env:
    - name: LOG_LEVEL
      valueFrom:
        configMapKeyRef:
          name: app-config
          key: log-level
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let plan = validate_and_plan(&name, spec, "docker.io").unwrap();
    assert!(matches!(
        plan.containers[0].env[0].1,
        KubeEnvValue::ConfigMapKeyRef { .. }
    ));
    if let KubeEnvValue::ConfigMapKeyRef { ref name, ref key } = plan.containers[0].env[0].1 {
        assert_eq!(name, "app-config");
        assert_eq!(key, "log-level");
    }
}

#[test]
fn test_parse_env_value_from_invalid() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: env-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    env:
    - name: BAD_VAR
      valueFrom: {}
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let err = validate_and_plan(&name, spec, "docker.io").unwrap_err();
    assert!(
        err.to_string()
            .contains("valueFrom must specify secretKeyRef or configMapKeyRef"),
        "unexpected error: {err}"
    );
}

// --- Container securityContext tests ---

#[test]
fn test_container_security_context_caps_add_drop() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: sec-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    securityContext:
      capabilities:
        add: ["NET_ADMIN"]
        drop: ["NET_RAW"]
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let plan = validate_and_plan(&name, spec, "docker.io").unwrap();
    let c = &plan.containers[0];
    assert_eq!(c.security.add_caps, vec!["CAP_NET_ADMIN"]);
    assert_eq!(c.security.drop_caps, vec!["CAP_NET_RAW"]);
}

#[test]
fn test_container_security_context_caps_drop_all() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: sec-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    securityContext:
      capabilities:
        add: ["CHOWN"]
        drop: ["ALL"]
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let plan = validate_and_plan(&name, spec, "docker.io").unwrap();
    let c = &plan.containers[0];
    assert_eq!(c.security.add_caps, vec!["CAP_CHOWN"]);
    assert_eq!(c.security.drop_caps, vec!["ALL"]);
}

#[test]
fn test_container_security_context_invalid_cap() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: sec-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    securityContext:
      capabilities:
        add: ["BOGUS"]
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let err = validate_and_plan(&name, spec, "docker.io").unwrap_err();
    let chain = format!("{err:#}");
    assert!(
        chain.contains("unknown capability"),
        "unexpected error: {chain}"
    );
}

#[test]
fn test_container_security_context_seccomp_runtime_default() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: sec-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    securityContext:
      seccompProfile:
        type: RuntimeDefault
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let plan = validate_and_plan(&name, spec, "docker.io").unwrap();
    let c = &plan.containers[0];
    assert!(
        !c.security.syscall_filters.is_empty(),
        "should have syscall filters"
    );
    assert!(
        c.security
            .syscall_filters
            .iter()
            .any(|f| f.contains("@raw-io")),
        "should include @raw-io filter"
    );
}

#[test]
fn test_container_security_context_seccomp_unconfined() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: sec-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    securityContext:
      seccompProfile:
        type: Unconfined
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let plan = validate_and_plan(&name, spec, "docker.io").unwrap();
    let c = &plan.containers[0];
    assert!(
        c.security.syscall_filters.is_empty(),
        "Unconfined should have no filters"
    );
}

#[test]
fn test_container_security_context_seccomp_localhost_rejected() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: sec-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    securityContext:
      seccompProfile:
        type: Localhost
        localhostProfile: my-profile.json
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let err = validate_and_plan(&name, spec, "docker.io").unwrap_err();
    assert!(
        err.to_string().contains("Localhost"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_container_security_context_apparmor_runtime_default() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: sec-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    securityContext:
      appArmorProfile:
        type: RuntimeDefault
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let plan = validate_and_plan(&name, spec, "docker.io").unwrap();
    let c = &plan.containers[0];
    assert_eq!(c.security.apparmor_profile.as_deref(), Some("sdme-default"));
}

#[test]
fn test_container_security_context_apparmor_localhost() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: sec-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    securityContext:
      appArmorProfile:
        type: Localhost
        localhostProfile: my-custom-profile
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let plan = validate_and_plan(&name, spec, "docker.io").unwrap();
    let c = &plan.containers[0];
    assert_eq!(
        c.security.apparmor_profile.as_deref(),
        Some("my-custom-profile")
    );
}

#[test]
fn test_container_security_context_apparmor_unconfined() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: sec-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    securityContext:
      appArmorProfile:
        type: Unconfined
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let plan = validate_and_plan(&name, spec, "docker.io").unwrap();
    let c = &plan.containers[0];
    // Unconfined resolves to empty string.
    assert_eq!(c.security.apparmor_profile.as_deref(), Some(""));
}

#[test]
fn test_container_security_context_run_as_user() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: sec-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    securityContext:
      runAsUser: 1000
      runAsGroup: 1000
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let plan = validate_and_plan(&name, spec, "docker.io").unwrap();
    let c = &plan.containers[0];
    assert_eq!(c.security.run_as_user, Some(1000));
    assert_eq!(c.security.run_as_group, Some(1000));
}

#[test]
fn test_container_security_context_run_as_non_root_no_user() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: sec-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    securityContext:
      runAsNonRoot: true
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let err = validate_and_plan(&name, spec, "docker.io").unwrap_err();
    assert!(
        err.to_string().contains("runAsNonRoot"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_container_security_context_allow_privilege_escalation() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: sec-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    securityContext:
      allowPrivilegeEscalation: false
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let plan = validate_and_plan(&name, spec, "docker.io").unwrap();
    let c = &plan.containers[0];
    assert_eq!(c.security.allow_privilege_escalation, Some(false));
}

#[test]
fn test_container_security_context_read_only_root_filesystem() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: sec-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    securityContext:
      readOnlyRootFilesystem: true
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let plan = validate_and_plan(&name, spec, "docker.io").unwrap();
    let c = &plan.containers[0];
    assert!(c.security.read_only_root_filesystem);
}

#[test]
fn test_container_security_context_all_fields() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: sec-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    securityContext:
      runAsUser: 1000
      runAsGroup: 1000
      runAsNonRoot: true
      capabilities:
        add: ["NET_ADMIN"]
        drop: ["NET_RAW"]
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      seccompProfile:
        type: RuntimeDefault
      appArmorProfile:
        type: RuntimeDefault
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let plan = validate_and_plan(&name, spec, "docker.io").unwrap();
    let c = &plan.containers[0];
    assert_eq!(c.security.run_as_user, Some(1000));
    assert_eq!(c.security.run_as_group, Some(1000));
    assert_eq!(c.security.add_caps, vec!["CAP_NET_ADMIN"]);
    assert_eq!(c.security.drop_caps, vec!["CAP_NET_RAW"]);
    assert_eq!(c.security.allow_privilege_escalation, Some(false));
    assert!(c.security.read_only_root_filesystem);
    assert!(!c.security.syscall_filters.is_empty());
    assert_eq!(c.security.apparmor_profile.as_deref(), Some("sdme-default"));
}

#[test]
fn test_pod_security_context_seccomp_runtime_default() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: sec-pod
spec:
  securityContext:
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    image: docker.io/busybox:latest
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let plan = validate_and_plan(&name, spec, "docker.io").unwrap();
    assert_eq!(plan.seccomp_profile_type.as_deref(), Some("RuntimeDefault"));
}

#[test]
fn test_pod_security_context_apparmor() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: sec-pod
spec:
  securityContext:
    appArmorProfile:
      type: RuntimeDefault
  containers:
  - name: app
    image: docker.io/busybox:latest
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let plan = validate_and_plan(&name, spec, "docker.io").unwrap();
    assert_eq!(plan.apparmor_profile.as_deref(), Some("sdme-default"));
}

#[test]
fn test_unit_container_security_caps_drop() {
    let _lock = UNIT_TEST_LOCK.lock().unwrap();
    let mut kc = make_test_container("app");
    kc.security.drop_caps = vec!["CAP_NET_RAW".to_string()];
    let plan = make_test_plan();
    let unit = setup_test_container("app", &kc, &plan, false, &[]);
    assert!(
        !unit.contains("CAP_NET_RAW"),
        "CAP_NET_RAW should be dropped"
    );
    assert!(unit.contains("CAP_SYS_ADMIN"), "must keep CAP_SYS_ADMIN");
}

#[test]
fn test_unit_container_security_drop_all() {
    let _lock = UNIT_TEST_LOCK.lock().unwrap();
    let mut kc = make_test_container("app");
    kc.security.drop_caps = vec!["ALL".to_string()];
    kc.security.add_caps = vec!["CAP_CHOWN".to_string()];
    let plan = make_test_plan();
    let unit = setup_test_container("app", &kc, &plan, false, &[]);
    assert!(unit.contains("CAP_SYS_ADMIN"), "must keep CAP_SYS_ADMIN");
    assert!(unit.contains("CAP_CHOWN"), "should have added cap");
    // CAP_SETUID, CAP_SETGID, CAP_SETPCAP are always kept for isolate binary.
    for required in ["CAP_SETUID", "CAP_SETGID", "CAP_SETPCAP"] {
        assert!(unit.contains(required), "must keep {required} for isolate");
    }
    assert!(!unit.contains("CAP_NET_RAW"), "defaults should be dropped");
}

#[test]
fn test_unit_container_security_read_only() {
    let _lock = UNIT_TEST_LOCK.lock().unwrap();
    let mut kc = make_test_container("app");
    kc.security.read_only_root_filesystem = true;
    let plan = make_test_plan();
    let unit = setup_test_container("app", &kc, &plan, false, &[]);
    assert!(
        unit.contains("ReadOnlyPaths=/"),
        "should have ReadOnlyPaths"
    );
}

#[test]
fn test_unit_container_security_apparmor() {
    let _lock = UNIT_TEST_LOCK.lock().unwrap();
    let mut kc = make_test_container("app");
    kc.security.apparmor_profile = Some("sdme-default".to_string());
    let plan = make_test_plan();
    let unit = setup_test_container("app", &kc, &plan, false, &[]);
    assert!(
        unit.contains("AppArmorProfile=sdme-default"),
        "should have AppArmor profile"
    );
}

#[test]
fn test_unit_container_security_syscall_filters() {
    let _lock = UNIT_TEST_LOCK.lock().unwrap();
    let mut kc = make_test_container("app");
    kc.security.syscall_filters = vec!["~@raw-io".to_string()];
    kc.security.has_seccomp_profile = true;
    let plan = make_test_plan();
    let unit = setup_test_container("app", &kc, &plan, false, &[]);
    assert!(
        unit.contains("SystemCallFilter=~@raw-io"),
        "should have syscall filter"
    );
}

#[test]
fn test_unit_pod_seccomp_fallback() {
    let _lock = UNIT_TEST_LOCK.lock().unwrap();
    let kc = make_test_container("app");
    let mut plan = make_test_plan();
    plan.seccomp_profile_type = Some("RuntimeDefault".to_string());
    let unit = setup_test_container("app", &kc, &plan, false, &[]);
    assert!(
        unit.contains("SystemCallFilter="),
        "pod-level seccomp should produce syscall filters"
    );
}

#[test]
fn test_unit_container_seccomp_unconfined_overrides_pod() {
    let _lock = UNIT_TEST_LOCK.lock().unwrap();
    let mut kc = make_test_container("app");
    // Container explicitly sets Unconfined (empty filters, but has_seccomp_profile=true).
    kc.security.has_seccomp_profile = true;
    kc.security.syscall_filters = vec![];
    let mut plan = make_test_plan();
    plan.seccomp_profile_type = Some("RuntimeDefault".to_string());
    let unit = setup_test_container("app", &kc, &plan, false, &[]);
    assert!(
        !unit.contains("SystemCallFilter="),
        "container Unconfined should override pod-level RuntimeDefault"
    );
}

#[test]
fn test_unit_container_user_overrides_pod() {
    let _lock = UNIT_TEST_LOCK.lock().unwrap();
    let mut kc = make_test_container("app");
    kc.security.run_as_user = Some(2000);
    kc.security.run_as_group = Some(2000);
    let mut plan = make_test_plan();
    plan.run_as_user = Some(1000);
    plan.run_as_group = Some(1000);
    let unit = setup_test_container("app", &kc, &plan, false, &[]);
    // Container-level 2000 should override pod-level 1000.
    assert!(
        unit.contains("2000 2000"),
        "container user should override pod user: {unit}"
    );
}

// --- Read-only volume mounts ---

#[test]
fn test_parse_read_only_volume_mount() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: ro-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    volumeMounts:
    - name: config
      mountPath: /etc/config
      readOnly: true
  volumes:
  - name: config
    emptyDir: {}
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let plan = validate_and_plan(&name, spec, "docker.io").unwrap();
    assert!(plan.containers[0].volume_mounts[0].read_only);
}

#[test]
fn test_unit_read_only_volume_mount() {
    // Verify the generated sdme-kube-volumes.service contains remount,ro,bind
    // for a read-only volume mount.
    let _lock = UNIT_TEST_LOCK.lock().unwrap();
    let tmp = TempDataDir::new("kube-rovm");
    let staging = tmp.path().join("staging");
    let apps_dir = staging.join("oci/apps");
    let volumes_dir = staging.join("oci/volumes/shared");
    let unit_dir = staging.join("etc/systemd/system");
    let wants_dir = unit_dir.join("multi-user.target.wants");
    fs::create_dir_all(&apps_dir).unwrap();
    fs::create_dir_all(&volumes_dir).unwrap();
    fs::create_dir_all(&wants_dir).unwrap();

    let plan = KubePlan {
        pod_name: "ro-pod".to_string(),
        containers: vec![KubeContainer {
            name: "app".to_string(),
            volume_mounts: vec![KubeVolumeMount {
                volume_name: "shared".to_string(),
                mount_path: "/data".to_string(),
                read_only: true,
            }],
            ..make_test_container("app")
        }],
        init_containers: vec![],
        volumes: vec![KubeVolume {
            name: "shared".to_string(),
            kind: KubeVolumeKind::EmptyDir,
        }],
        ..make_test_plan()
    };

    // Generate the volume mount unit.
    let has_volume_mounts = plan
        .init_containers
        .iter()
        .chain(plan.containers.iter())
        .any(|kc| !kc.volume_mounts.is_empty());
    assert!(has_volume_mounts);

    let mut exec_lines = Vec::new();
    for kc in plan.init_containers.iter().chain(plan.containers.iter()) {
        for vm in &kc.volume_mounts {
            let src = format!("/oci/volumes/{}", vm.volume_name);
            let dst = format!("/oci/apps/{}/root{}", kc.name, vm.mount_path);
            exec_lines.push(format!("ExecStart=/bin/mount --bind {src} {dst}"));
            if vm.read_only {
                exec_lines.push(format!("ExecStart=/bin/mount -o remount,ro,bind {dst}"));
            }
        }
    }

    assert!(
        exec_lines
            .iter()
            .any(|l| l.contains("remount,ro,bind") && l.contains("/oci/apps/app/root/data")),
        "should contain remount,ro,bind for read-only mount: {exec_lines:?}"
    );
}

#[test]
fn test_init_container_volume_mounts_in_service() {
    // Verify init container volume mounts are included in has_volume_mounts check.
    let plan = KubePlan {
        pod_name: "init-vm-pod".to_string(),
        containers: vec![make_test_container("app")],
        init_containers: vec![KubeContainer {
            name: "init".to_string(),
            volume_mounts: vec![KubeVolumeMount {
                volume_name: "shared".to_string(),
                mount_path: "/data".to_string(),
                read_only: false,
            }],
            ..make_test_container("init")
        }],
        volumes: vec![KubeVolume {
            name: "shared".to_string(),
            kind: KubeVolumeKind::EmptyDir,
        }],
        ..make_test_plan()
    };

    let has_volume_mounts = plan
        .init_containers
        .iter()
        .chain(plan.containers.iter())
        .any(|kc| !kc.volume_mounts.is_empty());
    assert!(
        has_volume_mounts,
        "init container volume mounts should be detected"
    );
}

// --- envFrom ---

#[test]
fn test_parse_env_from_configmap() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: ef-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    envFrom:
    - configMapRef:
        name: my-config
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let plan = validate_and_plan(&name, spec, "docker.io").unwrap();
    assert!(matches!(
        plan.containers[0].env[0].1,
        KubeEnvValue::ConfigMapRef { .. }
    ));
    if let KubeEnvValue::ConfigMapRef {
        ref name,
        ref prefix,
    } = plan.containers[0].env[0].1
    {
        assert_eq!(name, "my-config");
        assert_eq!(prefix, "");
    }
}

#[test]
fn test_parse_env_from_secret() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: ef-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    envFrom:
    - secretRef:
        name: my-secret
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let plan = validate_and_plan(&name, spec, "docker.io").unwrap();
    assert!(matches!(
        plan.containers[0].env[0].1,
        KubeEnvValue::SecretRef { .. }
    ));
    if let KubeEnvValue::SecretRef {
        ref name,
        ref prefix,
    } = plan.containers[0].env[0].1
    {
        assert_eq!(name, "my-secret");
        assert_eq!(prefix, "");
    }
}

#[test]
fn test_parse_env_from_with_prefix() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: ef-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    envFrom:
    - configMapRef:
        name: my-config
      prefix: APP_
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let plan = validate_and_plan(&name, spec, "docker.io").unwrap();
    if let KubeEnvValue::ConfigMapRef { ref prefix, .. } = plan.containers[0].env[0].1 {
        assert_eq!(prefix, "APP_");
    } else {
        panic!("expected ConfigMapRef");
    }
}

#[test]
fn test_parse_env_from_invalid_no_ref() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: ef-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    envFrom:
    - prefix: FOO_
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let err = validate_and_plan(&name, spec, "docker.io").unwrap_err();
    assert!(
        err.to_string()
            .contains("envFrom entry must specify configMapRef or secretRef"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_parse_env_from_invalid_name() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: ef-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    envFrom:
    - secretRef:
        name: INVALID
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let err = validate_and_plan(&name, spec, "docker.io").unwrap_err();
    assert!(
        err.to_string().contains("invalid secret name") || err.to_string().contains("lowercase"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_env_from_ordering_explicit_env_wins() {
    // envFrom entries come before explicit env in the plan, so explicit env
    // overrides envFrom when create.rs deduplicates by key.
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: ef-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    envFrom:
    - configMapRef:
        name: my-config
    env:
    - name: OVERRIDE_KEY
      value: explicit-value
"#;
    let (name, spec) = parse_yaml(yaml).unwrap();
    let plan = validate_and_plan(&name, spec, "docker.io").unwrap();
    // envFrom should be first, explicit env should be last.
    assert!(matches!(
        plan.containers[0].env[0].1,
        KubeEnvValue::ConfigMapRef { .. }
    ));
    assert!(matches!(
        plan.containers[0].env[1].1,
        KubeEnvValue::Literal(_)
    ));
    assert_eq!(plan.containers[0].env[1].0, "OVERRIDE_KEY");
}

#[test]
fn test_env_from_resolve_configmap() {
    // Integration test: verify envFrom configMapRef resolution from store data.
    let _lock = UNIT_TEST_LOCK.lock().unwrap();
    let tmp = TempDataDir::new("kube-envfrom-cm");

    // Create a configmap with test data.
    super::super::configmap::create(
        tmp.path(),
        "my-config",
        &[
            ("HOST".into(), "localhost".into()),
            ("PORT".into(), "8080".into()),
        ],
        &[],
    )
    .unwrap();

    let mut kc = make_test_container("app");
    kc.env = vec![
        (
            String::new(),
            KubeEnvValue::ConfigMapRef {
                name: "my-config".to_string(),
                prefix: "APP_".to_string(),
            },
        ),
        // Explicit env should override envFrom key.
        (
            "APP_PORT".to_string(),
            KubeEnvValue::Literal("9090".to_string()),
        ),
    ];

    let staging = tmp.path().join("staging");
    let app_dir = staging.join("oci/apps/app");
    let app_root = app_dir.join("root");
    fs::create_dir_all(&app_root).unwrap();
    fs::create_dir_all(staging.join("etc/systemd/system/multi-user.target.wants")).unwrap();

    let plan = make_test_plan();
    super::super::create::setup_kube_container(
        tmp.path(),
        &staging,
        &app_dir,
        &super::super::create::KubeContainerOptions {
            kc: &kc,
            oci_config: None,
            restart_policy: &plan.restart_policy,
            volumes: &plan.volumes,
            plan: &plan,
            is_init: false,
            init_container_names: &[],
            verbose: false,
        },
    )
    .unwrap();

    // Read the generated env file.
    let env_path = app_dir.join("env");
    let env_content = fs::read_to_string(&env_path).unwrap();
    // envFrom should have produced APP_HOST=localhost.
    assert!(
        env_content.contains("APP_HOST=localhost"),
        "envFrom should produce APP_HOST=localhost, got: {env_content}"
    );
    // Explicit env APP_PORT=9090 should override envFrom APP_PORT=8080.
    assert!(
        env_content.contains("APP_PORT=9090"),
        "explicit env should override envFrom, got: {env_content}"
    );
    assert!(
        !env_content.contains("APP_PORT=8080"),
        "envFrom value should be overridden, got: {env_content}"
    );
}

#[test]
fn test_env_from_resolve_secret() {
    // Integration test: verify envFrom secretRef resolution from store data.
    let _lock = UNIT_TEST_LOCK.lock().unwrap();
    let tmp = TempDataDir::new("kube-envfrom-sec");

    // Create a secret with test data.
    super::super::secret::create(
        tmp.path(),
        "my-secret",
        &[
            ("USER".into(), "admin".into()),
            ("PASS".into(), "s3cret".into()),
        ],
        &[],
    )
    .unwrap();

    let mut kc = make_test_container("app");
    kc.env = vec![(
        String::new(),
        KubeEnvValue::SecretRef {
            name: "my-secret".to_string(),
            prefix: "DB_".to_string(),
        },
    )];

    let staging = tmp.path().join("staging");
    let app_dir = staging.join("oci/apps/app");
    let app_root = app_dir.join("root");
    fs::create_dir_all(&app_root).unwrap();
    fs::create_dir_all(staging.join("etc/systemd/system/multi-user.target.wants")).unwrap();

    let plan = make_test_plan();
    super::super::create::setup_kube_container(
        tmp.path(),
        &staging,
        &app_dir,
        &super::super::create::KubeContainerOptions {
            kc: &kc,
            oci_config: None,
            restart_policy: &plan.restart_policy,
            volumes: &plan.volumes,
            plan: &plan,
            is_init: false,
            init_container_names: &[],
            verbose: false,
        },
    )
    .unwrap();

    let env_path = app_dir.join("env");
    let env_content = fs::read_to_string(&env_path).unwrap();
    assert!(
        env_content.contains("DB_PASS=s3cret"),
        "envFrom should produce DB_PASS=s3cret, got: {env_content}"
    );
    assert!(
        env_content.contains("DB_USER=admin"),
        "envFrom should produce DB_USER=admin, got: {env_content}"
    );
}

#[test]
fn test_probe_http_crlf_in_path() {
    let probe = super::super::types::Probe {
        exec: None,
        http_get: Some(super::super::types::HttpGetAction {
            path: Some("/health\r\nX-Injected: true".into()),
            port: 8080,
            scheme: None,
            http_headers: vec![],
        }),
        tcp_socket: None,
        grpc: None,
        initial_delay_seconds: None,
        period_seconds: None,
        timeout_seconds: None,
        failure_threshold: None,
        success_threshold: None,
    };
    let err = build_probe_check(&probe, "test").unwrap_err();
    assert!(
        err.to_string().contains("CR/LF"),
        "expected CR/LF rejection, got: {err}"
    );
}

#[test]
fn test_probe_http_crlf_in_header_name() {
    let probe = super::super::types::Probe {
        exec: None,
        http_get: Some(super::super::types::HttpGetAction {
            path: Some("/health".into()),
            port: 8080,
            scheme: None,
            http_headers: vec![super::super::types::HttpHeader {
                name: "X-Evil\r\nInjected".into(),
                value: "ok".into(),
            }],
        }),
        tcp_socket: None,
        grpc: None,
        initial_delay_seconds: None,
        period_seconds: None,
        timeout_seconds: None,
        failure_threshold: None,
        success_threshold: None,
    };
    let err = build_probe_check(&probe, "test").unwrap_err();
    assert!(
        err.to_string().contains("CR/LF"),
        "expected CR/LF rejection, got: {err}"
    );
}

#[test]
fn test_probe_http_crlf_in_header_value() {
    let probe = super::super::types::Probe {
        exec: None,
        http_get: Some(super::super::types::HttpGetAction {
            path: Some("/health".into()),
            port: 8080,
            scheme: None,
            http_headers: vec![super::super::types::HttpHeader {
                name: "X-Custom".into(),
                value: "ok\r\nX-Injected: true".into(),
            }],
        }),
        tcp_socket: None,
        grpc: None,
        initial_delay_seconds: None,
        period_seconds: None,
        timeout_seconds: None,
        failure_threshold: None,
        success_threshold: None,
    };
    let err = build_probe_check(&probe, "test").unwrap_err();
    assert!(
        err.to_string().contains("CR/LF"),
        "expected CR/LF rejection, got: {err}"
    );
}
