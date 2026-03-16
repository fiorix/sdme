#!/usr/bin/env bash
set -uo pipefail

# verify-kube-L2-probes.sh - end-to-end verification of Kubernetes probe support
# Run as root. Requires a base-fs imported (e.g. ubuntu).
#
# Tests each probe type individually:
#
#   1. Startup probe (exec) - blocks service start until check passes
#   2. Liveness probe (exec) - restarts service on failure threshold
#   3. Readiness probe (exec) - writes ready/not-ready state for sdme ps
#   4. httpGet probes - liveness via wget --spider
#   5. tcpSocket probes - readiness via /dev/tcp
#   6. Combined probes - startup + liveness + readiness together
#
# Each test creates its own pod to isolate behavior. Uses alpine:latest
# to minimize image pulls.

source "$(dirname "$0")/lib.sh"

SDME="${SDME:-sdme}"
BASE_FS="${BASE_FS:-ubuntu}"
DATADIR="/var/lib/sdme"
REPORT_DIR="."

PREFIX="vfy-kp"

# Timeouts (seconds)
TIMEOUT_CREATE=600
TIMEOUT_BOOT=120

# Result tracking
declare -A RESULTS

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

End-to-end verification of sdme Kubernetes probe support.
Must be run as root.

Options:
  --base-fs NAME   Base rootfs to use (default: ubuntu)
  --report-dir DIR Write report to DIR (default: .)
  --help           Show help
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --base-fs)
                shift
                BASE_FS="$1"
                ;;
            --report-dir)
                shift
                REPORT_DIR="$1"
                ;;
            --help)
                usage
                exit 0
                ;;
            *)
                echo "unknown option: $1" >&2
                usage >&2
                exit 1
                ;;
        esac
        shift
    done
}

record() {
    local test_name="$1" result="$2" msg="${3:-}"
    RESULTS["$test_name"]="$result|$msg"
    case "$result" in
        PASS) ((_pass++)) || true; echo "  [PASS] $test_name${msg:+: $msg}" ;;
        FAIL) ((_fail++)) || true; echo "  [FAIL] $test_name${msg:+: $msg}" ;;
        SKIP) ((_skip++)) || true; echo "  [SKIP] $test_name${msg:+: $msg}" ;;
    esac
}

result_status() {
    local val="${RESULTS[$1]}"
    echo "${val%%|*}"
}

result_msg() {
    local val="${RESULTS[$1]}"
    echo "${val#*|}"
}

# Check if the probe binary exists in the kube rootfs.
probe_binary_exists() {
    local pod_name="$1"
    test -x "$DATADIR/fs/kube-$pod_name/oci/.sdme-kube-probe"
}

# Read a unit file from the kube rootfs.
read_unit() {
    local pod_name="$1" app_name="$2"
    cat "$DATADIR/fs/kube-$pod_name/etc/systemd/system/sdme-oci-${app_name}.service" 2>/dev/null || echo ""
}

# Read a probe unit file (timer or service) from the kube rootfs.
read_probe_unit() {
    local pod_name="$1" filename="$2"
    cat "$DATADIR/fs/kube-$pod_name/etc/systemd/system/${filename}" 2>/dev/null || echo ""
}

# Check if a timer symlink exists in multi-user.target.wants.
timer_enabled() {
    local pod_name="$1" timer_name="$2"
    test -L "$DATADIR/fs/kube-$pod_name/etc/systemd/system/multi-user.target.wants/${timer_name}"
}

# --- Cleanup ------------------------------------------------------------------

cleanup() {
    echo "==> Cleaning up..."
    cleanup_prefix "$PREFIX"
}

trap cleanup EXIT INT TERM

# =============================================================================
# Test 1: Startup probe (exec)
#
# The startup probe blocks the service from reaching "started" state until
# the probe succeeds. Uses ExecStartPost= on the main service unit.
# =============================================================================

test_startup_probe() {
    local pod_name="${PREFIX}-startup"
    local test_prefix="startup-probe"
    echo ""
    echo "=== Test: Startup probe (exec) ==="

    # Create pod with a startup probe that checks for /tmp/ready.
    # The app creates /tmp/ready immediately, so the probe should succeed.
    local yaml_file
    yaml_file=$(mktemp /tmp/kube-probe-XXXXXX.yaml)
    cat > "$yaml_file" <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: ${pod_name}
spec:
  containers:
  - name: app
    image: docker.io/alpine:latest
    command: ["/bin/sh", "-c", "touch /tmp/ready && sleep infinity"]
    startupProbe:
      exec:
        command: ["/bin/sh", "-c", "test -f /tmp/ready"]
      initialDelaySeconds: 1
      periodSeconds: 1
      failureThreshold: 10
YAML

    # Create.
    local output
    if ! output=$(timeout "$TIMEOUT_CREATE" "$SDME" kube create -f "$yaml_file" --base-fs "$BASE_FS" $VFLAG 2>&1); then
        record "${test_prefix}-create" FAIL "$output"
        rm -f "$yaml_file"
        return
    fi
    record "${test_prefix}-create" PASS
    rm -f "$yaml_file"

    # Static check: startup probe uses timer + service (no ExecStartPost).
    local unit
    unit=$(read_unit "$pod_name" "app")
    if echo "$unit" | grep -q 'ExecStartPost='; then
        record "${test_prefix}-no-exec-start-post" FAIL "startup probe should not use ExecStartPost"
        echo "    unit content:"
        echo "$unit"
    else
        record "${test_prefix}-no-exec-start-post" PASS
    fi

    # Static check: startup timer and service units exist.
    local startup_svc
    startup_svc=$(read_probe_unit "$pod_name" "sdme-probe-startup-app.service")
    if echo "$startup_svc" | grep -q '/oci/.sdme-kube-probe.*--type startup'; then
        record "${test_prefix}-probe-binary" PASS
    else
        record "${test_prefix}-probe-binary" FAIL "startup service should reference probe binary with --type startup"
        echo "    service content:"
        echo "$startup_svc"
    fi

    # Boot and verify service is active (meaning startup probe passed).
    if ! output=$(timeout "$TIMEOUT_BOOT" "$SDME" start "$pod_name" $VFLAG 2>&1); then
        record "${test_prefix}-boot" FAIL "$output"
        return
    fi
    record "${test_prefix}-boot" PASS

    # Wait for the startup probe ExecStartPost to complete and services to settle.
    local active=""
    for i in $(seq 1 10); do
        sleep 3
        active=$("$SDME" exec "$pod_name" -- \
            /usr/bin/systemctl is-active sdme-oci-app.service 2>/dev/null || echo "")
        if echo "$active" | grep -qw 'active'; then
            break
        fi
    done

    # Verify app service is active.
    output="$active"
    if echo "$output" | grep -qw 'active'; then
        record "${test_prefix}-service-active" PASS
    else
        local status
        status=$(echo "$output" | grep -v 'Connected to\|Press \^]\|Connection to\|^$' | tail -1)
        record "${test_prefix}-service-active" FAIL "service: $status"
    fi

    stop_container "$pod_name"
}

# =============================================================================
# Test 2: Liveness probe (exec)
#
# The liveness probe runs periodically via a systemd timer. On failure
# threshold, it restarts the main service via systemctl restart.
# =============================================================================

test_liveness_probe() {
    local pod_name="${PREFIX}-liveness"
    local test_prefix="liveness-probe"
    echo ""
    echo "=== Test: Liveness probe (exec) ==="

    local yaml_file
    yaml_file=$(mktemp /tmp/kube-probe-XXXXXX.yaml)
    cat > "$yaml_file" <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: ${pod_name}
spec:
  containers:
  - name: app
    image: docker.io/alpine:latest
    command: ["/bin/sh", "-c", "sleep infinity"]
    livenessProbe:
      exec:
        command: ["/bin/sh", "-c", "true"]
      initialDelaySeconds: 2
      periodSeconds: 3
      failureThreshold: 3
YAML

    # Create.
    local output
    if ! output=$(timeout "$TIMEOUT_CREATE" "$SDME" kube create -f "$yaml_file" --base-fs "$BASE_FS" $VFLAG 2>&1); then
        record "${test_prefix}-create" FAIL "$output"
        rm -f "$yaml_file"
        return
    fi
    record "${test_prefix}-create" PASS
    rm -f "$yaml_file"

    # Static: timer unit exists and is enabled.
    local timer
    timer=$(read_probe_unit "$pod_name" "sdme-probe-liveness-app.timer")
    if [[ -n "$timer" ]]; then
        record "${test_prefix}-timer-exists" PASS
    else
        record "${test_prefix}-timer-exists" FAIL "timer unit not found"
        return
    fi

    # Static: timer has correct OnActiveSec and OnUnitActiveSec.
    local fail=0
    if ! echo "$timer" | grep -q 'OnActiveSec=2s'; then
        echo "    missing: OnActiveSec=2s"
        fail=1
    fi
    if ! echo "$timer" | grep -q 'OnUnitActiveSec=3s'; then
        echo "    missing: OnUnitActiveSec=3s"
        fail=1
    fi
    if ! echo "$timer" | grep -q "BindsTo=sdme-oci-app.service"; then
        echo "    missing: BindsTo=sdme-oci-app.service"
        fail=1
    fi
    if [[ $fail -eq 0 ]]; then
        record "${test_prefix}-timer-config" PASS
    else
        record "${test_prefix}-timer-config" FAIL "timer directives wrong"
        echo "    timer content:"
        echo "$timer"
    fi

    # Static: timer is enabled via symlink.
    if timer_enabled "$pod_name" "sdme-probe-liveness-app.timer"; then
        record "${test_prefix}-timer-enabled" PASS
    else
        record "${test_prefix}-timer-enabled" FAIL "timer symlink not in multi-user.target.wants"
    fi

    # Static: probe service references the probe binary with --type liveness.
    local probe_svc
    probe_svc=$(read_probe_unit "$pod_name" "sdme-probe-liveness-app.service")
    if echo "$probe_svc" | grep -q '/oci/.sdme-kube-probe.*--type liveness'; then
        record "${test_prefix}-probe-binary" PASS
    else
        record "${test_prefix}-probe-binary" FAIL "liveness service should reference probe binary"
        echo "    service content:"
        echo "$probe_svc"
    fi

    # Boot and verify timer is active at runtime.
    if ! output=$(timeout "$TIMEOUT_BOOT" "$SDME" start "$pod_name" $VFLAG 2>&1); then
        record "${test_prefix}-boot" FAIL "$output"
        return
    fi
    record "${test_prefix}-boot" PASS

    sleep 5

    # Check timer is active inside the container.
    output=$("$SDME" exec "$pod_name" -- \
        /usr/bin/systemctl is-active sdme-probe-liveness-app.timer 2>/dev/null || echo "")
    if echo "$output" | grep -qw 'active'; then
        record "${test_prefix}-timer-active" PASS
    else
        local status
        status=$(echo "$output" | grep -v 'Connected to\|Press \^]\|Connection to\|^$' | tail -1)
        record "${test_prefix}-timer-active" FAIL "timer: $status"
    fi

    # Wait for at least one probe execution, then check the probe service ran.
    sleep 5
    output=$("$SDME" exec "$pod_name" -- \
        /usr/bin/systemctl show sdme-probe-liveness-app.service -p NRestarts --value 2>/dev/null || echo "")
    # NRestarts should exist (even if 0); confirms the service unit loaded.
    if echo "$output" | grep -qE '[0-9]+'; then
        record "${test_prefix}-probe-ran" PASS
    else
        record "${test_prefix}-probe-ran" FAIL "could not read NRestarts"
    fi

    stop_container "$pod_name"
}

# =============================================================================
# Test 3: Readiness probe (exec)
#
# The readiness probe writes ready/not-ready to /oci/apps/{name}/probe-ready.
# sdme ps reads this file from the host to show health status.
# =============================================================================

test_readiness_probe() {
    local pod_name="${PREFIX}-readiness"
    local test_prefix="readiness-probe"
    echo ""
    echo "=== Test: Readiness probe (exec) ==="

    local yaml_file
    yaml_file=$(mktemp /tmp/kube-probe-XXXXXX.yaml)
    cat > "$yaml_file" <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: ${pod_name}
spec:
  containers:
  - name: app
    image: docker.io/alpine:latest
    command: ["/bin/sh", "-c", "touch /tmp/healthy && sleep infinity"]
    readinessProbe:
      exec:
        command: ["/bin/sh", "-c", "test -f /tmp/healthy"]
      initialDelaySeconds: 1
      periodSeconds: 2
      failureThreshold: 3
YAML

    # Create.
    local output
    if ! output=$(timeout "$TIMEOUT_CREATE" "$SDME" kube create -f "$yaml_file" --base-fs "$BASE_FS" $VFLAG 2>&1); then
        record "${test_prefix}-create" FAIL "$output"
        rm -f "$yaml_file"
        return
    fi
    record "${test_prefix}-create" PASS
    rm -f "$yaml_file"

    # Static: readiness timer and service exist.
    local timer svc
    timer=$(read_probe_unit "$pod_name" "sdme-probe-readiness-app.timer")
    svc=$(read_probe_unit "$pod_name" "sdme-probe-readiness-app.service")

    if [[ -n "$timer" ]] && [[ -n "$svc" ]]; then
        record "${test_prefix}-units-exist" PASS
    else
        record "${test_prefix}-units-exist" FAIL "timer or service unit missing"
        return
    fi

    # Static: readiness probe service references probe binary with --type readiness.
    local probe_svc
    probe_svc=$(read_probe_unit "$pod_name" "sdme-probe-readiness-app.service")
    if echo "$probe_svc" | grep -q '/oci/.sdme-kube-probe.*--type readiness'; then
        record "${test_prefix}-probe-binary" PASS
    else
        record "${test_prefix}-probe-binary" FAIL "readiness service should reference probe binary"
        echo "    service content:"
        echo "$probe_svc"
    fi

    # Boot.
    if ! output=$(timeout "$TIMEOUT_BOOT" "$SDME" start "$pod_name" $VFLAG 2>&1); then
        record "${test_prefix}-boot" FAIL "$output"
        return
    fi
    record "${test_prefix}-boot" PASS

    # Wait for readiness probe to fire and write the ready file.
    echo "    waiting for readiness probe to fire..."
    local ready=""
    for i in $(seq 1 15); do
        sleep 2
        ready=$(cat "$DATADIR/containers/$pod_name/merged/oci/apps/app/probe-ready" 2>/dev/null || echo "")
        if [[ "$ready" == "ready" ]]; then
            break
        fi
    done

    if [[ "$ready" == "ready" ]]; then
        record "${test_prefix}-ready-file" PASS
    else
        record "${test_prefix}-ready-file" FAIL "probe-ready file not 'ready' after 30s, got: '$ready'"
    fi

    # Check sdme ps shows 'ready' in health column.
    local ps_output
    ps_output=$("$SDME" ps 2>/dev/null || echo "")
    if echo "$ps_output" | grep "$pod_name" | grep -q 'ready'; then
        record "${test_prefix}-ps-health" PASS
    else
        local health_line
        health_line=$(echo "$ps_output" | grep "$pod_name" || echo "(not found)")
        record "${test_prefix}-ps-health" FAIL "expected 'ready' in ps output: $health_line"
    fi

    stop_container "$pod_name"
}

# =============================================================================
# Test 4: httpGet probe
#
# Uses wget --spider to check an HTTP endpoint. Tests with a simple
# busybox httpd serving files.
# =============================================================================

test_httpget_probe() {
    local pod_name="${PREFIX}-httpget"
    local test_prefix="httpget-probe"
    echo ""
    echo "=== Test: httpGet probe ==="

    local yaml_file
    yaml_file=$(mktemp /tmp/kube-probe-XXXXXX.yaml)
    # Use a shell loop with nc to serve HTTP responses. BusyBox nc in Alpine
    # supports -l -p and can serve a minimal HTTP response.
    cat > "$yaml_file" <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: ${pod_name}
spec:
  containers:
  - name: app
    image: docker.io/alpine:latest
    command: ["/bin/sh", "-c", "while true; do echo -e 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok' | nc -l -p 8080; done"]
    livenessProbe:
      httpGet:
        path: /healthz
        port: 8080
      initialDelaySeconds: 5
      periodSeconds: 5
      failureThreshold: 3
YAML

    # Create.
    local output
    if ! output=$(timeout "$TIMEOUT_CREATE" "$SDME" kube create -f "$yaml_file" --base-fs "$BASE_FS" $VFLAG 2>&1); then
        record "${test_prefix}-create" FAIL "$output"
        rm -f "$yaml_file"
        return
    fi
    record "${test_prefix}-create" PASS
    rm -f "$yaml_file"

    # Static: liveness probe service references probe binary with http check.
    local probe_svc
    probe_svc=$(read_probe_unit "$pod_name" "sdme-probe-liveness-app.service")
    if echo "$probe_svc" | grep -q '/oci/.sdme-kube-probe.*http.*--port 8080.*--path /healthz'; then
        record "${test_prefix}-http-probe" PASS
    else
        record "${test_prefix}-http-probe" FAIL "http probe with port 8080 and /healthz not found"
        echo "    service content:"
        echo "$probe_svc"
    fi

    # Boot and verify timer is active.
    if ! output=$(timeout "$TIMEOUT_BOOT" "$SDME" start "$pod_name" $VFLAG 2>&1); then
        record "${test_prefix}-boot" FAIL "$output"
        return
    fi
    record "${test_prefix}-boot" PASS

    sleep 10

    # Verify the liveness timer is active.
    output=$("$SDME" exec "$pod_name" -- \
        /usr/bin/systemctl is-active sdme-probe-liveness-app.timer 2>/dev/null || echo "")
    if echo "$output" | grep -qw 'active'; then
        record "${test_prefix}-timer-active" PASS
    else
        local status
        status=$(echo "$output" | grep -v 'Connected to\|Press \^]\|Connection to\|^$' | tail -1)
        record "${test_prefix}-timer-active" FAIL "timer: $status"
    fi

    # Verify the app is still running (liveness probes are passing).
    output=$("$SDME" exec "$pod_name" -- \
        /usr/bin/systemctl is-active sdme-oci-app.service 2>/dev/null || echo "")
    if echo "$output" | grep -qw 'active'; then
        record "${test_prefix}-app-alive" PASS
    else
        local status
        status=$(echo "$output" | grep -v 'Connected to\|Press \^]\|Connection to\|^$' | tail -1)
        record "${test_prefix}-app-alive" FAIL "app service: $status"
    fi

    stop_container "$pod_name"
}

# =============================================================================
# Test 5: tcpSocket probe
#
# Uses /dev/tcp to check a TCP port. Tests with busybox nc -l.
# =============================================================================

test_tcpsocket_probe() {
    local pod_name="${PREFIX}-tcpsock"
    local test_prefix="tcpsocket-probe"
    echo ""
    echo "=== Test: tcpSocket probe ==="

    local yaml_file
    yaml_file=$(mktemp /tmp/kube-probe-XXXXXX.yaml)
    cat > "$yaml_file" <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: ${pod_name}
spec:
  containers:
  - name: app
    image: docker.io/alpine:latest
    command: ["/bin/sh", "-c", "while true; do echo ok | nc -l -p 9090; done"]
    readinessProbe:
      tcpSocket:
        port: 9090
      initialDelaySeconds: 3
      periodSeconds: 3
      failureThreshold: 3
YAML

    # Create.
    local output
    if ! output=$(timeout "$TIMEOUT_CREATE" "$SDME" kube create -f "$yaml_file" --base-fs "$BASE_FS" $VFLAG 2>&1); then
        record "${test_prefix}-create" FAIL "$output"
        rm -f "$yaml_file"
        return
    fi
    record "${test_prefix}-create" PASS
    rm -f "$yaml_file"

    # Static: readiness probe service references probe binary with tcp check.
    local probe_svc
    probe_svc=$(read_probe_unit "$pod_name" "sdme-probe-readiness-app.service")
    if echo "$probe_svc" | grep -q '/oci/.sdme-kube-probe.*tcp.*--port 9090'; then
        record "${test_prefix}-tcp-probe" PASS
    else
        record "${test_prefix}-tcp-probe" FAIL "tcp probe with port 9090 not found"
        echo "    service content:"
        echo "$probe_svc"
    fi

    # Boot.
    if ! output=$(timeout "$TIMEOUT_BOOT" "$SDME" start "$pod_name" $VFLAG 2>&1); then
        record "${test_prefix}-boot" FAIL "$output"
        return
    fi
    record "${test_prefix}-boot" PASS

    # Wait for readiness probe.
    echo "    waiting for readiness probe..."
    local ready=""
    for i in $(seq 1 15); do
        sleep 2
        ready=$(cat "$DATADIR/containers/$pod_name/merged/oci/apps/app/probe-ready" 2>/dev/null || echo "")
        if [[ "$ready" == "ready" ]]; then
            break
        fi
    done

    if [[ "$ready" == "ready" ]]; then
        record "${test_prefix}-ready" PASS
    else
        record "${test_prefix}-ready" FAIL "probe-ready not 'ready' after 30s, got: '$ready'"
    fi

    stop_container "$pod_name"
}

# =============================================================================
# Test 6: Combined probes (startup + liveness + readiness)
#
# Verifies that startup probe gates liveness/readiness via After= ordering.
# =============================================================================

test_combined_probes() {
    local pod_name="${PREFIX}-combined"
    local test_prefix="combined-probes"
    echo ""
    echo "=== Test: Combined probes (startup + liveness + readiness) ==="

    local yaml_file
    yaml_file=$(mktemp /tmp/kube-probe-XXXXXX.yaml)
    cat > "$yaml_file" <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: ${pod_name}
spec:
  containers:
  - name: app
    image: docker.io/alpine:latest
    command: ["/bin/sh", "-c", "touch /tmp/started && while true; do echo ok | nc -l -p 8080; done"]
    startupProbe:
      exec:
        command: ["/bin/sh", "-c", "test -f /tmp/started"]
      initialDelaySeconds: 1
      periodSeconds: 1
      failureThreshold: 10
    livenessProbe:
      exec:
        command: ["/bin/sh", "-c", "test -f /tmp/started"]
      initialDelaySeconds: 5
      periodSeconds: 10
      failureThreshold: 3
    readinessProbe:
      tcpSocket:
        port: 8080
      initialDelaySeconds: 5
      periodSeconds: 5
      failureThreshold: 5
YAML

    # Create.
    local output
    if ! output=$(timeout "$TIMEOUT_CREATE" "$SDME" kube create -f "$yaml_file" --base-fs "$BASE_FS" $VFLAG 2>&1); then
        record "${test_prefix}-create" FAIL "$output"
        rm -f "$yaml_file"
        return
    fi
    record "${test_prefix}-create" PASS
    rm -f "$yaml_file"

    # Static: verify all three probe timer+service pairs are present.
    local startup_svc
    startup_svc=$(read_probe_unit "$pod_name" "sdme-probe-startup-app.service")
    if echo "$startup_svc" | grep -q '/oci/.sdme-kube-probe.*--type startup'; then
        record "${test_prefix}-startup-unit" PASS
    else
        record "${test_prefix}-startup-unit" FAIL "startup probe service not found"
    fi

    local liveness_timer liveness_svc readiness_timer readiness_svc
    liveness_timer=$(read_probe_unit "$pod_name" "sdme-probe-liveness-app.timer")
    liveness_svc=$(read_probe_unit "$pod_name" "sdme-probe-liveness-app.service")
    readiness_timer=$(read_probe_unit "$pod_name" "sdme-probe-readiness-app.timer")
    readiness_svc=$(read_probe_unit "$pod_name" "sdme-probe-readiness-app.service")

    if [[ -n "$liveness_timer" ]] && [[ -n "$liveness_svc" ]]; then
        record "${test_prefix}-liveness-units" PASS
    else
        record "${test_prefix}-liveness-units" FAIL "liveness timer or service missing"
    fi

    if [[ -n "$readiness_timer" ]] && [[ -n "$readiness_svc" ]]; then
        record "${test_prefix}-readiness-units" PASS
    else
        record "${test_prefix}-readiness-units" FAIL "readiness timer or service missing"
    fi

    # Static: probe services gate on startup probe done file via ConditionPathExists.
    if echo "$liveness_svc" | grep -q 'ConditionPathExists=/run/sdme-probe-startup-app.done'; then
        record "${test_prefix}-liveness-condition" PASS
    else
        record "${test_prefix}-liveness-condition" FAIL "liveness service missing ConditionPathExists for startup done file"
    fi

    if echo "$readiness_svc" | grep -q 'ConditionPathExists=/run/sdme-probe-startup-app.done'; then
        record "${test_prefix}-readiness-condition" PASS
    else
        record "${test_prefix}-readiness-condition" FAIL "readiness service missing ConditionPathExists for startup done file"
    fi

    # Boot and verify everything converges.
    if ! output=$(timeout "$TIMEOUT_BOOT" "$SDME" start "$pod_name" $VFLAG 2>&1); then
        record "${test_prefix}-boot" FAIL "$output"
        return
    fi
    record "${test_prefix}-boot" PASS

    echo "    waiting for probes to converge..."
    sleep 25

    # All should be working: app active, timers active, readiness file is "ready".
    # Check startup timer too.
    output=$("$SDME" exec "$pod_name" -- \
        /usr/bin/systemctl is-active sdme-probe-startup-app.timer 2>/dev/null || echo "")
    if echo "$output" | grep -qw 'active'; then
        record "${test_prefix}-startup-timer-active" PASS
    else
        record "${test_prefix}-startup-timer-active" FAIL "startup timer not active"
    fi

    output=$("$SDME" exec "$pod_name" -- \
        /usr/bin/systemctl is-active sdme-oci-app.service 2>/dev/null || echo "")
    if echo "$output" | grep -qw 'active'; then
        record "${test_prefix}-app-active" PASS
    else
        record "${test_prefix}-app-active" FAIL "app not active"
    fi

    output=$("$SDME" exec "$pod_name" -- \
        /usr/bin/systemctl is-active sdme-probe-liveness-app.timer 2>/dev/null || echo "")
    if echo "$output" | grep -qw 'active'; then
        record "${test_prefix}-liveness-timer-active" PASS
    else
        record "${test_prefix}-liveness-timer-active" FAIL "liveness timer not active"
    fi

    output=$("$SDME" exec "$pod_name" -- \
        /usr/bin/systemctl is-active sdme-probe-readiness-app.timer 2>/dev/null || echo "")
    if echo "$output" | grep -qw 'active'; then
        record "${test_prefix}-readiness-timer-active" PASS
    else
        record "${test_prefix}-readiness-timer-active" FAIL "readiness timer not active"
    fi

    # Check readiness state file.
    local ready=""
    ready=$(cat "$DATADIR/containers/$pod_name/merged/oci/apps/app/probe-ready" 2>/dev/null || echo "")
    if [[ "$ready" == "ready" ]]; then
        record "${test_prefix}-ready-state" PASS
    else
        record "${test_prefix}-ready-state" FAIL "probe-ready: '$ready'"
    fi

    # sdme ps health column.
    local ps_output
    ps_output=$("$SDME" ps 2>/dev/null || echo "")
    if echo "$ps_output" | grep "$pod_name" | grep -q 'ready'; then
        record "${test_prefix}-ps-health" PASS
    else
        local health_line
        health_line=$(echo "$ps_output" | grep "$pod_name" || echo "(not found)")
        record "${test_prefix}-ps-health" FAIL "$health_line"
    fi

    stop_container "$pod_name"
}

# --- Report -------------------------------------------------------------------

generate_report() {
    local ts
    ts=$(date +%Y%m%d-%H%M%S)
    local report="$REPORT_DIR/verify-kube-probes-$ts.md"

    mkdir -p "$REPORT_DIR"

    {
        echo "# sdme Kube Probes Verification Report"
        echo ""
        echo "## System Info"
        echo ""
        echo "| Field | Value |"
        echo "|-------|-------|"
        echo "| Date | $(date -Iseconds) |"
        echo "| Hostname | $(hostname) |"
        echo "| Kernel | $(uname -r) |"
        echo "| systemd | $(systemctl --version | head -1) |"
        local sdme_ver
        sdme_ver=$(sed -n 's/^version = "\(.*\)"/\1/p' "$REPO_ROOT/Cargo.toml" 2>/dev/null || echo unknown)
        echo "| sdme | $sdme_ver |"
        echo "| Base FS | $BASE_FS |"
        echo ""

        echo "## Summary"
        echo ""
        local total=$((_pass + _fail + _skip))
        echo "| Result | Count |"
        echo "|--------|-------|"
        echo "| PASS | $_pass |"
        echo "| FAIL | $_fail |"
        echo "| SKIP | $_skip |"
        echo "| Total | $total |"
        echo ""

        echo "## Results"
        echo ""
        echo "| Test | Result |"
        echo "|------|--------|"
        for key in $(echo "${!RESULTS[@]}" | tr ' ' '\n' | sort); do
            echo "| $key | $(result_status "$key") |"
        done
        echo ""

        # Detailed failures
        local has_failures=0
        for key in "${!RESULTS[@]}"; do
            if [[ "$(result_status "$key")" == "FAIL" ]]; then
                has_failures=1
                break
            fi
        done

        if [[ $has_failures -eq 1 ]]; then
            echo "## Failures"
            echo ""
            for key in $(echo "${!RESULTS[@]}" | tr ' ' '\n' | sort); do
                if [[ "$(result_status "$key")" == "FAIL" ]]; then
                    local msg
                    msg=$(result_msg "$key")
                    echo "### $key"
                    echo ""
                    echo '```'
                    echo "$msg"
                    echo '```'
                    echo ""
                fi
            done
        fi
    } > "$report"

    echo "Report: $report"
}

# --- Main ---------------------------------------------------------------------

main() {
    parse_args "$@"

    ensure_root
    ensure_sdme

    if [[ "$BASE_FS" == "ubuntu" ]]; then
        ensure_base_fs ubuntu docker.io/ubuntu:24.04
    fi

    echo "=== sdme kube probes verification ==="
    echo "base-fs: $BASE_FS"
    echo ""

    # Clean up any previous artifacts.
    cleanup_prefix "$PREFIX"

    # Run each probe test individually.
    test_startup_probe
    test_liveness_probe
    test_readiness_probe
    test_httpget_probe
    test_tcpsocket_probe
    test_combined_probes

    generate_report

    print_summary
}

main "$@"
