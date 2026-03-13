#!/usr/bin/env bash
set -uo pipefail

# verify-kube-L2-spec.sh - end-to-end verification of kube pod spec features
# Run as root. Requires a base-fs imported (e.g. ubuntu).
#
# Deploys a single pod that exercises all kube features at once to minimize
# image pulls (avoiding Docker Hub rate limits):
#   - terminationGracePeriodSeconds (pod-level)
#   - securityContext.runAsUser/runAsGroup (pod-level)
#   - initContainers with Type=oneshot, ordering deps
#   - workingDir override
#   - resources (limits + requests)
#   - readinessProbe (exec)
#
# Verifies both the generated unit files (static) and runtime behavior.
#
# --- K8s Pod Spec Gap Analysis ---
# Source of truth: src/kube.rs
#
# SUPPORTED:
#   Pod-level:
#     metadata.name, spec.containers, spec.initContainers, spec.volumes,
#     spec.restartPolicy, spec.terminationGracePeriodSeconds,
#     spec.securityContext (runAsUser, runAsGroup, runAsNonRoot)
#   Container-level:
#     name, image, command, args, env (name/value), ports (containerPort,
#     protocol, hostPort), volumeMounts (name, mountPath, readOnly),
#     workingDir, imagePullPolicy, resources (limits/requests for memory
#     and cpu), readinessProbe (exec only), livenessProbe (exec only),
#     securityContext (runAsUser, runAsGroup, runAsNonRoot)
#   Volume types:
#     emptyDir, hostPath (path, type), secret (secretName, items with
#     key/path, defaultMode), configMap (name, items with key/path,
#     defaultMode), persistentVolumeClaim (claimName)
#   env:
#     name/value, valueFrom (secretKeyRef, configMapKeyRef)
#   Top-level kinds:
#     v1 Pod, apps/v1 Deployment (extracts pod template)
#
# NOT SUPPORTED (notable):
#   env: envFrom (configMapRef, secretRef)
#   Probes: httpGet, tcpSocket, grpc; startupProbe; lifecycle hooks
#   Volumes: projected, downwardAPI, subPath, subPathExpr
#   Networking: hostNetwork, dnsPolicy, dnsConfig, hostAliases
#   Security: per-container securityContext (capabilities, seLinux,
#             seccompProfile, allowPrivilegeEscalation, readOnlyRootFilesystem)
#   Images: imagePullSecrets
#   Scheduling: nodeSelector, tolerations, affinity, nodeName,
#               topologySpreadConstraints (not applicable to single-node)
#   Other kinds: StatefulSet, DaemonSet, Job, CronJob
# --- End Gap Analysis ---

SDME="${SDME:-sdme}"
BASE_FS="${BASE_FS:-ubuntu}"
DATADIR="/var/lib/sdme"
KEEP=0
REPORT_DIR="."

POD_NAME="vfy-kf-all"

# Timeouts (seconds)
TIMEOUT_CREATE=600
TIMEOUT_BOOT=120

# Result tracking
declare -A RESULTS
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

# State flags
POD_CREATED=0
POD_RUNNING=0

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

End-to-end verification of sdme kube pod spec features.
Must be run as root.

Options:
  --base-fs NAME   Base rootfs to use (default: ubuntu)
  --keep           Do not remove test artifacts on exit
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
            --keep)
                KEEP=1
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
        PASS) ((PASS_COUNT++)); echo "  [PASS] $test_name${msg:+: $msg}" ;;
        FAIL) ((FAIL_COUNT++)); echo "  [FAIL] $test_name${msg:+: $msg}" ;;
        SKIP) ((SKIP_COUNT++)); echo "  [SKIP] $test_name${msg:+: $msg}" ;;
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

# Read a unit file from the kube rootfs.
read_unit() {
    local app_name="$1"
    cat "$DATADIR/fs/kube-$POD_NAME/etc/systemd/system/sdme-oci-${app_name}.service" 2>/dev/null || echo ""
}

# --- Cleanup ------------------------------------------------------------------

cleanup() {
    if [[ $KEEP -eq 1 ]]; then
        echo "==> Keeping test artifacts (--keep)"
        return
    fi
    echo "==> Cleaning up..."
    "$SDME" kube delete "$POD_NAME" --force 2>/dev/null || true
}

trap cleanup EXIT INT TERM

# --- Create the all-in-one test pod -------------------------------------------

test_create_pod() {
    local test_name="create-pod"
    local yaml_file
    yaml_file=$(mktemp /tmp/kube-feat-XXXXXX.yaml)

    cat > "$yaml_file" <<'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: vfy-kf-all
spec:
  terminationGracePeriodSeconds: 45
  securityContext:
    runAsUser: 65534
    runAsGroup: 65534
  initContainers:
  - name: init-setup
    image: docker.io/alpine:latest
    command: ["/bin/sh", "-c", "echo init-done"]
  containers:
  - name: testapp
    image: docker.io/alpine:latest
    command: ["/bin/sh", "-c", "touch /tmp/healthy && sleep infinity"]
    workingDir: /tmp
    resources:
      limits:
        memory: 256Mi
        cpu: "1"
      requests:
        memory: 128Mi
        cpu: 250m
    readinessProbe:
      exec:
        command: ["/bin/sh", "-c", "test -f /tmp/healthy"]
      initialDelaySeconds: 1
      periodSeconds: 1
      failureThreshold: 5
YAML

    echo "--- $test_name: creating pod ---"
    local output
    if output=$(timeout "$TIMEOUT_CREATE" "$SDME" kube create -f "$yaml_file" --base-fs "$BASE_FS" -v 2>&1); then
        record "$test_name" PASS
        POD_CREATED=1
    else
        record "$test_name" FAIL "$output"
    fi
    rm -f "$yaml_file"
}

# --- Unit file checks (static, no boot needed) --------------------------------

test_unit_termination_grace_period() {
    local test_name="unit-termination-grace-period"
    if [[ $POD_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "pod not created"
        return
    fi

    local unit
    unit=$(read_unit "app")
    if echo "$unit" | grep -q 'TimeoutStopSec=45s'; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "TimeoutStopSec=45s not found"
    fi
}

test_unit_working_dir() {
    local test_name="unit-working-dir"
    if [[ $POD_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "pod not created"
        return
    fi

    local unit
    unit=$(read_unit "app")
    # With isolate mode, the working dir is passed as an argument to .sdme-isolate,
    # so it appears in ExecStart rather than WorkingDirectory.
    if echo "$unit" | grep -q '/tmp'; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "working dir /tmp not found in unit"
        echo "    unit content:"
        echo "$unit"
    fi
}

test_unit_resources() {
    local test_name="unit-resources"
    if [[ $POD_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "pod not created"
        return
    fi

    local unit fail=0
    unit=$(read_unit "app")

    for directive in "MemoryMax=256M" "CPUQuota=100%" "MemoryLow=128M" "CPUWeight=250"; do
        if ! echo "$unit" | grep -q "$directive"; then
            echo "    missing: $directive"
            fail=1
        fi
    done

    if [[ $fail -eq 0 ]]; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "resource directives missing"
        echo "    unit content:"
        echo "$unit"
    fi
}

test_unit_security_context() {
    local test_name="unit-security-context"
    if [[ $POD_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "pod not created"
        return
    fi

    local unit
    unit=$(read_unit "app")
    if echo "$unit" | grep -q '\.sdme-isolate 65534 65534'; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "isolate 65534 65534 not found"
        echo "    unit content:"
        echo "$unit"
    fi
}

test_unit_init_container() {
    local test_name="unit-init-container"
    if [[ $POD_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "pod not created"
        return
    fi

    local init_unit fail=0
    init_unit=$(read_unit "init-setup")

    if ! echo "$init_unit" | grep -q 'Type=oneshot'; then
        echo "    missing: Type=oneshot"
        fail=1
    fi
    if ! echo "$init_unit" | grep -q 'RemainAfterExit=yes'; then
        echo "    missing: RemainAfterExit=yes"
        fail=1
    fi
    if echo "$init_unit" | grep -q '^Restart='; then
        echo "    unexpected: Restart= in oneshot unit"
        fail=1
    fi

    if [[ $fail -eq 0 ]]; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "init unit directives wrong"
        echo "    init unit:"
        echo "$init_unit"
    fi
}

test_unit_init_deps() {
    local test_name="unit-init-deps"
    if [[ $POD_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "pod not created"
        return
    fi

    local app_unit fail=0
    app_unit=$(read_unit "app")

    if ! echo "$app_unit" | grep -q 'After=.*sdme-oci-init-setup.service'; then
        echo "    missing: After= dependency on init-setup"
        fail=1
    fi
    if ! echo "$app_unit" | grep -q 'Requires=.*sdme-oci-init-setup.service'; then
        echo "    missing: Requires= dependency on init-setup"
        fail=1
    fi

    if [[ $fail -eq 0 ]]; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "app unit missing init dependencies"
        echo "    app unit:"
        echo "$app_unit"
    fi
}

test_unit_readiness_probe() {
    local test_name="unit-readiness-probe"
    if [[ $POD_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "pod not created"
        return
    fi

    local unit
    unit=$(read_unit "app")
    if echo "$unit" | grep -q 'ExecStartPost='; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "ExecStartPost not found"
        echo "    unit content:"
        echo "$unit"
    fi
}

# --- Runtime checks (boot the pod) -------------------------------------------

test_start_pod() {
    local test_name="start-pod"
    if [[ $POD_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "pod not created"
        return
    fi

    echo "--- $test_name: starting pod ---"
    local output
    if output=$(timeout "$TIMEOUT_BOOT" "$SDME" start "$POD_NAME" -v 2>&1); then
        record "$test_name" PASS
        POD_RUNNING=1
        echo "    waiting 5s for services to settle..."
        sleep 5
    else
        record "$test_name" FAIL "$output"
    fi
}

test_runtime_init_service() {
    local test_name="runtime-init-service"
    if [[ $POD_RUNNING -eq 0 ]]; then
        record "$test_name" SKIP "pod not running"
        return
    fi

    local output
    output=$("$SDME" exec "$POD_NAME" -- \
        /usr/bin/systemctl is-active sdme-oci-init-setup.service 2>/dev/null || echo "")
    # machinectl outputs banner on stdout; grep for the status keyword.
    if echo "$output" | grep -qw 'active'; then
        record "$test_name" PASS
    else
        # Extract just non-banner lines for the error message.
        local status
        status=$(echo "$output" | grep -v 'Connected to\|Press \^]\|Connection to\|^$' | tail -1)
        record "$test_name" FAIL "init service: $status"
    fi
}

test_runtime_app_service() {
    local test_name="runtime-app-service"
    if [[ $POD_RUNNING -eq 0 ]]; then
        record "$test_name" SKIP "pod not running"
        return
    fi

    local output
    output=$("$SDME" exec "$POD_NAME" -- \
        /usr/bin/systemctl is-active sdme-oci-testapp.service 2>/dev/null || echo "")
    if echo "$output" | grep -qw '^active'; then
        record "$test_name" PASS
    else
        local status
        status=$(echo "$output" | grep -v 'Connected to\|Press \^]\|Connection to\|^$' | tail -1)
        record "$test_name" FAIL "app service: $status"
        "$SDME" exec "$POD_NAME" -- /usr/bin/systemctl status sdme-oci-testapp.service 2>&1 || true
    fi
}

test_runtime_memory_limit() {
    local test_name="runtime-memory-limit"
    if [[ $POD_RUNNING -eq 0 ]]; then
        record "$test_name" SKIP "pod not running"
        return
    fi

    # Check cgroup memory limit applied to the service.
    local output
    output=$("$SDME" exec "$POD_NAME" -- \
        /usr/bin/systemctl show sdme-oci-testapp.service -p MemoryMax --value 2>/dev/null || echo "")
    # 256Mi = 268435456 bytes; grep for the number in the output.
    if echo "$output" | grep -q '268435456'; then
        record "$test_name" PASS "MemoryMax=268435456"
    else
        local mem_max
        mem_max=$(echo "$output" | grep -v 'Connected to\|Press \^]\|Connection to\|^$' | tail -1)
        record "$test_name" FAIL "expected 268435456, got: $mem_max"
    fi
}

# --- Report -------------------------------------------------------------------

generate_report() {
    local ts
    ts=$(date +%Y%m%d-%H%M%S)
    local report="$REPORT_DIR/verify-kube-features-$ts.md"

    mkdir -p "$REPORT_DIR"

    {
        echo "# sdme Kube Features Verification Report"
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
        sdme_ver=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml 2>/dev/null || echo unknown)
        echo "| sdme | $sdme_ver |"
        echo "| Base FS | $BASE_FS |"
        echo ""

        echo "## Summary"
        echo ""
        local total=$((PASS_COUNT + FAIL_COUNT + SKIP_COUNT))
        echo "| Result | Count |"
        echo "|--------|-------|"
        echo "| PASS | $PASS_COUNT |"
        echo "| FAIL | $FAIL_COUNT |"
        echo "| SKIP | $SKIP_COUNT |"
        echo "| Total | $total |"
        echo ""

        echo "## Results"
        echo ""
        echo "| Test | Result |"
        echo "|------|--------|"
        for test_name in create-pod \
            unit-termination-grace-period unit-working-dir unit-resources \
            unit-security-context unit-init-container unit-init-deps \
            unit-readiness-probe \
            start-pod runtime-init-service runtime-app-service \
            runtime-memory-limit; do
            if [[ -n "${RESULTS[$test_name]+x}" ]]; then
                echo "| $test_name | $(result_status "$test_name") |"
            fi
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

    if [[ $EUID -ne 0 ]]; then
        echo "error: must be run as root" >&2
        exit 1
    fi

    if [[ ! -d "$DATADIR/fs/$BASE_FS" ]]; then
        echo "error: base rootfs '$BASE_FS' not found; import it first:" >&2
        echo "  sdme fs import docker.io/$BASE_FS:latest -n $BASE_FS" >&2
        exit 1
    fi

    echo "=== sdme kube features verification ==="
    echo "base-fs: $BASE_FS"
    echo "pod:     $POD_NAME"
    echo ""

    # Phase 1: Create the pod (single pull).
    test_create_pod

    # Phase 2: Verify unit file contents (static checks).
    echo ""
    echo "--- unit file checks ---"
    test_unit_termination_grace_period
    test_unit_working_dir
    test_unit_resources
    test_unit_security_context
    test_unit_init_container
    test_unit_init_deps
    test_unit_readiness_probe

    # Phase 3: Boot and verify runtime behavior.
    echo ""
    echo "--- runtime checks ---"
    test_start_pod
    test_runtime_init_service
    test_runtime_app_service
    test_runtime_memory_limit

    echo ""
    echo "=== Results ==="
    echo "Total: $PASS_COUNT passed, $FAIL_COUNT failed, $SKIP_COUNT skipped"

    generate_report

    [[ $FAIL_COUNT -eq 0 ]]
}

main "$@"
