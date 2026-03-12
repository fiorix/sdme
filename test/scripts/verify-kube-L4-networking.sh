#!/usr/bin/env bash
set -uo pipefail

# verify-kube-L4-networking.sh - inter-container localhost networking test
# Run as root. Requires a base-fs imported (e.g. ubuntu).
#
# Two-container pod proving localhost network sharing:
#   - nginx-unprivileged serves HTTP on port 8888
#   - busybox client fetches from 127.0.0.1:8888
#
# This is the key kube networking assertion: containers in the same pod
# share a network namespace and can communicate via localhost.

SDME="${SDME:-sdme}"
BASE_FS="${BASE_FS:-ubuntu}"
DATADIR="/var/lib/sdme"
KEEP=0
REPORT_DIR="."

POD_NAME="vfy-kube-net"
YAML_FILE="test/kube/networking-pod.yaml"

# Timeouts (seconds)
TIMEOUT_CREATE=600
TIMEOUT_BOOT=120
TIMEOUT_READY=90

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

End-to-end verification of kube inter-container localhost networking.
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

# --- Tests --------------------------------------------------------------------

test_create_pod() {
    local test_name="create-pod"

    if [[ ! -f "$YAML_FILE" ]]; then
        # Try relative to script location.
        YAML_FILE="$(dirname "$0")/../kube/networking-pod.yaml"
    fi
    if [[ ! -f "$YAML_FILE" ]]; then
        record "$test_name" FAIL "YAML file not found"
        return
    fi

    echo "--- $test_name: creating pod from networking-pod.yaml ---"
    local output
    if output=$(timeout "$TIMEOUT_CREATE" "$SDME" kube create -f "$YAML_FILE" --base-fs "$BASE_FS" -v 2>&1); then
        record "$test_name" PASS
        POD_CREATED=1
    else
        record "$test_name" FAIL "$output"
    fi
}

test_inject_nginx_config() {
    local test_name="setup/nginx-config"
    if [[ $POD_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "pod not created"
        return
    fi

    echo "--- $test_name: writing nginx config for port 8888 ---"
    local conf_dir="$DATADIR/containers/$POD_NAME/upper/oci/apps/nginx-unprivileged/root/etc/nginx/conf.d"
    mkdir -p "$conf_dir"

    cat > "$conf_dir/default.conf" <<'NGINXEOF'
server {
    listen 8888;
    server_name _;
    location / {
        return 200 'kube-net-ok\n';
        add_header Content-Type text/plain;
    }
}
NGINXEOF

    if [[ -f "$conf_dir/default.conf" ]]; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "could not write nginx config"
    fi
}

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

test_service_nginx() {
    local test_name="service/nginx-unprivileged"
    if [[ $POD_RUNNING -eq 0 ]]; then
        record "$test_name" SKIP "pod not running"
        return
    fi

    local ok=0 output
    for i in $(seq 1 10); do
        sleep 3
        output=$("$SDME" exec "$POD_NAME" -- /usr/bin/systemctl is-active sdme-oci-nginx-unprivileged.service 2>&1 || true)
        if echo "$output" | grep -q '^active'; then
            ok=1
            break
        fi
    done

    if [[ $ok -eq 1 ]]; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "nginx service not active"
        "$SDME" exec "$POD_NAME" -- /usr/bin/systemctl status sdme-oci-nginx-unprivileged.service 2>&1 || true
    fi
}

test_ready_nginx() {
    local test_name="ready/nginx"
    if [[ $POD_RUNNING -eq 0 ]]; then
        record "$test_name" SKIP "pod not running"
        return
    fi

    echo "--- $test_name: waiting for port 8888 (up to ${TIMEOUT_READY}s) ---"
    if "$SDME" exec "$POD_NAME" -- /usr/bin/python3 -c "
import socket,sys,time
end=time.time()+${TIMEOUT_READY}
while time.time()<end:
 try: s=socket.create_connection(('127.0.0.1',8888),2); s.close(); sys.exit(0)
 except: time.sleep(3)
sys.exit(1)" 2>/dev/null; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "port 8888 not listening after ${TIMEOUT_READY}s"
    fi
}

test_localhost_http() {
    local test_name="networking/localhost-http"
    if [[ $POD_RUNNING -eq 0 ]]; then
        record "$test_name" SKIP "pod not running"
        return
    fi
    if [[ "$(result_status "ready/nginx")" != "PASS" ]]; then
        record "$test_name" SKIP "nginx not ready"
        return
    fi

    echo "--- $test_name: busybox client fetching from nginx via localhost ---"
    local output
    output=$("$SDME" exec "$POD_NAME" --oci-app client -- \
        wget -qO- http://127.0.0.1:8888 2>&1 || echo "")

    if echo "$output" | grep -q 'kube-net-ok'; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "expected 'kube-net-ok', got: $output"
    fi
}

# --- Report -------------------------------------------------------------------

generate_report() {
    local ts
    ts=$(date +%Y%m%d-%H%M%S)
    local report="$REPORT_DIR/verify-kube-L4-networking-$ts.md"

    mkdir -p "$REPORT_DIR"

    {
        echo "# sdme Kube Networking Verification Report"
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
        for test_name in create-pod setup/nginx-config start-pod \
            service/nginx-unprivileged ready/nginx networking/localhost-http; do
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

    echo "=== sdme kube networking verification ==="
    echo "base-fs: $BASE_FS"
    echo "pod:     $POD_NAME"
    echo ""

    test_create_pod
    test_inject_nginx_config
    test_start_pod
    test_service_nginx
    test_ready_nginx
    test_localhost_http

    echo ""
    echo "=== Results ==="
    echo "Total: $PASS_COUNT passed, $FAIL_COUNT failed, $SKIP_COUNT skipped"

    generate_report

    [[ $FAIL_COUNT -eq 0 ]]
}

main "$@"
