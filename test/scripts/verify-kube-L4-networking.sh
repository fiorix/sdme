#!/usr/bin/env bash
set -uo pipefail

# verify-kube-L4-networking.sh - inter-container localhost networking test
# Run as root. Requires a base-fs imported (e.g. ubuntu).
#
# Two-container pod proving localhost network sharing:
#   - nginx-unprivileged serves HTTP on port 8080
#   - busybox client fetches from 127.0.0.1:8080
#
# This is the key kube networking assertion: containers in the same pod
# share a network namespace and can communicate via localhost.

source "$(dirname "$0")/lib.sh"

BASE_FS="${BASE_FS:-ubuntu}"
DATADIR="/var/lib/sdme"
REPORT_DIR="."

POD_NAME="vfy-kube-net"
YAML_FILE="test/kube/networking-pod.yaml"

# Timeouts (seconds)
TIMEOUT_CREATE=600
TIMEOUT_BOOT=120
TIMEOUT_READY=90

# State flags
POD_CREATED=0
POD_RUNNING=0

# --- Cleanup ------------------------------------------------------------------

cleanup() {
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

    echo "--- $test_name: writing nginx config for port 8080 ---"
    local conf_dir="$DATADIR/containers/$POD_NAME/upper/oci/apps/nginx-unprivileged/root/etc/nginx/conf.d"
    mkdir -p "$conf_dir"

    cat > "$conf_dir/default.conf" <<'NGINXEOF'
server {
    listen 8080;
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

    echo "--- $test_name: waiting for port 8080 (up to ${TIMEOUT_READY}s) ---"
    if "$SDME" exec "$POD_NAME" -- /usr/bin/python3 -c "
import socket,sys,time
end=time.time()+${TIMEOUT_READY}
while time.time()<end:
 try: s=socket.create_connection(('127.0.0.1',8080),2); s.close(); sys.exit(0)
 except: time.sleep(3)
sys.exit(1)" 2>/dev/null; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "port 8080 not listening after ${TIMEOUT_READY}s"
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
    output=$("$SDME" exec "$POD_NAME" --oci client -- \
        /bin/wget -qO- http://127.0.0.1:8080 2>&1 || echo "")

    if echo "$output" | grep -q 'kube-net-ok'; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "expected 'kube-net-ok', got: $output"
    fi
}

# --- Main ---------------------------------------------------------------------

main() {
    parse_standard_args "End-to-end verification of sdme Kubernetes networking." "$@"

    ensure_root
    ensure_sdme

    ensure_default_base_fs

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

    generate_standard_report "verify-kube-L4-networking" "sdme Kube Networking Verification Report"

    print_summary
}

main "$@"
