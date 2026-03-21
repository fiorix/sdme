#!/usr/bin/env bash
set -uo pipefail

# verify-kube-L5-redis-stack.sh - redis data round-trip in a kube pod
# Run as root. Requires a base-fs imported (e.g. ubuntu).
#
# Two-container pod with a real service and data validation:
#   - redis server accepting connections on 6379
#   - busybox client (unused; python3 from base OS drives validation)
#
# Tests: service readiness, PING/PONG, SET/GET round-trip via raw
# Redis protocol over a TCP socket from the container's base OS.

source "$(dirname "$0")/lib.sh"

BASE_FS="${BASE_FS:-ubuntu}"
DATADIR="/var/lib/sdme"
REPORT_DIR="."

POD_NAME="vfy-kube-redis"
YAML_FILE="test/kube/redis-pod.yaml"

# Timeouts (seconds)
TIMEOUT_CREATE=$(scale_timeout 600)
TIMEOUT_BOOT=$(scale_timeout 120)
TIMEOUT_READY=$(scale_timeout 90)

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
        YAML_FILE="$(dirname "$0")/../kube/redis-pod.yaml"
    fi
    if [[ ! -f "$YAML_FILE" ]]; then
        record "$test_name" FAIL "YAML file not found"
        return
    fi

    echo "--- $test_name: creating pod from redis-pod.yaml ---"
    local output
    if output=$(timeout "$TIMEOUT_CREATE" "$SDME" kube create -f "$YAML_FILE" --base-fs "$BASE_FS" -v 2>&1); then
        record "$test_name" PASS
        POD_CREATED=1
    else
        record "$test_name" FAIL "$output"
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

test_service_redis() {
    local test_name="service/redis"
    if [[ $POD_RUNNING -eq 0 ]]; then
        record "$test_name" SKIP "pod not running"
        return
    fi

    local ok=0 output
    for i in $(seq 1 10); do
        sleep 3
        output=$("$SDME" exec "$POD_NAME" -- /usr/bin/systemctl is-active sdme-oci-redis.service 2>&1 || true)
        if echo "$output" | grep -q '^active'; then
            ok=1
            break
        fi
    done

    if [[ $ok -eq 1 ]]; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "redis service not active"
        "$SDME" exec "$POD_NAME" -- /usr/bin/systemctl status sdme-oci-redis.service 2>&1 || true
    fi
}

test_ready_redis() {
    local test_name="ready/redis"
    if [[ $POD_RUNNING -eq 0 ]]; then
        record "$test_name" SKIP "pod not running"
        return
    fi

    echo "--- $test_name: waiting for port 6379 (up to ${TIMEOUT_READY}s) ---"
    if "$SDME" exec "$POD_NAME" -- /usr/bin/python3 -c "
import socket,sys,time
end=time.time()+${TIMEOUT_READY}
while time.time()<end:
 try: s=socket.create_connection(('127.0.0.1',6379),2); s.close(); sys.exit(0)
 except: time.sleep(3)
sys.exit(1)" 2>/dev/null; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "port 6379 not listening after ${TIMEOUT_READY}s"
    fi
}

test_redis_ping() {
    local test_name="redis/ping"
    if [[ $POD_RUNNING -eq 0 ]]; then
        record "$test_name" SKIP "pod not running"
        return
    fi
    if [[ "$(result_status "ready/redis")" != "PASS" ]]; then
        record "$test_name" SKIP "redis not ready"
        return
    fi

    echo "--- $test_name: sending PING to redis ---"
    local output
    output=$("$SDME" exec "$POD_NAME" -- /usr/bin/python3 -c "
import socket
s = socket.create_connection(('127.0.0.1', 6379), 10)
s.sendall(b'PING\r\n')
data = s.recv(64).decode().strip()
s.close()
print(data)
" 2>&1 || echo "")

    if echo "$output" | grep -q '+PONG'; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "expected +PONG, got: $output"
    fi
}

test_redis_set_get() {
    local test_name="redis/set-get"
    if [[ $POD_RUNNING -eq 0 ]]; then
        record "$test_name" SKIP "pod not running"
        return
    fi
    if [[ "$(result_status "redis/ping")" != "PASS" ]]; then
        record "$test_name" SKIP "redis ping failed"
        return
    fi

    echo "--- $test_name: SET/GET round-trip ---"
    local output
    output=$("$SDME" exec "$POD_NAME" -- /usr/bin/python3 -c "
import socket
s = socket.create_connection(('127.0.0.1', 6379), 10)
# SET
s.sendall(b'SET sdme-test-key kube-L5-ok\r\n')
r = s.recv(64).decode().strip()
if r != '+OK':
    print(f'SET failed: {r}')
    raise SystemExit(1)
# GET
s.sendall(b'GET sdme-test-key\r\n')
# Redis bulk string: \$N\r\ndata\r\n
r = b''
while b'kube-L5-ok' not in r:
    r += s.recv(256)
s.close()
data = r.decode()
print(data.strip())
" 2>&1 || echo "")

    if echo "$output" | grep -q 'kube-L5-ok'; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "expected 'kube-L5-ok', got: $output"
    fi
}

# --- Main ---------------------------------------------------------------------

main() {
    parse_standard_args "End-to-end verification of sdme Kubernetes Redis stack." "$@"

    ensure_root
    ensure_sdme
    require_gate smoke
    require_gate interrupt
    require_gate kube-l1

    ensure_default_base_fs

    echo "=== sdme kube redis verification ==="
    echo "base-fs: $BASE_FS"
    echo "pod:     $POD_NAME"
    echo ""

    test_create_pod
    test_start_pod
    test_service_redis
    test_ready_redis
    test_redis_ping
    test_redis_set_get

    generate_standard_report "verify-kube-L5-redis" "sdme Kube Redis Stack Verification Report"

    print_summary
}

main "$@"
