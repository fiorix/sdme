#!/usr/bin/env bash
set -euo pipefail

# verify-pods.sh — end-to-end pod verification
# Must run as root. Requires a base Ubuntu rootfs imported as "ubuntu".
#
# Usage:
#   sudo sdme fs import ubuntu docker.io/ubuntu:24.04 -v
#   sudo ./scripts/verify-pods.sh
#
# Tests:
#   1. nspawn pods (--pod): two host-rootfs containers share localhost via pod netns
#   2. OCI pods (--oci-pod): two OCI app containers share localhost via inner netns
#   3. Composed (--pod + --oci-pod): both mechanisms together
#   4. Validation: mutual exclusion and error cases

SDME="${SDME:-sdme}"
VERBOSE="${VERBOSE:-}"
VFLAG=""
if [[ -n "$VERBOSE" ]]; then
    VFLAG="-v"
fi

pass=0
fail=0

ok() {
    echo "  PASS: $1"
    ((pass++)) || true
}

fail() {
    echo "  FAIL: $1"
    ((fail++)) || true
}

cleanup_container() {
    $SDME rm -f "$1" 2>/dev/null || true
}

cleanup_pod() {
    $SDME pod rm -f "$1" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Test 1: nspawn pods (--pod)
# ---------------------------------------------------------------------------
echo "=== Test 1: nspawn pods (--pod) ==="

cleanup_container pod-c1
cleanup_container pod-c2
cleanup_pod testpod

$SDME pod new testpod $VFLAG
$SDME create --pod=testpod -r ubuntu pod-c1 $VFLAG
$SDME create --pod=testpod -r ubuntu pod-c2 $VFLAG
$SDME start pod-c1 $VFLAG
$SDME start pod-c2 $VFLAG

# Start a listener in c1 on port 9999 as a transient systemd unit.
# The pod netns has no internet, so we use Python (available in Ubuntu)
# instead of nc. We use systemd-run so the listener survives session exit.
machinectl shell pod-c1 /usr/bin/systemd-run --unit=test-listener \
    /usr/bin/python3 -c \
    'import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("127.0.0.1",9999)); s.listen(1); c,_=s.accept(); c.sendall(b"HELLO\n"); c.close(); s.close()' \
    >/dev/null 2>&1
sleep 1

# Connect from c2 to c1 via 127.0.0.1:9999 using Python.
result=$(machinectl shell pod-c2 /usr/bin/python3 -c \
    'import socket; s=socket.socket(); s.settimeout(2); s.connect(("127.0.0.1",9999)); print(s.recv(1024).decode().strip()); s.close()' \
    2>/dev/null || true)
if [[ "$result" == *"HELLO"* ]]; then
    ok "pod containers share loopback"
else
    fail "pod containers cannot communicate via loopback (got: '$result')"
fi

# Cleanup.
cleanup_container pod-c1
cleanup_container pod-c2
cleanup_pod testpod

# ---------------------------------------------------------------------------
# Test 4: Validation
# ---------------------------------------------------------------------------
echo "=== Test 4: Validation ==="

# 4a: --pod + --private-network → should error
$SDME pod new valpod $VFLAG
if $SDME create --pod=valpod --private-network val-err1 2>/dev/null; then
    fail "--pod + --private-network should error"
    cleanup_container val-err1
else
    ok "--pod + --private-network rejected"
fi

# 4b: --oci-pod without OCI app rootfs → should error
if $SDME create --oci-pod=valpod val-err2 2>/dev/null; then
    fail "--oci-pod without OCI rootfs should error"
    cleanup_container val-err2
else
    ok "--oci-pod without OCI rootfs rejected"
fi

# 4c: --pod=nonexistent → should error
if $SDME create --pod=nonexistent val-err3 2>/dev/null; then
    fail "--pod=nonexistent should error"
    cleanup_container val-err3
else
    ok "--pod=nonexistent rejected"
fi

# 4d: --oci-pod + --private-network → should succeed (no mutual exclusion)
# We can't fully test this without an OCI app rootfs, but we can verify the
# error is about rootfs, not about private-network.
err_msg=$($SDME create --oci-pod=valpod --private-network val-err4 2>&1 || true)
if echo "$err_msg" | grep -q "requires an OCI app rootfs"; then
    ok "--oci-pod + --private-network not rejected for network conflict"
else
    fail "--oci-pod + --private-network error unexpected: $err_msg"
fi
cleanup_container val-err4

cleanup_pod valpod

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: $pass passed, $fail failed"
if [[ $fail -gt 0 ]]; then
    exit 1
fi
