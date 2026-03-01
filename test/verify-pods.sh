#!/usr/bin/env bash
set -euo pipefail

# verify-pods.sh - end-to-end pod verification
# Must run as root. Requires a base Ubuntu rootfs imported as "ubuntu".
#
# Usage:
#   sudo sdme fs import ubuntu docker.io/ubuntu:24.04 -v
#   sudo ./test/verify-pods.sh
#
# Tests:
#   1. nspawn pods (--pod): two host-rootfs containers share localhost via pod netns
#   2. --pod + --private-network: private-network silently dropped, loopback works
#   3. Validation: error cases (--pod + userns, --oci-pod w/o rootfs, etc.)

SDME="${SDME:-sdme}"
VERBOSE="${VERBOSE:-}"
VFLAG=""
if [[ -n "$VERBOSE" ]]; then
    VFLAG="-v"
fi

TIMEOUT_BOOT=120
TIMEOUT_TEST=60

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
    timeout 30 "$SDME" stop "$1" 2>/dev/null || \
        timeout 30 "$SDME" stop --term "$1" 2>/dev/null || true
    "$SDME" rm -f "$1" 2>/dev/null || true
}

cleanup_pod() {
    $SDME pod rm -f "$1" 2>/dev/null || true
}

cleanup_all() {
    echo "Cleaning up pod test artifacts..."
    local names
    names=$($SDME ps 2>/dev/null | awk 'NR>1 {print $1}' | grep -E '^(pod-|val-)' || true)
    for name in $names; do
        cleanup_container "$name"
    done
    cleanup_pod testpod
    cleanup_pod pnpod
    cleanup_pod valpod
}

trap cleanup_all EXIT INT TERM

# -- Preflight -----------------------------------------------------------------

if [[ $(id -u) -ne 0 ]]; then
    echo "error: must run as root" >&2
    exit 1
fi

if ! command -v "$SDME" &>/dev/null; then
    echo "error: $SDME not found in PATH" >&2
    exit 1
fi

# Check ubuntu rootfs exists.
if ! "$SDME" fs ls 2>/dev/null | awk 'NR>1 {print $1}' | grep -qx "ubuntu"; then
    echo "error: rootfs 'ubuntu' not found" >&2
    echo "import it first: sudo sdme fs import ubuntu docker.io/ubuntu:24.04 -v --install-packages=yes" >&2
    exit 1
fi

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
# Test 2: --pod + --private-network (without userns)
# ---------------------------------------------------------------------------
echo "=== Test 2: --pod + --private-network ==="

# --private-network is silently dropped when a pod provides the netns.
# This tests the non-userns path: --private-network without --hardened/--userns.
cleanup_container pod-pn1
cleanup_container pod-pn2
cleanup_pod pnpod

$SDME pod new pnpod $VFLAG
$SDME create --pod=pnpod --private-network -r ubuntu pod-pn1 $VFLAG
$SDME create --pod=pnpod --private-network -r ubuntu pod-pn2 $VFLAG

timeout "$TIMEOUT_BOOT" "$SDME" start pod-pn1 -t "$TIMEOUT_BOOT" $VFLAG 2>&1
timeout "$TIMEOUT_BOOT" "$SDME" start pod-pn2 -t "$TIMEOUT_BOOT" $VFLAG 2>&1

# Verify --private-network is omitted from the nspawn drop-in.
dropin="/etc/systemd/system/sdme@pod-pn1.service.d/nspawn.conf"
if [[ -f "$dropin" ]] && grep -q -- "--network-namespace-path=" "$dropin"; then
    if ! grep -q -- "--private-network" "$dropin"; then
        ok "--pod + --private-network: --private-network omitted from drop-in"
    else
        fail "--pod + --private-network: --private-network should be omitted"
    fi
else
    fail "--pod + --private-network: drop-in missing or no --network-namespace-path"
fi

# Loopback connectivity.
machinectl shell pod-pn1 /usr/bin/systemd-run --unit=test-listener \
    /usr/bin/python3 -c \
    'import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("127.0.0.1",9997)); s.listen(1); c,_=s.accept(); c.sendall(b"PRIVNET\n"); c.close(); s.close()' \
    >/dev/null 2>&1
sleep 1

result=$(machinectl shell pod-pn2 /usr/bin/python3 -c \
    'import socket; s=socket.socket(); s.settimeout(2); s.connect(("127.0.0.1",9997)); print(s.recv(1024).decode().strip()); s.close()' \
    2>/dev/null || true)
if [[ "$result" == *"PRIVNET"* ]]; then
    ok "--pod + --private-network: containers share loopback"
else
    fail "--pod + --private-network: loopback failed (got: '$result')"
fi

cleanup_container pod-pn1
cleanup_container pod-pn2
cleanup_pod pnpod

# ---------------------------------------------------------------------------
# Test 3: Validation
# ---------------------------------------------------------------------------
echo "=== Test 3: Validation ==="

# 3a: --pod + --hardened → should error (kernel blocks setns(CLONE_NEWNET)
# across user namespace boundaries; use --oci-pod instead)
$SDME pod new valpod $VFLAG
if err=$($SDME create --pod=valpod --hardened -r ubuntu val-err0 2>&1); then
    fail "--pod + --hardened should error"
    cleanup_container val-err0
else
    if echo "$err" | grep -q "incompatible with user namespace"; then
        ok "--pod + --hardened rejected (userns incompatible)"
    else
        fail "--pod + --hardened: unexpected error: $err"
    fi
fi

# 3b: --pod + --userns → should error (same reason)
if err=$($SDME create --pod=valpod --userns -r ubuntu val-err0b 2>&1); then
    fail "--pod + --userns should error"
    cleanup_container val-err0b
else
    if echo "$err" | grep -q "incompatible with user namespace"; then
        ok "--pod + --userns rejected (userns incompatible)"
    else
        fail "--pod + --userns: unexpected error: $err"
    fi
fi

# 3c: --oci-pod without OCI app rootfs → should error
$SDME pod new valpod 2>/dev/null || true
if $SDME create --oci-pod=valpod val-err1 2>/dev/null; then
    fail "--oci-pod without OCI rootfs should error"
    cleanup_container val-err1
else
    ok "--oci-pod without OCI rootfs rejected"
fi

# 3d: --pod=nonexistent → should error
if $SDME create --pod=nonexistent val-err2 2>/dev/null; then
    fail "--pod=nonexistent should error"
    cleanup_container val-err2
else
    ok "--pod=nonexistent rejected"
fi

# 3e: --oci-pod + --hardened → should succeed (OCI app enters pod netns via
# inner systemd drop-in, not via nspawn's --network-namespace-path, so userns
# is not a problem). Without an OCI app rootfs the error should be about the
# rootfs, not about network/userns conflicts.
err_msg=$($SDME create --oci-pod=valpod --hardened val-err3 2>&1 || true)
if echo "$err_msg" | grep -q "requires an OCI app rootfs"; then
    ok "--oci-pod + --hardened not rejected for network conflict"
else
    fail "--oci-pod + --hardened error unexpected: $err_msg"
fi
cleanup_container val-err3

cleanup_pod valpod

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: $pass passed, $fail failed"
if [[ $fail -gt 0 ]]; then
    exit 1
fi
