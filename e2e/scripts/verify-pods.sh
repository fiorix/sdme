#!/usr/bin/env bash
set -euo pipefail

# verify-pods.sh - end-to-end pod verification
#
# Tests:
#   1. nspawn pods (--pod): two host-rootfs containers share localhost via pod netns
#   2. --pod + --private-network: private-network silently dropped, loopback works
#   3. Validation: error cases (--oci-pod w/o --private-network, --pod + userns, etc.)
#   4. Pod name prefixes: --pod and pod rm accept a unique prefix, the state
#      file records the full name, an ambiguous prefix is refused

source "$(dirname "$0")/lib.sh"

TIMEOUT_BOOT=$(scale_timeout 120)
TIMEOUT_TEST=$(scale_timeout 60)

cleanup_pod() {
    $SDME pod rm -f "$1" 2>/dev/null || true
}

cleanup_all() {
    local names
    names=$($SDME ps 2>/dev/null | awk 'NR>1 {print $1}' | grep -E '^(pod-|val-)' || true)
    for name in $names; do
        cleanup_container "$name"
    done
    cleanup_pod testpod
    cleanup_pod pnpod
    cleanup_pod valpod
    cleanup_pod pfxpod-alpha
    cleanup_pod pfxpod-beta
}

trap cleanup_all EXIT INT TERM

ensure_root
ensure_sdme
require_gate smoke
require_gate interrupt
ensure_base_fs ubuntu docker.io/ubuntu
ensure_python3_in_rootfs ubuntu

# ---------------------------------------------------------------------------
# Test 1: nspawn pods (--pod)
# ---------------------------------------------------------------------------
echo "=== Test 1: nspawn pods (--pod) ==="

cleanup_container pod-c1
cleanup_container pod-c2
cleanup_pod testpod

$SDME pod new testpod $VFLAG
$SDME create --name pod-c1 --pod=testpod -r ubuntu $VFLAG
$SDME create --name pod-c2 --pod=testpod -r ubuntu $VFLAG
$SDME start pod-c1 $VFLAG
$SDME start pod-c2 $VFLAG

# Start a listener in c1 on port 9999 as a transient systemd unit.
# The pod netns has no internet, so we use Python (available in Ubuntu)
# instead of nc. We use systemd-run so the listener survives session exit.
$SDME exec pod-c1 /usr/bin/systemd-run --unit=test-listener \
    /usr/bin/python3 -c \
    'import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("127.0.0.1",9999)); s.listen(1); c,_=s.accept(); c.sendall(b"HELLO\n"); c.close(); s.close()' \
    >/dev/null 2>&1
sleep 1

# Connect from c2 to c1 via 127.0.0.1:9999 using Python.
result=$($SDME exec pod-c2 /usr/bin/python3 -c \
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
$SDME create --name pod-pn1 --pod=pnpod --private-network -r ubuntu $VFLAG
$SDME create --name pod-pn2 --pod=pnpod --private-network -r ubuntu $VFLAG

timeout "$TIMEOUT_BOOT" "$SDME" start pod-pn1 -t "$TIMEOUT_BOOT" $VFLAG 2>&1
timeout "$TIMEOUT_BOOT" "$SDME" start pod-pn2 -t "$TIMEOUT_BOOT" $VFLAG 2>&1

# Verify nsenter --net= is used and --private-network is omitted from the drop-in.
dropin="/etc/systemd/system/sdme@pod-pn1.service.d/nspawn.conf"
if [[ -f "$dropin" ]] && grep -q "nsenter --net=" "$dropin"; then
    if ! grep -q -- "--private-network" "$dropin"; then
        ok "--pod + --private-network: --private-network omitted, nsenter used"
    else
        fail "--pod + --private-network: --private-network should be omitted"
    fi
else
    fail "--pod + --private-network: drop-in missing or no nsenter --net="
fi

# Loopback connectivity.
$SDME exec pod-pn1 /usr/bin/systemd-run --unit=test-listener \
    /usr/bin/python3 -c \
    'import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("127.0.0.1",9997)); s.listen(1); c,_=s.accept(); c.sendall(b"PRIVNET\n"); c.close(); s.close()' \
    >/dev/null 2>&1
sleep 1

result=$($SDME exec pod-pn2 /usr/bin/python3 -c \
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

# 3a: --pod + --hardened → should succeed (nsenter enters the netns before
# nspawn creates the userns, avoiding the cross-userns setns restriction)
$SDME pod new valpod $VFLAG
if $SDME create --name val-h1 --pod=valpod --hardened -r ubuntu $VFLAG; then
    dropin="/etc/systemd/system/sdme@val-h1.service.d/nspawn.conf"
    timeout "$TIMEOUT_BOOT" "$SDME" start val-h1 -t "$TIMEOUT_BOOT" $VFLAG 2>&1
    if [[ -f "$dropin" ]] && grep -q "nsenter --net=" "$dropin" \
            && grep -q -- "--private-users=" "$dropin"; then
        ok "--pod + --hardened: nsenter + userns in drop-in"
    else
        fail "--pod + --hardened: expected nsenter and --private-users=pick in drop-in"
    fi
    cleanup_container val-h1
else
    fail "--pod + --hardened should succeed"
fi

# 3b: --pod + --userns → should succeed (same nsenter mechanism)
if $SDME create --name val-u1 --pod=valpod --userns -r ubuntu $VFLAG; then
    dropin="/etc/systemd/system/sdme@val-u1.service.d/nspawn.conf"
    timeout "$TIMEOUT_BOOT" "$SDME" start val-u1 -t "$TIMEOUT_BOOT" $VFLAG 2>&1
    if [[ -f "$dropin" ]] && grep -q "nsenter --net=" "$dropin" \
            && grep -q -- "--private-users=" "$dropin"; then
        ok "--pod + --userns: nsenter + userns in drop-in"
    else
        fail "--pod + --userns: expected nsenter and --private-users=pick in drop-in"
    fi
    cleanup_container val-u1
else
    fail "--pod + --userns should succeed"
fi

# 3c: --oci-pod without --private-network → should error (nspawn strips
# CAP_NET_ADMIN on host-network containers, breaking NetworkNamespacePath=)
$SDME pod new valpod 2>/dev/null || true
if err=$($SDME create --name val-err1 --oci-pod=valpod -r ubuntu 2>&1); then
    fail "--oci-pod without --private-network should error"
    cleanup_container val-err1
else
    if echo "$err" | grep -q "requires --private-network"; then
        ok "--oci-pod without --private-network rejected"
    else
        fail "--oci-pod without --private-network: unexpected error: $err"
    fi
fi

# 3d: --oci-pod without OCI app rootfs → should error (needs
# --private-network to pass that check first)
if err=$($SDME create --name val-err1b --oci-pod=valpod --private-network 2>&1); then
    fail "--oci-pod without OCI rootfs should error"
    cleanup_container val-err1b
else
    if echo "$err" | grep -q "requires an OCI app rootfs"; then
        ok "--oci-pod without OCI rootfs rejected"
    else
        fail "--oci-pod without OCI rootfs: unexpected error: $err"
    fi
fi

# 3e: --pod=nonexistent → should error
if $SDME create --name val-err2 --pod=nonexistent 2>/dev/null; then
    fail "--pod=nonexistent should error"
    cleanup_container val-err2
else
    ok "--pod=nonexistent rejected"
fi

# 3f: --oci-pod with user namespace isolation → should error. The app
# service cannot enter a netns owned by the host's user namespace from inside
# the container's, and systemd would start it outside the pod without failing.
for flag in --userns --hardened --strict; do
    err_msg=$($SDME create --name val-err3 --oci-pod=valpod --private-network "$flag" 2>&1 || true)
    if echo "$err_msg" | grep -q "cannot be combined with user namespace isolation"; then
        ok "--oci-pod + $flag rejected"
    else
        fail "--oci-pod + $flag: unexpected result: $err_msg"
    fi
    cleanup_container val-err3
done

cleanup_pod valpod

# ---------------------------------------------------------------------------
# Test 4: Pod name prefixes
# ---------------------------------------------------------------------------
echo "=== Test 4: Pod name prefixes ==="

cleanup_container pod-pfx1
cleanup_pod pfxpod-alpha
cleanup_pod pfxpod-beta
$SDME pod new pfxpod-alpha $VFLAG >/dev/null
$SDME pod new pfxpod-beta $VFLAG >/dev/null

# --pod with a unique prefix joins the pod and records its full name.
if $SDME create --name pod-pfx1 -r ubuntu --pod pfxpod-a $VFLAG >/dev/null 2>&1 \
        && grep -qx "POD=pfxpod-alpha" "${DATADIR:-/var/lib/sdme}/state/pod-pfx1"; then
    ok "--pod prefix resolves and stores the full pod name"
else
    fail "--pod prefix did not resolve to pfxpod-alpha"
fi
cleanup_container pod-pfx1

# An ambiguous prefix is refused and removes nothing.
if err=$($SDME pod rm pfxpod 2>&1); then
    fail "pod rm with an ambiguous prefix succeeded"
elif echo "$err" | grep -q "ambiguous name 'pfxpod', could match: pfxpod-alpha, pfxpod-beta" \
        && $SDME pod ls 2>/dev/null | grep -q pfxpod-alpha \
        && $SDME pod ls 2>/dev/null | grep -q pfxpod-beta; then
    ok "pod rm with an ambiguous prefix refused"
else
    fail "pod rm with an ambiguous prefix: unexpected result: $err"
fi

# pod rm with a unique prefix removes that pod only.
if $SDME pod rm pfxpod-b >/dev/null 2>&1 \
        && ! $SDME pod ls 2>/dev/null | grep -q pfxpod-beta \
        && $SDME pod ls 2>/dev/null | grep -q pfxpod-alpha; then
    ok "pod rm with a unique prefix removes that pod"
else
    fail "pod rm pfxpod-b did not remove pfxpod-beta alone"
fi

if err=$($SDME pod rm pfxpod-zzz 2>&1); then
    fail "pod rm of an unknown prefix succeeded"
elif echo "$err" | grep -q "no pod found matching 'pfxpod-zzz'"; then
    ok "pod rm of an unknown prefix refused"
else
    fail "pod rm of an unknown prefix: unexpected error: $err"
fi
cleanup_pod pfxpod-alpha

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print_summary
