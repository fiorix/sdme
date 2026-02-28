#!/usr/bin/env bash
set -euo pipefail

# verify-userns.sh - end-to-end user namespace isolation verification
# Must run as root. Requires base distro rootfs already imported as
# vfy-debian, vfy-ubuntu, etc. (from verify-matrix.sh --keep).
#
# Usage:
#   sudo ./test/verify-matrix.sh --keep  # import base rootfs first
#   sudo ./test/verify-userns.sh
#
# Tests:
#   1. Boot each distro with --userns and verify systemd reaches running/degraded
#   2. OCI app (nginx on ubuntu) with --userns

SDME="${SDME:-sdme}"
VERBOSE="${VERBOSE:-}"
VFLAG=()
if [[ -n "$VERBOSE" ]]; then
    VFLAG=("-v")
fi

DISTROS=(debian ubuntu fedora centos almalinux)
TIMEOUT_BOOT=120
TIMEOUT_TEST=300

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
    "$SDME" rm -f "$1" 2>/dev/null || true
}

cleanup_all() {
    echo "Cleaning up usrns- artifacts..."
    local names
    names=$("$SDME" ps 2>/dev/null | awk 'NR>1 {print $1}' | grep '^usrns-' || true)
    for name in $names; do
        "$SDME" stop "$name" 2>/dev/null || "$SDME" stop --term "$name" 2>/dev/null || true
        "$SDME" rm -f "$name" 2>/dev/null || true
    done
    # Remove OCI app rootfs imported by this script
    "$SDME" fs rm usrns-nginx-on-ubuntu 2>/dev/null || true
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

# ---------------------------------------------------------------------------
# Test 1: Boot each distro with --userns
# ---------------------------------------------------------------------------

for distro in "${DISTROS[@]}"; do
    echo "=== Test: boot $distro with --userns ==="
    fs_name="vfy-$distro"
    ct_name="usrns-$distro"

    # Check rootfs exists
    if ! "$SDME" fs ls 2>/dev/null | awk 'NR>1 {print $1}' | grep -qx "$fs_name"; then
        fail "$distro: rootfs $fs_name not found (run verify-matrix.sh --keep first)"
        continue
    fi

    cleanup_container "$ct_name"

    # Create with --userns
    if ! output=$(timeout "$TIMEOUT_BOOT" "$SDME" create -r "$fs_name" --userns "$ct_name" "${VFLAG[@]}" 2>&1); then
        fail "$distro: create failed: $output"
        continue
    fi

    # Start
    if ! output=$(timeout "$TIMEOUT_BOOT" "$SDME" start "$ct_name" -t 120 "${VFLAG[@]}" 2>&1); then
        fail "$distro: start failed: $output"
        cleanup_container "$ct_name"
        continue
    fi

    # Verify systemd reaches running/degraded
    if output=$(timeout "$TIMEOUT_TEST" "$SDME" exec "$ct_name" /usr/bin/systemctl is-system-running --wait 2>&1); then
        ok "$distro: systemd running with userns"
    else
        # degraded is acceptable (some units may fail in userns)
        if [[ "$output" == *"degraded"* ]]; then
            ok "$distro: systemd degraded with userns (acceptable)"
        else
            fail "$distro: systemd not running: $output"
        fi
    fi

    # Cleanup
    timeout 30 "$SDME" stop "$ct_name" 2>/dev/null || \
        timeout 30 "$SDME" stop --term "$ct_name" 2>/dev/null || true
    cleanup_container "$ct_name"
done

# ---------------------------------------------------------------------------
# Test 2: OCI app (nginx on ubuntu) with --userns
# ---------------------------------------------------------------------------

echo "=== Test: nginx OCI app on ubuntu with --userns ==="

fs_name="usrns-nginx-on-ubuntu"
ct_name="usrns-oci-nginx"

# Check ubuntu base rootfs exists
if ! "$SDME" fs ls 2>/dev/null | awk 'NR>1 {print $1}' | grep -qx "vfy-ubuntu"; then
    fail "nginx-oci: rootfs vfy-ubuntu not found (run verify-matrix.sh --keep first)"
else
    cleanup_container "$ct_name"
    "$SDME" fs rm "$fs_name" 2>/dev/null || true

    # Import nginx as OCI app on ubuntu base
    if ! output=$(timeout 600 "$SDME" fs import "$fs_name" docker.io/nginx \
            --base-fs=vfy-ubuntu --oci-mode=app -v --install-packages=yes -f 2>&1); then
        fail "nginx-oci: import failed: $output"
    else
        # Create with --userns
        if ! output=$(timeout "$TIMEOUT_BOOT" "$SDME" create -r "$fs_name" --userns "$ct_name" "${VFLAG[@]}" 2>&1); then
            fail "nginx-oci: create failed: $output"
        else
            # Start
            if ! output=$(timeout "$TIMEOUT_BOOT" "$SDME" start "$ct_name" -t 120 "${VFLAG[@]}" 2>&1); then
                fail "nginx-oci: start failed: $output"
            else
                # Wait for app readiness
                sleep 3

                # Verify sdme-oci-app.service is active
                if output=$(timeout "$TIMEOUT_TEST" "$SDME" exec "$ct_name" \
                        /usr/bin/systemctl is-active sdme-oci-app.service 2>&1); then
                    ok "nginx-oci: sdme-oci-app.service active with userns"
                else
                    fail "nginx-oci: sdme-oci-app.service not active: $output"
                fi
            fi

            # Cleanup container
            timeout 30 "$SDME" stop "$ct_name" 2>/dev/null || \
                timeout 30 "$SDME" stop --term "$ct_name" 2>/dev/null || true
            cleanup_container "$ct_name"
        fi

        # Cleanup rootfs
        "$SDME" fs rm "$fs_name" 2>/dev/null || true
    fi
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: $pass passed, $fail failed"
if [[ $fail -gt 0 ]]; then
    exit 1
fi
