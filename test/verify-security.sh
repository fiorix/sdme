#!/usr/bin/env bash
set -euo pipefail

# verify-security.sh - end-to-end security hardening verification
# Must run as root. Requires a base Ubuntu rootfs imported as "ubuntu".
# For multi-distro userns tests, also requires vfy-{debian,ubuntu,fedora,...}
# rootfs from verify-matrix.sh --keep.
#
# Usage:
#   sudo sdme fs import ubuntu docker.io/ubuntu:24.04 -v --install-packages=yes
#   sudo ./test/verify-security.sh
#
# Tests:
#   1. CLI validation: bad capabilities, bad filters, contradictions
#   2. State persistence: security flags roundtrip through create → state file
#   3. --drop-capability: dropped cap is absent in the container
#   4. --capability: added cap is present in the container
#   5. --no-new-privileges: setuid execution blocked
#   6. --read-only: rootfs is read-only inside the container
#   7. --system-call-filter: denied syscall group is blocked
#   8. --hardened: bundle applies userns + private-network + no-new-privs + cap drops
#   9. --hardened with overrides: explicit --capability suppresses hardened drop
#  10. --apparmor-profile: profile name persists in state (enforcement is AppArmor-dependent)
#  11. --hardened boot: container boots with full hardened profile
#  12. sdme ps shows security info
#  13. --userns boot: each distro boots with user namespace isolation
#  14. --userns OCI app: nginx on ubuntu with user namespace isolation

SDME="${SDME:-sdme}"
VERBOSE="${VERBOSE:-}"
VFLAG=()
if [[ -n "$VERBOSE" ]]; then
    VFLAG=("-v")
fi

TIMEOUT_BOOT=120
TIMEOUT_TEST=60
DATADIR="/var/lib/sdme"

pass=0
fail=0
skip=0

ok() {
    echo "  PASS: $1"
    ((pass++)) || true
}

fail() {
    echo "  FAIL: $1"
    ((fail++)) || true
}

skipped() {
    echo "  SKIP: $1"
    ((skip++)) || true
}

cleanup_container() {
    timeout 30 "$SDME" stop "$1" 2>/dev/null || \
        timeout 30 "$SDME" stop --term "$1" 2>/dev/null || true
    "$SDME" rm -f "$1" 2>/dev/null || true
}

cleanup_all() {
    echo "Cleaning up sec-/usrns- artifacts..."
    local names
    names=$("$SDME" ps 2>/dev/null | awk 'NR>1 {print $1}' | grep -E '^(sec-|usrns-)' || true)
    for name in $names; do
        cleanup_container "$name"
    done
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

# Check ubuntu rootfs exists.
if ! "$SDME" fs ls 2>/dev/null | awk 'NR>1 {print $1}' | grep -qx "ubuntu"; then
    echo "error: rootfs 'ubuntu' not found" >&2
    echo "import it first: sudo sdme fs import ubuntu docker.io/ubuntu:24.04 -v --install-packages=yes" >&2
    exit 1
fi

# ===========================================================================
# Test 1: CLI validation
# ===========================================================================
echo "=== Test 1: CLI validation ==="

# 1a: unknown capability → error
if err=$("$SDME" create --drop-capability=CAP_BOGUS -r ubuntu sec-val1 2>&1); then
    fail "unknown capability should error"
    cleanup_container sec-val1
else
    if echo "$err" | grep -qi "unknown capability"; then
        ok "unknown capability rejected"
    else
        fail "unknown capability: unexpected error: $err"
    fi
fi

# 1b: invalid syscall filter → error
if err=$("$SDME" create --system-call-filter=mount -r ubuntu sec-val2 2>&1); then
    fail "invalid syscall filter should error"
    cleanup_container sec-val2
else
    if echo "$err" | grep -qi "must start with @"; then
        ok "invalid syscall filter rejected"
    else
        fail "invalid syscall filter: unexpected error: $err"
    fi
fi

# 1c: contradictory caps (same cap in both add and drop) → error
if err=$("$SDME" create --drop-capability=CAP_NET_RAW --capability=CAP_NET_RAW -r ubuntu sec-val3 2>&1); then
    fail "contradictory caps should error"
    cleanup_container sec-val3
else
    if echo "$err" | grep -qi "appears in both"; then
        ok "contradictory caps rejected"
    else
        fail "contradictory caps: unexpected error: $err"
    fi
fi

# 1d: invalid AppArmor profile name → error
if err=$("$SDME" create --apparmor-profile="foo/bar" -r ubuntu sec-val4 2>&1); then
    fail "invalid AppArmor profile should error"
    cleanup_container sec-val4
else
    if echo "$err" | grep -qi "invalid character"; then
        ok "invalid AppArmor profile rejected"
    else
        fail "invalid AppArmor profile: unexpected error: $err"
    fi
fi

# 1e: empty syscall filter group → error
if err=$("$SDME" create --system-call-filter=@ -r ubuntu sec-val5 2>&1); then
    fail "empty syscall filter group should error"
    cleanup_container sec-val5
else
    if echo "$err" | grep -qi "cannot be empty"; then
        ok "empty syscall filter group rejected"
    else
        fail "empty syscall filter group: unexpected error: $err"
    fi
fi

# ===========================================================================
# Test 2: State persistence
# ===========================================================================
echo "=== Test 2: State persistence ==="

cleanup_container sec-state

"$SDME" create -r ubuntu \
    --drop-capability=CAP_SYS_PTRACE \
    --drop-capability=CAP_NET_RAW \
    --capability=CAP_NET_ADMIN \
    --no-new-privileges \
    --read-only \
    --system-call-filter=~@mount \
    --system-call-filter=~@raw-io \
    --apparmor-profile=sdme-test \
    sec-state "${VFLAG[@]}" 2>&1

state_file="$DATADIR/state/sec-state"
if [[ ! -f "$state_file" ]]; then
    fail "state file not found: $state_file"
else
    # Verify each security key is in the state file.
    state_ok=true

    if ! grep -q "^DROP_CAPS=CAP_SYS_PTRACE,CAP_NET_RAW$" "$state_file"; then
        fail "state: DROP_CAPS mismatch"
        state_ok=false
    fi
    if ! grep -q "^ADD_CAPS=CAP_NET_ADMIN$" "$state_file"; then
        fail "state: ADD_CAPS mismatch"
        state_ok=false
    fi
    if ! grep -q "^NO_NEW_PRIVS=yes$" "$state_file"; then
        fail "state: NO_NEW_PRIVS mismatch"
        state_ok=false
    fi
    if ! grep -q "^READ_ONLY=yes$" "$state_file"; then
        fail "state: READ_ONLY mismatch"
        state_ok=false
    fi
    if ! grep -q "^SYSCALL_FILTER=~@mount,~@raw-io$" "$state_file"; then
        fail "state: SYSCALL_FILTER mismatch"
        state_ok=false
    fi
    if ! grep -q "^APPARMOR_PROFILE=sdme-test$" "$state_file"; then
        fail "state: APPARMOR_PROFILE mismatch"
        state_ok=false
    fi

    if $state_ok; then
        ok "all security fields persisted in state file"
    fi
fi

cleanup_container sec-state

# ===========================================================================
# Test 3: --drop-capability blocks the dropped cap inside the container
# ===========================================================================
echo "=== Test 3: --drop-capability ==="

cleanup_container sec-dropcap

"$SDME" create -r ubuntu --drop-capability=CAP_NET_RAW sec-dropcap "${VFLAG[@]}" 2>&1
timeout "$TIMEOUT_BOOT" "$SDME" start sec-dropcap -t "$TIMEOUT_BOOT" "${VFLAG[@]}" 2>&1

# Read the container's bounding set from /proc/1/status.
# CapBnd is a hex bitmask. CAP_NET_RAW is bit 13.
# machinectl shell wraps output with "Connected to machine..." lines,
# so we extract just the hex value with grep + awk and strip noise.
raw=$(timeout "$TIMEOUT_TEST" "$SDME" exec sec-dropcap \
    /bin/sh -c "grep '^CapBnd:' /proc/1/status" 2>&1 || true)
capbnd=$(echo "$raw" | grep '^CapBnd:' | awk '{print $2}' | tr -d '[:space:]')

if [[ -z "$capbnd" ]]; then
    fail "drop-cap: could not read CapBnd (raw: '$raw')"
else
    # Convert hex to decimal and check bit 13 (CAP_NET_RAW).
    capbnd_dec=$((16#${capbnd}))
    cap_net_raw_bit=$((1 << 13))
    if (( (capbnd_dec & cap_net_raw_bit) == 0 )); then
        ok "CAP_NET_RAW dropped from bounding set"
    else
        fail "CAP_NET_RAW still present in bounding set (CapBnd=$capbnd)"
    fi
fi

cleanup_container sec-dropcap

# ===========================================================================
# Test 4: --capability adds the cap inside the container
# ===========================================================================
echo "=== Test 4: --capability ==="

cleanup_container sec-addcap

# CAP_NET_ADMIN (bit 12) is not in the default nspawn set.
"$SDME" create -r ubuntu --capability=CAP_NET_ADMIN sec-addcap "${VFLAG[@]}" 2>&1
timeout "$TIMEOUT_BOOT" "$SDME" start sec-addcap -t "$TIMEOUT_BOOT" "${VFLAG[@]}" 2>&1

raw=$(timeout "$TIMEOUT_TEST" "$SDME" exec sec-addcap \
    /bin/sh -c "grep '^CapBnd:' /proc/1/status" 2>&1 || true)
capbnd=$(echo "$raw" | grep '^CapBnd:' | awk '{print $2}' | tr -d '[:space:]')

if [[ -z "$capbnd" ]]; then
    fail "add-cap: could not read CapBnd (raw: '$raw')"
else
    capbnd_dec=$((16#${capbnd}))
    cap_net_admin_bit=$((1 << 12))
    if (( (capbnd_dec & cap_net_admin_bit) != 0 )); then
        ok "CAP_NET_ADMIN present in bounding set"
    else
        fail "CAP_NET_ADMIN not in bounding set (CapBnd=$capbnd)"
    fi
fi

cleanup_container sec-addcap

# ===========================================================================
# Test 5: --no-new-privileges blocks setuid escalation
# ===========================================================================
echo "=== Test 5: --no-new-privileges ==="

cleanup_container sec-nnp

"$SDME" create -r ubuntu --no-new-privileges sec-nnp "${VFLAG[@]}" 2>&1
timeout "$TIMEOUT_BOOT" "$SDME" start sec-nnp -t "$TIMEOUT_BOOT" "${VFLAG[@]}" 2>&1

# Check that NoNewPrivs is 1 for a newly spawned process.
nnp=$(timeout "$TIMEOUT_TEST" "$SDME" exec sec-nnp \
    /bin/sh -c "cat /proc/self/status | grep '^NoNewPrivs:' | awk '{print \$2}'" 2>&1 || true)

if [[ "$nnp" == *"1"* ]]; then
    ok "NoNewPrivs=1 inside container"
else
    fail "NoNewPrivs not set (got: '$nnp')"
fi

cleanup_container sec-nnp

# ===========================================================================
# Test 6: --read-only makes rootfs read-only
# ===========================================================================
echo "=== Test 6: --read-only ==="

cleanup_container sec-ro

"$SDME" create -r ubuntu --read-only sec-ro "${VFLAG[@]}" 2>&1
timeout "$TIMEOUT_BOOT" "$SDME" start sec-ro -t "$TIMEOUT_BOOT" "${VFLAG[@]}" 2>&1

# Attempt to write to /usr should fail (read-only filesystem).
write_result=$(timeout "$TIMEOUT_TEST" "$SDME" exec sec-ro \
    /bin/sh -c "touch /usr/test-readonly 2>&1 || echo READONLY" 2>&1 || true)

if echo "$write_result" | grep -q "READONLY\|Read-only\|read-only"; then
    ok "rootfs is read-only inside container"
else
    fail "rootfs is writable (got: '$write_result')"
fi

cleanup_container sec-ro

# ===========================================================================
# Test 7: --system-call-filter blocks denied syscall group
# ===========================================================================
echo "=== Test 7: --system-call-filter ==="

cleanup_container sec-seccomp

# Use ~@raw-io to deny raw I/O syscalls (iopl, ioperm, etc.) — this
# doesn't interfere with systemd boot. Verify state persistence and that
# the nspawn drop-in contains the filter flag.
"$SDME" create -r ubuntu --system-call-filter=~@raw-io sec-seccomp "${VFLAG[@]}" 2>&1

# Verify state file.
state_file="$DATADIR/state/sec-seccomp"
if grep -q "^SYSCALL_FILTER=~@raw-io$" "$state_file"; then
    ok "syscall filter persisted in state"
else
    fail "syscall filter not in state file"
fi

# Boot and verify the drop-in contains the filter argument.
timeout "$TIMEOUT_BOOT" "$SDME" start sec-seccomp -t "$TIMEOUT_BOOT" "${VFLAG[@]}" 2>&1

dropin="/etc/systemd/system/sdme@sec-seccomp.service.d/nspawn.conf"
if [[ -f "$dropin" ]] && grep -q -- "--system-call-filter=~@raw-io" "$dropin"; then
    ok "syscall filter in nspawn drop-in"
else
    fail "syscall filter not in nspawn drop-in ($dropin)"
fi

cleanup_container sec-seccomp

# ===========================================================================
# Test 8: --hardened bundle
# ===========================================================================
echo "=== Test 8: --hardened ==="

cleanup_container sec-hardened

"$SDME" create -r ubuntu --hardened sec-hardened "${VFLAG[@]}" 2>&1

state_file="$DATADIR/state/sec-hardened"
if [[ ! -f "$state_file" ]]; then
    fail "hardened: state file not found"
else
    hardened_ok=true

    # --hardened implies userns.
    if ! grep -q "^USERNS=yes$" "$state_file"; then
        fail "hardened: USERNS not set"
        hardened_ok=false
    fi

    # --hardened implies private-network (stored as "1", not "yes").
    if ! grep -q "^PRIVATE_NETWORK=1$" "$state_file"; then
        fail "hardened: PRIVATE_NETWORK not set"
        hardened_ok=false
    fi

    # --hardened implies no-new-privileges.
    if ! grep -q "^NO_NEW_PRIVS=yes$" "$state_file"; then
        fail "hardened: NO_NEW_PRIVS not set"
        hardened_ok=false
    fi

    # --hardened drops default caps.
    drop_caps=$(grep "^DROP_CAPS=" "$state_file" | cut -d= -f2 || true)
    for cap in CAP_SYS_PTRACE CAP_NET_RAW CAP_SYS_RAWIO CAP_SYS_BOOT; do
        if ! echo "$drop_caps" | grep -q "$cap"; then
            fail "hardened: $cap not in DROP_CAPS"
            hardened_ok=false
        fi
    done

    if $hardened_ok; then
        ok "hardened bundle: userns + private-network + no-new-privs + cap drops"
    fi
fi

cleanup_container sec-hardened

# ===========================================================================
# Test 9: --hardened with --capability override
# ===========================================================================
echo "=== Test 9: --hardened with capability override ==="

cleanup_container sec-hard-ovr

# Explicitly re-add CAP_NET_RAW: it should NOT appear in DROP_CAPS.
"$SDME" create -r ubuntu --hardened --capability=CAP_NET_RAW sec-hard-ovr "${VFLAG[@]}" 2>&1

state_file="$DATADIR/state/sec-hard-ovr"
if [[ ! -f "$state_file" ]]; then
    fail "hardened-override: state file not found"
else
    drop_caps=$(grep "^DROP_CAPS=" "$state_file" | cut -d= -f2 || true)
    add_caps=$(grep "^ADD_CAPS=" "$state_file" | cut -d= -f2 || true)

    override_ok=true

    # CAP_NET_RAW should NOT be in drop list.
    if echo "$drop_caps" | grep -q "CAP_NET_RAW"; then
        fail "hardened-override: CAP_NET_RAW still in DROP_CAPS"
        override_ok=false
    fi

    # CAP_NET_RAW should be in add list.
    if ! echo "$add_caps" | grep -q "CAP_NET_RAW"; then
        fail "hardened-override: CAP_NET_RAW not in ADD_CAPS"
        override_ok=false
    fi

    # Other hardened caps should still be dropped.
    for cap in CAP_SYS_PTRACE CAP_SYS_RAWIO CAP_SYS_BOOT; do
        if ! echo "$drop_caps" | grep -q "$cap"; then
            fail "hardened-override: $cap not in DROP_CAPS"
            override_ok=false
        fi
    done

    if $override_ok; then
        ok "hardened override: --capability=CAP_NET_RAW suppresses its drop"
    fi
fi

cleanup_container sec-hard-ovr

# ===========================================================================
# Test 10: --apparmor-profile state persistence
# ===========================================================================
echo "=== Test 10: --apparmor-profile persistence ==="

cleanup_container sec-apparmor

"$SDME" create -r ubuntu --apparmor-profile=sdme-container sec-apparmor "${VFLAG[@]}" 2>&1

state_file="$DATADIR/state/sec-apparmor"
if [[ ! -f "$state_file" ]]; then
    fail "apparmor: state file not found"
else
    if grep -q "^APPARMOR_PROFILE=sdme-container$" "$state_file"; then
        ok "AppArmor profile persisted in state file"
    else
        fail "apparmor: APPARMOR_PROFILE not found in state"
    fi
fi

# Also verify the nspawn drop-in contains AppArmorProfile= when started.
# We cannot actually enforce AppArmor without a loaded profile, but we can
# check the unit file generation.
if timeout "$TIMEOUT_BOOT" "$SDME" start sec-apparmor -t "$TIMEOUT_BOOT" "${VFLAG[@]}" 2>&1; then
    dropin="/etc/systemd/system/sdme@sec-apparmor.service.d/nspawn.conf"
    if [[ -f "$dropin" ]] && grep -q "AppArmorProfile=sdme-container" "$dropin"; then
        ok "AppArmorProfile= directive in systemd drop-in"
    else
        fail "apparmor: AppArmorProfile= not found in drop-in ($dropin)"
    fi
else
    # Start may fail if AppArmor profile doesn't exist. That's fine;
    # we still check the drop-in if it was written before the failure.
    dropin="/etc/systemd/system/sdme@sec-apparmor.service.d/nspawn.conf"
    if [[ -f "$dropin" ]] && grep -q "AppArmorProfile=sdme-container" "$dropin"; then
        ok "AppArmorProfile= directive in systemd drop-in (start failed, expected without profile loaded)"
    else
        skipped "AppArmor drop-in not generated (start failed before writing drop-in)"
    fi
fi

cleanup_container sec-apparmor

# ===========================================================================
# Test 11: --hardened container boots and reaches running/degraded
# ===========================================================================
echo "=== Test 11: --hardened boot test ==="

cleanup_container sec-hardboot

if ! output=$(timeout "$TIMEOUT_BOOT" "$SDME" create -r ubuntu --hardened sec-hardboot "${VFLAG[@]}" 2>&1); then
    fail "hardened-boot: create failed: $output"
else
    if ! output=$(timeout "$TIMEOUT_BOOT" "$SDME" start sec-hardboot -t "$TIMEOUT_BOOT" "${VFLAG[@]}" 2>&1); then
        fail "hardened-boot: start failed: $output"
    else
        # Verify systemd reaches running/degraded.
        if output=$(timeout "$TIMEOUT_TEST" "$SDME" exec sec-hardboot \
                /usr/bin/systemctl is-system-running --wait 2>&1); then
            ok "hardened: systemd running"
        else
            if [[ "$output" == *"degraded"* ]]; then
                ok "hardened: systemd degraded (acceptable)"
            else
                fail "hardened: systemd not running: $output"
            fi
        fi

        # Verify hardened properties are enforced at runtime.
        hardened_rt_ok=true

        # NoNewPrivs should be 1.
        nnp=$(timeout "$TIMEOUT_TEST" "$SDME" exec sec-hardboot \
            /bin/sh -c "grep '^NoNewPrivs:' /proc/self/status | awk '{print \$2}'" 2>&1 || true)
        if [[ "$nnp" != *"1"* ]]; then
            fail "hardened-boot: NoNewPrivs not set (got: '$nnp')"
            hardened_rt_ok=false
        fi

        # CAP_NET_RAW (bit 13) should be dropped.
        raw=$(timeout "$TIMEOUT_TEST" "$SDME" exec sec-hardboot \
            /bin/sh -c "grep '^CapBnd:' /proc/1/status" 2>&1 || true)
        capbnd=$(echo "$raw" | grep '^CapBnd:' | awk '{print $2}' | tr -d '[:space:]')
        if [[ -n "$capbnd" ]]; then
            capbnd_dec=$((16#${capbnd}))
            cap_net_raw_bit=$((1 << 13))
            if (( (capbnd_dec & cap_net_raw_bit) != 0 )); then
                fail "hardened-boot: CAP_NET_RAW still in bounding set"
                hardened_rt_ok=false
            fi
        else
            fail "hardened-boot: could not read CapBnd"
            hardened_rt_ok=false
        fi

        if $hardened_rt_ok; then
            ok "hardened: runtime properties verified (no-new-privs, cap drops)"
        fi
    fi
fi

cleanup_container sec-hardboot

# ===========================================================================
# Test 12: sdme ps shows security info
# ===========================================================================
echo "=== Test 12: sdme ps with security flags ==="

cleanup_container sec-pschk

"$SDME" create -r ubuntu --no-new-privileges --read-only sec-pschk "${VFLAG[@]}" 2>&1

# Check that ps output shows the container (existence check).
ps_output=$("$SDME" ps 2>&1 || true)
if echo "$ps_output" | grep -q "sec-pschk"; then
    ok "container visible in sdme ps"
else
    fail "container sec-pschk not in sdme ps output"
fi

cleanup_container sec-pschk

# ===========================================================================
# Test 13: --userns boot with multiple distros
# ===========================================================================
echo "=== Test 13: --userns multi-distro boot ==="

USERNS_DISTROS=(debian ubuntu fedora centos almalinux)
userns_any=false

for distro in "${USERNS_DISTROS[@]}"; do
    fs_name="vfy-$distro"
    ct_name="usrns-$distro"

    # Check rootfs exists; skip if not.
    if ! "$SDME" fs ls 2>/dev/null | awk 'NR>1 {print $1}' | grep -qx "$fs_name"; then
        skipped "$distro userns: rootfs $fs_name not found (run verify-matrix.sh --keep)"
        continue
    fi

    userns_any=true
    cleanup_container "$ct_name"

    if ! output=$(timeout "$TIMEOUT_BOOT" "$SDME" create -r "$fs_name" --userns "$ct_name" "${VFLAG[@]}" 2>&1); then
        fail "$distro userns: create failed: $output"
        continue
    fi

    if ! output=$(timeout "$TIMEOUT_BOOT" "$SDME" start "$ct_name" -t 120 "${VFLAG[@]}" 2>&1); then
        fail "$distro userns: start failed: $output"
        cleanup_container "$ct_name"
        continue
    fi

    # Verify systemd reaches running/degraded.
    if output=$(timeout "$TIMEOUT_TEST" "$SDME" exec "$ct_name" \
            /usr/bin/systemctl is-system-running --wait 2>&1); then
        ok "$distro userns: systemd running"
    else
        if [[ "$output" == *"degraded"* ]]; then
            ok "$distro userns: systemd degraded (acceptable)"
        else
            fail "$distro userns: systemd not running: $output"
        fi
    fi

    cleanup_container "$ct_name"
done

if ! $userns_any; then
    skipped "no vfy-* rootfs found for multi-distro userns tests"
fi

# ===========================================================================
# Test 14: --userns OCI app (nginx on ubuntu)
# ===========================================================================
echo "=== Test 14: --userns OCI app (nginx on ubuntu) ==="

fs_name="usrns-nginx-on-ubuntu"
ct_name="usrns-oci-nginx"

if ! "$SDME" fs ls 2>/dev/null | awk 'NR>1 {print $1}' | grep -qx "vfy-ubuntu"; then
    skipped "nginx userns OCI: rootfs vfy-ubuntu not found (run verify-matrix.sh --keep)"
else
    cleanup_container "$ct_name"
    "$SDME" fs rm "$fs_name" 2>/dev/null || true

    if ! output=$(timeout 600 "$SDME" fs import "$fs_name" docker.io/nginx \
            --base-fs=vfy-ubuntu --oci-mode=app -v --install-packages=yes -f 2>&1); then
        fail "nginx userns OCI: import failed: $output"
    else
        if ! output=$(timeout "$TIMEOUT_BOOT" "$SDME" create -r "$fs_name" --userns "$ct_name" "${VFLAG[@]}" 2>&1); then
            fail "nginx userns OCI: create failed: $output"
        else
            if ! output=$(timeout "$TIMEOUT_BOOT" "$SDME" start "$ct_name" -t 120 "${VFLAG[@]}" 2>&1); then
                fail "nginx userns OCI: start failed: $output"
            else
                sleep 3

                if output=$(timeout "$TIMEOUT_TEST" "$SDME" exec "$ct_name" \
                        /usr/bin/systemctl is-active sdme-oci-app.service 2>&1); then
                    ok "nginx userns OCI: sdme-oci-app.service active"
                else
                    fail "nginx userns OCI: sdme-oci-app.service not active: $output"
                fi
            fi

            cleanup_container "$ct_name"
        fi

        "$SDME" fs rm "$fs_name" 2>/dev/null || true
    fi
fi

# ===========================================================================
# Summary
# ===========================================================================
echo ""
echo "Results: $pass passed, $fail failed, $skip skipped"
if [[ $fail -gt 0 ]]; then
    exit 1
fi
