#!/usr/bin/env bash
set -uo pipefail

# verify-kube-L2-security.sh - e2e verification of kube container securityContext
# Run as root. Requires a base-fs imported (e.g. ubuntu).
#
# Deploys a single pod with two containers to exercise all container-level
# securityContext fields in one image pull:
#   - capabilities.add / capabilities.drop (including "ALL")
#   - allowPrivilegeEscalation: false
#   - readOnlyRootFilesystem: true
#   - seccompProfile.type: RuntimeDefault
#   - appArmorProfile.type: RuntimeDefault
#   - per-container runAsUser/runAsGroup overriding pod-level
#   - pod-level seccompProfile / appArmorProfile defaults
#
# Verifies both generated unit files (static) and runtime behavior.

source "$(dirname "$0")/lib.sh"

BASE_FS="${BASE_FS:-ubuntu}"
DATADIR="/var/lib/sdme"
REPORT_DIR="."

POD_NAME="vfy-ks-sec"

# Timeouts (seconds)
TIMEOUT_CREATE=600
TIMEOUT_BOOT=120

# State flags
POD_CREATED=0
POD_RUNNING=0

# Read a unit file from the kube rootfs.
read_unit() {
    local app_name="$1"
    cat "$DATADIR/fs/kube-$POD_NAME/etc/systemd/system/sdme-oci-${app_name}.service" 2>/dev/null || echo ""
}

# --- Cleanup ------------------------------------------------------------------

cleanup() {
    echo "==> Cleaning up..."
    "$SDME" kube delete "$POD_NAME" --force 2>/dev/null || true
}

trap cleanup EXIT INT TERM

# --- Create the test pod ------------------------------------------------------
#
# Two containers:
#   - "hardened": drops ALL caps, adds back CHOWN + NET_BIND_SERVICE,
#     readOnlyRootFilesystem, seccomp RuntimeDefault, apparmor RuntimeDefault,
#     allowPrivilegeEscalation: false, runAsUser/runAsGroup override
#   - "relaxed": only drops NET_RAW, no seccomp/apparmor, allows privilege escalation
#
# Pod-level: seccomp RuntimeDefault, apparmor RuntimeDefault, runAsUser=65534

test_create_pod() {
    local test_name="create-pod"
    local yaml_file
    yaml_file=$(mktemp /tmp/kube-sec-XXXXXX.yaml)

    cat > "$yaml_file" <<'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: vfy-ks-sec
spec:
  securityContext:
    runAsUser: 65534
    runAsGroup: 65534
    seccompProfile:
      type: RuntimeDefault
    appArmorProfile:
      type: RuntimeDefault
  containers:
  - name: hardened
    image: docker.io/alpine:latest
    command: ["/bin/sh", "-c", "sleep infinity"]
    securityContext:
      runAsUser: 1000
      runAsGroup: 1000
      capabilities:
        drop: ["ALL"]
        add: ["CHOWN", "NET_BIND_SERVICE"]
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      seccompProfile:
        type: RuntimeDefault
      appArmorProfile:
        type: RuntimeDefault
  - name: relaxed
    image: docker.io/alpine:latest
    command: ["/bin/sh", "-c", "sleep infinity"]
    securityContext:
      capabilities:
        drop: ["NET_RAW"]
      allowPrivilegeEscalation: true
      seccompProfile:
        type: Unconfined
      appArmorProfile:
        type: Unconfined
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

# -- "hardened" container checks --

test_unit_hardened_caps_drop_all() {
    local test_name="unit-hardened-caps-drop-all"
    if [[ $POD_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "pod not created"
        return
    fi

    local unit
    unit=$(read_unit "hardened")

    # With drop ALL + add CHOWN,NET_BIND_SERVICE: SYS_ADMIN (always for isolate),
    # SETUID/SETGID/SETPCAP (always for privilege drop), CHOWN, NET_BIND_SERVICE.
    local fail=0
    for cap in CAP_SYS_ADMIN CAP_CHOWN CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID CAP_SETPCAP; do
        if ! echo "$unit" | grep -q "CapabilityBoundingSet=.*${cap}"; then
            echo "    missing expected cap: $cap"
            fail=1
        fi
    done

    # Default caps that should be absent after drop ALL.
    for cap in CAP_NET_RAW CAP_KILL CAP_FOWNER; do
        if echo "$unit" | grep "CapabilityBoundingSet=" | grep -q "${cap}"; then
            echo "    unexpected cap present: $cap"
            fail=1
        fi
    done

    if [[ $fail -eq 0 ]]; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "capability bounding set wrong"
        echo "    unit CapabilityBoundingSet line:"
        echo "$unit" | grep "CapabilityBoundingSet="
    fi
}

test_unit_hardened_no_new_privileges() {
    local test_name="unit-hardened-no-new-privileges"
    if [[ $POD_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "pod not created"
        return
    fi

    local unit
    unit=$(read_unit "hardened")
    if echo "$unit" | grep -q 'NoNewPrivileges=yes'; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "NoNewPrivileges=yes not found"
    fi
}

test_unit_hardened_read_only() {
    local test_name="unit-hardened-read-only"
    if [[ $POD_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "pod not created"
        return
    fi

    local unit
    unit=$(read_unit "hardened")
    if echo "$unit" | grep -q 'ReadOnlyPaths=/'; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "ReadOnlyPaths=/ not found"
    fi
}

test_unit_hardened_seccomp() {
    local test_name="unit-hardened-seccomp"
    if [[ $POD_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "pod not created"
        return
    fi

    local unit fail=0
    unit=$(read_unit "hardened")

    # RuntimeDefault maps to STRICT_SYSCALL_FILTERS.
    for filter in "~@cpu-emulation" "~@debug" "~@obsolete" "~@raw-io"; do
        if ! echo "$unit" | grep -q "SystemCallFilter=${filter}"; then
            echo "    missing: SystemCallFilter=${filter}"
            fail=1
        fi
    done

    if [[ $fail -eq 0 ]]; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "syscall filters missing"
    fi
}

test_unit_hardened_apparmor() {
    local test_name="unit-hardened-apparmor"
    if [[ $POD_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "pod not created"
        return
    fi

    local unit
    unit=$(read_unit "hardened")
    if echo "$unit" | grep -q 'AppArmorProfile=sdme-default'; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "AppArmorProfile=sdme-default not found"
    fi
}

test_unit_hardened_user_override() {
    local test_name="unit-hardened-user-override"
    if [[ $POD_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "pod not created"
        return
    fi

    local unit
    unit=$(read_unit "hardened")
    # Container-level runAsUser=1000:1000 should override pod-level 65534:65534.
    if echo "$unit" | grep -q '\.sdme-isolate 1000 1000'; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "isolate 1000 1000 not found (container user override)"
        echo "    ExecStart line:"
        echo "$unit" | grep "ExecStart="
    fi
}

# -- "relaxed" container checks --

test_unit_relaxed_caps_drop_single() {
    local test_name="unit-relaxed-caps-drop-single"
    if [[ $POD_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "pod not created"
        return
    fi

    local unit
    unit=$(read_unit "relaxed")

    # NET_RAW should be absent, but other defaults should remain.
    local fail=0
    if echo "$unit" | grep "CapabilityBoundingSet=" | grep -q "CAP_NET_RAW"; then
        echo "    CAP_NET_RAW should have been dropped"
        fail=1
    fi
    for cap in CAP_SYS_ADMIN CAP_CHOWN CAP_SETUID CAP_KILL; do
        if ! echo "$unit" | grep -q "CapabilityBoundingSet=.*${cap}"; then
            echo "    missing expected cap: $cap"
            fail=1
        fi
    done

    if [[ $fail -eq 0 ]]; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "capability bounding set wrong"
        echo "    unit CapabilityBoundingSet line:"
        echo "$unit" | grep "CapabilityBoundingSet="
    fi
}

test_unit_relaxed_allow_privilege_escalation() {
    local test_name="unit-relaxed-allow-priv-esc"
    if [[ $POD_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "pod not created"
        return
    fi

    local unit
    unit=$(read_unit "relaxed")
    if echo "$unit" | grep -q 'NoNewPrivileges=no'; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "NoNewPrivileges=no not found (allowPrivilegeEscalation: true)"
    fi
}

test_unit_relaxed_no_seccomp() {
    local test_name="unit-relaxed-no-seccomp"
    if [[ $POD_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "pod not created"
        return
    fi

    local unit
    unit=$(read_unit "relaxed")
    # Container seccomp Unconfined overrides pod-level RuntimeDefault: no filters.
    if echo "$unit" | grep -q 'SystemCallFilter='; then
        record "$test_name" FAIL "should not have SystemCallFilter (Unconfined overrides pod)"
    else
        record "$test_name" PASS
    fi
}

test_unit_relaxed_no_apparmor() {
    local test_name="unit-relaxed-no-apparmor"
    if [[ $POD_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "pod not created"
        return
    fi

    local unit
    unit=$(read_unit "relaxed")
    # Container apparmor Unconfined overrides pod-level RuntimeDefault: no profile.
    if echo "$unit" | grep -q 'AppArmorProfile='; then
        record "$test_name" FAIL "should not have AppArmorProfile (Unconfined overrides pod)"
    else
        record "$test_name" PASS
    fi
}

test_unit_relaxed_no_read_only() {
    local test_name="unit-relaxed-no-read-only"
    if [[ $POD_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "pod not created"
        return
    fi

    local unit
    unit=$(read_unit "relaxed")
    if echo "$unit" | grep -q 'ReadOnlyPaths='; then
        record "$test_name" FAIL "should not have ReadOnlyPaths"
    else
        record "$test_name" PASS
    fi
}

test_unit_relaxed_user_inherits_pod() {
    local test_name="unit-relaxed-user-inherits-pod"
    if [[ $POD_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "pod not created"
        return
    fi

    local unit
    unit=$(read_unit "relaxed")
    # No container-level user override, so should inherit pod-level 65534:65534.
    if echo "$unit" | grep -q '\.sdme-isolate 65534 65534'; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "isolate 65534 65534 not found (should inherit pod user)"
        echo "    ExecStart line:"
        echo "$unit" | grep "ExecStart="
    fi
}

# -- Shared hardening directives (both containers should have these) --

test_unit_fixed_directives() {
    local test_name="unit-fixed-directives"
    if [[ $POD_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "pod not created"
        return
    fi

    local fail=0
    for app in hardened relaxed; do
        local unit
        unit=$(read_unit "$app")
        for directive in "ProtectKernelModules=yes" "ProtectKernelLogs=yes" \
                         "ProtectControlGroups=yes" "ProtectClock=yes" \
                         "RestrictSUIDSGID=yes" "LockPersonality=yes" \
                         "ProtectProc=invisible" "ProcSubset=pid"; do
            if ! echo "$unit" | grep -q "$directive"; then
                echo "    $app: missing $directive"
                fail=1
            fi
        done
    done

    if [[ $fail -eq 0 ]]; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "fixed hardening directives missing"
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

test_runtime_hardened_service_active() {
    local test_name="runtime-hardened-active"
    if [[ $POD_RUNNING -eq 0 ]]; then
        record "$test_name" SKIP "pod not running"
        return
    fi

    local output
    output=$("$SDME" exec "$POD_NAME" -- \
        /usr/bin/systemctl is-active sdme-oci-hardened.service 2>/dev/null || echo "")
    if echo "$output" | grep -qw 'active'; then
        record "$test_name" PASS
    else
        local status
        status=$(echo "$output" | grep -v 'Connected to\|Press \^]\|Connection to\|^$' | tail -1)
        record "$test_name" FAIL "service: $status"
        "$SDME" exec "$POD_NAME" -- /usr/bin/systemctl status sdme-oci-hardened.service 2>&1 || true
    fi
}

test_runtime_relaxed_service_active() {
    local test_name="runtime-relaxed-active"
    if [[ $POD_RUNNING -eq 0 ]]; then
        record "$test_name" SKIP "pod not running"
        return
    fi

    local output
    output=$("$SDME" exec "$POD_NAME" -- \
        /usr/bin/systemctl is-active sdme-oci-relaxed.service 2>/dev/null || echo "")
    if echo "$output" | grep -qw 'active'; then
        record "$test_name" PASS
    else
        local status
        status=$(echo "$output" | grep -v 'Connected to\|Press \^]\|Connection to\|^$' | tail -1)
        record "$test_name" FAIL "service: $status"
        "$SDME" exec "$POD_NAME" -- /usr/bin/systemctl status sdme-oci-relaxed.service 2>&1 || true
    fi
}

# --- Main ---------------------------------------------------------------------

main() {
    parse_standard_args "End-to-end verification of sdme Kubernetes security context support." "$@"

    ensure_root
    ensure_sdme

    ensure_default_base_fs

    echo "=== sdme kube security context verification ==="
    echo "base-fs: $BASE_FS"
    echo "pod:     $POD_NAME"
    echo ""

    # Phase 1: Create the pod (single pull).
    test_create_pod

    # Phase 2: Verify unit file contents (static checks).
    echo ""
    echo "--- unit file checks: hardened container ---"
    test_unit_hardened_caps_drop_all
    test_unit_hardened_no_new_privileges
    test_unit_hardened_read_only
    test_unit_hardened_seccomp
    test_unit_hardened_apparmor
    test_unit_hardened_user_override

    echo ""
    echo "--- unit file checks: relaxed container ---"
    test_unit_relaxed_caps_drop_single
    test_unit_relaxed_allow_privilege_escalation
    test_unit_relaxed_no_seccomp
    test_unit_relaxed_no_apparmor
    test_unit_relaxed_no_read_only
    test_unit_relaxed_user_inherits_pod

    echo ""
    echo "--- unit file checks: shared ---"
    test_unit_fixed_directives

    # Phase 3: Boot and verify runtime behavior.
    echo ""
    echo "--- runtime checks ---"
    test_start_pod
    test_runtime_hardened_service_active
    test_runtime_relaxed_service_active

    generate_standard_report "verify-kube-L2-security" "sdme Kube Security Verification Report"

    print_summary
}

main "$@"
