#!/usr/bin/env bash
set -uo pipefail

# verify-nixos.sh - end-to-end verification of NixOS rootfs import, container boot,
# and OCI nginx-unprivileged on a NixOS base.
#
# Run as root. Requires nix (with daemon running) to build the rootfs.
# Uses vfy-nix- prefix for all artifacts.
#
# Phases:
#   1. Build NixOS rootfs via nix-build
#   2. Import rootfs into sdme (verifies systemd+dbus detection)
#   3. Boot a plain NixOS container and verify it's running
#   4. Import nginx-unprivileged OCI app on the NixOS base
#   5. Create, boot, and test the OCI app container
#   6. Cleanup

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_SCRIPT="$SCRIPT_DIR/nix/build-rootfs.sh"
ROOTFS_DIR="$SCRIPT_DIR/nix/nixos-rootfs"

FS_NAME="vfy-nix-nixos"
CT_PLAIN="vfy-nix-plain"
CT_OCI="vfy-nix-oci"

APP_IMAGE="quay.io/nginx/nginx-unprivileged"
APP_FS="vfy-nix-nginx"
APP_PORT=8080
VOLUME_PATH="/usr/share/nginx/html"
TEST_MARKER="sdme-nixos-test"

DATADIR="/var/lib/sdme"
KEEP=0
REPORT_DIR="."

# Timeouts (seconds)
TIMEOUT_BUILD=900
TIMEOUT_IMPORT=300
TIMEOUT_BOOT=120
TIMEOUT_TEST=60

# Result tracking
declare -A RESULTS
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

End-to-end verification of NixOS rootfs import, container boot, and OCI app.
Must be run as root. Requires nix to build the rootfs.

Options:
  --keep           Do not remove test artifacts on exit
  --report-dir DIR Write report to DIR (default: .)
  --help           Show help
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
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
                echo "error: unknown option: $1" >&2
                usage >&2
                exit 1
                ;;
        esac
        shift
    done
}

# -- Logging -------------------------------------------------------------------

log() { echo "==> $*"; }
log_ok() { echo "  [PASS] $*"; }
log_fail() { echo "  [FAIL] $*"; }
log_skip() { echo "  [SKIP] $*"; }

record() {
    local key="$1" status="$2" msg="${3:-}"
    RESULTS["$key"]="$status|$msg"
    case "$status" in
        PASS) PASS_COUNT=$((PASS_COUNT + 1)); log_ok "$key${msg:+: $msg}" ;;
        FAIL) FAIL_COUNT=$((FAIL_COUNT + 1)); log_fail "$key${msg:+: $msg}" ;;
        SKIP) SKIP_COUNT=$((SKIP_COUNT + 1)); log_skip "$key${msg:+: $msg}" ;;
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

# -- Cleanup -------------------------------------------------------------------

cleanup() {
    if [[ $KEEP -eq 1 ]]; then
        log "Keeping test artifacts (--keep)"
        return
    fi
    log "Cleaning up vfy-nix- artifacts..."

    # Stop and remove containers
    local names
    names=$(sdme ps 2>/dev/null | awk 'NR>1 {print $1}' | grep '^vfy-nix-' || true)
    for name in $names; do
        sdme stop "$name" 2>/dev/null || sdme stop --term "$name" 2>/dev/null || true
        sdme rm -f "$name" 2>/dev/null || true
    done

    # Remove rootfs
    names=$(sdme fs ls 2>/dev/null | awk 'NR>1 {print $1}' | grep '^vfy-nix-' || true)
    for name in $names; do
        sdme fs rm "$name" 2>/dev/null || true
    done

    # Remove built rootfs directory
    if [[ -d "$ROOTFS_DIR" ]]; then
        rm -rf "$ROOTFS_DIR"
    fi
}

trap cleanup EXIT INT TERM

# -- Helpers -------------------------------------------------------------------

stop_container() {
    local name="$1"
    timeout 30 sdme stop "$name" 2>/dev/null || \
        timeout 30 sdme stop --term "$name" 2>/dev/null || true
}

fs_exists() {
    sdme fs ls 2>/dev/null | awk 'NR>1 {print $1}' | grep -qx "$1"
}

# -- Phase 1: Build NixOS rootfs -----------------------------------------------

phase1_build() {
    log "Phase 1: Build NixOS rootfs"

    if [[ -d "$ROOTFS_DIR" ]] && [[ -e "$ROOTFS_DIR/sbin/init" ]]; then
        log "  Rootfs already built at $ROOTFS_DIR, skipping"
        record "build" PASS "exists"
        return
    fi

    local output
    if output=$(timeout "$TIMEOUT_BUILD" "$BUILD_SCRIPT" "$ROOTFS_DIR" 2>&1); then
        record "build" PASS
    else
        record "build" FAIL "$output"
    fi
}

# -- Phase 2: Import rootfs into sdme ------------------------------------------

phase2_import() {
    log "Phase 2: Import NixOS rootfs"

    if [[ "$(result_status build)" != "PASS" ]]; then
        record "import" SKIP "build failed"
        return
    fi

    if fs_exists "$FS_NAME"; then
        log "  $FS_NAME already exists, skipping import"
        record "import" PASS "exists"
        return
    fi

    local output
    if output=$(timeout "$TIMEOUT_IMPORT" sdme fs import "$FS_NAME" "$ROOTFS_DIR" -v -f 2>&1); then
        record "import" PASS
    else
        record "import" FAIL "$output"
    fi
}

# -- Phase 3: Boot plain NixOS container ----------------------------------------

phase3_boot_plain() {
    log "Phase 3: Boot plain NixOS container"

    if [[ "$(result_status import)" != "PASS" ]]; then
        record "plain/create" SKIP "import failed"
        record "plain/boot" SKIP "import failed"
        record "plain/exec" SKIP "import failed"
        return
    fi

    # Create
    local output
    if ! output=$(timeout "$TIMEOUT_BOOT" sdme create -r "$FS_NAME" "$CT_PLAIN" 2>&1); then
        record "plain/create" FAIL "$output"
        record "plain/boot" SKIP "create failed"
        record "plain/exec" SKIP "create failed"
        return
    fi
    record "plain/create" PASS

    # Start
    if ! output=$(timeout "$TIMEOUT_BOOT" sdme start "$CT_PLAIN" -t 120 2>&1); then
        record "plain/boot" FAIL "start failed: $output"
        record "plain/exec" SKIP "start failed"
        sdme rm -f "$CT_PLAIN" 2>/dev/null || true
        return
    fi
    record "plain/boot" PASS

    # Exec a basic command
    if output=$(timeout "$TIMEOUT_TEST" sdme exec "$CT_PLAIN" /run/current-system/sw/bin/uname -a 2>&1); then
        record "plain/exec" PASS "$output"
    else
        record "plain/exec" FAIL "$output"
    fi

    stop_container "$CT_PLAIN"
    sdme rm -f "$CT_PLAIN" 2>/dev/null || true
}

# -- Phase 4: Import nginx-unprivileged OCI app ---------------------------------

phase4_import_oci() {
    log "Phase 4: Import nginx-unprivileged OCI app on NixOS base"

    if [[ "$(result_status import)" != "PASS" ]]; then
        record "oci/import" SKIP "base import failed"
        return
    fi

    if fs_exists "$APP_FS"; then
        log "  $APP_FS already exists, skipping import"
        record "oci/import" PASS "exists"
        return
    fi

    local output
    if output=$(timeout "$TIMEOUT_IMPORT" sdme fs import "$APP_FS" "$APP_IMAGE" \
            --base-fs="$FS_NAME" --oci-mode=app -v --install-packages=yes -f 2>&1); then
        record "oci/import" PASS
    else
        record "oci/import" FAIL "$output"
    fi
}

# -- Phase 5: Create, boot, and test OCI app container --------------------------

phase5_test_oci() {
    log "Phase 5: Test OCI nginx-unprivileged on NixOS"

    if [[ "$(result_status "oci/import")" != "PASS" ]]; then
        record "oci/create" SKIP "app import failed"
        record "oci/state-ports" SKIP "app import failed"
        record "oci/volume-dir" SKIP "app import failed"
        record "oci/boot" SKIP "app import failed"
        record "oci/service" SKIP "app import failed"
        record "oci/logs" SKIP "app import failed"
        record "oci/curl-port" SKIP "app import failed"
        record "oci/curl-content" SKIP "app import failed"
        return
    fi

    # Patch volumes file to exercise the volume pipeline.
    local volumes_file="$DATADIR/fs/$APP_FS/oci/volumes"
    echo "$VOLUME_PATH" >> "$volumes_file"
    log "  Appended $VOLUME_PATH to $volumes_file"

    # Create container with private network + veth for port forwarding.
    local output
    if ! output=$(timeout "$TIMEOUT_BOOT" sdme create -r "$APP_FS" --private-network --network-veth "$CT_OCI" 2>&1); then
        record "oci/create" FAIL "$output"
        record "oci/state-ports" SKIP "create failed"
        record "oci/volume-dir" SKIP "create failed"
        record "oci/boot" SKIP "create failed"
        record "oci/service" SKIP "create failed"
        record "oci/logs" SKIP "create failed"
        record "oci/curl-port" SKIP "create failed"
        record "oci/curl-content" SKIP "create failed"
        return
    fi
    record "oci/create" PASS

    # Verify state file has ports
    local state_file="$DATADIR/state/$CT_OCI"
    local ports_val
    ports_val=$(grep '^PORTS=' "$state_file" 2>/dev/null | cut -d= -f2- || true)
    if [[ "$ports_val" == *"$APP_PORT"* ]]; then
        record "oci/state-ports" PASS "$ports_val"
    else
        record "oci/state-ports" FAIL "PORTS=$ports_val"
    fi

    # Verify volume directory
    local vol_dir="$DATADIR/volumes/$CT_OCI/usr-share-nginx-html"
    if [[ -d "$vol_dir" ]]; then
        record "oci/volume-dir" PASS "$vol_dir"
    else
        record "oci/volume-dir" FAIL "$vol_dir does not exist"
        record "oci/boot" SKIP "volume dir missing"
        record "oci/service" SKIP "volume dir missing"
        record "oci/logs" SKIP "volume dir missing"
        record "oci/curl-port" SKIP "volume dir missing"
        record "oci/curl-content" SKIP "volume dir missing"
        stop_container "$CT_OCI"
        sdme rm -f "$CT_OCI" 2>/dev/null || true
        return
    fi

    # Write test content
    cat > "$vol_dir/index.html" <<HTMLEOF
<h1>$TEST_MARKER</h1>
HTMLEOF
    log "  Wrote test content to $vol_dir/index.html"

    # Enable systemd-networkd in the container for veth DHCP.
    # NixOS uses /etc/systemd/system symlinks managed by NixOS activation,
    # but our overlayfs upper layer takes precedence.
    local upper="$DATADIR/containers/$CT_OCI/upper"
    local wants_dir="$upper/etc/systemd/system/multi-user.target.wants"
    mkdir -p "$wants_dir"

    # NixOS stores unit files in the nix store. Find the networkd unit path.
    local networkd_unit
    networkd_unit=$(find "$DATADIR/fs/$APP_FS/nix/store" -path "*/lib/systemd/system/systemd-networkd.service" -print -quit 2>/dev/null || true)
    if [[ -n "$networkd_unit" ]]; then
        # Use the in-container path (strip the rootfs prefix).
        local ct_unit_path="/${networkd_unit#"$DATADIR/fs/$APP_FS"/}"
        ln -sf "$ct_unit_path" "$wants_dir/systemd-networkd.service"
        local ct_socket_path="${ct_unit_path%.service}.socket"
        ln -sf "$ct_socket_path" "$wants_dir/systemd-networkd.socket"
    else
        # Fallback: standard systemd paths.
        ln -sf /usr/lib/systemd/system/systemd-networkd.service "$wants_dir/systemd-networkd.service"
        ln -sf /usr/lib/systemd/system/systemd-networkd.socket "$wants_dir/systemd-networkd.socket"
    fi

    # Start container
    if ! output=$(timeout "$TIMEOUT_BOOT" sdme start "$CT_OCI" -t 120 2>&1); then
        record "oci/boot" FAIL "start failed: $output"
        record "oci/service" SKIP "start failed"
        record "oci/logs" SKIP "start failed"
        record "oci/curl-port" SKIP "start failed"
        record "oci/curl-content" SKIP "start failed"
        sdme rm -f "$CT_OCI" 2>/dev/null || true
        return
    fi
    record "oci/boot" PASS

    # Wait for networkd DHCP + nginx readiness
    sleep 5

    # Check sdme-oci-app.service
    if output=$(timeout "$TIMEOUT_TEST" sdme exec "$CT_OCI" \
            /run/current-system/sw/bin/systemctl is-active sdme-oci-app.service 2>&1); then
        record "oci/service" PASS
    else
        record "oci/service" FAIL "$output"
    fi

    # Check OCI app logs via sdme logs --oci
    if output=$(timeout "$TIMEOUT_TEST" sdme logs --oci "$CT_OCI" --no-pager -n 5 2>&1); then
        record "oci/logs" PASS
    else
        record "oci/logs" FAIL "$output"
    fi

    # Curl the port-forwarded nginx via the host-side veth IP.
    local veth_ip
    veth_ip=$(ip -4 addr show to 192.168.0.0/16 dev "$(ip -o link show | grep "altname ve-${CT_OCI}" | awk -F'[ :]+' '{print $2}')" 2>/dev/null \
        | grep -oP 'inet \K[0-9.]+' || true)
    if [[ -z "$veth_ip" ]]; then
        veth_ip=$(ip -4 addr show | grep -A2 "ve-" | grep -oP 'inet \K192\.168\.[0-9.]+' | head -1 || true)
    fi
    if [[ -z "$veth_ip" ]]; then
        record "oci/curl-port" FAIL "could not find veth IP"
        record "oci/curl-content" SKIP "no veth IP"
        stop_container "$CT_OCI"
        sdme rm -f "$CT_OCI" 2>/dev/null || true
        return
    fi
    log "  Using veth IP $veth_ip for port-forwarded curl"

    local http_code body
    http_code=$(timeout 10 curl -s -o /dev/null -w '%{http_code}' "http://${veth_ip}:${APP_PORT}" 2>&1) || true
    if [[ "$http_code" == "200" ]]; then
        record "oci/curl-port" PASS "HTTP $http_code via $veth_ip"
    else
        record "oci/curl-port" FAIL "HTTP $http_code via $veth_ip"
    fi

    body=$(timeout 10 curl -s "http://${veth_ip}:${APP_PORT}" 2>&1) || true
    if [[ "$body" == *"$TEST_MARKER"* ]]; then
        record "oci/curl-content" PASS
    else
        record "oci/curl-content" FAIL "body does not contain $TEST_MARKER"
    fi

    # Cleanup this container
    stop_container "$CT_OCI"
    sdme rm -f "$CT_OCI" 2>/dev/null || true
}

# -- Report generation ---------------------------------------------------------

generate_report() {
    local ts
    ts=$(date +%Y%m%d-%H%M%S)
    local report="$REPORT_DIR/verify-nixos-$ts.md"

    log "Writing report to $report"

    mkdir -p "$REPORT_DIR"

    {
        echo "# sdme NixOS Verification Report"
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
        echo "| Test | Status | Details |"
        echo "|------|--------|---------|"
        for key in build import plain/create plain/boot plain/exec \
                   oci/import oci/create oci/state-ports oci/volume-dir \
                   oci/boot oci/service oci/logs oci/curl-port oci/curl-content; do
            if [[ -n "${RESULTS[$key]+x}" ]]; then
                local st msg
                st=$(result_status "$key")
                msg=$(result_msg "$key")
                echo "| $key | $st | ${msg:--} |"
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

    echo ""
    echo "Report: $report"
}

# -- Main ----------------------------------------------------------------------

main() {
    parse_args "$@"

    if [[ $(id -u) -ne 0 ]]; then
        echo "error: must run as root" >&2
        exit 1
    fi

    if ! command -v sdme &>/dev/null; then
        echo "error: sdme not found in PATH" >&2
        exit 1
    fi

    # Check nix availability early.
    local has_nix=1
    if ! command -v nix-build &>/dev/null; then
        # Try sourcing nix profile.
        for f in /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh \
                 /etc/profile.d/nix.sh; do
            if [[ -f "$f" ]]; then
                # shellcheck source=/dev/null
                . "$f"
                break
            fi
        done
        if ! command -v nix-build &>/dev/null; then
            has_nix=0
        fi
    fi

    if [[ $has_nix -eq 0 ]]; then
        echo "error: nix not found; install it first: https://nixos.org/download" >&2
        exit 1
    fi

    echo "NixOS verification: rootfs build, import, boot, OCI nginx"
    echo ""

    phase1_build
    phase2_import
    phase3_boot_plain
    phase4_import_oci
    phase5_test_oci
    generate_report

    echo ""
    echo "Results: $PASS_COUNT passed, $FAIL_COUNT failed, $SKIP_COUNT skipped"

    if [[ $FAIL_COUNT -gt 0 ]]; then
        exit 1
    fi
}

main "$@"
