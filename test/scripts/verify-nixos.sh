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
#
# NixOS note: OCI app unit files are placed in /etc/systemd/system.control/
# instead of /etc/systemd/system/ because NixOS activation replaces the
# latter with an immutable symlink to the Nix store.

source "$(dirname "$0")/lib.sh"

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
REPORT_DIR="."

# Timeouts (seconds)
TIMEOUT_BUILD=900
TIMEOUT_IMPORT=300
TIMEOUT_BOOT=120
TIMEOUT_TEST=60

# Result tracking
declare -A RESULTS

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

End-to-end verification of NixOS rootfs import, container boot, and OCI app.
Must be run as root. Requires nix to build the rootfs.

Options:
  --report-dir DIR Write report to DIR (default: .)
  --help           Show help
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
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

record() {
    local key="$1" status="$2" msg="${3:-}"
    RESULTS["$key"]="$status|$msg"
    case "$status" in
        PASS) ((_pass++)) || true; echo "  [PASS] $key${msg:+: $msg}" ;;
        FAIL) ((_fail++)) || true; echo "  [FAIL] $key${msg:+: $msg}" ;;
        SKIP) ((_skip++)) || true; echo "  [SKIP] $key${msg:+: $msg}" ;;
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
    log "Cleaning up vfy-nix- artifacts..."

    # Stop and remove containers
    local names
    names=$(sdme ps 2>/dev/null | awk 'NR>1 {print $1}' | grep '^vfy-nix-' || true)
    for name in $names; do
        stop_container "$name"
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
    local volumes_file="$DATADIR/fs/$APP_FS/oci/apps/nginx-unprivileged/volumes"
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

    # NixOS already enables systemd-networkd via its configuration
    # (networking.useNetworkd = true in container.nix), so no manual
    # enablement in the overlayfs upper layer is needed.  Writing to
    # upper/etc/systemd/system/ would conflict with NixOS activation,
    # which replaces /etc/systemd/system with an immutable symlink.

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

    # Check sdme-oci-nginx-unprivileged.service
    if output=$(timeout "$TIMEOUT_TEST" sdme exec "$CT_OCI" \
            /run/current-system/sw/bin/systemctl is-active sdme-oci-nginx-unprivileged.service 2>&1); then
        record "oci/service" PASS
    else
        record "oci/service" FAIL "$output"
    fi

    # Check OCI app logs via sdme logs --oci
    if output=$(timeout "$TIMEOUT_TEST" sdme logs --oci -- "$CT_OCI" --no-pager -n 5 2>&1); then
        record "oci/logs" PASS
    else
        record "oci/logs" FAIL "$output"
    fi

    # Curl the nginx service from inside the container's network namespace.
    # NixOS containers with veth get a link-local IP (DHCP isn't served by
    # the host networkd for the container subnet), so host-side curl can't
    # route to the container.  Instead, nsenter into the network namespace
    # and curl localhost, which reliably tests the OCI app service.
    local leader
    leader=$(machinectl show "$CT_OCI" -p Leader --value 2>/dev/null) || true
    if [[ -z "$leader" ]] || [[ ! -d "/proc/$leader" ]]; then
        record "oci/curl-port" FAIL "could not find container leader PID"
        record "oci/curl-content" SKIP "no leader PID"
        stop_container "$CT_OCI"
        sdme rm -f "$CT_OCI" 2>/dev/null || true
        return
    fi

    local http_code body
    http_code=$(timeout 10 nsenter -t "$leader" -n curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${APP_PORT}" 2>&1) || true
    if [[ "$http_code" == "200" ]]; then
        record "oci/curl-port" PASS "HTTP $http_code via nsenter localhost"
    else
        record "oci/curl-port" FAIL "HTTP $http_code via nsenter localhost"
    fi

    body=$(timeout 10 nsenter -t "$leader" -n curl -s "http://127.0.0.1:${APP_PORT}" 2>&1) || true
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
        local total=$((_pass + _fail + _skip))
        echo "| Result | Count |"
        echo "|--------|-------|"
        echo "| PASS | $_pass |"
        echo "| FAIL | $_fail |"
        echo "| SKIP | $_skip |"
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

    ensure_root
    ensure_sdme

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

    print_summary
}

main "$@"
