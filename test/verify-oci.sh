#!/usr/bin/env bash
set -uo pipefail

# verify-oci.sh - end-to-end verification of OCI port forwarding and volume mounting
# Run as root. Uses vfy-oci- prefix for all artifacts.
#
# Tests nginx-unprivileged on multiple base distros with --hardened mode,
# verifying that OCI-declared ports are auto-forwarded and OCI-declared
# volumes are auto-mounted and serve content.

DISTROS=(ubuntu fedora)

declare -A DISTRO_IMAGES=(
    [ubuntu]="docker.io/ubuntu:24.04"
    [fedora]="quay.io/fedora/fedora:41"
)

APP_IMAGE="quay.io/nginx/nginx-unprivileged"
APP_PORT=8080
VOLUME_PATH="/usr/share/nginx/html"
TEST_MARKER="sdme-oci-test"

DATADIR="/var/lib/sdme"
KEEP=0
REPORT_DIR="."
FILTER_DISTROS=()

# Timeouts (seconds)
TIMEOUT_IMPORT=600
TIMEOUT_BOOT=120
TIMEOUT_TEST=300

# Result tracking
declare -A RESULTS
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

End-to-end verification of OCI port forwarding and volume mounting.
Must be run as root.

Options:
  --distro NAME    Only test this distro (repeatable)
  --keep           Do not remove test artifacts on exit
  --report-dir DIR Write report and log to DIR (default: .)
  --help           Show help
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --distro)
                shift
                FILTER_DISTROS+=("$1")
                ;;
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

    # Validate filters
    for d in "${FILTER_DISTROS[@]}"; do
        if [[ -z "${DISTRO_IMAGES[$d]+x}" ]]; then
            echo "error: unknown distro: $d" >&2
            exit 1
        fi
    done

    # Apply filters
    if [[ ${#FILTER_DISTROS[@]} -gt 0 ]]; then
        DISTROS=("${FILTER_DISTROS[@]}")
    fi
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
    log "Cleaning up vfy-oci- artifacts..."

    # Stop and remove containers
    local names
    names=$(sdme ps 2>/dev/null | awk 'NR>1 {print $1}' | grep '^vfy-oci-' || true)
    for name in $names; do
        sdme stop "$name" 2>/dev/null || sdme stop --term "$name" 2>/dev/null || true
        sdme rm -f "$name" 2>/dev/null || true
    done

    # Remove rootfs
    names=$(sdme fs ls 2>/dev/null | awk 'NR>1 {print $1}' | grep '^vfy-oci-' || true)
    for name in $names; do
        sdme fs rm "$name" 2>/dev/null || true
    done
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

# -- Phase 1: Import base OS rootfs -------------------------------------------

phase1_import_base() {
    log "Phase 1: Import base OS rootfs"
    for distro in "${DISTROS[@]}"; do
        local fs_name="vfy-oci-$distro"
        local image="${DISTRO_IMAGES[$distro]}"
        if fs_exists "$fs_name"; then
            log "  $fs_name already exists, skipping import"
            record "$distro/import-base" PASS "exists"
            continue
        fi
        log "  Importing $fs_name from $image"
        local output
        if output=$(timeout "$TIMEOUT_IMPORT" sdme fs import "$fs_name" "$image" -v --install-packages=yes -f 2>&1); then
            record "$distro/import-base" PASS
        else
            record "$distro/import-base" FAIL "$output"
        fi
    done
}

# -- Phase 2: Import nginx app, patch volumes, create & test -------------------

phase2_test_oci() {
    log "Phase 2: OCI port forwarding and volume mounting"
    for distro in "${DISTROS[@]}"; do
        local base_fs="vfy-oci-$distro"
        local app_fs="vfy-oci-nginx-on-$distro"
        local ct_name="vfy-oci-ct-$distro"

        if [[ "$(result_status "$distro/import-base")" != "PASS" ]]; then
            record "$distro/import-app" SKIP "base import failed"
            record "$distro/state-ports" SKIP "base import failed"
            record "$distro/state-volumes" SKIP "base import failed"
            record "$distro/volume-dir" SKIP "base import failed"
            record "$distro/boot" SKIP "base import failed"
            record "$distro/service" SKIP "base import failed"
            record "$distro/oci-logs" SKIP "base import failed"
            record "$distro/curl-port" SKIP "base import failed"
            record "$distro/curl-content" SKIP "base import failed"
            continue
        fi

        log "  Testing nginx-unprivileged on $distro"

        # -- Import app rootfs --
        local output
        if fs_exists "$app_fs"; then
            log "    $app_fs already exists, skipping import"
            record "$distro/import-app" PASS "exists"
        elif output=$(timeout "$TIMEOUT_IMPORT" sdme fs import "$app_fs" "$APP_IMAGE" \
                --base-fs="$base_fs" --oci-mode=app -v --install-packages=yes -f 2>&1); then
            record "$distro/import-app" PASS
        else
            record "$distro/import-app" FAIL "$output"
            record "$distro/state-ports" SKIP "app import failed"
            record "$distro/state-volumes" SKIP "app import failed"
            record "$distro/volume-dir" SKIP "app import failed"
            record "$distro/boot" SKIP "app import failed"
            record "$distro/service" SKIP "app import failed"
            record "$distro/oci-logs" SKIP "app import failed"
            record "$distro/curl-port" SKIP "app import failed"
            record "$distro/curl-content" SKIP "app import failed"
            continue
        fi

        # -- Patch volumes file --
        # nginx-unprivileged declares 8080/tcp but no volumes.
        # Append the nginx document root so the volume pipeline is exercised.
        local volumes_file="$DATADIR/fs/$app_fs/oci/volumes"
        echo "$VOLUME_PATH" >> "$volumes_file"
        log "  Appended $VOLUME_PATH to $volumes_file"

        # -- Create container with private network + veth --
        # --private-network triggers port auto-forwarding; --network-veth
        # creates the virtual ethernet pair needed for the forwarding to work.
        if ! output=$(timeout "$TIMEOUT_BOOT" sdme create -r "$app_fs" --private-network --network-veth "$ct_name" 2>&1); then
            record "$distro/state-ports" SKIP "create failed: $output"
            record "$distro/state-volumes" SKIP "create failed"
            record "$distro/volume-dir" SKIP "create failed"
            record "$distro/boot" SKIP "create failed"
            record "$distro/service" SKIP "create failed"
            record "$distro/oci-logs" SKIP "create failed"
            record "$distro/curl-port" SKIP "create failed"
            record "$distro/curl-content" SKIP "create failed"
            continue
        fi

        # -- Verify state file --
        local state_file="$DATADIR/state/$ct_name"

        # Check PORTS contains 8080
        local ports_val
        ports_val=$(grep '^PORTS=' "$state_file" 2>/dev/null | cut -d= -f2- || true)
        if [[ "$ports_val" == *"$APP_PORT"* ]]; then
            record "$distro/state-ports" PASS "$ports_val"
        else
            record "$distro/state-ports" FAIL "PORTS=$ports_val"
        fi

        # Check OCI_VOLUMES is set
        local volumes_val
        volumes_val=$(grep '^OCI_VOLUMES=' "$state_file" 2>/dev/null | cut -d= -f2- || true)
        if [[ -n "$volumes_val" ]]; then
            record "$distro/state-volumes" PASS "$volumes_val"
        else
            record "$distro/state-volumes" FAIL "OCI_VOLUMES not found in state"
        fi

        # -- Verify volume directory exists --
        local vol_dir="$DATADIR/volumes/$ct_name/usr-share-nginx-html"
        if [[ -d "$vol_dir" ]]; then
            record "$distro/volume-dir" PASS "$vol_dir"
        else
            record "$distro/volume-dir" FAIL "$vol_dir does not exist"
            # Can't serve content without the volume dir
            record "$distro/boot" SKIP "volume dir missing"
            record "$distro/service" SKIP "volume dir missing"
            record "$distro/oci-logs" SKIP "volume dir missing"
            record "$distro/curl-port" SKIP "volume dir missing"
            record "$distro/curl-content" SKIP "volume dir missing"
            stop_container "$ct_name"
            sdme rm -f "$ct_name" 2>/dev/null || true
            continue
        fi

        # -- Write test content into volume --
        cat > "$vol_dir/index.html" <<HTMLEOF
<h1>$TEST_MARKER</h1>
HTMLEOF
        log "  Wrote test content to $vol_dir/index.html"

        # -- Enable systemd-networkd in the container --
        # --network-veth creates a virtual ethernet pair. The container side
        # (host0) is configured via DHCP by systemd-networkd, which is
        # disabled by default in most distro rootfs. Enable it via a symlink
        # in the overlayfs upper layer before starting.
        local upper="$DATADIR/containers/$ct_name/upper"
        local wants_dir="$upper/etc/systemd/system/multi-user.target.wants"
        mkdir -p "$wants_dir"
        ln -sf /usr/lib/systemd/system/systemd-networkd.service "$wants_dir/systemd-networkd.service"
        ln -sf /usr/lib/systemd/system/systemd-networkd.socket "$wants_dir/systemd-networkd.socket"
        # Also enable systemd-networkd-wait-online to avoid races.
        ln -sf /usr/lib/systemd/system/systemd-networkd-wait-online.service \
            "$upper/etc/systemd/system/network-online.target.wants/systemd-networkd-wait-online.service" 2>/dev/null || true

        # -- Start container --
        if ! output=$(timeout "$TIMEOUT_BOOT" sdme start "$ct_name" -t 120 2>&1); then
            record "$distro/boot" FAIL "start failed: $output"
            record "$distro/service" SKIP "start failed"
            record "$distro/oci-logs" SKIP "start failed"
            record "$distro/curl-port" SKIP "start failed"
            record "$distro/curl-content" SKIP "start failed"
            sdme rm -f "$ct_name" 2>/dev/null || true
            continue
        fi
        record "$distro/boot" PASS

        # Wait for networkd DHCP + nginx readiness
        sleep 5

        # -- Check sdme-oci-app.service --
        if output=$(timeout "$TIMEOUT_TEST" sdme exec "$ct_name" \
                /usr/bin/systemctl is-active sdme-oci-app.service 2>&1); then
            record "$distro/service" PASS
        else
            record "$distro/service" FAIL "$output"
        fi

        # -- Check OCI app logs via sdme logs --oci --
        if output=$(timeout "$TIMEOUT_TEST" sdme logs --oci "$ct_name" --no-pager -n 5 2>&1); then
            record "$distro/oci-logs" PASS
        else
            record "$distro/oci-logs" FAIL "$output"
        fi

        # -- Curl the port-forwarded nginx --
        # systemd-nspawn's nft DNAT rules exclude 127.0.0.0/8 in the
        # output chain, so we must curl the host-side veth IP instead
        # of localhost. Find the interface by its altname.
        local veth_ip
        veth_ip=$(ip -4 addr show to 192.168.0.0/16 dev "$(ip -o link show | grep "altname ve-${ct_name}" | awk -F'[ :]+' '{print $2}')" 2>/dev/null \
            | grep -oP 'inet \K[0-9.]+' || true)
        if [[ -z "$veth_ip" ]]; then
            # Fallback: find any ve- interface with a 192.168.x.x address
            veth_ip=$(ip -4 addr show | grep -A2 "ve-" | grep -oP 'inet \K192\.168\.[0-9.]+' | head -1 || true)
        fi
        if [[ -z "$veth_ip" ]]; then
            record "$distro/curl-port" FAIL "could not find veth IP"
            record "$distro/curl-content" SKIP "no veth IP"
            stop_container "$ct_name"
            sdme rm -f "$ct_name" 2>/dev/null || true
            continue
        fi
        log "  Using veth IP $veth_ip for port-forwarded curl"

        local http_code body
        http_code=$(timeout 10 curl -s -o /dev/null -w '%{http_code}' "http://${veth_ip}:${APP_PORT}" 2>&1) || true
        if [[ "$http_code" == "200" ]]; then
            record "$distro/curl-port" PASS "HTTP $http_code via $veth_ip"
        else
            record "$distro/curl-port" FAIL "HTTP $http_code via $veth_ip"
        fi

        body=$(timeout 10 curl -s "http://${veth_ip}:${APP_PORT}" 2>&1) || true
        if [[ "$body" == *"$TEST_MARKER"* ]]; then
            record "$distro/curl-content" PASS
        else
            record "$distro/curl-content" FAIL "body does not contain $TEST_MARKER"
        fi

        # -- Cleanup --
        stop_container "$ct_name"
        sdme rm -f "$ct_name" 2>/dev/null || true
    done
}

# -- Phase 3: Remove rootfs ---------------------------------------------------

phase3_cleanup() {
    if [[ $KEEP -eq 1 ]]; then
        log "Phase 3: Skipping rootfs cleanup (--keep)"
        return
    fi
    log "Phase 3: Remove rootfs"
    for distro in "${DISTROS[@]}"; do
        sdme fs rm "vfy-oci-nginx-on-$distro" 2>/dev/null || true
        sdme fs rm "vfy-oci-$distro" 2>/dev/null || true
    done
}

# -- Phase 4: Report generation -----------------------------------------------

generate_report() {
    local ts
    ts=$(date +%Y%m%d-%H%M%S)
    local report="$REPORT_DIR/verify-oci-$ts.md"

    log "Phase 4: Writing report to $report"

    mkdir -p "$REPORT_DIR"

    {
        echo "# sdme OCI Port/Volume Verification Report"
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
        echo "| Distro | Import Base | Import App | State Ports | State Volumes | Volume Dir | Boot | Service | OCI Logs | Curl Port | Curl Content |"
        echo "|--------|------------|------------|-------------|---------------|------------|------|---------|----------|-----------|--------------|"
        for distro in "${DISTROS[@]}"; do
            local ib ia sp sv vd bo se ol cp cc
            ib=$(result_status "$distro/import-base")
            ia=$(result_status "$distro/import-app")
            sp=$(result_status "$distro/state-ports")
            sv=$(result_status "$distro/state-volumes")
            vd=$(result_status "$distro/volume-dir")
            bo=$(result_status "$distro/boot")
            se=$(result_status "$distro/service")
            ol=$(result_status "$distro/oci-logs")
            cp=$(result_status "$distro/curl-port")
            cc=$(result_status "$distro/curl-content")
            echo "| $distro | $ib | $ia | $sp | $sv | $vd | $bo | $se | $ol | $cp | $cc |"
        done
        echo ""

        # Detailed failures
        local has_failures=0
        for key in "${!RESULTS[@]}"; do
            local st
            st=$(result_status "$key")
            if [[ "$st" == "FAIL" ]]; then
                has_failures=1
                break
            fi
        done

        if [[ $has_failures -eq 1 ]]; then
            echo "## Failures"
            echo ""
            for key in $(echo "${!RESULTS[@]}" | tr ' ' '\n' | sort); do
                local st
                st=$(result_status "$key")
                if [[ "$st" == "FAIL" ]]; then
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

    echo "OCI port/volume verification: ${#DISTROS[@]} distros"
    echo "Distros: ${DISTROS[*]}"
    echo "App:     $APP_IMAGE"
    echo ""

    phase1_import_base
    phase2_test_oci
    phase3_cleanup
    generate_report

    echo ""
    echo "Results: $PASS_COUNT passed, $FAIL_COUNT failed, $SKIP_COUNT skipped"

    if [[ $FAIL_COUNT -gt 0 ]]; then
        exit 1
    fi
}

main "$@"
