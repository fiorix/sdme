#!/usr/bin/env bash
set -uo pipefail

# verify-matrix.sh - end-to-end verification of distro x OCI app matrix
# Run as root. Uses vfy- prefix for all artifacts.

DISTROS=(debian ubuntu fedora centos almalinux)
APPS=(nginx mysql postgres redis)

declare -A DISTRO_IMAGES=(
    [debian]="docker.io/debian:stable"
    [ubuntu]="docker.io/ubuntu:24.04"
    [fedora]="quay.io/fedora/fedora:41"
    [centos]="quay.io/centos/centos:stream9"
    [almalinux]="quay.io/almalinuxorg/almalinux:9"
)

declare -A APP_IMAGES=(
    [nginx]="docker.io/nginx"
    [mysql]="docker.io/mysql"
    [postgres]="docker.io/postgres"
    [redis]="docker.io/redis"
)

declare -A APP_READY_WAIT=(
    [nginx]=3
    [mysql]=15
    [postgres]=10
    [redis]=3
)

DATADIR="/var/lib/sdme"
KEEP=0
REPORT_DIR="."
FILTER_DISTROS=()
FILTER_APPS=()

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

End-to-end verification of sdme distro x OCI app matrix.
Must be run as root.

Options:
  --distro NAME    Only test this distro (repeatable)
  --app NAME       Only test this app (repeatable)
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
            --app)
                shift
                FILTER_APPS+=("$1")
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
    for a in "${FILTER_APPS[@]}"; do
        if [[ -z "${APP_IMAGES[$a]+x}" ]]; then
            echo "error: unknown app: $a" >&2
            exit 1
        fi
    done

    # Apply filters
    if [[ ${#FILTER_DISTROS[@]} -gt 0 ]]; then
        DISTROS=("${FILTER_DISTROS[@]}")
    fi
    if [[ ${#FILTER_APPS[@]} -gt 0 ]]; then
        APPS=("${FILTER_APPS[@]}")
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
    log "Cleaning up vfy- artifacts..."

    # Stop and remove containers
    local names
    names=$(sdme ps 2>/dev/null | awk 'NR>1 {print $1}' | grep '^vfy-' || true)
    for name in $names; do
        sdme stop "$name" 2>/dev/null || sdme stop --term "$name" 2>/dev/null || true
        sdme rm -f "$name" 2>/dev/null || true
    done

    # Remove rootfs
    names=$(sdme fs ls 2>/dev/null | awk 'NR>1 {print $1}' | grep '^vfy-' || true)
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

# -- Phase 1: Import base OS rootfs --------------------------------------------

phase1_import() {
    log "Phase 1: Import base OS rootfs"
    for distro in "${DISTROS[@]}"; do
        local fs_name="vfy-$distro"
        local image="${DISTRO_IMAGES[$distro]}"
        log "  Importing $fs_name from $image"
        local output
        if output=$(timeout "$TIMEOUT_IMPORT" sdme fs import "$fs_name" "$image" -v --install-packages=yes -f 2>&1); then
            record "import/$distro" PASS
        else
            record "import/$distro" FAIL "$output"
        fi
    done
}

# -- Phase 2: Boot tests -------------------------------------------------------

phase2_boot() {
    log "Phase 2: Boot tests"
    for distro in "${DISTROS[@]}"; do
        local fs_name="vfy-$distro"
        local ct_name="vfy-boot-$distro"

        if [[ "$(result_status "import/$distro")" != "PASS" ]]; then
            record "boot/$distro/create" SKIP "base import failed"
            record "boot/$distro/systemd" SKIP "base import failed"
            record "boot/$distro/journalctl" SKIP "base import failed"
            record "boot/$distro/systemctl" SKIP "base import failed"
            continue
        fi

        log "  Boot testing $ct_name"

        # Create
        local output
        if ! output=$(timeout "$TIMEOUT_BOOT" sdme create -r "$fs_name" "$ct_name" 2>&1); then
            record "boot/$distro/create" FAIL "$output"
            continue
        fi
        record "boot/$distro/create" PASS

        # Start
        if ! output=$(timeout "$TIMEOUT_BOOT" sdme start "$ct_name" -t 120 2>&1); then
            record "boot/$distro/systemd" FAIL "start failed: $output"
            sdme rm -f "$ct_name" 2>/dev/null || true
            continue
        fi

        # systemctl is-system-running --wait
        if output=$(timeout "$TIMEOUT_TEST" sdme exec "$ct_name" /usr/bin/systemctl is-system-running --wait 2>&1); then
            record "boot/$distro/systemd" PASS
        else
            record "boot/$distro/systemd" FAIL "$output"
        fi

        # journalctl
        if output=$(timeout "$TIMEOUT_TEST" sdme exec "$ct_name" /usr/bin/journalctl --no-pager -n 5 2>&1); then
            record "boot/$distro/journalctl" PASS
        else
            record "boot/$distro/journalctl" FAIL "$output"
        fi

        # systemctl list-units
        if output=$(timeout "$TIMEOUT_TEST" sdme exec "$ct_name" /usr/bin/systemctl list-units --no-pager -q 2>&1); then
            record "boot/$distro/systemctl" PASS
        else
            record "boot/$distro/systemctl" FAIL "$output"
        fi

        # Cleanup
        stop_container "$ct_name"
        sdme rm -f "$ct_name" 2>/dev/null || true
    done
}

# -- Phase 3: OCI app matrix ---------------------------------------------------

app_verify() {
    local app="$1" ct_name="$2"
    case "$app" in
        nginx)
            local code
            code=$(timeout 10 curl -s -o /dev/null -w '%{http_code}' http://localhost:80 2>&1) || true
            if [[ "$code" == "200" ]]; then
                return 0
            else
                echo "HTTP $code"
                return 1
            fi
            ;;
        mysql)
            timeout 10 sdme exec "$ct_name" \
                /usr/sbin/chroot /oci/root /usr/bin/mysqladmin -u root -psecret status 2>&1
            ;;
        postgres)
            timeout 10 sdme exec "$ct_name" \
                /usr/sbin/chroot /oci/root /bin/su - postgres -c 'pg_isready' 2>&1
            ;;
        redis)
            local reply
            reply=$(timeout 10 sdme exec "$ct_name" \
                /usr/sbin/chroot /oci/root /usr/local/bin/redis-cli ping 2>&1) || true
            if [[ "$reply" == *"PONG"* ]]; then
                return 0
            else
                echo "$reply"
                return 1
            fi
            ;;
    esac
}

phase3_apps() {
    log "Phase 3: OCI app matrix"
    for distro in "${DISTROS[@]}"; do
        if [[ "$(result_status "import/$distro")" != "PASS" ]]; then
            for app in "${APPS[@]}"; do
                record "app/$app-on-$distro/import" SKIP "base import failed"
                record "app/$app-on-$distro/boot" SKIP "base import failed"
                record "app/$app-on-$distro/service" SKIP "base import failed"
                record "app/$app-on-$distro/logs" SKIP "base import failed"
                record "app/$app-on-$distro/status" SKIP "base import failed"
                record "app/$app-on-$distro/verify" SKIP "base import failed"
            done
            continue
        fi

        for app in "${APPS[@]}"; do
            local fs_name="vfy-$app-on-$distro"
            local ct_name="vfy-app-$app-on-$distro"
            local image="${APP_IMAGES[$app]}"
            local base_fs="vfy-$distro"

            log "  Testing $app on $distro"

            # Import app
            local output
            if ! output=$(timeout "$TIMEOUT_IMPORT" sdme fs import "$fs_name" "$image" \
                    --base-fs="$base_fs" --oci-mode=app -v --install-packages=yes -f 2>&1); then
                record "app/$app-on-$distro/import" FAIL "$output"
                record "app/$app-on-$distro/boot" SKIP "import failed"
                record "app/$app-on-$distro/service" SKIP "import failed"
                record "app/$app-on-$distro/logs" SKIP "import failed"
                record "app/$app-on-$distro/status" SKIP "import failed"
                record "app/$app-on-$distro/verify" SKIP "import failed"
                continue
            fi
            record "app/$app-on-$distro/import" PASS

            # Inject env vars
            local env_file="$DATADIR/fs/$fs_name/oci/env"
            case "$app" in
                mysql)
                    echo 'MYSQL_ROOT_PASSWORD=secret' >> "$env_file"
                    ;;
                postgres)
                    echo 'POSTGRES_PASSWORD=secret' >> "$env_file"
                    ;;
            esac

            # Create
            if ! output=$(timeout "$TIMEOUT_BOOT" sdme create -r "$fs_name" "$ct_name" 2>&1); then
                record "app/$app-on-$distro/boot" FAIL "create failed: $output"
                record "app/$app-on-$distro/service" SKIP "create failed"
                record "app/$app-on-$distro/logs" SKIP "create failed"
                record "app/$app-on-$distro/status" SKIP "create failed"
                record "app/$app-on-$distro/verify" SKIP "create failed"
                continue
            fi

            # Start
            if ! output=$(timeout "$TIMEOUT_BOOT" sdme start "$ct_name" -t 120 2>&1); then
                record "app/$app-on-$distro/boot" FAIL "start failed: $output"
                record "app/$app-on-$distro/service" SKIP "start failed"
                record "app/$app-on-$distro/logs" SKIP "start failed"
                record "app/$app-on-$distro/status" SKIP "start failed"
                record "app/$app-on-$distro/verify" SKIP "start failed"
                sdme rm -f "$ct_name" 2>/dev/null || true
                continue
            fi
            record "app/$app-on-$distro/boot" PASS

            # Wait for app readiness
            local wait_secs="${APP_READY_WAIT[$app]}"
            sleep "$wait_secs"

            # Service active check
            if output=$(timeout "$TIMEOUT_TEST" sdme exec "$ct_name" \
                    /usr/bin/systemctl is-active sdme-oci-app.service 2>&1); then
                record "app/$app-on-$distro/service" PASS
            else
                record "app/$app-on-$distro/service" FAIL "$output"
            fi

            # Logs
            if output=$(timeout "$TIMEOUT_TEST" sdme exec "$ct_name" \
                    /usr/bin/journalctl -u sdme-oci-app.service --no-pager -n 10 2>&1); then
                record "app/$app-on-$distro/logs" PASS
            else
                record "app/$app-on-$distro/logs" FAIL "$output"
            fi

            # Status
            if output=$(timeout "$TIMEOUT_TEST" sdme exec "$ct_name" \
                    /usr/bin/systemctl status sdme-oci-app.service --no-pager 2>&1); then
                record "app/$app-on-$distro/status" PASS
            else
                record "app/$app-on-$distro/status" FAIL "$output"
            fi

            # App-specific verify
            if output=$(app_verify "$app" "$ct_name"); then
                record "app/$app-on-$distro/verify" PASS
            else
                record "app/$app-on-$distro/verify" FAIL "$output"
            fi

            # Cleanup container (rootfs kept for Phase 3c hardened tests)
            stop_container "$ct_name"
            sdme rm -f "$ct_name" 2>/dev/null || true
        done
    done
}

# -- Phase 3b: Hardened boot tests ---------------------------------------------

phase3b_hardened_boot() {
    log "Phase 3b: Hardened boot tests"
    for distro in "${DISTROS[@]}"; do
        local fs_name="vfy-$distro"
        local ct_name="vfy-h-boot-$distro"

        if [[ "$(result_status "import/$distro")" != "PASS" ]]; then
            record "hardened-boot/$distro/create" SKIP "base import failed"
            record "hardened-boot/$distro/systemd" SKIP "base import failed"
            continue
        fi

        log "  Hardened boot testing $ct_name"

        # Create with --hardened
        local output
        if ! output=$(timeout "$TIMEOUT_BOOT" sdme create -r "$fs_name" --hardened "$ct_name" 2>&1); then
            record "hardened-boot/$distro/create" FAIL "$output"
            continue
        fi
        record "hardened-boot/$distro/create" PASS

        # Start
        if ! output=$(timeout "$TIMEOUT_BOOT" sdme start "$ct_name" -t 120 2>&1); then
            record "hardened-boot/$distro/systemd" FAIL "start failed: $output"
            sdme rm -f "$ct_name" 2>/dev/null || true
            continue
        fi

        # systemctl is-system-running --wait
        if output=$(timeout "$TIMEOUT_TEST" sdme exec "$ct_name" /usr/bin/systemctl is-system-running --wait 2>&1); then
            record "hardened-boot/$distro/systemd" PASS
        else
            if [[ "$output" == *"degraded"* ]]; then
                record "hardened-boot/$distro/systemd" PASS "degraded (acceptable)"
            else
                record "hardened-boot/$distro/systemd" FAIL "$output"
            fi
        fi

        # Cleanup
        stop_container "$ct_name"
        sdme rm -f "$ct_name" 2>/dev/null || true
    done
}

# -- Phase 3c: Hardened OCI app matrix -----------------------------------------

phase3c_hardened_apps() {
    log "Phase 3c: Hardened OCI app matrix"
    for distro in "${DISTROS[@]}"; do
        if [[ "$(result_status "import/$distro")" != "PASS" ]]; then
            for app in "${APPS[@]}"; do
                record "hardened-app/$app-on-$distro/boot" SKIP "base import failed"
                record "hardened-app/$app-on-$distro/service" SKIP "base import failed"
            done
            continue
        fi

        for app in "${APPS[@]}"; do
            local fs_name="vfy-$app-on-$distro"
            local ct_name="vfy-h-app-$app-on-$distro"

            # The rootfs must already exist from Phase 3.
            if [[ "$(result_status "app/$app-on-$distro/import")" != "PASS" ]]; then
                record "hardened-app/$app-on-$distro/boot" SKIP "app import failed"
                record "hardened-app/$app-on-$distro/service" SKIP "app import failed"
                continue
            fi

            # Check rootfs still exists (Phase 3 removes it unless --keep).
            if ! sdme fs ls 2>/dev/null | awk 'NR>1 {print $1}' | grep -qx "$fs_name"; then
                record "hardened-app/$app-on-$distro/boot" SKIP "rootfs removed (use --keep)"
                record "hardened-app/$app-on-$distro/service" SKIP "rootfs removed (use --keep)"
                continue
            fi

            log "  Hardened testing $app on $distro"

            # Create with --hardened
            local output
            if ! output=$(timeout "$TIMEOUT_BOOT" sdme create -r "$fs_name" --hardened "$ct_name" 2>&1); then
                record "hardened-app/$app-on-$distro/boot" FAIL "create failed: $output"
                record "hardened-app/$app-on-$distro/service" SKIP "create failed"
                continue
            fi

            # Start
            if ! output=$(timeout "$TIMEOUT_BOOT" sdme start "$ct_name" -t 120 2>&1); then
                record "hardened-app/$app-on-$distro/boot" FAIL "start failed: $output"
                record "hardened-app/$app-on-$distro/service" SKIP "start failed"
                sdme rm -f "$ct_name" 2>/dev/null || true
                continue
            fi
            record "hardened-app/$app-on-$distro/boot" PASS

            # Wait for app readiness
            local wait_secs="${APP_READY_WAIT[$app]}"
            sleep "$wait_secs"

            # Service active check
            if output=$(timeout "$TIMEOUT_TEST" sdme exec "$ct_name" \
                    /usr/bin/systemctl is-active sdme-oci-app.service 2>&1); then
                record "hardened-app/$app-on-$distro/service" PASS
            else
                record "hardened-app/$app-on-$distro/service" FAIL "$output"
            fi

            # Cleanup
            stop_container "$ct_name"
            sdme rm -f "$ct_name" 2>/dev/null || true
        done
    done
}

# -- Phase 4: Remove base rootfs -----------------------------------------------

phase4_cleanup() {
    if [[ $KEEP -eq 1 ]]; then
        log "Phase 4: Skipping rootfs cleanup (--keep)"
        return
    fi
    log "Phase 4: Remove rootfs"
    # Remove app rootfs
    for distro in "${DISTROS[@]}"; do
        for app in "${APPS[@]}"; do
            sdme fs rm "vfy-$app-on-$distro" 2>/dev/null || true
        done
    done
    # Remove base rootfs
    for distro in "${DISTROS[@]}"; do
        sdme fs rm "vfy-$distro" 2>/dev/null || true
    done
}

# -- Phase 5: Report generation ------------------------------------------------

generate_report() {
    local ts
    ts=$(date +%Y%m%d-%H%M%S)
    local report="$REPORT_DIR/verify-matrix-$ts.md"

    log "Phase 5: Writing report to $report"

    mkdir -p "$REPORT_DIR"

    {
        echo "# sdme Verification Matrix Report"
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

        # Phase 1 table
        echo "## Phase 1: Base OS Import"
        echo ""
        echo "| Distro | Image | Result |"
        echo "|--------|-------|--------|"
        for distro in "${DISTROS[@]}"; do
            local key="import/$distro"
            local st
            st=$(result_status "$key")
            echo "| $distro | ${DISTRO_IMAGES[$distro]} | $st |"
        done
        echo ""

        # Phase 2 table
        echo "## Phase 2: Boot Tests"
        echo ""
        echo "| Distro | Create | systemd | journalctl | systemctl |"
        echo "|--------|--------|---------|------------|-----------|"
        for distro in "${DISTROS[@]}"; do
            local c s j u
            c=$(result_status "boot/$distro/create")
            s=$(result_status "boot/$distro/systemd")
            j=$(result_status "boot/$distro/journalctl")
            u=$(result_status "boot/$distro/systemctl")
            echo "| $distro | $c | $s | $j | $u |"
        done
        echo ""

        # Phase 3 table
        echo "## Phase 3: OCI App Matrix"
        echo ""
        echo "| App | Distro | Import | Boot | Service | Logs | Status | Verify |"
        echo "|-----|--------|--------|------|---------|------|--------|--------|"
        for distro in "${DISTROS[@]}"; do
            for app in "${APPS[@]}"; do
                local prefix="app/$app-on-$distro"
                local i b sv l st v
                i=$(result_status "$prefix/import")
                b=$(result_status "$prefix/boot")
                sv=$(result_status "$prefix/service")
                l=$(result_status "$prefix/logs")
                st=$(result_status "$prefix/status")
                v=$(result_status "$prefix/verify")
                echo "| $app | $distro | $i | $b | $sv | $l | $st | $v |"
            done
        done
        echo ""

        # Phase 3b table
        echo "## Phase 3b: Hardened Boot Tests"
        echo ""
        echo "| Distro | Create | systemd |"
        echo "|--------|--------|---------|"
        for distro in "${DISTROS[@]}"; do
            local c s
            c=$(result_status "hardened-boot/$distro/create")
            s=$(result_status "hardened-boot/$distro/systemd")
            echo "| $distro | $c | $s |"
        done
        echo ""

        # Phase 3c table
        echo "## Phase 3c: Hardened OCI App Matrix"
        echo ""
        echo "| App | Distro | Boot | Service |"
        echo "|-----|--------|------|---------|"
        for distro in "${DISTROS[@]}"; do
            for app in "${APPS[@]}"; do
                local prefix="hardened-app/$app-on-$distro"
                local b sv
                b=$(result_status "$prefix/boot")
                sv=$(result_status "$prefix/service")
                echo "| $app | $distro | $b | $sv |"
            done
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

    echo "Verification matrix: ${#DISTROS[@]} distros x ${#APPS[@]} apps"
    echo "Distros: ${DISTROS[*]}"
    echo "Apps:    ${APPS[*]}"
    echo ""

    phase1_import
    phase2_boot
    phase3_apps
    phase3b_hardened_boot
    phase3c_hardened_apps
    phase4_cleanup
    generate_report

    echo ""
    echo "Results: $PASS_COUNT passed, $FAIL_COUNT failed, $SKIP_COUNT skipped"

    if [[ $FAIL_COUNT -gt 0 ]]; then
        exit 1
    fi
}

main "$@"
