#!/usr/bin/env bash
set -uo pipefail

# verify-distro-oci.sh - end-to-end verification of distro x OCI app matrix
#
# Tests OCI app deployment and hardened OCI app deployment across 7 distros:
#   Phase 1: Import base OS rootfs (7 distros)
#   Phase 2: OCI app matrix (3 apps x 7 distros = 21 combinations)
#   Phase 3: Hardened OCI app matrix (3 apps x 7 distros = 21 combinations)
#   Phase 4: Cleanup
#
# All artifacts use the "vfy-doci-" prefix.

source "$(dirname "$0")/lib.sh"

DISTROS=(debian ubuntu fedora centos almalinux archlinux opensuse)
APPS=(nginx-unprivileged redis postgresql)

declare -A APP_IMAGES=(
    [nginx-unprivileged]="docker.io/nginxinc/nginx-unprivileged"
    [redis]="docker.io/redis"
    [postgresql]="docker.io/postgres"
)

declare -A APP_READY_WAIT=(
    [nginx-unprivileged]=3
    [redis]=3
    [postgresql]=10
)

NGINX_MARKER="sdme-distro-oci-test-$$"
DATADIR="/var/lib/sdme"
REPORT_DIR="."
FILTER_DISTROS=()
FILTER_APPS=()

TIMEOUT_IMPORT=$(scale_timeout 600)
TIMEOUT_BOOT=$(scale_timeout 120)
TIMEOUT_TEST=$(scale_timeout 300)

# -- App verification ----------------------------------------------------------

app_verify() {
    local app="$1" ct_name="$2"
    case "$app" in
        nginx-unprivileged)
            # Curl the marker file via exec --oci (enters net namespace).
            local body
            body=$(timeout 10 sdme exec --oci -- "$ct_name" \
                curl -s http://127.0.0.1:8080/sdme-test.txt 2>&1) || true
            if [[ "$body" == *"$NGINX_MARKER"* ]]; then
                return 0
            else
                local code
                code=$(timeout 10 sdme exec --oci -- "$ct_name" \
                    curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/sdme-test.txt 2>&1) || true
                echo "HTTP $code"
                return 1
            fi
            ;;
        postgresql)
            timeout 10 sdme exec --oci -- "$ct_name" \
                /bin/sh -c 'pg_isready -h 127.0.0.1 -p 5432' 2>&1
            ;;
        redis)
            local reply
            reply=$(timeout 10 sdme exec --oci -- "$ct_name" \
                /usr/local/bin/redis-cli ping 2>&1) || true
            if [[ "$reply" == *"PONG"* ]]; then
                return 0
            else
                echo "$reply"
                return 1
            fi
            ;;
    esac
}

# -- Argument parsing ----------------------------------------------------------

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

End-to-end verification of distro x OCI app matrix.
Must be run as root.

Options:
  --distro NAME    Only test this distro (repeatable)
  --app NAME       Only test this app (repeatable)
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

log() { echo "==> $*"; }

cleanup() { cleanup_prefix vfy-doci-; }

trap cleanup EXIT INT TERM

# -- Phase 1: Import base OS rootfs --------------------------------------------

phase1_import() {
    log "Phase 1: Import base OS rootfs"
    for distro in "${DISTROS[@]}"; do
        local fs_name="vfy-doci-$distro"
        local image="${DISTRO_IMAGES[$distro]}"
        if fs_exists "$fs_name"; then
            log "  $fs_name already exists, skipping import"
            record "import/$distro" PASS "exists"
            continue
        fi
        log "  Importing $fs_name from $image"
        local output
        if output=$(timeout "$TIMEOUT_IMPORT" sdme fs import "$fs_name" "$image" -v --install-packages=yes -f 2>&1); then
            record "import/$distro" PASS
        else
            record "import/$distro" FAIL "$output"
        fi
    done
}

# -- Phase 2: OCI app matrix ---------------------------------------------------

phase2_apps() {
    log "Phase 2: OCI app matrix"
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
            local fs_name="vfy-doci-$app-on-$distro"
            local ct_name="vfy-doci-app-$app-on-$distro"
            local image="${APP_IMAGES[$app]}"
            local base_fs="vfy-doci-$distro"

            log "  Testing $app on $distro"

            # Import app
            local output
            if fs_exists "$fs_name"; then
                log "    $fs_name already exists, skipping import"
                record "app/$app-on-$distro/import" PASS "exists"
            elif output=$(timeout "$TIMEOUT_IMPORT" sdme fs import "$fs_name" "$image" \
                    --base-fs="$base_fs" --oci-mode=app -v --install-packages=yes -f 2>&1); then
                record "app/$app-on-$distro/import" PASS
            else
                record "app/$app-on-$distro/import" FAIL "$output"
                record "app/$app-on-$distro/boot" SKIP "import failed"
                record "app/$app-on-$distro/service" SKIP "import failed"
                record "app/$app-on-$distro/logs" SKIP "import failed"
                record "app/$app-on-$distro/status" SKIP "import failed"
                record "app/$app-on-$distro/verify" SKIP "import failed"
                continue
            fi

            # Build create args: private network + veth so no host port binding.
            # --no-oci-ports prevents auto port forwarding to the host.
            local create_args=(-r "$fs_name" --private-network --network-veth --no-oci-ports)
            case "$app" in
                postgresql) create_args+=(--oci-env "POSTGRES_PASSWORD=secret") ;;
            esac

            # Create
            if ! output=$(timeout "$TIMEOUT_BOOT" sdme create "${create_args[@]}" "$ct_name" 2>&1); then
                record "app/$app-on-$distro/boot" FAIL "create failed: $output"
                record "app/$app-on-$distro/service" SKIP "create failed"
                record "app/$app-on-$distro/logs" SKIP "create failed"
                record "app/$app-on-$distro/status" SKIP "create failed"
                record "app/$app-on-$distro/verify" SKIP "create failed"
                continue
            fi

            # Write nginx test file into the overlayfs upper layer before
            # start so the marker is present when nginx boots.
            if [[ "$app" == "nginx-unprivileged" ]]; then
                local html_dir="$DATADIR/containers/$ct_name/upper/oci/apps/$app/root/usr/share/nginx/html"
                mkdir -p "$html_dir"
                echo "$NGINX_MARKER" > "$html_dir/sdme-test.txt"
            fi

            # Work around Redis 8.x ARM64-COW-BUG test failure in containers.
            if [[ "$app" == "redis" ]]; then
                fix_redis_oci "$ct_name" "$distro"
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
            local svc_name systemctl
            svc_name=$(oci_service_name "$image")
            systemctl=$(distro_bin "$distro" systemctl)
            if output=$(timeout "$TIMEOUT_TEST" sdme exec "$ct_name" \
                    "$systemctl" is-active "$svc_name" 2>&1); then
                record "app/$app-on-$distro/service" PASS
            else
                record "app/$app-on-$distro/service" FAIL "$output"
            fi

            # Logs
            if output=$(timeout "$TIMEOUT_TEST" sdme logs --oci -- "$ct_name" --no-pager -n 10 2>&1); then
                record "app/$app-on-$distro/logs" PASS
            else
                record "app/$app-on-$distro/logs" FAIL "$output"
            fi

            # Status
            if output=$(timeout "$TIMEOUT_TEST" sdme exec "$ct_name" \
                    "$systemctl" status "$svc_name" --no-pager 2>&1); then
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

            # Cleanup container (rootfs kept for Phase 3 hardened tests)
            stop_container "$ct_name"
            sdme rm -f "$ct_name" 2>/dev/null || true
        done
    done
}

# -- Phase 3: Hardened OCI app matrix ------------------------------------------

phase3_hardened_apps() {
    log "Phase 3: Hardened OCI app matrix"
    for distro in "${DISTROS[@]}"; do
        if [[ "$(result_status "import/$distro")" != "PASS" ]]; then
            for app in "${APPS[@]}"; do
                record "hardened-app/$app-on-$distro/boot" SKIP "base import failed"
                record "hardened-app/$app-on-$distro/service" SKIP "base import failed"
            done
            continue
        fi

        for app in "${APPS[@]}"; do
            local fs_name="vfy-doci-$app-on-$distro"
            local ct_name="vfy-doci-h-app-$app-on-$distro"

            # The rootfs must already exist from Phase 2.
            if [[ "$(result_status "app/$app-on-$distro/import")" != "PASS" ]]; then
                record "hardened-app/$app-on-$distro/boot" SKIP "app import failed"
                record "hardened-app/$app-on-$distro/service" SKIP "app import failed"
                continue
            fi

            # Check rootfs still exists from Phase 2.
            if ! fs_exists "$fs_name"; then
                record "hardened-app/$app-on-$distro/boot" SKIP "rootfs removed"
                record "hardened-app/$app-on-$distro/service" SKIP "rootfs removed"
                continue
            fi

            log "  Hardened testing $app on $distro"

            # Build create args with OCI env vars
            local create_args=(-r "$fs_name" --hardened)
            case "$app" in
                postgresql) create_args+=(--oci-env "POSTGRES_PASSWORD=secret") ;;
            esac

            # Create with --hardened
            local output
            if ! output=$(timeout "$TIMEOUT_BOOT" sdme create "${create_args[@]}" "$ct_name" 2>&1); then
                record "hardened-app/$app-on-$distro/boot" FAIL "create failed: $output"
                record "hardened-app/$app-on-$distro/service" SKIP "create failed"
                continue
            fi

            # Work around Redis 8.x ARM64-COW-BUG test failure in containers.
            if [[ "$app" == "redis" ]]; then
                fix_redis_oci "$ct_name" "$distro"
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
            local svc_name systemctl
            svc_name=$(oci_service_name "${APP_IMAGES[$app]}")
            systemctl=$(distro_bin "$distro" systemctl)
            if output=$(timeout "$TIMEOUT_TEST" sdme exec "$ct_name" \
                    "$systemctl" is-active "$svc_name" 2>&1); then
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

# -- Report generation ---------------------------------------------------------

generate_report() {
    local ts
    ts=$(date +%Y%m%d-%H%M%S)
    local report="$REPORT_DIR/verify-distro-oci-$ts.md"

    log "Writing report to $report"

    mkdir -p "$REPORT_DIR"

    {
        echo "# sdme Distro OCI App Verification Report"
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
        sdme_ver=$(sed -n 's/^version = "\(.*\)"/\1/p' "$REPO_ROOT/Cargo.toml" 2>/dev/null || echo unknown)
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

        # Import table
        echo "## Base OS Import"
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

        # OCI app matrix table
        echo "## OCI App Matrix"
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

        # Hardened OCI app matrix table
        echo "## Hardened OCI App Matrix"
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
    ensure_root
    ensure_sdme
    require_gate smoke
    require_gate interrupt

    echo "Distro OCI verification: ${#DISTROS[@]} distros x ${#APPS[@]} apps"
    echo "Distros: ${DISTROS[*]}"
    echo "Apps:    ${APPS[*]}"
    echo ""

    phase1_import
    phase2_apps
    phase3_hardened_apps
    generate_report

    echo ""
    echo "Results: $_pass passed, $_fail failed, $_skip skipped"

    if [[ $_fail -gt 0 ]]; then
        exit 1
    fi
}

main "$@"
