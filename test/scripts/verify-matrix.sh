#!/usr/bin/env bash
set -uo pipefail

# verify-matrix.sh - end-to-end verification of distro x OCI app matrix
# Run as root. Uses vfy- prefix for all artifacts.

source "$(dirname "$0")/lib.sh"

DISTROS=(debian ubuntu fedora centos almalinux archlinux opensuse)
APPS=(nginx-unprivileged redis postgresql)

declare -A DISTRO_IMAGES=(
    [debian]="docker.io/debian:stable"
    [ubuntu]="docker.io/ubuntu:24.04"
    [fedora]="quay.io/fedora/fedora:41"
    [centos]="quay.io/centos/centos:stream10"
    [almalinux]="quay.io/almalinuxorg/almalinux:9"
    [archlinux]="docker.io/lopsided/archlinux:latest"
    [opensuse]="registry.opensuse.org/opensuse/tumbleweed:latest"
)

declare -A APP_IMAGES=(
    [nginx-unprivileged]="docker.io/nginxinc/nginx-unprivileged"
    [redis]="docker.io/redis"
    [postgresql]="docker.io/postgres"
)

# Expected substring in the OS column of `sdme ps` for each distro.
declare -A DISTRO_OS_PATTERN=(
    [debian]="Debian"
    [ubuntu]="Ubuntu"
    [fedora]="Fedora"
    [centos]="CentOS"
    [almalinux]="AlmaLinux"
    [archlinux]="Arch Linux"
    [opensuse]="openSUSE Tumbleweed"
)

declare -A APP_READY_WAIT=(
    [nginx-unprivileged]=3
    [redis]=3
    [postgresql]=10
)

NGINX_MARKER="sdme-matrix-test-$$"
DATADIR="/var/lib/sdme"
REPORT_DIR="."
FILTER_DISTROS=()
FILTER_APPS=()

# Redis 8.x workarounds for container environments:
# - ARM64: tests for a kernel COW bug, fails inside containers, and exits.
#   Suppress with --ignore-warnings ARM64-COW-BUG.
# - Locale: redis treats locale config failure as fatal. The OCI root may
#   lack the host container's locale (e.g. en_US.UTF-8 on archlinux).
#   Force LANG=C.UTF-8 which is universally available.
fix_redis_oci() {
    local ct_name="$1"
    local svc_dir="$DATADIR/containers/$ct_name/upper/etc/systemd/system/sdme-oci-redis.service.d"
    mkdir -p "$svc_dir"
    local extra_args=""
    if [[ "$(uname -m)" == "aarch64" ]]; then
        extra_args=" --ignore-warnings ARM64-COW-BUG"
    fi
    cat > "$svc_dir/workarounds.conf" <<DROPIN
[Service]
Environment=LANG=C.UTF-8
ExecStart=
ExecStart=/.sdme-isolate 0 0 /data /usr/local/bin/docker-entrypoint.sh redis-server${extra_args}
DROPIN
}

# Check that `sdme ps` shows the expected OS pattern for a container.
#   check_os <container_name> <distro>
# Returns 0 on match, 1 on mismatch. On mismatch, prints the actual OS value.
check_os() {
    local ct_name="$1" distro="$2"
    local pattern="${DISTRO_OS_PATTERN[$distro]}"
    local os_col
    os_col=$($SDME ps 2>/dev/null | awk -v name="$ct_name" '$1 == name {
        # OS is the 4th column — but it may contain spaces (e.g. "Arch Linux").
        # Columns 1-3 are single-word (NAME, STATUS, HEALTH). Print from field 4
        # to the end, then strip trailing columns that start with known suffixes.
        for (i=4; i<=NF; i++) printf "%s ", $i
        printf "\n"
    }')
    # Trim trailing whitespace.
    os_col="${os_col%"${os_col##*[![:space:]]}"}"
    if [[ "$os_col" == *"$pattern"* ]]; then
        return 0
    else
        echo "$os_col"
        return 1
    fi
}

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

cleanup() { cleanup_prefix vfy-; }

trap cleanup EXIT INT TERM

# -- Phase 1: Import base OS rootfs --------------------------------------------

phase1_import() {
    log "Phase 1: Import base OS rootfs"
    for distro in "${DISTROS[@]}"; do
        local fs_name="vfy-$distro"
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
            record "boot/$distro/os-running" SKIP "base import failed"
            record "boot/$distro/os-stopped" SKIP "base import failed"
            continue
        fi

        log "  Boot testing $ct_name"

        # Create
        local output
        if ! output=$(timeout "$TIMEOUT_BOOT" sdme create -r "$fs_name" "$ct_name" 2>&1); then
            record "boot/$distro/create" FAIL "$output"
            record "boot/$distro/systemd" SKIP "create failed"
            record "boot/$distro/journalctl" SKIP "create failed"
            record "boot/$distro/systemctl" SKIP "create failed"
            record "boot/$distro/os-running" SKIP "create failed"
            record "boot/$distro/os-stopped" SKIP "create failed"
            continue
        fi
        record "boot/$distro/create" PASS

        # Start
        if ! output=$(timeout "$TIMEOUT_BOOT" sdme start "$ct_name" -t 120 2>&1); then
            record "boot/$distro/systemd" FAIL "start failed: $output"
            record "boot/$distro/journalctl" SKIP "start failed"
            record "boot/$distro/systemctl" SKIP "start failed"
            record "boot/$distro/os-running" SKIP "start failed"
            record "boot/$distro/os-stopped" SKIP "start failed"
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

        # OS detection (running)
        if output=$(check_os "$ct_name" "$distro"); then
            record "boot/$distro/os-running" PASS
        else
            record "boot/$distro/os-running" FAIL "expected *${DISTRO_OS_PATTERN[$distro]}*, got: $output"
        fi

        # Cleanup
        stop_container "$ct_name"

        # OS detection (stopped)
        if output=$(check_os "$ct_name" "$distro"); then
            record "boot/$distro/os-stopped" PASS
        else
            record "boot/$distro/os-stopped" FAIL "expected *${DISTRO_OS_PATTERN[$distro]}*, got: $output"
        fi

        sdme rm -f "$ct_name" 2>/dev/null || true
    done
}

# -- Phase 3: OCI app matrix ---------------------------------------------------

app_verify() {
    local app="$1" ct_name="$2"
    case "$app" in
        nginx-unprivileged)
            # Curl the marker file written into the upper layer before start.
            local body
            body=$(timeout 10 curl -s http://localhost:8080/sdme-test.txt 2>&1) || true
            if [[ "$body" == *"$NGINX_MARKER"* ]]; then
                return 0
            else
                local code
                code=$(timeout 10 curl -s -o /dev/null -w '%{http_code}' http://localhost:8080/sdme-test.txt 2>&1) || true
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

            # Skip nginx if port 8080 is already in use (host-network containers
            # share ports with the host; a conflicting listener causes silent
            # bind failures inside the container).
            if [[ "$app" == "nginx-unprivileged" ]] && ss -tlnH '( sport = :8080 )' | grep -q .; then
                local blocker
                blocker=$(ss -tlnp '( sport = :8080 )' | tail -1)
                record "app/$app-on-$distro/boot" SKIP "port 8080 in use: $blocker"
                record "app/$app-on-$distro/service" SKIP "port 8080 in use"
                record "app/$app-on-$distro/logs" SKIP "port 8080 in use"
                record "app/$app-on-$distro/status" SKIP "port 8080 in use"
                record "app/$app-on-$distro/verify" SKIP "port 8080 in use"
                continue
            fi

            # Build create args with OCI env vars
            local create_args=(-r "$fs_name")
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
            # start so the marker is present when nginx boots. This avoids
            # depending on the default welcome page which varies by distro.
            if [[ "$app" == "nginx-unprivileged" ]]; then
                local html_dir="$DATADIR/containers/$ct_name/upper/oci/apps/$app/root/usr/share/nginx/html"
                mkdir -p "$html_dir"
                echo "$NGINX_MARKER" > "$html_dir/sdme-test.txt"
            fi

            # Work around Redis 8.x ARM64-COW-BUG test failure in containers.
            if [[ "$app" == "redis" ]]; then
                fix_redis_oci "$ct_name"
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
            local svc_name
            svc_name=$(oci_service_name "$image")
            if output=$(timeout "$TIMEOUT_TEST" sdme exec "$ct_name" \
                    /usr/bin/systemctl is-active "$svc_name" 2>&1); then
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
                    /usr/bin/systemctl status "$svc_name" --no-pager 2>&1); then
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
            record "hardened-boot/$distro/systemd" SKIP "create failed"
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

            # Check rootfs still exists from Phase 3.
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
                fix_redis_oci "$ct_name"
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
            local svc_name
            svc_name=$(oci_service_name "${APP_IMAGES[$app]}")
            if output=$(timeout "$TIMEOUT_TEST" sdme exec "$ct_name" \
                    /usr/bin/systemctl is-active "$svc_name" 2>&1); then
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
        echo "| Distro | Create | systemd | journalctl | systemctl | OS (running) | OS (stopped) |"
        echo "|--------|--------|---------|------------|-----------|--------------|--------------|"
        for distro in "${DISTROS[@]}"; do
            local c s j u or os
            c=$(result_status "boot/$distro/create")
            s=$(result_status "boot/$distro/systemd")
            j=$(result_status "boot/$distro/journalctl")
            u=$(result_status "boot/$distro/systemctl")
            or=$(result_status "boot/$distro/os-running")
            os=$(result_status "boot/$distro/os-stopped")
            echo "| $distro | $c | $s | $j | $u | $or | $os |"
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
    ensure_root
    ensure_sdme

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
