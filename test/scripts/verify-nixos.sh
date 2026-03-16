#!/usr/bin/env bash
set -uo pipefail

# verify-nixos.sh - end-to-end verification of NixOS rootfs import, container boot,
# OCI nginx-unprivileged on a NixOS base, and Kubernetes Pod YAML.
#
# Run as root. Imports NixOS rootfs via docker.io/nixos/nix (no local nix required).
# Uses vfy-nix- prefix for all artifacts.
#
# Phases:
#   1. Import NixOS rootfs via docker.io/nixos/nix --install-packages=yes
#   2. Boot a plain NixOS container and verify it's running
#   3. Import nginx-unprivileged OCI app on the NixOS base
#   4. Create, boot, and test the OCI app container
#   5. Apply a single-container Kubernetes Pod YAML on the NixOS base
#   6. Apply a multi-service Kubernetes Pod (nginx + redis + mysql)
#   7. Cleanup
#
# NixOS note: OCI app unit files are placed in /etc/systemd/system.control/
# instead of /etc/systemd/system/ because NixOS activation replaces the
# latter with an immutable symlink to the Nix store.

source "$(dirname "$0")/lib.sh"

FS_NAME="vfy-nix-nixos"
CT_PLAIN="vfy-nix-plain"
CT_OCI="vfy-nix-oci"
CT_KUBE="vfy-nix-kube"
CT_KUBE_MULTI="vfy-nix-kube-multi"

APP_IMAGE="quay.io/nginx/nginx-unprivileged"
APP_FS="vfy-nix-nginx"
APP_PORT=8080
VOLUME_PATH="/usr/share/nginx/html"
TEST_MARKER="sdme-nixos-test"

DATADIR="/var/lib/sdme"
REPORT_DIR="."

# NixOS binaries are under /run/current-system/sw/bin.
NIXOS_BIN="/run/current-system/sw/bin"

# Timeouts (seconds)
TIMEOUT_IMPORT=900
TIMEOUT_BOOT=120
TIMEOUT_TEST=60

# Result tracking
declare -A RESULTS

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

End-to-end verification of NixOS rootfs import, container boot, and OCI app.
Must be run as root. Imports NixOS via docker.io/nixos/nix (no local nix required).

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

    # Delete kube containers first (removes both container and kube rootfs).
    sdme kube delete "$CT_KUBE_MULTI" 2>/dev/null || true
    sdme kube delete "$CT_KUBE" 2>/dev/null || true

    # Stop and remove remaining containers.
    local names
    names=$(sdme ps 2>/dev/null | awk 'NR>1 {print $1}' | grep '^vfy-nix-' || true)
    for name in $names; do
        stop_container "$name"
        sdme rm -f "$name" 2>/dev/null || true
    done

    # Remove rootfs (including kube- prefixed rootfs for kube containers).
    names=$(sdme fs ls 2>/dev/null | awk 'NR>1 {print $1}' | grep -E '^(vfy-nix-|kube-vfy-nix-)' || true)
    for name in $names; do
        sdme fs rm "$name" 2>/dev/null || true
    done
}

trap cleanup EXIT INT TERM

# -- Phase 1: Import NixOS rootfs ----------------------------------------------

phase1_import() {
    log "Phase 1: Import NixOS rootfs via docker.io/nixos/nix"

    if fs_exists "$FS_NAME"; then
        log "  $FS_NAME already exists, skipping import"
        record "import" PASS "exists"
        return
    fi

    local output
    if output=$(timeout "$TIMEOUT_IMPORT" sdme fs import "$FS_NAME" docker.io/nixos/nix \
            -v --install-packages=yes -f 2>&1); then
        record "import" PASS
    else
        record "import" FAIL "$output"
    fi
}

# -- Phase 2: Boot plain NixOS container ----------------------------------------

phase2_boot_plain() {
    log "Phase 2: Boot plain NixOS container"

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
    if output=$(timeout "$TIMEOUT_TEST" sdme exec "$CT_PLAIN" "$NIXOS_BIN/uname" -a 2>&1); then
        record "plain/exec" PASS "$output"
    else
        record "plain/exec" FAIL "$output"
    fi

    stop_container "$CT_PLAIN"
    sdme rm -f "$CT_PLAIN" 2>/dev/null || true
}

# -- Phase 3: Import nginx-unprivileged OCI app ---------------------------------

phase3_import_oci() {
    log "Phase 3: Import nginx-unprivileged OCI app on NixOS base"

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

# -- Phase 4: Create, boot, and test OCI app container --------------------------

phase4_test_oci() {
    log "Phase 4: Test OCI nginx-unprivileged on NixOS"

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
            "$NIXOS_BIN/systemctl" is-active sdme-oci-nginx-unprivileged.service 2>&1); then
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

# -- Phase 5: Kubernetes Pod YAML on NixOS base --------------------------------

phase5_test_kube() {
    log "Phase 5: Test Kubernetes Pod YAML on NixOS base"

    if [[ "$(result_status import)" != "PASS" ]]; then
        record "kube/create" SKIP "base import failed"
        record "kube/boot" SKIP "base import failed"
        record "kube/service" SKIP "base import failed"
        record "kube/curl-port" SKIP "base import failed"
        record "kube/delete" SKIP "base import failed"
        return
    fi

    # Write a minimal Pod YAML with nginx-unprivileged.
    local yaml
    yaml=$(mktemp /tmp/vfy-nix-kube-XXXXXX.yaml)
    cat > "$yaml" <<'YAMLEOF'
apiVersion: v1
kind: Pod
metadata:
  name: vfy-nix-kube
spec:
  containers:
  - name: nginx-unprivileged
    image: quay.io/nginx/nginx-unprivileged
    ports:
    - containerPort: 8080
YAMLEOF

    # Create the kube container (no start).
    local output
    if ! output=$(timeout "$TIMEOUT_BOOT" sdme kube create -f "$yaml" --base-fs "$FS_NAME" -v 2>&1); then
        record "kube/create" FAIL "$output"
        record "kube/boot" SKIP "create failed"
        record "kube/service" SKIP "create failed"
        record "kube/curl-port" SKIP "create failed"
        record "kube/delete" SKIP "create failed"
        rm -f "$yaml"
        sdme kube delete "$CT_KUBE" 2>/dev/null || true
        return
    fi
    record "kube/create" PASS
    rm -f "$yaml"

    # Start the container.
    if ! output=$(timeout "$TIMEOUT_BOOT" sdme start "$CT_KUBE" -t 120 2>&1); then
        record "kube/boot" FAIL "start failed: $output"
        record "kube/service" SKIP "start failed"
        record "kube/curl-port" SKIP "start failed"
        record "kube/delete" SKIP "start failed"
        sdme kube delete "$CT_KUBE" 2>/dev/null || true
        return
    fi
    record "kube/boot" PASS

    # Check the OCI app service inside the container.
    if output=$(timeout "$TIMEOUT_TEST" sdme exec "$CT_KUBE" \
            "$NIXOS_BIN/systemctl" is-active sdme-oci-nginx-unprivileged.service 2>&1); then
        record "kube/service" PASS
    else
        record "kube/service" FAIL "$output"
    fi

    # Curl nginx from inside the container's network namespace.
    sleep 3
    local leader
    leader=$(machinectl show "$CT_KUBE" -p Leader --value 2>/dev/null) || true
    if [[ -n "$leader" ]] && [[ -d "/proc/$leader" ]]; then
        local http_code
        http_code=$(timeout 10 nsenter -t "$leader" -n curl -s -o /dev/null -w '%{http_code}' \
            "http://127.0.0.1:${APP_PORT}" 2>&1) || true
        if [[ "$http_code" == "200" ]]; then
            record "kube/curl-port" PASS "HTTP $http_code via nsenter localhost"
        else
            record "kube/curl-port" FAIL "HTTP $http_code via nsenter localhost"
        fi
    else
        record "kube/curl-port" FAIL "could not find container leader PID"
    fi

    # Delete the kube container.
    if output=$(timeout "$TIMEOUT_TEST" sdme kube delete "$CT_KUBE" 2>&1); then
        record "kube/delete" PASS
    else
        record "kube/delete" FAIL "$output"
    fi
}

# -- Phase 6: Multi-service kube pod (nginx + redis + mysql) -------------------

phase6_test_kube_multi() {
    log "Phase 6: Multi-service Kubernetes Pod on NixOS (nginx + redis + mysql)"

    if [[ "$(result_status import)" != "PASS" ]]; then
        record "kube-multi/create" SKIP "base import failed"
        record "kube-multi/boot" SKIP "base import failed"
        record "kube-multi/service-nginx" SKIP "base import failed"
        record "kube-multi/service-redis" SKIP "base import failed"
        record "kube-multi/service-mysql" SKIP "base import failed"
        record "kube-multi/redis-ping" SKIP "base import failed"
        record "kube-multi/nginx-http" SKIP "base import failed"
        record "kube-multi/mysql-connect" SKIP "base import failed"
        record "kube-multi/delete" SKIP "base import failed"
        return
    fi

    # Write a multi-service Pod YAML (the README example with LANG fix for redis 8).
    local yaml
    yaml=$(mktemp /tmp/vfy-nix-kube-multi-XXXXXX.yaml)
    cat > "$yaml" <<'YAMLEOF'
apiVersion: v1
kind: Pod
metadata:
  name: vfy-nix-kube-multi
spec:
  containers:
  - name: nginx
    image: docker.io/nginx:latest
    ports:
    - containerPort: 80
  - name: redis
    image: docker.io/redis:latest
    env:
    - name: LANG
      value: C.UTF-8
  - name: mysql
    image: docker.io/mysql:latest
    env:
    - name: MYSQL_ROOT_PASSWORD
      value: secret
YAMLEOF

    # Create
    local output
    if ! output=$(timeout "$TIMEOUT_BOOT" sdme kube create -f "$yaml" --base-fs "$FS_NAME" -v 2>&1); then
        record "kube-multi/create" FAIL "$output"
        record "kube-multi/boot" SKIP "create failed"
        record "kube-multi/service-nginx" SKIP "create failed"
        record "kube-multi/service-redis" SKIP "create failed"
        record "kube-multi/service-mysql" SKIP "create failed"
        record "kube-multi/redis-ping" SKIP "create failed"
        record "kube-multi/nginx-http" SKIP "create failed"
        record "kube-multi/mysql-connect" SKIP "create failed"
        record "kube-multi/delete" SKIP "create failed"
        rm -f "$yaml"
        sdme kube delete "$CT_KUBE_MULTI" 2>/dev/null || true
        return
    fi
    record "kube-multi/create" PASS
    rm -f "$yaml"

    # Start
    if ! output=$(timeout "$TIMEOUT_BOOT" sdme start "$CT_KUBE_MULTI" -t 120 2>&1); then
        record "kube-multi/boot" FAIL "start failed: $output"
        record "kube-multi/service-nginx" SKIP "start failed"
        record "kube-multi/service-redis" SKIP "start failed"
        record "kube-multi/service-mysql" SKIP "start failed"
        record "kube-multi/redis-ping" SKIP "start failed"
        record "kube-multi/nginx-http" SKIP "start failed"
        record "kube-multi/mysql-connect" SKIP "start failed"
        record "kube-multi/delete" SKIP "start failed"
        sdme kube delete "$CT_KUBE_MULTI" 2>/dev/null || true
        return
    fi
    record "kube-multi/boot" PASS

    # Wait for services to settle
    sleep 15

    # Check all three OCI app services
    for svc in nginx redis mysql; do
        local test_key="kube-multi/service-$svc"
        if output=$(timeout "$TIMEOUT_TEST" sdme exec "$CT_KUBE_MULTI" \
                "$NIXOS_BIN/systemctl" is-active "sdme-oci-${svc}.service" 2>&1) && \
           [[ "$output" == *"active"* ]]; then
            record "$test_key" PASS
        else
            record "$test_key" FAIL "$output"
        fi
    done

    # Redis PING/PONG
    local ping_out
    ping_out=$(timeout "$TIMEOUT_TEST" sdme exec "$CT_KUBE_MULTI" \
        "$NIXOS_BIN/bash" -c "echo PING | $NIXOS_BIN/nc -w2 127.0.0.1 6379" 2>&1) || true
    if [[ "$ping_out" == *"+PONG"* ]]; then
        record "kube-multi/redis-ping" PASS
    else
        record "kube-multi/redis-ping" FAIL "$ping_out"
    fi

    # Nginx HTTP via nsenter
    local leader
    leader=$(machinectl show "$CT_KUBE_MULTI" -p Leader --value 2>/dev/null) || true
    if [[ -n "$leader" ]] && [[ -d "/proc/$leader" ]]; then
        local http_code
        http_code=$(timeout 10 nsenter -t "$leader" -n curl -s -o /dev/null -w '%{http_code}' \
            "http://127.0.0.1:80" 2>&1) || true
        if [[ "$http_code" == "200" ]]; then
            record "kube-multi/nginx-http" PASS "HTTP $http_code"
        else
            record "kube-multi/nginx-http" FAIL "HTTP $http_code"
        fi
    else
        record "kube-multi/nginx-http" FAIL "could not find container leader PID"
    fi

    # MySQL TCP connect
    local mysql_out
    mysql_out=$(timeout "$TIMEOUT_TEST" sdme exec "$CT_KUBE_MULTI" \
        "$NIXOS_BIN/bash" -c "echo '' | $NIXOS_BIN/nc -w2 127.0.0.1 3306 | head -c1 | wc -c" 2>&1) || true
    if [[ "$mysql_out" == *"1"* ]]; then
        record "kube-multi/mysql-connect" PASS "port 3306 responded"
    else
        record "kube-multi/mysql-connect" FAIL "$mysql_out"
    fi

    # Delete
    if output=$(timeout "$TIMEOUT_TEST" sdme kube delete "$CT_KUBE_MULTI" 2>&1); then
        record "kube-multi/delete" PASS
    else
        record "kube-multi/delete" FAIL "$output"
    fi
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
        for key in import plain/create plain/boot plain/exec \
                   oci/import oci/create oci/state-ports oci/volume-dir \
                   oci/boot oci/service oci/logs oci/curl-port oci/curl-content \
                   kube/create kube/boot kube/service kube/curl-port kube/delete \
                   kube-multi/create kube-multi/boot \
                   kube-multi/service-nginx kube-multi/service-redis kube-multi/service-mysql \
                   kube-multi/redis-ping kube-multi/nginx-http kube-multi/mysql-connect \
                   kube-multi/delete; do
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

    echo "NixOS verification: import, boot, OCI nginx, kube, multi-service kube"
    echo ""

    phase1_import
    phase2_boot_plain
    phase3_import_oci
    phase4_test_oci
    phase5_test_kube
    phase6_test_kube_multi
    generate_report

    print_summary
}

main "$@"
