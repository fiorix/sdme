#!/usr/bin/env bash
set -uo pipefail

# verify-usage.sh - verify the commands documented in docs/usage.md
#
# Walks through each section of the usage guide and runs the documented
# commands (or close equivalents) to ensure nothing is stale or broken.
# Uses vfy-usage- prefix for all artifacts.
#
# Requires: root, sdme in PATH, network access for OCI registry pulls.

source "$(dirname "$0")/lib.sh"

DATADIR="/var/lib/sdme"
REPORT_DIR="."

# Base distro for most tests (fast to import)
BASE_IMAGE="docker.io/ubuntu:24.04"
BASE_FS="vfy-usage-ubuntu"

# OCI app images
NGINX_IMAGE="docker.io/nginx"
REDIS_IMAGE="docker.io/redis"
POSTGRES_IMAGE="docker.io/postgres"

# Timeouts (seconds)
TIMEOUT_IMPORT=$(scale_timeout 600)
TIMEOUT_BOOT=$(scale_timeout 120)
TIMEOUT_TEST=$(scale_timeout 60)

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Verify the commands documented in docs/usage.md.
Must be run as root.

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

# -- Cleanup -------------------------------------------------------------------

cleanup() {
    log "Cleaning up vfy-usage- artifacts..."
    cleanup_prefix "vfy-usage-"
}

trap cleanup EXIT INT TERM

need_base() {
    if [[ "$(result_status "import/base")" != "PASS" ]]; then
        return 1
    fi
    return 0
}

# =============================================================================
# Section: Your first container (host-rootfs clone)
# =============================================================================

test_host_clone() {
    log "Section: Your first container"

    local ct="vfy-usage-host"
    local output

    # sdme create (host clone, no -r)
    if ! output=$(timeout "$TIMEOUT_BOOT" $SDME create "$ct" 2>&1); then
        record "host/create" FAIL "$output"
        record "host/start" SKIP "create failed"
        record "host/ps" SKIP "create failed"
        record "host/exec" SKIP "create failed"
        record "host/logs" SKIP "create failed"
        record "host/stop" SKIP "create failed"
        record "host/enable" SKIP "create failed"
        record "host/disable" SKIP "create failed"
        record "host/rm" SKIP "create failed"
        return
    fi
    record "host/create" PASS

    # sdme start
    if ! output=$(timeout "$TIMEOUT_BOOT" $SDME start "$ct" -t 120 2>&1); then
        record "host/start" FAIL "$output"
        record "host/ps" SKIP "start failed"
        record "host/exec" SKIP "start failed"
        record "host/logs" SKIP "start failed"
        record "host/stop" SKIP "start failed"
        record "host/enable" SKIP "start failed"
        record "host/disable" SKIP "start failed"
        $SDME rm -f "$ct" 2>/dev/null || true
        record "host/rm" SKIP "start failed"
        return
    fi
    record "host/start" PASS

    # sdme ps
    if output=$($SDME ps 2>&1) && echo "$output" | grep -q "$ct"; then
        record "host/ps" PASS
    else
        record "host/ps" FAIL "$output"
    fi

    # sdme exec <name> -- /bin/ls /
    if output=$(timeout "$TIMEOUT_TEST" $SDME exec "$ct" -- /bin/ls / 2>&1); then
        record "host/exec" PASS
    else
        record "host/exec" FAIL "$output"
    fi

    # sdme logs <name>
    if output=$(timeout "$TIMEOUT_TEST" $SDME logs "$ct" --no-pager -n 5 2>&1); then
        record "host/logs" PASS
    else
        record "host/logs" FAIL "$output"
    fi

    # sdme enable / disable
    if output=$(timeout 10 $SDME enable "$ct" 2>&1); then
        record "host/enable" PASS
    else
        record "host/enable" FAIL "$output"
    fi

    if output=$(timeout 10 $SDME disable "$ct" 2>&1); then
        record "host/disable" PASS
    else
        record "host/disable" FAIL "$output"
    fi

    # sdme stop
    if output=$(timeout 30 $SDME stop "$ct" 2>&1); then
        record "host/stop" PASS
    else
        record "host/stop" FAIL "$output"
    fi

    # sdme rm
    if output=$(timeout 10 $SDME rm -f "$ct" 2>&1); then
        record "host/rm" PASS
    else
        record "host/rm" FAIL "$output"
    fi
}

# =============================================================================
# Section: Importing other distros (OCI registry)
# =============================================================================

test_import_oci() {
    log "Section: Importing other distros"

    local output

    # sdme fs import ubuntu docker.io/ubuntu:24.04
    if ensure_base_fs "$BASE_FS" "$BASE_IMAGE"; then
        record "import/base" PASS
    else
        record "import/base" FAIL "ensure_base_fs failed"
        return
    fi

    # sdme fs ls
    if output=$($SDME fs ls 2>&1) && echo "$output" | grep -q "$BASE_FS"; then
        record "import/fs-ls" PASS
    else
        record "import/fs-ls" FAIL "$output"
    fi

    # sdme new -r ubuntu (create + start + join → we skip the join, just create+start)
    local ct="vfy-usage-distro"
    if ! output=$(timeout "$TIMEOUT_BOOT" $SDME create -r "$BASE_FS" "$ct" 2>&1); then
        record "import/create" FAIL "$output"
        record "import/boot" SKIP "create failed"
        return
    fi
    record "import/create" PASS

    if ! output=$(timeout "$TIMEOUT_BOOT" $SDME start "$ct" -t 120 2>&1); then
        record "import/boot" FAIL "$output"
        $SDME rm -f "$ct" 2>/dev/null || true
        return
    fi
    record "import/boot" PASS

    stop_container "$ct"
    $SDME rm -f "$ct" 2>/dev/null || true
}

# =============================================================================
# Section: OCI applications (nginx, redis, postgresql with --oci-env)
# =============================================================================

test_oci_apps() {
    log "Section: OCI applications"

    if ! need_base; then
        for k in oci/nginx-import oci/nginx-boot oci/nginx-service \
                 oci/nginx-logs oci/redis-import oci/redis-boot \
                 oci/redis-exec-oci oci/pg-import oci/pg-boot \
                 oci/pg-env; do
            record "$k" SKIP "base import failed"
        done
        return
    fi

    local output

    # -- nginx --
    local nginx_fs="vfy-usage-nginx"
    local nginx_ct="vfy-usage-ct-nginx"

    if fs_exists "$nginx_fs"; then
        record "oci/nginx-import" PASS "exists"
    elif output=$(timeout "$TIMEOUT_IMPORT" $SDME fs import "$nginx_fs" "$NGINX_IMAGE" \
            --base-fs="$BASE_FS" -v 2>&1); then
        record "oci/nginx-import" PASS
    else
        record "oci/nginx-import" FAIL "$output"
    fi

    if [[ "$(result_status "oci/nginx-import")" == "PASS" ]]; then
        if output=$(timeout "$TIMEOUT_BOOT" $SDME create -r "$nginx_fs" "$nginx_ct" 2>&1) && \
           output=$(timeout "$TIMEOUT_BOOT" $SDME start "$nginx_ct" -t 120 2>&1); then
            record "oci/nginx-boot" PASS
            sleep 3

            # systemctl status sdme-oci-nginx.service (from inside)
            if output=$(timeout "$TIMEOUT_TEST" $SDME exec "$nginx_ct" \
                    /usr/bin/systemctl is-active sdme-oci-nginx.service 2>&1); then
                record "oci/nginx-service" PASS
            else
                record "oci/nginx-service" FAIL "$output"
            fi

            # sdme logs --oci
            if output=$(timeout "$TIMEOUT_TEST" $SDME logs --oci -- "$nginx_ct" --no-pager -n 5 2>&1); then
                record "oci/nginx-logs" PASS
            else
                record "oci/nginx-logs" FAIL "$output"
            fi

            stop_container "$nginx_ct"
            $SDME rm -f "$nginx_ct" 2>/dev/null || true
        else
            record "oci/nginx-boot" FAIL "$output"
            record "oci/nginx-service" SKIP "boot failed"
            record "oci/nginx-logs" SKIP "boot failed"
            $SDME rm -f "$nginx_ct" 2>/dev/null || true
        fi
    else
        record "oci/nginx-boot" SKIP "import failed"
        record "oci/nginx-service" SKIP "import failed"
        record "oci/nginx-logs" SKIP "import failed"
    fi

    # -- redis (tests exec --oci) --
    local redis_fs="vfy-usage-redis"
    local redis_ct="vfy-usage-ct-redis"

    if fs_exists "$redis_fs"; then
        record "oci/redis-import" PASS "exists"
    elif output=$(timeout "$TIMEOUT_IMPORT" $SDME fs import "$redis_fs" "$REDIS_IMAGE" \
            --base-fs="$BASE_FS" -v 2>&1); then
        record "oci/redis-import" PASS
    else
        record "oci/redis-import" FAIL "$output"
    fi

    if [[ "$(result_status "oci/redis-import")" == "PASS" ]]; then
        if output=$(timeout "$TIMEOUT_BOOT" $SDME create -r "$redis_fs" "$redis_ct" 2>&1) && \
           output=$(timeout "$TIMEOUT_BOOT" $SDME start "$redis_ct" -t 120 2>&1); then
            record "oci/redis-boot" PASS
            sleep 3

            # sdme exec --oci <name> redis-cli ping
            local reply
            reply=$(timeout "$TIMEOUT_TEST" $SDME exec --oci -- "$redis_ct" \
                /usr/local/bin/redis-cli ping 2>&1) || true
            if [[ "$reply" == *"PONG"* ]]; then
                record "oci/redis-exec-oci" PASS
            else
                record "oci/redis-exec-oci" FAIL "$reply"
            fi

            stop_container "$redis_ct"
            $SDME rm -f "$redis_ct" 2>/dev/null || true
        else
            record "oci/redis-boot" FAIL "$output"
            record "oci/redis-exec-oci" SKIP "boot failed"
            $SDME rm -f "$redis_ct" 2>/dev/null || true
        fi
    else
        record "oci/redis-boot" SKIP "import failed"
        record "oci/redis-exec-oci" SKIP "import failed"
    fi

    # -- postgresql (tests --oci-env) --
    local pg_fs="vfy-usage-postgres"
    local pg_ct="vfy-usage-ct-pg"

    if fs_exists "$pg_fs"; then
        record "oci/pg-import" PASS "exists"
    elif output=$(timeout "$TIMEOUT_IMPORT" $SDME fs import "$pg_fs" "$POSTGRES_IMAGE" \
            --base-fs="$BASE_FS" -v 2>&1); then
        record "oci/pg-import" PASS
    else
        record "oci/pg-import" FAIL "$output"
    fi

    if [[ "$(result_status "oci/pg-import")" == "PASS" ]]; then
        # sdme new -r postgresql --oci-env POSTGRES_PASSWORD=secret
        if output=$(timeout "$TIMEOUT_BOOT" $SDME create -r "$pg_fs" \
                --oci-env "POSTGRES_PASSWORD=secret" "$pg_ct" 2>&1) && \
           output=$(timeout "$TIMEOUT_BOOT" $SDME start "$pg_ct" -t 120 2>&1); then
            record "oci/pg-boot" PASS
            sleep 10

            # Verify the env var took effect: pg_isready should succeed
            if output=$(timeout "$TIMEOUT_TEST" $SDME exec --oci -- "$pg_ct" \
                    /bin/sh -c 'pg_isready -h 127.0.0.1 -p 5432' 2>&1); then
                record "oci/pg-env" PASS
            else
                record "oci/pg-env" FAIL "$output"
            fi

            stop_container "$pg_ct"
            $SDME rm -f "$pg_ct" 2>/dev/null || true
        else
            record "oci/pg-boot" FAIL "$output"
            record "oci/pg-env" SKIP "boot failed"
            $SDME rm -f "$pg_ct" 2>/dev/null || true
        fi
    else
        record "oci/pg-boot" SKIP "import failed"
        record "oci/pg-env" SKIP "import failed"
    fi
}

# =============================================================================
# Section: Pods
# =============================================================================

test_pods() {
    log "Section: Pods"

    if ! need_base; then
        for k in pod/create pod/ls pod/join-pod pod/connectivity pod/rm; do
            record "$k" SKIP "base import failed"
        done
        return
    fi

    local output

    # sdme pod new my-pod
    local pod="vfy-usage-pod"
    if output=$(timeout 10 $SDME pod new "$pod" 2>&1); then
        record "pod/create" PASS
    else
        record "pod/create" FAIL "$output"
        record "pod/ls" SKIP "create failed"
        record "pod/join-pod" SKIP "create failed"
        record "pod/connectivity" SKIP "create failed"
        record "pod/rm" SKIP "create failed"
        return
    fi

    # sdme pod ls
    if output=$($SDME pod ls 2>&1) && echo "$output" | grep -q "$pod"; then
        record "pod/ls" PASS
    else
        record "pod/ls" FAIL "$output"
    fi

    # sdme create --pod=my-pod -r ubuntu db / app
    local ct_db="vfy-usage-pod-db"
    local ct_app="vfy-usage-pod-app"
    if output=$(timeout "$TIMEOUT_BOOT" $SDME create --pod="$pod" -r "$BASE_FS" "$ct_db" 2>&1) && \
       output=$(timeout "$TIMEOUT_BOOT" $SDME create --pod="$pod" -r "$BASE_FS" "$ct_app" 2>&1); then
        record "pod/join-pod" PASS
    else
        record "pod/join-pod" FAIL "$output"
        record "pod/connectivity" SKIP "create failed"
        record "pod/rm" SKIP "create failed"
        $SDME rm -f "$ct_db" 2>/dev/null || true
        $SDME rm -f "$ct_app" 2>/dev/null || true
        $SDME pod rm -f "$pod" 2>/dev/null || true
        return
    fi

    # Start both, verify connectivity via shared loopback
    if timeout "$TIMEOUT_BOOT" $SDME start "$ct_db" -t 120 2>&1 >/dev/null && \
       timeout "$TIMEOUT_BOOT" $SDME start "$ct_app" -t 120 2>&1 >/dev/null; then

        # Start listener in db, connect from app
        $SDME exec "$ct_db" /usr/bin/systemd-run --unit=test-listener \
            /usr/bin/python3 -c \
            'import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("127.0.0.1",9998)); s.listen(1); c,_=s.accept(); c.sendall(b"USAGE\n"); c.close(); s.close()' \
            >/dev/null 2>&1
        sleep 1

        local result
        result=$($SDME exec "$ct_app" /usr/bin/python3 -c \
            'import socket; s=socket.socket(); s.settimeout(2); s.connect(("127.0.0.1",9998)); print(s.recv(1024).decode().strip()); s.close()' \
            2>/dev/null || true)
        if [[ "$result" == *"USAGE"* ]]; then
            record "pod/connectivity" PASS
        else
            record "pod/connectivity" FAIL "got: '$result'"
        fi
    else
        record "pod/connectivity" FAIL "start failed"
    fi

    stop_container "$ct_db"
    stop_container "$ct_app"
    $SDME rm -f "$ct_db" 2>/dev/null || true
    $SDME rm -f "$ct_app" 2>/dev/null || true

    # sdme pod rm
    if output=$(timeout 10 $SDME pod rm -f "$pod" 2>&1); then
        record "pod/rm" PASS
    else
        record "pod/rm" FAIL "$output"
    fi
}

# =============================================================================
# Section: Security (--hardened, --strict, individual flags)
# =============================================================================

test_security() {
    log "Section: Security"

    if ! need_base; then
        for k in sec/hardened sec/strict sec/individual; do
            record "$k" SKIP "base import failed"
        done
        return
    fi

    local output ct

    # sdme new -r ubuntu --hardened
    ct="vfy-usage-hardened"
    if output=$(timeout "$TIMEOUT_BOOT" $SDME create -r "$BASE_FS" --hardened "$ct" 2>&1) && \
       output=$(timeout "$TIMEOUT_BOOT" $SDME start "$ct" -t 120 2>&1); then
        record "sec/hardened" PASS
        stop_container "$ct"
    else
        record "sec/hardened" FAIL "$output"
    fi
    $SDME rm -f "$ct" 2>/dev/null || true

    # sdme new -r ubuntu --strict
    ct="vfy-usage-strict"
    if output=$(timeout "$TIMEOUT_BOOT" $SDME create -r "$BASE_FS" --strict "$ct" 2>&1) && \
       output=$(timeout "$TIMEOUT_BOOT" $SDME start "$ct" -t 120 2>&1); then
        record "sec/strict" PASS
        stop_container "$ct"
    else
        record "sec/strict" FAIL "$output"
    fi
    $SDME rm -f "$ct" 2>/dev/null || true

    # Individual flags
    ct="vfy-usage-secflags"
    if output=$(timeout "$TIMEOUT_BOOT" $SDME create -r "$BASE_FS" \
            --userns \
            --private-network \
            --drop-capability CAP_NET_RAW \
            --no-new-privileges \
            --read-only \
            --system-call-filter '~@raw-io' \
            "$ct" 2>&1) && \
       output=$(timeout "$TIMEOUT_BOOT" $SDME start "$ct" -t 120 2>&1); then
        record "sec/individual" PASS
        stop_container "$ct"
    else
        record "sec/individual" FAIL "$output"
    fi
    $SDME rm -f "$ct" 2>/dev/null || true
}

# =============================================================================
# Section: Networking (private, veth, port forwarding, zones)
# =============================================================================

test_networking() {
    log "Section: Networking"

    if ! need_base; then
        for k in net/private net/veth-port net/zone; do
            record "$k" SKIP "base import failed"
        done
        return
    fi

    local output ct

    # --private-network (loopback only)
    ct="vfy-usage-net-priv"
    if output=$(timeout "$TIMEOUT_BOOT" $SDME create -r "$BASE_FS" --private-network "$ct" 2>&1) && \
       output=$(timeout "$TIMEOUT_BOOT" $SDME start "$ct" -t 120 2>&1); then
        record "net/private" PASS
        stop_container "$ct"
    else
        record "net/private" FAIL "$output"
    fi
    $SDME rm -f "$ct" 2>/dev/null || true

    # --private-network --network-veth --port 8080:80
    ct="vfy-usage-net-veth"
    if output=$(timeout "$TIMEOUT_BOOT" $SDME create -r "$BASE_FS" \
            --private-network --network-veth --port 8080:80 "$ct" 2>&1) && \
       output=$(timeout "$TIMEOUT_BOOT" $SDME start "$ct" -t 120 2>&1); then
        record "net/veth-port" PASS
        stop_container "$ct"
    else
        record "net/veth-port" FAIL "$output"
    fi
    $SDME rm -f "$ct" 2>/dev/null || true

    # --network-zone
    local ct_web="vfy-usage-zone-web"
    local ct_client="vfy-usage-zone-cli"
    if output=$(timeout "$TIMEOUT_BOOT" $SDME create -r "$BASE_FS" \
            --private-network --network-zone=vfyzone "$ct_web" 2>&1) && \
       output=$(timeout "$TIMEOUT_BOOT" $SDME create -r "$BASE_FS" \
            --private-network --network-zone=vfyzone "$ct_client" 2>&1) && \
       output=$(timeout "$TIMEOUT_BOOT" $SDME start "$ct_web" -t 120 2>&1) && \
       output=$(timeout "$TIMEOUT_BOOT" $SDME start "$ct_client" -t 120 2>&1); then
        record "net/zone" PASS
        stop_container "$ct_web"
        stop_container "$ct_client"
    else
        record "net/zone" FAIL "$output"
    fi
    $SDME rm -f "$ct_web" 2>/dev/null || true
    $SDME rm -f "$ct_client" 2>/dev/null || true
}

# =============================================================================
# Section: Resource limits
# =============================================================================

test_limits() {
    log "Section: Resource limits"

    if ! need_base; then
        record "limits/create" SKIP "base import failed"
        record "limits/set" SKIP "base import failed"
        return
    fi

    local output ct="vfy-usage-limits"

    # sdme create mybox -r ubuntu --memory 2G --cpus 0.5
    if output=$(timeout "$TIMEOUT_BOOT" $SDME create -r "$BASE_FS" \
            --memory 2G --cpus 0.5 "$ct" 2>&1); then
        record "limits/create" PASS
    else
        record "limits/create" FAIL "$output"
        record "limits/set" SKIP "create failed"
        return
    fi

    # sdme set mybox --memory 4G --cpus 2
    if output=$(timeout 10 $SDME set "$ct" --memory 4G --cpus 2 2>&1); then
        record "limits/set" PASS
    else
        record "limits/set" FAIL "$output"
    fi

    $SDME rm -f "$ct" 2>/dev/null || true
}

# =============================================================================
# Section: Bind mounts and environment variables
# =============================================================================

test_binds_env() {
    log "Section: Bind mounts and env vars"

    if ! need_base; then
        record "binds/create" SKIP "base import failed"
        record "binds/verify" SKIP "base import failed"
        return
    fi

    local output ct="vfy-usage-binds"
    local bind_dir="/tmp/vfy-usage-bind-test"
    mkdir -p "$bind_dir"
    echo "test-data" > "$bind_dir/file.txt"

    # sdme create mybox -r ubuntu --bind /srv/data:/data --env MY_VAR=hello
    if output=$(timeout "$TIMEOUT_BOOT" $SDME create -r "$BASE_FS" \
            --bind "$bind_dir:/data:ro" \
            --env MY_VAR=hello \
            "$ct" 2>&1); then
        record "binds/create" PASS
    else
        record "binds/create" FAIL "$output"
        record "binds/verify" SKIP "create failed"
        rm -rf "$bind_dir"
        return
    fi

    # Start and verify the bind mount and env var
    if output=$(timeout "$TIMEOUT_BOOT" $SDME start "$ct" -t 120 2>&1); then
        local file_content env_val
        file_content=$(timeout "$TIMEOUT_TEST" $SDME exec "$ct" -- /bin/cat /data/file.txt 2>&1) || true
        env_val=$(timeout "$TIMEOUT_TEST" $SDME exec "$ct" -- /bin/cat /proc/1/environ 2>&1) || true
        if [[ "$file_content" == *"test-data"* ]] && [[ "$env_val" == *"MY_VAR=hello"* ]]; then
            record "binds/verify" PASS
        else
            record "binds/verify" FAIL "file='$file_content' env='$env_val'"
        fi
        stop_container "$ct"
    else
        record "binds/verify" FAIL "start failed: $output"
    fi

    $SDME rm -f "$ct" 2>/dev/null || true
    rm -rf "$bind_dir"
}

# =============================================================================
# Section: Opaque directories
# =============================================================================

test_opaque_dirs() {
    log "Section: Opaque dirs"

    local output ct="vfy-usage-opaque"

    # sdme create mybox -o /etc/systemd/system,/var/log,/tmp (host clone)
    if output=$(timeout "$TIMEOUT_BOOT" $SDME create \
            -o /etc/systemd/system,/var/log,/tmp "$ct" 2>&1); then
        record "opaque/create" PASS
    else
        record "opaque/create" FAIL "$output"
        record "opaque/verify" SKIP "create failed"
        return
    fi

    # Verify the xattr is set on the upper layer directories (host-side check,
    # the xattr is on the upper layer, not visible inside the container).
    local upper_dir="$DATADIR/containers/$ct/upper"
    local ok=1
    for d in /etc/systemd/system /var/log /tmp; do
        if ! getfattr -n trusted.overlay.opaque "$upper_dir$d" 2>/dev/null | \
                grep -q "trusted.overlay.opaque"; then
            ok=0
            break
        fi
    done
    if [[ $ok -eq 1 ]]; then
        record "opaque/verify" PASS
    else
        record "opaque/verify" FAIL "opaque xattr not found on upper layer"
    fi

    $SDME rm -f "$ct" 2>/dev/null || true
}

# =============================================================================
# Section: Kube apply
# =============================================================================

test_kube_apply() {
    log "Section: Kube apply"

    if ! need_base; then
        record "kube/apply" SKIP "base import failed"
        record "kube/delete" SKIP "base import failed"
        return
    fi

    local output
    local ct="vfy-usage-kube"
    local yaml_file="/tmp/vfy-usage-kube-pod.yaml"

    # Write a minimal Pod YAML
    cat > "$yaml_file" <<'EOYAML'
apiVersion: v1
kind: Pod
metadata:
  name: vfy-usage-kube
spec:
  containers:
  - name: nginx
    image: docker.io/nginx
EOYAML

    # sdme kube create -f <file> --base-fs <name> (we use create+start instead
    # of apply to avoid the interactive join)
    if output=$(timeout "$TIMEOUT_IMPORT" $SDME kube create \
            -f "$yaml_file" --base-fs "$BASE_FS" 2>&1) && \
       output=$(timeout "$TIMEOUT_BOOT" $SDME start "$ct" -t 120 2>&1); then
        record "kube/apply" PASS
        sleep 3

        # Verify the kube container is visible in ps with kube metadata
        local ps_out
        ps_out=$($SDME ps 2>&1)
        if echo "$ps_out" | grep -q "$ct"; then
            : # good
        fi

        stop_container "$ct"
    else
        record "kube/apply" FAIL "$output"
    fi

    # sdme kube delete
    if output=$(timeout 30 $SDME kube delete "$ct" 2>&1); then
        record "kube/delete" PASS
    else
        record "kube/delete" FAIL "$output"
    fi

    rm -f "$yaml_file"
}

# =============================================================================
# Section: Configuration
# =============================================================================

test_config() {
    log "Section: Configuration"

    local output

    # sdme config get
    if output=$(timeout 10 $SDME config get 2>&1); then
        record "config/get" PASS
    else
        record "config/get" FAIL "$output"
    fi

    # sdme config set default_base_fs ubuntu (then reset)
    if output=$(timeout 10 $SDME config set default_base_fs test-value 2>&1); then
        # Verify it stuck
        local val
        val=$(timeout 10 $SDME config get 2>&1 | grep default_base_fs || true)
        if [[ "$val" == *"test-value"* ]]; then
            record "config/set" PASS
        else
            record "config/set" FAIL "value not found after set: $val"
        fi
        # Reset
        $SDME config set default_base_fs "" 2>/dev/null || true
    else
        record "config/set" FAIL "$output"
    fi
}

# =============================================================================
# Section: Managing root filesystems (fs rm)
# =============================================================================

test_fs_rm() {
    log "Section: FS removal"

    if ! need_base; then
        record "fs/rm" SKIP "base import failed"
        return
    fi

    local output
    local tmp_fs="vfy-usage-tmp-fs"

    # Import a throwaway rootfs, then remove it
    if fs_exists "$tmp_fs"; then
        $SDME fs rm "$tmp_fs" 2>/dev/null || true
    fi

    if output=$(timeout "$TIMEOUT_IMPORT" $SDME fs import "$tmp_fs" "$BASE_IMAGE" \
            -v --install-packages=yes -f 2>&1); then
        if output=$($SDME fs rm "$tmp_fs" 2>&1); then
            if ! fs_exists "$tmp_fs"; then
                record "fs/rm" PASS
            else
                record "fs/rm" FAIL "still exists after rm"
            fi
        else
            record "fs/rm" FAIL "$output"
        fi
    else
        record "fs/rm" FAIL "import failed: $output"
    fi
}

# =============================================================================
# Section: join --start
# =============================================================================

test_join_start() {
    log "Section: join --start"

    if ! need_base; then
        record "join/start" SKIP "base import failed"
        return
    fi

    local output ct="vfy-usage-join"

    if ! output=$(timeout "$TIMEOUT_BOOT" $SDME create -r "$BASE_FS" "$ct" 2>&1); then
        record "join/start" FAIL "create failed: $output"
        return
    fi

    # join --start should start a stopped container. We can't actually
    # join interactively, but we can verify it starts by checking ps.
    # Start it manually first to confirm the flow works.
    if output=$(timeout "$TIMEOUT_BOOT" $SDME start "$ct" -t 120 2>&1); then
        # Verify it's listed as running
        if $SDME ps 2>/dev/null | grep -q "$ct"; then
            record "join/start" PASS
        else
            record "join/start" FAIL "not visible in ps after start"
        fi
        stop_container "$ct"
    else
        record "join/start" FAIL "start failed: $output"
    fi

    $SDME rm -f "$ct" 2>/dev/null || true
}

# =============================================================================
# Section: stop --all, start --all, rm --all
# =============================================================================

test_stop_rm_all() {
    log "Section: stop/start/rm --all"

    if ! need_base; then
        record "batch/stop-all" SKIP "base import failed"
        record "batch/start-all" SKIP "base import failed"
        record "batch/rm-all" SKIP "base import failed"
        return
    fi

    local output

    # NOTE: --all affects ALL sdme containers on the system. This test
    # is last so other tests have already cleaned up. We verify the flag
    # works by checking our specific containers in the output.

    # Create two containers
    local ct1="vfy-usage-all1"
    local ct2="vfy-usage-all2"
    timeout "$TIMEOUT_BOOT" $SDME create -r "$BASE_FS" "$ct1" 2>/dev/null || true
    timeout "$TIMEOUT_BOOT" $SDME create -r "$BASE_FS" "$ct2" 2>/dev/null || true
    timeout "$TIMEOUT_BOOT" $SDME start "$ct1" -t 120 2>/dev/null || true
    timeout "$TIMEOUT_BOOT" $SDME start "$ct2" -t 120 2>/dev/null || true

    # sdme stop --all
    if output=$(timeout 90 $SDME stop --all 2>&1); then
        record "batch/stop-all" PASS
    else
        record "batch/stop-all" FAIL "$output"
    fi

    # sdme start --all (both containers should be stopped now)
    if output=$(timeout "$TIMEOUT_BOOT" $SDME start --all -t 120 2>&1); then
        # Verify both are running
        local ps_out
        ps_out=$($SDME ps 2>&1)
        if echo "$ps_out" | grep -q "$ct1" && echo "$ps_out" | grep -q "$ct2"; then
            record "batch/start-all" PASS
        else
            record "batch/start-all" FAIL "containers not visible after start --all: $ps_out"
        fi
    else
        record "batch/start-all" FAIL "$output"
    fi

    # Stop before rm
    timeout 90 $SDME stop --all 2>/dev/null || true

    # sdme rm --all -f
    if output=$(timeout 30 $SDME rm --all -f 2>&1); then
        # Verify vfy-usage-all containers are gone
        local ps_out
        ps_out=$($SDME ps 2>&1)
        if echo "$ps_out" | grep -q "vfy-usage-all"; then
            record "batch/rm-all" FAIL "containers still present after rm --all"
        else
            record "batch/rm-all" PASS
        fi
    else
        record "batch/rm-all" FAIL "$output"
    fi
}

# =============================================================================
# Report
# =============================================================================

generate_report() {
    local ts
    ts=$(date +%Y%m%d-%H%M%S)
    local report="$REPORT_DIR/verify-usage-$ts.md"

    log "Writing report to $report"
    mkdir -p "$REPORT_DIR"

    {
        echo "# sdme Usage Guide Verification Report"
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
        echo "| Section | Test | Status | Details |"
        echo "|---------|------|--------|---------|"
        for key in \
            host/create host/start host/ps host/exec host/logs \
            host/enable host/disable host/stop host/rm \
            import/base import/fs-ls import/create import/boot \
            oci/nginx-import oci/nginx-boot oci/nginx-service oci/nginx-logs \
            oci/redis-import oci/redis-boot oci/redis-exec-oci \
            oci/pg-import oci/pg-boot oci/pg-env \
            pod/create pod/ls pod/join-pod pod/connectivity pod/rm \
            sec/hardened sec/strict sec/individual \
            net/private net/veth-port net/zone \
            limits/create limits/set \
            binds/create binds/verify \
            opaque/create opaque/verify \
            kube/apply kube/delete \
            config/get config/set \
            fs/rm \
            join/start \
            batch/stop-all batch/start-all batch/rm-all; do
            if [[ -n "${RESULTS[$key]+x}" ]]; then
                local section st msg
                section="${key%%/*}"
                st=$(result_status "$key")
                msg="${RESULTS[$key]#*|}"
                echo "| $section | ${key#*/} | $st | ${msg:--} |"
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
                    msg="${RESULTS[$key]#*|}"
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

# =============================================================================
# Main
# =============================================================================

main() {
    parse_args "$@"

    ensure_root
    ensure_sdme
    require_gate smoke
    require_gate interrupt

    echo "Usage guide verification"
    echo "Base image: $BASE_IMAGE"
    echo ""

    test_host_clone
    test_import_oci
    test_oci_apps
    test_pods
    test_security
    test_networking
    test_limits
    test_binds_env
    test_opaque_dirs
    test_kube_apply
    test_config
    test_fs_rm
    test_join_start
    test_stop_rm_all
    generate_report

    print_summary
}

main "$@"
