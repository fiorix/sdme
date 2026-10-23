#!/usr/bin/env bash
set -uo pipefail

# verify-ephemeral.sh - end-to-end verification of ephemeral containers
# Run as root. Uses the vfy-eph- prefix for all artifacts.
#
# Tests:
#   1. Session trigger: `new --ephemeral -- CMD` removes the container and
#      returns CMD's exit status
#   2. Session trigger: killing the client's process group tears down
#   3. Service trigger: a main service finishing (success and failure)
#   4. OCI default main service, and --no-main-service; ephemeral containers
#      sharing a pod
#   5. Health trigger: --health-cmd, --health-tcp, --health-http
#   6. Port forward and bind mount gone after `sdme stop`; stop waits
#   7. Refusals: --enable, restart, enable, set, trigger flags without
#      --ephemeral, start of an orphan; prune lists the orphan; a reboot
#      inside the container tears it down
#   8. Distro matrix: session trigger on each distro in EPH_DISTROS
#
# EPH_STORAGE selects the storage backend for every container (overlay or
# btrfs; default: sdme's configured default). With btrfs, the datadir's
# filesystem decides the mode: Mode A on btrfs, Mode B (loopback pool)
# elsewhere.

source "$(dirname "$0")/lib.sh"

PREFIX="vfy-eph"
DATADIR="${DATADIR:-/var/lib/sdme}"
BASE_FS="${BASE_FS:-ubuntu}"
APP_IMAGE="quay.io/nginx/nginx-unprivileged"
APP_FS="${PREFIX}-nginx"
APP_SERVICE=$(oci_service_name "$APP_IMAGE")
TMPDIR_EPH=$(mktemp -d "/tmp/${PREFIX}-XXXXXX")

TIMEOUT_BOOT=$(scale_timeout 120)
TIMEOUT_IMPORT=$(scale_timeout 600)
TIMEOUT_GONE=$(scale_timeout 60)

parse_standard_args "End-to-end verification of ephemeral containers." "$@"
EPH_DISTROS="${EPH_DISTROS:-$BASE_FS}"
STORAGE_ARGS=()
if [[ -n "${EPH_STORAGE:-}" ]]; then
    STORAGE_ARGS=(--storage "$EPH_STORAGE")
fi

cleanup() {
    cleanup_prefix "${PREFIX}-"
    rm -rf "$TMPDIR_EPH"
}
trap cleanup EXIT INT TERM

# True when no trace of the container is left: state, overlayfs dirs,
# btrfs subvolume (Mode A or Mode B location), and the transient unit.
is_gone() {
    local name="$1"
    [[ ! -e "$DATADIR/state/$name" ]] &&
        [[ ! -e "$DATADIR/containers/$name" ]] &&
        [[ ! -e "$DATADIR/btrfs/containers/$name" ]] &&
        [[ ! -e "$DATADIR/pool/containers/$name" ]] &&
        [[ -z "$(systemctl list-units --all --no-legend "sdme-ephemeral@$name.service" 2>/dev/null)" ]]
}

# Wait up to $2 seconds for is_gone.
wait_gone() {
    local name="$1" secs="$2"
    for ((i = 0; i < secs; i++)); do
        is_gone "$name" && return 0
        sleep 1
    done
    is_gone "$name"
}

# The container's writable root: overlay upper, or btrfs subvolume (Mode A
# or Mode B location).
container_root() {
    local name="$1" dir
    for dir in "$DATADIR/containers/$name/upper" "$DATADIR/btrfs/containers/$name" \
            "$DATADIR/pool/containers/$name"; do
        if [[ -d "$dir" ]]; then
            echo "$dir"
            return 0
        fi
    done
    return 1
}

is_running() {
    systemctl is-active --quiet "sdme-ephemeral@$1.service"
}

# Wait up to $2 seconds for the container's transient unit to be active.
wait_running() {
    local name="$1" secs="$2"
    for ((i = 0; i < secs; i++)); do
        is_running "$name" && return 0
        sleep 1
    done
    return 1
}

ensure_root
ensure_sdme
require_gate smoke
require_gate interrupt
ensure_base_fs "$BASE_FS" "${DISTRO_IMAGES[$BASE_FS]}"
cleanup_prefix "${PREFIX}-"

# ---------------------------------------------------------------------------
# Test 1: session trigger, command exit status
# ---------------------------------------------------------------------------
echo "=== Test 1: session trigger, exit status ==="

ct="${PREFIX}-s1"
if timeout "$TIMEOUT_BOOT" "$SDME" new "${STORAGE_ARGS[@]}" --ephemeral -r "$BASE_FS" -t "$TIMEOUT_BOOT" \
        --name "$ct" $VFLAG -- /bin/true </dev/null; then
    if is_gone "$ct"; then
        ok "new --ephemeral -- true: removed on exit"
    else
        fail "new --ephemeral -- true: container left behind"
    fi
else
    fail "new --ephemeral -- true: command failed"
fi

# With stdout not a TTY, the join runs the command through systemd-run
# --pipe --wait, which propagates its exit status.
ct="${PREFIX}-s2"
timeout "$TIMEOUT_BOOT" "$SDME" new "${STORAGE_ARGS[@]}" --ephemeral -r "$BASE_FS" -t "$TIMEOUT_BOOT" \
    --name "$ct" $VFLAG -- /bin/sh -c 'exit 7' </dev/null >/dev/null
rc=$?
if [[ $rc -eq 7 ]] && is_gone "$ct"; then
    ok "new --ephemeral -- exit 7: status propagated, removed"
else
    fail "new --ephemeral -- exit 7: rc=$rc, gone=$(is_gone "$ct" && echo yes || echo no)"
fi

# ---------------------------------------------------------------------------
# Test 2: session trigger, client killed
# ---------------------------------------------------------------------------
echo "=== Test 2: session trigger, client killed ==="

# Simulate a lost terminal: SIGKILL the whole process group of the client
# (sdme and its machinectl child). The session scope empties and systemd
# stops the container.
ct="${PREFIX}-k1"
setsid "$SDME" new "${STORAGE_ARGS[@]}" --ephemeral -r "$BASE_FS" -t "$TIMEOUT_BOOT" --name "$ct" \
    -- /bin/sleep 600 </dev/null >"$TMPDIR_EPH/k1.log" 2>&1 &
client=$!
if wait_running "$ct" "$TIMEOUT_BOOT"; then
    # Give join a moment to attach.
    sleep 3
    # A second session (sdme join) does not own the container.
    timeout 30 "$SDME" join "$ct" -- /bin/true </dev/null >/dev/null 2>&1
    if is_running "$ct"; then
        ok "join and exit during a session: container kept"
    else
        fail "join and exit during a session: container stopped"
    fi
    kill -KILL -- "-$client" 2>/dev/null || kill -KILL "$client"
    if wait_gone "$ct" "$TIMEOUT_GONE"; then
        ok "client SIGKILL: container torn down"
    else
        fail "client SIGKILL: container still present"
    fi
else
    fail "client SIGKILL: container never started ($(tail -3 "$TMPDIR_EPH/k1.log"))"
fi
wait "$client" 2>/dev/null

# ---------------------------------------------------------------------------
# Test 3: service trigger
# ---------------------------------------------------------------------------
echo "=== Test 3: service trigger ==="

# The trigger drop-in applies to transient units too, so a unit started
# later with systemd-run inside the container works as a main service.
for result in success failure; do
    ct="${PREFIX}-m-${result}"
    if [[ $result == success ]]; then cmd=/bin/true; else cmd=/bin/false; fi
    if timeout "$TIMEOUT_BOOT" "$SDME" create "${STORAGE_ARGS[@]}" --ephemeral -r "$BASE_FS" -t "$TIMEOUT_BOOT" \
            --main-service vfy-job --name "$ct" $VFLAG >/dev/null; then
        root=$(container_root "$ct")
        if [[ ! -f "$root/etc/systemd/system/vfy-job.service.d/sdme-ephemeral.conf" ]]; then
            fail "service trigger ($result): drop-in missing"
        fi
        "$SDME" exec "$ct" /usr/bin/systemd-run --unit=vfy-job "$cmd" >/dev/null 2>&1
        if wait_gone "$ct" "$TIMEOUT_GONE"; then
            ok "service trigger ($result): torn down"
        else
            fail "service trigger ($result): container still present"
        fi
    else
        fail "service trigger ($result): create failed"
    fi
done

# ---------------------------------------------------------------------------
# Test 4: OCI app default main service
# ---------------------------------------------------------------------------
echo "=== Test 4: OCI app main service ==="

if fs_exists "$APP_FS" || timeout "$TIMEOUT_IMPORT" "$SDME" fs import "$APP_IMAGE" --name "$APP_FS" \
        --base-fs="$BASE_FS" --oci-mode=app -v -f >"$TMPDIR_EPH/import.log" 2>&1; then
    ct="${PREFIX}-o1"
    if timeout "$TIMEOUT_BOOT" "$SDME" create "${STORAGE_ARGS[@]}" --ephemeral -r "$APP_FS" -t "$TIMEOUT_BOOT" \
            --name "$ct" $VFLAG >/dev/null; then
        if [[ -d "$DATADIR/volumes/$ct" ]]; then
            fail "OCI ephemeral: volume dir created despite implied --no-oci-volumes"
        fi
        sleep 2
        "$SDME" exec "$ct" /usr/bin/systemctl kill --signal=KILL "$APP_SERVICE" >/dev/null 2>&1
        if wait_gone "$ct" "$TIMEOUT_GONE"; then
            ok "OCI app killed: torn down (default main service)"
        else
            fail "OCI app killed: container still present"
        fi
    else
        fail "OCI ephemeral: create failed"
    fi

    ct="${PREFIX}-o2"
    if timeout "$TIMEOUT_BOOT" "$SDME" create "${STORAGE_ARGS[@]}" --ephemeral --no-main-service -r "$APP_FS" \
            -t "$TIMEOUT_BOOT" --name "$ct" $VFLAG >/dev/null; then
        sleep 2
        "$SDME" exec "$ct" /usr/bin/systemctl kill --signal=KILL "$APP_SERVICE" >/dev/null 2>&1
        sleep 5
        if is_running "$ct"; then
            ok "--no-main-service: OCI app exit keeps the container"
        else
            fail "--no-main-service: container stopped"
        fi
        cleanup_container "$ct"
    else
        fail "--no-main-service: create failed"
    fi
else
    skipped "OCI app tests: import of $APP_IMAGE failed"
fi

# An ephemeral server and an ephemeral client share a pod's network
# namespace; the client reaches the server on 127.0.0.1.
if fs_exists "$APP_FS"; then
    pod="${PREFIX}-pod"
    "$SDME" pod rm -f "$pod" >/dev/null 2>&1
    "$SDME" pod new "$pod" $VFLAG >/dev/null
    ct="${PREFIX}-pod-srv"
    if timeout "$TIMEOUT_BOOT" "$SDME" create "${STORAGE_ARGS[@]}" --ephemeral -r "$APP_FS" \
            -t "$TIMEOUT_BOOT" --pod "$pod" --name "$ct" $VFLAG >/dev/null; then
        sleep 2
        reply=$(timeout "$TIMEOUT_BOOT" "$SDME" new "${STORAGE_ARGS[@]}" --ephemeral -r "$BASE_FS" \
            -t "$TIMEOUT_BOOT" --pod "$pod" --name "${PREFIX}-pod-cli" -- /bin/bash -c \
            'exec 3<>/dev/tcp/127.0.0.1/8080; printf "GET / HTTP/1.0\r\n\r\n" >&3; head -1 <&3' \
            </dev/null 2>/dev/null)
        if [[ "$reply" == "HTTP/1.1 200"* ]] && is_gone "${PREFIX}-pod-cli"; then
            ok "ephemeral containers share a pod: client reached the server"
        else
            fail "ephemeral containers in a pod: got '$reply'"
        fi
        "$SDME" stop "$ct" $VFLAG >/dev/null 2>&1
        if is_gone "$ct"; then
            ok "ephemeral pod member removed on stop"
        else
            fail "ephemeral pod member left behind"
        fi
    else
        fail "ephemeral pod member: create failed"
    fi
    "$SDME" pod rm -f "$pod" >/dev/null 2>&1
fi

# ---------------------------------------------------------------------------
# Test 5: health trigger
# ---------------------------------------------------------------------------
echo "=== Test 5: health trigger ==="

# Failing exec check: 2 retries every 2s, first check after 2s.
ct="${PREFIX}-h1"
if timeout "$TIMEOUT_BOOT" "$SDME" create "${STORAGE_ARGS[@]}" --ephemeral -r "$BASE_FS" -t "$TIMEOUT_BOOT" \
        --health-cmd 'test -e /nonexistent' --health-interval 2 --health-retries 2 \
        --name "$ct" $VFLAG >/dev/null; then
    if wait_gone "$ct" "$TIMEOUT_GONE"; then
        ok "--health-cmd failing: torn down"
    else
        fail "--health-cmd failing: container still present"
    fi
else
    fail "--health-cmd failing: create failed"
fi

# Passing exec check keeps the container.
ct="${PREFIX}-h2"
if timeout "$TIMEOUT_BOOT" "$SDME" create "${STORAGE_ARGS[@]}" --ephemeral -r "$BASE_FS" -t "$TIMEOUT_BOOT" \
        --health-cmd 'test -d /etc' --health-interval 2 --health-retries 1 \
        --name "$ct" $VFLAG >/dev/null; then
    sleep 8
    if is_running "$ct"; then
        ok "--health-cmd passing: container kept"
    else
        fail "--health-cmd passing: container stopped"
    fi
    cleanup_container "$ct"
else
    fail "--health-cmd passing: create failed"
fi

# TCP check on a closed port in a private network namespace.
ct="${PREFIX}-h3"
if timeout "$TIMEOUT_BOOT" "$SDME" create "${STORAGE_ARGS[@]}" --ephemeral -r "$BASE_FS" -t "$TIMEOUT_BOOT" \
        --private-network --health-tcp 9 --health-interval 2 --health-retries 2 \
        --name "$ct" $VFLAG >/dev/null; then
    if wait_gone "$ct" "$TIMEOUT_GONE"; then
        ok "--health-tcp closed port: torn down"
    else
        fail "--health-tcp closed port: container still present"
    fi
else
    fail "--health-tcp: create failed"
fi

# HTTP check against nginx-unprivileged (port 8080): healthy while it
# serves, torn down after it stops. --no-main-service so stopping nginx
# exercises the health trigger, not the service trigger.
ct="${PREFIX}-h4"
if fs_exists "$APP_FS"; then
    if timeout "$TIMEOUT_BOOT" "$SDME" create "${STORAGE_ARGS[@]}" --ephemeral --no-main-service -r "$APP_FS" \
            -t "$TIMEOUT_BOOT" --private-network --health-http 8080/ --health-interval 2 \
            --health-retries 2 --health-start-period 3 --name "$ct" $VFLAG >/dev/null; then
        sleep 10
        if is_running "$ct"; then
            ok "--health-http serving: container kept"
            "$SDME" exec "$ct" /usr/bin/systemctl stop "$APP_SERVICE" >/dev/null 2>&1
            if wait_gone "$ct" "$TIMEOUT_GONE"; then
                ok "--health-http server stopped: torn down"
            else
                fail "--health-http server stopped: container still present"
            fi
        else
            fail "--health-http serving: container stopped"
        fi
    else
        fail "--health-http: create failed"
    fi
else
    skipped "--health-http: $APP_FS not imported"
fi

# ---------------------------------------------------------------------------
# Test 6: port forward and bind mount gone after stop
# ---------------------------------------------------------------------------
echo "=== Test 6: port forward and bind mount ==="

ct="${PREFIX}-p1"
mkdir -p "$TMPDIR_EPH/bind"
echo marker >"$TMPDIR_EPH/bind/file"
if timeout "$TIMEOUT_BOOT" "$SDME" create "${STORAGE_ARGS[@]}" --ephemeral -r "$BASE_FS" -t "$TIMEOUT_BOOT" \
        --network-veth -p 18089:80 -b "$TMPDIR_EPH/bind:/mnt/vfy:ro" \
        --name "$ct" $VFLAG >/dev/null; then
    if "$SDME" exec "$ct" /bin/cat /mnt/vfy/file 2>/dev/null | grep -q marker; then
        ok "bind mount visible while running"
    else
        fail "bind mount not visible while running"
    fi
    if "$SDME" ps | awk -v n="$ct" '$1 == n' | grep -q ephemeral; then
        ok "ps marks the container ephemeral"
    else
        fail "ps does not mark the container ephemeral"
    fi
    has_nft=0
    nft list tables >/dev/null 2>&1 && has_nft=1
    if [[ $has_nft -eq 1 ]]; then
        # nspawn installs the DNAT rule once the container's veth has an
        # address, a few seconds after boot.
        rule_seen=0
        for ((i = 0; i < $(scale_timeout 30); i++)); do
            if nft list ruleset 2>/dev/null | grep -q 18089; then
                rule_seen=1
                break
            fi
            sleep 1
        done
        if [[ $rule_seen -eq 1 ]]; then
            ok "port forward rule present while running"
        else
            fail "port forward rule missing while running"
        fi
    fi
    "$SDME" stop "$ct" $VFLAG >/dev/null 2>&1
    # stop returns after teardown: no waiting here.
    if is_gone "$ct"; then
        ok "stop returns after teardown"
    else
        fail "container still present right after stop"
    fi
    if [[ $has_nft -eq 1 ]]; then
        if nft list ruleset 2>/dev/null | grep -q 18089; then
            fail "port forward rule left after teardown"
        else
            ok "port forward rule removed"
        fi
    else
        skipped "port forward rule check: nftables not usable on this host"
    fi
    if [[ -f "$TMPDIR_EPH/bind/file" ]]; then
        ok "bind mount source untouched by teardown"
    else
        fail "bind mount source deleted by teardown"
    fi
else
    fail "port/bind: create failed"
fi

# ---------------------------------------------------------------------------
# Test 7: refusals
# ---------------------------------------------------------------------------
echo "=== Test 7: refusals ==="

if "$SDME" create "${STORAGE_ARGS[@]}" --ephemeral --enable -r "$BASE_FS" --name "${PREFIX}-r1" >/dev/null 2>&1; then
    fail "--ephemeral --enable accepted"
    cleanup_container "${PREFIX}-r1"
else
    ok "--ephemeral --enable rejected"
fi

if "$SDME" create "${STORAGE_ARGS[@]}" --health-cmd true -r "$BASE_FS" --name "${PREFIX}-r2" >/dev/null 2>&1; then
    fail "--health-cmd without --ephemeral accepted"
    cleanup_container "${PREFIX}-r2"
else
    ok "trigger flags without --ephemeral rejected"
fi

ct="${PREFIX}-r3"
if timeout "$TIMEOUT_BOOT" "$SDME" create "${STORAGE_ARGS[@]}" --ephemeral -r "$BASE_FS" -t "$TIMEOUT_BOOT" \
        --name "$ct" $VFLAG >/dev/null; then
    if "$SDME" restart "$ct" >/dev/null 2>&1; then
        fail "restart of an ephemeral container accepted"
    elif is_running "$ct"; then
        ok "restart refused, container still running"
    else
        fail "restart refused but container stopped"
    fi
    if "$SDME" enable "$ct" >/dev/null 2>&1; then
        fail "enable of an ephemeral container accepted"
    else
        ok "enable refused"
    fi
    if "$SDME" set "$ct" --memory 1G >/dev/null 2>&1; then
        fail "set of an ephemeral container accepted"
    else
        ok "set refused"
    fi
    cleanup_container "$ct"
    if is_gone "$ct"; then
        ok "rm of a running ephemeral container"
    else
        fail "rm left the ephemeral container behind"
    fi
else
    fail "restart refusal: create failed"
fi

# A reboot inside the container ends it: teardown runs in ExecStopPost, so
# the unit cannot restart.
ct="${PREFIX}-reboot"
if timeout "$TIMEOUT_BOOT" "$SDME" create "${STORAGE_ARGS[@]}" --ephemeral -r "$BASE_FS" \
        -t "$TIMEOUT_BOOT" --name "$ct" $VFLAG >/dev/null; then
    "$SDME" exec "$ct" /usr/bin/systemctl reboot >/dev/null 2>&1
    if wait_gone "$ct" "$TIMEOUT_GONE"; then
        ok "reboot inside the container: torn down"
    else
        fail "reboot inside the container: container still present"
    fi
else
    fail "reboot: create failed"
fi

# An orphan (host crash skipped teardown) is a stopped container marked
# ephemeral. Fake one from a persistent container.
ct="${PREFIX}-orphan"
if "$SDME" create "${STORAGE_ARGS[@]}" -r "$BASE_FS" --name "$ct" $VFLAG >/dev/null; then
    echo "EPHEMERAL=yes" >>"$DATADIR/state/$ct"
    if "$SDME" start "$ct" >/dev/null 2>&1; then
        fail "start of an orphan accepted"
    else
        ok "start of an orphan refused"
    fi
    if "$SDME" prune --dry-run 2>&1 | grep -E "^\s+$ct\s" | grep -q "ephemeral orphan"; then
        ok "prune lists the orphan"
    else
        fail "prune does not list the orphan"
    fi
    if "$SDME" rm -f "$ct" >/dev/null 2>&1 && is_gone "$ct"; then
        ok "rm of an orphan"
    else
        fail "rm of an orphan failed"
    fi
else
    fail "orphan: create failed"
fi

# ---------------------------------------------------------------------------
# Test 8: distro matrix
# ---------------------------------------------------------------------------
echo "=== Test 8: distro matrix ($EPH_DISTROS) ==="

for distro in $EPH_DISTROS; do
    if [[ -z "${DISTRO_IMAGES[$distro]+x}" ]]; then
        skipped "$distro: unknown distro"
        continue
    fi
    if ! ensure_base_fs "$distro" "${DISTRO_IMAGES[$distro]}" >/dev/null 2>&1; then
        skipped "$distro: import failed"
        continue
    fi
    ct="${PREFIX}-d-${distro}"
    if timeout "$TIMEOUT_BOOT" "$SDME" new "${STORAGE_ARGS[@]}" --ephemeral -r "$distro" -t "$TIMEOUT_BOOT" \
            --name "$ct" $VFLAG -- "$(distro_bin "$distro" true)" </dev/null && is_gone "$ct"; then
        ok "$distro: ephemeral session"
    else
        fail "$distro: ephemeral session"
    fi
done

print_summary
