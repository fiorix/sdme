#!/usr/bin/env bash
set -uo pipefail

# verify-network.sh - end-to-end verification of private networking
#
# Tests:
#   1-4:   Service masking state file assertions (zone auto-unmask, defaults, overrides)
#   5-7:   Zone connectivity (HTTP via IP, resolved running, LLMNR name resolution)
#   8-9:   Bridge connectivity (create bridge, HTTP via IP, cleanup)
#
# All artifacts use the "net-" prefix.

source "$(dirname "$0")/lib.sh"

APP_IMAGE="quay.io/nginx/nginx-unprivileged"
APP_PORT=8080
ZONE_NAME="sdmezone"
BRIDGE_NAME="sdmebr0"
DATADIR="/var/lib/sdme"
REPORT_DIR="."
BASE_FS="ubuntu"

TIMEOUT_IMPORT=600
TIMEOUT_BOOT=120
TIMEOUT_TEST=60

parse_standard_args "End-to-end verification of private networking (zones, bridges, masking)." "$@"

log() { echo "==> $*"; }

cleanup() {
    log "Cleaning up net- artifacts..."
    cleanup_prefix "net-"
    # Remove the test bridge if it exists.
    if ip link show "$BRIDGE_NAME" &>/dev/null; then
        ip link set "$BRIDGE_NAME" down 2>/dev/null || true
        ip link delete "$BRIDGE_NAME" 2>/dev/null || true
    fi
}

trap cleanup EXIT INT TERM

# -- Helpers -------------------------------------------------------------------

get_container_ip() {
    local ct="$1"
    local leader ip=""
    leader=$(machinectl show "$ct" -p Leader --value 2>/dev/null) || true
    if [[ -n "$leader" ]] && [[ -d "/proc/$leader" ]]; then
        local _i nsout
        for _i in $(seq 1 15); do
            nsout=$(nsenter -t "$leader" -n ip -4 addr show host0 2>/dev/null) || true
            ip=$(echo "$nsout" | grep -oP 'inet \K[0-9.]+') || true
            if [[ -n "$ip" ]]; then
                break
            fi
            sleep 1
        done
    fi
    echo "$ip"
}

# HTTP fetch from inside a container via Python3 (curl may not be in the rootfs).
# Usage: http_get_from <container> <url>
# Prints "HTTP <status>" on success, "ERROR <msg>" on failure.
http_get_from() {
    local ct="$1" url="$2"
    timeout "$TIMEOUT_TEST" sdme exec "$ct" \
        /usr/bin/python3 -c "
import urllib.request
try:
    r = urllib.request.urlopen('${url}', timeout=10)
    print('HTTP', r.status)
except Exception as e:
    print('ERROR', e)
" 2>&1 || true
}

# -- Phase 1: Import rootfs ---------------------------------------------------

phase1_import() {
    log "Phase 1: Import rootfs"

    ensure_base_fs "net-ubuntu" "${DISTRO_IMAGES[ubuntu]}"

    local app_fs="net-nginx"
    if fs_exists "$app_fs"; then
        log "  $app_fs already exists, skipping import"
    else
        log "  Importing $app_fs from $APP_IMAGE"
        if ! timeout "$TIMEOUT_IMPORT" sdme fs import "$app_fs" "$APP_IMAGE" \
                --base-fs=net-ubuntu --oci-mode=app -v --install-packages=yes -f 2>&1; then
            echo "error: failed to import $app_fs" >&2
            exit 1
        fi
    fi
}

# -- Phase 2: Service masking state file assertions (no boot, fast) ------------

phase2_masking() {
    log "Phase 2: Service masking state file assertions"

    # Test 1: zone auto-unmask (config default masks resolved, zone removes it)
    local ct="net-mask1"
    if sdme create --network-zone="$ZONE_NAME" -r net-ubuntu "$ct" $VFLAG 2>&1; then
        local state_file="$DATADIR/state/$ct"
        if grep -q '^MASKED_SERVICES=' "$state_file" 2>/dev/null; then
            record "mask/zone-auto-unmask" FAIL "MASKED_SERVICES should be absent, got: $(grep '^MASKED_SERVICES=' "$state_file")"
        else
            record "mask/zone-auto-unmask" PASS "MASKED_SERVICES absent as expected"
        fi
    else
        record "mask/zone-auto-unmask" FAIL "create failed"
    fi
    sdme rm -f "$ct" 2>/dev/null || true

    # Test 2: non-zone masks resolved (--private-network keeps default mask)
    ct="net-mask2"
    if sdme create --private-network -r net-ubuntu "$ct" $VFLAG 2>&1; then
        local state_file="$DATADIR/state/$ct"
        local masked
        masked=$(grep '^MASKED_SERVICES=' "$state_file" 2>/dev/null | cut -d= -f2- || true)
        if [[ "$masked" == "systemd-resolved.service" ]]; then
            record "mask/private-net-masks-resolved" PASS "MASKED_SERVICES=$masked"
        else
            record "mask/private-net-masks-resolved" FAIL "expected systemd-resolved.service, got: '$masked'"
        fi
    else
        record "mask/private-net-masks-resolved" FAIL "create failed"
    fi
    sdme rm -f "$ct" 2>/dev/null || true

    # Test 3: explicit override (--masked-services kept even with zone)
    ct="net-mask3"
    if sdme create --network-zone="$ZONE_NAME" --masked-services=systemd-resolved.service -r net-ubuntu "$ct" $VFLAG 2>&1; then
        local state_file="$DATADIR/state/$ct"
        local masked
        masked=$(grep '^MASKED_SERVICES=' "$state_file" 2>/dev/null | cut -d= -f2- || true)
        if [[ "$masked" == "systemd-resolved.service" ]]; then
            record "mask/explicit-override" PASS "MASKED_SERVICES=$masked"
        else
            record "mask/explicit-override" FAIL "expected systemd-resolved.service, got: '$masked'"
        fi
    else
        record "mask/explicit-override" FAIL "create failed"
    fi
    sdme rm -f "$ct" 2>/dev/null || true

    # Test 4: empty masks nothing (--masked-services= clears all masks)
    ct="net-mask4"
    if sdme create --masked-services= -r net-ubuntu "$ct" $VFLAG 2>&1; then
        local state_file="$DATADIR/state/$ct"
        if grep -q '^MASKED_SERVICES=' "$state_file" 2>/dev/null; then
            record "mask/empty-clears-all" FAIL "MASKED_SERVICES should be absent, got: $(grep '^MASKED_SERVICES=' "$state_file")"
        else
            record "mask/empty-clears-all" PASS "MASKED_SERVICES absent as expected"
        fi
    else
        record "mask/empty-clears-all" FAIL "create failed"
    fi
    sdme rm -f "$ct" 2>/dev/null || true
}

# -- Phase 3: Zone connectivity -----------------------------------------------

phase3_zone() {
    log "Phase 3: Zone connectivity"

    local engine="net-zengine"
    local car="net-zcar"

    # Create containers in the same zone.
    local output
    if ! output=$(sdme create --network-zone="$ZONE_NAME" -r net-nginx "$engine" $VFLAG 2>&1); then
        record "zone/http-via-ip" FAIL "create engine failed: $output"
        record "zone/resolved-running" FAIL "create engine failed"
        record "zone/llmnr-resolution" FAIL "create engine failed"
        return
    fi
    if ! output=$(sdme create --network-zone="$ZONE_NAME" -r net-ubuntu "$car" $VFLAG 2>&1); then
        record "zone/http-via-ip" FAIL "create car failed: $output"
        record "zone/resolved-running" FAIL "create car failed"
        record "zone/llmnr-resolution" FAIL "create car failed"
        sdme rm -f "$engine" 2>/dev/null || true
        return
    fi

    # Start both containers (sdme auto-enables systemd-networkd for zones).
    if ! output=$(timeout "$TIMEOUT_BOOT" sdme start "$engine" -t "$TIMEOUT_BOOT" $VFLAG 2>&1); then
        record "zone/http-via-ip" FAIL "start engine failed: $output"
        record "zone/resolved-running" FAIL "start engine failed"
        record "zone/llmnr-resolution" FAIL "start engine failed"
        sdme rm -f "$engine" 2>/dev/null || true
        sdme rm -f "$car" 2>/dev/null || true
        return
    fi
    if ! output=$(timeout "$TIMEOUT_BOOT" sdme start "$car" -t "$TIMEOUT_BOOT" $VFLAG 2>&1); then
        record "zone/http-via-ip" FAIL "start car failed: $output"
        record "zone/resolved-running" FAIL "start car failed"
        record "zone/llmnr-resolution" FAIL "start car failed"
        stop_container "$engine"
        sdme rm -f "$engine" 2>/dev/null || true
        sdme rm -f "$car" 2>/dev/null || true
        return
    fi

    # Wait for DHCP + nginx readiness.
    sleep 5

    # -- Test: HTTP via IP --
    local engine_ip
    engine_ip=$(get_container_ip "$engine")
    if [[ -z "$engine_ip" ]]; then
        record "zone/http-via-ip" FAIL "could not discover engine IP"
    else
        log "  Zone engine IP: $engine_ip"
        local http_result
        http_result=$(http_get_from "$car" "http://${engine_ip}:${APP_PORT}")
        if [[ "$http_result" == *"HTTP 200"* ]]; then
            record "zone/http-via-ip" PASS "got HTTP 200 from $engine_ip:$APP_PORT"
        else
            record "zone/http-via-ip" FAIL "expected HTTP 200, got: $http_result"
        fi
    fi

    # -- Test: resolved is running in both containers --
    local resolved_ok=true
    for ct in "$engine" "$car"; do
        if ! timeout "$TIMEOUT_TEST" sdme exec "$ct" \
            /usr/bin/systemctl is-active systemd-resolved >/dev/null 2>&1; then
            resolved_ok=false
            record "zone/resolved-running" FAIL "systemd-resolved not active in $ct"
            break
        fi
    done
    if [[ "$resolved_ok" == "true" ]]; then
        record "zone/resolved-running" PASS "systemd-resolved active in both containers"
    fi

    # -- Test: LLMNR name resolution + HTTP by name --
    # Check via exit code: machinectl shell wraps output with connection
    # messages and ANSI codes, making text matching unreliable.
    if timeout "$TIMEOUT_TEST" sdme exec "$car" \
        /usr/bin/resolvectl query "$engine" >/dev/null 2>&1; then
        # Resolution worked, try HTTP by name.
        local http_by_name
        http_by_name=$(http_get_from "$car" "http://${engine}:${APP_PORT}")
        if [[ "$http_by_name" == *"HTTP 200"* ]]; then
            record "zone/llmnr-resolution" PASS "resolved $engine by name and got HTTP 200"
        else
            record "zone/llmnr-resolution" FAIL "resolved name but HTTP failed: $http_by_name"
        fi
    else
        record "zone/llmnr-resolution" FAIL "resolvectl query $engine failed"
    fi

    # Cleanup running containers.
    stop_container "$engine"
    stop_container "$car"
    sdme rm -f "$engine" 2>/dev/null || true
    sdme rm -f "$car" 2>/dev/null || true
}

# -- Phase 4: Bridge connectivity ---------------------------------------------

phase4_bridge() {
    log "Phase 4: Bridge connectivity"

    local server="net-bserver"
    local client="net-bclient"

    # Create a host bridge with a subnet for DHCP.
    # systemd-networkd inside the container will DHCP from systemd-nspawn's
    # built-in DHCP server on this bridge.
    if ! ip link add "$BRIDGE_NAME" type bridge 2>/dev/null; then
        record "bridge/http-via-ip" SKIP "could not create bridge $BRIDGE_NAME"
        record "bridge/networkd-enabled" SKIP "could not create bridge"
        return
    fi
    ip addr add 10.99.0.1/24 dev "$BRIDGE_NAME"
    ip link set "$BRIDGE_NAME" up

    # Create containers on the bridge.
    local output
    if ! output=$(sdme create --network-bridge="$BRIDGE_NAME" -r net-nginx "$server" $VFLAG 2>&1); then
        record "bridge/http-via-ip" FAIL "create server failed: $output"
        record "bridge/networkd-enabled" FAIL "create server failed"
        return
    fi
    if ! output=$(sdme create --network-bridge="$BRIDGE_NAME" -r net-ubuntu "$client" $VFLAG 2>&1); then
        record "bridge/http-via-ip" FAIL "create client failed: $output"
        record "bridge/networkd-enabled" FAIL "create client failed"
        sdme rm -f "$server" 2>/dev/null || true
        return
    fi

    # --network-bridge doesn't provide a built-in DHCP server (unlike
    # --network-zone and --network-veth). Write static .network files
    # for host0 in each container's upper layer.
    local server_ip="10.99.0.2"
    local client_ip="10.99.0.3"
    for pair in "$server:$server_ip" "$client:$client_ip"; do
        local ct="${pair%%:*}" ip="${pair##*:}"
        local net_dir="$DATADIR/containers/$ct/upper/etc/systemd/network"
        mkdir -p "$net_dir"
        cat > "$net_dir/10-bridge.network" <<NETEOF
[Match]
Name=host0

[Network]
Address=${ip}/24
DNS=10.99.0.1
NETEOF
    done

    # Start both containers (sdme auto-enables systemd-networkd for bridges).
    if ! output=$(timeout "$TIMEOUT_BOOT" sdme start "$server" -t "$TIMEOUT_BOOT" $VFLAG 2>&1); then
        record "bridge/http-via-ip" FAIL "start server failed: $output"
        record "bridge/networkd-enabled" FAIL "start server failed"
        sdme rm -f "$server" 2>/dev/null || true
        sdme rm -f "$client" 2>/dev/null || true
        return
    fi
    if ! output=$(timeout "$TIMEOUT_BOOT" sdme start "$client" -t "$TIMEOUT_BOOT" $VFLAG 2>&1); then
        record "bridge/http-via-ip" FAIL "start client failed: $output"
        record "bridge/networkd-enabled" FAIL "start client failed"
        stop_container "$server"
        sdme rm -f "$server" 2>/dev/null || true
        sdme rm -f "$client" 2>/dev/null || true
        return
    fi

    # Wait for networkd + nginx readiness.
    sleep 5

    # -- Test: networkd is running (proves auto-enable worked) --
    if timeout "$TIMEOUT_TEST" sdme exec "$server" \
        /usr/bin/systemctl is-active systemd-networkd >/dev/null 2>&1; then
        record "bridge/networkd-enabled" PASS "systemd-networkd active in server"
    else
        record "bridge/networkd-enabled" FAIL "systemd-networkd not active in server"
    fi

    # -- Test: HTTP from client to server via static IP --
    log "  Bridge server IP: $server_ip"
    local http_result
    http_result=$(http_get_from "$client" "http://${server_ip}:${APP_PORT}")
    if [[ "$http_result" == *"HTTP 200"* ]]; then
        record "bridge/http-via-ip" PASS "got HTTP 200 from $server_ip:$APP_PORT"
    else
        record "bridge/http-via-ip" FAIL "expected HTTP 200, got: $http_result"
    fi

    # Cleanup running containers.
    stop_container "$server"
    stop_container "$client"
    sdme rm -f "$server" 2>/dev/null || true
    sdme rm -f "$client" 2>/dev/null || true
}

# -- Phase 5: Cleanup + report ------------------------------------------------

phase5_report() {
    log "Phase 5: Report"
    generate_standard_report "verify-network" "sdme Network Verification Report"
}

# -- Main ----------------------------------------------------------------------

main() {
    ensure_root
    ensure_sdme

    echo "Network verification (zones, bridges, masking)"
    echo "Zone: $ZONE_NAME  Bridge: $BRIDGE_NAME"
    echo ""

    phase1_import
    phase2_masking
    phase3_zone
    phase4_bridge

    cleanup_prefix "net-"

    phase5_report
    print_summary
}

main
