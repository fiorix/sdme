#!/usr/bin/env bash
set -euo pipefail

# preflight.sh - validate the test environment before running e2e tests
#
# Checks required and optional dependencies, kernel features, disk space,
# host ports, and registry connectivity. Exits 0 if all required checks
# pass, 1 otherwise. Writes a gate file for the runner.
#
# Usage:
#   sudo ./test/scripts/preflight.sh

source "$(dirname "$0")/lib.sh"

_req_pass=0
_req_fail=0
_opt_pass=0
_opt_warn=0

log() { echo "==> $*"; }

req_ok() {
    echo "  [OK]   $1"
    ((_req_pass++)) || true
}

req_fail() {
    echo "  [FAIL] $1"
    ((_req_fail++)) || true
}

opt_ok() {
    echo "  [OK]   $1 (optional)"
    ((_opt_pass++)) || true
}

opt_warn() {
    echo "  [WARN] $1 (optional)"
    ((_opt_warn++)) || true
}

# Check if a binary exists in PATH.
has_binary() { command -v "$1" &>/dev/null; }

# -- Required checks ----------------------------------------------------------

log "Required checks"

# Root
if [[ $(id -u) -eq 0 ]]; then
    req_ok "running as root"
else
    req_fail "not running as root (euid=$(id -u))"
fi

# sdme binary
if has_binary sdme; then
    local_ver=$(sdme --version 2>&1 | awk '{print $2}' || true)
    req_ok "sdme in PATH ($local_ver)"
elif [[ -x "$REPO_ROOT/target/release/sdme" ]]; then
    req_ok "sdme found at target/release/sdme (not yet in PATH)"
else
    req_fail "sdme not found in PATH or target/release/"
fi

# systemd version >= 252
if has_binary systemctl; then
    sd_ver_str=$(systemctl --version 2>/dev/null | head -1 || true)
    sd_ver=$(echo "$sd_ver_str" | grep -oP '\d+' | head -1 || true)
    if [[ -n "$sd_ver" && "$sd_ver" -ge 252 ]]; then
        req_ok "systemd >= 252 ($sd_ver_str)"
    else
        req_fail "systemd >= 252 required (found: ${sd_ver_str:-unknown})"
    fi
else
    req_fail "systemctl not found"
fi

# Required binaries
for bin in systemd-nspawn machinectl nsenter busctl journalctl; do
    if has_binary "$bin"; then
        req_ok "$bin"
    else
        req_fail "$bin not found in PATH"
    fi
done

# Kernel overlayfs support
if [[ -d /sys/module/overlay ]]; then
    req_ok "kernel overlayfs module loaded"
elif modprobe overlay 2>/dev/null; then
    req_ok "kernel overlayfs module loaded (via modprobe)"
else
    req_fail "kernel overlayfs module not available"
fi

# Disk space (>= 10 GB free on /var/lib/sdme filesystem)
sdme_dir="/var/lib/sdme"
if [[ -d "$sdme_dir" ]]; then
    fs_mount="$sdme_dir"
else
    fs_mount="/var/lib"
fi
avail_kb=$(df -P "$fs_mount" 2>/dev/null | awk 'NR==2 {print $4}' || echo 0)
avail_gb=$((avail_kb / 1048576))
if [[ $avail_gb -ge 10 ]]; then
    req_ok "disk space: ${avail_gb} GB free on $fs_mount"
else
    req_fail "disk space: ${avail_gb} GB free on $fs_mount (need >= 10 GB)"
fi

echo ""

# -- Optional checks -----------------------------------------------------------

log "Optional checks"

# sdme version match
cargo_ver=$(sed -n 's/^version = "\(.*\)"/\1/p' "$REPO_ROOT/Cargo.toml" 2>/dev/null || true)
if has_binary sdme; then
    installed_ver=$(sdme --version 2>&1 | awk '{print $2}' || true)
    if [[ -n "$cargo_ver" && "$cargo_ver" == "$installed_ver" ]]; then
        opt_ok "sdme version matches Cargo.toml ($cargo_ver)"
    elif [[ -n "$cargo_ver" ]]; then
        opt_warn "sdme version mismatch: installed=$installed_ver, Cargo.toml=$cargo_ver"
    fi
fi

# Optional binaries
for bin in mkfs.ext4 mkfs.btrfs zstdcat kubeconform qemu-nbd sfdisk mkswap; do
    if has_binary "$bin"; then
        opt_ok "$bin"
    else
        opt_warn "$bin not found (some tests will be skipped)"
    fi
done

# Host ports (5432, 8080)
for port in 5432 8080; do
    if has_binary ss; then
        if ss -tlnp 2>/dev/null | grep -q ":${port} "; then
            opt_warn "port $port already bound (some tests may fail)"
        else
            opt_ok "port $port is free"
        fi
    else
        opt_warn "ss not found, cannot check port $port"
    fi
done

# Docker Hub connectivity
if has_binary curl; then
    if curl -sI --connect-timeout 5 --max-time 10 \
            https://registry-1.docker.io/v2/ >/dev/null 2>&1; then
        opt_ok "Docker Hub reachable"
    else
        opt_warn "Docker Hub not reachable (OCI imports may fail)"
    fi
else
    opt_warn "curl not found, cannot check Docker Hub connectivity"
fi

# AppArmor
if [[ -d /sys/kernel/security/apparmor ]]; then
    if has_binary aa-status; then
        if aa-status 2>/dev/null | grep -q "sdme-default"; then
            opt_ok "AppArmor active, sdme-default profile loaded"
        else
            opt_warn "AppArmor active but sdme-default profile not loaded"
        fi
    else
        opt_warn "AppArmor active but aa-status not found"
    fi
else
    opt_warn "AppArmor not active"
fi

echo ""

# -- Summary -------------------------------------------------------------------

log "Preflight summary"
echo "  Required: $_req_pass passed, $_req_fail failed"
echo "  Optional: $_opt_pass passed, $_opt_warn warnings"
echo ""

if [[ $_req_fail -gt 0 ]]; then
    echo "PREFLIGHT FAILED: $_req_fail required check(s) failed"
    write_gate preflight fail
    exit 1
else
    echo "PREFLIGHT PASSED"
    write_gate preflight pass
    exit 0
fi
