#!/usr/bin/env bash
# lib.sh - shared test helpers for sdme integration tests
#
# Source this from verify-*.sh scripts. Provides:
#   - build_and_install: build sdme and install to PATH
#   - ensure_sdme: verify sdme is in PATH (warns if version mismatches Cargo.toml)
#   - ensure_root: check we're running as root
#   - DISTRO_IMAGES: canonical distro -> OCI image mapping
#   - DISTRO_OS_PATTERN: expected OS column substring in `sdme ps`
#   - distro_bin: resolve binary path (NixOS uses /run/current-system/sw/bin)
#   - check_os: verify `sdme ps` OS column matches expected pattern
#   - fix_redis_oci: apply Redis 8.x workarounds (ARM64 COW bug, locale)
#   - ensure_base_fs: import a base rootfs if not already present
#   - ensure_default_base_fs: import ubuntu if BASE_FS is "ubuntu"
#   - cleanup_prefix: remove all containers and rootfs matching a prefix
#   - ok/fail/skipped: simple result tracking (for scripts without per-test state)
#   - record/result_status/result_msg: per-test result tracking with RESULTS map
#   - parse_standard_args: common --base-fs/--report-dir/--help arg parsing
#   - generate_standard_report: markdown report with system info and results
#   - stop_container/cleanup_container: container lifecycle helpers
#   - write_gate/check_gate/require_gate: inter-stage dependency gating
#   - scale_timeout: apply TIMEOUT_SCALE multiplier to timeout values
#
# Convention: every test script uses a unique prefix for all artifacts
# (containers, rootfs, pods). The prefix is cleaned on startup so tests
# are idempotent and don't interfere with each other or user data.
#
# Host ports that must be free before running the full test suite:
#
#   Port  Service              Used by
#   ----  -------------------  -------------------------------------------
#   3000  Gitea                verify-kube-L6-gitea-stack.sh (private net)
#   3306  MySQL                verify-kube-L6-gitea-stack.sh (private net)
#   5432  PostgreSQL           verify-usage.sh
#   6379  Redis                verify-kube-L5-redis-stack.sh (private net)
#   8080  nginx-unprivileged   verify-usage.sh,
#                              verify-distro-oci.sh (private net),
#                              verify-oci.sh (private net),
#                              verify-nixos.sh (private net),
#                              verify-kube-L4-networking.sh (private net),
#                              verify-kube-L6-gitea-stack.sh (private net),
#                              verify-kube-L2-probes.sh (private net)
#   9090  TCP probe target     verify-kube-L2-probes.sh (private net)
#   9999  pod comm test        verify-pods.sh (private net)
#
# Ports marked "(private net)" are inside containers with their own network
# namespace and do not actually bind on the host. The ports that MUST be
# free on the host are: 5432, 8080.

SDME="${SDME:-sdme}"
VERBOSE="${VERBOSE:-}"
VFLAG=""
if [[ -n "$VERBOSE" ]]; then
    VFLAG="-v"
fi

# Resolve the repo root (two levels up from test/scripts/).
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# Result counters.
_pass=0
_fail=0
_skip=0

ok() {
    echo "  [PASS] $1"
    ((_pass++)) || true
}

fail() {
    echo "  [FAIL] $1"
    ((_fail++)) || true
}

skipped() {
    echo "  [SKIP] $1"
    ((_skip++)) || true
}

print_summary() {
    local total=$((_pass + _fail + _skip))
    echo ""
    echo "Results: $_pass passed, $_fail failed, $_skip skipped (total $total)"
    if [[ $_fail -gt 0 ]]; then
        return 1
    fi
    return 0
}

# -- Timeout scaling ----------------------------------------------------------
# Set TIMEOUT_SCALE > 1 to proportionally increase all timeouts (for slow
# machines). The runner passes --timeout-scale N which exports this variable.

TIMEOUT_SCALE="${TIMEOUT_SCALE:-1}"

# Apply the timeout scale multiplier to a base value.
#   scale_timeout 600   # returns 600 * TIMEOUT_SCALE
scale_timeout() {
    local base="$1"
    echo $((base * TIMEOUT_SCALE))
}

# -- Gate system --------------------------------------------------------------
# Inter-stage dependency gating for the test runner. Gate files are written
# by early-stage scripts (preflight, smoke, interrupt) and checked by
# downstream scripts. When running standalone (no gate files), require_gate
# is a no-op so scripts remain independently runnable.
#
# The runner sets GATE_DIR to its temp directory. For standalone runs, a
# default location is used (stale gate files from a prior standalone run
# are harmless).

GATE_DIR="${GATE_DIR:-/tmp/sdme-e2e-gates}"

# Write a gate marker file.
#   write_gate <name> <pass|fail>
write_gate() {
    local name="$1" result="$2"
    mkdir -p "$GATE_DIR"
    if [[ "$result" == "pass" ]]; then
        touch "$GATE_DIR/${name}.pass"
        rm -f "$GATE_DIR/${name}.fail"
    else
        touch "$GATE_DIR/${name}.fail"
        rm -f "$GATE_DIR/${name}.pass"
    fi
}

# Check a gate.
# Returns: 0 = passed, 1 = failed, 2 = not found (standalone mode).
#   check_gate <name>
check_gate() {
    local name="$1"
    if [[ -f "$GATE_DIR/${name}.pass" ]]; then
        return 0
    elif [[ -f "$GATE_DIR/${name}.fail" ]]; then
        return 1
    else
        return 2  # gate not found (standalone mode)
    fi
}

# Require a gate to have passed. If the gate failed, skip all tests in this
# script and exit 0. If the gate is not found (standalone mode), continue.
#   require_gate <name>
require_gate() {
    local name="$1"
    local rc=0
    check_gate "$name" || rc=$?
    case $rc in
        0) return 0 ;;  # gate passed, continue
        1)
            echo "SKIPPING: gate '$name' failed"
            echo ""
            echo "Results: 0 passed, 0 failed, 0 skipped (total 0)"
            exit 0
            ;;
        2) return 0 ;;  # gate not found, standalone mode, continue
    esac
}

# -- Build and install ---------------------------------------------------------

build_and_install() {
    echo "==> Building sdme..."
    if [[ $(id -u) -eq 0 && -n "${SUDO_USER:-}" ]]; then
        # Running as root via sudo: build as the original user so that
        # rustup/cargo (which are configured per-user) work correctly.
        (cd "$REPO_ROOT" && sudo -u "$SUDO_USER" cargo build --release --quiet) || {
            echo "error: cargo build failed" >&2
            exit 1
        }
    else
        (cd "$REPO_ROOT" && cargo build --release --quiet) || {
            echo "error: cargo build failed" >&2
            exit 1
        }
    fi
    local bin="$REPO_ROOT/target/release/sdme"
    if [[ ! -x "$bin" ]]; then
        echo "error: $bin not found after build" >&2
        exit 1
    fi

    local dest
    dest=$(command -v sdme 2>/dev/null || echo "/usr/local/bin/sdme")

    # Only copy if binary differs.
    if ! cmp -s "$bin" "$dest" 2>/dev/null; then
        echo "==> Installing sdme to $dest"
        rm -f "$dest" 2>/dev/null || true
        cp "$bin" "$dest"
    fi

    echo "==> sdme $(sdme --version 2>&1 | awk '{print $2}')"
}

# -- Preflight checks ---------------------------------------------------------

ensure_sdme() {
    if ! command -v "$SDME" &>/dev/null; then
        echo "error: sdme not found in PATH; run build_and_install first" >&2
        exit 1
    fi
    # Warn if installed version doesn't match Cargo.toml.
    local cargo_ver installed_ver
    cargo_ver=$(sed -n 's/^version = "\(.*\)"/\1/p' "$REPO_ROOT/Cargo.toml" 2>/dev/null || true)
    installed_ver=$("$SDME" --version 2>&1 | awk '{print $2}' || true)
    if [[ -n "$cargo_ver" && -n "$installed_ver" && "$cargo_ver" != "$installed_ver" ]]; then
        echo "warning: sdme version mismatch: installed=$installed_ver, Cargo.toml=$cargo_ver" >&2
    fi
}

ensure_root() {
    if [[ $(id -u) -ne 0 ]]; then
        echo "error: must run as root" >&2
        exit 1
    fi
}

# -- Distro data --------------------------------------------------------------
# Canonical distro -> OCI image mapping. Test scripts reference this instead
# of maintaining their own copies.

declare -A DISTRO_IMAGES=(
    [debian]="docker.io/debian:stable"
    [ubuntu]="docker.io/ubuntu:24.04"
    [fedora]="quay.io/fedora/fedora:41"
    [centos]="quay.io/centos/centos:stream10"
    [almalinux]="quay.io/almalinuxorg/almalinux:9"
    [archlinux]="docker.io/lopsided/archlinux:latest"
    [opensuse]="registry.opensuse.org/opensuse/tumbleweed:latest"
    [nixos]="docker.io/nixos/nix"
)

# Expected OS column substring in `sdme ps` output for each distro.
declare -A DISTRO_OS_PATTERN=(
    [debian]="Debian"
    [ubuntu]="Ubuntu"
    [fedora]="Fedora"
    [centos]="CentOS"
    [almalinux]="AlmaLinux"
    [archlinux]="Arch Linux"
    [opensuse]="openSUSE Tumbleweed"
)

# NixOS puts binaries under /run/current-system/sw/bin instead of /usr/bin.
distro_bin() {
    local distro="$1" cmd="$2"
    if [[ "$distro" == "nixos" ]]; then
        echo "/run/current-system/sw/bin/$cmd"
    else
        echo "/usr/bin/$cmd"
    fi
}

# Check that `sdme ps` shows the expected OS pattern for a container.
#   check_os <container_name> <distro>
# Returns 0 on match, 1 on mismatch. On mismatch, prints the actual OS value.
check_os() {
    local ct_name="$1" distro="$2"
    local pattern="${DISTRO_OS_PATTERN[$distro]}"
    local os_col
    os_col=$($SDME ps 2>/dev/null | awk -v name="$ct_name" '$1 == name {
        # OS is the 4th column, but it may contain spaces (e.g. "Arch Linux").
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

# Redis 8.x workarounds for container environments:
# - ARM64: tests for a kernel COW bug, fails inside containers, and exits.
#   Suppress with --ignore-warnings ARM64-COW-BUG.
# - Locale: redis treats locale config failure as fatal. The OCI root may
#   lack the host container's locale (e.g. en_US.UTF-8 on archlinux).
#   Force LANG=C.UTF-8 which is universally available.
#
#   fix_redis_oci <container_name> [distro]
fix_redis_oci() {
    local ct_name="$1" distro="${2:-}"
    local datadir="/var/lib/sdme"
    # NixOS replaces /etc/systemd/system with an immutable symlink;
    # drop-ins must go to system.control instead.
    local unit_dir="etc/systemd/system"
    if [[ "$distro" == "nixos" ]]; then
        unit_dir="etc/systemd/system.control"
    fi
    local svc_dir="$datadir/containers/$ct_name/upper/$unit_dir/sdme-oci-redis.service.d"
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

# -- Rootfs management ---------------------------------------------------------

# Import a base rootfs if it doesn't exist. Idempotent (OCI cache makes
# re-imports fast).
#   ensure_base_fs <name> <image>
ensure_base_fs() {
    local name="$1" image="$2"
    if sdme fs ls 2>/dev/null | awk 'NR>1 {print $1}' | grep -qx "$name"; then
        return 0
    fi
    echo "==> Importing base rootfs '$name' from $image"
    if ! sdme fs import "$name" "$image" -v --install-packages=yes -f 2>&1; then
        echo "error: failed to import $name" >&2
        return 1
    fi
}

# Import default base rootfs when BASE_FS is "ubuntu" (the common case).
ensure_default_base_fs() {
    if [[ "${BASE_FS:-}" == "ubuntu" ]]; then
        ensure_base_fs ubuntu "${DISTRO_IMAGES[ubuntu]}"
    fi
}

# -- Per-test result tracking -------------------------------------------------
# Use record()/result_status()/result_msg() for scripts that track individual
# test results and generate reports. For simpler scripts, ok()/fail()/skipped()
# above are sufficient.

declare -A RESULTS

record() {
    local test_name="$1" result="$2" msg="${3:-}"
    RESULTS["$test_name"]="$result|$msg"
    case "$result" in
        PASS) ((_pass++)) || true; echo "  [PASS] $test_name${msg:+: $msg}" ;;
        FAIL) ((_fail++)) || true; echo "  [FAIL] $test_name${msg:+: $msg}" ;;
        SKIP) ((_skip++)) || true; echo "  [SKIP] $test_name${msg:+: $msg}" ;;
    esac
}

result_status() {
    echo "${RESULTS[$1]%%|*}"
}

result_msg() {
    echo "${RESULTS[$1]#*|}"
}

# -- Standard argument parsing ------------------------------------------------
# For scripts with the common --base-fs / --report-dir / --help flags.
#   parse_standard_args "Description of the test." "$@"

parse_standard_args() {
    local desc="$1"
    shift
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --base-fs)  shift; BASE_FS="$1" ;;
            --report-dir) shift; REPORT_DIR="$1" ;;
            --help)
                echo "Usage: $(basename "$0") [OPTIONS]"
                echo ""
                echo "$desc"
                echo "Must be run as root."
                echo ""
                echo "Options:"
                echo "  --base-fs NAME   Base rootfs to use (default: ubuntu)"
                echo "  --report-dir DIR Write report to DIR (default: .)"
                echo "  --help           Show help"
                exit 0
                ;;
            *) echo "unknown option: $1" >&2; exit 1 ;;
        esac
        shift
    done
}

# -- Standard report generation -----------------------------------------------
# Generates a markdown report with system info, summary, results table, and
# failure details. Reads from RESULTS, _pass, _fail, _skip.
#   generate_standard_report <report-prefix> <title>

generate_standard_report() {
    local report_prefix="$1" title="$2"
    local ts
    ts=$(date +%Y%m%d-%H%M%S)
    local report="$REPORT_DIR/${report_prefix}-${ts}.md"

    mkdir -p "$REPORT_DIR"

    {
        echo "# $title"
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
        if [[ -n "${BASE_FS:-}" ]]; then
            echo "| Base FS | $BASE_FS |"
        fi
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
        echo "| Test | Result |"
        echo "|------|--------|"
        for key in $(echo "${!RESULTS[@]}" | tr ' ' '\n' | sort); do
            echo "| $key | $(result_status "$key") |"
        done
        echo ""

        # Failures section.
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

    echo "Report: $report"
}

# -- Cleanup helpers -----------------------------------------------------------

# Stop and remove a single container.
stop_container() {
    timeout 30 "$SDME" stop "$1" 2>/dev/null || \
        timeout 30 "$SDME" stop --term "$1" 2>/dev/null || true
}

cleanup_container() {
    stop_container "$1"
    "$SDME" rm -f "$1" 2>/dev/null || true
}

# Remove all containers, rootfs, and pods matching a prefix.
#   cleanup_prefix <prefix>
cleanup_prefix() {
    local prefix="$1"
    local names

    # Stop and remove containers.
    names=$($SDME ps 2>/dev/null | awk 'NR>1 {print $1}' | grep "^${prefix}" || true)
    for name in $names; do
        cleanup_container "$name"
    done

    # Remove rootfs (including kube- prefixed rootfs for kube containers).
    names=$($SDME fs ls 2>/dev/null | awk 'NR>1 {print $1}' | grep -E "^(${prefix}|kube-${prefix})" || true)
    for name in $names; do
        $SDME fs rm -f "$name" 2>/dev/null || true
    done

    # Remove pods.
    names=$($SDME pod ls 2>/dev/null | awk 'NR>1 {print $1}' | grep "^${prefix}" || true)
    for name in $names; do
        $SDME pod rm -f "$name" 2>/dev/null || true
    done

    # Remove kube secrets and configmaps.
    names=$($SDME kube secret ls 2>/dev/null | awk 'NR>1 {print $1}' | grep "^${prefix}" || true)
    for name in $names; do
        $SDME kube secret rm "$name" 2>/dev/null || true
    done
    names=$($SDME kube configmap ls 2>/dev/null | awk 'NR>1 {print $1}' | grep "^${prefix}" || true)
    for name in $names; do
        $SDME kube configmap rm "$name" 2>/dev/null || true
    done
}

# Check if a rootfs exists.
fs_exists() {
    $SDME fs ls 2>/dev/null | awk 'NR>1 {print $1}' | grep -qx "$1"
}

# Derive OCI service name from image reference.
# e.g. "docker.io/nginxinc/nginx-unprivileged" -> "sdme-oci-nginx-unprivileged.service"
oci_service_name() {
    local image="${1%%:*}"
    local last="${image##*/}"
    local name="${last//_/-}"
    echo "sdme-oci-${name}.service"
}
