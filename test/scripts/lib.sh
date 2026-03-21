#!/usr/bin/env bash
# lib.sh - shared test helpers for sdme integration tests
#
# Source this from verify-*.sh scripts. Provides:
#   - build_and_install: build sdme and install to PATH
#   - ensure_sdme: verify sdme is in PATH and matches the repo version
#   - ensure_root: check we're running as root
#   - DISTRO_IMAGES: canonical distro → OCI image mapping
#   - ensure_base_fs: import a base rootfs if not already present
#   - ensure_default_base_fs: import ubuntu if BASE_FS is "ubuntu"
#   - cleanup_prefix: remove all containers and rootfs matching a prefix
#   - ok/fail/skipped: simple result tracking (for scripts without per-test state)
#   - record/result_status/result_msg: per-test result tracking with RESULTS map
#   - parse_standard_args: common --base-fs/--report-dir/--help arg parsing
#   - generate_standard_report: markdown report with system info and results
#   - stop_container/cleanup_container: container lifecycle helpers
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
#                              verify-matrix.sh (private net),
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

# -- Build and install ---------------------------------------------------------

build_and_install() {
    echo "==> Building sdme..."
    (cd "$REPO_ROOT" && cargo build --release --quiet) || {
        echo "error: cargo build failed" >&2
        exit 1
    }
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
}

ensure_root() {
    if [[ $(id -u) -ne 0 ]]; then
        echo "error: must run as root" >&2
        exit 1
    fi
}

# Canonical distro → OCI image mapping. Test scripts reference this instead
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
