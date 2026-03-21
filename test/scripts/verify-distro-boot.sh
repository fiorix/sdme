#!/usr/bin/env bash
set -uo pipefail

# verify-distro-boot.sh - end-to-end verification of distro boot and hardened boot
#
# Tests boot and hardened boot across 7 distros:
#   Phase 1: Import base OS rootfs (7 distros)
#   Phase 2: Boot tests per distro (create, start, systemd, journalctl, systemctl, OS detection)
#   Phase 3: Hardened boot tests per distro (create --hardened, start, systemd)
#   Phase 4: Cleanup
#
# All artifacts use the "vfy-dboot-" prefix.

source "$(dirname "$0")/lib.sh"

DISTROS=(debian ubuntu fedora centos almalinux archlinux opensuse)
REPORT_DIR="."
FILTER_DISTROS=()

TIMEOUT_IMPORT=$(scale_timeout 600)
TIMEOUT_BOOT=$(scale_timeout 120)
TIMEOUT_TEST=$(scale_timeout 300)

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

End-to-end verification of distro boot and hardened boot.
Must be run as root.

Options:
  --distro NAME    Only test this distro (repeatable)
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

    # Apply filters
    if [[ ${#FILTER_DISTROS[@]} -gt 0 ]]; then
        DISTROS=("${FILTER_DISTROS[@]}")
    fi
}

log() { echo "==> $*"; }

cleanup() { cleanup_prefix vfy-dboot-; }

trap cleanup EXIT INT TERM

# -- Phase 1: Import base OS rootfs --------------------------------------------

phase1_import() {
    log "Phase 1: Import base OS rootfs"
    for distro in "${DISTROS[@]}"; do
        local fs_name="vfy-dboot-$distro"
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
        local fs_name="vfy-dboot-$distro"
        local ct_name="vfy-dboot-boot-$distro"

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
        local systemctl journalctl
        systemctl=$(distro_bin "$distro" systemctl)
        journalctl=$(distro_bin "$distro" journalctl)

        if output=$(timeout "$TIMEOUT_TEST" sdme exec "$ct_name" "$systemctl" is-system-running --wait 2>&1); then
            record "boot/$distro/systemd" PASS
        else
            record "boot/$distro/systemd" FAIL "$output"
        fi

        # journalctl
        if output=$(timeout "$TIMEOUT_TEST" sdme exec "$ct_name" "$journalctl" --no-pager -n 5 2>&1); then
            record "boot/$distro/journalctl" PASS
        else
            record "boot/$distro/journalctl" FAIL "$output"
        fi

        # systemctl list-units
        if output=$(timeout "$TIMEOUT_TEST" sdme exec "$ct_name" "$systemctl" list-units --no-pager -q 2>&1); then
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

# -- Phase 3: Hardened boot tests ----------------------------------------------

phase3_hardened_boot() {
    log "Phase 3: Hardened boot tests"
    for distro in "${DISTROS[@]}"; do
        local fs_name="vfy-dboot-$distro"
        local ct_name="vfy-dboot-h-boot-$distro"

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
        local systemctl
        systemctl=$(distro_bin "$distro" systemctl)
        if output=$(timeout "$TIMEOUT_TEST" sdme exec "$ct_name" "$systemctl" is-system-running --wait 2>&1); then
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

# -- Report generation ---------------------------------------------------------

generate_report() {
    local ts
    ts=$(date +%Y%m%d-%H%M%S)
    local report="$REPORT_DIR/verify-distro-boot-$ts.md"

    log "Writing report to $report"

    mkdir -p "$REPORT_DIR"

    {
        echo "# sdme Distro Boot Verification Report"
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

        # Boot tests table
        echo "## Boot Tests"
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

        # Hardened boot table
        echo "## Hardened Boot Tests"
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

    echo "Distro boot verification: ${#DISTROS[@]} distros"
    echo "Distros: ${DISTROS[*]}"
    echo ""

    phase1_import
    phase2_boot
    phase3_hardened_boot
    generate_report

    echo ""
    echo "Results: $_pass passed, $_fail failed, $_skip skipped"

    if [[ $_fail -gt 0 ]]; then
        exit 1
    fi
}

main "$@"
