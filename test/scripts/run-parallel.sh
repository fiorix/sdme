#!/usr/bin/env bash
set -uo pipefail

# run-parallel.sh - parallel e2e test runner for sdme
#
# Runs all verify-*.sh tests with maximum parallelism while respecting
# resource constraints (host ports, shared secrets/configmaps).
#
# Usage:
#   sudo ./test/scripts/run-parallel.sh [OPTIONS]
#
# Grouping:
#   - 17 tests run in parallel (bounded by --jobs)
#   - kube-L3-secrets + kube-L3-volumes run as a serial pair within the wave
#   - verify-usage.sh runs LAST (its batch ops affect all containers)

source "$(dirname "$0")/lib.sh"

# -- Defaults -----------------------------------------------------------------

MAX_JOBS=8
REPORT_DIR="./test-reports"
BASE_FS="ubuntu"
DO_SETUP=1
SKIP_SCRIPTS=()
ONLY_SCRIPTS=()

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
START_TIME=""
TMPDIR_RUN=""
FIFO=""
CHILD_PIDS=()

# -- Usage --------------------------------------------------------------------

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Parallel e2e test runner for sdme.
Must be run as root.

Options:
  --jobs N           Max parallel jobs (default: $MAX_JOBS)
  --report-dir DIR   Report output directory (default: $REPORT_DIR)
  --base-fs NAME     Base rootfs name (default: $BASE_FS)
  --skip SCRIPT      Skip a script (repeatable, basename without .sh)
  --only SCRIPT      Run only these scripts (repeatable)
  --no-setup         Skip build + base rootfs import
  -v, --verbose      Show test output in real time
  --help             Show help

Examples:
  sudo $0                                    # run all tests, 8 jobs
  sudo $0 --jobs 4                           # limit to 4 parallel jobs
  sudo $0 --only verify-export --only verify-interrupt --jobs 2
  sudo $0 --skip verify-matrix --skip verify-nixos   # skip slow tests
EOF
}

# -- Argument parsing ---------------------------------------------------------

parse_runner_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --jobs)     shift; MAX_JOBS="$1" ;;
            --report-dir) shift; REPORT_DIR="$1" ;;
            --base-fs)  shift; BASE_FS="$1" ;;
            --skip)     shift; SKIP_SCRIPTS+=("$1") ;;
            --only)     shift; ONLY_SCRIPTS+=("$1") ;;
            --no-setup) DO_SETUP=0 ;;
            # shellcheck disable=SC2034  # VFLAG is used by lib.sh helpers
            -v|--verbose) VERBOSE=1; VFLAG="-v" ;;
            --help)     usage; exit 0 ;;
            *)          echo "error: unknown option: $1" >&2; usage >&2; exit 1 ;;
        esac
        shift
    done
}

# -- Helpers ------------------------------------------------------------------

log() { echo "==> $*"; }

now_epoch() { date +%s; }

fmt_duration() {
    local secs="$1"
    if [[ $secs -ge 3600 ]]; then
        printf '%dh%02dm%02ds' $((secs/3600)) $(((secs%3600)/60)) $((secs%60))
    elif [[ $secs -ge 60 ]]; then
        printf '%dm%02ds' $((secs/60)) $((secs%60))
    else
        printf '%ds' "$secs"
    fi
}

# Check if a script should be skipped.
should_run() {
    local name="$1"
    # --only filter
    if [[ ${#ONLY_SCRIPTS[@]} -gt 0 ]]; then
        local found=0
        for s in "${ONLY_SCRIPTS[@]}"; do
            if [[ "$s" == "$name" || "$s" == "${name}.sh" ]]; then
                found=1
                break
            fi
        done
        [[ $found -eq 0 ]] && return 1
    fi
    # --skip filter
    for s in "${SKIP_SCRIPTS[@]}"; do
        if [[ "$s" == "$name" || "$s" == "${name}.sh" ]]; then
            return 1
        fi
    done
    return 0
}

# Build the args to pass to each test script.
test_args() {
    local script_name="$1"
    local args="--report-dir $REPORT_DIR"
    case "$script_name" in
        verify-matrix.sh|verify-export.sh|verify-usage.sh|verify-oci.sh|verify-nixos.sh|verify-security.sh|verify-pods.sh)
            # These scripts don't accept --base-fs (custom or no arg parser).
            ;;
        *)
            args="$args --base-fs $BASE_FS"
            ;;
    esac
    echo "$args"
}

# -- Semaphore ----------------------------------------------------------------

init_semaphore() {
    FIFO="$TMPDIR_RUN/semaphore"
    mkfifo "$FIFO"
    exec 3<>"$FIFO"
    for _ in $(seq 1 "$MAX_JOBS"); do
        echo >&3
    done
}

# -- Job management -----------------------------------------------------------

# Run a single test script with semaphore-limited concurrency.
run_test() {
    local script="$1"
    local name
    name=$(basename "$script" .sh)
    local logfile="$TMPDIR_RUN/${name}.log"
    local timefile="$TMPDIR_RUN/${name}.time"
    local rcfile="$TMPDIR_RUN/${name}.rc"
    local args
    args=$(test_args "$(basename "$script")")

    read -r -u 3  # acquire semaphore slot
    (
        now_epoch > "$timefile"
        log "[$name] started"
        # shellcheck disable=SC2086
        "$script" $args >"$logfile" 2>&1
        local rc=$?
        echo "$rc" > "$rcfile"
        now_epoch >> "$timefile"
        if [[ $rc -eq 0 ]]; then
            log "[$name] PASSED ($(fmt_duration $(( $(tail -1 "$timefile") - $(head -1 "$timefile") ))))"
        else
            log "[$name] FAILED ($(fmt_duration $(( $(tail -1 "$timefile") - $(head -1 "$timefile") ))))"
        fi
        echo >&3  # release semaphore slot
    ) &
    CHILD_PIDS+=($!)
}

# Run a group of tests sequentially, occupying one semaphore slot.
run_serial_group() {
    local group_name="$1"
    shift
    local scripts=("$@")

    read -r -u 3  # acquire one semaphore slot for the entire group
    (
        log "[serial:$group_name] started"
        for script in "${scripts[@]}"; do
            local name
            name=$(basename "$script" .sh)
            local logfile="$TMPDIR_RUN/${name}.log"
            local timefile="$TMPDIR_RUN/${name}.time"
            local rcfile="$TMPDIR_RUN/${name}.rc"
            local args
            args=$(test_args "$(basename "$script")")

            now_epoch > "$timefile"
            log "[$name] started (serial:$group_name)"
            # shellcheck disable=SC2086
            "$script" $args >"$logfile" 2>&1
            local rc=$?
            echo "$rc" > "$rcfile"
            now_epoch >> "$timefile"
            if [[ $rc -eq 0 ]]; then
                log "[$name] PASSED ($(fmt_duration $(( $(tail -1 "$timefile") - $(head -1 "$timefile") ))))"
            else
                log "[$name] FAILED ($(fmt_duration $(( $(tail -1 "$timefile") - $(head -1 "$timefile") ))))"
            fi
        done
        log "[serial:$group_name] done"
        echo >&3  # release semaphore slot
    ) &
    CHILD_PIDS+=($!)
}

# -- Signal handling ----------------------------------------------------------

cleanup_runner() {
    log "Cleaning up..."
    # Kill all child processes.
    for pid in "${CHILD_PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    # Close the semaphore fd.
    exec 3>&- 2>/dev/null || true
    rm -rf "$TMPDIR_RUN" 2>/dev/null || true
}

# -- Report aggregation -------------------------------------------------------

aggregate_reports() {
    local end_time
    end_time=$(now_epoch)
    local total_duration=$((end_time - START_TIME))

    local summary
    summary="$REPORT_DIR/summary-$(date +%Y%m%d-%H%M%S).md"

    local total_pass=0 total_fail=0 total_skip=0
    local any_failed=0

    {
        echo "# sdme E2E Test Summary"
        echo ""
        echo "## Execution"
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
        echo "| Parallel jobs | $MAX_JOBS |"
        echo "| Wall clock | $(fmt_duration $total_duration) |"
        echo ""

        echo "## Results by Script"
        echo ""
        echo "| Script | Pass | Fail | Skip | Duration | Status |"
        echo "|--------|------|------|------|----------|--------|"

        for logfile in "$TMPDIR_RUN"/*.log; do
            [[ -f "$logfile" ]] || continue
            local name
            name=$(basename "$logfile" .log)
            local rcfile="$TMPDIR_RUN/${name}.rc"
            local timefile="$TMPDIR_RUN/${name}.time"

            # Parse results from the log's last "Results:" line.
            local results_line
            results_line=$(grep -E '^Results: ' "$logfile" | tail -1 || true)
            local p=0 f=0 s=0
            if [[ -n "$results_line" ]]; then
                p=$(echo "$results_line" | grep -oP '\d+ passed' | grep -oP '\d+' || echo 0)
                f=$(echo "$results_line" | grep -oP '\d+ failed' | grep -oP '\d+' || echo 0)
                s=$(echo "$results_line" | grep -oP '\d+ skipped' | grep -oP '\d+' || echo 0)
            fi
            total_pass=$((total_pass + p))
            total_fail=$((total_fail + f))
            total_skip=$((total_skip + s))

            # Exit code and duration.
            local rc="?"
            [[ -f "$rcfile" ]] && rc=$(cat "$rcfile")
            local dur="-"
            if [[ -f "$timefile" ]] && [[ $(wc -l < "$timefile") -ge 2 ]]; then
                local t0 t1
                t0=$(head -1 "$timefile")
                t1=$(tail -1 "$timefile")
                dur=$(fmt_duration $((t1 - t0)))
            fi

            local status="PASS"
            if [[ "$rc" != "0" ]]; then
                status="FAIL"
                any_failed=1
            fi

            echo "| $name | $p | $f | $s | $dur | $status |"
        done

        echo ""
        echo "## Totals"
        echo ""
        local grand_total=$((total_pass + total_fail + total_skip))
        echo "| Result | Count |"
        echo "|--------|-------|"
        echo "| PASS | $total_pass |"
        echo "| FAIL | $total_fail |"
        echo "| SKIP | $total_skip |"
        echo "| Total | $grand_total |"
        echo ""

        # List any failures with log excerpts.
        if [[ $any_failed -eq 1 ]]; then
            echo "## Failures"
            echo ""
            for logfile in "$TMPDIR_RUN"/*.log; do
                [[ -f "$logfile" ]] || continue
                local name
                name=$(basename "$logfile" .log)
                local rcfile="$TMPDIR_RUN/${name}.rc"
                local rc="?"
                [[ -f "$rcfile" ]] && rc=$(cat "$rcfile")
                if [[ "$rc" != "0" ]]; then
                    echo "### $name"
                    echo ""
                    echo '```'
                    tail -20 "$logfile"
                    echo '```'
                    echo ""
                fi
            done
        fi
    } > "$summary"

    log "Summary report: $summary"
    return $any_failed
}

# -- Main ---------------------------------------------------------------------

main() {
    parse_runner_args "$@"
    ensure_root

    TMPDIR_RUN=$(mktemp -d /tmp/sdme-test-run-XXXXXX)
    trap cleanup_runner EXIT INT TERM

    mkdir -p "$REPORT_DIR"

    # -- Setup phase --
    if [[ $DO_SETUP -eq 1 ]]; then
        log "Setup: building and installing sdme"
        build_and_install

        log "Setup: importing $BASE_FS base rootfs"
        ensure_base_fs "$BASE_FS" "${DISTRO_IMAGES[$BASE_FS]}"
    else
        ensure_sdme
    fi

    START_TIME=$(now_epoch)
    init_semaphore

    log "Starting tests (max $MAX_JOBS parallel jobs)"
    echo ""

    # -- Parallel wave: tests with no host port conflicts --
    local parallel_tests=(
        verify-export.sh
        verify-interrupt.sh
        verify-build.sh
        verify-security.sh
        verify-pods.sh
        verify-network.sh
        verify-oci.sh
        verify-nixos.sh
        verify-matrix.sh
        verify-kube-L1-basic.sh
        verify-kube-L2-spec.sh
        verify-kube-L2-security.sh
        verify-kube-L2-probes.sh
        verify-kube-L4-networking.sh
        verify-kube-L5-redis-stack.sh
        verify-kube-L6-gitea-stack.sh
    )

    local _launch_count=0
    for script_name in "${parallel_tests[@]}"; do
        local name="${script_name%.sh}"
        if should_run "$name"; then
            # Stagger launches by 2s to avoid Docker Hub rate limiting
            # when many tests pull OCI images simultaneously.
            if [[ $_launch_count -gt 0 ]]; then
                sleep 2
            fi
            run_test "$SCRIPT_DIR/$script_name"
            ((_launch_count++)) || true
        fi
    done

    # -- Serial pair: kube L3 secrets then volumes (shared secret names) --
    local kube_l3_scripts=()
    if should_run "verify-kube-L3-secrets"; then
        kube_l3_scripts+=("$SCRIPT_DIR/verify-kube-L3-secrets.sh")
    fi
    if should_run "verify-kube-L3-volumes"; then
        kube_l3_scripts+=("$SCRIPT_DIR/verify-kube-L3-volumes.sh")
    fi
    if [[ ${#kube_l3_scripts[@]} -gt 0 ]]; then
        if [[ ${#kube_l3_scripts[@]} -eq 1 ]]; then
            run_test "${kube_l3_scripts[0]}"
        else
            run_serial_group "kube-l3" "${kube_l3_scripts[@]}"
        fi
    fi

    # -- Wait for parallel wave --
    log "Waiting for parallel tests to complete..."
    local overall_rc=0
    for pid in "${CHILD_PIDS[@]}"; do
        wait "$pid" 2>/dev/null || overall_rc=1
    done

    # -- verify-usage.sh runs LAST --
    # Its batch tests (sdme stop --all, sdme rm --all) affect ALL containers
    # system-wide, so it must run after everything else finishes.
    if should_run "verify-usage"; then
        CHILD_PIDS=()
        run_test "$SCRIPT_DIR/verify-usage.sh"
        for pid in "${CHILD_PIDS[@]}"; do
            wait "$pid" 2>/dev/null || overall_rc=1
        done
    fi

    echo ""

    # -- Aggregate reports --
    aggregate_reports || overall_rc=1

    # -- Print summary --
    local end_time
    end_time=$(now_epoch)
    local total_duration=$((end_time - START_TIME))

    echo ""
    log "All tests completed in $(fmt_duration $total_duration)"

    if [[ $overall_rc -ne 0 ]]; then
        log "SOME TESTS FAILED"
        # Show verbose output of failed tests if not already showing.
        if [[ -z "$VERBOSE" ]]; then
            echo ""
            for logfile in "$TMPDIR_RUN"/*.log; do
                [[ -f "$logfile" ]] || continue
                local name
                name=$(basename "$logfile" .log)
                local rcfile="$TMPDIR_RUN/${name}.rc"
                local rc="?"
                [[ -f "$rcfile" ]] && rc=$(cat "$rcfile")
                if [[ "$rc" != "0" ]]; then
                    echo "--- $name (last 10 lines) ---"
                    tail -10 "$logfile"
                    echo ""
                fi
            done
        fi
        exit 1
    else
        log "ALL TESTS PASSED"
        exit 0
    fi
}

main "$@"
