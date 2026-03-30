#!/usr/bin/env bash
set -uo pipefail

# run-parallel.sh - staged parallel e2e test runner for sdme
#
# Runs all verify-*.sh tests with staged execution and controlled parallelism.
#
# Stages:
#   0. Preflight: validate environment (systemd, binaries, disk, ports)
#   1. Setup + Smoke + Interrupt: build, import base-fs, smoke test, interrupt test
#   2. Parallel tests:
#      Wave A: core tests + kube-L1 (semaphore-bounded)
#      Wave B: kube L2+ (launched after L1 completes, only if L1 passed)
#   3. Destructive: verify-tutorial.sh (batch ops affect all containers)
#
# Usage:
#   sudo ./test/scripts/run-parallel.sh [OPTIONS]

source "$(dirname "$0")/lib.sh"

# -- Defaults -----------------------------------------------------------------

MAX_JOBS=8
REPORT_DIR="./test-reports"
BASE_FS="ubuntu"
DO_SETUP=1
STAGGER=1
SKIP_SCRIPTS=()
ONLY_SCRIPTS=()

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
START_TIME=""
TMPDIR_RUN=""
FIFO=""
CHILD_PIDS=()
KUBE_L1_PID=""

# Known test prefixes for stale cleanup.
KNOWN_PREFIXES=(
    smoke-
    net-
    sec-
    usrns-
    vfy-dboot-
    vfy-doci-
    vfy-oci-
    vfy-tut-
    vfy-int-
    vfy-bld-
    vfy-exp-
    vfy-nixos-
    kube-vfy-
    vfy-mx-
    vfy-cp-
)

# -- Usage --------------------------------------------------------------------

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Staged parallel e2e test runner for sdme.
Must be run as root.

Options:
  --jobs N             Max parallel jobs (default: $MAX_JOBS)
  --report-dir DIR     Report output directory (default: $REPORT_DIR)
  --base-fs NAME       Base rootfs name (default: $BASE_FS)
  --timeout-scale N    Multiply all timeouts by N (default: 1)
  --stagger N          Seconds between OCI-pulling test launches (default: $STAGGER)
  --skip SCRIPT        Skip a script (repeatable, basename without .sh)
  --only SCRIPT        Run only these scripts (repeatable)
  --no-setup           Skip build + base rootfs import
  -v, --verbose        Show test output in real time
  --help               Show help

Examples:
  sudo $0                                    # run all tests, 8 jobs
  sudo $0 --jobs 4                           # limit to 4 parallel jobs
  sudo $0 --timeout-scale 2                  # double all timeouts (slow machine)
  sudo $0 --only verify-export --only verify-build --jobs 2
  sudo $0 --skip verify-distro-oci --skip verify-nixos   # skip slow tests
EOF
}

# -- Argument parsing ---------------------------------------------------------

parse_runner_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --jobs)     shift; MAX_JOBS="$1" ;;
            --report-dir) shift; REPORT_DIR="$1" ;;
            --base-fs)  shift; BASE_FS="$1" ;;
            --timeout-scale) shift; export TIMEOUT_SCALE="$1" ;;
            --stagger)  shift; STAGGER="$1" ;;
            --skip)     shift; SKIP_SCRIPTS+=("$1") ;;
            --only)     shift; ONLY_SCRIPTS+=("$1") ;;
            --no-setup) DO_SETUP=0 ;;
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
        verify-distro-boot.sh|verify-distro-oci.sh|verify-export.sh|verify-tutorial.sh|verify-oci.sh|verify-nixos.sh|verify-security.sh|verify-pods.sh)
            # These scripts don't accept --base-fs (custom or no arg parser).
            ;;
        *)
            args="$args --base-fs $BASE_FS"
            ;;
    esac
    echo "$args"
}

# -- Stale cleanup ------------------------------------------------------------
# Remove leftover artifacts from prior interrupted runs.

cleanup_stale() {
    log "Cleaning up stale test artifacts..."
    for prefix in "${KNOWN_PREFIXES[@]}"; do
        cleanup_prefix "$prefix"
    done
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
        echo "| Timeout scale | ${TIMEOUT_SCALE:-1} |"
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
    export GATE_DIR="$TMPDIR_RUN/gates"
    mkdir -p "$GATE_DIR"
    trap cleanup_runner EXIT INT TERM

    mkdir -p "$REPORT_DIR"

    # ========================================================================
    # Stage 0: Preflight
    # ========================================================================
    log "Stage 0: Preflight"
    if ! "$SCRIPT_DIR/preflight.sh"; then
        log "PREFLIGHT FAILED - aborting"
        exit 1
    fi
    echo ""

    # ========================================================================
    # Stage 1: Setup + Smoke + Interrupt
    # ========================================================================
    log "Stage 1: Setup + Smoke + Interrupt"

    if [[ $DO_SETUP -eq 1 ]]; then
        log "Building and installing sdme"
        build_and_install

        log "Importing $BASE_FS base rootfs"
        ensure_base_fs "$BASE_FS" "${DISTRO_IMAGES[$BASE_FS]}"
    else
        ensure_sdme
    fi

    # Smoke test: validates core container lifecycle.
    log "Running smoke test"
    if ! "$SCRIPT_DIR/smoke.sh" --report-dir "$REPORT_DIR" --base-fs "$BASE_FS"; then
        log "SMOKE TEST FAILED - aborting"
        write_gate smoke fail
        exit 1
    fi
    write_gate smoke pass

    # Interrupt test: validates SIGINT/SIGTERM handling (foundational for cleanup).
    if should_run "verify-interrupt"; then
        log "Running interrupt test"
        local int_args
        int_args=$(test_args "verify-interrupt.sh")
        # shellcheck disable=SC2086
        if ! "$SCRIPT_DIR/verify-interrupt.sh" $int_args; then
            log "INTERRUPT TEST FAILED - aborting"
            write_gate interrupt fail
            exit 1
        fi
        write_gate interrupt pass
    else
        # If skipped via --skip/--only, write pass so downstream gates don't block.
        write_gate interrupt pass
    fi

    echo ""

    # ========================================================================
    # Stage 2: Parallel tests
    # ========================================================================
    START_TIME=$(now_epoch)
    init_semaphore

    # Clean up stale artifacts from prior interrupted runs.
    cleanup_stale

    # -- Wave A: core tests + kube-L1 --
    log "Stage 2, Wave A: core tests (max $MAX_JOBS parallel jobs)"
    echo ""

    local wave_a_tests=(
        verify-cp.sh
        verify-export.sh
        verify-build.sh
        verify-security.sh
        verify-pods.sh
        verify-network.sh
        verify-oci.sh
        verify-nixos.sh
        verify-distro-boot.sh
        verify-distro-oci.sh
        verify-kube-L1-basic.sh
    )

    local _launch_count=0
    for script_name in "${wave_a_tests[@]}"; do
        local name="${script_name%.sh}"
        if should_run "$name"; then
            if [[ $_launch_count -gt 0 && $STAGGER -gt 0 ]]; then
                sleep "$STAGGER"
            fi
            run_test "$SCRIPT_DIR/$script_name"
            # Track kube-L1 PID for Wave B gating.
            if [[ "$script_name" == "verify-kube-L1-basic.sh" ]]; then
                KUBE_L1_PID="${CHILD_PIDS[-1]}"
            fi
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

    # -- Wait for kube-L1 to complete, then launch Wave B --
    local wave_b_tests=(
        verify-kube-L2-spec.sh
        verify-kube-L2-security.sh
        verify-kube-L2-probes.sh
        verify-kube-L4-networking.sh
        verify-kube-L5-redis-stack.sh
        verify-kube-L6-gitea-stack.sh
    )

    local wave_b_wanted=0
    for script_name in "${wave_b_tests[@]}"; do
        local name="${script_name%.sh}"
        if should_run "$name"; then
            wave_b_wanted=1
            break
        fi
    done

    if [[ $wave_b_wanted -eq 1 ]]; then
        if [[ -n "$KUBE_L1_PID" ]]; then
            log "Waiting for kube-L1 to complete before launching Wave B..."
            wait "$KUBE_L1_PID" 2>/dev/null || true
        fi

        local kube_l1_rc=0
        check_gate kube-l1 || kube_l1_rc=$?

        if [[ $kube_l1_rc -eq 0 ]]; then
            log "Stage 2, Wave B: kube advanced tests"
            echo ""
            for script_name in "${wave_b_tests[@]}"; do
                local name="${script_name%.sh}"
                if should_run "$name"; then
                    if [[ $_launch_count -gt 0 && $STAGGER -gt 0 ]]; then
                        sleep "$STAGGER"
                    fi
                    run_test "$SCRIPT_DIR/$script_name"
                    ((_launch_count++)) || true
                fi
            done
        elif [[ $kube_l1_rc -eq 1 ]]; then
            log "Stage 2, Wave B: SKIPPED (kube-L1 failed)"
        else
            # Gate not found (L1 was filtered out). Launch Wave B anyway;
            # scripts have their own require_gate which will no-op.
            log "Stage 2, Wave B: kube advanced tests (L1 not run)"
            echo ""
            for script_name in "${wave_b_tests[@]}"; do
                local name="${script_name%.sh}"
                if should_run "$name"; then
                    if [[ $_launch_count -gt 0 && $STAGGER -gt 0 ]]; then
                        sleep "$STAGGER"
                    fi
                    run_test "$SCRIPT_DIR/$script_name"
                    ((_launch_count++)) || true
                fi
            done
        fi
    fi

    # -- Wait for all parallel tests --
    log "Waiting for all parallel tests to complete..."
    local overall_rc=0
    for pid in "${CHILD_PIDS[@]}"; do
        wait "$pid" 2>/dev/null || overall_rc=1
    done

    # ========================================================================
    # Stage 3: Destructive (verify-tutorial.sh)
    # ========================================================================
    # Its batch tests (sdme stop --all, sdme rm --all) affect ALL containers
    # system-wide, so it must run after everything else finishes.
    if should_run "verify-tutorial"; then
        echo ""
        log "Stage 3: Destructive tests"
        CHILD_PIDS=()
        run_test "$SCRIPT_DIR/verify-tutorial.sh"
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
