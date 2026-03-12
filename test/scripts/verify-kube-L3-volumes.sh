#!/usr/bin/env bash
set -uo pipefail

# verify-kube-L3-volumes.sh - end-to-end verification of kube volumes
# Run as root. Requires a base-fs imported (e.g. ubuntu).
#
# Tests:
#   - sdme kube configmap create/ls/rm lifecycle
#   - sdme kube secret create/ls/rm lifecycle
#   - ConfigMap volume mounting (all keys, projected items, defaultMode)
#   - Secret volume mounting (all keys, projected items, defaultMode)
#   - env valueFrom (secretKeyRef, configMapKeyRef)
#   - PVC volume mounting and persistence
#   - Missing resource error handling

SDME="${SDME:-sdme}"
BASE_FS="${BASE_FS:-ubuntu}"
DATADIR="/var/lib/sdme"
KEEP=0
REPORT_DIR="."

# Pod and resource names.
SECRET_POD="secret-test-pod"
CONFIGMAP_POD="configmap-test-pod"
PVC_POD="pvc-test-pod"
SECRET_ALL="test-secret"
SECRET_PROJ="mysecret"
SECRET_ENV="env-secret"
CONFIGMAP_NAME="app-config"

# Timeouts (seconds)
TIMEOUT_CREATE=600
TIMEOUT_BOOT=120

# Result tracking
declare -A RESULTS
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

# State flags
SECRETS_CREATED=0
CONFIGMAPS_CREATED=0
SECRET_POD_CREATED=0
SECRET_POD_RUNNING=0
CONFIGMAP_POD_CREATED=0
CONFIGMAP_POD_RUNNING=0
PVC_POD_CREATED=0
PVC_POD_RUNNING=0

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

End-to-end verification of sdme kube volumes (secrets, configmaps, PVCs).
Must be run as root.

Options:
  --base-fs NAME   Base rootfs to use (default: ubuntu)
  --keep           Do not remove test artifacts on exit
  --report-dir DIR Write report to DIR (default: .)
  --help           Show help
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --base-fs)
                shift
                BASE_FS="$1"
                ;;
            --keep)
                KEEP=1
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
                echo "unknown option: $1" >&2
                usage >&2
                exit 1
                ;;
        esac
        shift
    done
}

record() {
    local test_name="$1" result="$2" msg="${3:-}"
    RESULTS["$test_name"]="$result|$msg"
    case "$result" in
        PASS) ((PASS_COUNT++)); echo "  [PASS] $test_name${msg:+: $msg}" ;;
        FAIL) ((FAIL_COUNT++)); echo "  [FAIL] $test_name${msg:+: $msg}" ;;
        SKIP) ((SKIP_COUNT++)); echo "  [SKIP] $test_name${msg:+: $msg}" ;;
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

# --- Cleanup ------------------------------------------------------------------

cleanup() {
    if [[ $KEEP -eq 1 ]]; then
        echo "==> Keeping test artifacts (--keep)"
        return
    fi
    echo "==> Cleaning up..."
    "$SDME" kube delete "$SECRET_POD" --force 2>/dev/null || true
    "$SDME" kube delete "$CONFIGMAP_POD" --force 2>/dev/null || true
    "$SDME" kube delete "$PVC_POD" --force 2>/dev/null || true
    "$SDME" kube secret rm "$SECRET_ALL" 2>/dev/null || true
    "$SDME" kube secret rm "$SECRET_PROJ" 2>/dev/null || true
    "$SDME" kube secret rm "$SECRET_ENV" 2>/dev/null || true
    "$SDME" kube configmap rm "$CONFIGMAP_NAME" 2>/dev/null || true
}

trap cleanup EXIT INT TERM

# --- ConfigMap lifecycle tests ------------------------------------------------

test_configmap_create() {
    local test_name="configmap-create"

    echo "--- $test_name ---"
    local output

    if output=$("$SDME" kube configmap create "$CONFIGMAP_NAME" \
        --from-literal 'database-url=postgres://localhost/db' \
        --from-literal 'log-level=info' 2>&1); then
        record "$test_name" PASS
        CONFIGMAPS_CREATED=1
    else
        record "$test_name" FAIL "$output"
    fi
}

test_configmap_ls() {
    local test_name="configmap-ls"
    if [[ $CONFIGMAPS_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "configmaps not created"
        return
    fi

    local output
    output=$("$SDME" kube configmap ls 2>&1)

    if echo "$output" | grep -q "$CONFIGMAP_NAME"; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "configmap not found in listing"
        echo "    output: $output"
    fi
}

test_configmap_key_count() {
    local test_name="configmap-key-count"
    if [[ $CONFIGMAPS_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "configmaps not created"
        return
    fi

    local output
    output=$("$SDME" kube configmap ls 2>&1)

    local line
    line=$(echo "$output" | grep "$CONFIGMAP_NAME " || echo "")

    if echo "$line" | grep -qE '\b2\b'; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "expected 2 keys, got: $line"
    fi
}

test_configmap_duplicate() {
    local test_name="configmap-create-duplicate"
    if [[ $CONFIGMAPS_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "configmaps not created"
        return
    fi

    local output
    if output=$("$SDME" kube configmap create "$CONFIGMAP_NAME" \
        --from-literal k=v 2>&1); then
        record "$test_name" FAIL "should have failed for duplicate"
    else
        if echo "$output" | grep -q "already exists"; then
            record "$test_name" PASS
        else
            record "$test_name" FAIL "unexpected error: $output"
        fi
    fi
}

# --- Secret lifecycle tests ---------------------------------------------------

test_secret_create() {
    local test_name="secret-create"

    echo "--- $test_name ---"
    local output

    # Create "test-secret" (from K8s docs distribute-credentials-secure example).
    if output=$("$SDME" kube secret create "$SECRET_ALL" \
        --from-literal 'username=my-app' \
        --from-literal 'password=39528$vdg7Jb' 2>&1); then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "$output"
        return
    fi

    # Create "mysecret" (from K8s docs project-keys-to-specific-paths example).
    if output=$("$SDME" kube secret create "$SECRET_PROJ" \
        --from-literal username=projuser \
        --from-literal password=projpass 2>&1); then
        true
    else
        record "$test_name" FAIL "second secret: $output"
        return
    fi

    # Create "env-secret" for valueFrom test.
    if output=$("$SDME" kube secret create "$SECRET_ENV" \
        --from-literal api-key=secret-api-key-123 2>&1); then
        SECRETS_CREATED=1
    else
        record "$test_name" FAIL "env-secret: $output"
    fi
}

test_secret_ls() {
    local test_name="secret-ls"
    if [[ $SECRETS_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "secrets not created"
        return
    fi

    local output
    output=$("$SDME" kube secret ls 2>&1)

    local fail=0
    if ! echo "$output" | grep -q "$SECRET_ALL"; then
        echo "    missing: $SECRET_ALL in listing"
        fail=1
    fi
    if ! echo "$output" | grep -q "$SECRET_PROJ"; then
        echo "    missing: $SECRET_PROJ in listing"
        fail=1
    fi

    if [[ $fail -eq 0 ]]; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "secrets not found in listing"
        echo "    output: $output"
    fi
}

test_secret_key_count() {
    local test_name="secret-key-count"
    if [[ $SECRETS_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "secrets not created"
        return
    fi

    local output
    output=$("$SDME" kube secret ls 2>&1)

    # Both secrets have 2 keys each.
    local all_line proj_line
    all_line=$(echo "$output" | grep "$SECRET_ALL " || echo "")
    proj_line=$(echo "$output" | grep "$SECRET_PROJ " || echo "")

    local fail=0
    if ! echo "$all_line" | grep -qE '\b2\b'; then
        echo "    $SECRET_ALL: expected 2 keys, got: $all_line"
        fail=1
    fi
    if ! echo "$proj_line" | grep -qE '\b2\b'; then
        echo "    $SECRET_PROJ: expected 2 keys, got: $proj_line"
        fail=1
    fi

    if [[ $fail -eq 0 ]]; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "unexpected key counts"
    fi
}

test_secret_duplicate() {
    local test_name="secret-create-duplicate"
    if [[ $SECRETS_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "secrets not created"
        return
    fi

    local output
    if output=$("$SDME" kube secret create "$SECRET_ALL" \
        --from-literal k=v 2>&1); then
        record "$test_name" FAIL "should have failed for duplicate"
    else
        if echo "$output" | grep -q "already exists"; then
            record "$test_name" PASS
        else
            record "$test_name" FAIL "unexpected error: $output"
        fi
    fi
}

# --- Pod with secret volumes (from K8s docs) ---------------------------------

test_create_secret_pod() {
    local test_name="create-secret-pod"
    if [[ $SECRETS_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "secrets not created"
        return
    fi

    local yaml_file
    yaml_file=$(dirname "$0")/../kube/secret-pod.yaml
    if [[ ! -f "$yaml_file" ]]; then
        record "$test_name" FAIL "test/kube/secret-pod.yaml not found"
        return
    fi

    echo "--- $test_name: creating pod from test/kube/secret-pod.yaml ---"
    local output
    if output=$(timeout "$TIMEOUT_CREATE" "$SDME" kube create -f "$yaml_file" --base-fs "$BASE_FS" -v 2>&1); then
        record "$test_name" PASS
        SECRET_POD_CREATED=1
    else
        record "$test_name" FAIL "$output"
    fi
}

# --- Static checks: secrets ---

test_static_secret_all_keys() {
    local test_name="static-secret-all-keys"
    if [[ $SECRET_POD_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "secret pod not created"
        return
    fi

    local vol_dir="$DATADIR/fs/kube-$SECRET_POD/oci/volumes/secret-volume"
    local fail=0

    if [[ ! -f "$vol_dir/username" ]]; then
        echo "    missing: $vol_dir/username"
        fail=1
    elif [[ "$(cat "$vol_dir/username")" != "my-app" ]]; then
        echo "    wrong content: username=$(cat "$vol_dir/username")"
        fail=1
    fi

    if [[ ! -f "$vol_dir/password" ]]; then
        echo "    missing: $vol_dir/password"
        fail=1
    elif [[ "$(cat "$vol_dir/password")" != '39528$vdg7Jb' ]]; then
        echo "    wrong content: password=$(cat "$vol_dir/password")"
        fail=1
    fi

    if [[ $fail -eq 0 ]]; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "secret files missing or wrong"
    fi
}

test_static_secret_projected() {
    local test_name="static-secret-projected"
    if [[ $SECRET_POD_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "secret pod not created"
        return
    fi

    local vol_dir="$DATADIR/fs/kube-$SECRET_POD/oci/volumes/foo"
    local fail=0

    if [[ ! -f "$vol_dir/my-group/my-username" ]]; then
        echo "    missing: $vol_dir/my-group/my-username"
        fail=1
    elif [[ "$(cat "$vol_dir/my-group/my-username")" != "projuser" ]]; then
        echo "    wrong content: my-group/my-username=$(cat "$vol_dir/my-group/my-username")"
        fail=1
    fi

    if [[ -f "$vol_dir/password" ]]; then
        echo "    unexpected: $vol_dir/password should not exist (not in items)"
        fail=1
    fi

    if [[ $fail -eq 0 ]]; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "projected secret files wrong"
    fi
}

test_static_secret_permissions() {
    local test_name="static-secret-permissions"
    if [[ $SECRET_POD_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "secret pod not created"
        return
    fi

    local fail=0

    # secret-volume: default mode (0644).
    local all_dir="$DATADIR/fs/kube-$SECRET_POD/oci/volumes/secret-volume"
    for f in username password; do
        local mode
        mode=$(stat -c '%a' "$all_dir/$f" 2>/dev/null || echo "???")
        if [[ "$mode" != "644" ]]; then
            echo "    $f: expected 644, got $mode"
            fail=1
        fi
    done

    # foo: defaultMode 0400 (from K8s docs).
    local proj_dir="$DATADIR/fs/kube-$SECRET_POD/oci/volumes/foo"
    local mode
    mode=$(stat -c '%a' "$proj_dir/my-group/my-username" 2>/dev/null || echo "???")
    if [[ "$mode" != "400" ]]; then
        echo "    my-group/my-username: expected 400, got $mode"
        fail=1
    fi

    if [[ $fail -eq 0 ]]; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "file permissions wrong"
    fi
}

# --- Pod with configMap volumes + valueFrom -----------------------------------

test_create_configmap_pod() {
    local test_name="create-configmap-pod"
    if [[ $SECRETS_CREATED -eq 0 ]] || [[ $CONFIGMAPS_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "secrets or configmaps not created"
        return
    fi

    local yaml_file
    yaml_file=$(dirname "$0")/../kube/configmap-pod.yaml
    if [[ ! -f "$yaml_file" ]]; then
        record "$test_name" FAIL "test/kube/configmap-pod.yaml not found"
        return
    fi

    echo "--- $test_name: creating pod from test/kube/configmap-pod.yaml ---"
    local output
    if output=$(timeout "$TIMEOUT_CREATE" "$SDME" kube create -f "$yaml_file" --base-fs "$BASE_FS" -v 2>&1); then
        record "$test_name" PASS
        CONFIGMAP_POD_CREATED=1
    else
        record "$test_name" FAIL "$output"
    fi
}

# --- Static checks: configmaps ---

test_static_configmap_all_keys() {
    local test_name="static-configmap-all-keys"
    if [[ $CONFIGMAP_POD_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "configmap pod not created"
        return
    fi

    local vol_dir="$DATADIR/fs/kube-$CONFIGMAP_POD/oci/volumes/config-volume"
    local fail=0

    if [[ ! -f "$vol_dir/database-url" ]]; then
        echo "    missing: $vol_dir/database-url"
        fail=1
    elif [[ "$(cat "$vol_dir/database-url")" != "postgres://localhost/db" ]]; then
        echo "    wrong content: database-url=$(cat "$vol_dir/database-url")"
        fail=1
    fi

    if [[ ! -f "$vol_dir/log-level" ]]; then
        echo "    missing: $vol_dir/log-level"
        fail=1
    elif [[ "$(cat "$vol_dir/log-level")" != "info" ]]; then
        echo "    wrong content: log-level=$(cat "$vol_dir/log-level")"
        fail=1
    fi

    if [[ $fail -eq 0 ]]; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "configmap files missing or wrong"
    fi
}

test_static_configmap_projected() {
    local test_name="static-configmap-projected"
    if [[ $CONFIGMAP_POD_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "configmap pod not created"
        return
    fi

    local vol_dir="$DATADIR/fs/kube-$CONFIGMAP_POD/oci/volumes/config-projected"
    local fail=0

    if [[ ! -f "$vol_dir/db/connection-string" ]]; then
        echo "    missing: $vol_dir/db/connection-string"
        fail=1
    elif [[ "$(cat "$vol_dir/db/connection-string")" != "postgres://localhost/db" ]]; then
        echo "    wrong content: db/connection-string=$(cat "$vol_dir/db/connection-string")"
        fail=1
    fi

    # "log-level" key should NOT be present (not listed in items).
    if [[ -f "$vol_dir/log-level" ]]; then
        echo "    unexpected: $vol_dir/log-level should not exist (not in items)"
        fail=1
    fi

    if [[ $fail -eq 0 ]]; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "projected configmap files wrong"
    fi
}

test_static_configmap_permissions() {
    local test_name="static-configmap-permissions"
    if [[ $CONFIGMAP_POD_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "configmap pod not created"
        return
    fi

    local fail=0

    # config-volume: default mode (0644).
    local all_dir="$DATADIR/fs/kube-$CONFIGMAP_POD/oci/volumes/config-volume"
    for f in database-url log-level; do
        local mode
        mode=$(stat -c '%a' "$all_dir/$f" 2>/dev/null || echo "???")
        if [[ "$mode" != "644" ]]; then
            echo "    $f: expected 644, got $mode"
            fail=1
        fi
    done

    # config-projected: defaultMode 0400.
    local proj_dir="$DATADIR/fs/kube-$CONFIGMAP_POD/oci/volumes/config-projected"
    local mode
    mode=$(stat -c '%a' "$proj_dir/db/connection-string" 2>/dev/null || echo "???")
    if [[ "$mode" != "400" ]]; then
        echo "    db/connection-string: expected 400, got $mode"
        fail=1
    fi

    if [[ $fail -eq 0 ]]; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "file permissions wrong"
    fi
}

# --- Static checks: env valueFrom ---

test_static_env_from_secret() {
    local test_name="static-env-from-secret"
    if [[ $CONFIGMAP_POD_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "configmap pod not created"
        return
    fi

    local env_file="$DATADIR/fs/kube-$CONFIGMAP_POD/oci/apps/test-container/env"
    if [[ ! -f "$env_file" ]]; then
        record "$test_name" FAIL "env file not found: $env_file"
        return
    fi

    local content
    content=$(cat "$env_file")

    if echo "$content" | grep -q 'SECRET_VAR=secret-api-key-123'; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "expected SECRET_VAR=secret-api-key-123 in env file"
        echo "    env file content:"
        echo "$content"
    fi
}

test_static_env_from_configmap() {
    local test_name="static-env-from-configmap"
    if [[ $CONFIGMAP_POD_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "configmap pod not created"
        return
    fi

    local env_file="$DATADIR/fs/kube-$CONFIGMAP_POD/oci/apps/test-container/env"
    if [[ ! -f "$env_file" ]]; then
        record "$test_name" FAIL "env file not found: $env_file"
        return
    fi

    local content
    content=$(cat "$env_file")

    if echo "$content" | grep -q 'CONFIG_VAR=info'; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "expected CONFIG_VAR=info in env file"
        echo "    env file content:"
        echo "$content"
    fi
}

# --- Runtime checks: secrets --------------------------------------------------

test_start_secret_pod() {
    local test_name="start-secret-pod"
    if [[ $SECRET_POD_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "secret pod not created"
        return
    fi

    echo "--- $test_name: starting pod ---"
    local output
    if output=$(timeout "$TIMEOUT_BOOT" "$SDME" start "$SECRET_POD" -v 2>&1); then
        record "$test_name" PASS
        SECRET_POD_RUNNING=1
        echo "    waiting 5s for services to settle..."
        sleep 5
    else
        record "$test_name" FAIL "$output"
    fi
}

test_runtime_read_all_keys() {
    local test_name="runtime-read-all-keys"
    if [[ $SECRET_POD_RUNNING -eq 0 ]]; then
        record "$test_name" SKIP "secret pod not running"
        return
    fi

    local fail=0

    local output
    output=$("$SDME" exec "$SECRET_POD" --oci -- \
        cat /etc/secret-volume/username 2>/dev/null || echo "")
    if ! echo "$output" | grep -q 'my-app'; then
        echo "    username: expected 'my-app', got: $output"
        fail=1
    fi

    output=$("$SDME" exec "$SECRET_POD" --oci -- \
        cat /etc/secret-volume/password 2>/dev/null || echo "")
    if ! echo "$output" | grep -q '39528'; then
        echo "    password: expected '39528\$vdg7Jb', got: $output"
        fail=1
    fi

    if [[ $fail -eq 0 ]]; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "could not read secret data at runtime"
    fi
}

test_runtime_read_projected() {
    local test_name="runtime-read-projected"
    if [[ $SECRET_POD_RUNNING -eq 0 ]]; then
        record "$test_name" SKIP "secret pod not running"
        return
    fi

    local output
    output=$("$SDME" exec "$SECRET_POD" --oci -- \
        cat /etc/foo/my-group/my-username 2>/dev/null || echo "")
    if echo "$output" | grep -q 'projuser'; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "expected 'projuser', got: $output"
    fi
}

# --- PVC tests ----------------------------------------------------------------

test_create_pvc_pod() {
    local test_name="pvc-create-pod"

    local yaml_file
    yaml_file=$(dirname "$0")/../kube/pvc-pod.yaml
    if [[ ! -f "$yaml_file" ]]; then
        record "$test_name" FAIL "test/kube/pvc-pod.yaml not found"
        return
    fi

    echo "--- $test_name: creating pod from test/kube/pvc-pod.yaml ---"
    local output
    if output=$(timeout "$TIMEOUT_CREATE" "$SDME" kube create -f "$yaml_file" --base-fs "$BASE_FS" -v 2>&1); then
        record "$test_name" PASS
        PVC_POD_CREATED=1
    else
        record "$test_name" FAIL "$output"
    fi
}

test_static_pvc_host_dir() {
    local test_name="static-pvc-host-dir"
    if [[ $PVC_POD_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "pvc pod not created"
        return
    fi

    if [[ -d "$DATADIR/volumes/test-data" ]]; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "host dir $DATADIR/volumes/test-data not found"
    fi
}

test_static_pvc_volume_dir() {
    local test_name="static-pvc-volume-dir"
    if [[ $PVC_POD_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "pvc pod not created"
        return
    fi

    local vol_dir="$DATADIR/fs/kube-$PVC_POD/oci/volumes/data-volume"
    if [[ -d "$vol_dir" ]]; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "volume dir $vol_dir not found"
    fi
}

test_pvc_start_runtime() {
    local test_name="pvc-start-runtime"
    if [[ $PVC_POD_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "pvc pod not created"
        return
    fi

    echo "--- $test_name: starting pvc pod ---"
    local output
    if output=$(timeout "$TIMEOUT_BOOT" "$SDME" start "$PVC_POD" -v 2>&1); then
        PVC_POD_RUNNING=1
        echo "    waiting 5s for services to settle..."
        sleep 5
    else
        record "$test_name" FAIL "failed to start: $output"
        return
    fi

    # Write a file to the PVC from the host side.
    echo "pvc-test-marker" > "$DATADIR/volumes/test-data/marker.txt"

    # Read it from inside the container.
    output=$("$SDME" exec "$PVC_POD" --oci -- \
        cat /data/marker.txt 2>/dev/null || echo "")
    if echo "$output" | grep -q 'pvc-test-marker'; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "expected 'pvc-test-marker' inside container, got: $output"
    fi
}

# --- Resource rm tests --------------------------------------------------------

test_secret_rm() {
    local test_name="secret-rm"

    local rm_name="vfy-ks-rm-test"
    "$SDME" kube secret create "$rm_name" --from-literal k=v 2>/dev/null || true

    local output
    if output=$("$SDME" kube secret rm "$rm_name" 2>&1); then
        if "$SDME" kube secret ls 2>/dev/null | grep -q "$rm_name"; then
            record "$test_name" FAIL "secret still listed after rm"
        else
            record "$test_name" PASS
        fi
    else
        record "$test_name" FAIL "$output"
    fi
}

test_secret_rm_not_found() {
    local test_name="secret-rm-not-found"

    local output
    if output=$("$SDME" kube secret rm "nonexistent-secret" 2>&1); then
        record "$test_name" FAIL "should have failed for nonexistent secret"
    else
        if echo "$output" | grep -q "not found"; then
            record "$test_name" PASS
        else
            record "$test_name" FAIL "unexpected error: $output"
        fi
    fi
}

test_configmap_rm() {
    local test_name="configmap-rm"

    local rm_name="vfy-cm-rm-test"
    "$SDME" kube configmap create "$rm_name" --from-literal k=v 2>/dev/null || true

    local output
    if output=$("$SDME" kube configmap rm "$rm_name" 2>&1); then
        if "$SDME" kube configmap ls 2>/dev/null | grep -q "$rm_name"; then
            record "$test_name" FAIL "configmap still listed after rm"
        else
            record "$test_name" PASS
        fi
    else
        record "$test_name" FAIL "$output"
    fi
}

test_configmap_rm_not_found() {
    local test_name="configmap-rm-not-found"

    local output
    if output=$("$SDME" kube configmap rm "nonexistent-configmap" 2>&1); then
        record "$test_name" FAIL "should have failed for nonexistent configmap"
    else
        if echo "$output" | grep -q "not found"; then
            record "$test_name" PASS
        else
            record "$test_name" FAIL "unexpected error: $output"
        fi
    fi
}

# --- Missing secret test (no pod needed) --------------------------------------

test_missing_secret_error() {
    local test_name="missing-secret-error"

    local yaml_file
    yaml_file=$(mktemp /tmp/kube-secret-miss-XXXXXX.yaml)

    cat > "$yaml_file" <<'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: vfy-ks-miss
spec:
  containers:
  - name: test-container
    image: docker.io/nginx:latest
    volumeMounts:
    - name: secret-volume
      mountPath: /etc/secret-volume
  volumes:
  - name: secret-volume
    secret:
      secretName: this-does-not-exist
YAML

    local output
    if output=$(timeout "$TIMEOUT_CREATE" "$SDME" kube create -f "$yaml_file" --base-fs "$BASE_FS" 2>&1); then
        record "$test_name" FAIL "should have failed for missing secret"
        "$SDME" kube delete "vfy-ks-miss" --force 2>/dev/null || true
    else
        if echo "$output" | grep -q "not found"; then
            record "$test_name" PASS
        else
            record "$test_name" FAIL "unexpected error: $output"
        fi
    fi
    rm -f "$yaml_file"
}

test_missing_configmap_error() {
    local test_name="missing-configmap-error"

    local yaml_file
    yaml_file=$(mktemp /tmp/kube-cm-miss-XXXXXX.yaml)

    cat > "$yaml_file" <<'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: vfy-cm-miss
spec:
  containers:
  - name: test-container
    image: docker.io/nginx:latest
    volumeMounts:
    - name: config-volume
      mountPath: /etc/config
  volumes:
  - name: config-volume
    configMap:
      name: this-does-not-exist
YAML

    local output
    if output=$(timeout "$TIMEOUT_CREATE" "$SDME" kube create -f "$yaml_file" --base-fs "$BASE_FS" 2>&1); then
        record "$test_name" FAIL "should have failed for missing configmap"
        "$SDME" kube delete "vfy-cm-miss" --force 2>/dev/null || true
    else
        if echo "$output" | grep -q "not found"; then
            record "$test_name" PASS
        else
            record "$test_name" FAIL "unexpected error: $output"
        fi
    fi
    rm -f "$yaml_file"
}

# --- Report -------------------------------------------------------------------

generate_report() {
    local ts
    ts=$(date +%Y%m%d-%H%M%S)
    local report="$REPORT_DIR/verify-kube-volumes-$ts.md"

    mkdir -p "$REPORT_DIR"

    {
        echo "# sdme Kube Volumes Verification Report"
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
        echo "| Base FS | $BASE_FS |"
        echo ""

        echo "## Summary"
        echo ""
        local total=$((PASS_COUNT + FAIL_COUNT + SKIP_COUNT))
        echo "| Result | Count |"
        echo "|--------|-------|"
        echo "| PASS | $PASS_COUNT |"
        echo "| FAIL | $FAIL_COUNT |"
        echo "| SKIP | $SKIP_COUNT |"
        echo "| Total | $total |"
        echo ""

        echo "## Results"
        echo ""
        echo "| Test | Result |"
        echo "|------|--------|"
        for test_name in \
            configmap-create configmap-ls configmap-key-count configmap-create-duplicate \
            secret-create secret-ls secret-key-count secret-create-duplicate \
            create-secret-pod \
            static-secret-all-keys static-secret-projected static-secret-permissions \
            create-configmap-pod \
            static-configmap-all-keys static-configmap-projected static-configmap-permissions \
            static-env-from-secret static-env-from-configmap \
            start-secret-pod runtime-read-all-keys runtime-read-projected \
            pvc-create-pod static-pvc-host-dir static-pvc-volume-dir pvc-start-runtime \
            secret-rm secret-rm-not-found configmap-rm configmap-rm-not-found \
            missing-secret-error missing-configmap-error; do
            if [[ -n "${RESULTS[$test_name]+x}" ]]; then
                echo "| $test_name | $(result_status "$test_name") |"
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

    echo "Report: $report"
}

# --- Main ---------------------------------------------------------------------

main() {
    parse_args "$@"

    if [[ $EUID -ne 0 ]]; then
        echo "error: must be run as root" >&2
        exit 1
    fi

    if [[ ! -d "$DATADIR/fs/$BASE_FS" ]]; then
        echo "error: base rootfs '$BASE_FS' not found; import it first:" >&2
        echo "  sdme fs import docker.io/$BASE_FS:latest -n $BASE_FS" >&2
        exit 1
    fi

    echo "=== sdme kube volumes verification ==="
    echo "base-fs: $BASE_FS"
    echo ""

    # Phase 1: ConfigMap lifecycle.
    echo "--- configmap lifecycle ---"
    test_configmap_create
    test_configmap_ls
    test_configmap_key_count
    test_configmap_duplicate

    # Phase 2: Secret lifecycle.
    echo ""
    echo "--- secret lifecycle ---"
    test_secret_create
    test_secret_ls
    test_secret_key_count
    test_secret_duplicate

    # Phase 3: Create pods.
    echo ""
    test_create_secret_pod
    test_create_configmap_pod

    # Phase 4: Static checks.
    echo ""
    echo "--- static checks: secrets ---"
    test_static_secret_all_keys
    test_static_secret_projected
    test_static_secret_permissions

    echo ""
    echo "--- static checks: configmaps ---"
    test_static_configmap_all_keys
    test_static_configmap_projected
    test_static_configmap_permissions

    echo ""
    echo "--- static checks: env valueFrom ---"
    test_static_env_from_secret
    test_static_env_from_configmap

    # Phase 5: Runtime checks.
    echo ""
    echo "--- runtime checks: secrets ---"
    test_start_secret_pod
    test_runtime_read_all_keys
    test_runtime_read_projected

    # Phase 6: PVC tests.
    echo ""
    echo "--- PVC tests ---"
    test_create_pvc_pod
    test_static_pvc_host_dir
    test_static_pvc_volume_dir
    test_pvc_start_runtime

    # Phase 7: Resource rm and error handling.
    echo ""
    echo "--- cleanup and error handling ---"
    test_secret_rm
    test_secret_rm_not_found
    test_configmap_rm
    test_configmap_rm_not_found
    test_missing_secret_error
    test_missing_configmap_error

    echo ""
    echo "=== Results ==="
    echo "Total: $PASS_COUNT passed, $FAIL_COUNT failed, $SKIP_COUNT skipped"

    generate_report

    if [[ $FAIL_COUNT -gt 0 ]]; then
        exit 1
    fi
}

main "$@"
