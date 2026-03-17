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
#   - envFrom (configMapRef, secretRef with prefix, explicit env override)
#   - Read-only volume mounts (remount,ro,bind verification)
#   - PVC volume mounting and persistence
#   - Missing resource error handling

source "$(dirname "$0")/lib.sh"

BASE_FS="${BASE_FS:-ubuntu}"
DATADIR="/var/lib/sdme"
REPORT_DIR="."

# Pod and resource names.
SECRET_POD="secret-test-pod"
CONFIGMAP_POD="configmap-test-pod"
PVC_POD="pvc-test-pod"
ENVFROM_POD="envfrom-test-pod"
RONLY_POD="readonly-vol-pod"
SECRET_ALL="test-secret"
SECRET_PROJ="mysecret"
SECRET_ENV="env-secret"
SECRET_ENVFROM="envfrom-secret"
CONFIGMAP_NAME="app-config"
CONFIGMAP_ENVFROM="envfrom-config"

# Timeouts (seconds)
TIMEOUT_CREATE=600
TIMEOUT_BOOT=120

# State flags
SECRETS_CREATED=0
CONFIGMAPS_CREATED=0
SECRET_POD_CREATED=0
SECRET_POD_RUNNING=0
CONFIGMAP_POD_CREATED=0
CONFIGMAP_POD_RUNNING=0
PVC_POD_CREATED=0
PVC_POD_RUNNING=0
ENVFROM_POD_CREATED=0
RONLY_POD_CREATED=0
RONLY_POD_RUNNING=0

# --- Cleanup ------------------------------------------------------------------

cleanup() {
    echo "==> Cleaning up..."
    "$SDME" kube delete "$SECRET_POD" --force 2>/dev/null || true
    "$SDME" kube delete "$CONFIGMAP_POD" --force 2>/dev/null || true
    "$SDME" kube delete "$PVC_POD" --force 2>/dev/null || true
    "$SDME" kube delete "$ENVFROM_POD" --force 2>/dev/null || true
    "$SDME" kube delete "$RONLY_POD" --force 2>/dev/null || true
    "$SDME" kube secret rm "$SECRET_ALL" 2>/dev/null || true
    "$SDME" kube secret rm "$SECRET_PROJ" 2>/dev/null || true
    "$SDME" kube secret rm "$SECRET_ENV" 2>/dev/null || true
    "$SDME" kube secret rm "$SECRET_ENVFROM" 2>/dev/null || true
    "$SDME" kube configmap rm "$CONFIGMAP_NAME" 2>/dev/null || true
    "$SDME" kube configmap rm "$CONFIGMAP_ENVFROM" 2>/dev/null || true
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

# --- envFrom tests ------------------------------------------------------------

test_envfrom_create_resources() {
    local test_name="envfrom-create-resources"

    echo "--- $test_name ---"
    local output

    # Create a configmap for envFrom.
    if output=$("$SDME" kube configmap create "$CONFIGMAP_ENVFROM" \
        --from-literal 'HOST=db.example.com' \
        --from-literal 'PORT=5432' 2>&1); then
        true
    else
        record "$test_name" FAIL "configmap: $output"
        return
    fi

    # Create a secret for envFrom.
    if output=$("$SDME" kube secret create "$SECRET_ENVFROM" \
        --from-literal 'USER=admin' \
        --from-literal 'PASS=s3cret' 2>&1); then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "secret: $output"
    fi
}

test_envfrom_create_pod() {
    local test_name="envfrom-create-pod"
    if [[ "$(result_status envfrom-create-resources 2>/dev/null)" != "PASS" ]]; then
        record "$test_name" SKIP "envfrom resources not created"
        return
    fi

    local yaml_file
    yaml_file=$(mktemp /tmp/kube-envfrom-XXXXXX.yaml)

    cat > "$yaml_file" <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: $ENVFROM_POD
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    command: ["/bin/sh", "-c", "sleep infinity"]
    envFrom:
    - configMapRef:
        name: $CONFIGMAP_ENVFROM
      prefix: CFG_
    - secretRef:
        name: $SECRET_ENVFROM
      prefix: SEC_
    env:
    - name: CFG_PORT
      value: "9999"
YAML

    echo "--- $test_name: creating pod ---"
    local output
    if output=$(timeout "$TIMEOUT_CREATE" "$SDME" kube create -f "$yaml_file" --base-fs "$BASE_FS" -v 2>&1); then
        record "$test_name" PASS
        ENVFROM_POD_CREATED=1
    else
        record "$test_name" FAIL "$output"
    fi
    rm -f "$yaml_file"
}

test_static_envfrom_configmap_keys() {
    local test_name="static-envfrom-configmap-keys"
    if [[ $ENVFROM_POD_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "envfrom pod not created"
        return
    fi

    local env_file="$DATADIR/fs/kube-$ENVFROM_POD/oci/apps/app/env"
    if [[ ! -f "$env_file" ]]; then
        record "$test_name" FAIL "env file not found: $env_file"
        return
    fi

    local content
    content=$(cat "$env_file")
    local fail=0

    # envFrom with prefix CFG_ should produce CFG_HOST=db.example.com.
    if ! echo "$content" | grep -q 'CFG_HOST=db.example.com'; then
        echo "    missing: CFG_HOST=db.example.com"
        fail=1
    fi

    if [[ $fail -eq 0 ]]; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "envFrom configmap keys missing"
        echo "    env file content:"
        echo "$content"
    fi
}

test_static_envfrom_secret_keys() {
    local test_name="static-envfrom-secret-keys"
    if [[ $ENVFROM_POD_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "envfrom pod not created"
        return
    fi

    local env_file="$DATADIR/fs/kube-$ENVFROM_POD/oci/apps/app/env"
    local content
    content=$(cat "$env_file")
    local fail=0

    # envFrom with prefix SEC_ should produce SEC_USER=admin and SEC_PASS=s3cret.
    if ! echo "$content" | grep -q 'SEC_USER=admin'; then
        echo "    missing: SEC_USER=admin"
        fail=1
    fi
    if ! echo "$content" | grep -q 'SEC_PASS=s3cret'; then
        echo "    missing: SEC_PASS=s3cret"
        fail=1
    fi

    if [[ $fail -eq 0 ]]; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "envFrom secret keys missing"
        echo "    env file content:"
        echo "$content"
    fi
}

test_static_envfrom_explicit_override() {
    local test_name="static-envfrom-explicit-override"
    if [[ $ENVFROM_POD_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "envfrom pod not created"
        return
    fi

    local env_file="$DATADIR/fs/kube-$ENVFROM_POD/oci/apps/app/env"
    local content
    content=$(cat "$env_file")

    # Explicit env CFG_PORT=9999 should override envFrom CFG_PORT=5432.
    if echo "$content" | grep -q 'CFG_PORT=9999'; then
        if echo "$content" | grep -q 'CFG_PORT=5432'; then
            record "$test_name" FAIL "envFrom value CFG_PORT=5432 still present"
            echo "    env file content:"
            echo "$content"
        else
            record "$test_name" PASS
        fi
    else
        record "$test_name" FAIL "expected CFG_PORT=9999 (explicit override)"
        echo "    env file content:"
        echo "$content"
    fi
}

# --- Read-only volume mount tests --------------------------------------------

test_ronly_create_pod() {
    local test_name="ronly-create-pod"

    local yaml_file
    yaml_file=$(mktemp /tmp/kube-ronly-XXXXXX.yaml)

    cat > "$yaml_file" <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: $RONLY_POD
spec:
  containers:
  - name: writer
    image: docker.io/busybox:latest
    command: ["/bin/sh", "-c", "echo hello > /rw-data/marker && sleep infinity"]
    volumeMounts:
    - name: shared
      mountPath: /rw-data
    - name: shared
      mountPath: /ro-data
      readOnly: true
  volumes:
  - name: shared
    emptyDir: {}
YAML

    echo "--- $test_name: creating pod ---"
    local output
    if output=$(timeout "$TIMEOUT_CREATE" "$SDME" kube create -f "$yaml_file" --base-fs "$BASE_FS" -v 2>&1); then
        record "$test_name" PASS
        RONLY_POD_CREATED=1
    else
        record "$test_name" FAIL "$output"
    fi
    rm -f "$yaml_file"
}

test_static_ronly_volume_service() {
    local test_name="static-ronly-volume-service"
    if [[ $RONLY_POD_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "readonly pod not created"
        return
    fi

    local unit_path="$DATADIR/fs/kube-$RONLY_POD/etc/systemd/system/sdme-kube-volumes.service"
    if [[ ! -f "$unit_path" ]]; then
        record "$test_name" FAIL "sdme-kube-volumes.service not found"
        return
    fi

    local unit
    unit=$(cat "$unit_path")
    local fail=0

    # Should have a regular bind mount for /rw-data.
    if ! echo "$unit" | grep -q 'mount --bind.*/oci/apps/writer/root/rw-data'; then
        echo "    missing: bind mount for /rw-data"
        fail=1
    fi

    # Should have a bind mount for /ro-data.
    if ! echo "$unit" | grep -q 'mount --bind.*/oci/apps/writer/root/ro-data'; then
        echo "    missing: bind mount for /ro-data"
        fail=1
    fi

    # Should have a remount,ro,bind for /ro-data but NOT for /rw-data.
    if ! echo "$unit" | grep -q 'remount,ro,bind.*/oci/apps/writer/root/ro-data'; then
        echo "    missing: remount,ro,bind for /ro-data"
        fail=1
    fi
    if echo "$unit" | grep -q 'remount,ro,bind.*/oci/apps/writer/root/rw-data'; then
        echo "    unexpected: remount,ro,bind for /rw-data (should be rw)"
        fail=1
    fi

    if [[ $fail -eq 0 ]]; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "volume service read-only config wrong"
        echo "    unit content:"
        echo "$unit"
    fi
}

test_ronly_start_runtime() {
    local test_name="ronly-start-runtime"
    if [[ $RONLY_POD_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "readonly pod not created"
        return
    fi

    echo "--- $test_name: starting pod ---"
    local output
    if output=$(timeout "$TIMEOUT_BOOT" "$SDME" start "$RONLY_POD" -v 2>&1); then
        RONLY_POD_RUNNING=1
    else
        record "$test_name" FAIL "failed to start: $output"
        return
    fi

    # Wait for the OCI app service to become active and the marker file to appear.
    local ok=0
    for i in $(seq 1 10); do
        sleep 3
        output=$("$SDME" exec "$RONLY_POD" --oci -- \
            /bin/cat /rw-data/marker 2>/dev/null || echo "")
        if echo "$output" | grep -q 'hello'; then
            ok=1
            break
        fi
    done
    if [[ $ok -eq 0 ]]; then
        record "$test_name" FAIL "rw mount: expected 'hello' in /rw-data/marker after retries, got: $output"
        return
    fi

    # Verify the ro mount is read-only: try to write and expect failure.
    output=$("$SDME" exec "$RONLY_POD" --oci -- \
        /bin/sh -c 'echo test > /ro-data/write-test 2>&1' 2>&1 || true)
    if echo "$output" | grep -qi 'read-only\|Read-only'; then
        record "$test_name" PASS
    else
        # Also check if the file was NOT created (some shells don't print the error).
        output=$("$SDME" exec "$RONLY_POD" --oci -- \
            /bin/cat /ro-data/write-test 2>&1 || echo "NOT_FOUND")
        if echo "$output" | grep -q 'NOT_FOUND\|No such file'; then
            record "$test_name" PASS
        else
            record "$test_name" FAIL "ro mount is writable: /ro-data/write-test has content: $output"
        fi
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

# --- Main ---------------------------------------------------------------------

main() {
    parse_standard_args "End-to-end verification of sdme Kubernetes volume support." "$@"

    ensure_root
    ensure_sdme

    ensure_default_base_fs

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

    # Phase 7: envFrom tests.
    echo ""
    echo "--- envFrom tests ---"
    test_envfrom_create_resources
    test_envfrom_create_pod
    test_static_envfrom_configmap_keys
    test_static_envfrom_secret_keys
    test_static_envfrom_explicit_override

    # Phase 8: Read-only volume mount tests.
    echo ""
    echo "--- read-only volume mount tests ---"
    test_ronly_create_pod
    test_static_ronly_volume_service
    test_ronly_start_runtime

    # Phase 9: Resource rm and error handling.
    echo ""
    echo "--- cleanup and error handling ---"
    test_secret_rm
    test_secret_rm_not_found
    test_configmap_rm
    test_configmap_rm_not_found
    test_missing_secret_error
    test_missing_configmap_error

    generate_standard_report "verify-kube-L3-volumes" "sdme Kube Volumes Verification Report"

    print_summary
}

main "$@"
