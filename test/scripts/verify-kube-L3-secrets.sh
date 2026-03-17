#!/usr/bin/env bash
set -uo pipefail

# verify-kube-L3-secrets.sh - end-to-end verification of kube secret volumes
# Run as root. Requires a base-fs imported (e.g. ubuntu).
#
# Uses examples from the Kubernetes documentation:
# https://kubernetes.io/docs/tasks/inject-data-application/distribute-credentials-secure/
#
# Tests:
#   - sdme kube secret create/ls/rm lifecycle
#   - Secret volume mounting (all keys, from K8s docs secret-pod.yaml)
#   - Secret volume mounting (projected items with key/path, from K8s docs)
#   - defaultMode permission setting (from K8s docs)
#   - Runtime access to secret data from inside the container
#   - Missing secret error handling

source "$(dirname "$0")/lib.sh"

BASE_FS="${BASE_FS:-ubuntu}"
DATADIR="/var/lib/sdme"
REPORT_DIR="."

# Pod and secret names from K8s documentation examples.
POD_NAME="secret-test-pod"
SECRET_ALL="test-secret"
SECRET_PROJ="mysecret"

# Timeouts (seconds)
TIMEOUT_CREATE=600
TIMEOUT_BOOT=120

# State flags
SECRETS_CREATED=0
POD_CREATED=0
POD_RUNNING=0

# --- Cleanup ------------------------------------------------------------------

cleanup() {
    echo "==> Cleaning up..."
    "$SDME" kube delete "$POD_NAME" --force 2>/dev/null || true
    "$SDME" kube secret rm "$SECRET_ALL" 2>/dev/null || true
    "$SDME" kube secret rm "$SECRET_PROJ" 2>/dev/null || true
}

trap cleanup EXIT INT TERM

# --- Secret lifecycle tests ---------------------------------------------------

# From K8s docs: kubectl create secret generic test-secret \
#   --from-literal='username=my-app' --from-literal='password=39528$vdg7Jb'
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
        SECRETS_CREATED=1
    else
        record "$test_name" FAIL "second secret: $output"
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

# Uses test/kube/secret-pod.yaml which is based on the K8s documentation:
# - pods/inject/secret-pod.yaml (all keys mounted at /etc/secret-volume)
# - projected keys example (key "username" projected to "my-group/my-username")
# - defaultMode example (0400 permissions)
test_create_pod() {
    local test_name="create-pod"
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
        POD_CREATED=1
    else
        record "$test_name" FAIL "$output"
    fi
}

# --- Static checks (rootfs content, no boot needed) --------------------------

# Verify all keys from "test-secret" are present at /oci/volumes/secret-volume/.
# K8s docs: "Each key in the Secret data map becomes the filename"
test_static_secret_all_keys() {
    local test_name="static-secret-all-keys"
    if [[ $POD_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "pod not created"
        return
    fi

    local vol_dir="$DATADIR/fs/kube-$POD_NAME/oci/volumes/secret-volume"
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

# Verify projected keys from "mysecret" at /oci/volumes/foo/.
# K8s docs: "username key stored under my-group/my-username instead of username"
test_static_secret_projected() {
    local test_name="static-secret-projected"
    if [[ $POD_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "pod not created"
        return
    fi

    local vol_dir="$DATADIR/fs/kube-$POD_NAME/oci/volumes/foo"
    local fail=0

    # Should have my-group/my-username (projected path from docs).
    if [[ ! -f "$vol_dir/my-group/my-username" ]]; then
        echo "    missing: $vol_dir/my-group/my-username"
        fail=1
    elif [[ "$(cat "$vol_dir/my-group/my-username")" != "projuser" ]]; then
        echo "    wrong content: my-group/my-username=$(cat "$vol_dir/my-group/my-username")"
        fail=1
    fi

    # "password" key should NOT be present (not listed in items).
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

# Verify defaultMode permissions.
# K8s docs: "defaultMode: 0400" sets file permissions to 0400.
test_static_secret_permissions() {
    local test_name="static-secret-permissions"
    if [[ $POD_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "pod not created"
        return
    fi

    local fail=0

    # secret-volume: default mode (0644).
    local all_dir="$DATADIR/fs/kube-$POD_NAME/oci/volumes/secret-volume"
    for f in username password; do
        local mode
        mode=$(stat -c '%a' "$all_dir/$f" 2>/dev/null || echo "???")
        if [[ "$mode" != "644" ]]; then
            echo "    $f: expected 644, got $mode"
            fail=1
        fi
    done

    # foo: defaultMode 0400 (from K8s docs).
    local proj_dir="$DATADIR/fs/kube-$POD_NAME/oci/volumes/foo"
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

test_static_volume_mount_dirs() {
    local test_name="static-volume-mount-dirs"
    if [[ $POD_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "pod not created"
        return
    fi

    local fail=0
    local app_root="$DATADIR/fs/kube-$POD_NAME/oci/apps/test-container/root"

    if [[ ! -d "$app_root/etc/secret-volume" ]]; then
        echo "    missing mount point: $app_root/etc/secret-volume"
        fail=1
    fi
    if [[ ! -d "$app_root/etc/foo" ]]; then
        echo "    missing mount point: $app_root/etc/foo"
        fail=1
    fi

    if [[ $fail -eq 0 ]]; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "mount point directories missing"
    fi
}

test_static_volume_service() {
    local test_name="static-volume-service"
    if [[ $POD_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "pod not created"
        return
    fi

    local unit_path="$DATADIR/fs/kube-$POD_NAME/etc/systemd/system/sdme-kube-volumes.service"
    if [[ ! -f "$unit_path" ]]; then
        record "$test_name" FAIL "sdme-kube-volumes.service not found"
        return
    fi

    local unit
    unit=$(cat "$unit_path")
    local fail=0

    if ! echo "$unit" | grep -q '/oci/volumes/secret-volume'; then
        echo "    missing: bind mount for secret-volume"
        fail=1
    fi
    if ! echo "$unit" | grep -q '/oci/volumes/foo'; then
        echo "    missing: bind mount for foo"
        fail=1
    fi

    if [[ $fail -eq 0 ]]; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "volume service incomplete"
        echo "    unit content:"
        echo "$unit"
    fi
}

# --- Runtime checks -----------------------------------------------------------

test_start_pod() {
    local test_name="start-pod"
    if [[ $POD_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "pod not created"
        return
    fi

    echo "--- $test_name: starting pod ---"
    local output
    if output=$(timeout "$TIMEOUT_BOOT" "$SDME" start "$POD_NAME" -v 2>&1); then
        record "$test_name" PASS
        POD_RUNNING=1
        echo "    waiting 5s for services to settle..."
        sleep 5
    else
        record "$test_name" FAIL "$output"
    fi
}

# Verify the container can read all keys from /etc/secret-volume/.
test_runtime_read_all_keys() {
    local test_name="runtime-read-all-keys"
    if [[ $POD_RUNNING -eq 0 ]]; then
        record "$test_name" SKIP "pod not running"
        return
    fi

    local fail=0

    local output
    output=$("$SDME" exec "$POD_NAME" --oci -- \
        cat /etc/secret-volume/username 2>/dev/null || echo "")
    if ! echo "$output" | grep -q 'my-app'; then
        echo "    username: expected 'my-app', got: $output"
        fail=1
    fi

    output=$("$SDME" exec "$POD_NAME" --oci -- \
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

# Verify the container can read the projected key at /etc/foo/my-group/my-username.
test_runtime_read_projected() {
    local test_name="runtime-read-projected"
    if [[ $POD_RUNNING -eq 0 ]]; then
        record "$test_name" SKIP "pod not running"
        return
    fi

    local output
    output=$("$SDME" exec "$POD_NAME" --oci -- \
        cat /etc/foo/my-group/my-username 2>/dev/null || echo "")
    if echo "$output" | grep -q 'projuser'; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "expected 'projuser', got: $output"
    fi
}

# --- Secret rm test (after pod tests) ----------------------------------------

test_secret_rm() {
    local test_name="secret-rm"

    # Create a throwaway secret to test rm independently.
    local rm_name="vfy-ks-rm-test"
    "$SDME" kube secret create "$rm_name" --from-literal k=v 2>/dev/null || true

    local output
    if output=$("$SDME" kube secret rm "$rm_name" 2>&1); then
        # Verify it's gone.
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

# --- Missing secret test (no pod needed) --------------------------------------

test_missing_secret_error() {
    local test_name="missing-secret-error"

    local yaml_file
    yaml_file=$(mktemp /tmp/kube-secret-miss-XXXXXX.yaml)

    # From K8s docs pattern but with a nonexistent secret name.
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

# --- Main ---------------------------------------------------------------------

main() {
    parse_standard_args "End-to-end verification of sdme Kubernetes secrets and configmaps." "$@"

    ensure_root
    ensure_sdme

    ensure_default_base_fs

    echo "=== sdme kube secrets verification ==="
    echo "base-fs: $BASE_FS"
    echo "pod:     $POD_NAME"
    echo ""

    # Phase 1: Secret lifecycle.
    echo "--- secret lifecycle ---"
    test_secret_create
    test_secret_ls
    test_secret_key_count
    test_secret_duplicate

    # Phase 2: Create pod with secret volumes (from K8s docs example).
    echo ""
    test_create_pod

    # Phase 3: Static checks (rootfs content).
    echo ""
    echo "--- static checks ---"
    test_static_secret_all_keys
    test_static_secret_projected
    test_static_secret_permissions
    test_static_volume_mount_dirs
    test_static_volume_service

    # Phase 4: Runtime checks.
    echo ""
    echo "--- runtime checks ---"
    test_start_pod
    test_runtime_read_all_keys
    test_runtime_read_projected

    # Phase 5: Secret rm and error handling.
    echo ""
    echo "--- cleanup and error handling ---"
    test_secret_rm
    test_secret_rm_not_found
    test_missing_secret_error

    generate_standard_report "verify-kube-L3-secrets" "sdme Kube Secrets Verification Report"

    print_summary
}

main "$@"
