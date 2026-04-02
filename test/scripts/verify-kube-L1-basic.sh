#!/usr/bin/env bash
set -uo pipefail

# verify-kube-L1-basic.sh - end-to-end verification of sdme kube apply/create/delete
# Run as root. Requires a base-fs imported (e.g. ubuntu).
#
# Tests:
# 1. Single container pod (nginx)
# 2. Two containers with shared emptyDir volume
# 3. Command override with busybox
# 4. Cleanup with sdme kube delete

source "$(dirname "$0")/lib.sh"

BASE_FS="${BASE_FS:-ubuntu}"
DATADIR="/var/lib/sdme"
REPORT_DIR="."

# Timeouts (seconds)
TIMEOUT_CREATE=$(scale_timeout 600)
TIMEOUT_BOOT=$(scale_timeout 120)

# --- Test 0: Validate YAML files with kubeconform ---
test_validate_yaml() {
    local kubeconform=""

    # Check PATH first.
    if command -v kubeconform &>/dev/null; then
        kubeconform="kubeconform"
    else
        # Download to /tmp if not available.
        local kc_bin="/tmp/kubeconform"
        if [[ -x "$kc_bin" ]]; then
            kubeconform="$kc_bin"
        else
            echo "--- validate/yaml: downloading kubeconform ---"
            local arch
            arch=$(uname -m)
            case "$arch" in
                x86_64)  arch="amd64" ;;
                aarch64) arch="arm64" ;;
            esac
            local url="https://github.com/yannh/kubeconform/releases/latest/download/kubeconform-linux-${arch}.tar.gz"
            if curl -fsSL "$url" | tar xz -C /tmp kubeconform 2>/dev/null; then
                chmod +x "$kc_bin"
                kubeconform="$kc_bin"
            fi
        fi
    fi

    if [[ -z "$kubeconform" ]]; then
        record "validate/yaml" SKIP "kubeconform not available"
        return
    fi

    local script_dir
    script_dir=$(dirname "$0")
    local yaml_dir="$script_dir/../kube"
    local fail=0

    for yaml_file in "$yaml_dir"/*.yaml; do
        local basename
        basename=$(basename "$yaml_file")
        if "$kubeconform" -strict "$yaml_file" 2>&1; then
            record "validate/yaml-$basename" PASS
        else
            record "validate/yaml-$basename" FAIL
            fail=1
        fi
    done

    if [[ $fail -eq 0 ]]; then
        echo "  all YAML files validated"
    fi
}

# --- Test 1: Single container nginx pod ---
test_single_container() {
    local test_name="single-container-nginx"
    local pod_name="vfy-kube-nginx"
    local yaml_file
    yaml_file=$(mktemp /tmp/kube-test-XXXXXX.yaml)

    cat > "$yaml_file" <<'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: vfy-kube-nginx
spec:
  containers:
  - name: nginx
    image: docker.io/nginx:latest
    ports:
    - containerPort: 80
YAML

    echo "--- $test_name: creating pod from YAML ---"
    if ! "$SDME" kube create -f "$yaml_file" --base-fs "$BASE_FS" -v 2>&1; then
        record "$test_name" FAIL
        rm -f "$yaml_file"
        return
    fi
    rm -f "$yaml_file"

    echo "--- $test_name: starting pod ---"
    if ! timeout "$TIMEOUT_BOOT" "$SDME" start "$pod_name" -v 2>&1; then
        record "$test_name" FAIL
        "$SDME" kube delete "$pod_name" --force 2>/dev/null || true
        return
    fi

    echo "--- $test_name: checking nginx service inside container ---"
    local ok=0 output
    for i in $(seq 1 10); do
        sleep 3
        output=$("$SDME" exec "$pod_name" -- /usr/bin/systemctl is-active sdme-oci-nginx.service 2>&1 || true)
        if echo "$output" | grep -q '^active'; then
            ok=1
            break
        fi
    done
    if [[ $ok -eq 1 ]]; then
        record "$test_name" PASS
    else
        echo "nginx service not active after retries"
        "$SDME" exec "$pod_name" -- /usr/bin/systemctl status sdme-oci-nginx.service 2>&1 || true
        record "$test_name" FAIL
    fi

    "$SDME" kube delete "$pod_name" --force 2>/dev/null || true
}

# --- Test 2: Command override with busybox ---
test_command_override() {
    local test_name="command-override"
    local pod_name="vfy-kube-cmd"
    local yaml_file
    yaml_file=$(mktemp /tmp/kube-test-XXXXXX.yaml)

    cat > "$yaml_file" <<'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: vfy-kube-cmd
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    command: ["/bin/sh", "-c"]
    args: ["echo hello-from-kube > /tmp/marker && sleep infinity"]
YAML

    echo "--- $test_name: creating pod ---"
    if ! "$SDME" kube create -f "$yaml_file" --base-fs "$BASE_FS" -v 2>&1; then
        record "$test_name" FAIL
        rm -f "$yaml_file"
        return
    fi
    rm -f "$yaml_file"

    echo "--- $test_name: starting pod ---"
    if ! timeout "$TIMEOUT_BOOT" "$SDME" start "$pod_name" -v 2>&1; then
        record "$test_name" FAIL
        "$SDME" kube delete "$pod_name" --force 2>/dev/null || true
        return
    fi

    sleep 3

    echo "--- $test_name: checking marker file ---"
    local marker
    marker=$("$SDME" exec "$pod_name" -- /usr/bin/cat /oci/apps/app/root/tmp/marker 2>/dev/null || echo "")
    if [[ "$marker" == *"hello-from-kube"* ]]; then
        record "$test_name" PASS
    else
        echo "marker file not found or wrong content: '$marker'"
        record "$test_name" FAIL
    fi

    "$SDME" kube delete "$pod_name" --force 2>/dev/null || true
}

# --- Test 3: kube delete removes both container and rootfs ---
test_kube_delete() {
    local test_name="kube-delete-cleanup"
    local pod_name="vfy-kube-del"
    local yaml_file
    yaml_file=$(mktemp /tmp/kube-test-XXXXXX.yaml)

    cat > "$yaml_file" <<'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: vfy-kube-del
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    command: ["/bin/sh", "-c", "sleep infinity"]
YAML

    echo "--- $test_name: creating pod ---"
    if ! "$SDME" kube create -f "$yaml_file" --base-fs "$BASE_FS" -v 2>&1; then
        record "$test_name" FAIL
        rm -f "$yaml_file"
        return
    fi
    rm -f "$yaml_file"

    # Verify state and rootfs exist.
    if [[ ! -f "$DATADIR/state/$pod_name" ]]; then
        echo "state file missing before delete"
        record "$test_name" FAIL
        "$SDME" kube delete "$pod_name" --force 2>/dev/null || true
        return
    fi

    echo "--- $test_name: deleting pod ---"
    if ! "$SDME" kube delete "$pod_name" 2>&1; then
        record "$test_name" FAIL
        return
    fi

    # Verify state and rootfs are gone.
    if [[ -f "$DATADIR/state/$pod_name" ]]; then
        echo "state file still exists after delete"
        record "$test_name" FAIL
        return
    fi
    if [[ -d "$DATADIR/fs/kube-$pod_name" ]]; then
        echo "rootfs dir still exists after delete"
        record "$test_name" FAIL
        return
    fi

    record "$test_name" PASS
}

# --- Test 4: Shared emptyDir volume between containers ---
test_shared_volume() {
    local test_name="shared-emptydir-volume"
    local pod_name="vfy-kube-vol"
    local yaml_file
    yaml_file=$(mktemp /tmp/kube-test-XXXXXX.yaml)

    cat > "$yaml_file" <<'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: vfy-kube-vol
spec:
  containers:
  - name: writer
    image: docker.io/busybox:latest
    command: ["/bin/sh", "-c", "echo shared-data > /shared/marker && sleep infinity"]
    volumeMounts:
    - name: shared
      mountPath: /shared
  - name: reader
    image: docker.io/busybox:latest
    command: ["/bin/sh", "-c", "sleep infinity"]
    volumeMounts:
    - name: shared
      mountPath: /shared
  volumes:
  - name: shared
    emptyDir: {}
YAML

    echo "--- $test_name: creating pod ---"
    if ! "$SDME" kube create -f "$yaml_file" --base-fs "$BASE_FS" -v 2>&1; then
        record "$test_name" FAIL
        rm -f "$yaml_file"
        return
    fi
    rm -f "$yaml_file"

    echo "--- $test_name: starting pod ---"
    if ! timeout "$TIMEOUT_BOOT" "$SDME" start "$pod_name" -v 2>&1; then
        record "$test_name" FAIL
        "$SDME" kube delete "$pod_name" --force 2>/dev/null || true
        return
    fi

    echo "--- $test_name: waiting for writer to create marker ---"
    local ok=0 marker
    for i in $(seq 1 10); do
        sleep 3
        marker=$("$SDME" exec "$pod_name" -- /usr/bin/cat /oci/apps/reader/root/shared/marker 2>/dev/null || echo "")
        if [[ "$marker" == *"shared-data"* ]]; then
            ok=1
            break
        fi
    done

    if [[ $ok -eq 1 ]]; then
        record "$test_name" PASS
    else
        echo "marker file not found or wrong content via reader: '$marker'"
        "$SDME" exec "$pod_name" -- /bin/ls -la /oci/volumes/shared/ 2>&1 || true
        record "$test_name" FAIL
    fi

    "$SDME" kube delete "$pod_name" --force 2>/dev/null || true
}

# --- Test 5: sdme ps shows kube metadata ---
test_ps_kube_column() {
    local test_name="ps-kube-column"
    local pod_name="vfy-kube-ps"
    local yaml_file
    yaml_file=$(mktemp /tmp/kube-test-XXXXXX.yaml)

    cat > "$yaml_file" <<'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: vfy-kube-ps
spec:
  containers:
  - name: web
    image: docker.io/busybox:latest
    command: ["/bin/sh", "-c", "sleep infinity"]
  - name: sidecar
    image: docker.io/busybox:latest
    command: ["/bin/sh", "-c", "sleep infinity"]
YAML

    echo "--- $test_name: creating pod ---"
    if ! "$SDME" kube create -f "$yaml_file" --base-fs "$BASE_FS" -v 2>&1; then
        record "$test_name" FAIL
        rm -f "$yaml_file"
        return
    fi
    rm -f "$yaml_file"

    echo "--- $test_name: checking sdme ps --json output ---"
    local ps_json kube_names
    ps_json=$("$SDME" ps --json 2>/dev/null)
    kube_names=$(echo "$ps_json" | jq -r '.[] | select(.name == "'"$pod_name"'") | .kube | sort | join(",")')
    if [[ "$kube_names" == "sidecar,web" ]]; then
        record "$test_name" PASS
    else
        echo "expected kube=['sidecar','web'], got: '$kube_names'"
        echo "$ps_json" | jq '.[] | select(.name == "'"$pod_name"'")'
        record "$test_name" FAIL
    fi

    "$SDME" kube delete "$pod_name" --force 2>/dev/null || true
}

# --- Main ---
main() {
    parse_standard_args "End-to-end verification of sdme kube apply/create/delete." "$@"

    ensure_root
    ensure_sdme
    require_gate smoke
    require_gate interrupt

    ensure_default_base_fs

    echo "=== sdme kube verification ==="
    echo "base-fs: $BASE_FS"
    echo ""

    test_validate_yaml
    test_single_container
    test_command_override
    test_kube_delete
    test_shared_volume
    test_ps_kube_column

    generate_standard_report "verify-kube" "sdme Kube Basic Verification Report"

    if [[ $_fail -eq 0 ]]; then
        write_gate kube-l1 pass
    else
        write_gate kube-l1 fail
    fi

    print_summary
}

main "$@"
