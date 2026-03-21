#!/usr/bin/env bash
set -uo pipefail

# verify-kube-L6-gitea-stack.sh - end-to-end verification of Gitea + MySQL + Nginx
# Run as root. Requires a base-fs imported (e.g. ubuntu).
#
# Deploys a Gitea + MySQL + Nginx stack as a single kube pod and verifies:
#   - MySQL accepts connections
#   - Gitea starts and serves its API
#   - Nginx reverse-proxies to Gitea
#   - REST API token creation, repo creation, and read-back through Nginx

source "$(dirname "$0")/lib.sh"

BASE_FS="${BASE_FS:-ubuntu}"
DATADIR="/var/lib/sdme"
REPORT_DIR="."

POD_NAME="gitea-pod"
YAML_FILE="test/kube/gitea-stack.yaml"

# Timeouts (seconds)
TIMEOUT_CREATE=$(scale_timeout 600)
TIMEOUT_BOOT=$(scale_timeout 120)
TIMEOUT_MYSQL=$(scale_timeout 90)
TIMEOUT_GITEA=$(scale_timeout 90)
TIMEOUT_NGINX=$(scale_timeout 30)
TIMEOUT_ADMIN=$(scale_timeout 60)

# State flags
POD_CREATED=0
POD_RUNNING=0

# --- Cleanup ------------------------------------------------------------------

cleanup() {
    echo "==> Cleaning up..."
    "$SDME" kube delete "$POD_NAME" --force 2>/dev/null || true
}

trap cleanup EXIT INT TERM

# --- Phase 1: Create kube pod ------------------------------------------------

test_create_pod() {
    local test_name="create/kube"
    echo "--- $test_name: creating kube pod ---"

    if [[ ! -f "$YAML_FILE" ]]; then
        record "$test_name" FAIL "YAML file not found: $YAML_FILE"
        return
    fi

    local output
    if output=$(timeout "$TIMEOUT_CREATE" "$SDME" kube create -f "$YAML_FILE" --base-fs "$BASE_FS" -v 2>&1); then
        record "$test_name" PASS
        POD_CREATED=1
    else
        record "$test_name" FAIL "$output"
    fi
}

# --- Phase 2: Inject nginx reverse proxy config ------------------------------

test_setup_nginx_config() {
    local test_name="setup/nginx-config"
    if [[ $POD_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "pod not created"
        return
    fi

    echo "--- $test_name: writing nginx reverse proxy config ---"
    local conf_dir="$DATADIR/containers/$POD_NAME/upper/oci/apps/nginx-unprivileged/root/etc/nginx/conf.d"
    mkdir -p "$conf_dir"

    cat > "$conf_dir/default.conf" <<'NGINXEOF'
server {
    listen 8080;
    server_name _;
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
NGINXEOF

    if [[ -f "$conf_dir/default.conf" ]]; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "could not write nginx config"
    fi
}

# --- Phase 3: Write Python validation script ----------------------------------

test_setup_validate_script() {
    local test_name="setup/validate-script"
    if [[ $POD_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "pod not created"
        return
    fi

    echo "--- $test_name: writing validation script ---"
    local script_dir="$DATADIR/containers/$POD_NAME/upper/opt/sdme-test"
    mkdir -p "$script_dir"

    cat > "$script_dir/validate.py" <<'PYEOF'
#!/usr/bin/env python3
"""Gitea validation: create API token, create repo, read repo through Nginx."""

import http.client
import json
import sys
import base64

TEST_MARKER = sys.argv[1] if len(sys.argv) > 1 else "sdme-test"

GITEA_HOST = "127.0.0.1"
GITEA_PORT = 3000
NGINX_PORT = 8080
ADMIN_USER = "admin"
ADMIN_PASS = "adminpass123!"


def result(name, passed, msg=""):
    status = "PASS" if passed else "FAIL"
    print(f"RESULT {name} {status} {msg}")
    return passed


def api_request(host, port, method, path, body=None, headers=None):
    """Make an HTTP request and return (status, parsed_json_or_None, raw_body)."""
    conn = http.client.HTTPConnection(host, port, timeout=30)
    hdrs = headers or {}
    if body is not None and "Content-Type" not in hdrs:
        hdrs["Content-Type"] = "application/json"
    conn.request(method, path, body=body, headers=hdrs)
    resp = conn.getresponse()
    raw = resp.read().decode("utf-8", errors="replace")
    conn.close()
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        data = None
    return resp.status, data, raw


def create_token():
    """Create an API token via Basic auth."""
    auth = base64.b64encode(f"{ADMIN_USER}:{ADMIN_PASS}".encode()).decode()
    headers = {"Authorization": f"Basic {auth}", "Content-Type": "application/json"}
    body = json.dumps({"name": f"test-{TEST_MARKER}", "scopes": ["all"]})

    status, data, raw = api_request(GITEA_HOST, GITEA_PORT, "POST",
                                    f"/api/v1/users/{ADMIN_USER}/tokens",
                                    body=body, headers=headers)

    if status not in (200, 201) or data is None:
        return result("validate/create-token", False, f"status={status} body={raw[:200]}"), None

    # Gitea changed the token field name across versions: check both
    token = data.get("sha1") or data.get("token") or data.get("plain_text")
    if not token:
        return result("validate/create-token", False, f"no token in response: {raw[:200]}"), None

    return result("validate/create-token", True, f"token={token[:8]}..."), token


def create_repo(token):
    """Create a test repository."""
    headers = {"Authorization": f"token {token}", "Content-Type": "application/json"}
    repo_name = f"test-repo-{TEST_MARKER}"
    body = json.dumps({"name": repo_name, "auto_init": True})

    status, data, raw = api_request(GITEA_HOST, GITEA_PORT, "POST",
                                    "/api/v1/user/repos",
                                    body=body, headers=headers)

    if status not in (200, 201) or data is None:
        return result("validate/create-repo", False, f"status={status} body={raw[:200]}"), None

    return result("validate/create-repo", True, f"repo={data.get('full_name', '?')}"), repo_name


def read_repo_through_nginx(token, repo_name):
    """Read the repo back through the Nginx reverse proxy."""
    headers = {"Authorization": f"token {token}"}

    status, data, raw = api_request(GITEA_HOST, NGINX_PORT, "GET",
                                    f"/api/v1/repos/{ADMIN_USER}/{repo_name}",
                                    headers=headers)

    if status != 200 or data is None:
        result("validate/read-repo", False, f"status={status} body={raw[:200]}")
        return result("validate/repo-name-match", False, "skipped: read failed")

    result("validate/read-repo", True)

    actual_name = data.get("name", "")
    if actual_name == repo_name:
        return result("validate/repo-name-match", True, f"name={actual_name}")
    else:
        return result("validate/repo-name-match", False,
                       f"expected={repo_name} actual={actual_name}")


def main():
    ok, token = create_token()
    if not ok or token is None:
        result("validate/create-repo", False, "skipped: token creation failed")
        result("validate/read-repo", False, "skipped: token creation failed")
        result("validate/repo-name-match", False, "skipped: token creation failed")
        return 1

    ok, repo_name = create_repo(token)
    if not ok or repo_name is None:
        result("validate/read-repo", False, "skipped: repo creation failed")
        result("validate/repo-name-match", False, "skipped: repo creation failed")
        return 1

    read_repo_through_nginx(token, repo_name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
PYEOF

    if [[ -f "$script_dir/validate.py" ]]; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "could not write validation script"
    fi
}

# --- Phase 4: Start and check services ---------------------------------------

test_start_pod() {
    local test_name="start/pod"
    if [[ $POD_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "pod not created"
        return
    fi

    echo "--- $test_name: starting pod ---"
    local output
    if output=$(timeout "$TIMEOUT_BOOT" "$SDME" start "$POD_NAME" -t 120 -v 2>&1); then
        record "$test_name" PASS
        POD_RUNNING=1
        echo "    waiting 10s for services to settle..."
        sleep 10
    else
        record "$test_name" FAIL "$output"
    fi
}

test_service_active() {
    local service_name="$1" test_name="$2"
    if [[ $POD_RUNNING -eq 0 ]]; then
        record "$test_name" SKIP "pod not running"
        return
    fi

    echo "--- $test_name: checking service ---"
    local output
    if output=$("$SDME" exec "$POD_NAME" -- /usr/bin/systemctl is-active "sdme-oci-${service_name}.service" 2>&1) && \
       [[ "$output" == *"active"* ]]; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "$output"
    fi
}

test_ready_mysql() {
    local test_name="ready/mysql"
    if [[ $POD_RUNNING -eq 0 ]]; then
        record "$test_name" SKIP "pod not running"
        return
    fi

    echo "--- $test_name: waiting for MySQL (up to ${TIMEOUT_MYSQL}s) ---"
    if "$SDME" exec "$POD_NAME" -- /usr/bin/python3 -c "
import socket,sys,time
end=time.time()+${TIMEOUT_MYSQL}
while time.time()<end:
 try: s=socket.create_connection(('127.0.0.1',3306),2); s.close(); sys.exit(0)
 except: time.sleep(3)
sys.exit(1)" 2>/dev/null; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "port 3306 not listening after ${TIMEOUT_MYSQL}s"
    fi
}

test_ready_gitea() {
    local test_name="ready/gitea"
    if [[ $POD_RUNNING -eq 0 ]]; then
        record "$test_name" SKIP "pod not running"
        return
    fi
    if [[ "$(result_status "ready/mysql")" != "PASS" ]]; then
        record "$test_name" SKIP "mysql not ready"
        return
    fi

    echo "--- $test_name: waiting for Gitea (up to ${TIMEOUT_GITEA}s) ---"
    if "$SDME" exec "$POD_NAME" -- /usr/bin/python3 -c "
import socket,sys,time
end=time.time()+${TIMEOUT_GITEA}
while time.time()<end:
 try: s=socket.create_connection(('127.0.0.1',3000),2); s.close(); sys.exit(0)
 except: time.sleep(3)
sys.exit(1)" 2>/dev/null; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "port 3000 not listening after ${TIMEOUT_GITEA}s"
    fi
}

test_ready_nginx() {
    local test_name="ready/nginx"
    if [[ $POD_RUNNING -eq 0 ]]; then
        record "$test_name" SKIP "pod not running"
        return
    fi

    echo "--- $test_name: waiting for Nginx (up to ${TIMEOUT_NGINX}s) ---"
    if "$SDME" exec "$POD_NAME" -- /usr/bin/python3 -c "
import socket,sys,time
end=time.time()+${TIMEOUT_NGINX}
while time.time()<end:
 try: s=socket.create_connection(('127.0.0.1',8080),2); s.close(); sys.exit(0)
 except: time.sleep(3)
sys.exit(1)" 2>/dev/null; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "port 8080 not listening after ${TIMEOUT_NGINX}s"
    fi
}

# --- Phase 5: Create admin user -----------------------------------------------

test_setup_admin_user() {
    local test_name="setup/admin-user"
    if [[ $POD_RUNNING -eq 0 ]]; then
        record "$test_name" SKIP "pod not running"
        return
    fi
    if [[ "$(result_status "ready/gitea")" != "PASS" ]]; then
        record "$test_name" SKIP "gitea not ready"
        return
    fi

    echo "--- $test_name: creating Gitea admin user (up to ${TIMEOUT_ADMIN}s) ---"
    local deadline=$((SECONDS + TIMEOUT_ADMIN))
    local output rc

    while [[ $SECONDS -lt $deadline ]]; do
        output=$("$SDME" exec "$POD_NAME" --oci gitea -- \
            /bin/su -s /bin/bash -c \
            "/usr/local/bin/gitea admin user create --admin --username admin --password 'adminpass123!' --email admin@test.local" \
            git 2>&1)
        rc=$?
        if [[ $rc -eq 0 ]] || [[ "$output" == *"already exists"* ]]; then
            record "$test_name" PASS
            return
        fi
        echo "    retrying admin user creation in 5s... (rc=$rc)"
        sleep 5
    done

    record "$test_name" FAIL "could not create admin user after ${TIMEOUT_ADMIN}s: $output"
}

# --- Phase 6: Validate Gitea through Nginx ------------------------------------

test_validate_gitea() {
    if [[ $POD_RUNNING -eq 0 ]]; then
        for t in validate/create-token validate/create-repo validate/read-repo validate/repo-name-match; do
            record "$t" SKIP "pod not running"
        done
        return
    fi
    if [[ "$(result_status "setup/admin-user")" != "PASS" || "$(result_status "ready/nginx")" != "PASS" ]]; then
        for t in validate/create-token validate/create-repo validate/read-repo validate/repo-name-match; do
            record "$t" SKIP "services not ready"
        done
        return
    fi

    local test_marker="sdme-$(date +%s)"
    echo "--- validate: running Gitea validation (marker=$test_marker) ---"

    local output
    output=$("$SDME" exec "$POD_NAME" -- /usr/bin/python3 /opt/sdme-test/validate.py "$test_marker" 2>&1)
    local rc=$?

    echo "$output"

    # Parse RESULT lines from the Python script output
    local found_results=0
    while IFS= read -r line; do
        if [[ "$line" == RESULT\ * ]]; then
            found_results=1
            local name status msg
            name=$(echo "$line" | awk '{print $2}')
            status=$(echo "$line" | awk '{print $3}')
            msg=$(echo "$line" | cut -d' ' -f4-)
            record "$name" "$status" "$msg"
        fi
    done <<< "$output"

    if [[ $found_results -eq 0 ]]; then
        echo "    no RESULT lines found in output"
        for t in validate/create-token validate/create-repo validate/read-repo validate/repo-name-match; do
            if [[ -z "${RESULTS[$t]+x}" ]]; then
                record "$t" FAIL "no output from validation script (rc=$rc)"
            fi
        done
    fi
}

# --- Main ---------------------------------------------------------------------

main() {
    parse_standard_args "End-to-end verification of sdme Kubernetes Gitea stack." "$@"

    ensure_root
    ensure_sdme
    require_gate smoke
    require_gate interrupt
    require_gate kube-l1

    ensure_default_base_fs

    echo "=== sdme Gitea pod verification ==="
    echo "base-fs: $BASE_FS"
    echo "pod:     $POD_NAME"
    echo ""

    # Phase 1: Create
    test_create_pod

    # Phase 2: Inject nginx config
    test_setup_nginx_config

    # Phase 3: Write validation script
    test_setup_validate_script

    # Phase 4: Start and check services
    test_start_pod
    test_service_active "mysql" "service/mysql"
    test_service_active "gitea" "service/gitea"
    test_service_active "nginx-unprivileged" "service/nginx"

    # Readiness checks
    test_ready_mysql
    test_ready_gitea
    test_ready_nginx

    # Phase 5: Create admin user
    test_setup_admin_user

    # Phase 6: Validate Gitea
    test_validate_gitea

    # Phase 7: Report
    generate_standard_report "verify-kube-L6-gitea" "sdme Kube Gitea Stack Verification Report"

    print_summary
}

main "$@"
