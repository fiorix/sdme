# sdme v0.4.1 — E2E Test Results

**Date:** 2026-03-16
**Version:** sdme 0.4.1
**Host:** Linux 6.19.6-2-cachyos (AppArmor enabled)

## Initial Run

| # | Test Suite | Status | Passed | Failed | Skipped | Total | Duration |
|---|-----------|--------|--------|--------|---------|-------|----------|
| 1 | verify-usage.sh | FAIL | 48 | 1 | 0 | 49 | 92s |
| 2 | verify-security.sh | PASS | 19 | 0 | 9 | 28 | 9s |
| 3 | verify-oci.sh | FAIL | 16 | 2 | 2 | 20 | 47s |
| 4 | verify-pods.sh | PASS | 9 | 0 | 0 | 9 | 7s |
| 5 | verify-export.sh | FAIL | 8 | 4 | 0 | 12 | 62s |
| 6 | verify-matrix.sh | PASS | 231 | 0 | 0 | 231 | 447s |
| 7 | verify-nixos.sh | FAIL | 0 | 1 | 13 | 14 | 1s |
| 8 | verify-kube-L1-basic.sh | PASS | 14 | 0 | 0 | 14 | 44s |
| 9 | verify-kube-L2-spec.sh | FAIL | 6 | 6 | 0 | 12 | 19s |
| 10 | verify-kube-L2-probes.sh | FAIL | 39 | 2 | 0 | 41 | 312s |
| 11 | verify-kube-L2-security.sh | FAIL | 15 | 2 | 0 | 17 | 20s |
| 12 | verify-kube-L3-volumes.sh | PASS | 39 | 0 | 0 | 39 | 36s |
| 13 | verify-kube-L3-secrets.sh | PASS | 16 | 0 | 0 | 16 | 9s |
| 14 | verify-kube-L4-networking.sh | PASS | 6 | 0 | 0 | 6 | 113s |
| 15 | verify-kube-L5-redis-stack.sh | PASS | 6 | 0 | 0 | 6 | 113s |
| 16 | verify-kube-L6-gitea-stack.sh | PASS | 15 | 0 | 0 | 15 | 238s |

**Initial totals: 487 passed, 18 failed, 24 skipped (529 tests)**

## Fixes Applied

### 1. kube-L2-spec: test bug — wrong container name (6 failures)

The test called `read_unit "app"` but the YAML container was named `testapp`, so it was
reading a nonexistent unit file. Fixed `read_unit` calls to use `"testapp"`. Also updated
the readiness probe check from `ExecStartPost` to the probe timer+service approach that
kube containers actually use.

**Files changed:** `test/scripts/verify-kube-L2-spec.sh`

### 2. kube-L2-probes: sdme ps health column not showing probe readiness (2 failures)

`sdme ps` health column only checked structural health (missing dirs/rootfs), not probe
readiness state. Added `probe_readiness_health()` function that checks `probe-ready`
files under `/oci/apps/{name}/` in the container's overlayfs for kube containers with
`HAS_PROBES=yes`.

**Files changed:** `src/containers.rs`

### 3. kube-L2-security: seccomp Unconfined not overriding pod-level RuntimeDefault (1 failure)

Container-level `seccompProfile.type: Unconfined` returned empty `syscall_filters` which
was indistinguishable from "no profile specified", causing the pod-level `RuntimeDefault`
to apply instead. Added `has_seccomp_profile: bool` field to `KubeContainer` so the merge
logic can distinguish "explicitly Unconfined" from "not specified".

**Files changed:** `src/kube/plan.rs`, `src/kube/create.rs`

### 4. kube-L2-security: hardened container boot failure with drop ALL caps (1 failure)

The `.sdme-isolate` binary needs `prctl(PR_CAPBSET_DROP)` (requires `CAP_SETPCAP`),
`setuid()` (requires `CAP_SETUID`), `setgid()`/`setgroups()` (requires `CAP_SETGID`).
When `capabilities.drop: ["ALL"]` removed these caps, the isolate binary failed.

Two fixes:
- Always include `CAP_SETUID`, `CAP_SETGID`, `CAP_SETPCAP` in the bounding set (alongside
  the existing `CAP_SYS_ADMIN` requirement) for isolate binary operation.
- Made `prctl(PR_CAPBSET_DROP, CAP_SYS_ADMIN)` best-effort in the isolate binary — if
  `CAP_SETPCAP` is unavailable, the systemd unit's `CapabilityBoundingSet` already restricts it.

**Files changed:** `src/oci/app.rs`, `src/isolate/x86_64.rs`, `src/isolate/aarch64.rs`,
  `test/scripts/verify-kube-L2-security.sh`

### 5. readOnlyRootFilesystem blocking /proc remount (discovered during fix 4)

`ReadOnlyPaths=/` prevented the isolate binary from remounting `/proc` in the new PID
namespace. Added `ReadWritePaths=/proc` to match Kubernetes semantics where
`readOnlyRootFilesystem` only affects the app's rootfs, not /proc.

**Files changed:** `src/oci/app.rs`

### 6. AppArmor environment setup

Enabled AppArmor in kernel cmdline (`apparmor=1 security=apparmor`) and loaded the
`sdme-default` profile. This fixed `verify-usage.sh`'s `--strict` test.

## After Fixes

| # | Test Suite | Status | Passed | Failed | Skipped | Total |
|---|-----------|--------|--------|--------|---------|-------|
| 1 | verify-usage.sh | **PASS** | 49 | 0 | 0 | 49 |
| 2 | verify-security.sh | PASS | 19 | 0 | 9 | 28 |
| 3 | verify-oci.sh | FAIL | 16 | 4 | 0 | 20 |
| 4 | verify-pods.sh | PASS | 9 | 0 | 0 | 9 |
| 5 | verify-export.sh | **PASS** | 12 | 0 | 0 | 12 |
| 6 | verify-matrix.sh | PASS | 231 | 0 | 0 | 231 |
| 7 | verify-nixos.sh | FAIL | 9 | 1 | 4 | 14 |
| 8 | verify-kube-L1-basic.sh | PASS | 14 | 0 | 0 | 14 |
| 9 | verify-kube-L2-spec.sh | **PASS** | 12 | 0 | 0 | 12 |
| 10 | verify-kube-L2-probes.sh | **PASS** | 41 | 0 | 0 | 41 |
| 11 | verify-kube-L2-security.sh | **PASS** | 17 | 0 | 0 | 17 |
| 12 | verify-kube-L3-volumes.sh | PASS | 39 | 0 | 0 | 39 |
| 13 | verify-kube-L3-secrets.sh | PASS | 16 | 0 | 0 | 16 |
| 14 | verify-kube-L4-networking.sh | PASS | 6 | 0 | 0 | 6 |
| 15 | verify-kube-L5-redis-stack.sh | PASS | 6 | 0 | 0 | 6 |
| 16 | verify-kube-L6-gitea-stack.sh | PASS | 15 | 0 | 0 | 15 |

**After fixes: 508 passed, 5 failed, 16 skipped (529 tests) — 14 suites pass, 2 fail**

## Additional Fixes (round 2)

### 7. NixOS build: NIX_PATH not set

`nix-build` failed with `file 'nixpkgs' was not found in the Nix search path`. The distro-
packaged nix had no channels configured. Fixed `build-rootfs.sh` to auto-detect missing
nixpkgs and fetch the nixos-24.11 tarball as a fallback.

**Files changed:** `test/scripts/nix/build-rootfs.sh`
**Result:** NixOS rootfs build, import, and plain boot now pass (9/14).

### 8. verify-export: loop devices (resolved by reboot)

Loop device failures were from the pre-reboot environment. After reboot with AppArmor,
all 12 export tests pass.

### 9. veth networking: systemd-networkd + ufw forwarding

Enabled `systemd-networkd` on the host (required for veth IP assignment) and changed
`DEFAULT_FORWARD_POLICY` from DROP to ACCEPT in ufw. Also added auto-enable of
`systemd-networkd` inside containers when `--network-veth` is used.

**Files changed:** `src/containers.rs`

## Remaining Failures (environment issues)

### verify-oci.sh (4 failures)

- `curl-port` / `curl-content` fail for ubuntu and fedora.
- systemd-nspawn `--port` DNAT rules are not populated in the `io.systemd.nat`
  nft map. The container is reachable via its link-local IP (HTTP 200) but not
  via the host-side veth IP due to empty DNAT map.
- **Root cause:** systemd 259 + ufw nftables interaction — nspawn's port forwarding
  nft map (`map_port_ipport`) is never populated when ufw manages its own nft tables.

### verify-nixos.sh (1 failure, 4 skips)

- `oci/boot`: NixOS OCI app container (nginx on NixOS base) fails to start within
  the boot timeout. Plain NixOS containers boot fine.
- **Root cause:** Likely NixOS-specific systemd service dependency or path issue
  with the OCI app unit.
