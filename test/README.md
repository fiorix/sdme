# E2E Tests

End-to-end tests for sdme. Runs real containers via systemd-nspawn,
imports rootfs from OCI registries, and validates the full lifecycle.
Requires root and a working systemd >= 252.

## Quick start

```bash
make e2e                # full suite (preflight + smoke + all tests)
make e2e-smoke          # smoke test only (lifecycle sanity check)
make e2e-preflight      # validate environment (no containers)
make e2e-quick          # export + build + interrupt tests only
```

Individual scripts are self-contained and can be run standalone:

```bash
sudo ./test/scripts/verify-export.sh
sudo ./test/scripts/verify-kube-L1-basic.sh --base-fs ubuntu
```

Options accepted by all scripts: `--report-dir DIR`, `--help`.
Set `VERBOSE=1` for detailed output on any script.

## Staged runner

The parallel runner (`run-parallel.sh`) executes in four stages:

```
Stage 0: Preflight
    Validate environment: root, sdme, systemd, binaries, overlayfs,
    disk space, optional deps, ports, Docker Hub, AppArmor.

Stage 1: Smoke + Interrupt (serial, gates)
    Build and install sdme, import base rootfs.
    Smoke test: create -> start -> boot -> exec -> stop -> rm.
    Interrupt test: SIGINT/SIGTERM during batch ops.
    If either fails, all downstream tests are skipped.

Stage 2: Parallel tests (semaphore-bounded, default 8 jobs)
    Wave A: all core tests + kube-L1.
    Wait for kube-L1 to complete.
    Wave B: kube L2-L6 (only if L1 passed).

Stage 3: Destructive (serial)
    verify-usage.sh (batch ops: stop --all, rm --all).
```

Runner options: `--jobs N`, `--timeout-scale N`, `--stagger N`,
`--skip SCRIPT`, `--only SCRIPT`, `--no-setup`. See `--help`.

## Test scripts

| Script | Description |
|--------|-------------|
| preflight.sh | Environment validation (no containers) |
| smoke.sh | Minimal container lifecycle gate test |
| verify-interrupt.sh | SIGINT/SIGTERM abort handling |
| verify-cp.sh | File copy between host, containers, rootfs, hard links |
| verify-export.sh | Rootfs/container export (dir, tar, raw image, hard links, xattrs) |
| verify-build.sh | `sdme fs build` hot COPY, source prefixes, locking, cache/resume |
| verify-security.sh | Capabilities, seccomp, AppArmor, userns, hardened |
| verify-pods.sh | Pod shared network namespace |
| verify-network.sh | Zones, bridges, service masking, LLMNR |
| verify-oci.sh | OCI port forwarding and volume mounting |
| verify-distro-boot.sh | Boot + hardened boot across 7 distros |
| verify-distro-oci.sh | OCI app matrix: 3 apps x 7 distros (+ hardened) |
| verify-nixos.sh | NixOS container, OCI app, kube pod |
| verify-usage.sh | CLI commands end-to-end across all features |
| verify-kube-L1-basic.sh | Kube lifecycle, YAML validation, emptyDir |
| verify-kube-L2-spec.sh | Pod spec compliance, initContainers, resources |
| verify-kube-L2-probes.sh | Startup, liveness, readiness probes |
| verify-kube-L2-security.sh | Kube securityContext, capabilities |
| verify-kube-L3-secrets.sh | Secret create/ls/rm, volume mount, envFrom |
| verify-kube-L3-volumes.sh | emptyDir, hostPath, PVC, configMap, secret |
| verify-kube-L4-networking.sh | Inter-container localhost networking |
| verify-kube-L5-redis-stack.sh | Redis multi-container pod |
| verify-kube-L6-gitea-stack.sh | Gitea + MySQL + Nginx stack |

## Prerequisites

- Root access
- systemd >= 252 with systemd-nspawn, machinectl, journalctl, busctl
- nsenter (util-linux)
- systemd-networkd running on host (for --network-veth tests)
- AppArmor with sdme-default profile loaded (for --strict tests)
- Free host ports: 5432, 8080

The preflight script (`make e2e-preflight`) checks all of these.

## Known limitations

### openSUSE + user namespaces (resolved)

openSUSE Tumbleweed ships newuidmap/newgidmap with security.capability
xattrs instead of setuid bits. The kernel refuses idmapped mounts when
these xattrs are present. The built-in Suse import prehook now strips
them automatically; both export prehooks restore them.

### NixOS + OCI apps (resolved)

NixOS activation replaces /etc/systemd/system with an immutable
symlink to the Nix store. OCI app units are now placed in
/etc/systemd/system.control/ on NixOS. See `oci::app::systemd_unit_dir()`.

### Redis 8 locale (workaround)

Redis 8+ treats locale config failure as fatal. Set `LANG=C.UTF-8`
via `--oci-env` or kube YAML `env`. The test suite applies this
automatically via `fix_redis_oci()` in lib.sh.

## Adding new tests

1. Choose a unique prefix for artifacts. Use `cleanup_prefix "prefix-"`
   in the cleanup trap.
2. Add `require_gate smoke` and `require_gate interrupt` after
   `ensure_root`/`ensure_sdme`.
3. Use `scale_timeout` for all timeout values.
4. Declare port usage in the lib.sh port inventory comment.
5. Add to `run-parallel.sh`: wave A for most tests, wave B for kube L2+.

## Results

Last verified: 2026-03-22

System: Linux 6.19.6-2-cachyos (x86_64), systemd 259, sdme 0.5.3,
AppArmor enabled

| # | Test Suite | Status | Pass | Fail | Skip |
|---|-----------|--------|------|------|------|
| 1 | verify-build | PASS | 11 | 0 | 0 |
| 2 | verify-cp | PASS | 17 | 0 | 0 |
| 3 | verify-distro-boot | PASS | 63 | 0 | 0 |
| 4 | verify-distro-oci | PASS | 175 | 0 | 0 |
| 5 | verify-export | PASS | 23 | 0 | 0 |
| 6 | verify-kube-L1-basic | PASS | 14 | 0 | 0 |
| 7 | verify-kube-L2-probes | PASS | 41 | 0 | 0 |
| 8 | verify-kube-L2-security | PASS | 17 | 0 | 0 |
| 9 | verify-kube-L2-spec | PASS | 12 | 0 | 0 |
| 10 | verify-kube-L3-secrets | PASS | 16 | 0 | 0 |
| 11 | verify-kube-L3-volumes | PASS | 39 | 0 | 0 |
| 12 | verify-kube-L4-networking | PASS | 6 | 0 | 0 |
| 13 | verify-kube-L5-redis-stack | PASS | 6 | 0 | 0 |
| 14 | verify-kube-L6-gitea-stack | PASS | 15 | 0 | 0 |
| 15 | verify-network | FAIL | 7 | 2 | 0 |
| 16 | verify-nixos | PASS | 26 | 0 | 0 |
| 17 | verify-oci | PASS | 18 | 0 | 0 |
| 18 | verify-pods | PASS | 9 | 0 | 0 |
| 19 | verify-security | PASS | 31 | 0 | 0 |
| 20 | verify-usage | PASS | 49 | 0 | 0 |

**Totals: 595 passed, 2 failed, 0 skipped -- 20 suites**

verify-network zone/http-via-ip and zone/llmnr-resolution fail with
"Network is unreachable" between zone containers. Environment issue
(systemd-networkd zone DHCP), not a code regression -- passed clean
on 0.5.2 on the same host.

## Log

### 0.5.3 -- code cleanup, hard link/xattr test fixes (2026-03-22, x86_64)

597 passed, 2 failed, 0 skipped across 20 suites. New tests: cp hard
link preservation (17 total), export tar hard links + tar xattrs + dir
export hard links (23 total). Fixed two test bugs: cp test used shadowed
/tmp path, export xattr test missing `--xattrs` flag on tar extract.
verify-network zone failures are environment-only (passed on 0.5.2).
Wall clock: 9m29s.

### 0.5.2 -- sdme cp, version bump (2026-03-22, x86_64)

593 passed, 0 failed, 0 skipped across 20 suites. New verify-cp suite
(16 tests). Clean run. Wall clock: 9m33s.

### 0.5.0 -- version bump, clean run (2026-03-21, x86_64)

577 passed, 0 failed, 0 skipped across 19 suites. All tests pass
on x86_64 with kernel 6.19.6, systemd 259. Wall clock: 9m34s.

### 0.4.8 -- test infrastructure revamp (2026-03-21, aarch64)

Staged runner with preflight, smoke, and interrupt gates. Matrix split
into verify-distro-boot.sh and verify-distro-oci.sh. Timeout scaling,
stale cleanup, kube-L1 gating. Makefile e2e targets added.
583 passed, 1 failed, 0 skipped -- 20 suites.

### 0.4.6 -- parallel runner (2026-03-21, aarch64)

575 passed, 1 failed, 0 skipped (576 tests), 18/18 suites pass.
Same known platform issue (opaque xattr on aarch64).

### 0.4.5 -- nix-build pipeline removal (2026-03-19, aarch64)

577 passed, 1 failed, 0 skipped (578 tests), 16/16 suites pass.
264 matrix tests (including NixOS, which has since been removed from
the matrix -- see verify-nixos.sh for dedicated NixOS testing).

### 0.4.4 -- openSUSE caps fix (2026-03-19, aarch64)

The built-in Suse import prehook now strips security.capability xattrs
from newuidmap/newgidmap, fixing the idmapped mount error that blocked
--userns and --hardened on openSUSE.

### 0.4.2 (2026-03-17, x86_64)

System: Linux 6.19.6-2-cachyos (x86_64), systemd 259, sdme 0.4.2

577 passed, 0 failed, 1 skipped (578 tests), 16/16 suites pass.
