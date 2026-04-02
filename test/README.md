# E2E Tests

End-to-end tests for sdme. Runs real containers via systemd-nspawn,
imports rootfs from OCI registries, and validates the full lifecycle.
Requires root and a working systemd >= 255.

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
    verify-tutorial.sh (batch ops: stop --all, rm --all).
```

Runner options: `--jobs N`, `--timeout-scale N`, `--stagger N`,
`--skip SCRIPT`, `--only SCRIPT`, `--no-setup`. See `--help`.

## Test scripts

```
Script                       Description
---------------------------  -------------------------------------------
preflight.sh                 Environment validation (no containers)
smoke.sh                     Container lifecycle gate test
verify-interrupt.sh          SIGINT/SIGTERM abort handling
verify-cp.sh                 File copy: host, containers, rootfs
verify-export.sh             Export: dir, tar, raw image, xattrs
verify-build.sh              sdme fs build, COPY, locking, resume
verify-security.sh           Capabilities, seccomp, AppArmor, userns
verify-pods.sh               Pod shared network namespace
verify-network.sh            Zones, bridges, service masking, LLMNR
verify-oci.sh                OCI port forwarding and volume mounting
verify-distro-boot.sh        Boot + hardened boot across 7 distros
verify-distro-oci.sh         OCI app matrix: 3 apps x 7 distros
verify-nixos.sh              NixOS container, OCI app, kube pod
verify-tutorial.sh           Tutorial walkthrough end-to-end
verify-kube-L1-basic.sh      Kube lifecycle, YAML validation, emptyDir
verify-kube-L2-spec.sh       Pod spec, initContainers, resources
verify-kube-L2-probes.sh     Startup, liveness, readiness probes
verify-kube-L2-security.sh   Kube securityContext, capabilities
verify-kube-L3-secrets.sh    Secret create/ls/rm, volume, envFrom
verify-kube-L3-volumes.sh    emptyDir, hostPath, PVC, configMap, secret
verify-kube-L4-networking.sh Inter-container localhost networking
verify-kube-L5-redis-stack.sh Redis multi-container pod
verify-kube-L6-gitea-stack.sh Gitea + MySQL + Nginx stack
```

## Prerequisites

- Root access
- systemd >= 255 with systemd-nspawn, machinectl, journalctl, busctl
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

Last verified: 2026-04-02

System: Linux 6.17.0-19-generic (aarch64), systemd 257, sdme 0.5.7,
AppArmor enabled

```
Test Suite                 Pass  Fail  Skip  Status
-------------------------  ----  ----  ----  ------
verify-build                 11     0     0  PASS
verify-cp                    17     0     0  PASS
verify-distro-boot           56     7     0  FAIL*
verify-distro-oci             -     -     -  (killed)
verify-export                22     0     1  PASS
verify-kube-L1-basic         14     0     0  PASS
verify-kube-L2-probes        41     0     0  PASS
verify-kube-L2-security      17     0     0  PASS
verify-kube-L2-spec          12     0     0  PASS
verify-kube-L3-secrets       16     0     0  PASS
verify-kube-L3-volumes       39     0     0  PASS
verify-kube-L4-networking     6     0     0  PASS
verify-kube-L5-redis-stack    6     0     0  PASS
verify-kube-L6-gitea-stack   15     0     0  PASS
verify-network                9     0     0  PASS
verify-nixos                 26     0     0  PASS
verify-oci                   18     0     0  PASS
verify-pods                   9     0     0  PASS
verify-security               -     -     -  FAIL*
verify-tutorial               -     -     -  (killed)
-------------------------  ----  ----  ----  ------
Totals                      334     7     1  17/20 suites ran
```

*Hardened-boot (--userns) timeouts on aarch64 Lima VM under
parallel load. Standard boot passes for all 7 distros. Security
userns tests have the same root cause. See 0.5.7 log entry.

## Log

### 0.5.7 -- patch release, dead code cleanup (2026-04-02, aarch64)

334 passed, 7 failed, 1 skipped across 17 suites (distro-oci and
tutorial killed due to long runtime; security not recorded). Fixed
ps-kube-column test to use --json (KUBE column removed from text
table in fba5ee3). All 7 failures are hardened-boot (--userns)
timeouts on aarch64 Lima VM -- nspawn falls back to recursive
chown when idmapped mounts are not available on overlayfs. Standard
boot passes for all 7 distros. Switched --private-users-ownership
from map to auto so nspawn picks the best strategy per filesystem.
Bumped userns test timeouts to 5 min. All kube L1-L6, nixos, oci,
pods, network, build, cp, export clean.

### 0.5.4 -- tutorial test rewrite, website docs (2026-03-30, aarch64)

626 passed, 0 failed, 1 skipped across 20 suites. Replaced
verify-usage.sh with verify-tutorial.sh: each test section now maps
1:1 to a website tutorial. New tests for management (help, ps --json,
cp), services (fedora + zone + hardened), oci-volumes (postgres
persistence across rm/recreate), and pod --oci-pod (redis). Dropped
tests covered by verify-security.sh. verify-network zone issues from
0.5.3 resolved on this system. Wall clock: 19m55s.

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
