# Test Results

Last verified: 2026-03-19

System: Linux 6.17.0-19-generic (aarch64), systemd 257, sdme 0.4.5, AppArmor enabled

See [README.md](README.md) for how to run the tests and known limitations.

## Summary

| # | Test Suite | Status | Passed | Failed | Skipped | Total |
|---|-----------|--------|--------|--------|---------|-------|
| 1 | verify-usage.sh | PASS* | 48 | 1 | 0 | 49 |
| 2 | verify-security.sh | PASS | 31 | 0 | 0 | 31 |
| 3 | verify-oci.sh | PASS | 20 | 0 | 0 | 20 |
| 4 | verify-pods.sh | PASS | 9 | 0 | 0 | 9 |
| 5 | verify-export.sh | PASS | 12 | 0 | 0 | 12 |
| 6 | verify-matrix.sh | PASS | 264 | 0 | 0 | 264 |
| 7 | verify-nixos.sh | PASS | 27 | 0 | 0 | 27 |
| 8 | verify-kube-L1-basic.sh | PASS | 14 | 0 | 0 | 14 |
| 9 | verify-kube-L2-spec.sh | PASS | 12 | 0 | 0 | 12 |
| 10 | verify-kube-L2-probes.sh | PASS | 41 | 0 | 0 | 41 |
| 11 | verify-kube-L2-security.sh | PASS | 17 | 0 | 0 | 17 |
| 12 | verify-kube-L3-volumes.sh | PASS | 39 | 0 | 0 | 39 |
| 13 | verify-kube-L3-secrets.sh | PASS | 16 | 0 | 0 | 16 |
| 14 | verify-kube-L4-networking.sh | PASS | 6 | 0 | 0 | 6 |
| 15 | verify-kube-L5-redis-stack.sh | PASS | 6 | 0 | 0 | 6 |
| 16 | verify-kube-L6-gitea-stack.sh | PASS | 15 | 0 | 0 | 15 |

**Totals: 577 passed, 1 failed, 0 skipped (578 tests), 16/16 suites pass**

\* Known platform issue only (no code regression); see below.

### Pending verification

The following test changes have not yet been included in a full test pass:

- **verify-export.sh**: 4 new timezone tests added (Tests 13-16); total
  expected to rise from 12 to ~17 (Test 13 has 2 sub-assertions).
- **verify-network.sh**: new 9-test suite for private networking (service
  masking state, zone connectivity, bridge connectivity).

## Failures

### verify-usage.sh: opaque/verify (1 failure)

`getfattr` did not find the `trusted.overlay.opaque` xattr on the upper
layer directory. This is environment-specific (kernel/filesystem
configuration); the same test passes on x86_64 with kernel 6.19.

## Known Issues

No known issues at this time.

## Previous Results

### 0.4.5 -- nix-build pipeline removal (2026-03-19, aarch64)

Removed the built-in `DistroFamily::Nix` nix-build pipeline from sdme.
NixOS rootfs are now built externally via `test/scripts/build-nixos-rootfs.sh`
(pulls `docker.io/nixos/nix`, runs `nix-build` in a chroot, rebuilds a
clean rootfs from the closure) and imported as a directory. All 27
verify-nixos.sh tests pass: import, plain container boot, OCI
nginx-unprivileged app, single-container kube pod, and multi-service
kube pod (nginx + redis + mysql).

### 0.4.4 -- openSUSE caps fix (2026-03-19, aarch64)

The built-in Suse import prehook now strips `security.capability`
xattrs from `newuidmap`/`newgidmap`, fixing the idmapped mount error
that blocked `--userns` and `--hardened` on openSUSE. The original
prehook passed both files to a single `setcap -r` invocation, but
`setcap` only accepts one file per `-r` flag -- `newgidmap` was never
stripped. Splitting into two commands fixed all 3 failures and 23
port conflict skips (33/33 openSUSE matrix tests pass).

### 0.4.2 (2026-03-17, x86_64)

System: Linux 6.19.6-2-cachyos (x86_64), systemd 259, sdme 0.4.2

577 passed, 0 failed, 1 skipped (578 tests), 16/16 suites pass. All
264 matrix tests passed (including openSUSE hardened OCI apps on
x86_64).
