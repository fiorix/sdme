# Test Results

Last verified: 2026-03-17

System: Linux 6.19.6-2-cachyos (x86_64), systemd 259, sdme 0.4.2, AppArmor enabled

See [README.md](README.md) for how to run the tests and known limitations.

## Summary

| # | Test Suite | Status | Passed | Failed | Skipped | Total |
|---|-----------|--------|--------|--------|---------|-------|
| 1 | verify-usage.sh | PASS | 49 | 0 | 0 | 49 |
| 2 | verify-security.sh | PASS | 30 | 0 | 1 | 31 |
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

**Totals: 577 passed, 0 failed, 1 skipped (578 tests), 16/16 suites pass**

## Skipped Tests

- **verify-security.sh** (1 skip): AppArmor profile enforcement test skipped when
  the `sdme-container` AppArmor profile is not loaded on the host.

## Previous Failures (resolved in 0.4.2)

### verify-matrix.sh: openSUSE hardened OCI apps (was: 3 failures, 3 skips)

Previously, hardened OCI apps (nginx, redis, postgresql) on openSUSE Tumbleweed
failed because `security.capability` xattrs on `newuidmap`/`newgidmap` blocked
idmapped mounts. Fixed by stripping `security.capability` xattrs during rootfs
import. All 264 matrix tests now pass.

**TODO:** Stripping `security.capability` from `newuidmap`/`newgidmap` allows
containers to boot with idmapped mounts, but those binaries lose their file
capabilities (`CAP_SETUID`/`CAP_SETGID`) and won't function correctly inside
the container. On `sdme fs export` of an openSUSE rootfs, the stripped xattrs
should be re-added so the exported filesystem is fully functional.

### verify-nixos.sh: OCI app boot failure (resolved in 0.4.1)

Previously, NixOS OCI app containers failed because NixOS activation replaced
`/etc/systemd/system` with an immutable symlink to the Nix store, destroying
sdme's unit files. Fixed by placing OCI app units in `/etc/systemd/system.control/`
on NixOS (the highest-priority persistent unit search path, not managed by NixOS
activation). See `oci::app::systemd_unit_dir()` for the detection logic.
