# E2E Tests

End-to-end tests for sdme. Runs real containers via systemd-nspawn, imports rootfs from OCI registries, and validates the full lifecycle. Requires root and a working systemd >= 255.

## Quick start

Build and install before running tests:

```bash
make && sudo make install
```

Then run the suite:

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

Options accepted by all scripts: `--report-dir DIR`, `--help`. Set `VERBOSE=1` for detailed output on any script.

## Staged runner

The parallel runner (`run-parallel.sh`) executes in four stages:

```
Stage 0: Preflight
    Validate environment: root, sdme, systemd, binaries, overlayfs,
    disk space, optional deps, ports, Docker Hub, AppArmor.

Stage 1: Smoke + Interrupt (serial, gates)
    Import base rootfs, run smoke test and interrupt test.
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

Runner options: `--jobs N`, `--timeout-scale N`, `--stagger N`, `--skip SCRIPT`, `--only SCRIPT`. See `--help`.

## Test scripts

```
Script                       Description
---------------------------  -------------------------------------------
preflight.sh                 Environment validation (no containers)
smoke.sh                     Container lifecycle gate test
verify-interrupt.sh          SIGINT/SIGTERM abort handling
verify-cp.sh                 File copy: host, containers, rootfs
verify-storage.sh            btrfs backend: lifecycle, cp/export/diff, disk cap
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
verify-nested-userns.sh      Nested UID/GID range reservation
verify-nested.sh             sdme-in-sdme: nested btrfs state ops, storage
                             auto, chroot /dev import, preflight, kube pod
```

Set `KUBE_STORAGE=btrfs` to run all kube suites against the btrfs storage backend instead of the default overlayfs:

```bash
sudo env KUBE_STORAGE=btrfs ./test/scripts/verify-kube-L1-basic.sh
sudo env KUBE_STORAGE=btrfs make e2e
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

openSUSE Tumbleweed ships newuidmap/newgidmap with security.capability xattrs instead of setuid bits. The kernel refuses idmapped mounts when these xattrs are present. The built-in Suse import prehook now strips them automatically; both export prehooks restore them.

### NixOS + OCI apps (resolved)

NixOS activation replaces /etc/systemd/system with an immutable symlink to the Nix store. OCI app units are now placed in /etc/systemd/system.control/ on NixOS. See `oci::app::systemd_unit_dir()`.

### Redis 8 locale (workaround)

Redis 8+ treats locale config failure as fatal. Set `LANG=C.UTF-8` via `--oci-env` or kube YAML `env`. The test suite applies this automatically via `fix_redis_oci()` in lib.sh.

### Docker-in-container needs working veth DHCP

The docker/registry tutorial test needs outbound internet inside a `--network-veth` container, which depends on the host's nspawn DHCP/NAT (systemd-networkd's `80-container-ve.network`). Hosts where the container never gets a lease (no default route on `host0`) skip the network-dependent steps (`docker/install` onward) instead of failing.

## Adding new tests

1. Choose a unique prefix for artifacts. Use `cleanup_prefix "prefix-"` in the cleanup trap.
2. Add `require_gate smoke` and `require_gate interrupt` after `ensure_root`/`ensure_sdme`.
3. Use `scale_timeout` for all timeout values.
4. Declare port usage in the lib.sh port inventory comment.
5. Add to `run-parallel.sh`: wave A for most tests, wave B for kube L2+.

## Results

Last verified: 2026-07-21

System: Linux 7.0.0-28-generic (x86_64), systemd 259.5, sdme 0.18.0
release binary. Eight parallel jobs, timeout scale 1, wall clock 38m01s.
This is the exact release-candidate run; failures are retained as failures
rather than relabeled after triage.

```
Test Suite                 Pass  Fail  Skip  Status
-------------------------  ----  ----  ----  ------
verify-build                 11     0     0  PASS
verify-cp                    17     0     0  PASS
verify-diff                   9     0     0  PASS
verify-distro-boot           63     0     0  PASS
verify-distro-oci           175     0     0  PASS
verify-export                22     0     1  PASS
verify-kube-L1-basic         14     0     0  PASS
verify-kube-L2-probes        41     0     0  PASS
verify-kube-L2-security      16     0     1  PASS
verify-kube-L2-spec          12     0     0  PASS
verify-kube-L3-secrets       16     0     0  PASS
verify-kube-L3-volumes       39     0     0  PASS
verify-kube-L4-networking     6     0     0  PASS
verify-kube-L5-redis-stack    6     0     0  PASS
verify-kube-L6-gitea-stack    8     1     6  FAIL
verify-nested                 4     1     0  FAIL
verify-nested-userns          7     0     0  PASS
verify-network                7     2     0  FAIL
verify-nixos                 26     0     0  PASS
verify-oci                   18     0     0  PASS
verify-pods                   9     0     0  PASS
verify-security              41     0     0  PASS
verify-storage               11     0     0  PASS
verify-tutorial              83     1     7  FAIL
-------------------------  ----  ----  ----  ------
Totals                      661     5    15  24 suites
```

- `verify-network` reproduced the devsrv host's known unmanaged zone bridge:
  no route to the zone peer and no LLMNR response. Bridge networking passed.
  A clean serial rerun reproduced the same 7/2 result.
- `verify-nested` failed when Docker Hub DNS resolution temporarily failed
  inside the outer container. A clean serial rerun passed 16/16, including
  import, btrfs cleanup, preflight, and kube coverage.
- `verify-tutorial` failed because `start --all` included the stopped
  `gitea-pod` left by the preceding failed suite. A clean serial rerun passed
  84/84 with seven expected Docker/veth DHCP skips.
- `verify-kube-L6-gitea-stack` remains unresolved. The canonical serial stage
  timed out waiting for MySQL port 3306. A clean serial rerun cleared MySQL but
  timed out waiting for Gitea port 3000, producing 9 passed, 1 failed, and
  5 skipped. This is retained as a release-review failure.

## Log

### 0.18.0 -- source-first import and --name migration (2026-07-21, x86_64)

Full `run-parallel.sh --jobs 8` against the installed 0.18.0 release binary on
Linux 7.0.0-28-generic and systemd 259.5: 661 passed, 5 failed, and 15 skipped
across 24 suites in 38m01s. The exact aggregate is
`test-reports/summary-20260721-070727.md`.

All changed CLI paths passed throughout the import, distro, OCI, build,
storage, security, tutorial, and nested suites. Triage retained the canonical
failures and added clean serial reruns: nested passed 16/16 after transient
Docker Hub DNS; tutorial passed 84/84 after removing failed-Gitea state;
network reproduced the host's known zone route and LLMNR failures at 7/2;
Gitea remained unresolved, moving from a MySQL readiness timeout in the full
run to a Gitea readiness timeout in the rerun. The missing `qemu-nbd` and
`kubeconform` tools account for two optional skips; seven tutorial Docker
checks skipped because the host veth received no default route.

### 0.17.2 -- kube probe build safety (2026-07-20, x86_64)

`verify-kube-L2-probes.sh` against the 0.17.2 native release binary on Linux
7.0.0-28-generic, systemd 259.5, and an Ubuntu base rootfs: 41 passed, 0 failed,
0 skipped. Coverage includes the embedded probe binary, exec startup/liveness/
readiness probes, HTTP and TCP probes, timer activation, readiness health state,
and combined-probe behavior. Rust verification passed in debug and release
profiles: 852 tests passed and 3 ignored, plus 6 doctests passed and 1 ignored;
fmt and clippy with warnings denied passed. The release package verified with
`cargo package --locked --allow-dirty`.

### 0.17.0 -- nested-operation fixes (2026-07-19, x86_64)

Implements all five work items from the nested-operation fixes plan (sdme
running inside a user-namespaced container): stat-based subvolume inspection
(no btrfs-progs tree search, works without privilege in nested contexts),
direct `BTRFS_IOC_SNAP_DESTROY_V2` deletion with a `.trash` fallback plus
`sdme prune` trash collection, tmpfs-staged chroot `/dev` for
`fs import --install-packages=yes`, `--storage auto` as the default with
nested-aware selection (overlay nested; explicit btrfs is a hard error
nested), and a create-time nested preflight (mknod probe, non-`--userns`
warning). New `verify-nested.sh` replicates the devsrv tier topology
(outer: btrfs + `--userns --userns-nested=32`) and runs serially in Stage 3
because it toggles `user_subvol_rm_allowed` on the shared data root.

Full run-parallel.sh against the 0.17.0 release binary on Linux
7.0.0-28-generic (x86_64), systemd 259.5, Mode A loop-backed btrfs datadir:
674 passed, 4 failed, 14 skipped across 24 suites, wall clock 30m55s. Nested
passed 16/16. Gitea readiness and NixOS graceful deletion failed only under
four-way load; a targeted serial release-binary run passed Gitea 15/15 and
NixOS 26/26 in 11m38s. The runner now serializes these heavyweight suites;
post-change verification passed Gitea 15/15 and NixOS 26/26. Rust verification
after review fixes: 849 passed, 3 ignored across targets; fmt and clippy with
warnings denied pass.

Failure triage is recorded with the table above. The exact release-candidate
summary is `test-reports/summary-20260719-183653.md`; targeted reruns are in
`test-reports/summary-20260719-164335.md` and
`test-reports/summary-20260719-175552.md`. Heavyweight-stage verification is in
`test-reports/summary-20260719-185653.md` and
`test-reports/summary-20260719-190505.md`.

Key findings on nested boot (documented in the architecture guide): nested
nspawn boots are blocked by kernel rules, not (only) the outer seccomp
filter the plan assumed: `mknod` of device nodes requires CAP_MKNOD in
`init_user_ns`; fresh sysfs mounts and the first proc mount in a fresh mount
namespace have matching ownership restrictions. The item-5 preflight
therefore gates every nested create with a fast, named error. Subvolume
deletion in nested contexts was verified end-to-end: nested-created
subvolumes get the idmapped host-root owner, so `SNAP_DESTROY_V2` passes
`may_delete_subvol` with `user_subvol_rm_allowed`, and without the option
the subvolume is parked in `.trash` (later destroyed by a privileged
`sdme prune`).

### 0.16.0 -- kube btrfs storage + nested userns ranges (2026-07-18, x86_64)

Merged `kube-btrfs-storage` (`sdme kube apply/create --storage btrfs` and `--disk`) and `nested-userns` (`--userns-nested N`, `userns_nested_ranges` config) for v0.16.0. Full run-parallel.sh on Linux 7.0.12-1-cachyos (x86_64), systemd 260: 659 passed, 0 failed, 11 skipped across 23 suites, wall clock 9m06s (skips: 2 AppArmor not active, 1 qemu-nbd missing, 8 docker-in-container veth DHCP). The complete kube matrix (L1-L6) was additionally run against the btrfs backend (`KUBE_STORAGE=btrfs`, Mode A native-btrfs datadir): 166 passed, 0 failed, 0 skipped across 9 suites. cargo test: 823 passed, 3 ignored.

Runtime bugs found by the new coverage and fixed:

- systemd-nspawn rejects `--private-users-ownership=auto` for UID ranges larger than 64K, so `--userns-nested` containers would not boot; `SecurityConfig::to_nspawn_args` now takes the storage backend and emits `ownership=map` (btrfs idmapped mounts) or `ownership=off` (overlay, which cannot recursive-chown >64K).
- `sdme ps` hardcoded overlay paths for OS detection, OCI app detection, probe readiness, and the `missing fs` health check, so btrfs kube pods showed empty `oci_apps` and a phantom `missing fs`. `list.rs` now resolves the container root from the `STORAGE` state key (overlay merged/upper, or the btrfs subvolume under the pool root) without mounting an offline Mode B pool.

Test-infrastructure fixes (also in this release): kube suites honor `KUBE_STORAGE` and resolve rootfs/container paths through lib.sh helpers instead of hardcoded `$DATADIR/fs`; `sdme start` calls pass the scaled `-t` boot timeout (60s default was flaky under load); `cleanup_prefix` unmounts stale `/run/systemd/nspawn/unix-export` mounts left by SIGKILLed containers (a leftover mount makes the next same-name start fail with "Mount point exists already"); the PVC runtime check polls instead of racing the volume bind mount; the docker-in-container tutorial test skips its network-dependent steps when the host's veth DHCP hands out no lease. One environment note: a stale btrfs base subvolume (missing `python3`/`ss` relative to its imported rootfs) broke kube readiness checks until refreshed; btrfs bases are invalidated on `fs rm`/`import -f`/`fs build`, so this only happens when a rootfs is changed out of band.

### 0.14.0 -- --system-call-filter bare syscall names + recursive btrfs rm (2026-07-15, aarch64)

Relaxed `validate_syscall_filter` (src/security.rs) to accept individual syscall names (e.g. `bpf`, `keyctl`, `add_key`) and the `~name` deny form, in addition to `@group` tokens. This lets nested container engines run with the tight seccomp set nspawn needs (runc programs the cgroup v2 device controller via `bpf()`) instead of granting a whole capability or opening `@privileged`. Validator-only change: persistence (the `SYSCALL_FILTER` state list), nspawn emission (`--system-call-filter=<token>`), and drop-in regeneration on start were already pass-through. The bare-name character class is `[a-z0-9_]`, an injection guard for the generated unit `ExecStart` (unit tests confirm newline/space/uppercase/punctuation tokens are rejected).

verify-security.sh standalone against the built binary (SDME override, no system install) on Linux 7.0.0-27-generic (aarch64), systemd 259, ubuntu base fs: 39 passed, 0 failed, 0 skipped. Covers the updated CLI-validation case 1b (an invalid bare name is rejected) and a new Test 7b: create with `--system-call-filter bpf/keyctl/add_key`, assert `SYSCALL_FILTER=bpf,keyctl,add_key` in state, the three `--system-call-filter=` lines in the nspawn drop-in, and their survival across a stop/start regeneration. cargo test: 817 passed, 3 ignored; fmt clean; no new clippy warnings (one pre-existing nit in src/diff.rs is unrelated).

Full pure-btrfs Docker reproduction (the docker-in-container tutorial rewrite) on the same host: created a container with `--storage btrfs --network-veth --capability CAP_NET_ADMIN --system-call-filter bpf --system-call-filter keyctl --system-call-filter add_key`. The container's `CapEff` high dword is `00000000` (no CAP_BPF), yet `docker run --rm hello-world` prints "Hello from Docker!", confirming the `bpf` syscall path works via seccomp alone, with the retained CAP_SYS_ADMIN covering the operation. A `registry:2` + build/push/rmi/pull/run round trip returned the built image's output. `btrfs subvolume list` on the Mode B pool shows the container-root subvolume (`containers/dnest`) with 10 nested Docker layer subvolumes under `.../var/lib/docker/btrfs/subvolumes/`, no overlay or fuse in the chain. Filters persisted across `sdme stop`/`start`.

During that E2E, `sdme rm` was found to fail on a btrfs container that ran Docker: Docker's btrfs driver creates nested subvolumes under the container root, and `delete_subvol` (src/storage/btrfs.rs) issued a single `btrfs subvolume delete`, which btrfs refuses with "Directory not empty". Fixed by falling back, only on a failed plain delete, to enumerating nested subvolume roots (`find -inum 256`, mount-layout independent across Mode A/B) and removing them deepest-first before the root. Verified: a container with hand-created multi-level nested subvolumes (including a subvolume inside a subvolume, exactly the shape a plain delete cannot remove) is now removed cleanly by `sdme rm -f` with zero leftover subvolumes, which also makes the docker-in-container tutorial's cleanup step correct as written.

Docs updated (architecture.md Section 14, security.md, cli.rs flag help). The docker-in-container tutorial was rewritten onto this recipe (`--storage btrfs` + `--system-call-filter`, dropping the `CAP_BPF` + bind-mount workaround) and its verify-tutorial.sh `test_docker_in_container` updated to match, but the full verify-tutorial suite was not re-run in this session. Bumped 0.13.1 -> 0.14.0 (feature: new CLI capability).

### btrfs storage backend, Mode A full-suite run (v0.13.0, 2026-07-15, x86_64)

Branch feat/btrfs-storage-backend merged to main for v0.13.0. Full run-parallel.sh on a native-btrfs datadir host (Mode A; kernel 7.0.12-cachyos, systemd 260, x86_64), exercising the previously untested Mode A path: 637 passed, 2 failed, 2 skipped across 22 suites initially. Overlay default path showed zero regression (every non-storage suite green: build, cp, diff, distro-boot, distro-oci, export, kube L1-L6, network, nixos, oci, pods, tutorial). Both failures were triaged and fixed.

Failure 1, verify-storage: the script assumed the Mode B pool path ({datadir}/pool/...) and could not run on a native btrfs datadir, where subvolumes live under {datadir}/btrfs/...; the product itself worked (boot, exec, offline cp/export/diff, symlink-escape all passed). Fixed by deriving the subvolume root from the datadir filesystem (stat -f), making the test mode-agnostic. Mode A re-run: 8 passed, 0 failed, 1 skipped.

Failure 2, verify-security Test 15: an OCI app-mode nginx ran on privileged port 80 under --userns, which systemd-nspawn cannot bind (CAP_NET_BIND_SERVICE is dropped from the bounding set under userns, and the netns keeps ip_unprivileged_port_start=1024). Overlay container, unrelated to btrfs. Fixed by switching Test 15 to the quay.io/nginx/nginx-unprivileged image, which listens on :8080 as a non-root user. verify-security re-run: 32 passed, 0 failed, 2 skipped (the 2 skips are AppArmor-not-available on this host).

Product finding, fixed: on a Mode A datadir whose btrfs simple quotas (squota) are enabled externally (a host root btrfs managed by snapper or btrfs-assistant), sdme's per-subvolume writes are not accounted, so a --disk qgroup limit never triggers and the cap is silently unenforced while sdme ps still reports it. Isolated the cause: a fresh sdme-owned btrfs enforces the cap exactly (dd stops at the limit), an externally-managed one does not. sdme now refuses --disk when it does not own the quota lifecycle rather than accepting a phantom cap; verify-storage Test 6 skips on such hosts. cargo test: 815 passed; clippy and fmt clean.

Note: the periodic Results snapshot above is an aarch64, sdme 0.7.0-era table and is due for a fresh full green refresh on a clean single-run before the next version bump.

### 0.12.1 -- userns pre-chown setuid/setgid fix (2026-07-14, x86_64)

verify-security.sh standalone against the built 0.12.1 binary (SDME override, no system install) on Linux 7.0.0-22-generic (x86_64), systemd 259, ubuntu base fs: 37 passed, 1 failed, 0 skipped. Overlayfs idmap is unavailable on this kernel (mount_setattr(MOUNT_ATTR_IDMAP) returns EINVAL), so --userns and --hardened take the recursive pre-chown fallback, which is exactly the path this fix touches. The fix re-applies the mode after lchown so chown's clearing of S_ISUID/S_ISGID no longer strips setuid binaries; the new Test 14 assertion confirms a setuid-root binary keeps its bit inside a --userns container on all seven distros (debian, ubuntu, fedora, centos, almalinux, archlinux, opensuse show passwd or su at 4755). cargo test: 813 passed.

The one failure is Test 15 (nginx OCI app under --userns), pre-existing and unrelated to this change: nginx could not bind port 80 in this host environment (the host is already using it). A fresh-import re-run in isolation reproduced it, and it cannot involve this fix because no OCI app file carries the setuid/setgid bits that the fix re-applies (the shim and app files are written 0o555/0o111/0o600/0o644/0o1777, and nginx's binary is 0o755). The Last verified table above is unchanged pending a full cross-arch matrix run.

### keep-unit registration + opt-in restart policy (2026-07-12, aarch64)

Branch feat/keep-unit-restart-safe (unreleased, sdme 0.11.1). Full parallel runner on Linux 7.0.0-27-generic (aarch64, lima-default), systemd 259, ubuntu base fs: 568 passed, 2 failed, 1 skipped across 21 suites, wall clock 11m22s. Both failures were load-induced flakiness under 8-way parallelism and PASS deterministically when re-run in isolation (verify-export 23/0/0; verify-security 30/0/0); both are in code paths this change does not touch:

- verify-export flaked under concurrent I/O alongside distro-oci, kube-L2-probes, and nixos.
- verify-security aborted at the --hardened test when probe_and_prechown could not stat 10 apt-cache .deb files mid-walk under load. Overlayfs idmap is unavailable on this kernel, so --hardened falls back to a recursive pre-chown; that file walk is not resilient to transient stat failures under heavy I/O (pre-existing, not from this change).

1 skip: verify-kube-L2-security (pre-existing). The destructive verify-tutorial stage (batch stop-all/start-all/rm-all) passed 79/79. A targeted live smoke of the new behavior on the same host passed 16/16: keep-unit puts the container in /machine.slice/sdme@<name>.service with no separate machine-<name>.scope while machinectl and exec still work; sdme stop --kill stays down (no restart resurrection); --restart on-failure recovers a SIGKILL; rm is clean. This covers only the systemd >= 256 side; the 255 side (Ubuntu 24.04) is still pending because keep-unit's Terminate/Kill semantics split at v256. The Last verified table above is unchanged pending a clean cross-arch matrix and a version bump.

### 0.9.0 -- in-container health in ps (2026-06-12, x86_64)

smoke: 12 passed, 0 failed, 0 skipped, including 3 new health assertions (ok on a running container, degraded after an injected unit failure, ok again after reset-failed). Run on Linux 6.8.0-117-generic (x86_64), systemd 255, ubuntu base fs. The full matrix was not re-run for this change: the affected paths (ps health, prune analysis) are covered by the smoke gate, cargo test (787 passed), and a read-only check of `ps` and `prune --dry-run` against a production host running five containers.

### 0.7.0 -- self-update, archlinux image swap (2026-04-23, aarch64)

601 passed, 0 failed, 0 skipped across 21 suites. Wall clock: 11m47s for the parallel runner, plus standalone re-runs after environment and test fixes. Changes that produced clean run:

- Swapped the archlinux base image from `docker.io/lopsided/archlinux:latest` (multi-arch manifest, but the arm64 entry points at an amd64 config blob and is rejected by sdme's architecture check) to the official `docker.io/archlinux/archlinux:base`. The official image is x86_64 only; `filter_distros_by_arch()` (in lib.sh) now drops archlinux from the distro matrix on non-x86_64 hosts.
- Added `verify-diff` to the matrix (the 0.6.11 feature already had its own standalone script; it is now surfaced in the Results table).
- Installed host tooling for optional coverage: `bzip2` (unblocks tar.bz2 export verification), `attr` (setfattr/getfattr for tar xattr check), `qemu-utils` (qemu-nbd), `kubeconform` (v0.7.0, SHA-256 verified from upstream release).

### 0.6.5 -- nsenter fallback, tutorial restructure (2026-04-08, aarch64)

626 passed, 0 failed, 1 skipped across 20 suites. Fixed verify-pods assertion: check for `--private-users=` instead of `--private-users=pick` since sdme uses explicit UID ranges. Fixed machinectl stderr capture swallowing stdout by inheriting stdout while only piping stderr. 1 skip: export xattr. Wall clock: ~23m.


### 0.6.0 -- test infra fixes, CLAUDE.md rewrite (2026-04-03, aarch64)

626 passed, 0 failed, 1 skipped across 20 suites. Fixed ps-kube-column test: check .kube != null and get container names from .oci_apps[].name instead of the non-existent .kube array. Removed build_and_install from test runner; tests now require `make && sudo make install` before running. Removed --no-setup flag. Added missing kube test prefixes to stale cleanup list. Added stale cleanup between Stage 2 and Stage 3 to prevent kube container leftovers from breaking tutorial batch ops. Removed SDME_SKIP_PROBE_BUILD (redundant). 1 skip: export xattr. Interrupt test skipped (flaky timing on fast systems). Wall clock: 14m05s.

### 0.5.6 -- userns ownership fix, test updates (2026-04-02, aarch64)

624 passed, 0 failed, 2 skipped across 20 suites. Fixed --private-users-ownership from map to auto: map fails hard on filesystems without idmapped mount support (overlayfs on virtiofs), auto lets nspawn fall back to recursive chown gracefully. This resolved all hardened-boot and userns test failures. Fixed ps-kube-column test to use --json (KUBE column removed from text table in fba5ee3). Removed unused os_w variable. Bumped userns boot timeouts to 180s. 2 skips from stale state (distro-boot archlinux, export xattr). Wall clock: ~45m.

### 0.5.4 -- tutorial test rewrite, website docs (2026-03-30, aarch64)

626 passed, 0 failed, 1 skipped across 20 suites. Replaced verify-usage.sh with verify-tutorial.sh: each test section now maps 1:1 to a website tutorial. New tests for management (help, ps --json, cp), services (fedora + zone + hardened), oci-volumes (postgres persistence across rm/recreate), and pod --oci-pod (redis). Dropped tests covered by verify-security.sh. verify-network zone issues from 0.5.3 resolved on this system. Wall clock: 19m55s.

### 0.5.3 -- code cleanup, hard link/xattr test fixes (2026-03-22, x86_64)

597 passed, 2 failed, 0 skipped across 20 suites. New tests: cp hard link preservation (17 total), export tar hard links + tar xattrs + dir export hard links (23 total). Fixed two test bugs: cp test used shadowed /tmp path, export xattr test missing `--xattrs` flag on tar extract. verify-network zone failures are environment-only (passed on 0.5.2). Wall clock: 9m29s.

### 0.5.2 -- sdme cp, version bump (2026-03-22, x86_64)

593 passed, 0 failed, 0 skipped across 20 suites. New verify-cp suite (16 tests). Clean run. Wall clock: 9m33s.

### 0.5.0 -- version bump, clean run (2026-03-21, x86_64)

577 passed, 0 failed, 0 skipped across 19 suites. All tests pass on x86_64 with kernel 6.19.6, systemd 259. Wall clock: 9m34s.

### 0.4.8 -- test infrastructure revamp (2026-03-21, aarch64)

Staged runner with preflight, smoke, and interrupt gates. Matrix split into verify-distro-boot.sh and verify-distro-oci.sh. Timeout scaling, stale cleanup, kube-L1 gating. Makefile e2e targets added. 583 passed, 1 failed, 0 skipped -- 20 suites.

### 0.4.6 -- parallel runner (2026-03-21, aarch64)

575 passed, 1 failed, 0 skipped (576 tests), 18/18 suites pass. Same known platform issue (opaque xattr on aarch64).

### 0.4.5 -- nix-build pipeline removal (2026-03-19, aarch64)

577 passed, 1 failed, 0 skipped (578 tests), 16/16 suites pass. 264 matrix tests (including NixOS, which has since been removed from the matrix -- see verify-nixos.sh for dedicated NixOS testing).

### 0.4.4 -- openSUSE caps fix (2026-03-19, aarch64)

The built-in Suse import prehook now strips security.capability xattrs from newuidmap/newgidmap, fixing the idmapped mount error that blocked --userns and --hardened on openSUSE.

### 0.4.2 (2026-03-17, x86_64)

System: Linux 6.19.6-2-cachyos (x86_64), systemd 259, sdme 0.4.2

577 passed, 0 failed, 1 skipped (578 tests), 16/16 suites pass.
