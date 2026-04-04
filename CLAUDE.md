# CLAUDE.md

This file provides contribution guidelines for Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

sdme boots systemd-nspawn containers using overlayfs copy-on-write layers, with OCI registry integration and Kubernetes Pod YAML support. Single binary, runs on Linux with systemd, requires root. Default containers are overlayfs clones of `/`. Also supports importing rootfs from other distros that have systemd and dbus.

## Build & Test

```bash
cargo build --release       # build the binary (with embedded probe)
cargo test                  # run all tests
cargo test <test_name>      # run a single test
make                        # same as cargo build --release
make deb                    # build .deb package
make rpm                    # build .rpm package
make pkg                    # build .pkg.tar.zst package (Arch Linux)
sudo make install           # install to /usr/local (does NOT rebuild)
```

The probe binary (`sdme-kube-probe`) is built and embedded by `build.rs`. Override with `SDME_KUBE_PROBE_PATH` for cross-compilation. During `cargo test`, the probe build is skipped by default; set `SDME_BUILD_PROBE=1` to force it.

### E2E Tests

Staged parallel test suite in `test/scripts/`. Run with `sudo ./test/scripts/run-parallel.sh`. Covers core operations, distro boot/OCI, networking, security, pods, and Kubernetes L1-L6. Tested distros: Debian, Ubuntu, Fedora, CentOS, AlmaLinux, Arch Linux, openSUSE, NixOS. E2E tests must pass before version bumps. When adding new functionality, add E2E tests and verify they pass across supported distros. Record test results in [`test/README.md`](test/README.md).

### Release

Static musl binaries (x86_64 + aarch64) built with `cargo-zigbuild`: `./dist/build-release.sh`. Pushing a `v*` tag triggers `.github/workflows/release.yml`.

## Project Principles

### Security

- sdme runs as root and handles untrusted input. Validate all names (`validate_name` in `src/lib.rs`), paths (`sanitize_dest_path` in `src/copy.rs`), and OCI digests (`resolve_blob` in `src/oci/layout.rs`).
- No path traversal: reject `..` components, enforce absolute paths within rootfs boundaries.
- Cap download sizes (`max_download_size` in `src/config.rs`), enforced in `src/oci/registry.rs` and `src/import/mod.rs`.
- Never validate rootfs data against host system state. The container rootfs is untrusted and foreign; do not assume it matches the host.

### Reliability

- Cooperative locking with `flock(2)`. Shared locks for reads, exclusive for mutations. See `src/lock.rs`.
- Lock ordering to prevent deadlocks: fs, containers, pods, secrets, configmaps.
- Transactional file operations: stage in `.{name}.{kind}-txn-{pid}` directories, atomic rename on commit. See `src/txn.rs`.
- Interrupt handling: `check_interrupted()` at loop top, `INTERRUPTED` check + break after each action, `check_interrupted()` before final error summary. Reference: `for_each_container` in `src/cli.rs`.

### systemd Compatibility

- Use systemd APIs: D-Bus for lifecycle (`src/systemd/dbus.rs`), nspawn for container execution, machinectl/nsenter for join/exec.
- Follow systemd conventions: `Type=notify` services, template units, drop-in files, journalctl for logs.
- Do not fight the init system. Containers run full systemd init with journald, D-Bus, and systemctl.

### OCI Compatibility

- Follow the OCI Distribution Spec for registry pulling (`src/oci/registry.rs`).
- Handle OCI whiteouts correctly: `.wh..wh..opq` and `.wh.<name>` markers during layer unpacking (`src/oci/layout.rs`).
- Verify content digests on every blob fetch. Validate digest format before using in filesystem paths.

### Shell-out vs Code

- Prefer shelling out to system tools (systemd-nspawn, machinectl, nsenter, journalctl, mkfs.*) over reimplementing their functionality.
- Write Rust code when you need programmability (overlayfs management), error handling (transaction staging), or performance (filesystem copy with hard link preservation).
- External binaries are checked at runtime via `system_check::check_dependencies()` before use.

## Writing Rules

- **No em dashes** in comments or documentation. They hurt readability in terminals and often divert the reader's train of thought. Use commas, semicolons, parentheses, or separate sentences instead.
- **Tables**: pure ASCII, space-aligned columns with dashed separators, target 80 columns. No pipes, no Unicode box-drawing. When a table would exceed 80 columns, keep a short summary table and expand details below with bullet points.
- **Factual**: keep documentation strictly factual. When reporting test results or benchmarks, include analysis of what the numbers mean and whether they meet expectations.
- **Comments**: explain "why", not "what". The code shows what; the comment explains the reasoning.

## Contributor Patterns

These rules apply when adding or modifying code, on top of the Project Principles above:

- **CLI help**: update the relevant `*_HELP` constant in `src/main.rs` so `--help` stays in sync. This is the only CLI documentation.
- **cp/build COPY sync**: `sdme cp` and `sdme fs build` COPY share the same copy engine and path validation. When modifying one, keep both in sync.
- **Doc comments**: all public items need `///` doc comments. New modules need a `//!` header describing purpose and a row in the `src/lib.rs` module table.
- **Tutorial sync**: when changing or creating tutorials, update `verify-tutorial.sh` accordingly.

## Documentation

- **Architecture and design**: [`site/content/docs/architecture.md`](site/content/docs/architecture.md)
- **Security model**: [`site/content/docs/security.md`](site/content/docs/security.md)
- **CLI reference**: `sdme --help` and subcommand `--help` (`*_HELP` constants in `src/main.rs`)
- **Tutorials**: [`site/content/tutorial/`](site/content/tutorial/) (kept in sync with E2E tests in `test/scripts/`)
