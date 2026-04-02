# Refactoring TODO

Module splits and function signature cleanups, in priority order.
Each item is a self-contained session: split one file, run tests, commit.

## Module Splits

- [x] **P1: `kube/plan.rs` (4,012 lines) → `kube/plan/`**
  - `mod.rs` — types, constants, re-exports (221 lines)
  - `parse.rs` — YAML parsing (112 lines)
  - `validate.rs` — validation and plan building (736 lines)
  - `tests.rs` — all tests (2,958 lines)

- [x] **P2: `export.rs` (3,224 lines) → `export/`**
  - `mod.rs` — types, dispatch, shared helpers (467 lines)
  - `dir.rs` — directory export (25 lines)
  - `tar.rs` — tarball export (207 lines)
  - `raw.rs` — raw disk image export (461 lines)
  - `vm.rs` — VM rootfs preparation (808 lines)
  - `tests.rs` — all tests (1,310 lines)

- [x] **P3: `containers.rs` (2,402 lines) → `containers/`**
  - `mod.rs` — re-exports, shared utilities, overlay management (278 lines)
  - `create.rs` — CreateOptions, create, do_create (659 lines)
  - `list.rs` — ContainerInfo, KubeInfo, list (312 lines)
  - `exec.rs` — join, exec, exec_oci, machinectl_shell (253 lines)
  - `manage.rs` — stop, remove, set_limits (170 lines)
  - `tests.rs` — all tests (788 lines)

- [ ] **P4: `main.rs` (3,710 lines) — extract `src/cli.rs`**
  - Move helper functions out: parse_network, parse_security, parse_mounts,
    auto_wire_oci_ports, validate_oci_pod, resolve_oci_app_name,
    for_each_container, start_and_await_boot

- [ ] **P5: `systemd.rs` (1,669 lines) → `systemd/`**
  - `mod.rs` — re-exports, unit state queries
  - `dbus.rs` — D-Bus module (already exists as inner mod dbus)
  - `units.rs` — unit template generation, nspawn dropin, escape helpers

## Function Signature Cleanups (7+ params)

- [ ] `oci/registry.rs` `download_layers` (8 params) → `LayerDownloadJob` struct
- [ ] `import/mod.rs` `import_url` (7 params) → `UrlImportJob` struct
- [ ] `kube/probe/runner.rs` `handle_result` (7 params) → `ProbeOutcome` struct
- [ ] `build.rs` `do_copy` (7 params) → `CopyContext` struct

## Function Signature Cleanups (5-6 params, batch by file)

- [ ] `containers.rs` join/exec/exec_oci/machinectl_shell → `ExecOptions` struct
- [ ] `systemd.rs` enable/start → `ServiceOptions` struct
- [ ] `export.rs` export_raw_bare/export_raw_gpt → `RawExportJob` struct
- [ ] `oci/registry.rs` fetch_config_blob/fetch_manifest/resolve_manifest → `RegistrySession` struct
