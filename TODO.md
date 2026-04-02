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

- [x] **P4: `main.rs` (3,710 lines) — extract `src/cli.rs`**
  - `cli.rs` — 3 Args structs + 21 helper functions (753 lines)
  - `main.rs` reduced to 2,981 lines (clap defs, help text, dispatch)

- [x] **P5: `systemd.rs` (1,669 lines) → `systemd/`**
  - `mod.rs` — public API wrappers, orchestration (192 lines)
  - `dbus.rs` — D-Bus communication layer (757 lines)
  - `units.rs` — unit templates, dropins, escape helpers (389 lines)
  - `tests.rs` — all tests (346 lines)

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
