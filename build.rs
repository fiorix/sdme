/// Build script for sdme: builds and embeds the sdme-kube-probe binary.
///
/// The probe binary is built automatically by invoking cargo as a subprocess
/// with `--features probe --bin sdme-kube-probe`. A separate target directory
/// is used to avoid lock contention with the outer cargo process.
///
/// Override the probe binary path with the `SDME_KUBE_PROBE_PATH` env var
/// (e.g. for cross-compiled CI builds).
///
/// A build that cannot embed the probe FAILS. A probe-less sdme ships kube
/// pods whose health checks never run, and v0.17.0 showed that a warning is
/// too easy to miss. Set `SDME_SKIP_PROBE=1` to build without probe support
/// (exotic targets, offline dev builds); docs.rs builds skip it automatically.
fn main() {
    // Declare every environment input before any early return. Cargo uses the
    // directives from the previous run to decide whether to rerun this script.
    println!("cargo:rerun-if-env-changed=SDME_CHANNEL");
    println!("cargo:rerun-if-env-changed=SDME_KUBE_PROBE_PATH");
    println!("cargo:rerun-if-env-changed=SDME_SKIP_PROBE");
    println!("cargo:rerun-if-env-changed=DOCS_RS");

    // Provenance marker: distro package builds (Copr, Launchpad) set SDME_CHANNEL
    // so the binary defers self-upgrade to the system package manager. Default
    // "source" = built from source / install.sh musl binary, where self-upgrade
    // is allowed. Emitted before any early return below so env!/option_env! in
    // the crate always resolves it.
    let channel = std::env::var("SDME_CHANNEL").unwrap_or_else(|_| "source".into());
    println!("cargo:rustc-env=SDME_CHANNEL={channel}");

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let probe_dst = format!("{out_dir}/sdme-kube-probe");

    // When building the probe binary itself (inner build), the probe feature
    // is enabled. Skip all probe embedding logic, just write an empty
    // placeholder since the probe binary doesn't embed itself.
    if cfg!(feature = "probe") {
        std::fs::write(&probe_dst, b"").unwrap();
        return;
    }

    // Opt-outs: SDME_SKIP_PROBE=1 for builds where the probe cannot be built
    // or is not wanted, and docs.rs, which is sandboxed and ships no binary.
    // The empty blob is caught at runtime by kube::create if probes are used.
    if std::env::var("SDME_SKIP_PROBE").unwrap_or_default() == "1"
        || std::env::var("DOCS_RS").is_ok()
    {
        std::fs::write(&probe_dst, b"").unwrap();
        println!("cargo:rerun-if-changed=src/kube/probe/");
        return;
    }

    // Explicit override (used by CI/cross-compilation). Set but unusable is a
    // hard error: falling through to discovery here could embed a host-arch
    // probe from target/ on a cross build.
    if let Ok(src) = std::env::var("SDME_KUBE_PROBE_PATH") {
        match embed_probe(std::path::Path::new(&src), &probe_dst) {
            Ok(()) => {
                println!("cargo:rerun-if-changed={src}");
                return;
            }
            Err(e) => fatal(&format!("SDME_KUBE_PROBE_PATH={src}: {e}")),
        }
    }

    // Try auto-discovery from the main target directory (covers the case
    // where the probe was already built by a prior step, e.g. Makefile).
    if try_discover(&probe_dst) {
        return;
    }

    // Build the probe binary ourselves.
    if try_build_probe(&probe_dst) {
        return;
    }

    fatal("sdme-kube-probe could not be built or found (see warnings above)");
}

/// Print a hard error and abort the build. A build without the embedded probe
/// would ship a binary whose kube probes never run, so this must stay fatal;
/// the only way out is the explicit SDME_SKIP_PROBE opt-out above.
fn fatal(msg: &str) -> ! {
    eprintln!("error: {msg}");
    eprintln!("sdme embeds sdme-kube-probe and refuses to ship without it.");
    eprintln!("Fix the probe build, point SDME_KUBE_PROBE_PATH at a pre-built probe,");
    eprintln!("or set SDME_SKIP_PROBE=1 to build without kube probe support.");
    std::process::exit(1);
}

/// Check the 4-byte ELF magic of `path`.
fn is_elf(path: &std::path::Path) -> bool {
    use std::io::Read as _;
    let mut header = [0u8; 20];
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    if f.read_exact(&mut header).is_err() || &header[..4] != b"\x7fELF" {
        return false;
    }

    let Ok(target_arch) = std::env::var("CARGO_CFG_TARGET_ARCH") else {
        return false;
    };
    let Ok(target_endian) = std::env::var("CARGO_CFG_TARGET_ENDIAN") else {
        return false;
    };
    let Ok(target_width) = std::env::var("CARGO_CFG_TARGET_POINTER_WIDTH") else {
        return false;
    };
    elf_matches_target(&header, &target_arch, &target_endian, &target_width)
}

/// Check an ELF header against Cargo's target architecture configuration.
pub(crate) fn elf_matches_target(header: &[u8], arch: &str, endian: &str, width: &str) -> bool {
    if header.len() < 20 || &header[..4] != b"\x7fELF" {
        return false;
    }

    let expected_class = match width {
        "32" => 1,
        "64" => 2,
        _ => return false,
    };
    let expected_endian = match endian {
        "little" => 1,
        "big" => 2,
        _ => return false,
    };
    if header[4] != expected_class || header[5] != expected_endian {
        return false;
    }

    let machine = match header[5] {
        1 => u16::from_le_bytes([header[18], header[19]]),
        2 => u16::from_be_bytes([header[18], header[19]]),
        _ => return false,
    };
    let expected_machine = match arch {
        "x86" => 3,
        "mips" | "mips32r6" | "mips64" | "mips64r6" => 8,
        "powerpc" => 20,
        "powerpc64" => 21,
        "s390x" => 22,
        "arm" => 40,
        "x86_64" => 62,
        "aarch64" => 183,
        "riscv32" | "riscv64" => 243,
        "loongarch64" => 258,
        _ => return false,
    };
    machine == expected_machine
}

/// Copy `src` to `dst`, requiring `src` to be an ELF binary.
fn embed_probe(src: &std::path::Path, dst: &str) -> Result<(), String> {
    if !src.is_file() {
        return Err("file does not exist".to_string());
    }
    if !is_elf(src) {
        return Err("not an ELF binary for the Cargo target".to_string());
    }
    std::fs::copy(src, dst).map_err(|e| format!("failed to copy to {dst}: {e}"))?;
    Ok(())
}

/// Try to discover a pre-built probe binary in the main target directory.
fn try_discover(probe_dst: &str) -> bool {
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();

    let mut candidates = Vec::new();
    let target = std::env::var("TARGET").ok();
    let host = std::env::var("HOST").ok();
    if let Some(target) = &target {
        candidates.push(format!(
            "{manifest_dir}/target/{target}/{profile}/sdme-kube-probe"
        ));
    }
    if target == host {
        candidates.push(format!("{manifest_dir}/target/{profile}/sdme-kube-probe"));
    }

    for candidate in &candidates {
        // Require an ELF for this target, not just existence: a stale, empty,
        // or host-architecture file would silently break kube probes.
        if is_elf(std::path::Path::new(candidate)) {
            std::fs::copy(candidate, probe_dst).unwrap();
            println!("cargo:rerun-if-changed={candidate}");
            return true;
        }
    }
    false
}

/// Build the probe binary in a separate target directory to avoid cargo
/// lock contention, then copy it to OUT_DIR for `include_bytes!()`.
fn try_build_probe(probe_dst: &str) -> bool {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());

    // Use a separate target dir so the inner cargo doesn't contend with
    // the outer build's lock on the main target directory.
    let inner_target = format!("{manifest_dir}/target/probe-build");

    let mut cmd = std::process::Command::new(&cargo);
    cmd.arg("build")
        .arg("--features")
        .arg("probe")
        .arg("--bin")
        .arg("sdme-kube-probe")
        .arg("--manifest-path")
        .arg(format!("{manifest_dir}/Cargo.toml"))
        .env("CARGO_TARGET_DIR", &inner_target);

    if profile == "release" {
        cmd.arg("--release");
    }

    // Pass through the target triple for cross-compilation.
    if let Ok(target) = std::env::var("TARGET") {
        cmd.arg("--target").arg(&target);
    }

    eprintln!("building sdme-kube-probe...");
    let output = match cmd.output() {
        Ok(o) => o,
        Err(e) => {
            println!("cargo:warning=failed to run cargo for probe build: {e}");
            return false;
        }
    };

    if !output.status.success() {
        // Echo the tail of stderr, not the head: the first lines are always
        // cargo's "Downloading crates ..." chatter, which buried the real
        // error in the v0.17.0 musl failure.
        let stderr = String::from_utf8_lossy(&output.stderr);
        let lines: Vec<&str> = stderr.lines().collect();
        for line in &lines[lines.len().saturating_sub(20)..] {
            println!("cargo:warning=probe build: {line}");
        }
        println!(
            "cargo:warning=probe build failed (exit {}); see errors above",
            output.status.code().unwrap_or(-1)
        );
        return false;
    }

    // Find the built binary.
    let mut built_path = std::path::PathBuf::from(&inner_target);
    if let Ok(target) = std::env::var("TARGET") {
        built_path.push(&target);
    }
    built_path.push(&profile);
    built_path.push("sdme-kube-probe");

    if is_elf(&built_path) {
        std::fs::copy(&built_path, probe_dst).unwrap();
        strip_probe_debug(probe_dst);
        // Rebuild when probe source changes.
        println!("cargo:rerun-if-changed=src/kube/probe/");
        return true;
    }

    println!(
        "cargo:warning=probe binary not found at {} after build",
        built_path.display()
    );
    false
}

/// Strip debug info from the built probe so the embedded blob stays small.
///
/// The probe is embedded verbatim via `include_bytes!`, and some builds (notably
/// Fedora's rpm profile, which forces `-Cdebuginfo=2 -Cstrip=none` via rustflags
/// that also override any cargo `strip` profile setting) leave tens of MB of
/// DWARF in it. The outer `find-debuginfo` pass cannot reach it because it lives
/// inside a rodata blob, so it survives into the shipped binary. Strip it here.
///
/// Native builds only: a cross-built probe uses the debug-free release profile
/// anyway, and the host `strip` cannot process a foreign-arch ELF. Best effort;
/// a missing or failing strip just leaves the probe as-is.
fn strip_probe_debug(path: &str) {
    let host = std::env::var("HOST").unwrap_or_default();
    let target = std::env::var("TARGET").unwrap_or_default();
    if !target.is_empty() && target != host {
        return;
    }
    let _ = std::process::Command::new("strip")
        .arg("--strip-all")
        .arg(path)
        .status();
}
