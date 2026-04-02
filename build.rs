/// Build script for sdme: builds and embeds the sdme-kube-probe binary.
///
/// The probe binary is built automatically by invoking cargo as a subprocess
/// with `--features probe --bin sdme-kube-probe`. A separate target directory
/// is used to avoid lock contention with the outer cargo process.
///
/// Override the probe binary path with the `SDME_KUBE_PROBE_PATH` env var
/// (e.g. for cross-compiled CI builds). Set `SDME_SKIP_PROBE_BUILD=1` to
/// skip the automatic build and fall back to discovery or an empty placeholder.
///
/// During `cargo test`, the probe build is skipped by default since it is
/// only needed at runtime. Set `SDME_BUILD_PROBE=1` to force building
/// the probe during tests.
fn main() {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let probe_dst = format!("{out_dir}/sdme-kube-probe");

    // When building the probe binary itself (inner build), the probe feature
    // is enabled. Skip all probe embedding logic — just write an empty
    // placeholder since the probe binary doesn't embed itself.
    if cfg!(feature = "probe") {
        std::fs::write(&probe_dst, b"").unwrap();
        return;
    }

    // Skip probe build during cargo test unless SDME_BUILD_PROBE=1 is set.
    // The probe binary is only needed at runtime, not for unit tests.
    if std::env::var("CARGO_CFG_TEST").is_ok()
        && std::env::var("SDME_BUILD_PROBE").unwrap_or_default() != "1"
    {
        std::fs::write(&probe_dst, b"").unwrap();
        println!("cargo:rerun-if-changed=src/kube/probe/");
        return;
    }

    // Try explicit env var first (used by CI/cross-compilation).
    if let Ok(src) = std::env::var("SDME_KUBE_PROBE_PATH") {
        if std::path::Path::new(&src).is_file() {
            std::fs::copy(&src, &probe_dst).unwrap();
            println!("cargo:rerun-if-changed={src}");
            return;
        }
    }

    // Try auto-discovery from the main target directory (covers the case
    // where the probe was already built by a prior step, e.g. Makefile).
    if try_discover(&probe_dst) {
        return;
    }

    // Build the probe binary ourselves, unless explicitly skipped.
    if std::env::var("SDME_SKIP_PROBE_BUILD").unwrap_or_default() != "1"
        && try_build_probe(&probe_dst)
    {
        return;
    }

    // Empty placeholder: probes won't work without the real binary.
    println!("cargo:warning=sdme-kube-probe binary not found, kube probes will not work");
    std::fs::write(&probe_dst, b"").unwrap();
    println!("cargo:rerun-if-changed=src/kube/probe/");
}

/// Try to discover a pre-built probe binary in the main target directory.
fn try_discover(probe_dst: &str) -> bool {
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();

    let mut candidates = Vec::new();
    if let Ok(target) = std::env::var("TARGET") {
        candidates.push(format!(
            "{manifest_dir}/target/{target}/{profile}/sdme-kube-probe"
        ));
    }
    candidates.push(format!("{manifest_dir}/target/{profile}/sdme-kube-probe"));

    for candidate in &candidates {
        if std::path::Path::new(candidate).is_file() {
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
        let stderr = String::from_utf8_lossy(&output.stderr);
        for line in stderr.lines().take(10) {
            println!("cargo:warning=probe build: {line}");
        }
        println!(
            "cargo:warning=probe build failed (exit {}), kube probes will not work",
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

    if built_path.is_file() {
        std::fs::copy(&built_path, probe_dst).unwrap();
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
