/// Build script for sdme: embeds the pre-built sdme-kube-probe binary.
///
/// The probe binary must be built separately before building sdme:
///   cargo build [--release] --features probe --bin sdme-kube-probe
///
/// The build script auto-discovers it from the target directory. If not found,
/// an empty placeholder is embedded and kube probe creation will fail with a
/// clear error message.
fn main() {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let probe_dst = format!("{out_dir}/sdme-kube-probe");

    // Try explicit env var first (used by CI/Makefile).
    if let Ok(src) = std::env::var("SDME_KUBE_PROBE_PATH") {
        if std::path::Path::new(&src).is_file() {
            std::fs::copy(&src, &probe_dst).unwrap();
            println!("cargo:rerun-if-changed={src}");
            return;
        }
    }

    // Auto-discover from target directory.
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
            std::fs::copy(candidate, &probe_dst).unwrap();
            println!("cargo:rerun-if-changed={candidate}");
            return;
        }
    }

    // Empty placeholder: probes won't work without the real binary.
    std::fs::write(&probe_dst, b"").unwrap();
    println!("cargo:rerun-if-changed=src/kube/probe/");
}
