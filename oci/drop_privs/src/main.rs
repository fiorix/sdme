// main.rs — ELF generator for sdme-drop-privs
//
// Generates tiny static ELF64 binaries for x86_64 and aarch64 that drop
// privileges (setgroups/setgid/setuid) and exec a program. These binaries
// have no libc dependency — they talk directly to the kernel via syscalls.
//
// Usage:
//   cargo run                  # generates both binaries in current directory
//   cargo run -- --dir /path   # generates into specified directory

mod aarch64;
mod elf;
mod x86_64;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

fn main() {
    let mut dir = PathBuf::from(".");
    let mut verbose = false;

    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--dir" | "-d" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("--dir requires an argument");
                    std::process::exit(1);
                }
                dir = PathBuf::from(&args[i]);
            }
            "--verbose" | "-v" => {
                verbose = true;
            }
            other => {
                eprintln!("unknown argument: {other}");
                eprintln!("usage: sdme-drop-privs-gen [--dir DIR] [-v]");
                std::process::exit(1);
            }
        }
        i += 1;
    }

    let targets: &[(&str, u16, fn() -> Vec<u8>)] = &[
        ("x86_64", elf::EM_X86_64, x86_64::generate),
        ("aarch64", elf::EM_AARCH64, aarch64::generate),
    ];

    for &(name, machine, gen) in targets {
        let code = gen();
        let binary = elf::build(machine, &code);
        let path = dir.join(format!("sdme-drop-privs.{name}"));

        fs::write(&path, &binary).unwrap_or_else(|e| {
            eprintln!("error writing {}: {e}", path.display());
            std::process::exit(1);
        });
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();

        if verbose {
            eprintln!(
                "[gen] {}: {} bytes code, {} bytes total ELF",
                path.display(),
                code.len(),
                binary.len(),
            );
        }

        println!("{}: {} bytes", path.display(), binary.len());
    }
}
