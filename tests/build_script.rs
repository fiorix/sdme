#[allow(dead_code)]
#[path = "../build.rs"]
mod build_script;

fn elf_header(class: u8, endian: u8, machine: u16) -> [u8; 20] {
    let mut header = [0u8; 20];
    header[..4].copy_from_slice(b"\x7fELF");
    header[4] = class;
    header[5] = endian;
    let machine = if endian == 2 {
        machine.to_be_bytes()
    } else {
        machine.to_le_bytes()
    };
    header[18..20].copy_from_slice(&machine);
    header
}

#[test]
fn accepts_matching_elf_target() {
    assert!(build_script::elf_matches_target(
        &elf_header(2, 1, 62),
        "x86_64",
        "little",
        "64"
    ));
    assert!(build_script::elf_matches_target(
        &elf_header(2, 1, 183),
        "aarch64",
        "little",
        "64"
    ));
    assert!(build_script::elf_matches_target(
        &elf_header(2, 2, 21),
        "powerpc64",
        "big",
        "64"
    ));
}

#[test]
fn rejects_wrong_elf_target() {
    let x86_64 = elf_header(2, 1, 62);
    assert!(!build_script::elf_matches_target(
        &x86_64, "aarch64", "little", "64"
    ));
    assert!(!build_script::elf_matches_target(
        &x86_64, "x86_64", "big", "64"
    ));
    assert!(!build_script::elf_matches_target(
        &x86_64, "x86_64", "little", "32"
    ));
}

#[test]
fn rejects_invalid_or_unknown_elf_target() {
    assert!(!build_script::elf_matches_target(
        b"not an ELF file",
        "x86_64",
        "little",
        "64"
    ));
    assert!(!build_script::elf_matches_target(
        &elf_header(2, 1, 62),
        "sparc64",
        "little",
        "64"
    ));
}
