// devfd_shim: generates a tiny LD_PRELOAD shared library (.so) for OCI containers.
//
// Intercepts open()/openat()/open64()/openat64() to handle /dev/stdin,
// /dev/stdout, /dev/stderr, /dev/fd/{0,1,2}, and /proc/self/fd/{0,1,2}.
// When a path matches, dup(N) is returned instead of calling the real open.
// This works around ENXIO errors when FDs 0/1/2 are journal sockets (not
// pipes), which happens under systemd's service management.

mod aarch64;
mod elf;
mod x86_64;

use crate::drop_privs::Arch;

/// Generate a complete devfd shim shared library for the given architecture.
///
/// Returns the raw bytes of a ready-to-use .so file. Write to a file,
/// set readable permissions, and use via LD_PRELOAD.
pub fn generate(arch: Arch) -> Vec<u8> {
    let (machine, code, symbols) = match arch {
        Arch::X86_64 => {
            let (code, syms) = x86_64::generate();
            (elf::EM_X86_64, code, syms)
        }
        Arch::Aarch64 => {
            let (code, syms) = aarch64::generate();
            (elf::EM_AARCH64, code, syms)
        }
    };
    elf::build(machine, &code, &symbols)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_x86_64_valid_elf() {
        let elf = generate(Arch::X86_64);
        assert_eq!(&elf[0..4], b"\x7fELF");
        // ET_DYN
        assert_eq!(u16::from_le_bytes([elf[16], elf[17]]), 3);
        // e_machine = EM_X86_64
        assert_eq!(u16::from_le_bytes([elf[18], elf[19]]), 62);
    }

    #[test]
    fn generate_aarch64_valid_elf() {
        let elf = generate(Arch::Aarch64);
        assert_eq!(&elf[0..4], b"\x7fELF");
        // ET_DYN
        assert_eq!(u16::from_le_bytes([elf[16], elf[17]]), 3);
        // e_machine = EM_AARCH64
        assert_eq!(u16::from_le_bytes([elf[18], elf[19]]), 183);
    }

    #[test]
    fn dynstr_contains_symbol_names() {
        for arch in [Arch::X86_64, Arch::Aarch64] {
            let elf = generate(arch);
            let elf_str = String::from_utf8_lossy(&elf);
            for name in &["open", "openat", "open64", "openat64"] {
                assert!(
                    elf_str.contains(name),
                    "dynstr missing symbol: {name}"
                );
            }
        }
    }
}
