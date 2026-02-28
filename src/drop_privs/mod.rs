// drop_privs — Generates tiny static ELF64 binaries for privilege dropping
//
// These binaries have no libc dependency — they talk directly to the kernel
// via syscalls. They solve the systemd User=/RootDirectory= ordering problem
// where NSS resolves UIDs against the host before entering the chroot.

mod aarch64;
mod elf;
mod x86_64;

/// Generate a complete drop_privs ELF binary for the given architecture.
///
/// Returns the raw bytes of a ready-to-run static ELF64 executable.
/// The binary drops privileges (setgroups/setgid/setuid), changes to a
/// working directory, and execs a program — all via raw syscalls with
/// no libc dependency.
pub fn generate(arch: Arch) -> Vec<u8> {
    let (machine, code) = match arch {
        Arch::X86_64 => (elf::EM_X86_64, x86_64::generate()),
        Arch::Aarch64 => (elf::EM_AARCH64, aarch64::generate()),
    };
    elf::build(machine, &code)
}

/// Target architecture for the generated binary.
pub enum Arch {
    X86_64,
    Aarch64,
}
