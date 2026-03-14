//! Generates tiny static ELF64 binaries for PID/IPC namespace isolation.
//!
//! These binaries have no libc dependency; they talk directly to the kernel
//! via syscalls. They wrap a workload with its own PID namespace and IPC
//! namespace, remount /proc, optionally drop privileges, and exec the
//! target command.
//!
//! Same architecture as the ELF builder in crate::elf: raw machine code
//! emitted at build time, wrapped in a minimal ELF64 header.

mod aarch64;
mod x86_64;

use crate::elf;

/// Generate a complete isolate ELF binary for the given architecture.
///
/// Returns the raw bytes of a ready-to-run static ELF64 executable.
/// The binary creates new PID and IPC namespaces, forks, remounts /proc,
/// drops CAP_SYS_ADMIN from the bounding set, optionally drops privileges,
/// and execs the target command.
pub fn generate(arch: elf::Arch) -> Vec<u8> {
    let (machine, code) = match arch {
        elf::Arch::X86_64 => (elf::EM_X86_64, x86_64::generate()),
        elf::Arch::Aarch64 => (elf::EM_AARCH64, aarch64::generate()),
    };
    elf::build(machine, &code)
}
