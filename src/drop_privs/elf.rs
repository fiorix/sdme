// elf.rs — Minimal ELF64 header construction
//
// Builds the smallest valid ELF64 executable: a 64-byte ELF header followed
// by a single 56-byte PT_LOAD program header, then the machine code. No
// section headers, no interpreter, no dynamic linking. The kernel maps the
// entire file as a single read-execute segment and jumps to the entry point.

/// ELF header + program header = 120 bytes. Code starts at this offset.
pub const HEADER_SIZE: usize = 64 + 56;

/// Virtual address base. Code entry = BASE + HEADER_SIZE.
const BASE: u64 = 0x400000;

const EI_MAG: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1; // little-endian
const EV_CURRENT: u8 = 1;
const ELFOSABI_NONE: u8 = 0;
const ET_EXEC: u16 = 2;
const PT_LOAD: u32 = 1;
const PF_R: u32 = 4;
const PF_X: u32 = 1;

pub const EM_X86_64: u16 = 62;
pub const EM_AARCH64: u16 = 183;

/// Build a complete ELF64 static executable from raw machine code.
///
/// The returned bytes are a ready-to-run binary: write to a file, chmod +x,
/// and execute. No external tools needed.
pub fn build(machine: u16, code: &[u8]) -> Vec<u8> {
    let total_size = HEADER_SIZE + code.len();
    let entry = BASE + HEADER_SIZE as u64;
    let mut out = Vec::with_capacity(total_size);

    // ---- ELF64 Header (64 bytes) ----
    out.extend_from_slice(&EI_MAG); // e_ident[0..4]: magic
    out.push(ELFCLASS64); // e_ident[4]: 64-bit
    out.push(ELFDATA2LSB); // e_ident[5]: little-endian
    out.push(EV_CURRENT); // e_ident[6]: ELF version
    out.push(ELFOSABI_NONE); // e_ident[7]: OS/ABI
    out.extend_from_slice(&[0u8; 8]); // e_ident[8..16]: padding
    out.extend_from_slice(&ET_EXEC.to_le_bytes()); // e_type
    out.extend_from_slice(&machine.to_le_bytes()); // e_machine
    out.extend_from_slice(&1u32.to_le_bytes()); // e_version
    out.extend_from_slice(&entry.to_le_bytes()); // e_entry
    out.extend_from_slice(&64u64.to_le_bytes()); // e_phoff (right after ehdr)
    out.extend_from_slice(&0u64.to_le_bytes()); // e_shoff (no sections)
    out.extend_from_slice(&0u32.to_le_bytes()); // e_flags
    out.extend_from_slice(&64u16.to_le_bytes()); // e_ehsize
    out.extend_from_slice(&56u16.to_le_bytes()); // e_phentsize
    out.extend_from_slice(&1u16.to_le_bytes()); // e_phnum
    out.extend_from_slice(&0u16.to_le_bytes()); // e_shentsize
    out.extend_from_slice(&0u16.to_le_bytes()); // e_shnum
    out.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx
    debug_assert_eq!(out.len(), 64);

    // ---- Program Header (56 bytes) ----
    out.extend_from_slice(&PT_LOAD.to_le_bytes()); // p_type
    out.extend_from_slice(&(PF_R | PF_X).to_le_bytes()); // p_flags
    out.extend_from_slice(&0u64.to_le_bytes()); // p_offset (map from file start)
    out.extend_from_slice(&BASE.to_le_bytes()); // p_vaddr
    out.extend_from_slice(&BASE.to_le_bytes()); // p_paddr
    out.extend_from_slice(&(total_size as u64).to_le_bytes()); // p_filesz
    out.extend_from_slice(&(total_size as u64).to_le_bytes()); // p_memsz
    out.extend_from_slice(&0x1000u64.to_le_bytes()); // p_align (page)
    debug_assert_eq!(out.len(), HEADER_SIZE);

    // ---- Machine code ----
    out.extend_from_slice(code);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_size_is_120() {
        assert_eq!(HEADER_SIZE, 120);
    }

    #[test]
    fn elf_header_structure() {
        let code = vec![0xcc; 4]; // int3 placeholder
        let elf = build(EM_X86_64, &code);

        assert_eq!(elf.len(), HEADER_SIZE + 4);

        // Magic
        assert_eq!(&elf[0..4], b"\x7fELF");
        // Class (64-bit)
        assert_eq!(elf[4], 2);
        // Data (little-endian)
        assert_eq!(elf[5], 1);
        // Type (ET_EXEC)
        assert_eq!(u16::from_le_bytes([elf[16], elf[17]]), ET_EXEC);
        // Machine
        assert_eq!(u16::from_le_bytes([elf[18], elf[19]]), EM_X86_64);
        // Entry point
        let entry = u64::from_le_bytes(elf[24..32].try_into().unwrap());
        assert_eq!(entry, BASE + HEADER_SIZE as u64);
        // phoff
        let phoff = u64::from_le_bytes(elf[32..40].try_into().unwrap());
        assert_eq!(phoff, 64);
        // phnum
        assert_eq!(u16::from_le_bytes([elf[56], elf[57]]), 1);

        // Program header: p_type = PT_LOAD
        assert_eq!(u32::from_le_bytes(elf[64..68].try_into().unwrap()), PT_LOAD);
        // p_flags = R|X
        assert_eq!(
            u32::from_le_bytes(elf[68..72].try_into().unwrap()),
            PF_R | PF_X
        );
        // p_filesz = total size (at offset 64+32=96 in the program header)
        let filesz = u64::from_le_bytes(elf[96..104].try_into().unwrap());
        assert_eq!(filesz, (HEADER_SIZE + 4) as u64);
    }

    #[test]
    fn aarch64_machine_field() {
        let elf = build(EM_AARCH64, &[0; 4]);
        assert_eq!(u16::from_le_bytes([elf[18], elf[19]]), EM_AARCH64);
    }
}
