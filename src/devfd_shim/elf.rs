// elf.rs: Minimal ET_DYN ELF64 shared library builder
//
// Builds the smallest valid ELF64 shared library (.so): an ELF header,
// three program headers (PT_LOAD RX, PT_LOAD RW, PT_DYNAMIC), a SysV
// hash table, dynamic symbol table (.dynsym), dynamic string table
// (.dynstr), and a dynamic section. No section headers (not needed at
// runtime).
//
// The RX segment contains: ELF header, program headers, machine code,
// hash table, dynsym, and dynstr.
// The RW segment contains: the dynamic section (on the next page).

pub const EM_X86_64: u16 = 62;
pub const EM_AARCH64: u16 = 183;

/// A dynamic symbol exported by the shared library.
///
/// Used by both the ELF builder and the architecture-specific code generators.
pub struct Symbol {
    pub name: &'static str,
    /// Offset of this symbol within the code blob.
    pub offset: usize,
}

// ELF constants
const EI_MAG: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const EV_CURRENT: u8 = 1;
const ELFOSABI_NONE: u8 = 0;
const ET_DYN: u16 = 3;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PF_R: u32 = 4;
const PF_W: u32 = 2;
const PF_X: u32 = 1;

// Dynamic section tags
const DT_NULL: u64 = 0;
const DT_HASH: u64 = 4;
const DT_STRTAB: u64 = 5;
const DT_SYMTAB: u64 = 6;
const DT_STRSZ: u64 = 10;
const DT_SYMENT: u64 = 11;

// Symbol table constants
const STB_GLOBAL: u8 = 1;
const STT_FUNC: u8 = 2;
const SHN_ABS: u16 = 0xFFF1;

const PAGE_SIZE: usize = 0x1000;

/// SysV hash function for ELF symbol lookup.
fn elf_hash(name: &[u8]) -> u32 {
    let mut h: u32 = 0;
    for &b in name {
        h = (h << 4).wrapping_add(b as u32);
        let g = h & 0xF000_0000;
        if g != 0 {
            h ^= g >> 24;
        }
        h &= !g;
    }
    h
}

/// Build a complete ELF64 shared library from machine code and symbol list.
///
/// The returned bytes are a ready-to-use .so: write to a file, chmod +r,
/// and use via LD_PRELOAD.
pub fn build(machine: u16, code: &[u8], symbols: &[Symbol]) -> Vec<u8> {
    // Layout planning:
    //
    // RX segment (page-aligned, starts at vaddr 0):
    //   [0x00]   ELF header (64 bytes)
    //   [0x40]   3 program headers (3 * 56 = 168 bytes)
    //   [0xE8]   machine code (code.len() bytes)
    //   [...]    .hash table
    //   [...]    .dynsym table
    //   [...]    .dynstr table
    //
    // RW segment (next page):
    //   dynamic section (array of Elf64_Dyn entries)

    let ehdr_size = 64usize;
    let phdr_size = 56usize;
    let phdr_count = 3usize;
    let phdrs_total = phdr_count * phdr_size;

    let code_offset = ehdr_size + phdrs_total;

    // Build dynstr: "\0" + name1 + "\0" + name2 + "\0" + ...
    let mut dynstr = vec![0u8]; // initial null byte
    let mut name_offsets: Vec<usize> = Vec::with_capacity(symbols.len());
    for sym in symbols {
        name_offsets.push(dynstr.len());
        dynstr.extend_from_slice(sym.name.as_bytes());
        dynstr.push(0);
    }

    // Symbol count: STN_UNDEF + exported symbols
    let sym_count = 1 + symbols.len();

    // SysV hash table
    let nbucket = sym_count as u32; // 1 bucket per symbol for fast lookup
    let nchain = sym_count as u32;
    // Hash table layout: [nbucket, nchain, bucket[nbucket], chain[nchain]]
    let hash_size = (2 + nbucket as usize + nchain as usize) * 4;

    // Compute offsets within the RX segment
    let hash_offset = code_offset + code.len();
    // Align dynsym to 8 bytes
    let dynsym_offset = (hash_offset + hash_size + 7) & !7;
    let dynsym_size = sym_count * 24; // Elf64_Sym is 24 bytes
    let dynstr_offset = dynsym_offset + dynsym_size;
    let rx_file_size = dynstr_offset + dynstr.len();

    // RW segment starts on next page
    let rw_file_offset = (rx_file_size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let rw_vaddr = rw_file_offset; // identity-mapped for simplicity

    // Dynamic section: 6 entries (DT_HASH, DT_STRTAB, DT_SYMTAB, DT_STRSZ, DT_SYMENT, DT_NULL)
    let dyn_entry_size = 16usize; // Elf64_Dyn = 16 bytes
    let dyn_count = 6usize;
    let dynamic_size = dyn_count * dyn_entry_size;
    let total_file_size = rw_file_offset + dynamic_size;

    let mut out = Vec::with_capacity(total_file_size);

    // ---- ELF64 Header (64 bytes) ----
    out.extend_from_slice(&EI_MAG);
    out.push(ELFCLASS64);
    out.push(ELFDATA2LSB);
    out.push(EV_CURRENT);
    out.push(ELFOSABI_NONE);
    out.extend_from_slice(&[0u8; 8]); // padding
    out.extend_from_slice(&ET_DYN.to_le_bytes()); // e_type
    out.extend_from_slice(&machine.to_le_bytes()); // e_machine
    out.extend_from_slice(&1u32.to_le_bytes()); // e_version
    out.extend_from_slice(&0u64.to_le_bytes()); // e_entry (no entry point for .so)
    out.extend_from_slice(&(ehdr_size as u64).to_le_bytes()); // e_phoff
    out.extend_from_slice(&0u64.to_le_bytes()); // e_shoff (no sections)
    out.extend_from_slice(&0u32.to_le_bytes()); // e_flags
    out.extend_from_slice(&(ehdr_size as u16).to_le_bytes()); // e_ehsize
    out.extend_from_slice(&(phdr_size as u16).to_le_bytes()); // e_phentsize
    out.extend_from_slice(&(phdr_count as u16).to_le_bytes()); // e_phnum
    out.extend_from_slice(&0u16.to_le_bytes()); // e_shentsize
    out.extend_from_slice(&0u16.to_le_bytes()); // e_shnum
    out.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx
    debug_assert_eq!(out.len(), ehdr_size);

    // ---- Program Header 0: PT_LOAD RX (code + hash + dynsym + dynstr) ----
    out.extend_from_slice(&PT_LOAD.to_le_bytes()); // p_type
    out.extend_from_slice(&(PF_R | PF_X).to_le_bytes()); // p_flags
    out.extend_from_slice(&0u64.to_le_bytes()); // p_offset
    out.extend_from_slice(&0u64.to_le_bytes()); // p_vaddr
    out.extend_from_slice(&0u64.to_le_bytes()); // p_paddr
    out.extend_from_slice(&(rx_file_size as u64).to_le_bytes()); // p_filesz
    out.extend_from_slice(&(rx_file_size as u64).to_le_bytes()); // p_memsz
    out.extend_from_slice(&(PAGE_SIZE as u64).to_le_bytes()); // p_align
    debug_assert_eq!(out.len(), ehdr_size + phdr_size);

    // ---- Program Header 1: PT_LOAD RW (dynamic section) ----
    out.extend_from_slice(&PT_LOAD.to_le_bytes());
    out.extend_from_slice(&(PF_R | PF_W).to_le_bytes());
    out.extend_from_slice(&(rw_file_offset as u64).to_le_bytes()); // p_offset
    out.extend_from_slice(&(rw_vaddr as u64).to_le_bytes()); // p_vaddr
    out.extend_from_slice(&(rw_vaddr as u64).to_le_bytes()); // p_paddr
    out.extend_from_slice(&(dynamic_size as u64).to_le_bytes()); // p_filesz
    out.extend_from_slice(&(dynamic_size as u64).to_le_bytes()); // p_memsz
    out.extend_from_slice(&(PAGE_SIZE as u64).to_le_bytes()); // p_align
    debug_assert_eq!(out.len(), ehdr_size + 2 * phdr_size);

    // ---- Program Header 2: PT_DYNAMIC ----
    out.extend_from_slice(&PT_DYNAMIC.to_le_bytes());
    out.extend_from_slice(&(PF_R | PF_W).to_le_bytes());
    out.extend_from_slice(&(rw_file_offset as u64).to_le_bytes()); // p_offset
    out.extend_from_slice(&(rw_vaddr as u64).to_le_bytes()); // p_vaddr
    out.extend_from_slice(&(rw_vaddr as u64).to_le_bytes()); // p_paddr
    out.extend_from_slice(&(dynamic_size as u64).to_le_bytes()); // p_filesz
    out.extend_from_slice(&(dynamic_size as u64).to_le_bytes()); // p_memsz
    out.extend_from_slice(&8u64.to_le_bytes()); // p_align
    debug_assert_eq!(out.len(), code_offset);

    // ---- Machine code ----
    out.extend_from_slice(code);
    debug_assert_eq!(out.len(), hash_offset);

    // ---- .hash (SysV hash table) ----
    // Build bucket and chain arrays
    let mut buckets = vec![0u32; nbucket as usize];
    let mut chains = vec![0u32; nchain as usize];
    // STN_UNDEF (index 0) is never hashed
    for (i, sym) in symbols.iter().enumerate() {
        let sym_idx = (i + 1) as u32; // +1 because index 0 is STN_UNDEF
        let bucket = elf_hash(sym.name.as_bytes()) % nbucket;
        // Insert at head of chain for this bucket
        chains[sym_idx as usize] = buckets[bucket as usize];
        buckets[bucket as usize] = sym_idx;
    }

    out.extend_from_slice(&nbucket.to_le_bytes());
    out.extend_from_slice(&nchain.to_le_bytes());
    for b in &buckets {
        out.extend_from_slice(&b.to_le_bytes());
    }
    for c in &chains {
        out.extend_from_slice(&c.to_le_bytes());
    }

    // ---- Padding to align .dynsym to 8 bytes ----
    while out.len() < code_offset + (dynsym_offset - code_offset) {
        out.push(0);
    }
    debug_assert_eq!(out.len(), dynsym_offset);

    // ---- .dynsym (Elf64_Sym entries) ----
    // Entry 0: STN_UNDEF
    out.extend_from_slice(&[0u8; 24]);

    for (i, sym) in symbols.iter().enumerate() {
        let st_name = name_offsets[i] as u32;
        let st_info = (STB_GLOBAL << 4) | STT_FUNC;
        let st_other = 0u8;
        let st_shndx = SHN_ABS;
        let st_value = (code_offset + sym.offset) as u64; // vaddr of the symbol
        let st_size = 0u64;

        out.extend_from_slice(&st_name.to_le_bytes());
        out.push(st_info);
        out.push(st_other);
        out.extend_from_slice(&st_shndx.to_le_bytes());
        out.extend_from_slice(&st_value.to_le_bytes());
        out.extend_from_slice(&st_size.to_le_bytes());
    }

    // ---- .dynstr ----
    out.extend_from_slice(&dynstr);
    debug_assert_eq!(out.len(), rx_file_size);

    // ---- Padding to RW page boundary ----
    out.resize(rw_file_offset, 0);

    // ---- Dynamic section ----
    let emit_dyn = |out: &mut Vec<u8>, tag: u64, val: u64| {
        out.extend_from_slice(&tag.to_le_bytes());
        out.extend_from_slice(&val.to_le_bytes());
    };

    emit_dyn(&mut out, DT_HASH, hash_offset as u64);
    emit_dyn(&mut out, DT_STRTAB, dynstr_offset as u64);
    emit_dyn(&mut out, DT_SYMTAB, dynsym_offset as u64);
    emit_dyn(&mut out, DT_STRSZ, dynstr.len() as u64);
    emit_dyn(&mut out, DT_SYMENT, 24); // sizeof(Elf64_Sym)
    emit_dyn(&mut out, DT_NULL, 0);

    debug_assert_eq!(out.len(), total_file_size);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn code_offset() -> usize {
        64 + 3 * 56 // ehdr + 3 phdrs
    }

    fn test_symbols() -> Vec<Symbol> {
        vec![
            Symbol {
                name: "open",
                offset: 0,
            },
            Symbol {
                name: "openat",
                offset: 4,
            },
            Symbol {
                name: "open64",
                offset: 0,
            },
            Symbol {
                name: "openat64",
                offset: 4,
            },
        ]
    }

    #[test]
    fn elf_header_et_dyn() {
        let code = vec![0xcc; 16];
        let syms = test_symbols();
        let elf = build(EM_X86_64, &code, &syms);

        // Magic
        assert_eq!(&elf[0..4], b"\x7fELF");
        // Class (64-bit)
        assert_eq!(elf[4], 2);
        // Data (little-endian)
        assert_eq!(elf[5], 1);
        // Type (ET_DYN)
        assert_eq!(u16::from_le_bytes([elf[16], elf[17]]), ET_DYN);
        // Machine
        assert_eq!(u16::from_le_bytes([elf[18], elf[19]]), EM_X86_64);
        // e_entry = 0
        let entry = u64::from_le_bytes(elf[24..32].try_into().unwrap());
        assert_eq!(entry, 0);
        // e_phnum = 3
        assert_eq!(u16::from_le_bytes([elf[56], elf[57]]), 3);
    }

    #[test]
    fn program_headers_correct() {
        let code = vec![0xcc; 16];
        let syms = test_symbols();
        let elf = build(EM_X86_64, &code, &syms);

        // PH0: PT_LOAD RX
        let ph0_type = u32::from_le_bytes(elf[64..68].try_into().unwrap());
        let ph0_flags = u32::from_le_bytes(elf[68..72].try_into().unwrap());
        assert_eq!(ph0_type, PT_LOAD);
        assert_eq!(ph0_flags, PF_R | PF_X);

        // PH1: PT_LOAD RW
        let ph1_off = 64 + 56;
        let ph1_type = u32::from_le_bytes(elf[ph1_off..ph1_off + 4].try_into().unwrap());
        let ph1_flags = u32::from_le_bytes(elf[ph1_off + 4..ph1_off + 8].try_into().unwrap());
        assert_eq!(ph1_type, PT_LOAD);
        assert_eq!(ph1_flags, PF_R | PF_W);

        // PH2: PT_DYNAMIC
        let ph2_off = 64 + 2 * 56;
        let ph2_type = u32::from_le_bytes(elf[ph2_off..ph2_off + 4].try_into().unwrap());
        let ph2_flags = u32::from_le_bytes(elf[ph2_off + 4..ph2_off + 8].try_into().unwrap());
        assert_eq!(ph2_type, PT_DYNAMIC);
        assert_eq!(ph2_flags, PF_R | PF_W);
    }

    #[test]
    fn dynamic_section_has_required_tags() {
        let code = vec![0xcc; 16];
        let syms = test_symbols();
        let elf = build(EM_X86_64, &code, &syms);

        // Find the dynamic section via PH2's p_offset
        let ph2_off = 64 + 2 * 56;
        let dyn_offset =
            u64::from_le_bytes(elf[ph2_off + 8..ph2_off + 16].try_into().unwrap()) as usize;
        let dyn_size =
            u64::from_le_bytes(elf[ph2_off + 32..ph2_off + 40].try_into().unwrap()) as usize;

        let mut tags = Vec::new();
        let mut pos = dyn_offset;
        while pos + 16 <= dyn_offset + dyn_size {
            let tag = u64::from_le_bytes(elf[pos..pos + 8].try_into().unwrap());
            tags.push(tag);
            if tag == DT_NULL {
                break;
            }
            pos += 16;
        }

        assert!(tags.contains(&DT_HASH), "missing DT_HASH");
        assert!(tags.contains(&DT_STRTAB), "missing DT_STRTAB");
        assert!(tags.contains(&DT_SYMTAB), "missing DT_SYMTAB");
        assert!(tags.contains(&DT_STRSZ), "missing DT_STRSZ");
        assert!(tags.contains(&DT_SYMENT), "missing DT_SYMENT");
        assert!(tags.contains(&DT_NULL), "missing DT_NULL");
    }

    #[test]
    fn hash_table_counts_match_symbols() {
        let code = vec![0xcc; 16];
        let syms = test_symbols();
        let sym_count = 1 + syms.len(); // STN_UNDEF + 4
        let elf = build(EM_X86_64, &code, &syms);

        // Hash table starts right after code
        let hash_off = code_offset() + code.len();
        let nbucket = u32::from_le_bytes(elf[hash_off..hash_off + 4].try_into().unwrap());
        let nchain =
            u32::from_le_bytes(elf[hash_off + 4..hash_off + 8].try_into().unwrap());

        assert_eq!(nbucket as usize, sym_count);
        assert_eq!(nchain as usize, sym_count);
    }

    #[test]
    fn aarch64_machine_field() {
        let code = vec![0; 16];
        let syms = test_symbols();
        let elf = build(EM_AARCH64, &code, &syms);
        assert_eq!(u16::from_le_bytes([elf[18], elf[19]]), EM_AARCH64);
    }

    #[test]
    fn dynstr_contains_all_names() {
        let code = vec![0xcc; 16];
        let syms = test_symbols();
        let elf = build(EM_X86_64, &code, &syms);
        let elf_str = String::from_utf8_lossy(&elf);
        for sym in &syms {
            assert!(
                elf_str.contains(sym.name),
                "dynstr missing symbol: {}",
                sym.name
            );
        }
    }

    #[test]
    fn elf_hash_known_values() {
        // Known test vectors for SysV hash
        assert_eq!(elf_hash(b""), 0);
        // Basic sanity: different names produce different hashes
        assert_ne!(elf_hash(b"open"), elf_hash(b"openat"));
        assert_ne!(elf_hash(b"open"), elf_hash(b"open64"));
    }
}
