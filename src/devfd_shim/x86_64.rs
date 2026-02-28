// x86_64.rs: Machine code emitter for the devfd shim shared library (x86_64)
//
// Emits raw x86_64 machine code that intercepts open()/openat() libc calls.
// When the path matches /dev/stdin, /dev/stdout, /dev/stderr, /dev/fd/{0,1,2},
// or /proc/self/fd/{0,1,2}, the interceptor returns dup(N) for the
// appropriate fd. All other paths fall through to the real openat syscall.
//
// Exported symbols: open, openat, open64, openat64
// (open64/openat64 are aliases; identical on 64-bit Linux)
//
// Linux x86_64 syscall ABI:
//   rax = syscall number
//   rdi, rsi, rdx, r10 = first 4 arguments
//   syscall instruction; return in rax
//
// C calling convention (System V AMD64 ABI):
//   rdi, rsi, rdx, rcx, r8, r9 = arguments
//   rax = return value
//
// openat(int dirfd, const char *path, int flags, mode_t mode)
//   → rdi=dirfd, rsi=path, rdx=flags, rcx=mode
//
// open(const char *path, int flags, mode_t mode)
//   → rdi=path, rsi=flags, rdx=mode

// Syscall numbers
const SYS_DUP: u8 = 32;
const SYS_OPENAT: u16 = 257;

// AT_FDCWD = -100
const AT_FDCWD: i32 = -100;

use super::elf;

/// Label index for forward/backward references.
#[derive(Clone, Copy)]
struct Label(usize);

struct Fixup {
    offset: usize,   // byte offset in code[] to patch
    label: usize,    // target label index
    insn_end: usize, // byte offset of instruction end (for rel calculation)
    size: u8,        // 1 = rel8, 4 = rel32
}

struct Asm {
    code: Vec<u8>,
    labels: Vec<Option<usize>>,
    fixups: Vec<Fixup>,
}

impl Asm {
    fn new() -> Self {
        Self {
            code: Vec::with_capacity(512),
            labels: Vec::new(),
            fixups: Vec::new(),
        }
    }

    fn pos(&self) -> usize {
        self.code.len()
    }

    fn emit(&mut self, bytes: &[u8]) {
        self.code.extend_from_slice(bytes);
    }

    fn label(&mut self) -> Label {
        let idx = self.labels.len();
        self.labels.push(None);
        Label(idx)
    }

    fn bind(&mut self, label: Label) {
        assert!(self.labels[label.0].is_none(), "label already bound");
        self.labels[label.0] = Some(self.pos());
    }

    /// Emit a 1-byte relative jump with condition.
    fn jcc_short(&mut self, opcode: u8, target: Label) {
        self.code.push(opcode);
        let offset = self.pos();
        self.code.push(0);
        self.fixups.push(Fixup {
            offset,
            label: target.0,
            insn_end: self.pos(),
            size: 1,
        });
    }

    /// Emit a 4-byte relative jump with condition (2-byte opcode).
    fn jcc_near(&mut self, short_opcode: u8, target: Label) {
        self.emit(&[0x0F, short_opcode + 0x10]);
        let offset = self.pos();
        self.emit(&[0; 4]);
        self.fixups.push(Fixup {
            offset,
            label: target.0,
            insn_end: self.pos(),
            size: 4,
        });
    }

    /// Emit jmp rel8 (0xEB).
    fn jmp_short(&mut self, target: Label) {
        self.code.push(0xEB);
        let offset = self.pos();
        self.code.push(0);
        self.fixups.push(Fixup {
            offset,
            label: target.0,
            insn_end: self.pos(),
            size: 1,
        });
    }

    /// Emit jmp rel32 (0xE9).
    fn jmp_near(&mut self, target: Label) {
        self.code.push(0xE9);
        let offset = self.pos();
        self.emit(&[0; 4]);
        self.fixups.push(Fixup {
            offset,
            label: target.0,
            insn_end: self.pos(),
            size: 4,
        });
    }

    /// Resolve all fixups and return the final machine code.
    fn finish(mut self) -> Vec<u8> {
        for fixup in &self.fixups {
            let target = self.labels[fixup.label]
                .unwrap_or_else(|| panic!("unresolved label {}", fixup.label));
            let rel = target as isize - fixup.insn_end as isize;
            match fixup.size {
                1 => {
                    assert!(
                        (-128..=127).contains(&rel),
                        "rel8 overflow: offset {} to target {} = {}",
                        fixup.insn_end,
                        target,
                        rel
                    );
                    self.code[fixup.offset] = rel as i8 as u8;
                }
                4 => {
                    let bytes = (rel as i32).to_le_bytes();
                    self.code[fixup.offset..fixup.offset + 4].copy_from_slice(&bytes);
                }
                _ => unreachable!(),
            }
        }
        self.code
    }
}

/// Generate the x86_64 machine code and symbol table for the devfd shim.
///
/// Returns `(code_bytes, symbols)` where symbols list the exported
/// function names and their offsets within `code_bytes`.
pub fn generate() -> (Vec<u8>, Vec<elf::Symbol>) {
    let mut a = Asm::new();

    // Forward-declare labels
    let do_openat = a.label(); // openat entry (main logic)
    let fallthrough = a.label(); // real openat syscall
    let do_dup = a.label(); // dup(target_fd) and return
    let check_dev_fd = a.label();
    let check_proc = a.label();
    let dup_fd0 = a.label();
    let dup_fd1 = a.label();
    let dup_fd2 = a.label();

    // ========== open(path, flags, mode) ==========
    // Rewrite as openat(AT_FDCWD, path, flags, mode) and tail-call.
    //
    // C ABI in: rdi=path, rsi=flags, rdx=mode
    // We need:  rdi=AT_FDCWD, rsi=path, rdx=flags, rcx=mode
    let open_offset = a.pos();

    // mov rcx, rdx              ; mode → 4th arg
    a.emit(&[0x48, 0x89, 0xD1]);
    // mov rdx, rsi              ; flags → 3rd arg
    a.emit(&[0x48, 0x89, 0xF2]);
    // mov rsi, rdi              ; path → 2nd arg
    a.emit(&[0x48, 0x89, 0xFE]);
    // mov edi, AT_FDCWD         ; dirfd = AT_FDCWD
    a.emit(&[0xBF]);
    a.emit(&(AT_FDCWD as u32).to_le_bytes());
    // jmp do_openat             ; too far for rel8, use near
    a.jmp_near(do_openat);

    // ========== openat(dirfd, path, flags, mode) ==========
    // C ABI in: rdi=dirfd, rsi=path, rdx=flags, rcx=mode
    let openat_offset = a.pos();
    a.bind(do_openat);

    // Save arguments for the fallthrough case.
    // The syscall ABI uses r10 for the 4th arg (not rcx).
    // mov r10, rcx              ; mode → r10 (for syscall later)
    a.emit(&[0x49, 0x89, 0xCA]);

    // Load first 8 bytes of path for prefix matching.
    // mov rax, [rsi]            ; rax = *(uint64_t*)path
    a.emit(&[0x48, 0x8B, 0x06]);

    // ---- Check "/dev/std" prefix (8 bytes) ----
    // movabs rcx, imm64         ; rcx = "/dev/std" as u64
    a.emit(&[0x48, 0xB9]);
    a.emit(&u64::from_le_bytes(*b"/dev/std").to_le_bytes());
    // cmp rax, rcx
    a.emit(&[0x48, 0x39, 0xC8]);
    // jne check_dev_fd          ; too far for rel8
    a.jcc_near(0x75, check_dev_fd);

    // Matched "/dev/std" --check suffix at path[8].
    // Check for "in\0" (3 bytes), "out\0" (4 bytes), "err\0" (4 bytes).
    // Load 4 bytes at path+8 (may read past null, but that's fine since
    // we already matched the 8-byte prefix so the string is at least 8 bytes).
    // mov eax, [rsi+8]          ; eax = *(uint32_t*)(path+8)
    a.emit(&[0x8B, 0x46, 0x08]);

    // Check "in\0" --only need 3 bytes. Mask to 24 bits.
    // and eax with 0x00FFFFFF would clobber; use a temp.
    // mov ecx, eax
    a.emit(&[0x89, 0xC1]);
    // and ecx, 0x00FFFFFF       ; mask to 3 bytes
    a.emit(&[0x81, 0xE1]);
    a.emit(&0x00FFFFFFu32.to_le_bytes());
    // cmp ecx, "in\0"
    a.emit(&[0x81, 0xF9]);
    a.emit(&u32::from_le_bytes([b'i', b'n', 0, 0]).to_le_bytes());
    // je dup_fd0
    a.jcc_near(0x74, dup_fd0);

    // Check "out\0" (4 bytes, use full eax)
    // cmp eax, "out\0"
    a.emit(&[0x3D]);
    a.emit(&u32::from_le_bytes(*b"out\0").to_le_bytes());
    // je dup_fd1
    a.jcc_near(0x74, dup_fd1);

    // Check "err\0" (4 bytes)
    // cmp eax, "err\0"
    a.emit(&[0x3D]);
    a.emit(&u32::from_le_bytes(*b"err\0").to_le_bytes());
    // je dup_fd2
    a.jcc_near(0x74, dup_fd2);

    // No suffix match --fall through to real openat
    a.jmp_near(fallthrough);

    // ---- Check "/dev/fd/" prefix (8 bytes) ----
    a.bind(check_dev_fd);

    // Reload first 8 bytes (rax was clobbered by suffix checks above)
    // mov rax, [rsi]
    a.emit(&[0x48, 0x8B, 0x06]);

    // movabs rcx, "/dev/fd/"
    a.emit(&[0x48, 0xB9]);
    a.emit(&u64::from_le_bytes(*b"/dev/fd/").to_le_bytes());
    // cmp rax, rcx
    a.emit(&[0x48, 0x39, 0xC8]);
    // jne check_proc            ; too far for rel8
    a.jcc_near(0x75, check_proc);

    // Matched "/dev/fd/" --check path[8..10] for "0\0", "1\0", "2\0"
    // movzx eax, word [rsi+8]   ; load 2 bytes
    a.emit(&[0x0F, 0xB7, 0x46, 0x08]);

    // cmp ax, "0\0"
    a.emit(&[0x66, 0x3D]);
    a.emit(&u16::from_le_bytes([b'0', 0]).to_le_bytes());
    a.jcc_near(0x74, dup_fd0);

    // cmp ax, "1\0"
    a.emit(&[0x66, 0x3D]);
    a.emit(&u16::from_le_bytes([b'1', 0]).to_le_bytes());
    a.jcc_near(0x74, dup_fd1);

    // cmp ax, "2\0"
    a.emit(&[0x66, 0x3D]);
    a.emit(&u16::from_le_bytes([b'2', 0]).to_le_bytes());
    a.jcc_near(0x74, dup_fd2);

    a.jmp_near(fallthrough);

    // ---- Check "/proc/se" prefix (8 bytes) ----
    a.bind(check_proc);

    // rax already reloaded above, but clobbered by movzx. Reload.
    // mov rax, [rsi]
    a.emit(&[0x48, 0x8B, 0x06]);

    // movabs rcx, "/proc/se"
    a.emit(&[0x48, 0xB9]);
    a.emit(&u64::from_le_bytes(*b"/proc/se").to_le_bytes());
    // cmp rax, rcx
    a.emit(&[0x48, 0x39, 0xC8]);
    // jne fallthrough
    a.jcc_near(0x75, fallthrough);

    // Matched "/proc/se" --check suffix "lf/fd/0\0" (8 bytes) at path[8]
    // mov rax, [rsi+8]
    a.emit(&[0x48, 0x8B, 0x46, 0x08]);

    // movabs rcx, "lf/fd/0\0"
    a.emit(&[0x48, 0xB9]);
    a.emit(&u64::from_le_bytes(*b"lf/fd/0\0").to_le_bytes());
    // cmp rax, rcx
    a.emit(&[0x48, 0x39, 0xC8]);
    a.jcc_short(0x74, dup_fd0);

    // movabs rcx, "lf/fd/1\0"
    a.emit(&[0x48, 0xB9]);
    a.emit(&u64::from_le_bytes(*b"lf/fd/1\0").to_le_bytes());
    // cmp rax, rcx
    a.emit(&[0x48, 0x39, 0xC8]);
    a.jcc_short(0x74, dup_fd1);

    // movabs rcx, "lf/fd/2\0"
    a.emit(&[0x48, 0xB9]);
    a.emit(&u64::from_le_bytes(*b"lf/fd/2\0").to_le_bytes());
    // cmp rax, rcx
    a.emit(&[0x48, 0x39, 0xC8]);
    a.jcc_short(0x74, dup_fd2);

    // Fall through to real openat
    a.jmp_short(fallthrough);

    // ========== dup(N) handlers ==========
    a.bind(dup_fd0);
    // xor edi, edi              ; fd = 0
    a.emit(&[0x31, 0xFF]);
    a.jmp_short(do_dup);

    a.bind(dup_fd1);
    // mov edi, 1
    a.emit(&[0xBF, 0x01, 0x00, 0x00, 0x00]);
    a.jmp_short(do_dup);

    a.bind(dup_fd2);
    // mov edi, 2
    a.emit(&[0xBF, 0x02, 0x00, 0x00, 0x00]);
    // fall through to do_dup

    // ========== do_dup: syscall(SYS_dup, fd_in_edi) ==========
    a.bind(do_dup);
    // mov eax, SYS_DUP
    a.emit(&[0xB8]);
    a.emit(&(SYS_DUP as u32).to_le_bytes());
    // syscall
    a.emit(&[0x0F, 0x05]);
    // ret
    a.emit(&[0xC3]);

    // ========== fallthrough: real openat syscall ==========
    a.bind(fallthrough);
    // Arguments are already in place: rdi=dirfd, rsi=path, rdx=flags, r10=mode
    // mov eax, SYS_OPENAT
    a.emit(&[0xB8]);
    a.emit(&(SYS_OPENAT as u32).to_le_bytes());
    // syscall
    a.emit(&[0x0F, 0x05]);
    // ret
    a.emit(&[0xC3]);

    let code = a.finish();

    let symbols = vec![
        elf::Symbol {
            name: "open",
            offset: open_offset,
        },
        elf::Symbol {
            name: "openat",
            offset: openat_offset,
        },
        elf::Symbol {
            name: "open64",
            offset: open_offset, // alias
        },
        elf::Symbol {
            name: "openat64",
            offset: openat_offset, // alias
        },
    ];

    (code, symbols)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_generates_without_panic() {
        let (code, _) = generate();
        assert!(code.len() > 50, "code too small: {} bytes", code.len());
        assert!(code.len() < 1024, "code too large: {} bytes", code.len());
    }

    #[test]
    fn exports_four_symbols() {
        let (_, symbols) = generate();
        assert_eq!(symbols.len(), 4);
        let names: Vec<&str> = symbols.iter().map(|s| s.name).collect();
        assert!(names.contains(&"open"));
        assert!(names.contains(&"openat"));
        assert!(names.contains(&"open64"));
        assert!(names.contains(&"openat64"));
    }

    #[test]
    fn symbol_offsets_within_bounds() {
        let (code, symbols) = generate();
        for sym in &symbols {
            assert!(
                sym.offset < code.len(),
                "symbol {} offset {} out of bounds (code len {})",
                sym.name,
                sym.offset,
                code.len()
            );
        }
    }

    #[test]
    fn open64_aliases_open() {
        let (_, symbols) = generate();
        let open = symbols.iter().find(|s| s.name == "open").unwrap();
        let open64 = symbols.iter().find(|s| s.name == "open64").unwrap();
        assert_eq!(open.offset, open64.offset);
    }

    #[test]
    fn openat64_aliases_openat() {
        let (_, symbols) = generate();
        let openat = symbols.iter().find(|s| s.name == "openat").unwrap();
        let openat64 = symbols.iter().find(|s| s.name == "openat64").unwrap();
        assert_eq!(openat.offset, openat64.offset);
    }

    #[test]
    fn code_contains_two_syscall_instructions() {
        let (code, _) = generate();
        let count = code.windows(2).filter(|w| w == &[0x0F, 0x05]).count();
        // SYS_dup + SYS_openat = 2
        assert_eq!(count, 2, "expected 2 syscall instructions, got {count}");
    }
}
