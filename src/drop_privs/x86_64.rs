// x86_64.rs — Machine code emitter for the drop_privs binary (x86_64)
//
// Emits raw x86_64 machine code that performs:
//   1. Parse argc/argv from the Linux process stack
//   2. atoi(argv[1]) -> uid, atoi(argv[2]) -> gid
//   3. setgroups(0, NULL) -> setgid(gid) -> setuid(uid)
//   4. chdir(argv[3])
//   5. execve(argv[4], &argv[4..], envp)
//
// Linux x86_64 syscall ABI:
//   rax = syscall number
//   rdi, rsi, rdx, r10, r8, r9 = arguments
//   syscall instruction; return in rax (negative = -errno)
//
// Linux process startup ABI (no libc, _start):
//   [rsp+0]  = argc
//   [rsp+8]  = argv[0]
//   [rsp+16] = argv[1]
//   ...
//   NULL
//   envp[0], envp[1], ..., NULL

// Syscall numbers
const SYS_WRITE: u8 = 1;
const SYS_EXECVE: u8 = 59;
const SYS_EXIT: u8 = 60;
const SYS_CHDIR: u8 = 80;
const SYS_SETUID: u8 = 105;
const SYS_SETGID: u8 = 106;
const SYS_SETGROUPS: u8 = 116;

// Register numbers (low 3 bits, used in ModRM/SIB)
const RAX: u8 = 0;
const RCX: u8 = 1;
const RDX: u8 = 2;
const RBP: u8 = 5;
const RSI: u8 = 6;
const RDI: u8 = 7;

// Extended registers (need REX.R or REX.B)
const R8: u8 = 0; // + REX.B/REX.R
const R12: u8 = 4;
const R13: u8 = 5;

// Error message strings (shared between emitter and data section so
// lengths stay in sync with the actual bytes).
const MSG_USAGE: &[u8] = b"usage: drop_privs <uid> <gid> <dir> <cmd> [args...]\n";
const MSG_NUMBER: &[u8] = b"bad number\n";
const MSG_SETGROUPS: &[u8] = b"setgroups\n";
const MSG_SETGID: &[u8] = b"setgid\n";
const MSG_SETUID: &[u8] = b"setuid\n";
const MSG_CHDIR: &[u8] = b"chdir\n";
const MSG_EXECVE: &[u8] = b"execve\n";

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

    /// Allocate a new label (unbound).
    fn label(&mut self) -> Label {
        let idx = self.labels.len();
        self.labels.push(None);
        Label(idx)
    }

    /// Bind a label to the current code position.
    fn bind(&mut self, label: Label) {
        assert!(self.labels[label.0].is_none(), "label already bound");
        self.labels[label.0] = Some(self.pos());
    }

    /// Emit a 1-byte relative jump with condition.
    /// Opcodes: js=0x78, jl=0x7c, jz=0x74, jnz=0x75, ja=0x77, jb=0x72
    fn jcc_short(&mut self, opcode: u8, target: Label) {
        self.code.push(opcode);
        let offset = self.pos();
        self.code.push(0); // placeholder
        self.fixups.push(Fixup {
            offset,
            label: target.0,
            insn_end: self.pos(),
            size: 1,
        });
    }

    /// Emit a 4-byte relative jump with condition (2-byte opcode).
    /// Near conditional: 0F 8x rel32.
    /// Opcode is the short form (e.g. 0x7C for jl); we compute the near form.
    fn jcc_near(&mut self, short_opcode: u8, target: Label) {
        // Near form: 0F (short_opcode + 0x10) rel32
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

    /// Emit call rel32 (0xE8).
    fn call(&mut self, target: Label) {
        self.code.push(0xE8);
        let offset = self.pos();
        self.emit(&[0; 4]);
        self.fixups.push(Fixup {
            offset,
            label: target.0,
            insn_end: self.pos(),
            size: 4,
        });
    }

    /// Emit lea rsi, [rip + disp32] referencing a label.
    /// Encoding: 48 8D 35 <rel32>
    fn lea_rsi_rip(&mut self, target: Label) {
        self.emit(&[0x48, 0x8D, 0x35]);
        let offset = self.pos();
        self.emit(&[0; 4]);
        self.fixups.push(Fixup {
            offset,
            label: target.0,
            insn_end: self.pos(),
            size: 4,
        });
    }

    /// Emit data bytes at current position (for string constants).
    fn data(&mut self, bytes: &[u8]) {
        self.emit(bytes);
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

// ---- Instruction helpers (not methods, just emit patterns) ----

/// ModRM byte: mod(2) | reg(3) | rm(3)
const fn modrm(md: u8, reg: u8, rm: u8) -> u8 {
    (md << 6) | ((reg & 7) << 3) | (rm & 7)
}

/// REX prefix: 0100 WRXB
const fn rex(w: bool, r: bool, x: bool, b: bool) -> u8 {
    0x40 | ((w as u8) << 3) | ((r as u8) << 2) | ((x as u8) << 1) | (b as u8)
}

/// SIB byte for [rsp+disp] addressing (index=none, base=rsp)
const SIB_RSP: u8 = 0x24; // scale=0, index=100(none), base=100(rsp)

/// Generate the complete x86_64 machine code for drop_privs.
pub fn generate() -> Vec<u8> {
    let mut a = Asm::new();

    // Forward-declare all labels
    let atoi = a.label();
    let atoi_loop = a.label();
    let atoi_error = a.label();
    let error_exit = a.label();
    let err_setgroups = a.label();
    let err_setgid = a.label();
    let err_setuid = a.label();
    let err_chdir = a.label();
    let err_execve = a.label();
    let usage_error = a.label();

    let lbl_msg_usage = a.label();
    let lbl_msg_number = a.label();
    let lbl_msg_setgroups = a.label();
    let lbl_msg_setgid = a.label();
    let lbl_msg_setuid = a.label();
    let lbl_msg_chdir = a.label();
    let lbl_msg_execve = a.label();

    // ========== _start ==========

    // mov rbp, rsp                    ; save stack pointer
    // Encoding: REX.W(48) MOV r/m64,r64(89) modrm(3, rsp=4, rbp=5)=E5
    a.emit(&[0x48, 0x89, 0xE5]);

    // mov r8, [rsp]                   ; r8 = argc
    // REX: W=1, R=1 (r8 in reg). Opcode 8B. ModRM: mod=00, reg=r8(0), rm=100(SIB). SIB=0x24.
    a.emit(&[
        rex(true, true, false, false),
        0x8B,
        modrm(0, R8, 4),
        SIB_RSP,
    ]);
    // note: 4 in rm = "SIB follows", not rsp as dest

    // cmp r8, 5                       ; argc >= 5?
    // REX: W=1, B=1 (r8 in rm). Opcode 83 /7. ModRM: mod=11, reg=7, rm=r8(0).
    a.emit(&[rex(true, false, false, true), 0x83, modrm(3, 7, R8), 5]);

    // jl usage_error                  ; too far for rel8, use near jump
    a.jcc_near(0x7C, usage_error);

    // --- Parse UID (argv[1]) ---
    // mov rdi, [rbp + 16]             ; argv[1]
    a.emit(&[0x48, 0x8B, modrm(1, RDI, RBP), 16]);

    // call atoi
    a.call(atoi);

    // mov r12, rax                    ; r12 = uid
    // "mov r/m64, r64" with REX.B for r12: 49 89 C4
    a.emit(&[rex(true, false, false, true), 0x89, modrm(3, RAX, R12)]);

    // --- Parse GID (argv[2]) ---
    // mov rdi, [rbp + 24]             ; argv[2]
    a.emit(&[0x48, 0x8B, modrm(1, RDI, RBP), 24]);

    // call atoi
    a.call(atoi);

    // mov r13, rax                    ; r13 = gid
    a.emit(&[rex(true, false, false, true), 0x89, modrm(3, RAX, R13)]);

    // --- setgroups(0, NULL) ---
    // mov eax, SYS_SETGROUPS
    a.emit(&[0xB8]);
    a.emit(&(SYS_SETGROUPS as u32).to_le_bytes());

    // xor edi, edi                    ; count = 0
    a.emit(&[0x31, 0xFF]);

    // xor esi, esi                    ; list = NULL
    a.emit(&[0x31, 0xF6]);

    // syscall
    a.emit(&[0x0F, 0x05]);

    // test rax, rax
    a.emit(&[0x48, 0x85, 0xC0]);

    // js err_setgroups
    a.jcc_short(0x78, err_setgroups);

    // --- setgid(gid) ---
    // mov eax, SYS_SETGID
    a.emit(&[0xB8]);
    a.emit(&(SYS_SETGID as u32).to_le_bytes());

    // mov edi, r13d                   ; gid
    // "mov r/m32, r32" REX.R=1 for r13: 44 89 EF
    a.emit(&[0x44, 0x89, modrm(3, R13, RDI)]);

    // syscall
    a.emit(&[0x0F, 0x05]);

    // test rax, rax
    a.emit(&[0x48, 0x85, 0xC0]);

    // js err_setgid
    a.jcc_short(0x78, err_setgid);

    // --- setuid(uid) ---
    // mov eax, SYS_SETUID
    a.emit(&[0xB8]);
    a.emit(&(SYS_SETUID as u32).to_le_bytes());

    // mov edi, r12d                   ; uid
    a.emit(&[0x44, 0x89, modrm(3, R12, RDI)]);

    // syscall
    a.emit(&[0x0F, 0x05]);

    // test rax, rax
    a.emit(&[0x48, 0x85, 0xC0]);

    // js err_setuid
    a.jcc_short(0x78, err_setuid);

    // --- chdir(argv[3]) ---
    // mov eax, SYS_CHDIR
    a.emit(&[0xB8]);
    a.emit(&(SYS_CHDIR as u32).to_le_bytes());

    // mov rdi, [rbp + 32]             ; argv[3] = workdir
    a.emit(&[0x48, 0x8B, modrm(1, RDI, RBP), 32]);

    // syscall
    a.emit(&[0x0F, 0x05]);

    // test rax, rax
    a.emit(&[0x48, 0x85, 0xC0]);

    // js err_chdir
    a.jcc_short(0x78, err_chdir);

    // --- execve(argv[4], &argv[4..], envp) ---
    // mov rdi, [rbp + 40]             ; filename = argv[4]
    a.emit(&[0x48, 0x8B, modrm(1, RDI, RBP), 40]);

    // lea rsi, [rbp + 40]             ; argv = &argv[4..]
    a.emit(&[0x48, 0x8D, modrm(1, RSI, RBP), 40]);

    // Calculate envp: envp = rbp + (argc + 2) * 8
    // mov rdx, [rbp]                  ; rdx = argc
    // Note: [rbp+0] requires mod=01 disp8=0 (mod=00 rm=5 means RIP-relative)
    a.emit(&[0x48, 0x8B, modrm(1, RDX, RBP), 0]);

    // add rdx, 2
    a.emit(&[0x48, 0x83, modrm(3, 0, RDX), 2]);

    // shl rdx, 3
    a.emit(&[0x48, 0xC1, modrm(3, 4, RDX), 3]);

    // add rdx, rbp                    ; rdx = envp
    a.emit(&[0x48, 0x01, modrm(3, RBP, RDX)]);

    // mov eax, SYS_EXECVE
    a.emit(&[0xB8]);
    a.emit(&(SYS_EXECVE as u32).to_le_bytes());

    // syscall
    a.emit(&[0x0F, 0x05]);

    // execve only returns on error — fall through

    // ========== Error handlers ==========

    a.bind(err_execve);
    a.lea_rsi_rip(lbl_msg_execve);
    a.emit(&[0xBA]); // mov edx, imm32
    a.emit(&(MSG_EXECVE.len() as u32).to_le_bytes());
    a.jmp_short(error_exit);

    a.bind(err_setgroups);
    a.lea_rsi_rip(lbl_msg_setgroups);
    a.emit(&[0xBA]);
    a.emit(&(MSG_SETGROUPS.len() as u32).to_le_bytes());
    a.jmp_short(error_exit);

    a.bind(err_setgid);
    a.lea_rsi_rip(lbl_msg_setgid);
    a.emit(&[0xBA]);
    a.emit(&(MSG_SETGID.len() as u32).to_le_bytes());
    a.jmp_short(error_exit);

    a.bind(err_setuid);
    a.lea_rsi_rip(lbl_msg_setuid);
    a.emit(&[0xBA]);
    a.emit(&(MSG_SETUID.len() as u32).to_le_bytes());
    a.jmp_short(error_exit);

    a.bind(err_chdir);
    a.lea_rsi_rip(lbl_msg_chdir);
    a.emit(&[0xBA]);
    a.emit(&(MSG_CHDIR.len() as u32).to_le_bytes());
    a.jmp_short(error_exit);

    // Usage error
    a.bind(usage_error);
    a.lea_rsi_rip(lbl_msg_usage);
    a.emit(&[0xBA]);
    a.emit(&(MSG_USAGE.len() as u32).to_le_bytes());
    // fall through to error_exit

    // ========== error_exit: write(2, rsi, rdx) then exit(1) ==========

    a.bind(error_exit);
    // mov eax, SYS_WRITE
    a.emit(&[0xB8]);
    a.emit(&(SYS_WRITE as u32).to_le_bytes());
    // mov edi, 2                      ; stderr
    a.emit(&[0xBF]);
    a.emit(&2u32.to_le_bytes());
    // syscall
    a.emit(&[0x0F, 0x05]);
    // mov eax, SYS_EXIT
    a.emit(&[0xB8]);
    a.emit(&(SYS_EXIT as u32).to_le_bytes());
    // mov edi, 1
    a.emit(&[0xBF]);
    a.emit(&1u32.to_le_bytes());
    // syscall
    a.emit(&[0x0F, 0x05]);

    // ========== atoi subroutine ==========
    // Input: rdi = pointer to null-terminated ASCII decimal string
    // Output: rax = parsed value (guaranteed to fit in u32)
    // Clobbers: rcx, rdi
    // On bad input or overflow: jumps to error_exit (does not return)

    a.bind(atoi);

    // xor eax, eax                    ; result = 0
    a.emit(&[0x31, 0xC0]);

    // movzx ecx, byte [rdi]           ; load first char
    a.emit(&[0x0F, 0xB6, modrm(0, RCX, RDI)]);

    // test cl, cl                     ; empty string?
    a.emit(&[0x84, 0xC9]);

    // jz atoi_error                   ; empty = error
    a.jcc_short(0x74, atoi_error);

    a.bind(atoi_loop);

    // sub cl, 0x30                    ; cl -= '0'
    a.emit(&[0x80, 0xE9, 0x30]);

    // cmp cl, 9                       ; unsigned: if cl > 9, not a digit
    a.emit(&[0x80, 0xF9, 9]);

    // ja atoi_error
    a.jcc_short(0x77, atoi_error);

    // imul rax, rax, 10               ; result *= 10
    a.emit(&[0x48, 0x6B, 0xC0, 10]);

    // add rax, rcx                    ; result += digit (rcx upper bytes are 0)
    a.emit(&[0x48, 0x01, modrm(3, RCX, RAX)]);

    // inc rdi                         ; next char
    a.emit(&[0x48, 0xFF, modrm(3, 0, RDI)]);

    // movzx ecx, byte [rdi]           ; load next char
    a.emit(&[0x0F, 0xB6, modrm(0, RCX, RDI)]);

    // test cl, cl
    a.emit(&[0x84, 0xC9]);

    // jnz atoi_loop
    a.jcc_short(0x75, atoi_loop);

    // --- Overflow check: reject values > u32 max (4294967295) ---
    // UIDs/GIDs are u32. A crafted input like "99999999999999999999" would
    // silently wrap and could land on UID 0 (root), defeating the purpose
    // of privilege dropping.
    //
    // mov ecx, 0xFFFFFFFF             ; ecx = u32::MAX, rcx = 0x00000000FFFFFFFF
    a.emit(&[0xB9]);
    a.emit(&0xFFFFFFFFu32.to_le_bytes());
    // cmp rax, rcx                    ; 64-bit unsigned compare
    a.emit(&[0x48, 0x39, modrm(3, RCX, RAX)]);
    // ja atoi_error                   ; rax > 0xFFFFFFFF means overflow
    a.jcc_short(0x77, atoi_error);

    // ret
    a.emit(&[0xC3]);

    // atoi_error: bad number
    a.bind(atoi_error);
    a.lea_rsi_rip(lbl_msg_number);
    a.emit(&[0xBA]);
    a.emit(&(MSG_NUMBER.len() as u32).to_le_bytes());
    a.jmp_near(error_exit);

    // ========== String data ==========

    a.bind(lbl_msg_usage);
    a.data(MSG_USAGE);

    a.bind(lbl_msg_number);
    a.data(MSG_NUMBER);

    a.bind(lbl_msg_setgroups);
    a.data(MSG_SETGROUPS);

    a.bind(lbl_msg_setgid);
    a.data(MSG_SETGID);

    a.bind(lbl_msg_setuid);
    a.data(MSG_SETUID);

    a.bind(lbl_msg_chdir);
    a.data(MSG_CHDIR);

    a.bind(lbl_msg_execve);
    a.data(MSG_EXECVE);

    a.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_generates_without_panic() {
        let code = generate();
        // Sanity: code should be a few hundred bytes
        assert!(code.len() > 100, "code too small: {} bytes", code.len());
        assert!(code.len() < 1024, "code too large: {} bytes", code.len());
    }

    #[test]
    fn code_starts_with_mov_rbp_rsp() {
        let code = generate();
        // mov rbp, rsp = 48 89 E5
        assert_eq!(&code[0..3], &[0x48, 0x89, 0xE5]);
    }

    #[test]
    fn code_contains_syscall_instructions() {
        let code = generate();
        // Count syscall instructions (0F 05)
        let count = code.windows(2).filter(|w| w == &[0x0F, 0x05]).count();
        // We have: setgroups, setgid, setuid, chdir, execve, write, exit = 7
        assert_eq!(count, 7, "expected 7 syscall instructions");
    }

    #[test]
    fn code_contains_string_data() {
        let code = generate();
        let code_str = String::from_utf8_lossy(&code);
        assert!(code_str.contains("setgroups\n"));
        assert!(code_str.contains("setgid\n"));
        assert!(code_str.contains("setuid\n"));
        assert!(code_str.contains("chdir\n"));
        assert!(code_str.contains("execve\n"));
        assert!(code_str.contains("bad number\n"));
        assert!(code_str.contains("usage: drop_privs"));
    }

    #[test]
    fn atoi_has_overflow_guard() {
        // The atoi subroutine must contain a u32 overflow check.
        // It loads 0xFFFFFFFF into ecx (B9 FF FF FF FF) and compares
        // rax against rcx (48 39 C8) followed by ja (77).
        let code = generate();
        let has_guard = code.windows(5).any(|w| w == [0xB9, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert!(has_guard, "missing u32 overflow guard in atoi");
    }

    #[test]
    fn message_lengths_match_data() {
        // Verify the compile-time constants are correct.
        assert_eq!(MSG_USAGE.len(), 52);
        assert_eq!(MSG_NUMBER.len(), 11);
        assert_eq!(MSG_SETGROUPS.len(), 10);
        assert_eq!(MSG_SETGID.len(), 7);
        assert_eq!(MSG_SETUID.len(), 7);
        assert_eq!(MSG_CHDIR.len(), 6);
        assert_eq!(MSG_EXECVE.len(), 7);
    }
}
