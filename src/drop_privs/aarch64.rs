// aarch64.rs: Machine code emitter for the drop_privs binary (aarch64)
//
// Emits raw AArch64 machine code that performs the same sequence as x86_64.rs.
//
// Linux aarch64 syscall ABI:
//   x8 = syscall number
//   x0-x5 = arguments
//   svc #0; return in x0 (negative = -errno)
//
// Linux process startup ABI (_start, no libc):
//   [sp+0]  = argc
//   [sp+8]  = argv[0]
//   [sp+16] = argv[1]
//   ...
//   NULL
//   envp[0], envp[1], ..., NULL
//
// Callee-saved registers (preserved across bl calls):
//   x19 = argc
//   x20 = &argv[0] (sp + 8)
//   x21 = uid
//   x22 = gid
//   x30 = link register (set by bl, used by ret)

// Syscall numbers (aarch64)
const SYS_CHDIR: u16 = 49;
const SYS_WRITE: u16 = 64;
const SYS_EXIT: u16 = 93;
const SYS_SETGROUPS: u16 = 159;
const SYS_SETGID: u16 = 144;
const SYS_SETUID: u16 = 146;
const SYS_EXECVE: u16 = 221;

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

enum FixupKind {
    /// b.cond: 19-bit signed offset (in 4-byte units) at bits [23:5]
    BCond,
    /// b / bl: 26-bit signed offset (in 4-byte units) at bits [25:0]
    Branch26,
    /// adr: 21-bit signed offset (byte granularity), immlo at [30:29], immhi at [23:5]
    Adr,
    /// cbz / cbnz: 19-bit signed offset (in 4-byte units) at bits [23:5]
    Cbz,
}

struct Fixup {
    offset: usize, // byte offset of the instruction to patch
    label: usize,  // target label index
    kind: FixupKind,
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

    /// Emit a 32-bit little-endian instruction word.
    fn emit32(&mut self, insn: u32) {
        self.code.extend_from_slice(&insn.to_le_bytes());
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

    /// Emit data bytes (for string constants). Pad to 4-byte alignment.
    fn data(&mut self, bytes: &[u8]) {
        self.code.extend_from_slice(bytes);
        // Pad to 4-byte alignment (aarch64 instructions must be aligned)
        while !self.code.len().is_multiple_of(4) {
            self.code.push(0);
        }
    }

    // ---- AArch64 instruction emitters ----

    /// LDR Xt, [Xn, #imm]: 64-bit load, unsigned offset.
    /// imm must be a multiple of 8, max 32760.
    fn ldr_x(&mut self, rt: u8, rn: u8, imm: u16) {
        assert!(imm.is_multiple_of(8) && imm <= 32760);
        let imm12 = (imm / 8) as u32;
        // 11 111 0 01 01 imm12 Rn Rt
        let insn = 0xF9400000 | (imm12 << 10) | ((rn as u32) << 5) | (rt as u32);
        self.emit32(insn);
    }

    /// LDRB Wt, [Xn]: byte load, unsigned offset.
    fn ldrb_w(&mut self, rt: u8, rn: u8, imm: u16) {
        assert!(imm <= 4095);
        // 00 111 0 01 01 imm12 Rn Rt
        let insn = 0x39400000 | ((imm as u32) << 10) | ((rn as u32) << 5) | (rt as u32);
        self.emit32(insn);
    }

    /// ADD Xd, Xn, #imm12: 64-bit add immediate.
    fn add_x_imm(&mut self, rd: u8, rn: u8, imm: u16) {
        assert!(imm <= 4095);
        // 1 00 10001 0 imm12 Rn Rd
        let insn = 0x91000000 | ((imm as u32) << 10) | ((rn as u32) << 5) | (rd as u32);
        self.emit32(insn);
    }

    /// ADD Xd, Xn, Xm: 64-bit add register.
    fn add_x_reg(&mut self, rd: u8, rn: u8, rm: u8) {
        // 1 00 01011 00 0 Rm 000000 Rn Rd
        let insn = 0x8B000000 | ((rm as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit32(insn);
    }

    /// SUB Wd, Wn, #imm12: 32-bit subtract immediate.
    fn sub_w_imm(&mut self, rd: u8, rn: u8, imm: u16) {
        assert!(imm <= 4095);
        // 0 10 10001 0 imm12 Rn Rd
        let insn = 0x51000000 | ((imm as u32) << 10) | ((rn as u32) << 5) | (rd as u32);
        self.emit32(insn);
    }

    /// CMP Xn, #imm12: 64-bit compare (alias for SUBS XZR, Xn, #imm).
    fn cmp_x_imm(&mut self, rn: u8, imm: u16) {
        assert!(imm <= 4095);
        // 1 11 10001 0 imm12 Rn 11111(xzr)
        let insn = 0xF1000000 | ((imm as u32) << 10) | ((rn as u32) << 5) | 31;
        self.emit32(insn);
    }

    /// CMP Wn, #imm12: 32-bit compare.
    fn cmp_w_imm(&mut self, rn: u8, imm: u16) {
        assert!(imm <= 4095);
        // 0 11 10001 0 imm12 Rn 11111(wzr)
        let insn = 0x71000000 | ((imm as u32) << 10) | ((rn as u32) << 5) | 31;
        self.emit32(insn);
    }

    /// MOV Xd, Xm: 64-bit register move (alias for ORR Xd, XZR, Xm).
    fn mov_x(&mut self, rd: u8, rm: u8) {
        // 1 01 01010 00 0 Rm 000000 11111 Rd
        let insn = 0xAA0003E0 | ((rm as u32) << 16) | (rd as u32);
        self.emit32(insn);
    }

    /// MOVZ Xd, #imm16: move 16-bit immediate, zero rest.
    fn movz_x(&mut self, rd: u8, imm: u16) {
        // 1 10 100101 00 imm16 Rd
        let insn = 0xD2800000 | ((imm as u32) << 5) | (rd as u32);
        self.emit32(insn);
    }

    /// LSL Xd, Xn, #shift: logical shift left (alias for UBFM).
    fn lsl_x(&mut self, rd: u8, rn: u8, shift: u8) {
        assert!(shift < 64);
        let immr = (64 - shift) as u32;
        let imms = (63 - shift) as u32;
        // 1 10 100110 1 immr imms Rn Rd
        let insn = 0xD3400000 | (immr << 16) | (imms << 10) | ((rn as u32) << 5) | (rd as u32);
        self.emit32(insn);
    }

    /// LSR Xd, Xn, #shift: logical shift right (alias for UBFM).
    fn lsr_x(&mut self, rd: u8, rn: u8, shift: u8) {
        assert!(shift < 64);
        let immr = shift as u32;
        let imms = 63u32;
        // 1 10 100110 1 immr imms Rn Rd
        let insn = 0xD3400000 | (immr << 16) | (imms << 10) | ((rn as u32) << 5) | (rd as u32);
        self.emit32(insn);
    }

    /// MUL Xd, Xn, Xm: 64-bit multiply (alias for MADD Xd, Xn, Xm, XZR).
    fn mul_x(&mut self, rd: u8, rn: u8, rm: u8) {
        // 1 00 11011 000 Rm 0 11111 Rn Rd
        let insn = 0x9B007C00 | ((rm as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit32(insn);
    }

    /// SVC #0: supervisor call (syscall).
    fn svc(&mut self) {
        self.emit32(0xD4000001);
    }

    /// RET: return (BR X30).
    fn ret(&mut self) {
        self.emit32(0xD65F03C0);
    }

    /// B.cond label: conditional branch (19-bit range).
    fn b_cond(&mut self, cond: u8, target: Label) {
        let offset = self.pos();
        // 0101 0100 imm19(placeholder) 0 cond
        let insn = 0x54000000 | (cond as u32);
        self.emit32(insn);
        self.fixups.push(Fixup {
            offset,
            label: target.0,
            kind: FixupKind::BCond,
        });
    }

    /// B label: unconditional branch (26-bit range).
    fn b(&mut self, target: Label) {
        let offset = self.pos();
        self.emit32(0x14000000); // placeholder
        self.fixups.push(Fixup {
            offset,
            label: target.0,
            kind: FixupKind::Branch26,
        });
    }

    /// BL label: branch with link (26-bit range).
    fn bl(&mut self, target: Label) {
        let offset = self.pos();
        self.emit32(0x94000000); // placeholder
        self.fixups.push(Fixup {
            offset,
            label: target.0,
            kind: FixupKind::Branch26,
        });
    }

    /// CBZ Wn, label: compare and branch if zero (32-bit register).
    fn cbz_w(&mut self, rt: u8, target: Label) {
        let offset = self.pos();
        // 0 011010 0 imm19(placeholder) Rt
        let insn = 0x34000000 | (rt as u32);
        self.emit32(insn);
        self.fixups.push(Fixup {
            offset,
            label: target.0,
            kind: FixupKind::Cbz,
        });
    }

    /// CBNZ Xn, label: compare and branch if nonzero (64-bit register).
    fn cbnz_x(&mut self, rt: u8, target: Label) {
        let offset = self.pos();
        // 1 011010 1 imm19(placeholder) Rt
        let insn = 0xB5000000 | (rt as u32);
        self.emit32(insn);
        self.fixups.push(Fixup {
            offset,
            label: target.0,
            kind: FixupKind::Cbz, // same encoding layout as cbz
        });
    }

    /// ADR Xd, label: PC-relative address (21-bit range).
    fn adr(&mut self, rd: u8, target: Label) {
        let offset = self.pos();
        // immlo(2) 10000 immhi(19) Rd(5): placeholder all zero
        let insn = 0x10000000 | (rd as u32);
        self.emit32(insn);
        self.fixups.push(Fixup {
            offset,
            label: target.0,
            kind: FixupKind::Adr,
        });
    }

    /// Resolve all fixups and return the final machine code.
    fn finish(mut self) -> Vec<u8> {
        for fixup in &self.fixups {
            let target = self.labels[fixup.label]
                .unwrap_or_else(|| panic!("unresolved label {}", fixup.label));
            let pc = fixup.offset; // PC of the instruction being patched
            let rel = target as isize - pc as isize;

            let mut insn = u32::from_le_bytes(self.code[pc..pc + 4].try_into().unwrap());

            match fixup.kind {
                FixupKind::BCond | FixupKind::Cbz => {
                    // 19-bit signed offset in units of 4 bytes, at bits [23:5]
                    assert!(rel % 4 == 0, "branch target not aligned");
                    let imm19 = rel / 4;
                    assert!(
                        (-262144..=262143).contains(&imm19),
                        "b.cond/cbz offset out of range"
                    );
                    insn |= ((imm19 as u32) & 0x7FFFF) << 5;
                }
                FixupKind::Branch26 => {
                    // 26-bit signed offset in units of 4 bytes, at bits [25:0]
                    assert!(rel % 4 == 0, "branch target not aligned");
                    let imm26 = rel / 4;
                    assert!(
                        (-33554432..=33554431).contains(&imm26),
                        "b/bl offset out of range"
                    );
                    insn |= (imm26 as u32) & 0x3FFFFFF;
                }
                FixupKind::Adr => {
                    // 21-bit signed byte offset: immlo at [30:29], immhi at [23:5]
                    assert!(
                        (-1048576..=1048575).contains(&rel),
                        "adr offset out of range"
                    );
                    let imm = rel as u32;
                    let immlo = imm & 3;
                    let immhi = (imm >> 2) & 0x7FFFF;
                    insn |= (immlo << 29) | (immhi << 5);
                }
            }

            self.code[pc..pc + 4].copy_from_slice(&insn.to_le_bytes());
        }
        self.code
    }
}

// Condition codes for b.cond
const COND_LT: u8 = 0b1011; // signed less than
const COND_HI: u8 = 0b1000; // unsigned higher

// Register aliases
const X0: u8 = 0;
const X1: u8 = 1;
const X2: u8 = 2;
const X8: u8 = 8;
const X9: u8 = 9;
const X10: u8 = 10;
const X11: u8 = 11;
const X19: u8 = 19;
const X20: u8 = 20;
const X21: u8 = 21;
const X22: u8 = 22;
const SP: u8 = 31;

/// Generate the complete aarch64 machine code for drop_privs.
pub fn generate() -> Vec<u8> {
    let mut a = Asm::new();

    // Forward-declare labels
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

    // ldr x19, [sp, #0]               ; x19 = argc
    a.ldr_x(X19, SP, 0);

    // add x20, sp, #8                 ; x20 = &argv[0]
    a.add_x_imm(X20, SP, 8);

    // cmp x19, #5                     ; argc >= 5?
    a.cmp_x_imm(X19, 5);

    // b.lt usage_error
    a.b_cond(COND_LT, usage_error);

    // --- Parse UID (argv[1]) ---
    // ldr x0, [x20, #8]               ; argv[1]
    a.ldr_x(X0, X20, 8);
    // bl atoi
    a.bl(atoi);
    // mov x21, x0                     ; x21 = uid
    a.mov_x(X21, X0);

    // --- Parse GID (argv[2]) ---
    // ldr x0, [x20, #16]              ; argv[2]
    a.ldr_x(X0, X20, 16);
    // bl atoi
    a.bl(atoi);
    // mov x22, x0                     ; x22 = gid
    a.mov_x(X22, X0);

    // --- setgroups(0, NULL) ---
    a.movz_x(X8, SYS_SETGROUPS);
    a.movz_x(X0, 0);
    a.movz_x(X1, 0);
    a.svc();
    a.cmp_x_imm(X0, 0);
    a.b_cond(COND_LT, err_setgroups);

    // --- setgid(gid) ---
    a.movz_x(X8, SYS_SETGID);
    a.mov_x(X0, X22);
    a.svc();
    a.cmp_x_imm(X0, 0);
    a.b_cond(COND_LT, err_setgid);

    // --- setuid(uid) ---
    a.movz_x(X8, SYS_SETUID);
    a.mov_x(X0, X21);
    a.svc();
    a.cmp_x_imm(X0, 0);
    a.b_cond(COND_LT, err_setuid);

    // --- chdir(argv[3]) ---
    a.movz_x(X8, SYS_CHDIR);
    a.ldr_x(X0, X20, 24); // argv[3]
    a.svc();
    a.cmp_x_imm(X0, 0);
    a.b_cond(COND_LT, err_chdir);

    // --- execve(argv[4], &argv[4..], envp) ---
    a.ldr_x(X0, X20, 32); // filename = argv[4]
    a.add_x_imm(X1, X20, 32); // argv = &argv[4..]
                              // envp = &argv[0] + (argc + 1) * 8 = x20 + (x19 + 1) << 3
    a.add_x_imm(X2, X19, 1); // x2 = argc + 1
    a.lsl_x(X2, X2, 3); // x2 = (argc + 1) * 8
    a.add_x_reg(X2, X20, X2); // x2 = envp
    a.movz_x(X8, SYS_EXECVE);
    a.svc();
    // execve only returns on error; fall through

    // ========== Error handlers ==========

    a.bind(err_execve);
    a.adr(X1, lbl_msg_execve);
    a.movz_x(X2, MSG_EXECVE.len() as u16);
    a.b(error_exit);

    a.bind(err_setgroups);
    a.adr(X1, lbl_msg_setgroups);
    a.movz_x(X2, MSG_SETGROUPS.len() as u16);
    a.b(error_exit);

    a.bind(err_setgid);
    a.adr(X1, lbl_msg_setgid);
    a.movz_x(X2, MSG_SETGID.len() as u16);
    a.b(error_exit);

    a.bind(err_setuid);
    a.adr(X1, lbl_msg_setuid);
    a.movz_x(X2, MSG_SETUID.len() as u16);
    a.b(error_exit);

    a.bind(err_chdir);
    a.adr(X1, lbl_msg_chdir);
    a.movz_x(X2, MSG_CHDIR.len() as u16);
    a.b(error_exit);

    a.bind(usage_error);
    a.adr(X1, lbl_msg_usage);
    a.movz_x(X2, MSG_USAGE.len() as u16);
    // fall through to error_exit

    // ========== error_exit: write(2, x1, x2) then exit(1) ==========

    a.bind(error_exit);
    a.movz_x(X8, SYS_WRITE);
    a.movz_x(X0, 2); // stderr
    a.svc();
    a.movz_x(X8, SYS_EXIT);
    a.movz_x(X0, 1);
    a.svc();

    // ========== atoi subroutine ==========
    // Input: x0 = pointer to null-terminated ASCII decimal string
    // Output: x0 = parsed value (guaranteed to fit in u32)
    // Clobbers: x9, x10, x11
    // On bad input or overflow: branches to error_exit (does not return)

    a.bind(atoi);
    a.mov_x(X9, X0); // x9 = string pointer
    a.movz_x(X0, 0); // x0 = result = 0

    // Load first byte, check for empty string
    a.ldrb_w(X10, X9, 0);
    a.cbz_w(X10, atoi_error);

    a.bind(atoi_loop);

    // sub w10, w10, #'0'
    a.sub_w_imm(X10, X10, 0x30);

    // cmp w10, #9 (unsigned: catches both < '0' and > '9')
    a.cmp_w_imm(X10, 9);

    // b.hi atoi_error
    a.b_cond(COND_HI, atoi_error);

    // result = result * 10 + digit
    a.movz_x(X11, 10);
    a.mul_x(X0, X0, X11);
    // x10 was written as w10 by sub_w_imm, so upper 32 bits are zeroed
    a.add_x_reg(X0, X0, X10);

    // Advance pointer, load next byte
    a.add_x_imm(X9, X9, 1);
    a.ldrb_w(X10, X9, 0);
    // If not zero, loop
    let atoi_continue = a.label();
    a.cbz_w(X10, atoi_continue);
    a.b(atoi_loop);

    a.bind(atoi_continue);

    // --- Overflow check: reject values > u32 max (4294967295) ---
    // UIDs/GIDs are u32. A crafted input like "99999999999999999999" would
    // silently wrap and could land on UID 0 (root), defeating the purpose
    // of privilege dropping.
    //
    // lsr x11, x0, #32               ; x11 = upper 32 bits of result
    a.lsr_x(X11, X0, 32);
    // cbnz x11, atoi_error            ; if any upper bit set, overflow
    a.cbnz_x(X11, atoi_error);

    a.ret();

    // atoi_error: bad number
    a.bind(atoi_error);
    a.adr(X1, lbl_msg_number);
    a.movz_x(X2, MSG_NUMBER.len() as u16);
    a.b(error_exit);

    // ========== String data ==========
    // Data is placed after all code. adr instructions reference it.

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
        assert!(code.len() > 100, "code too small: {} bytes", code.len());
        assert!(code.len() < 1024, "code too large: {} bytes", code.len());
    }

    #[test]
    fn code_is_4byte_aligned() {
        let code = generate();
        assert_eq!(code.len() % 4, 0, "code must be 4-byte aligned");
    }

    #[test]
    fn code_starts_with_ldr_x19_sp() {
        let code = generate();
        // ldr x19, [sp, #0] = 0xF94003F3
        let first = u32::from_le_bytes(code[0..4].try_into().unwrap());
        assert_eq!(first, 0xF94003F3, "expected ldr x19, [sp]");
    }

    #[test]
    fn code_contains_svc_instructions() {
        let code = generate();
        // svc #0 = 0xD4000001
        let count = code
            .chunks_exact(4)
            .filter(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]) == 0xD4000001)
            .count();
        // setgroups, setgid, setuid, chdir, execve, write, exit = 7
        assert_eq!(count, 7, "expected 7 svc instructions");
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
        // It uses lsr x11, x0, #32 to extract upper 32 bits, then
        // cbnz x11, atoi_error. The lsr #32 encodes as UBFM with
        // immr=32, imms=63.
        let code = generate();
        let insns: Vec<u32> = code
            .chunks_exact(4)
            .map(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]))
            .collect();
        // lsr x11, x0, #32 = UBFM x11, x0, #32, #63
        // 1 10 100110 1 100000(32) 111111(63) 00000(x0) 01011(x11)
        let expected_lsr = 0xD360FC0B;
        assert!(
            insns.contains(&expected_lsr),
            "missing lsr x11, x0, #32 overflow guard in atoi"
        );
        // cbnz x11 should appear somewhere after it
        let has_cbnz = insns
            .iter()
            .any(|&i| (i & 0xFF000000) == 0xB5000000 && (i & 0x1F) == X11 as u32);
        assert!(has_cbnz, "missing cbnz x11 overflow guard in atoi");
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
