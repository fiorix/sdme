// aarch64.rs: Machine code emitter for the devfd shim shared library (aarch64)
//
// Emits raw AArch64 machine code that intercepts open()/openat() libc calls.
// Same logic as x86_64.rs but using the AArch64 calling convention and syscall ABI.
//
// Linux aarch64 syscall ABI:
//   x8 = syscall number
//   x0-x5 = arguments
//   svc #0; return in x0
//
// C calling convention (AAPCS64):
//   x0-x7 = arguments
//   x0 = return value
//
// openat(int dirfd, const char *path, int flags, mode_t mode)
//   → x0=dirfd, x1=path, x2=flags, x3=mode
//
// open(const char *path, int flags, mode_t mode)
//   → x0=path, x1=flags, x2=mode

// Syscall numbers (aarch64)
const SYS_DUP: u16 = 23;
const SYS_OPENAT: u16 = 56;

use super::elf;

/// Label index for forward/backward references.
#[derive(Clone, Copy)]
struct Label(usize);

enum FixupKind {
    /// b.cond / cbz / cbnz: 19-bit signed offset (in 4-byte units) at bits [23:5]
    BCond,
    /// b / bl: 26-bit signed offset (in 4-byte units) at bits [25:0]
    Branch26,
}

struct Fixup {
    offset: usize,
    label: usize,
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

    // ---- AArch64 instruction emitters ----

    /// LDR Xt, [Xn, #imm] --64-bit load, unsigned offset (imm must be multiple of 8).
    fn ldr_x(&mut self, rt: u8, rn: u8, imm: u16) {
        assert!(imm.is_multiple_of(8) && imm <= 32760);
        let imm12 = (imm / 8) as u32;
        let insn = 0xF9400000 | (imm12 << 10) | ((rn as u32) << 5) | (rt as u32);
        self.emit32(insn);
    }

    /// LDR Wt, [Xn, #imm] --32-bit load, unsigned offset (imm must be multiple of 4).
    fn ldr_w(&mut self, rt: u8, rn: u8, imm: u16) {
        assert!(imm.is_multiple_of(4) && imm <= 16380);
        let imm12 = (imm / 4) as u32;
        let insn = 0xB9400000 | (imm12 << 10) | ((rn as u32) << 5) | (rt as u32);
        self.emit32(insn);
    }

    /// LDRH Wt, [Xn, #imm] --16-bit load, unsigned offset (imm must be multiple of 2).
    fn ldrh_w(&mut self, rt: u8, rn: u8, imm: u16) {
        assert!(imm.is_multiple_of(2) && imm <= 8190);
        let imm12 = (imm / 2) as u32;
        let insn = 0x79400000 | (imm12 << 10) | ((rn as u32) << 5) | (rt as u32);
        self.emit32(insn);
    }

    /// MOV Xd, Xm --register move (alias for ORR Xd, XZR, Xm).
    fn mov_x(&mut self, rd: u8, rm: u8) {
        let insn = 0xAA0003E0 | ((rm as u32) << 16) | (rd as u32);
        self.emit32(insn);
    }

    /// MOVZ Xd, #imm16 --move 16-bit immediate, zero rest.
    fn movz_x(&mut self, rd: u8, imm: u16) {
        let insn = 0xD2800000 | ((imm as u32) << 5) | (rd as u32);
        self.emit32(insn);
    }

    /// MOVZ Wd, #imm16 --32-bit move immediate, zero rest.
    fn movz_w(&mut self, rd: u8, imm: u16) {
        let insn = 0x52800000 | ((imm as u32) << 5) | (rd as u32);
        self.emit32(insn);
    }

    /// MOVK Xd, #imm16, LSL #shift --move 16-bit immediate into position, keep rest.
    fn movk_x(&mut self, rd: u8, imm: u16, shift: u8) {
        assert!(shift == 0 || shift == 16 || shift == 32 || shift == 48);
        let hw = (shift / 16) as u32;
        let insn = 0xF2800000 | (hw << 21) | ((imm as u32) << 5) | (rd as u32);
        self.emit32(insn);
    }

    /// MOVK Wd, #imm16, LSL #shift --32-bit move keep.
    fn movk_w(&mut self, rd: u8, imm: u16, shift: u8) {
        assert!(shift == 0 || shift == 16);
        let hw = (shift / 16) as u32;
        let insn = 0x72800000 | (hw << 21) | ((imm as u32) << 5) | (rd as u32);
        self.emit32(insn);
    }

    /// MOVN Xd, #imm16 --move wide with NOT (for loading negative values).
    fn movn_x(&mut self, rd: u8, imm: u16) {
        let insn = 0x92800000 | ((imm as u32) << 5) | (rd as u32);
        self.emit32(insn);
    }

    /// CMP Xn, Xm --compare registers (alias for SUBS XZR, Xn, Xm).
    fn cmp_x_reg(&mut self, rn: u8, rm: u8) {
        let insn = 0xEB00001F | ((rm as u32) << 16) | ((rn as u32) << 5);
        self.emit32(insn);
    }

    /// CMP Wn, Wm --32-bit compare registers.
    fn cmp_w_reg(&mut self, rn: u8, rm: u8) {
        let insn = 0x6B00001F | ((rm as u32) << 16) | ((rn as u32) << 5);
        self.emit32(insn);
    }

    /// AND Wd, Wn, #imm --32-bit AND with bitmask immediate.
    /// Only supports the specific pattern 0x00FFFFFF (N=0, immr=0, imms=23 for 32-bit).
    fn and_w_imm_24bit(&mut self, rd: u8, rn: u8) {
        // Logical immediate encoding for 32-bit AND with 0x00FFFFFF:
        //   sf=0, opc=00, 100100, N=0, immr=0b000000, imms=0b010111 (23)
        //   24 consecutive 1-bits at bit 0 with no rotation.
        let insn = 0x12005C00 | ((rn as u32) << 5) | (rd as u32);
        self.emit32(insn);
    }

    /// SVC #0 --supervisor call (syscall).
    fn svc(&mut self) {
        self.emit32(0xD4000001);
    }

    /// RET --return via X30.
    fn ret(&mut self) {
        self.emit32(0xD65F03C0);
    }

    /// B.cond label --conditional branch.
    fn b_cond(&mut self, cond: u8, target: Label) {
        let offset = self.pos();
        let insn = 0x54000000 | (cond as u32);
        self.emit32(insn);
        self.fixups.push(Fixup {
            offset,
            label: target.0,
            kind: FixupKind::BCond,
        });
    }

    /// B label --unconditional branch.
    fn b(&mut self, target: Label) {
        let offset = self.pos();
        self.emit32(0x14000000);
        self.fixups.push(Fixup {
            offset,
            label: target.0,
            kind: FixupKind::Branch26,
        });
    }

    fn finish(mut self) -> Vec<u8> {
        for fixup in &self.fixups {
            let target = self.labels[fixup.label]
                .unwrap_or_else(|| panic!("unresolved label {}", fixup.label));
            let pc = fixup.offset;
            let rel = target as isize - pc as isize;

            let mut insn = u32::from_le_bytes(self.code[pc..pc + 4].try_into().unwrap());

            match fixup.kind {
                FixupKind::BCond => {
                    assert!(rel % 4 == 0, "branch target not aligned");
                    let imm19 = rel / 4;
                    assert!(
                        (-262144..=262143).contains(&imm19),
                        "b.cond offset out of range"
                    );
                    insn |= ((imm19 as u32) & 0x7FFFF) << 5;
                }
                FixupKind::Branch26 => {
                    assert!(rel % 4 == 0, "branch target not aligned");
                    let imm26 = rel / 4;
                    assert!(
                        (-33554432..=33554431).contains(&imm26),
                        "b offset out of range"
                    );
                    insn |= (imm26 as u32) & 0x3FFFFFF;
                }
            }

            self.code[pc..pc + 4].copy_from_slice(&insn.to_le_bytes());
        }
        self.code
    }
}

// Condition codes
const COND_EQ: u8 = 0b0000;
const COND_NE: u8 = 0b0001;

// Register aliases
const X0: u8 = 0;
const X1: u8 = 1;
const X2: u8 = 2;
const X3: u8 = 3;
const X4: u8 = 4; // scratch for path pointer
const X5: u8 = 5; // scratch for 8-byte loads
const X6: u8 = 6; // scratch for comparisons
const X7: u8 = 7; // scratch
const X8: u8 = 8; // syscall number

/// Load a 64-bit immediate into a register using MOVZ + MOVK sequence.
fn load_imm64(a: &mut Asm, rd: u8, val: u64) {
    a.movz_x(rd, val as u16);
    if val >> 16 != 0 {
        a.movk_x(rd, (val >> 16) as u16, 16);
    }
    if val >> 32 != 0 {
        a.movk_x(rd, (val >> 32) as u16, 32);
    }
    if val >> 48 != 0 {
        a.movk_x(rd, (val >> 48) as u16, 48);
    }
}

/// Load a 32-bit immediate into a 32-bit register.
fn load_imm32(a: &mut Asm, rd: u8, val: u32) {
    a.movz_w(rd, val as u16);
    if val >> 16 != 0 {
        a.movk_w(rd, (val >> 16) as u16, 16);
    }
}

/// Generate the aarch64 machine code and symbol table for the devfd shim.
pub fn generate() -> (Vec<u8>, Vec<elf::Symbol>) {
    let mut a = Asm::new();

    // Forward-declare labels
    let do_openat = a.label();
    let fallthrough = a.label();
    let do_dup = a.label();
    let check_dev_fd = a.label();
    let check_proc = a.label();
    let dup_fd0 = a.label();
    let dup_fd1 = a.label();
    let dup_fd2 = a.label();

    // ========== open(path, flags, mode) ==========
    // C ABI in: x0=path, x1=flags, x2=mode
    // Rewrite to: x0=AT_FDCWD, x1=path, x2=flags, x3=mode
    let open_offset = a.pos();

    // mov x3, x2              ; mode → 4th arg
    a.mov_x(X3, X2);
    // mov x2, x1              ; flags → 3rd arg
    a.mov_x(X2, X1);
    // mov x1, x0              ; path → 2nd arg
    a.mov_x(X1, X0);
    // movn x0, #99            ; AT_FDCWD = -100 = ~99
    a.movn_x(X0, 99);
    // b do_openat
    a.b(do_openat);

    // ========== openat(dirfd, path, flags, mode) ==========
    // C ABI in: x0=dirfd, x1=path, x2=flags, x3=mode
    let openat_offset = a.pos();
    a.bind(do_openat);

    // Save path pointer to a scratch register
    // mov x4, x1              ; x4 = path
    a.mov_x(X4, X1);

    // Load first 8 bytes of path
    // ldr x5, [x4]            ; x5 = *(uint64_t*)path
    a.ldr_x(X5, X4, 0);

    // ---- Check "/dev/std" prefix ----
    load_imm64(&mut a, X6, u64::from_le_bytes(*b"/dev/std"));
    a.cmp_x_reg(X5, X6);
    a.b_cond(COND_NE, check_dev_fd);

    // Matched "/dev/std" --check suffix at path[8]
    // ldr w7, [x4, #8]        ; w7 = *(uint32_t*)(path+8)
    a.ldr_w(X7, X4, 8);

    // Check "in\0" --mask to 24 bits
    a.and_w_imm_24bit(X6, X7);
    load_imm32(&mut a, X5, u32::from_le_bytes([b'i', b'n', 0, 0]));
    a.cmp_w_reg(X6, X5);
    a.b_cond(COND_EQ, dup_fd0);

    // Check "out\0"
    load_imm32(&mut a, X5, u32::from_le_bytes(*b"out\0"));
    a.cmp_w_reg(X7, X5);
    a.b_cond(COND_EQ, dup_fd1);

    // Check "err\0"
    load_imm32(&mut a, X5, u32::from_le_bytes(*b"err\0"));
    a.cmp_w_reg(X7, X5);
    a.b_cond(COND_EQ, dup_fd2);

    // No match
    a.b(fallthrough);

    // ---- Check "/dev/fd/" prefix ----
    a.bind(check_dev_fd);

    // Reload first 8 bytes (x5 was clobbered)
    a.ldr_x(X5, X4, 0);
    load_imm64(&mut a, X6, u64::from_le_bytes(*b"/dev/fd/"));
    a.cmp_x_reg(X5, X6);
    a.b_cond(COND_NE, check_proc);

    // Matched "/dev/fd/" --check path[8..10] for "0\0", "1\0", "2\0"
    // ldrh w7, [x4, #8]       ; w7 = *(uint16_t*)(path+8)
    a.ldrh_w(X7, X4, 8);

    load_imm32(&mut a, X5, u32::from(u16::from_le_bytes([b'0', 0])));
    a.cmp_w_reg(X7, X5);
    a.b_cond(COND_EQ, dup_fd0);

    load_imm32(&mut a, X5, u32::from(u16::from_le_bytes([b'1', 0])));
    a.cmp_w_reg(X7, X5);
    a.b_cond(COND_EQ, dup_fd1);

    load_imm32(&mut a, X5, u32::from(u16::from_le_bytes([b'2', 0])));
    a.cmp_w_reg(X7, X5);
    a.b_cond(COND_EQ, dup_fd2);

    a.b(fallthrough);

    // ---- Check "/proc/se" prefix ----
    a.bind(check_proc);

    // Reload (x5 was clobbered)
    a.ldr_x(X5, X4, 0);
    load_imm64(&mut a, X6, u64::from_le_bytes(*b"/proc/se"));
    a.cmp_x_reg(X5, X6);
    a.b_cond(COND_NE, fallthrough);

    // Matched "/proc/se" --check suffix "lf/fd/0\0" etc. at path[8]
    a.ldr_x(X5, X4, 8);

    load_imm64(&mut a, X6, u64::from_le_bytes(*b"lf/fd/0\0"));
    a.cmp_x_reg(X5, X6);
    a.b_cond(COND_EQ, dup_fd0);

    load_imm64(&mut a, X6, u64::from_le_bytes(*b"lf/fd/1\0"));
    a.cmp_x_reg(X5, X6);
    a.b_cond(COND_EQ, dup_fd1);

    load_imm64(&mut a, X6, u64::from_le_bytes(*b"lf/fd/2\0"));
    a.cmp_x_reg(X5, X6);
    a.b_cond(COND_EQ, dup_fd2);

    a.b(fallthrough);

    // ========== dup(N) handlers ==========
    a.bind(dup_fd0);
    a.movz_x(X0, 0); // fd = 0
    a.b(do_dup);

    a.bind(dup_fd1);
    a.movz_x(X0, 1); // fd = 1
    a.b(do_dup);

    a.bind(dup_fd2);
    a.movz_x(X0, 2); // fd = 2
    // fall through to do_dup

    // ========== do_dup: syscall(SYS_dup, fd_in_x0) ==========
    a.bind(do_dup);
    a.movz_x(X8, SYS_DUP);
    a.svc();
    a.ret();

    // ========== fallthrough: real openat syscall ==========
    a.bind(fallthrough);
    // Arguments: x0=dirfd, x1=path (in x4, need to restore), x2=flags, x3=mode
    // Restore x1 from x4 (path pointer was saved there)
    a.mov_x(X1, X4);
    a.movz_x(X8, SYS_OPENAT);
    a.svc();
    a.ret();

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
            offset: open_offset,
        },
        elf::Symbol {
            name: "openat64",
            offset: openat_offset,
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
    fn code_is_4byte_aligned() {
        let (code, _) = generate();
        assert_eq!(code.len() % 4, 0, "code must be 4-byte aligned");
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
    fn code_contains_two_svc_instructions() {
        let (code, _) = generate();
        let count = code
            .chunks_exact(4)
            .filter(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]) == 0xD4000001)
            .count();
        // SYS_dup + SYS_openat = 2
        assert_eq!(count, 2, "expected 2 svc instructions, got {count}");
    }
}
