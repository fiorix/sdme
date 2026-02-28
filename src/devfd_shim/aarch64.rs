// aarch64.rs: Machine code emitter for the devfd shim shared library (aarch64)
//
// Emits raw AArch64 machine code that intercepts open()/openat() libc calls.
// Same logic as x86_64.rs but using the AArch64 calling convention and syscall ABI.
//
// If the real openat returns ENXIO, the shim uses readlinkat to resolve
// one level of symlink and retries the path matching. This handles cases
// like nginx opening /var/log/nginx/error.log -> /dev/stderr.
//
// On error, errno is set via __errno_location() (imported through the GOT)
// and -1 is returned per C convention.
//
// Linux aarch64 syscall ABI:
//   x8 = syscall number
//   x0-x5 = arguments
//   svc #0; return in x0
//   Preserved across syscall: x1-x7 (kernel preserves all except x0)
//
// C calling convention (AAPCS64):
//   x0-x7 = arguments
//   x0 = return value
//   x9-x15 = caller-saved temporaries (but preserved by kernel across svc)
//   x19-x28 = callee-saved
//   x30 = link register (clobbered by bl/blr)
//
// openat(int dirfd, const char *path, int flags, mode_t mode)
//   -> x0=dirfd, x1=path, x2=flags, x3=mode
//
// open(const char *path, int flags, mode_t mode)
//   -> x0=path, x1=flags, x2=mode

// Syscall numbers (aarch64)
const SYS_DUP: u16 = 23;
const SYS_OPENAT: u16 = 56;
const SYS_READLINKAT: u16 = 78;

// errno value
const ENXIO: u16 = 6;

// readlink buffer size (must be multiple of 16 for stack alignment)
const READLINK_BUFSZ: u16 = 128;

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
            code: Vec::with_capacity(1024),
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

    /// LDR Xt, [Xn, #imm] -- 64-bit load, unsigned offset (imm must be multiple of 8).
    fn ldr_x(&mut self, rt: u8, rn: u8, imm: u16) {
        assert!(imm.is_multiple_of(8) && imm <= 32760);
        let imm12 = (imm / 8) as u32;
        let insn = 0xF9400000 | (imm12 << 10) | ((rn as u32) << 5) | (rt as u32);
        self.emit32(insn);
    }

    /// LDR Wt, [Xn, #imm] -- 32-bit load, unsigned offset (imm must be multiple of 4).
    fn ldr_w(&mut self, rt: u8, rn: u8, imm: u16) {
        assert!(imm.is_multiple_of(4) && imm <= 16380);
        let imm12 = (imm / 4) as u32;
        let insn = 0xB9400000 | (imm12 << 10) | ((rn as u32) << 5) | (rt as u32);
        self.emit32(insn);
    }

    /// LDRH Wt, [Xn, #imm] -- 16-bit load, unsigned offset (imm must be multiple of 2).
    fn ldrh_w(&mut self, rt: u8, rn: u8, imm: u16) {
        assert!(imm.is_multiple_of(2) && imm <= 8190);
        let imm12 = (imm / 2) as u32;
        let insn = 0x79400000 | (imm12 << 10) | ((rn as u32) << 5) | (rt as u32);
        self.emit32(insn);
    }

    /// STRB Wt, [Xn, Xm] -- store byte, register offset.
    fn strb_reg(&mut self, rt: u8, rn: u8, rm: u8) {
        // STRB Wt, [Xn, Xm] = 0x38206800 | Rm<<16 | Rn<<5 | Rt
        let insn = 0x38206800 | ((rm as u32) << 16) | ((rn as u32) << 5) | (rt as u32);
        self.emit32(insn);
    }

    /// STR Wt, [Xn, #imm] -- 32-bit store, unsigned offset (imm must be multiple of 4).
    fn str_w(&mut self, rt: u8, rn: u8, imm: u16) {
        assert!(imm.is_multiple_of(4) && imm <= 16380);
        let imm12 = (imm / 4) as u32;
        let insn = 0xB9000000 | (imm12 << 10) | ((rn as u32) << 5) | (rt as u32);
        self.emit32(insn);
    }

    /// MOV Xd, Xm -- register move (alias for ORR Xd, XZR, Xm).
    fn mov_x(&mut self, rd: u8, rm: u8) {
        let insn = 0xAA0003E0 | ((rm as u32) << 16) | (rd as u32);
        self.emit32(insn);
    }

    /// MOV Xd, SP -- read stack pointer into Xd (ADD Xd, SP, #0).
    fn mov_x_sp(&mut self, rd: u8) {
        // ADD Xd, SP, #0: 0x910003E0 | Rd
        let insn = 0x910003E0 | (rd as u32);
        self.emit32(insn);
    }

    /// MOVZ Xd, #imm16 -- move 16-bit immediate, zero rest.
    fn movz_x(&mut self, rd: u8, imm: u16) {
        let insn = 0xD2800000 | ((imm as u32) << 5) | (rd as u32);
        self.emit32(insn);
    }

    /// MOVZ Wd, #imm16 -- 32-bit move immediate, zero rest.
    fn movz_w(&mut self, rd: u8, imm: u16) {
        let insn = 0x52800000 | ((imm as u32) << 5) | (rd as u32);
        self.emit32(insn);
    }

    /// MOVK Xd, #imm16, LSL #shift -- move 16-bit immediate into position, keep rest.
    fn movk_x(&mut self, rd: u8, imm: u16, shift: u8) {
        assert!(shift == 0 || shift == 16 || shift == 32 || shift == 48);
        let hw = (shift / 16) as u32;
        let insn = 0xF2800000 | (hw << 21) | ((imm as u32) << 5) | (rd as u32);
        self.emit32(insn);
    }

    /// MOVK Wd, #imm16, LSL #shift -- 32-bit move keep.
    fn movk_w(&mut self, rd: u8, imm: u16, shift: u8) {
        assert!(shift == 0 || shift == 16);
        let hw = (shift / 16) as u32;
        let insn = 0x72800000 | (hw << 21) | ((imm as u32) << 5) | (rd as u32);
        self.emit32(insn);
    }

    /// MOVN Xd, #imm16 -- move wide with NOT (for loading negative values).
    fn movn_x(&mut self, rd: u8, imm: u16) {
        let insn = 0x92800000 | ((imm as u32) << 5) | (rd as u32);
        self.emit32(insn);
    }

    /// CMP Xn, Xm -- compare registers (alias for SUBS XZR, Xn, Xm).
    fn cmp_x_reg(&mut self, rn: u8, rm: u8) {
        let insn = 0xEB00001F | ((rm as u32) << 16) | ((rn as u32) << 5);
        self.emit32(insn);
    }

    /// CMP Wn, Wm -- 32-bit compare registers.
    fn cmp_w_reg(&mut self, rn: u8, rm: u8) {
        let insn = 0x6B00001F | ((rm as u32) << 16) | ((rn as u32) << 5);
        self.emit32(insn);
    }

    /// CMP Xn, #imm12 -- compare with unsigned immediate.
    fn cmp_x_imm(&mut self, rn: u8, imm: u16) {
        assert!(imm < 4096);
        // SUBS XZR, Xn, #imm: 0xF100001F | (imm12 << 10) | (Rn << 5)
        let insn = 0xF100001F | ((imm as u32) << 10) | ((rn as u32) << 5);
        self.emit32(insn);
    }

    /// NEG Xd, Xn -- negate register (alias for SUB Xd, XZR, Xn).
    fn neg_x(&mut self, rd: u8, rn: u8) {
        let insn = 0xCB0003E0 | ((rn as u32) << 16) | (rd as u32);
        self.emit32(insn);
    }

    /// AND Wd, Wn, #imm -- 32-bit AND with bitmask immediate.
    /// Only supports the specific pattern 0x00FFFFFF (N=0, immr=0, imms=23 for 32-bit).
    fn and_w_imm_24bit(&mut self, rd: u8, rn: u8) {
        let insn = 0x12005C00 | ((rn as u32) << 5) | (rd as u32);
        self.emit32(insn);
    }

    /// STP Xt1, Xt2, [SP, #-imm]! -- store pair, pre-index (push to stack).
    fn stp_pre(&mut self, rt1: u8, rt2: u8, imm: i16) {
        assert!(imm % 8 == 0 && (-512..=504).contains(&imm));
        let imm7 = ((imm / 8) as u32) & 0x7F;
        let insn = 0xA9800000 | (imm7 << 15) | ((rt2 as u32) << 10) | (31 << 5) | (rt1 as u32);
        self.emit32(insn);
    }

    /// LDP Xt1, Xt2, [SP], #imm -- load pair, post-index (pop from stack).
    fn ldp_post(&mut self, rt1: u8, rt2: u8, imm: i16) {
        assert!(imm % 8 == 0 && (-512..=504).contains(&imm));
        let imm7 = ((imm / 8) as u32) & 0x7F;
        let insn = 0xA8C00000 | (imm7 << 15) | ((rt2 as u32) << 10) | (31 << 5) | (rt1 as u32);
        self.emit32(insn);
    }

    /// SUB SP, SP, #imm -- subtract immediate from stack pointer.
    fn sub_sp_imm(&mut self, imm: u16) {
        assert!(imm < 4096);
        // SUB SP, SP, #imm: 0xD10003FF | (imm12 << 10)
        let insn = 0xD10003FF | ((imm as u32) << 10);
        self.emit32(insn);
    }

    /// ADD SP, SP, #imm -- add immediate to stack pointer.
    fn add_sp_imm(&mut self, imm: u16) {
        assert!(imm < 4096);
        // ADD SP, SP, #imm: 0x910003FF | (imm12 << 10)
        let insn = 0x910003FF | ((imm as u32) << 10);
        self.emit32(insn);
    }

    /// ADRP Xd, #0 -- placeholder, to be patched by ELF builder with page offset.
    fn adrp(&mut self, rd: u8) -> usize {
        let pos = self.pos();
        // ADRP: 1 immlo[30:29] 10000 immhi[23:5] Rd[4:0]
        // With imm=0: 0x90000000 | Rd
        let insn = 0x90000000 | (rd as u32);
        self.emit32(insn);
        pos
    }

    /// LDR Xt, [Xn, #0] -- placeholder for GOT load, offset patched by ELF builder.
    fn ldr_x_got_placeholder(&mut self, rt: u8, rn: u8) -> usize {
        let pos = self.pos();
        // LDR Xt, [Xn, #0]: 0xF9400000 | (Rn << 5) | Rt, imm12=0
        let insn = 0xF9400000 | ((rn as u32) << 5) | (rt as u32);
        self.emit32(insn);
        pos
    }

    /// BLR Xn -- branch with link to register.
    fn blr(&mut self, rn: u8) {
        let insn = 0xD63F0000 | ((rn as u32) << 5);
        self.emit32(insn);
    }

    /// SVC #0 -- supervisor call (syscall).
    fn svc(&mut self) {
        self.emit32(0xD4000001);
    }

    /// RET -- return via X30.
    fn ret(&mut self) {
        self.emit32(0xD65F03C0);
    }

    /// B.cond label -- conditional branch.
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

    /// B label -- unconditional branch.
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
const COND_GE: u8 = 0b1010;
const COND_LT: u8 = 0b1011;

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
const X9: u8 = 9; // saved dirfd / GOT pointer
const X10: u8 = 10; // saved flags
const X11: u8 = 11; // saved mode
const X19: u8 = 19; // callee-saved: errno value across blr
const X30: u8 = 30; // link register
const WZR: u8 = 31; // zero register (when used as source in W context)

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

/// Emit the path-matching logic for a given path pointer register.
/// On match, branches to the appropriate dup label.
/// On no match, branches to `no_match`.
fn emit_path_match(
    a: &mut Asm,
    path_reg: u8,
    dup_fd0: Label,
    dup_fd1: Label,
    dup_fd2: Label,
    no_match: Label,
) {
    let check_dev_fd = a.label();
    let check_proc = a.label();

    // Load first 8 bytes of path
    a.ldr_x(X5, path_reg, 0);

    // ---- Check "/dev/std" prefix ----
    load_imm64(a, X6, u64::from_le_bytes(*b"/dev/std"));
    a.cmp_x_reg(X5, X6);
    a.b_cond(COND_NE, check_dev_fd);

    // Matched "/dev/std" -- check suffix at path[8]
    a.ldr_w(X7, path_reg, 8);

    // Check "in\0" -- mask to 24 bits
    a.and_w_imm_24bit(X6, X7);
    load_imm32(a, X5, u32::from_le_bytes([b'i', b'n', 0, 0]));
    a.cmp_w_reg(X6, X5);
    a.b_cond(COND_EQ, dup_fd0);

    // Check "out\0"
    load_imm32(a, X5, u32::from_le_bytes(*b"out\0"));
    a.cmp_w_reg(X7, X5);
    a.b_cond(COND_EQ, dup_fd1);

    // Check "err\0"
    load_imm32(a, X5, u32::from_le_bytes(*b"err\0"));
    a.cmp_w_reg(X7, X5);
    a.b_cond(COND_EQ, dup_fd2);

    a.b(no_match);

    // ---- Check "/dev/fd/" prefix ----
    a.bind(check_dev_fd);

    // Reload (x5 was clobbered)
    a.ldr_x(X5, path_reg, 0);
    load_imm64(a, X6, u64::from_le_bytes(*b"/dev/fd/"));
    a.cmp_x_reg(X5, X6);
    a.b_cond(COND_NE, check_proc);

    // Matched "/dev/fd/" -- check digit
    a.ldrh_w(X7, path_reg, 8);

    load_imm32(a, X5, u32::from(u16::from_le_bytes([b'0', 0])));
    a.cmp_w_reg(X7, X5);
    a.b_cond(COND_EQ, dup_fd0);

    load_imm32(a, X5, u32::from(u16::from_le_bytes([b'1', 0])));
    a.cmp_w_reg(X7, X5);
    a.b_cond(COND_EQ, dup_fd1);

    load_imm32(a, X5, u32::from(u16::from_le_bytes([b'2', 0])));
    a.cmp_w_reg(X7, X5);
    a.b_cond(COND_EQ, dup_fd2);

    a.b(no_match);

    // ---- Check "/proc/se" prefix ----
    a.bind(check_proc);

    // Reload (x5 clobbered)
    a.ldr_x(X5, path_reg, 0);
    load_imm64(a, X6, u64::from_le_bytes(*b"/proc/se"));
    a.cmp_x_reg(X5, X6);
    a.b_cond(COND_NE, no_match);

    // Matched "/proc/se" -- check suffix
    a.ldr_x(X5, path_reg, 8);

    load_imm64(a, X6, u64::from_le_bytes(*b"lf/fd/0\0"));
    a.cmp_x_reg(X5, X6);
    a.b_cond(COND_EQ, dup_fd0);

    load_imm64(a, X6, u64::from_le_bytes(*b"lf/fd/1\0"));
    a.cmp_x_reg(X5, X6);
    a.b_cond(COND_EQ, dup_fd1);

    load_imm64(a, X6, u64::from_le_bytes(*b"lf/fd/2\0"));
    a.cmp_x_reg(X5, X6);
    a.b_cond(COND_EQ, dup_fd2);

    a.b(no_match);
}

/// Generate the aarch64 machine code and symbol table for the devfd shim.
pub fn generate() -> (Vec<u8>, Vec<elf::Symbol>, Vec<elf::GotFixup>) {
    let mut a = Asm::new();

    // Forward-declare labels
    let do_openat = a.label();
    let fallthrough = a.label();
    let do_dup = a.label();
    let dup_fd0 = a.label();
    let dup_fd1 = a.label();
    let dup_fd2 = a.label();
    let errno_check = a.label();
    let set_errno = a.label();
    let ok = a.label();
    let try_readlink = a.label();
    let readlink_no_match = a.label();
    let no_match_main = a.label(); // for main path matching -> falls through to openat

    // readlink dup labels (need stack cleanup)
    let rl_dup_fd0 = a.label();
    let rl_dup_fd1 = a.label();
    let rl_dup_fd2 = a.label();

    // ========== open(path, flags, mode) ==========
    // C ABI in: x0=path, x1=flags, x2=mode
    // Rewrite to: x0=AT_FDCWD, x1=path, x2=flags, x3=mode
    let open_offset = a.pos();

    a.mov_x(X3, X2); // mode -> 4th arg
    a.mov_x(X2, X1); // flags -> 3rd arg
    a.mov_x(X1, X0); // path -> 2nd arg
    a.movn_x(X0, 99); // AT_FDCWD = -100 = ~99
    a.b(do_openat);

    // ========== openat(dirfd, path, flags, mode) ==========
    // C ABI in: x0=dirfd, x1=path, x2=flags, x3=mode
    let openat_offset = a.pos();
    a.bind(do_openat);

    // Save dirfd, flags, mode in callee-saved-like scratch regs
    // (kernel preserves x9-x15 across svc, so these survive syscalls)
    a.mov_x(X9, X0); // x9 = dirfd
    a.mov_x(X4, X1); // x4 = path
    a.mov_x(X10, X2); // x10 = flags
    a.mov_x(X11, X3); // x11 = mode

    // Path matching on the original path
    emit_path_match(&mut a, X4, dup_fd0, dup_fd1, dup_fd2, no_match_main);

    // ========== no_match_main: fall through to real openat ==========
    a.bind(no_match_main);
    a.b(fallthrough);

    // ========== dup(N) handlers ==========
    a.bind(dup_fd0);
    a.movz_x(X0, 0);
    a.b(do_dup);

    a.bind(dup_fd1);
    a.movz_x(X0, 1);
    a.b(do_dup);

    a.bind(dup_fd2);
    a.movz_x(X0, 2);
    // fall through to do_dup

    // ========== do_dup: syscall(SYS_dup, fd_in_x0) ==========
    a.bind(do_dup);
    a.movz_x(X8, SYS_DUP);
    a.svc();
    a.b(errno_check);

    // ========== fallthrough: real openat syscall ==========
    a.bind(fallthrough);
    // Restore args from saved registers
    a.mov_x(X0, X9); // dirfd
    a.mov_x(X1, X4); // path
    a.mov_x(X2, X10); // flags
    a.mov_x(X3, X11); // mode
    a.movz_x(X8, SYS_OPENAT);
    a.svc();
    // After svc: x0=result, x1-x7 preserved by kernel, x9=dirfd, x4=path preserved

    // Check if result is -ENXIO (-6)
    load_imm64(&mut a, X5, -6i64 as u64);
    a.cmp_x_reg(X0, X5);
    a.b_cond(COND_EQ, try_readlink);
    a.b(errno_check);

    // ========== try_readlink: resolve symlink and retry matching ==========
    a.bind(try_readlink);
    // x9=dirfd, x4=path (both preserved across syscall)
    // Allocate stack buffer
    a.sub_sp_imm(READLINK_BUFSZ);

    // readlinkat(dirfd=x9, path=x4, buf=sp, bufsiz=128)
    a.mov_x(X0, X9); // dirfd
    a.mov_x(X1, X4); // path
    a.mov_x_sp(X2); // buf = sp
    a.movz_x(X3, READLINK_BUFSZ); // bufsiz
    a.movz_x(X8, SYS_READLINKAT);
    a.svc();

    // Check result: if negative, readlink failed
    a.cmp_x_imm(X0, 0);
    a.b_cond(COND_LT, readlink_no_match);

    // Check if result >= READLINK_BUFSZ (buffer full)
    a.cmp_x_imm(X0, READLINK_BUFSZ);
    a.b_cond(COND_GE, readlink_no_match);

    // Null-terminate: buf[x0] = 0
    // Reuse x4 for the buffer pointer -- the original path is no longer needed
    // since we'll either dup or return ENXIO from here.
    // (emit_path_match clobbers x5 as scratch, so path_reg must not be x5)
    a.mov_x_sp(X4); // x4 = sp (buf base)
    a.strb_reg(WZR, X4, X0); // buf[len] = 0

    // Path matching on the readlink result
    emit_path_match(
        &mut a,
        X4,
        rl_dup_fd0,
        rl_dup_fd1,
        rl_dup_fd2,
        readlink_no_match,
    );

    // ========== readlink dup handlers (deallocate stack, then dup) ==========
    a.bind(rl_dup_fd0);
    a.add_sp_imm(READLINK_BUFSZ);
    a.movz_x(X0, 0);
    a.b(do_dup);

    a.bind(rl_dup_fd1);
    a.add_sp_imm(READLINK_BUFSZ);
    a.movz_x(X0, 1);
    a.b(do_dup);

    a.bind(rl_dup_fd2);
    a.add_sp_imm(READLINK_BUFSZ);
    a.movz_x(X0, 2);
    a.b(do_dup);

    // ========== readlink_no_match: deallocate stack, return ENXIO ==========
    a.bind(readlink_no_match);
    a.add_sp_imm(READLINK_BUFSZ);
    a.movz_w(X0, ENXIO); // errno value
    a.b(set_errno);

    // ========== errno_check: convert raw syscall result to C convention ==========
    a.bind(errno_check);
    // CMP x0, #0
    a.cmp_x_imm(X0, 0);
    // b.ge ok (if >= 0, return as-is)
    a.b_cond(COND_GE, ok);
    // Negate to get positive errno value
    a.neg_x(X0, X0);
    // fall through to set_errno

    // ========== set_errno: call __errno_location(), set *it, return -1 ==========
    a.bind(set_errno);
    // x0 = positive errno value
    // Save x30 (link register, clobbered by blr) and x19 (callee-saved, for errno value)
    a.stp_pre(X30, X19, -16);
    // Move errno value to x19 (callee-saved, survives blr)
    a.mov_x(X19, X0);

    // Call __errno_location() via GOT: adrp x9, GOT_PAGE; ldr x9, [x9, #GOT_OFF]; blr x9
    let adrp_pos = a.adrp(X9);
    let ldr_pos = a.ldr_x_got_placeholder(X9, X9);
    a.blr(X9);
    // x0 = &errno

    // *errno = saved value
    a.str_w(X19, X0, 0);

    // Restore x30 and x19
    a.ldp_post(X30, X19, 16);

    // Return -1
    a.movn_x(X0, 0);

    a.bind(ok);
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

    let got_fixups = vec![elf::GotFixup {
        slot: 0,      // __errno_location is import[0]
        offset: ldr_pos, // position of the ldr instruction
        aux: adrp_pos,   // position of the adrp instruction
    }];

    (code, symbols, got_fixups)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_generates_without_panic() {
        let (code, _, _) = generate();
        assert!(code.len() > 50, "code too small: {} bytes", code.len());
        assert!(code.len() < 4096, "code too large: {} bytes", code.len());
    }

    #[test]
    fn code_is_4byte_aligned() {
        let (code, _, _) = generate();
        assert_eq!(code.len() % 4, 0, "code must be 4-byte aligned");
    }

    #[test]
    fn exports_four_symbols() {
        let (_, symbols, _) = generate();
        assert_eq!(symbols.len(), 4);
        let names: Vec<&str> = symbols.iter().map(|s| s.name).collect();
        assert!(names.contains(&"open"));
        assert!(names.contains(&"openat"));
        assert!(names.contains(&"open64"));
        assert!(names.contains(&"openat64"));
    }

    #[test]
    fn symbol_offsets_within_bounds() {
        let (code, symbols, _) = generate();
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
        let (_, symbols, _) = generate();
        let open = symbols.iter().find(|s| s.name == "open").unwrap();
        let open64 = symbols.iter().find(|s| s.name == "open64").unwrap();
        assert_eq!(open.offset, open64.offset);
    }

    #[test]
    fn openat64_aliases_openat() {
        let (_, symbols, _) = generate();
        let openat = symbols.iter().find(|s| s.name == "openat").unwrap();
        let openat64 = symbols.iter().find(|s| s.name == "openat64").unwrap();
        assert_eq!(openat.offset, openat64.offset);
    }

    #[test]
    fn code_contains_three_svc_instructions() {
        let (code, _, _) = generate();
        let count = code
            .chunks_exact(4)
            .filter(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]) == 0xD4000001)
            .count();
        // SYS_dup + SYS_openat + SYS_readlinkat = 3
        assert_eq!(count, 3, "expected 3 svc instructions, got {count}");
    }

    #[test]
    fn got_fixups_present_and_valid() {
        let (code, _, got_fixups) = generate();
        assert!(!got_fixups.is_empty(), "expected GOT fixups");
        assert_eq!(got_fixups.len(), 1, "expected 1 GOT fixup");
        let fixup = &got_fixups[0];
        assert_eq!(fixup.slot, 0);
        assert!(
            fixup.offset + 4 <= code.len(),
            "GOT fixup offset out of bounds"
        );
        assert!(
            fixup.aux + 4 <= code.len(),
            "GOT fixup aux (adrp) out of bounds"
        );
    }
}
