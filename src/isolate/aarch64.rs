//! Machine code emitter for the isolate binary (aarch64)
//!
//! Emits raw AArch64 machine code that performs the same sequence as x86_64.rs.
//!
//! Linux aarch64 syscall ABI:
//!   x8 = syscall number
//!   x0-x5 = arguments
//!   svc #0; return in x0 (negative = -errno)
//!
//! Linux process startup ABI (_start, no libc):
//! ```text
//!   [sp+0]  = argc
//!   [sp+8]  = argv[0]
//!   [sp+16] = argv[1]
//!   ...
//!   NULL
//!   envp[0], envp[1], ..., NULL
//! ```
//!
//! Callee-saved registers (preserved across bl calls):
//! ```text
//!   x19 = argc
//!   x20 = &argv[0] (sp + 8)
//!   x21 = uid
//!   x22 = gid
//!   x23 = child pid (parent path)
//!   x30 = link register
//! ```

// Syscall numbers (aarch64)
const SYS_MOUNT: u16 = 40;
const SYS_WRITE: u16 = 64;
const SYS_EXIT: u16 = 93;
const SYS_UNSHARE: u16 = 97;
const SYS_RT_SIGACTION: u16 = 134;
const SYS_SETGID: u16 = 144;
const SYS_SETUID: u16 = 146;
const SYS_PRCTL: u16 = 167;
const SYS_SETGROUPS: u16 = 159;
const SYS_CLONE: u16 = 220;
const SYS_EXECVE: u16 = 221;
const SYS_WAIT4: u16 = 260;
const SYS_CHDIR: u16 = 49;

// Constants
const SIGCHLD: u16 = 17;
const MS_NOSUID: u32 = 2;
const MS_NODEV: u32 = 4;
const MS_NOEXEC: u32 = 8;
const PR_CAPBSET_DROP: u16 = 24;
const CAP_SYS_ADMIN: u16 = 21;
const SIG_IGN: u16 = 1;
const SIGTERM: u16 = 15;
const SIGINT: u16 = 2;
const SIGHUP: u16 = 1;
const SIGQUIT: u16 = 3;
const EINTR: u16 = 4;

// Error message strings
const MSG_USAGE: &[u8] = b"usage: isolate <uid> <gid> <dir> <cmd> [args...]\n";
const MSG_NUMBER: &[u8] = b"bad number\n";
const MSG_UNSHARE: &[u8] = b"unshare\n";
const MSG_FORK: &[u8] = b"fork\n";
const MSG_MOUNT: &[u8] = b"mount\n";
const MSG_SETGROUPS: &[u8] = b"setgroups\n";
const MSG_SETGID: &[u8] = b"setgid\n";
const MSG_SETUID: &[u8] = b"setuid\n";
const MSG_CHDIR: &[u8] = b"chdir\n";
const MSG_EXECVE: &[u8] = b"execve\n";

// String data for mount syscall
const STR_PROC: &[u8] = b"proc\0";
const STR_SLASH_PROC: &[u8] = b"/proc\0";

/// Label index for forward/backward references.
#[derive(Clone, Copy)]
struct Label(usize);

enum FixupKind {
    /// b.cond: 19-bit signed offset (in 4-byte units) at bits \[23:5\]
    BCond,
    /// b / bl: 26-bit signed offset (in 4-byte units) at bits \[25:0\]
    Branch26,
    /// adr: 21-bit signed offset (byte granularity), immlo at \[30:29\], immhi at \[23:5\]
    Adr,
    /// cbz / cbnz: 19-bit signed offset (in 4-byte units) at bits \[23:5\]
    Cbz,
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

    fn data(&mut self, bytes: &[u8]) {
        self.code.extend_from_slice(bytes);
        while !self.code.len().is_multiple_of(4) {
            self.code.push(0);
        }
    }

    // ---- AArch64 instruction emitters ----

    fn ldr_x(&mut self, rt: u8, rn: u8, imm: u16) {
        assert!(imm.is_multiple_of(8) && imm <= 32760);
        let imm12 = (imm / 8) as u32;
        let insn = 0xF9400000 | (imm12 << 10) | ((rn as u32) << 5) | (rt as u32);
        self.emit32(insn);
    }

    fn ldr_w(&mut self, rt: u8, rn: u8, imm: u16) {
        assert!(imm.is_multiple_of(4) && imm <= 16380);
        let imm12 = (imm / 4) as u32;
        let insn = 0xB9400000 | (imm12 << 10) | ((rn as u32) << 5) | (rt as u32);
        self.emit32(insn);
    }

    fn str_x(&mut self, rt: u8, rn: u8, imm: u16) {
        assert!(imm.is_multiple_of(8) && imm <= 32760);
        let imm12 = (imm / 8) as u32;
        let insn = 0xF9000000 | (imm12 << 10) | ((rn as u32) << 5) | (rt as u32);
        self.emit32(insn);
    }

    fn ldrb_w(&mut self, rt: u8, rn: u8, imm: u16) {
        assert!(imm <= 4095);
        let insn = 0x39400000 | ((imm as u32) << 10) | ((rn as u32) << 5) | (rt as u32);
        self.emit32(insn);
    }

    fn add_x_imm(&mut self, rd: u8, rn: u8, imm: u16) {
        assert!(imm <= 4095);
        let insn = 0x91000000 | ((imm as u32) << 10) | ((rn as u32) << 5) | (rd as u32);
        self.emit32(insn);
    }

    fn add_x_reg(&mut self, rd: u8, rn: u8, rm: u8) {
        let insn = 0x8B000000 | ((rm as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit32(insn);
    }

    fn sub_x_imm(&mut self, rd: u8, rn: u8, imm: u16) {
        assert!(imm <= 4095);
        let insn = 0xD1000000 | ((imm as u32) << 10) | ((rn as u32) << 5) | (rd as u32);
        self.emit32(insn);
    }

    fn sub_w_imm(&mut self, rd: u8, rn: u8, imm: u16) {
        assert!(imm <= 4095);
        let insn = 0x51000000 | ((imm as u32) << 10) | ((rn as u32) << 5) | (rd as u32);
        self.emit32(insn);
    }

    fn cmp_x_imm(&mut self, rn: u8, imm: u16) {
        assert!(imm <= 4095);
        let insn = 0xF1000000 | ((imm as u32) << 10) | ((rn as u32) << 5) | 31;
        self.emit32(insn);
    }

    fn cmp_w_imm(&mut self, rn: u8, imm: u16) {
        assert!(imm <= 4095);
        let insn = 0x71000000 | ((imm as u32) << 10) | ((rn as u32) << 5) | 31;
        self.emit32(insn);
    }

    /// CMN Xn, #imm12: compare negative (ADDS XZR, Xn, #imm).
    fn cmn_x_imm(&mut self, rn: u8, imm: u16) {
        assert!(imm <= 4095);
        // 1 01 10001 0 imm12 Rn 11111
        let insn = 0xB1000000 | ((imm as u32) << 10) | ((rn as u32) << 5) | 31;
        self.emit32(insn);
    }

    fn mov_x(&mut self, rd: u8, rm: u8) {
        let insn = 0xAA0003E0 | ((rm as u32) << 16) | (rd as u32);
        self.emit32(insn);
    }

    fn movz_x(&mut self, rd: u8, imm: u16) {
        let insn = 0xD2800000 | ((imm as u32) << 5) | (rd as u32);
        self.emit32(insn);
    }

    /// MOVK Xd, #imm16, LSL #16: move with keep, shift 16.
    fn movk_x_16(&mut self, rd: u8, imm: u16) {
        // 1 11 100101 01 imm16 Rd  (hw=1 → LSL #16)
        let insn = 0xF2A00000 | ((imm as u32) << 5) | (rd as u32);
        self.emit32(insn);
    }

    fn lsl_x(&mut self, rd: u8, rn: u8, shift: u8) {
        assert!(shift < 64);
        let immr = (64 - shift) as u32;
        let imms = (63 - shift) as u32;
        let insn = 0xD3400000 | (immr << 16) | (imms << 10) | ((rn as u32) << 5) | (rd as u32);
        self.emit32(insn);
    }

    fn lsr_x(&mut self, rd: u8, rn: u8, shift: u8) {
        assert!(shift < 64);
        let immr = shift as u32;
        let imms = 63u32;
        let insn = 0xD3400000 | (immr << 16) | (imms << 10) | ((rn as u32) << 5) | (rd as u32);
        self.emit32(insn);
    }

    fn mul_x(&mut self, rd: u8, rn: u8, rm: u8) {
        let insn = 0x9B007C00 | ((rm as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit32(insn);
    }

    /// AND Wd, Wn, #imm: 32-bit AND with bitmask immediate.
    fn and_w_imm(&mut self, rd: u8, rn: u8, imm: u32) {
        // For AND Wd, Wn, #0x7F: N=0, immr=0, imms=0b000110 (encodes 7-bit mask)
        // Encoding: 0 00 100100 0 immr imms Rn Rd
        // For 0x7F (7 bits set): N=0, immr=0, imms=6
        // For 0xFF (8 bits set): N=0, immr=0, imms=7
        let (immr, imms) = encode_bitmask_imm_32(imm);
        let insn = 0x12000000 | (immr << 16) | (imms << 10) | ((rn as u32) << 5) | (rd as u32);
        self.emit32(insn);
    }

    fn svc(&mut self) {
        self.emit32(0xD4000001);
    }

    fn ret(&mut self) {
        self.emit32(0xD65F03C0);
    }

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

    fn b(&mut self, target: Label) {
        let offset = self.pos();
        self.emit32(0x14000000);
        self.fixups.push(Fixup {
            offset,
            label: target.0,
            kind: FixupKind::Branch26,
        });
    }

    fn bl(&mut self, target: Label) {
        let offset = self.pos();
        self.emit32(0x94000000);
        self.fixups.push(Fixup {
            offset,
            label: target.0,
            kind: FixupKind::Branch26,
        });
    }

    fn cbz_w(&mut self, rt: u8, target: Label) {
        let offset = self.pos();
        let insn = 0x34000000 | (rt as u32);
        self.emit32(insn);
        self.fixups.push(Fixup {
            offset,
            label: target.0,
            kind: FixupKind::Cbz,
        });
    }

    fn cbz_x(&mut self, rt: u8, target: Label) {
        let offset = self.pos();
        let insn = 0xB4000000 | (rt as u32);
        self.emit32(insn);
        self.fixups.push(Fixup {
            offset,
            label: target.0,
            kind: FixupKind::Cbz,
        });
    }

    fn cbnz_w(&mut self, rt: u8, target: Label) {
        let offset = self.pos();
        let insn = 0x35000000 | (rt as u32);
        self.emit32(insn);
        self.fixups.push(Fixup {
            offset,
            label: target.0,
            kind: FixupKind::Cbz,
        });
    }

    fn cbnz_x(&mut self, rt: u8, target: Label) {
        let offset = self.pos();
        let insn = 0xB5000000 | (rt as u32);
        self.emit32(insn);
        self.fixups.push(Fixup {
            offset,
            label: target.0,
            kind: FixupKind::Cbz,
        });
    }

    fn adr(&mut self, rd: u8, target: Label) {
        let offset = self.pos();
        let insn = 0x10000000 | (rd as u32);
        self.emit32(insn);
        self.fixups.push(Fixup {
            offset,
            label: target.0,
            kind: FixupKind::Adr,
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
                FixupKind::BCond | FixupKind::Cbz => {
                    assert!(rel % 4 == 0, "branch target not aligned");
                    let imm19 = rel / 4;
                    assert!(
                        (-262144..=262143).contains(&imm19),
                        "b.cond/cbz offset out of range"
                    );
                    insn |= ((imm19 as u32) & 0x7FFFF) << 5;
                }
                FixupKind::Branch26 => {
                    assert!(rel % 4 == 0, "branch target not aligned");
                    let imm26 = rel / 4;
                    assert!(
                        (-33554432..=33554431).contains(&imm26),
                        "b/bl offset out of range"
                    );
                    insn |= (imm26 as u32) & 0x3FFFFFF;
                }
                FixupKind::Adr => {
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

/// Encode a 32-bit bitmask immediate for AND/ORR/EOR instructions.
/// Returns (immr, imms) fields. Only supports simple contiguous bit patterns.
fn encode_bitmask_imm_32(imm: u32) -> (u32, u32) {
    // For our use cases we only need 0x7F and 0xFF
    match imm {
        0x7F => (0, 6), // 7 contiguous bits starting at bit 0
        0xFF => (0, 7), // 8 contiguous bits starting at bit 0
        _ => panic!("unsupported bitmask immediate: {:#x}", imm),
    }
}

// Condition codes
const COND_LT: u8 = 0b1011;
const COND_EQ: u8 = 0b0000;
const COND_HI: u8 = 0b1000;

// Register aliases
const X0: u8 = 0;
const X1: u8 = 1;
const X2: u8 = 2;
const X3: u8 = 3;
const X4: u8 = 4;
const X8: u8 = 8;
const X9: u8 = 9;
const X10: u8 = 10;
const X11: u8 = 11;
const X19: u8 = 19;
const X20: u8 = 20;
const X21: u8 = 21;
const X22: u8 = 22;
const X23: u8 = 23;
const SP: u8 = 31;

/// Generate the complete AArch64 machine code for the isolate binary.
pub fn generate() -> Vec<u8> {
    let mut a = Asm::new();

    // Forward-declare labels
    let atoi = a.label();
    let atoi_loop = a.label();
    let atoi_error = a.label();
    let error_exit = a.label();
    let err_unshare = a.label();
    let err_fork = a.label();
    let err_mount = a.label();
    let err_setgroups = a.label();
    let err_setgid = a.label();
    let err_setuid = a.label();
    let err_chdir = a.label();
    let err_execve = a.label();
    let usage_error = a.label();
    let parent_path = a.label();
    let child_path = a.label();
    let wait_loop = a.label();
    let child_exited = a.label();
    let child_signaled = a.label();
    let skip_privdrop = a.label();

    let lbl_msg_usage = a.label();
    let lbl_msg_number = a.label();
    let lbl_msg_unshare = a.label();
    let lbl_msg_fork = a.label();
    let lbl_msg_mount = a.label();
    let lbl_msg_setgroups = a.label();
    let lbl_msg_setgid = a.label();
    let lbl_msg_setuid = a.label();
    let lbl_msg_chdir = a.label();
    let lbl_msg_execve = a.label();

    let lbl_str_proc = a.label();
    let lbl_str_slash_proc = a.label();

    // ========== _start ==========

    // ldr x19, [sp, #0]               ; x19 = argc
    a.ldr_x(X19, SP, 0);
    // add x20, sp, #8                 ; x20 = &argv[0]
    a.add_x_imm(X20, SP, 8);
    // cmp x19, #5
    a.cmp_x_imm(X19, 5);
    // b.lt usage_error
    a.b_cond(COND_LT, usage_error);

    // --- Parse UID (argv[1]) ---
    a.ldr_x(X0, X20, 8);
    a.bl(atoi);
    a.mov_x(X21, X0);

    // --- Parse GID (argv[2]) ---
    a.ldr_x(X0, X20, 16);
    a.bl(atoi);
    a.mov_x(X22, X0);

    // --- unshare(CLONE_NEWPID | CLONE_NEWIPC) ---
    a.movz_x(X8, SYS_UNSHARE);
    // CLONE_NEWPID | CLONE_NEWIPC = 0x28000000
    // movz x0, #0x2800, lsl #16 then movk to add lower bits
    // 0x28000000 = 0x2800 << 16
    a.movz_x(X0, 0);
    a.movk_x_16(X0, 0x2800);
    a.svc();
    a.cmp_x_imm(X0, 0);
    a.b_cond(COND_LT, err_unshare);

    // --- clone(SIGCHLD, 0, ...) --- (aarch64 has no fork, use clone)
    a.movz_x(X8, SYS_CLONE);
    a.movz_x(X0, SIGCHLD); // flags = SIGCHLD
    a.movz_x(X1, 0); // stack = NULL (fork semantics)
    a.movz_x(X2, 0); // parent_tid = NULL
    a.movz_x(X3, 0); // tls = NULL
    a.movz_x(X4, 0); // child_tid = NULL
    a.svc();
    a.cmp_x_imm(X0, 0);
    a.b_cond(COND_LT, err_fork);
    // x0 > 0 = parent, x0 == 0 = child
    a.cbnz_x(X0, parent_path);

    // ========== Child path ==========
    a.bind(child_path);

    // --- mount("proc", "/proc", "proc", MS_NOSUID|MS_NODEV|MS_NOEXEC, NULL) ---
    a.movz_x(X8, SYS_MOUNT);
    a.adr(X0, lbl_str_proc); // source
    a.adr(X1, lbl_str_slash_proc); // target
    a.adr(X2, lbl_str_proc); // fstype
                             // MS_NOSUID | MS_NODEV | MS_NOEXEC = 14
    a.movz_x(X3, (MS_NOSUID | MS_NODEV | MS_NOEXEC) as u16);
    a.movz_x(X4, 0); // data = NULL
    a.svc();
    a.cmp_x_imm(X0, 0);
    a.b_cond(COND_LT, err_mount);

    // --- prctl(PR_CAPBSET_DROP, CAP_SYS_ADMIN) ---
    // Best-effort: may fail with EPERM when CAP_SETPCAP is not in the
    // effective set (e.g. capabilities drop ALL). In that case the systemd
    // unit's CapabilityBoundingSet already restricts CAP_SYS_ADMIN.
    a.movz_x(X8, SYS_PRCTL);
    a.movz_x(X0, PR_CAPBSET_DROP);
    a.movz_x(X1, CAP_SYS_ADMIN);
    a.svc();
    // (ignore return value; best-effort drop)

    // --- Conditional privilege drop: skip if uid == 0 ---
    a.cbz_x(X21, skip_privdrop);

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

    a.bind(skip_privdrop);

    // --- chdir(argv[3]) ---
    a.movz_x(X8, SYS_CHDIR);
    a.ldr_x(X0, X20, 24);
    a.svc();
    a.cmp_x_imm(X0, 0);
    a.b_cond(COND_LT, err_chdir);

    // --- execve(argv[4], &argv[4..], envp) ---
    a.ldr_x(X0, X20, 32); // filename = argv[4]
    a.add_x_imm(X1, X20, 32); // argv = &argv[4..]
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

    a.bind(err_unshare);
    a.adr(X1, lbl_msg_unshare);
    a.movz_x(X2, MSG_UNSHARE.len() as u16);
    a.b(error_exit);

    a.bind(err_fork);
    a.adr(X1, lbl_msg_fork);
    a.movz_x(X2, MSG_FORK.len() as u16);
    a.b(error_exit);

    a.bind(err_mount);
    a.adr(X1, lbl_msg_mount);
    a.movz_x(X2, MSG_MOUNT.len() as u16);
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

    // ========== Parent path ==========
    // x0 = child pid
    a.bind(parent_path);
    a.mov_x(X23, X0); // save child pid

    // --- Ignore signals via rt_sigaction ---
    // Kernel sigaction struct on aarch64:
    //   sa_handler:  8 bytes
    //   sa_flags:    8 bytes
    //   sa_mask:     8 bytes (sigsetsize=8)
    // = 24 bytes minimum (no sa_restorer on aarch64)
    // Allocate 32 bytes on stack (aligned)
    a.sub_x_imm(SP, SP, 32);

    // Store SIG_IGN as sa_handler at [sp]
    a.movz_x(X9, SIG_IGN);
    a.str_x(X9, SP, 0);
    // sa_flags = 0
    a.movz_x(X9, 0);
    a.str_x(X9, SP, 8);
    // sa_mask = 0
    a.str_x(X9, SP, 16);

    for sig in [SIGTERM, SIGINT, SIGHUP, SIGQUIT] {
        a.movz_x(X8, SYS_RT_SIGACTION);
        a.movz_x(X0, sig); // signum
        a.mov_x(X1, SP); // new action
        a.movz_x(X2, 0); // old action = NULL
        a.movz_x(X3, 8); // sigsetsize = 8
        a.svc();
    }

    // Restore stack
    a.add_x_imm(SP, SP, 32);

    // --- wait4(child, &status, 0, NULL) ---
    // Allocate 8 bytes on stack for status (4 bytes needed, 8 for alignment)
    a.sub_x_imm(SP, SP, 16);

    a.bind(wait_loop);
    a.movz_x(X8, SYS_WAIT4);
    a.mov_x(X0, X23); // pid = child
    a.mov_x(X1, SP); // &status
    a.movz_x(X2, 0); // options = 0
    a.movz_x(X3, 0); // rusage = NULL
    a.svc();

    // Check for EINTR: on aarch64, errors are returned as negative values
    // cmn x0, #EINTR (compare x0 + EINTR with 0; if x0 == -EINTR this sets Z)
    a.cmn_x_imm(X0, EINTR);
    a.b_cond(COND_EQ, wait_loop);

    // Load status (32-bit)
    a.ldr_w(X9, SP, 0);

    // Check WIFEXITED: (status & 0x7F) == 0
    a.and_w_imm(X10, X9, 0x7F);
    a.cbz_w(X10, child_exited);

    // Check WIFSIGNALED: ((status & 0x7F) + 1) >> 1 > 0
    a.add_x_imm(X10, X10, 1);
    a.lsr_x(X10, X10, 1);
    a.cbnz_w(X10, child_signaled);

    // Unknown status -- exit 1
    a.movz_x(X8, SYS_EXIT);
    a.movz_x(X0, 1);
    a.svc();

    // child_exited: exit(WEXITSTATUS = (status >> 8) & 0xFF)
    a.bind(child_exited);
    a.lsr_x(X0, X9, 8);
    a.and_w_imm(X0, X0, 0xFF);
    a.movz_x(X8, SYS_EXIT);
    a.svc();

    // child_signaled: exit(128 + WTERMSIG = 128 + (status & 0x7F))
    a.bind(child_signaled);
    a.and_w_imm(X0, X9, 0x7F);
    a.add_x_imm(X0, X0, 128);
    a.movz_x(X8, SYS_EXIT);
    a.svc();

    // ========== atoi subroutine ==========
    // Input: x0 = pointer to null-terminated ASCII decimal string
    // Output: x0 = parsed value (guaranteed to fit in u32)
    // Clobbers: x9, x10, x11
    // On bad input or overflow: branches to error_exit (does not return)

    a.bind(atoi);
    a.mov_x(X9, X0);
    a.movz_x(X0, 0);

    a.ldrb_w(X10, X9, 0);
    a.cbz_w(X10, atoi_error);

    a.bind(atoi_loop);
    a.sub_w_imm(X10, X10, 0x30);
    a.cmp_w_imm(X10, 9);
    a.b_cond(COND_HI, atoi_error);

    a.movz_x(X11, 10);
    a.mul_x(X0, X0, X11);
    a.add_x_reg(X0, X0, X10);

    a.add_x_imm(X9, X9, 1);
    a.ldrb_w(X10, X9, 0);
    let atoi_continue = a.label();
    a.cbz_w(X10, atoi_continue);
    a.b(atoi_loop);

    a.bind(atoi_continue);

    // Overflow check
    a.lsr_x(X11, X0, 32);
    a.cbnz_x(X11, atoi_error);

    a.ret();

    a.bind(atoi_error);
    a.adr(X1, lbl_msg_number);
    a.movz_x(X2, MSG_NUMBER.len() as u16);
    a.b(error_exit);

    // ========== String data ==========

    a.bind(lbl_msg_usage);
    a.data(MSG_USAGE);

    a.bind(lbl_msg_number);
    a.data(MSG_NUMBER);

    a.bind(lbl_msg_unshare);
    a.data(MSG_UNSHARE);

    a.bind(lbl_msg_fork);
    a.data(MSG_FORK);

    a.bind(lbl_msg_mount);
    a.data(MSG_MOUNT);

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

    a.bind(lbl_str_proc);
    a.data(STR_PROC);

    a.bind(lbl_str_slash_proc);
    a.data(STR_SLASH_PROC);

    a.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_generates_without_panic() {
        let code = generate();
        assert!(code.len() > 200, "code too small: {} bytes", code.len());
        assert!(code.len() < 2048, "code too large: {} bytes", code.len());
    }

    #[test]
    fn code_is_4byte_aligned() {
        let code = generate();
        assert_eq!(code.len() % 4, 0, "code must be 4-byte aligned");
    }

    #[test]
    fn code_starts_with_ldr_x19_sp() {
        let code = generate();
        let first = u32::from_le_bytes(code[0..4].try_into().unwrap());
        assert_eq!(first, 0xF94003F3, "expected ldr x19, [sp]");
    }

    #[test]
    fn code_contains_svc_instructions() {
        let code = generate();
        let count = code
            .chunks_exact(4)
            .filter(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]) == 0xD4000001)
            .count();
        // unshare, clone, mount, prctl (best-effort), setgroups, setgid, setuid, chdir, execve,
        // 4x rt_sigaction, wait4, write, exit (error_exit),
        // 3x exit (parent: unknown/exited/signaled)
        assert!(
            count >= 15,
            "expected at least 15 svc instructions, got {count}"
        );
    }

    #[test]
    fn code_contains_string_data() {
        let code = generate();
        let code_str = String::from_utf8_lossy(&code);
        assert!(code_str.contains("unshare\n"));
        assert!(code_str.contains("fork\n"));
        assert!(code_str.contains("mount\n"));
        assert!(code_str.contains("setgroups\n"));
        assert!(code_str.contains("setgid\n"));
        assert!(code_str.contains("setuid\n"));
        assert!(code_str.contains("chdir\n"));
        assert!(code_str.contains("execve\n"));
        assert!(code_str.contains("bad number\n"));
        assert!(code_str.contains("usage: isolate"));
    }

    #[test]
    fn atoi_has_overflow_guard() {
        let code = generate();
        let insns: Vec<u32> = code
            .chunks_exact(4)
            .map(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]))
            .collect();
        // lsr x11, x0, #32 = UBFM x11, x0, #32, #63 = 0xD360FC0B
        let expected_lsr = 0xD360FC0B;
        assert!(
            insns.contains(&expected_lsr),
            "missing lsr x11, x0, #32 overflow guard in atoi"
        );
        let has_cbnz = insns
            .iter()
            .any(|&i| (i & 0xFF000000) == 0xB5000000 && (i & 0x1F) == X11 as u32);
        assert!(has_cbnz, "missing cbnz x11 overflow guard in atoi");
    }

    #[test]
    fn code_contains_proc_strings() {
        let code = generate();
        let code_str = String::from_utf8_lossy(&code);
        assert!(code_str.contains("proc"));
        let has_slash_proc = code.windows(6).any(|w| w == b"/proc\0");
        assert!(has_slash_proc, "missing '/proc' string");
    }

    #[test]
    fn message_lengths_match_data() {
        assert_eq!(MSG_USAGE.len(), 49);
        assert_eq!(MSG_NUMBER.len(), 11);
        assert_eq!(MSG_UNSHARE.len(), 8);
        assert_eq!(MSG_FORK.len(), 5);
        assert_eq!(MSG_MOUNT.len(), 6);
        assert_eq!(MSG_SETGROUPS.len(), 10);
        assert_eq!(MSG_SETGID.len(), 7);
        assert_eq!(MSG_SETUID.len(), 7);
        assert_eq!(MSG_CHDIR.len(), 6);
        assert_eq!(MSG_EXECVE.len(), 7);
    }
}
