//! Machine code emitter for the isolate binary (x86_64)
//!
//! Emits raw x86_64 machine code that performs:
//! ```text
//!   Parent process:
//!     1. Parse argc/argv from the Linux process stack
//!     2. atoi(argv[1]) -> uid, atoi(argv[2]) -> gid
//!     3. unshare(CLONE_NEWPID | CLONE_NEWIPC)
//!     4. fork()
//!     5. Parent: ignore signals (SIGTERM, SIGINT, SIGHUP, SIGQUIT),
//!        wait4(child), exit with child's status
//!     6. Child: mount("proc", "/proc", "proc", MS_NOSUID|MS_NODEV|MS_NOEXEC, NULL)
//!     7. Child: prctl(PR_CAPBSET_DROP, CAP_SYS_ADMIN) (best-effort)
//!     8. Child: if uid > 0: setgroups(0, NULL) -> setgid(gid) -> setuid(uid)
//!     9. Child: chdir(argv[3])
//!    10. Child: execve(argv[4], &argv[4..], envp)
//! ```
//!
//! Linux x86_64 syscall ABI:
//! ```text
//!   rax = syscall number
//!   rdi, rsi, rdx, r10, r8, r9 = arguments
//!   syscall instruction; return in rax (negative = -errno)
//! ```
//!
//! Linux process startup ABI (no libc, _start):
//! ```text
//!   [rsp+0]  = argc
//!   [rsp+8]  = argv[0]
//!   [rsp+16] = argv[1]
//!   ...
//!   NULL
//!   envp[0], envp[1], ..., NULL
//! ```

// Syscall numbers
const SYS_WRITE: u8 = 1;
const SYS_RT_SIGACTION: u8 = 13;
const SYS_FORK: u8 = 57;
const SYS_EXECVE: u8 = 59;
const SYS_EXIT: u8 = 60;
const SYS_WAIT4: u8 = 61;
const SYS_CHDIR: u8 = 80;
const SYS_SETUID: u8 = 105;
const SYS_SETGID: u8 = 106;
const SYS_SETGROUPS: u8 = 116;
const SYS_PRCTL: u8 = 157;
const SYS_MOUNT: u16 = 165;
const SYS_UNSHARE: u16 = 272;

// Constants
const CLONE_NEWPID: u32 = 0x20000000;
const CLONE_NEWIPC: u32 = 0x08000000;
const MS_NOSUID: u32 = 2;
const MS_NODEV: u32 = 4;
const MS_NOEXEC: u32 = 8;
const PR_CAPBSET_DROP: u32 = 24;
const CAP_SYS_ADMIN: u32 = 21;
const SIG_IGN: u64 = 1;
const SIGTERM: u8 = 15;
const SIGINT: u8 = 2;
const SIGHUP: u8 = 1;
const SIGQUIT: u8 = 3;

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
const R14: u8 = 6;

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
            code: Vec::with_capacity(1024),
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

    /// Emit lea rdi, [rip + disp32] referencing a label.
    fn lea_rdi_rip(&mut self, target: Label) {
        self.emit(&[0x48, 0x8D, 0x3D]);
        let offset = self.pos();
        self.emit(&[0; 4]);
        self.fixups.push(Fixup {
            offset,
            label: target.0,
            insn_end: self.pos(),
            size: 4,
        });
    }

    /// Emit data bytes at current position.
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

/// ModRM byte: mod(2) | reg(3) | rm(3)
const fn modrm(md: u8, reg: u8, rm: u8) -> u8 {
    (md << 6) | ((reg & 7) << 3) | (rm & 7)
}

/// REX prefix: 0100 WRXB
const fn rex(w: bool, r: bool, x: bool, b: bool) -> u8 {
    0x40 | ((w as u8) << 3) | ((r as u8) << 2) | ((x as u8) << 1) | (b as u8)
}

/// SIB byte for [rsp+disp] addressing (index=none, base=rsp)
const SIB_RSP: u8 = 0x24;

/// Generate the complete x86_64 machine code for the isolate binary.
pub fn generate() -> Vec<u8> {
    let mut a = Asm::new();

    // Forward-declare all labels
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

    let lbl_sigaction = a.label();

    // ========== _start ==========

    // mov rbp, rsp                    ; save stack pointer
    a.emit(&[0x48, 0x89, 0xE5]);

    // mov r8, [rsp]                   ; r8 = argc
    a.emit(&[
        rex(true, true, false, false),
        0x8B,
        modrm(0, R8, 4),
        SIB_RSP,
    ]);

    // cmp r8, 5                       ; argc >= 5?
    a.emit(&[rex(true, false, false, true), 0x83, modrm(3, 7, R8), 5]);

    // jl usage_error
    a.jcc_near(0x7C, usage_error);

    // --- Parse UID (argv[1]) ---
    // mov rdi, [rbp + 16]             ; argv[1]
    a.emit(&[0x48, 0x8B, modrm(1, RDI, RBP), 16]);
    a.call(atoi);
    // mov r12, rax                    ; r12 = uid
    a.emit(&[rex(true, false, false, true), 0x89, modrm(3, RAX, R12)]);

    // --- Parse GID (argv[2]) ---
    // mov rdi, [rbp + 24]             ; argv[2]
    a.emit(&[0x48, 0x8B, modrm(1, RDI, RBP), 24]);
    a.call(atoi);
    // mov r13, rax                    ; r13 = gid
    a.emit(&[rex(true, false, false, true), 0x89, modrm(3, RAX, R13)]);

    // --- unshare(CLONE_NEWPID | CLONE_NEWIPC) ---
    // mov eax, SYS_UNSHARE (272)
    a.emit(&[0xB8]);
    a.emit(&(SYS_UNSHARE as u32).to_le_bytes());
    // mov edi, CLONE_NEWPID | CLONE_NEWIPC
    a.emit(&[0xBF]);
    a.emit(&(CLONE_NEWPID | CLONE_NEWIPC).to_le_bytes());
    // syscall
    a.emit(&[0x0F, 0x05]);
    // test rax, rax
    a.emit(&[0x48, 0x85, 0xC0]);
    // js err_unshare                  ; (near: error handlers are far)
    a.jcc_near(0x78, err_unshare);

    // --- fork() ---
    // mov eax, SYS_FORK
    a.emit(&[0xB8]);
    a.emit(&(SYS_FORK as u32).to_le_bytes());
    // syscall
    a.emit(&[0x0F, 0x05]);
    // test rax, rax
    a.emit(&[0x48, 0x85, 0xC0]);
    // js err_fork                     ; rax < 0 = error (near)
    a.jcc_near(0x78, err_fork);
    // jnz parent_path                 ; rax > 0 = parent (child pid)
    a.jcc_near(0x75, parent_path);

    // ========== Child path (rax == 0) ==========
    a.bind(child_path);

    // --- mount("proc", "/proc", "proc", MS_NOSUID|MS_NODEV|MS_NOEXEC, NULL) ---
    // mov eax, SYS_MOUNT (165)
    a.emit(&[0xB8]);
    a.emit(&(SYS_MOUNT as u32).to_le_bytes());
    // lea rdi, [rip + str_proc]       ; source = "proc"
    a.lea_rdi_rip(lbl_str_proc);
    // lea rsi, [rip + str_slash_proc] ; target = "/proc"
    a.lea_rsi_rip(lbl_str_slash_proc);
    // lea rdx, [rip + str_proc]       ; fstype = "proc"
    // (reuse str_proc for rdx -- lea rdx, [rip + disp32])
    a.emit(&[0x48, 0x8D, 0x15]); // lea rdx, [rip + disp32]
    let offset = a.pos();
    a.emit(&[0; 4]);
    a.fixups.push(Fixup {
        offset,
        label: lbl_str_proc.0,
        insn_end: a.pos(),
        size: 4,
    });
    // mov r10d, MS_NOSUID | MS_NODEV | MS_NOEXEC
    a.emit(&[0x41, 0xBA]); // mov r10d, imm32
    a.emit(&(MS_NOSUID | MS_NODEV | MS_NOEXEC).to_le_bytes());
    // xor r8d, r8d                    ; data = NULL
    a.emit(&[0x45, 0x31, 0xC0]);
    // syscall
    a.emit(&[0x0F, 0x05]);
    // test rax, rax
    a.emit(&[0x48, 0x85, 0xC0]);
    // js err_mount                    ; (near: error handlers are far)
    a.jcc_near(0x78, err_mount);

    // --- prctl(PR_CAPBSET_DROP, CAP_SYS_ADMIN) ---
    // Best-effort: may fail with EPERM when CAP_SETPCAP is not in the
    // effective set (e.g. capabilities drop ALL). In that case the systemd
    // unit's CapabilityBoundingSet already restricts CAP_SYS_ADMIN.
    // mov eax, SYS_PRCTL (157)
    a.emit(&[0xB8]);
    a.emit(&(SYS_PRCTL as u32).to_le_bytes());
    // mov edi, PR_CAPBSET_DROP
    a.emit(&[0xBF]);
    a.emit(&PR_CAPBSET_DROP.to_le_bytes());
    // mov esi, CAP_SYS_ADMIN
    a.emit(&[0xBE]);
    a.emit(&CAP_SYS_ADMIN.to_le_bytes());
    // syscall
    a.emit(&[0x0F, 0x05]);
    // (ignore return value; best-effort drop)

    // --- Conditional privilege drop: skip if uid == 0 ---
    // test r12d, r12d                 ; uid == 0?
    a.emit(&[0x45, 0x85, modrm(3, R12, R12)]);
    // jz skip_privdrop
    a.jcc_near(0x74, skip_privdrop);

    // --- setgroups(0, NULL) ---
    a.emit(&[0xB8]);
    a.emit(&(SYS_SETGROUPS as u32).to_le_bytes());
    a.emit(&[0x31, 0xFF]); // xor edi, edi
    a.emit(&[0x31, 0xF6]); // xor esi, esi
    a.emit(&[0x0F, 0x05]); // syscall
    a.emit(&[0x48, 0x85, 0xC0]); // test rax, rax
    a.jcc_near(0x78, err_setgroups);

    // --- setgid(gid) ---
    a.emit(&[0xB8]);
    a.emit(&(SYS_SETGID as u32).to_le_bytes());
    // mov edi, r13d
    a.emit(&[0x44, 0x89, modrm(3, R13, RDI)]);
    a.emit(&[0x0F, 0x05]);
    a.emit(&[0x48, 0x85, 0xC0]);
    a.jcc_near(0x78, err_setgid);

    // --- setuid(uid) ---
    a.emit(&[0xB8]);
    a.emit(&(SYS_SETUID as u32).to_le_bytes());
    // mov edi, r12d
    a.emit(&[0x44, 0x89, modrm(3, R12, RDI)]);
    a.emit(&[0x0F, 0x05]);
    a.emit(&[0x48, 0x85, 0xC0]);
    a.jcc_near(0x78, err_setuid);

    a.bind(skip_privdrop);

    // --- chdir(argv[3]) ---
    a.emit(&[0xB8]);
    a.emit(&(SYS_CHDIR as u32).to_le_bytes());
    a.emit(&[0x48, 0x8B, modrm(1, RDI, RBP), 32]); // mov rdi, [rbp + 32]
    a.emit(&[0x0F, 0x05]);
    a.emit(&[0x48, 0x85, 0xC0]);
    a.jcc_near(0x78, err_chdir);

    // --- execve(argv[4], &argv[4..], envp) ---
    a.emit(&[0x48, 0x8B, modrm(1, RDI, RBP), 40]); // mov rdi, [rbp + 40] ; filename
    a.emit(&[0x48, 0x8D, modrm(1, RSI, RBP), 40]); // lea rsi, [rbp + 40] ; argv
                                                   // envp = rbp + (argc + 2) * 8
    a.emit(&[0x48, 0x8B, modrm(1, RDX, RBP), 0]); // mov rdx, [rbp]      ; argc
    a.emit(&[0x48, 0x83, modrm(3, 0, RDX), 2]); // add rdx, 2
    a.emit(&[0x48, 0xC1, modrm(3, 4, RDX), 3]); // shl rdx, 3
    a.emit(&[0x48, 0x01, modrm(3, RBP, RDX)]); // add rdx, rbp
    a.emit(&[0xB8]);
    a.emit(&(SYS_EXECVE as u32).to_le_bytes());
    a.emit(&[0x0F, 0x05]);
    // execve only returns on error; fall through

    // ========== Error handlers ==========

    a.bind(err_execve);
    a.lea_rsi_rip(lbl_msg_execve);
    a.emit(&[0xBA]);
    a.emit(&(MSG_EXECVE.len() as u32).to_le_bytes());
    a.jmp_short(error_exit);

    a.bind(err_unshare);
    a.lea_rsi_rip(lbl_msg_unshare);
    a.emit(&[0xBA]);
    a.emit(&(MSG_UNSHARE.len() as u32).to_le_bytes());
    a.jmp_short(error_exit);

    a.bind(err_fork);
    a.lea_rsi_rip(lbl_msg_fork);
    a.emit(&[0xBA]);
    a.emit(&(MSG_FORK.len() as u32).to_le_bytes());
    a.jmp_short(error_exit);

    a.bind(err_mount);
    a.lea_rsi_rip(lbl_msg_mount);
    a.emit(&[0xBA]);
    a.emit(&(MSG_MOUNT.len() as u32).to_le_bytes());
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
    a.emit(&[0xB8]);
    a.emit(&(SYS_WRITE as u32).to_le_bytes());
    a.emit(&[0xBF]);
    a.emit(&2u32.to_le_bytes()); // stderr
    a.emit(&[0x0F, 0x05]);
    a.emit(&[0xB8]);
    a.emit(&(SYS_EXIT as u32).to_le_bytes());
    a.emit(&[0xBF]);
    a.emit(&1u32.to_le_bytes());
    a.emit(&[0x0F, 0x05]);

    // ========== Parent path ==========
    // rax = child PID. Save it in r14, then ignore signals and wait.
    a.bind(parent_path);

    // mov r14, rax                    ; r14 = child pid
    a.emit(&[rex(true, false, false, true), 0x89, modrm(3, RAX, R14)]);

    // --- Ignore signals: rt_sigaction(sig, {SIG_IGN, 0, 0, 0}, NULL, 8) ---
    // We need a sigaction struct on the stack:
    //   sa_handler = SIG_IGN (1)
    //   sa_flags   = 0
    //   sa_restorer = 0
    //   sa_mask    = 0
    // That's 32 bytes on x86_64 (handler:8, flags:8, restorer:8, mask:8 minimum).
    // Actually the kernel sigaction on x86_64 is:
    //   __sighandler_t sa_handler;   // 8 bytes
    //   unsigned long  sa_flags;     // 8 bytes
    //   __sigrestore_t sa_restorer;  // 8 bytes
    //   sigset_t       sa_mask;      // 8 bytes (kernel expects sigsetsize=8)
    // = 32 bytes total

    // sub rsp, 32                     ; allocate sigaction struct on stack
    a.emit(&[0x48, 0x83, 0xEC, 32]);

    // mov qword [rsp], SIG_IGN        ; sa_handler = SIG_IGN (1)
    a.emit(&[0x48, 0xC7, 0x04, SIB_RSP]); // mov [rsp], imm32 sign-extended
    a.emit(&(SIG_IGN as u32).to_le_bytes());

    // mov qword [rsp + 8], 0          ; sa_flags = 0
    a.emit(&[0x48, 0xC7, 0x44, SIB_RSP, 8]);
    a.emit(&0u32.to_le_bytes());

    // mov qword [rsp + 16], 0         ; sa_restorer = 0
    a.emit(&[0x48, 0xC7, 0x44, SIB_RSP, 16]);
    a.emit(&0u32.to_le_bytes());

    // mov qword [rsp + 24], 0         ; sa_mask = 0
    a.emit(&[0x48, 0xC7, 0x44, SIB_RSP, 24]);
    a.emit(&0u32.to_le_bytes());

    // Call rt_sigaction for each signal: SIGTERM, SIGINT, SIGHUP, SIGQUIT
    a.bind(lbl_sigaction);
    for sig in [SIGTERM, SIGINT, SIGHUP, SIGQUIT] {
        // mov eax, SYS_RT_SIGACTION
        a.emit(&[0xB8]);
        a.emit(&(SYS_RT_SIGACTION as u32).to_le_bytes());
        // mov edi, sig
        a.emit(&[0xBF]);
        a.emit(&(sig as u32).to_le_bytes());
        // mov rsi, rsp                ; new action = struct on stack
        a.emit(&[0x48, 0x89, 0xE6]);
        // xor edx, edx                ; old action = NULL
        a.emit(&[0x31, 0xD2]);
        // mov r10d, 8                 ; sigsetsize = 8
        a.emit(&[0x41, 0xBA]);
        a.emit(&8u32.to_le_bytes());
        // syscall
        a.emit(&[0x0F, 0x05]);
        // (ignore errors -- signals may already be ignored)
    }

    // Restore stack
    // add rsp, 32
    a.emit(&[0x48, 0x83, 0xC4, 32]);

    // --- wait4(child, &status, 0, NULL) ---
    // Allocate 4 bytes on stack for status
    // sub rsp, 8                      ; align + status storage
    a.emit(&[0x48, 0x83, 0xEC, 8]);

    a.bind(wait_loop);
    // mov eax, SYS_WAIT4
    a.emit(&[0xB8]);
    a.emit(&(SYS_WAIT4 as u32).to_le_bytes());
    // mov edi, r14d                   ; pid = child
    a.emit(&[0x44, 0x89, modrm(3, R14, RDI)]);
    // mov rsi, rsp                    ; &status
    a.emit(&[0x48, 0x89, 0xE6]);
    // xor edx, edx                    ; options = 0
    a.emit(&[0x31, 0xD2]);
    // xor r10d, r10d                  ; rusage = NULL
    a.emit(&[0x45, 0x31, 0xD2]);
    // syscall
    a.emit(&[0x0F, 0x05]);

    // cmp rax, -EINTR (-4)            ; EINTR = 4
    a.emit(&[0x48, 0x83, 0xF8, 0xFC]); // cmp rax, -4 (sign-extended imm8)
                                       // je wait_loop                    ; retry on EINTR
    a.jcc_short(0x74, wait_loop);

    // Load status into edi
    // mov edi, [rsp]
    a.emit(&[0x8B, 0x3C, SIB_RSP]);

    // Check WIFEXITED: (status & 0x7F) == 0
    // mov eax, edi
    a.emit(&[0x89, 0xF8]);
    // and eax, 0x7F
    a.emit(&[0x83, 0xE0, 0x7F]);
    // jz child_exited
    a.jcc_short(0x74, child_exited);

    // Check WIFSIGNALED: ((status & 0x7F) + 1) >> 1 > 0
    // We already have (status & 0x7F) in eax.
    // inc eax
    a.emit(&[0xFF, 0xC0]);
    // shr eax, 1
    a.emit(&[0xD1, 0xE8]);
    // jnz child_signaled              ; signaled
    a.jcc_short(0x75, child_signaled);

    // Unknown status -- exit 1
    a.emit(&[0xB8]);
    a.emit(&(SYS_EXIT as u32).to_le_bytes());
    a.emit(&[0xBF]);
    a.emit(&1u32.to_le_bytes());
    a.emit(&[0x0F, 0x05]);

    // child_exited: exit((status >> 8) & 0xFF) = WEXITSTATUS
    a.bind(child_exited);
    // edi still has status
    // shr edi, 8
    a.emit(&[0xC1, 0xEF, 8]);
    // and edi, 0xFF
    a.emit(&[0x81, 0xE7]);
    a.emit(&0xFFu32.to_le_bytes());
    a.emit(&[0xB8]);
    a.emit(&(SYS_EXIT as u32).to_le_bytes());
    a.emit(&[0x0F, 0x05]);

    // child_signaled: exit(128 + (status & 0x7F)) = 128 + WTERMSIG
    a.bind(child_signaled);
    // edi still has status
    // and edi, 0x7F
    a.emit(&[0x83, 0xE7, 0x7F]);
    // add edi, 128
    a.emit(&[0x81, 0xC7]);
    a.emit(&128u32.to_le_bytes());
    a.emit(&[0xB8]);
    a.emit(&(SYS_EXIT as u32).to_le_bytes());
    a.emit(&[0x0F, 0x05]);

    // ========== atoi subroutine ==========
    // Input: rdi = pointer to null-terminated ASCII decimal string
    // Output: rax = parsed value (guaranteed to fit in u32)
    // Clobbers: rcx, rdi
    // On bad input or overflow: jumps to error_exit (does not return)

    a.bind(atoi);
    a.emit(&[0x31, 0xC0]); // xor eax, eax
    a.emit(&[0x0F, 0xB6, modrm(0, RCX, RDI)]); // movzx ecx, byte [rdi]
    a.emit(&[0x84, 0xC9]); // test cl, cl
    a.jcc_short(0x74, atoi_error); // jz atoi_error

    a.bind(atoi_loop);
    a.emit(&[0x80, 0xE9, 0x30]); // sub cl, '0'
    a.emit(&[0x80, 0xF9, 9]); // cmp cl, 9
    a.jcc_short(0x77, atoi_error); // ja atoi_error
    a.emit(&[0x48, 0x6B, 0xC0, 10]); // imul rax, rax, 10
    a.emit(&[0x48, 0x01, modrm(3, RCX, RAX)]); // add rax, rcx
    a.emit(&[0x48, 0xFF, modrm(3, 0, RDI)]); // inc rdi
    a.emit(&[0x0F, 0xB6, modrm(0, RCX, RDI)]); // movzx ecx, byte [rdi]
    a.emit(&[0x84, 0xC9]); // test cl, cl
    a.jcc_short(0x75, atoi_loop); // jnz atoi_loop

    // Overflow check: reject values > u32 max
    a.emit(&[0xB9]);
    a.emit(&0xFFFFFFFFu32.to_le_bytes()); // mov ecx, 0xFFFFFFFF
    a.emit(&[0x48, 0x39, modrm(3, RCX, RAX)]); // cmp rax, rcx
    a.jcc_short(0x77, atoi_error); // ja atoi_error

    a.emit(&[0xC3]); // ret

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
    fn code_starts_with_mov_rbp_rsp() {
        let code = generate();
        // mov rbp, rsp = 48 89 E5
        assert_eq!(&code[0..3], &[0x48, 0x89, 0xE5]);
    }

    #[test]
    fn code_contains_syscall_instructions() {
        let code = generate();
        let count = code.windows(2).filter(|w| w == &[0x0F, 0x05]).count();
        // unshare, fork, mount, prctl (best-effort), setgroups, setgid, setuid, chdir, execve,
        // 4x rt_sigaction, wait4, write, exit (error_exit),
        // 3x exit (parent: unknown/exited/signaled)
        // = 9 + 4 + 1 + 2 + 3 = 19
        assert!(
            count >= 15,
            "expected at least 15 syscall instructions, got {count}"
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
        let has_guard = code.windows(5).any(|w| w == [0xB9, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert!(has_guard, "missing u32 overflow guard in atoi");
    }

    #[test]
    fn code_contains_proc_strings() {
        let code = generate();
        // The binary should contain "proc\0" and "/proc\0"
        let has_proc = code.windows(5).any(|w| w == b"proc\0");
        let has_slash_proc = code.windows(6).any(|w| w == b"/proc\0");
        assert!(has_proc, "missing 'proc' string");
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
