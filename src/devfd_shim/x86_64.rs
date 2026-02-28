// x86_64.rs: Machine code emitter for the devfd shim shared library (x86_64)
//
// Emits raw x86_64 machine code that intercepts open()/openat() libc calls.
// When the path matches /dev/stdin, /dev/stdout, /dev/stderr, /dev/fd/{0,1,2},
// or /proc/self/fd/{0,1,2}, the interceptor returns dup(N) for the
// appropriate fd. All other paths fall through to the real openat syscall.
//
// If the real openat returns ENXIO, the shim uses readlinkat to resolve
// one level of symlink and retries the path matching. This handles cases
// like nginx opening /var/log/nginx/error.log → /dev/stderr.
//
// On error, errno is set via __errno_location() (imported through the GOT)
// and -1 is returned per C convention.
//
// Exported symbols: open, openat, open64, openat64
// (open64/openat64 are aliases; identical on 64-bit Linux)
//
// Linux x86_64 syscall ABI:
//   rax = syscall number
//   rdi, rsi, rdx, r10 = first 4 arguments
//   syscall instruction; return in rax
//   Preserved across syscall: all regs except rax, rcx, r11
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
const SYS_READLINKAT: u16 = 267;

// AT_FDCWD = -100
const AT_FDCWD: i32 = -100;

// errno value
const ENXIO: u8 = 6;

// readlink buffer size
const READLINK_BUFSZ: u8 = 128;

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
/// Returns `(code_bytes, symbols, got_fixups)` where symbols list the exported
/// function names and their offsets within `code_bytes`, and got_fixups list
/// positions that need patching with GOT addresses by the ELF builder.
pub fn generate() -> (Vec<u8>, Vec<elf::Symbol>, Vec<elf::GotFixup>) {
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
    let errno_check = a.label();
    let set_errno = a.label();
    let ok = a.label();
    let try_readlink = a.label();
    let readlink_no_match = a.label();

    // Labels for readlink path matching (reuse pattern from main path matching)
    let rl_check_dev_fd = a.label();
    let rl_check_proc = a.label();

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
    // jmp do_openat
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
    // jne check_dev_fd
    a.jcc_near(0x75, check_dev_fd);

    // Matched "/dev/std" — check suffix at path[8].
    // mov eax, [rsi+8]          ; eax = *(uint32_t*)(path+8)
    a.emit(&[0x8B, 0x46, 0x08]);

    // Check "in\0" — only need 3 bytes. Mask to 24 bits.
    // mov ecx, eax
    a.emit(&[0x89, 0xC1]);
    // and ecx, 0x00FFFFFF
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

    // No suffix match — fall through to real openat
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
    // jne check_proc
    a.jcc_near(0x75, check_proc);

    // Matched "/dev/fd/" — check path[8..10] for "0\0", "1\0", "2\0"
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

    // Matched "/proc/se" — check suffix "lf/fd/0\0" (8 bytes) at path[8]
    // mov rax, [rsi+8]
    a.emit(&[0x48, 0x8B, 0x46, 0x08]);

    // movabs rcx, "lf/fd/0\0"
    a.emit(&[0x48, 0xB9]);
    a.emit(&u64::from_le_bytes(*b"lf/fd/0\0").to_le_bytes());
    // cmp rax, rcx
    a.emit(&[0x48, 0x39, 0xC8]);
    a.jcc_near(0x74, dup_fd0);

    // movabs rcx, "lf/fd/1\0"
    a.emit(&[0x48, 0xB9]);
    a.emit(&u64::from_le_bytes(*b"lf/fd/1\0").to_le_bytes());
    // cmp rax, rcx
    a.emit(&[0x48, 0x39, 0xC8]);
    a.jcc_near(0x74, dup_fd1);

    // movabs rcx, "lf/fd/2\0"
    a.emit(&[0x48, 0xB9]);
    a.emit(&u64::from_le_bytes(*b"lf/fd/2\0").to_le_bytes());
    // cmp rax, rcx
    a.emit(&[0x48, 0x39, 0xC8]);
    a.jcc_near(0x74, dup_fd2);

    // Fall through to real openat
    a.jmp_near(fallthrough);

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
    // jmp errno_check
    a.jmp_near(errno_check);

    // ========== fallthrough: real openat syscall ==========
    a.bind(fallthrough);
    // Arguments are already in place: rdi=dirfd, rsi=path, rdx=flags, r10=mode
    // mov eax, SYS_OPENAT
    a.emit(&[0xB8]);
    a.emit(&(SYS_OPENAT as u32).to_le_bytes());
    // syscall
    a.emit(&[0x0F, 0x05]);
    // After syscall: rax=result, rdi=dirfd (preserved), rsi=path (preserved)

    // Check if result is -ENXIO (== -6)
    // cmp rax, -ENXIO
    a.emit(&[0x48, 0x83, 0xF8]); // cmp rax, imm8 (sign-extended)
    a.emit(&[(-6i8) as u8]); // -6 = 0xFA
    // je try_readlink
    a.jcc_near(0x74, try_readlink);
    // Not ENXIO — fall through to errno_check
    a.jmp_near(errno_check);

    // ========== try_readlink: resolve symlink and retry matching ==========
    a.bind(try_readlink);
    // rdi=dirfd (preserved by syscall), rsi=path (preserved by syscall)
    // sub rsp, 128              ; allocate buffer on stack
    // Use imm32 encoding (0x81) because 128 = 0x80 is negative as imm8.
    a.emit(&[0x48, 0x81, 0xEC]);
    a.emit(&(READLINK_BUFSZ as u32).to_le_bytes());

    // readlinkat(dirfd=rdi, path=rsi, buf=rsp, bufsiz=128)
    // rdi already has dirfd, rsi already has path
    // mov rdx, rsp              ; buf
    a.emit(&[0x48, 0x89, 0xE2]);
    // mov r10d, 128             ; bufsiz
    a.emit(&[0x41, 0xBA]);
    a.emit(&(READLINK_BUFSZ as u32).to_le_bytes());
    // mov eax, SYS_READLINKAT
    a.emit(&[0xB8]);
    a.emit(&(SYS_READLINKAT as u32).to_le_bytes());
    // syscall
    a.emit(&[0x0F, 0x05]);

    // Check result: if negative, readlink failed → return ENXIO
    // test rax, rax
    a.emit(&[0x48, 0x85, 0xC0]);
    // js readlink_no_match       ; negative = error
    a.jcc_near(0x78, readlink_no_match);

    // Also check if result >= READLINK_BUFSZ (buffer full, can't null-terminate)
    // cmp rax, 128 (use imm32: 0x80 is negative as sign-extended imm8)
    a.emit(&[0x48, 0x3D]); // cmp rax, imm32
    a.emit(&(READLINK_BUFSZ as u32).to_le_bytes());
    // jge readlink_no_match
    a.jcc_near(0x7D, readlink_no_match);

    // Null-terminate the buffer: buf[rax] = 0
    // mov byte [rsp + rax], 0
    a.emit(&[0xC6, 0x04, 0x04, 0x00]);

    // Now match the readlink result against our patterns.
    // rsi = rsp (point to the resolved path buffer)
    // mov rsi, rsp
    a.emit(&[0x48, 0x89, 0xE6]);

    // Load first 8 bytes of resolved path
    // mov rax, [rsi]
    a.emit(&[0x48, 0x8B, 0x06]);

    // ---- Check "/dev/std" prefix (readlink result) ----
    a.emit(&[0x48, 0xB9]);
    a.emit(&u64::from_le_bytes(*b"/dev/std").to_le_bytes());
    a.emit(&[0x48, 0x39, 0xC8]);
    a.jcc_near(0x75, rl_check_dev_fd);

    // Matched "/dev/std" — check suffix
    a.emit(&[0x8B, 0x46, 0x08]); // mov eax, [rsi+8]
    a.emit(&[0x89, 0xC1]); // mov ecx, eax
    a.emit(&[0x81, 0xE1]); // and ecx, 0x00FFFFFF
    a.emit(&0x00FFFFFFu32.to_le_bytes());
    a.emit(&[0x81, 0xF9]); // cmp ecx, "in\0"
    a.emit(&u32::from_le_bytes([b'i', b'n', 0, 0]).to_le_bytes());
    // je → need to deallocate stack and dup fd 0
    // Since we need to clean up the stack, we can't just jump to dup_fd0.
    // We'll use a pattern: set edi to the fd, add rsp, jmp do_dup
    let rl_dup0 = a.label();
    a.jcc_near(0x74, rl_dup0);

    a.emit(&[0x3D]); // cmp eax, "out\0"
    a.emit(&u32::from_le_bytes(*b"out\0").to_le_bytes());
    let rl_dup1 = a.label();
    a.jcc_near(0x74, rl_dup1);

    a.emit(&[0x3D]); // cmp eax, "err\0"
    a.emit(&u32::from_le_bytes(*b"err\0").to_le_bytes());
    let rl_dup2 = a.label();
    a.jcc_near(0x74, rl_dup2);

    a.jmp_near(readlink_no_match);

    // ---- Check "/dev/fd/" prefix (readlink result) ----
    a.bind(rl_check_dev_fd);
    a.emit(&[0x48, 0x8B, 0x06]); // mov rax, [rsi]
    a.emit(&[0x48, 0xB9]); // movabs rcx, "/dev/fd/"
    a.emit(&u64::from_le_bytes(*b"/dev/fd/").to_le_bytes());
    a.emit(&[0x48, 0x39, 0xC8]); // cmp rax, rcx
    a.jcc_near(0x75, rl_check_proc);

    // Matched "/dev/fd/" — check digit
    a.emit(&[0x0F, 0xB7, 0x46, 0x08]); // movzx eax, word [rsi+8]

    a.emit(&[0x66, 0x3D]); // cmp ax, "0\0"
    a.emit(&u16::from_le_bytes([b'0', 0]).to_le_bytes());
    a.jcc_near(0x74, rl_dup0);

    a.emit(&[0x66, 0x3D]); // cmp ax, "1\0"
    a.emit(&u16::from_le_bytes([b'1', 0]).to_le_bytes());
    a.jcc_near(0x74, rl_dup1);

    a.emit(&[0x66, 0x3D]); // cmp ax, "2\0"
    a.emit(&u16::from_le_bytes([b'2', 0]).to_le_bytes());
    a.jcc_near(0x74, rl_dup2);

    a.jmp_near(readlink_no_match);

    // ---- Check "/proc/se" prefix (readlink result) ----
    a.bind(rl_check_proc);
    a.emit(&[0x48, 0x8B, 0x06]); // mov rax, [rsi]
    a.emit(&[0x48, 0xB9]); // movabs rcx, "/proc/se"
    a.emit(&u64::from_le_bytes(*b"/proc/se").to_le_bytes());
    a.emit(&[0x48, 0x39, 0xC8]); // cmp rax, rcx
    a.jcc_near(0x75, readlink_no_match);

    // Matched "/proc/se" — check suffix
    a.emit(&[0x48, 0x8B, 0x46, 0x08]); // mov rax, [rsi+8]

    a.emit(&[0x48, 0xB9]);
    a.emit(&u64::from_le_bytes(*b"lf/fd/0\0").to_le_bytes());
    a.emit(&[0x48, 0x39, 0xC8]);
    a.jcc_short(0x74, rl_dup0);

    a.emit(&[0x48, 0xB9]);
    a.emit(&u64::from_le_bytes(*b"lf/fd/1\0").to_le_bytes());
    a.emit(&[0x48, 0x39, 0xC8]);
    a.jcc_short(0x74, rl_dup1);

    a.emit(&[0x48, 0xB9]);
    a.emit(&u64::from_le_bytes(*b"lf/fd/2\0").to_le_bytes());
    a.emit(&[0x48, 0x39, 0xC8]);
    a.jcc_short(0x74, rl_dup2);

    a.jmp_short(readlink_no_match);

    // ========== readlink dup handlers (deallocate stack, then dup) ==========
    a.bind(rl_dup0);
    a.emit(&[0x48, 0x81, 0xC4]); // add rsp, 128 (imm32: 0x80 is negative as imm8)
    a.emit(&(READLINK_BUFSZ as u32).to_le_bytes());
    a.emit(&[0x31, 0xFF]); // xor edi, edi
    a.jmp_near(do_dup);

    a.bind(rl_dup1);
    a.emit(&[0x48, 0x81, 0xC4]); // add rsp, 128 (imm32: 0x80 is negative as imm8)
    a.emit(&(READLINK_BUFSZ as u32).to_le_bytes());
    a.emit(&[0xBF, 0x01, 0x00, 0x00, 0x00]); // mov edi, 1
    a.jmp_near(do_dup);

    a.bind(rl_dup2);
    a.emit(&[0x48, 0x81, 0xC4]); // add rsp, 128 (imm32: 0x80 is negative as imm8)
    a.emit(&(READLINK_BUFSZ as u32).to_le_bytes());
    a.emit(&[0xBF, 0x02, 0x00, 0x00, 0x00]); // mov edi, 2
    a.jmp_near(do_dup);

    // ========== readlink_no_match: deallocate stack, return ENXIO ==========
    a.bind(readlink_no_match);
    a.emit(&[0x48, 0x81, 0xC4]); // add rsp, 128 (imm32: 0x80 is negative as imm8)
    a.emit(&(READLINK_BUFSZ as u32).to_le_bytes());
    // mov edi, ENXIO
    a.emit(&[0xBF]);
    a.emit(&(ENXIO as u32).to_le_bytes());
    a.jmp_near(set_errno);

    // ========== errno_check: convert raw syscall result to C convention ==========
    // Linux syscalls return -errno on failure (range [-4095, -1]).
    // If result >= 0, return as-is. Otherwise, set errno and return -1.
    a.bind(errno_check);
    // test rax, rax              ; check sign
    a.emit(&[0x48, 0x85, 0xC0]);
    // jns .ok                    ; if non-negative, return as-is
    a.jcc_short(0x79, ok);
    // neg eax                    ; positive errno value in edi
    // (neg on 32-bit eax is fine: errno values are small positive ints)
    a.emit(&[0xF7, 0xD8]); // neg eax
    // mov edi, eax
    a.emit(&[0x89, 0xC7]);
    // fall through to set_errno

    // ========== set_errno: call __errno_location(), set *it = edi, return -1 ==========
    a.bind(set_errno);
    // At this point: edi = positive errno value
    // We need to call __errno_location() via the GOT, then store edi into *rax.
    //
    // Stack alignment: on function entry, rsp % 16 == 8 (return addr pushed by caller).
    // push rdi aligns rsp to 16 and saves the errno value.
    a.emit(&[0x57]); // push rdi  (saves errno value, aligns stack to 16)

    // call [rip + disp32]        ; call *GOT[__errno_location]
    // Opcode: FF 15 <disp32>
    a.emit(&[0xFF, 0x15]);
    let got_disp_offset = a.pos(); // position of the 4-byte displacement
    a.emit(&[0x00, 0x00, 0x00, 0x00]); // placeholder, patched by ELF builder
    let got_disp_end = a.pos(); // instruction end (for RIP-relative calc)

    a.emit(&[0x5F]); // pop rdi   (restore errno value)
    // mov [rax], edi             ; *errno_location = errno_value
    a.emit(&[0x89, 0x38]);
    // mov rax, -1
    a.emit(&[0x48, 0xC7, 0xC0]);
    a.emit(&(-1i32 as u32).to_le_bytes());
    // .ok:
    a.bind(ok);
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

    let got_fixups = vec![elf::GotFixup {
        slot: 0, // __errno_location is import[0]
        offset: got_disp_offset,
        aux: got_disp_end, // instruction end for RIP-relative
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
        assert!(code.len() < 2048, "code too large: {} bytes", code.len());
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
    fn code_contains_three_syscall_instructions() {
        let (code, _, _) = generate();
        let count = code.windows(2).filter(|w| w == &[0x0F, 0x05]).count();
        // SYS_dup + SYS_openat + SYS_readlinkat = 3
        assert_eq!(count, 3, "expected 3 syscall instructions, got {count}");
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
            fixup.aux <= code.len(),
            "GOT fixup aux out of bounds"
        );
    }
}
