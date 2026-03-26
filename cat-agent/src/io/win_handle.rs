//! Thin wrappers around `WriteFile` / `ReadFile` for raw Windows HANDLEs.
//!
//! Both functions loop to handle partial I/O.

#![cfg(target_os = "windows")]

use anyhow::{bail, Result};
use windows_sys::Win32::{
    Foundation::{GetLastError, HANDLE},
    Storage::FileSystem::{ReadFile, WriteFile},
};

/// Write all of `data` to `h`, looping on partial writes.
///
/// # Safety
/// `h` must be a valid, writable Windows HANDLE.
pub unsafe fn handle_write(h: HANDLE, data: &[u8]) -> Result<()> {
    let mut offset = 0usize;
    while offset < data.len() {
        let mut written: u32 = 0;
        let ok = WriteFile(
            h,
            data[offset..].as_ptr(),
            (data.len() - offset) as u32,
            &mut written,
            std::ptr::null_mut(),
        );
        if ok == 0 {
            bail!("WriteFile failed: error {}", GetLastError());
        }
        if written == 0 {
            bail!("WriteFile wrote 0 bytes");
        }
        offset += written as usize;
    }
    Ok(())
}

/// Read from `h` into `buf`, looping on partial reads.
///
/// Returns the total number of bytes read.  A single `ReadFile` returning 0
/// bytes (EOF / pipe closed) stops the loop.
///
/// # Safety
/// `h` must be a valid, readable Windows HANDLE.
pub unsafe fn handle_read(h: HANDLE, buf: &mut [u8]) -> Result<usize> {
    let mut offset = 0usize;
    while offset < buf.len() {
        let mut read: u32 = 0;
        let ok = ReadFile(
            h,
            buf[offset..].as_mut_ptr(),
            (buf.len() - offset) as u32,
            &mut read,
            std::ptr::null_mut(),
        );
        if ok == 0 {
            bail!("ReadFile failed: error {}", GetLastError());
        }
        if read == 0 {
            break; // EOF
        }
        offset += read as usize;
    }
    Ok(offset)
}
