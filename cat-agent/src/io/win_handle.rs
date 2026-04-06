//! Thin wrappers around `WriteFile` / `ReadFile` for raw Windows HANDLEs.
//!
//! Both functions loop to handle partial I/O.

#![cfg(target_os = "windows")]

use anyhow::{bail, Result};
use windows_sys::Win32::Foundation::{GetLastError, HANDLE};

#[link(name = "kernel32")]
unsafe extern "system" {
    fn ReadFile(hFile: HANDLE, lpBuffer: *mut u8, nNumberOfBytesToRead: u32, lpNumberOfBytesRead: *mut u32, lpOverlapped: *mut core::ffi::c_void) -> i32;
    fn WriteFile(hFile: HANDLE, lpBuffer: *const u8, nNumberOfBytesToWrite: u32, lpNumberOfBytesWritten: *mut u32, lpOverlapped: *mut core::ffi::c_void) -> i32;
}

use crate::codec::frame_encode;

const MAX_FRAME_LEN: usize = 16 * 1024 * 1024; // 16 MB — must match codec

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

/// Send a length-prefixed message over a Windows HANDLE.
///
/// # Safety
/// `h` must be a valid, writable Windows HANDLE.
pub unsafe fn send_msg(h: HANDLE, payload: &[u8]) -> Result<()> {
    let frame = frame_encode(payload);
    handle_write(h, &frame)
}

/// Receive a length-prefixed message from a Windows HANDLE.
///
/// # Safety
/// `h` must be a valid, readable Windows HANDLE.
pub unsafe fn recv_msg(h: HANDLE) -> Result<Vec<u8>> {
    // Read 4-byte LE length header
    let mut hdr = [0u8; 4];
    let n = handle_read(h, &mut hdr)?;
    if n < 4 {
        bail!("recv_msg: incomplete header ({n} bytes)");
    }

    let len = u32::from_le_bytes(hdr) as usize;
    if len > MAX_FRAME_LEN {
        bail!("recv_msg: frame length {len} exceeds 16 MB limit");
    }

    // Read payload
    let mut payload = vec![0u8; len];
    if len > 0 {
        let n = handle_read(h, &mut payload)?;
        if n < len {
            bail!("recv_msg: incomplete payload ({n}/{len} bytes)");
        }
    }
    Ok(payload)
}
