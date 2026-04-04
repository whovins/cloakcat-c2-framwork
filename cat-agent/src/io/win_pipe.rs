//! Named pipe server helpers for Windows IPC.

#![cfg(target_os = "windows")]

use anyhow::{bail, Result};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, GetLastError, GENERIC_READ, GENERIC_WRITE, HANDLE,
        INVALID_HANDLE_VALUE, ERROR_PIPE_CONNECTED, ERROR_PIPE_BUSY,
    },
    Storage::FileSystem::{
        CreateFileW, OPEN_EXISTING,
    },
    System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, SetNamedPipeHandleState,
        WaitNamedPipeW,
        PIPE_READMODE_MESSAGE, PIPE_TYPE_MESSAGE, PIPE_WAIT,
    },
};

// PIPE_ACCESS_DUPLEX is a named-pipe open-mode flag (value 0x3).
const PIPE_ACCESS_DUPLEX: u32 = 0x00000003;

/// Create a named pipe server in message mode.
///
/// `name` must be a valid pipe name (e.g. `\\.\pipe\cloakcat`).
///
/// # Safety
/// The returned HANDLE must be closed via [`close_handle`] when no longer needed.
pub fn create_pipe_server(name: &str) -> Result<HANDLE> {
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();

    let h = unsafe {
        CreateNamedPipeW(
            wide.as_ptr(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            1,     // nMaxInstances
            65536, // nOutBufferSize
            65536, // nInBufferSize
            0,     // nDefaultTimeOut (use system default)
            std::ptr::null(),
        )
    };

    if h == INVALID_HANDLE_VALUE {
        let err = unsafe { GetLastError() };
        bail!("CreateNamedPipeW failed: error {err}");
    }

    Ok(h)
}

/// Block until a client connects to the named pipe.
///
/// Handles `ERROR_PIPE_CONNECTED` (client already connected before the call)
/// as a successful connection.
pub fn accept_connection(h: HANDLE) -> Result<()> {
    let ok = unsafe { ConnectNamedPipe(h, std::ptr::null_mut()) };
    if ok == 0 {
        let err = unsafe { GetLastError() };
        if err == ERROR_PIPE_CONNECTED {
            return Ok(());
        }
        bail!("ConnectNamedPipe failed: error {err}");
    }
    Ok(())
}

/// Disconnect the server side of a named pipe, allowing re-use or cleanup.
pub fn disconnect(h: HANDLE) {
    unsafe {
        DisconnectNamedPipe(h);
    }
}

/// Connect to an existing named pipe as a client.
///
/// Opens the pipe with `GENERIC_READ | GENERIC_WRITE` and switches to message-read mode.
///
/// # Safety
/// The returned HANDLE must be closed via [`close_handle`] when no longer needed.
pub fn connect_pipe_client(name: &str) -> Result<HANDLE> {
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();

    let h = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };

    if h == INVALID_HANDLE_VALUE {
        let err = unsafe { GetLastError() };
        bail!("CreateFileW failed for pipe \"{name}\": error {err}");
    }

    let mut mode = PIPE_READMODE_MESSAGE;
    let ok = unsafe {
        SetNamedPipeHandleState(h, &mut mode, std::ptr::null_mut(), std::ptr::null_mut())
    };
    if ok == 0 {
        let err = unsafe { GetLastError() };
        unsafe { CloseHandle(h) };
        bail!("SetNamedPipeHandleState failed: error {err}");
    }

    Ok(h)
}

/// Connect to a named pipe with retry logic for busy pipes.
///
/// On `ERROR_PIPE_BUSY`, waits up to `timeout_ms` milliseconds for the pipe to become
/// available, then retries. Gives up after `max_retries` attempts.
pub fn connect_pipe_client_retry(name: &str, max_retries: u32, timeout_ms: u32) -> Result<HANDLE> {
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();

    for attempt in 0..=max_retries {
        match connect_pipe_client(name) {
            Ok(h) => return Ok(h),
            Err(e) => {
                let err = unsafe { GetLastError() };
                if err != ERROR_PIPE_BUSY || attempt == max_retries {
                    bail!(
                        "connect_pipe_client_retry failed after {} attempts: {e}",
                        attempt + 1
                    );
                }
                let ok = unsafe { WaitNamedPipeW(wide.as_ptr(), timeout_ms) };
                if ok == 0 {
                    bail!("WaitNamedPipeW timed out after {timeout_ms}ms");
                }
            }
        }
    }

    unreachable!()
}

/// RAII wrapper around a Windows pipe HANDLE.
///
/// Automatically closes the handle on drop. Provides framed send/recv
/// via [`win_handle::send_msg`] and [`win_handle::recv_msg`].
pub struct PipeHandle {
    handle: HANDLE,
}

impl PipeHandle {
    /// Wrap a raw HANDLE. The caller transfers ownership — the handle will be
    /// closed when this value is dropped.
    pub fn from_raw(h: HANDLE) -> Self {
        Self { handle: h }
    }

    /// Send a length-prefixed message over the pipe.
    pub fn send(&self, payload: &[u8]) -> Result<()> {
        unsafe { super::win_handle::send_msg(self.handle, payload) }
    }

    /// Receive a length-prefixed message from the pipe.
    pub fn recv(&self) -> Result<Vec<u8>> {
        unsafe { super::win_handle::recv_msg(self.handle) }
    }

    /// Access the underlying raw HANDLE.
    pub fn raw(&self) -> HANDLE {
        self.handle
    }
}

impl Drop for PipeHandle {
    fn drop(&mut self) {
        close_handle(self.handle);
    }
}

/// Close a Windows HANDLE.
pub fn close_handle(h: HANDLE) {
    unsafe {
        CloseHandle(h);
    }
}
