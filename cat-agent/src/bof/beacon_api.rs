//! Beacon Object File API compatibility layer.
//!
//! Provides C-callable functions that BOFs expect from Cobalt Strike's Beacon:
//! - Output: BeaconPrintf, BeaconOutput, BeaconOutputType
//! - Data parsing: BeaconDataParse, BeaconDataInt, BeaconDataShort, BeaconDataExtract, BeaconDataLength
//! - Format buffer: BeaconFormatAlloc, BeaconFormatPrintf, BeaconFormatToString, BeaconFormatFree, BeaconFormatReset, BeaconFormatAppend, BeaconFormatInt
//!
//! Output is captured in a thread-local buffer and harvested after BOF execution.

#![cfg(target_os = "windows")]

use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::{c_char, c_int, c_short, c_void, CStr};

// ── Thread-local output buffer ────────────────────────────────────────────────

thread_local! {
    static BOF_OUTPUT: RefCell<String> = RefCell::new(String::with_capacity(4096));
}

/// Append text to the BOF output buffer.
fn output_append(text: &str) {
    BOF_OUTPUT.with(|buf| buf.borrow_mut().push_str(text));
}

/// Take all accumulated output and reset the buffer.
pub fn take_output() -> String {
    BOF_OUTPUT.with(|buf| std::mem::take(&mut *buf.borrow_mut()))
}

/// Clear the output buffer (e.g. before a BOF run).
pub fn clear_output() {
    BOF_OUTPUT.with(|buf| buf.borrow_mut().clear());
}

// ── BeaconData* (argument parsing) ────────────────────────────────────────────

/// Parser state for BOF arguments.
/// Layout matches Cobalt Strike's `datap` struct.
#[repr(C)]
pub struct BeaconDataParser {
    /// Pointer to the start of the original data buffer.
    original: *const u8,
    /// Current read position.
    buffer: *const u8,
    /// Number of bytes remaining.
    length: c_int,
    /// Total size of the original buffer.
    size: c_int,
}

/// `void BeaconDataParse(datap* parser, char* buffer, int size)`
///
/// Initialize the argument parser from raw BOF argument bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BeaconDataParse(
    parser: *mut BeaconDataParser,
    buffer: *const u8,
    size: c_int,
) {
    if parser.is_null() {
        return;
    }
    unsafe {
        (*parser).original = buffer;
        (*parser).buffer = buffer;
        (*parser).length = size;
        (*parser).size = size;
    }
}

/// `int BeaconDataInt(datap* parser)`
///
/// Read a 4-byte big-endian integer from the argument stream.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BeaconDataInt(parser: *mut BeaconDataParser) -> c_int {
    if parser.is_null() {
        return 0;
    }
    unsafe {
        if (*parser).length < 4 {
            return 0;
        }
        let ptr = (*parser).buffer;
        let val = i32::from_be_bytes([*ptr, *ptr.add(1), *ptr.add(2), *ptr.add(3)]);
        (*parser).buffer = (*parser).buffer.add(4);
        (*parser).length -= 4;
        val as c_int
    }
}

/// `short BeaconDataShort(datap* parser)`
///
/// Read a 2-byte big-endian short from the argument stream.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BeaconDataShort(parser: *mut BeaconDataParser) -> c_short {
    if parser.is_null() {
        return 0;
    }
    unsafe {
        if (*parser).length < 2 {
            return 0;
        }
        let ptr = (*parser).buffer;
        let val = i16::from_be_bytes([*ptr, *ptr.add(1)]);
        (*parser).buffer = (*parser).buffer.add(2);
        (*parser).length -= 2;
        val as c_short
    }
}

/// `int BeaconDataLength(datap* parser)`
///
/// Return the number of bytes remaining in the argument stream.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BeaconDataLength(parser: *mut BeaconDataParser) -> c_int {
    if parser.is_null() {
        return 0;
    }
    unsafe { (*parser).length }
}

/// `char* BeaconDataExtract(datap* parser, int* out_len)`
///
/// Extract a length-prefixed byte blob: 4-byte BE length, then N bytes.
/// Returns pointer to the data within the argument buffer. Sets `*out_len` to N.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BeaconDataExtract(
    parser: *mut BeaconDataParser,
    out_len: *mut c_int,
) -> *const u8 {
    if parser.is_null() {
        if !out_len.is_null() {
            unsafe { *out_len = 0 };
        }
        return std::ptr::null();
    }
    unsafe {
        if (*parser).length < 4 {
            if !out_len.is_null() {
                *out_len = 0;
            }
            return std::ptr::null();
        }
        let ptr = (*parser).buffer;
        let len = u32::from_be_bytes([*ptr, *ptr.add(1), *ptr.add(2), *ptr.add(3)]) as c_int;
        (*parser).buffer = (*parser).buffer.add(4);
        (*parser).length -= 4;

        if len <= 0 || len > (*parser).length {
            if !out_len.is_null() {
                *out_len = 0;
            }
            return std::ptr::null();
        }

        let data_ptr = (*parser).buffer;
        (*parser).buffer = (*parser).buffer.add(len as usize);
        (*parser).length -= len;

        if !out_len.is_null() {
            *out_len = len;
        }
        data_ptr
    }
}

// ── BeaconOutput* (output capture) ────────────────────────────────────────────

/// `void BeaconPrintf(int type, const char* fmt, ...)`
///
/// BOFs call this with a printf-style format string. We only capture the format
/// string itself (no varargs expansion in Rust FFI). This is the standard CS
/// behaviour for simple string output.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BeaconPrintf(_typ: c_int, fmt: *const c_char) {
    if fmt.is_null() {
        return;
    }
    let s = unsafe { CStr::from_ptr(fmt) };
    if let Ok(text) = s.to_str() {
        output_append(text);
        output_append("\n");
    }
}

/// `void BeaconOutput(int type, const char* data, int len)`
///
/// Append raw bytes to the output buffer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BeaconOutput(_typ: c_int, data: *const c_char, len: c_int) {
    if data.is_null() || len <= 0 {
        return;
    }
    let slice = unsafe { std::slice::from_raw_parts(data as *const u8, len as usize) };
    let text = String::from_utf8_lossy(slice);
    output_append(&text);
}

/// Alias for `BeaconOutput` (CS has both).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BeaconOutputType(typ: c_int, data: *const c_char, len: c_int) {
    unsafe { BeaconOutput(typ, data, len) };
}

// ── BeaconFormat* (format buffer) ─────────────────────────────────────────────

/// Format buffer, heap-allocated and identified by pointer address.
/// CS BOFs use `formatp` struct — we store the backing buffer here.
#[repr(C)]
pub struct BeaconFormatBuf {
    /// Pointer to heap buffer.
    buffer: *mut u8,
    /// Current write position (bytes used).
    length: c_int,
    /// Total capacity.
    size: c_int,
    /// Pointer to the original allocation (for free).
    original: *mut u8,
}

/// `void BeaconFormatAlloc(formatp* fmt, int maxsz)`
///
/// Allocate a format buffer of `maxsz` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BeaconFormatAlloc(fmt: *mut BeaconFormatBuf, maxsz: c_int) {
    if fmt.is_null() || maxsz <= 0 {
        return;
    }
    let layout = std::alloc::Layout::from_size_align(maxsz as usize, 1).unwrap();
    let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
    if ptr.is_null() {
        return;
    }
    unsafe {
        (*fmt).buffer = ptr;
        (*fmt).length = 0;
        (*fmt).size = maxsz;
        (*fmt).original = ptr;
    }
}

/// `void BeaconFormatFree(formatp* fmt)`
///
/// Free a format buffer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BeaconFormatFree(fmt: *mut BeaconFormatBuf) {
    if fmt.is_null() {
        return;
    }
    unsafe {
        let ptr = (*fmt).original;
        let size = (*fmt).size;
        if !ptr.is_null() && size > 0 {
            let layout = std::alloc::Layout::from_size_align(size as usize, 1).unwrap();
            std::alloc::dealloc(ptr, layout);
        }
        (*fmt).buffer = std::ptr::null_mut();
        (*fmt).original = std::ptr::null_mut();
        (*fmt).length = 0;
        (*fmt).size = 0;
    }
}

/// `void BeaconFormatReset(formatp* fmt)`
///
/// Reset the write position to the start.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BeaconFormatReset(fmt: *mut BeaconFormatBuf) {
    if fmt.is_null() {
        return;
    }
    unsafe {
        (*fmt).buffer = (*fmt).original;
        (*fmt).length = 0;
    }
}

/// `void BeaconFormatAppend(formatp* fmt, const char* data, int len)`
///
/// Append raw bytes to the format buffer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BeaconFormatAppend(
    fmt: *mut BeaconFormatBuf,
    data: *const u8,
    len: c_int,
) {
    if fmt.is_null() || data.is_null() || len <= 0 {
        return;
    }
    unsafe {
        let remaining = (*fmt).size - (*fmt).length;
        if len > remaining {
            return; // silently truncate, like CS
        }
        std::ptr::copy_nonoverlapping(data, (*fmt).buffer.add((*fmt).length as usize), len as usize);
        (*fmt).length += len;
    }
}

/// `void BeaconFormatPrintf(formatp* fmt, const char* fmtstr, ...)`
///
/// Append a C string to the format buffer. Varargs not expanded.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BeaconFormatPrintf(fmt: *mut BeaconFormatBuf, fmtstr: *const c_char) {
    if fmt.is_null() || fmtstr.is_null() {
        return;
    }
    let s = unsafe { CStr::from_ptr(fmtstr) };
    let bytes = s.to_bytes();
    unsafe { BeaconFormatAppend(fmt, bytes.as_ptr(), bytes.len() as c_int) };
}

/// `void BeaconFormatInt(formatp* fmt, int value)`
///
/// Append a 4-byte big-endian integer to the format buffer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BeaconFormatInt(fmt: *mut BeaconFormatBuf, value: c_int) {
    let bytes = (value as i32).to_be_bytes();
    unsafe { BeaconFormatAppend(fmt, bytes.as_ptr(), 4) };
}

/// `char* BeaconFormatToString(formatp* fmt, int* out_len)`
///
/// Return a pointer to the format buffer contents and set `*out_len`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BeaconFormatToString(
    fmt: *mut BeaconFormatBuf,
    out_len: *mut c_int,
) -> *const u8 {
    if fmt.is_null() {
        if !out_len.is_null() {
            unsafe { *out_len = 0 };
        }
        return std::ptr::null();
    }
    unsafe {
        if !out_len.is_null() {
            *out_len = (*fmt).length;
        }
        (*fmt).original
    }
}

// ── Symbol resolution table ──────────────────────────────────────────────────

/// Build a lookup table mapping `__imp_BeaconXxx` symbol names to function
/// pointers. The BOF loader uses this to resolve Beacon API imports.
pub fn beacon_api_table() -> HashMap<&'static str, usize> {
    let mut m = HashMap::new();
    m.insert("BeaconDataParse", BeaconDataParse as usize);
    m.insert("BeaconDataInt", BeaconDataInt as usize);
    m.insert("BeaconDataShort", BeaconDataShort as usize);
    m.insert("BeaconDataLength", BeaconDataLength as usize);
    m.insert("BeaconDataExtract", BeaconDataExtract as usize);
    m.insert("BeaconPrintf", BeaconPrintf as usize);
    m.insert("BeaconOutput", BeaconOutput as usize);
    m.insert("BeaconOutputType", BeaconOutputType as usize);
    m.insert("BeaconFormatAlloc", BeaconFormatAlloc as usize);
    m.insert("BeaconFormatFree", BeaconFormatFree as usize);
    m.insert("BeaconFormatReset", BeaconFormatReset as usize);
    m.insert("BeaconFormatAppend", BeaconFormatAppend as usize);
    m.insert("BeaconFormatPrintf", BeaconFormatPrintf as usize);
    m.insert("BeaconFormatInt", BeaconFormatInt as usize);
    m.insert("BeaconFormatToString", BeaconFormatToString as usize);
    m
}
