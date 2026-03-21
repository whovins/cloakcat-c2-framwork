//! COFF (Common Object File Format) parser for BOF execution.
//!
//! Parses `.o` files produced by MSVC or MinGW into structured types.
//! Supports x86-64 COFF only (Machine = 0x8664).

#![cfg(target_os = "windows")]

use anyhow::{bail, ensure, Context, Result};

// ── Machine types ────────────────────────────────────────────────────────────

pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;

// ── Section characteristics (selected flags) ─────────────────────────────────

pub const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
pub const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
pub const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
pub const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

// ── Symbol storage classes ───────────────────────────────────────────────────

pub const IMAGE_SYM_CLASS_EXTERNAL: u8 = 2;
pub const IMAGE_SYM_CLASS_STATIC: u8 = 3;
pub const IMAGE_SYM_CLASS_LABEL: u8 = 6;
pub const IMAGE_SYM_CLASS_FILE: u8 = 103;

// ── Relocation types (x86-64) ─────────────────────────────────────────────────

pub const IMAGE_REL_AMD64_ABSOLUTE: u16 = 0x0000;
pub const IMAGE_REL_AMD64_ADDR64: u16 = 0x0001;
pub const IMAGE_REL_AMD64_ADDR32: u16 = 0x0002;
pub const IMAGE_REL_AMD64_ADDR32NB: u16 = 0x0003;
pub const IMAGE_REL_AMD64_REL32: u16 = 0x0004;

// ── On-disk record sizes ──────────────────────────────────────────────────────

const COFF_HEADER_SIZE: usize = 20;
const SECTION_HEADER_SIZE: usize = 40;
const SYMBOL_SIZE: usize = 18;
const RELOC_SIZE: usize = 10;

// ── Public types ──────────────────────────────────────────────────────────────

/// COFF file header (IMAGE_FILE_HEADER).
#[derive(Debug, Clone)]
pub struct CoffHeader {
    /// Target machine type. Must be `IMAGE_FILE_MACHINE_AMD64` (0x8664).
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

/// Section header (IMAGE_SECTION_HEADER).
#[derive(Debug, Clone)]
pub struct SectionHeader {
    /// Up to 8 bytes; NUL-padded. Long names use `/offset` into string table.
    pub name_raw: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_line_numbers: u32,
    pub number_of_relocations: u16,
    pub number_of_line_numbers: u16,
    pub characteristics: u32,
}

impl SectionHeader {
    /// Resolve the human-readable section name.
    ///
    /// If `name_raw` starts with `/`, the rest is a decimal offset into
    /// `string_table`; otherwise it is a NUL-terminated inline string.
    pub fn name<'a>(&'a self, string_table: &'a [u8]) -> &'a str {
        if self.name_raw[0] == b'/' {
            // Long-name: `/decimal_offset`
            let digits = self
                .name_raw
                .iter()
                .skip(1)
                .take_while(|&&b| b != 0)
                .copied()
                .collect::<Vec<u8>>();
            if let Ok(s) = std::str::from_utf8(&digits) {
                if let Ok(offset) = s.trim().parse::<usize>() {
                    if offset < string_table.len() {
                        let tail = &string_table[offset..];
                        let end = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
                        if let Ok(name) = std::str::from_utf8(&tail[..end]) {
                            return name;
                        }
                    }
                }
            }
            "<invalid-longname>"
        } else {
            let end = self
                .name_raw
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(self.name_raw.len());
            std::str::from_utf8(&self.name_raw[..end]).unwrap_or("<invalid-utf8>")
        }
    }

    /// Raw section data slice from the COFF byte blob.
    pub fn raw_data<'a>(&self, data: &'a [u8]) -> Result<&'a [u8]> {
        let start = self.pointer_to_raw_data as usize;
        let end = start
            .checked_add(self.size_of_raw_data as usize)
            .context("section raw data range overflow")?;
        ensure!(end <= data.len(), "section raw data out of bounds");
        Ok(&data[start..end])
    }
}

/// A parsed section: header + relocations.
#[derive(Debug, Clone)]
pub struct Section {
    pub header: SectionHeader,
    pub relocations: Vec<Relocation>,
}

/// COFF symbol table entry (IMAGE_SYMBOL).
#[derive(Debug, Clone)]
pub struct Symbol {
    /// Resolved symbol name (inline or from string table).
    pub name: String,
    /// Symbol value (e.g. offset within section, or address).
    pub value: u32,
    /// 1-based section index; 0 = undefined, -1 = absolute, -2 = debug.
    pub section_number: i16,
    pub typ: u16,
    pub storage_class: u8,
    /// Number of auxiliary records that follow (not parsed here).
    pub number_of_aux_symbols: u8,
}

impl Symbol {
    /// `true` if this symbol is externally visible (imported / exported).
    pub fn is_external(&self) -> bool {
        self.storage_class == IMAGE_SYM_CLASS_EXTERNAL
    }

    /// `true` if the symbol is undefined (section_number == 0).
    pub fn is_undefined(&self) -> bool {
        self.section_number == 0
    }
}

/// COFF relocation entry (IMAGE_RELOCATION).
#[derive(Debug, Clone)]
pub struct Relocation {
    /// Offset within the section where the fixup is applied.
    pub virtual_address: u32,
    /// Index into the symbol table.
    pub symbol_table_index: u32,
    /// Relocation type (machine-specific).
    pub typ: u16,
}

/// Top-level parsed COFF object file.
#[derive(Debug, Clone)]
pub struct CoffFile {
    pub header: CoffHeader,
    pub sections: Vec<Section>,
    pub symbols: Vec<Symbol>,
    /// Raw string table bytes (starts at byte 4 which is the 4-byte length field).
    pub string_table: Vec<u8>,
}

// ── Parsing ───────────────────────────────────────────────────────────────────

impl CoffFile {
    /// Parse a COFF `.o` file from raw bytes.
    pub fn parse(data: &[u8]) -> Result<Self> {
        ensure!(
            data.len() >= COFF_HEADER_SIZE,
            "data too short for COFF header ({} bytes)",
            data.len()
        );

        // ── COFF header ───────────────────────────────────────────────────────
        let header = parse_coff_header(data)?;

        ensure!(
            header.machine == IMAGE_FILE_MACHINE_AMD64,
            "unsupported machine type 0x{:04X} (expected AMD64 0x8664)",
            header.machine
        );
        ensure!(
            header.size_of_optional_header == 0,
            "optional header present (size {}); not a relocatable .o file",
            header.size_of_optional_header
        );

        // ── String table ──────────────────────────────────────────────────────
        let string_table = parse_string_table(data, &header)?;

        // ── Section headers ───────────────────────────────────────────────────
        let section_headers = parse_section_headers(data, &header)?;

        // ── Symbol table ──────────────────────────────────────────────────────
        let symbols = parse_symbols(data, &header, &string_table)?;

        // ── Relocations (one vec per section) ─────────────────────────────────
        let mut sections = Vec::with_capacity(section_headers.len());
        for sh in section_headers {
            let relocations = parse_relocations(data, &sh)?;
            sections.push(Section {
                header: sh,
                relocations,
            });
        }

        Ok(CoffFile {
            header,
            sections,
            symbols,
            string_table,
        })
    }

    /// Find a section by name (e.g. `.text`, `.data`).
    pub fn section_by_name(&self, name: &str) -> Option<&Section> {
        self.sections
            .iter()
            .find(|s| s.header.name(&self.string_table) == name)
    }

    /// Find a symbol by its resolved name.
    pub fn symbol_by_name(&self, name: &str) -> Option<&Symbol> {
        self.symbols.iter().find(|s| s.name == name)
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn read_u16_le(data: &[u8], offset: usize) -> Result<u16> {
    data.get(offset..offset + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .context("u16 read out of bounds")
}

fn read_u32_le(data: &[u8], offset: usize) -> Result<u32> {
    data.get(offset..offset + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .context("u32 read out of bounds")
}

fn read_i16_le(data: &[u8], offset: usize) -> Result<i16> {
    data.get(offset..offset + 2)
        .map(|b| i16::from_le_bytes([b[0], b[1]]))
        .context("i16 read out of bounds")
}

fn parse_coff_header(data: &[u8]) -> Result<CoffHeader> {
    Ok(CoffHeader {
        machine: read_u16_le(data, 0)?,
        number_of_sections: read_u16_le(data, 2)?,
        time_date_stamp: read_u32_le(data, 4)?,
        pointer_to_symbol_table: read_u32_le(data, 8)?,
        number_of_symbols: read_u32_le(data, 12)?,
        size_of_optional_header: read_u16_le(data, 16)?,
        characteristics: read_u16_le(data, 18)?,
    })
}

fn parse_string_table(data: &[u8], header: &CoffHeader) -> Result<Vec<u8>> {
    if header.pointer_to_symbol_table == 0 || header.number_of_symbols == 0 {
        return Ok(Vec::new());
    }
    let sym_end = header.pointer_to_symbol_table as usize
        + header.number_of_symbols as usize * SYMBOL_SIZE;
    if sym_end + 4 > data.len() {
        // No string table present (valid for small objects).
        return Ok(Vec::new());
    }
    let strtab_size = read_u32_le(data, sym_end)? as usize;
    if strtab_size < 4 {
        return Ok(Vec::new());
    }
    let end = sym_end
        .checked_add(strtab_size)
        .context("string table size overflow")?;
    ensure!(end <= data.len(), "string table extends past end of file");
    // Store the full string table including the 4-byte size field so that
    // symbol offsets (which are byte offsets from the start of the table)
    // remain valid.
    Ok(data[sym_end..end].to_vec())
}

fn parse_section_headers(data: &[u8], header: &CoffHeader) -> Result<Vec<SectionHeader>> {
    let n = header.number_of_sections as usize;
    let mut headers = Vec::with_capacity(n);
    let base = COFF_HEADER_SIZE + header.size_of_optional_header as usize;

    for i in 0..n {
        let off = base + i * SECTION_HEADER_SIZE;
        ensure!(
            off + SECTION_HEADER_SIZE <= data.len(),
            "section header {} out of bounds",
            i
        );

        let mut name_raw = [0u8; 8];
        name_raw.copy_from_slice(&data[off..off + 8]);

        headers.push(SectionHeader {
            name_raw,
            virtual_size: read_u32_le(data, off + 8)?,
            virtual_address: read_u32_le(data, off + 12)?,
            size_of_raw_data: read_u32_le(data, off + 16)?,
            pointer_to_raw_data: read_u32_le(data, off + 20)?,
            pointer_to_relocations: read_u32_le(data, off + 24)?,
            pointer_to_line_numbers: read_u32_le(data, off + 28)?,
            number_of_relocations: read_u16_le(data, off + 32)?,
            number_of_line_numbers: read_u16_le(data, off + 34)?,
            characteristics: read_u32_le(data, off + 36)?,
        });
    }
    Ok(headers)
}

fn parse_symbols(data: &[u8], header: &CoffHeader, string_table: &[u8]) -> Result<Vec<Symbol>> {
    if header.pointer_to_symbol_table == 0 {
        return Ok(Vec::new());
    }
    let n = header.number_of_symbols as usize;
    let base = header.pointer_to_symbol_table as usize;
    let mut symbols = Vec::with_capacity(n);
    let mut i = 0usize;

    while i < n {
        let off = base + i * SYMBOL_SIZE;
        ensure!(
            off + SYMBOL_SIZE <= data.len(),
            "symbol {} out of bounds",
            i
        );

        // Name: first 4 bytes == 0 → long name (next 4 = string table offset).
        let name = if data[off..off + 4] == [0, 0, 0, 0] {
            let str_off = read_u32_le(data, off + 4)? as usize;
            if str_off < string_table.len() {
                let tail = &string_table[str_off..];
                let end = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
                String::from_utf8_lossy(&tail[..end]).into_owned()
            } else {
                String::from("<invalid-symname>")
            }
        } else {
            let end = data[off..off + 8]
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(8);
            String::from_utf8_lossy(&data[off..off + end]).into_owned()
        };

        let aux_count = data[off + 17];
        symbols.push(Symbol {
            name,
            value: read_u32_le(data, off + 8)?,
            section_number: read_i16_le(data, off + 10)?,
            typ: read_u16_le(data, off + 12)?,
            storage_class: data[off + 16],
            number_of_aux_symbols: aux_count,
        });

        // Skip auxiliary records (they occupy SYMBOL_SIZE slots each but are
        // not represented as individual Symbol entries).
        i += 1 + aux_count as usize;
    }
    Ok(symbols)
}

fn parse_relocations(data: &[u8], sh: &SectionHeader) -> Result<Vec<Relocation>> {
    let n = sh.number_of_relocations as usize;
    if n == 0 {
        return Ok(Vec::new());
    }
    let base = sh.pointer_to_relocations as usize;
    let mut relocs = Vec::with_capacity(n);

    for i in 0..n {
        let off = base + i * RELOC_SIZE;
        ensure!(
            off + RELOC_SIZE <= data.len(),
            "relocation {} in section '{}' out of bounds",
            i,
            sh.name(&[])
        );
        relocs.push(Relocation {
            virtual_address: read_u32_le(data, off)?,
            symbol_table_index: read_u32_le(data, off + 4)?,
            typ: read_u16_le(data, off + 8)?,
        });
    }
    Ok(relocs)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal hand-crafted AMD64 COFF .o with:
    ///   - 1 section  : `.text`  (4 bytes of NOPs, no relocations)
    ///   - 2 symbols  : `go` (external, defined in .text) + `.text` (static)
    ///   - No string table needed (all names ≤ 8 bytes)
    ///
    /// Layout (offsets in decimal):
    ///   0  – 19  : COFF header          (20 bytes)
    ///   20 – 59  : section header x1    (40 bytes)
    ///   60 – 63  : .text raw data       (4 bytes: 0x90 NOP x4)
    ///   64 – 99  : symbol table x2      (2 × 18 = 36 bytes)
    ///   100–103  : string table size    (4 bytes: value = 4, meaning empty)
    fn minimal_coff_bytes() -> Vec<u8> {
        let mut b = vec![0u8; 104];

        // ── COFF header (offset 0) ────────────────────────────────────────────
        b[0..2].copy_from_slice(&0x8664u16.to_le_bytes()); // machine = AMD64
        b[2..4].copy_from_slice(&1u16.to_le_bytes()); // NumberOfSections = 1
        // TimeDateStamp = 0 (already zero)
        b[8..12].copy_from_slice(&64u32.to_le_bytes()); // PointerToSymbolTable = 64
        b[12..16].copy_from_slice(&2u32.to_le_bytes()); // NumberOfSymbols = 2
        // SizeOfOptionalHeader = 0
        // Characteristics = 0

        // ── Section header (offset 20) ────────────────────────────────────────
        b[20..28].copy_from_slice(b".text\0\0\0"); // Name
        // VirtualSize = 0 (obj files often 0)
        b[32..36].copy_from_slice(&4u32.to_le_bytes()); // SizeOfRawData = 4
        b[36..40].copy_from_slice(&60u32.to_le_bytes()); // PointerToRawData = 60
        // PointerToRelocations = 0, NumberOfRelocations = 0
        b[56..60].copy_from_slice(
            // Characteristics: CODE | EXECUTE | READ
            &(IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ).to_le_bytes(),
        );

        // ── .text raw data (offset 60) ────────────────────────────────────────
        b[60..64].copy_from_slice(&[0x90, 0x90, 0x90, 0x90]); // 4 × NOP

        // ── Symbol 0 (offset 64): `go` — external, defined in section 1 ──────
        b[64..68].copy_from_slice(b"go\0\0"); // Name (inline, ≤ 8 bytes)
        // Value = 0
        b[74..76].copy_from_slice(&1i16.to_le_bytes()); // SectionNumber = 1
        b[76..78].copy_from_slice(&0x20u16.to_le_bytes()); // Type = function
        b[78] = IMAGE_SYM_CLASS_EXTERNAL; // StorageClass
        // NumberOfAuxSymbols = 0

        // ── Symbol 1 (offset 82): `.text` — static ───────────────────────────
        b[82..90].copy_from_slice(b".text\0\0\0");
        // Value = 0, SectionNumber = 1
        b[92..94].copy_from_slice(&1i16.to_le_bytes());
        b[96] = IMAGE_SYM_CLASS_STATIC;

        // ── String table (offset 100): size = 4 (empty) ───────────────────────
        b[100..104].copy_from_slice(&4u32.to_le_bytes());

        b
    }

    #[test]
    fn parse_minimal_coff() {
        let data = minimal_coff_bytes();
        let coff = CoffFile::parse(&data).expect("parse failed");

        // Header
        assert_eq!(coff.header.machine, IMAGE_FILE_MACHINE_AMD64);
        assert_eq!(coff.header.number_of_sections, 1);
        assert_eq!(coff.header.number_of_symbols, 2);

        // Section
        assert_eq!(coff.sections.len(), 1);
        let sec = &coff.sections[0];
        assert_eq!(sec.header.name(&coff.string_table), ".text");
        assert_eq!(sec.header.size_of_raw_data, 4);
        assert!(sec.header.characteristics & IMAGE_SCN_CNT_CODE != 0);
        assert!(sec.header.characteristics & IMAGE_SCN_MEM_EXECUTE != 0);
        assert_eq!(sec.relocations.len(), 0);

        // Raw data
        let raw = sec.header.raw_data(&data).expect("raw_data failed");
        assert_eq!(raw, &[0x90, 0x90, 0x90, 0x90]);

        // Symbols
        assert_eq!(coff.symbols.len(), 2);
        let go_sym = coff.symbol_by_name("go").expect("symbol 'go' not found");
        assert!(go_sym.is_external());
        assert!(!go_sym.is_undefined());
        assert_eq!(go_sym.section_number, 1);

        let text_sym = coff
            .symbol_by_name(".text")
            .expect("symbol '.text' not found");
        assert_eq!(text_sym.storage_class, IMAGE_SYM_CLASS_STATIC);

        // section_by_name helper
        assert!(coff.section_by_name(".text").is_some());
        assert!(coff.section_by_name(".data").is_none());
    }

    #[test]
    fn reject_non_amd64() {
        let mut data = minimal_coff_bytes();
        // Change machine to i386 (0x014C)
        data[0..2].copy_from_slice(&0x014Cu16.to_le_bytes());
        let err = CoffFile::parse(&data).unwrap_err();
        assert!(err.to_string().contains("unsupported machine type"));
    }

    #[test]
    fn reject_too_short() {
        let data = vec![0u8; 10];
        assert!(CoffFile::parse(&data).is_err());
    }

    #[test]
    fn reject_optional_header_present() {
        let mut data = minimal_coff_bytes();
        // Set SizeOfOptionalHeader = 224 (PE32+ typical)
        data[16..18].copy_from_slice(&224u16.to_le_bytes());
        let err = CoffFile::parse(&data).unwrap_err();
        assert!(err.to_string().contains("optional header"));
    }
}
