//! BOF (Beacon Object File) loader subsystem.
//! Only compiled on Windows targets.

#[cfg(target_os = "windows")]
pub mod coff_parser;
