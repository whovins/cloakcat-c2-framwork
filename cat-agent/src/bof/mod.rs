//! BOF (Beacon Object File) loader subsystem.
//! Only compiled on Windows targets.

#[cfg(target_os = "windows")]
pub mod beacon_api;
#[cfg(target_os = "windows")]
pub mod coff_parser;
#[cfg(target_os = "windows")]
pub mod loader;

/// Execute a BOF (.o file) with the given arguments.
///
/// - Parses the COFF object
/// - Loads sections into executable memory
/// - Resolves Beacon API + Win32 imports
/// - Calls `go(args, args_len)` on a blocking thread with a 30-second timeout
/// - Returns the captured BeaconAPI output
///
/// On non-Windows, returns an error.
pub async fn execute_bof(data: &[u8], args: &[u8]) -> anyhow::Result<(i32, String, String)> {
    #[cfg(target_os = "windows")]
    {
        use std::time::Duration;
        use tokio::time::timeout;

        let data = data.to_vec();
        let args = args.to_vec();

        let loaded = loader::BofLoader::load(&data)?;

        let result = timeout(
            Duration::from_secs(30),
            tokio::task::spawn_blocking(move || unsafe { loaded.run(&args) }),
        )
        .await;

        match result {
            Ok(Ok(output)) => Ok((0, output, String::new())),
            Ok(Err(e)) => Ok((-1, String::new(), format!("BOF thread panicked: {e}"))),
            Err(_) => Ok((-1, String::new(), "BOF execution timed out (30s)".to_string())),
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = (data, args);
        Ok((-1, String::new(), "BOF execution requires Windows".to_string()))
    }
}
