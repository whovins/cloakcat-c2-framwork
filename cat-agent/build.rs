use std::{env, fs, path::Path};

fn main() {
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");

    // ── Embed agent config JSON ───────────────────────────────────────────────
    let cfg = env::var("CLOAKCAT_EMBED_CONFIG").unwrap_or_else(|_| "{}".to_string());
    let dest = Path::new(&out_dir).join("embedded_config.rs");
    let escaped = cfg.replace('\\', "\\\\").replace('"', "\\\"");
    let content = ["pub const EMBEDDED_CONFIG: &str = \"", &escaped, "\";"].concat();
    fs::write(dest, content).expect("failed to write embedded_config.rs");
    println!("cargo:rerun-if-env-changed=CLOAKCAT_EMBED_CONFIG");

    // ── Embed malleable profile TOML ─────────────────────────────────────────
    // Set CLOAKCAT_EMBED_PROFILE to a .toml file path at build time to bake
    // a MalleableProfile directly into the agent binary.
    let profile_toml = env::var("CLOAKCAT_EMBED_PROFILE")
        .ok()
        .and_then(|path| {
            fs::read_to_string(&path)
                .map_err(|e| eprintln!("cargo:warning=CLOAKCAT_EMBED_PROFILE read failed: {e}"))
                .ok()
        })
        .unwrap_or_default();
    let dest2 = Path::new(&out_dir).join("embedded_profile.rs");
    // Escape for inclusion in a regular Rust string literal.
    let escaped2 = profile_toml
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "");
    let content2 = ["pub const EMBEDDED_PROFILE_TOML: &str = \"", &escaped2, "\";"].concat();
    fs::write(dest2, content2).expect("failed to write embedded_profile.rs");
    println!("cargo:rerun-if-env-changed=CLOAKCAT_EMBED_PROFILE");

    println!("cargo:rustc-cfg=embed_has_out_dir");
}
