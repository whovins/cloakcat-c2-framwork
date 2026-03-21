//! Agent configuration loading (embedded + optional file override).

use std::env;
use std::path::Path;

use cloakcat_protocol::{AgentConfig, MalleableProfile};

#[cfg(embed_has_out_dir)]
mod embedded {
    include!(concat!(env!("OUT_DIR"), "/embedded_config.rs"));
    include!(concat!(env!("OUT_DIR"), "/embedded_profile.rs"));
}

#[cfg(not(embed_has_out_dir))]
mod embedded {
    pub const EMBEDDED_CONFIG: &str = r#"{}"#;
    pub const EMBEDDED_PROFILE_TOML: &str = "";
}

/// Load the agent's JSON config.
/// Priority: CLOAKCAT_CONFIG env var → agent_config.json next to binary → embedded.
pub fn load_agent_config() -> anyhow::Result<AgentConfig> {
    let embedded_cfg: AgentConfig = serde_json::from_str(embedded::EMBEDDED_CONFIG)
        .map_err(|e| anyhow::anyhow!("failed to parse embedded config: {}", e))?;

    let path = if let Ok(p) = env::var("CLOAKCAT_CONFIG") {
        Some(Path::new(&p).to_path_buf())
    } else {
        let exe = std::env::current_exe()?;
        Some(
            exe.parent()
                .unwrap_or_else(|| Path::new("."))
                .join("agent_config.json"),
        )
    };

    if let Some(path) = path {
        if path.exists() {
            let bytes = std::fs::read(&path)
                .map_err(|e| anyhow::anyhow!("failed to read config {:?}: {}", path, e))?;
            let cfg: AgentConfig = serde_json::from_slice(&bytes)
                .map_err(|e| anyhow::anyhow!("failed to parse config {:?}: {}", path, e))?;
            return Ok(cfg);
        }
    }

    Ok(embedded_cfg)
}

/// Load an optional malleable C2 profile.
///
/// Priority:
/// 1. `CLOAKCAT_PROFILE` env var pointing to a `.toml` file
/// 2. `agent_profile.toml` next to the agent binary
/// 3. TOML embedded at build time via `CLOAKCAT_EMBED_PROFILE`
/// 4. `None` — falls back to the built-in profile named in `AgentConfig.profile_name`
pub fn load_malleable_profile() -> anyhow::Result<Option<MalleableProfile>> {
    // 1. Runtime env override
    if let Ok(path) = env::var("CLOAKCAT_PROFILE") {
        if Path::new(&path).exists() {
            let p = MalleableProfile::from_file(&path)?;
            return Ok(Some(p));
        }
    }

    // 2. File next to binary
    let exe = std::env::current_exe()?;
    let profile_path = exe
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("agent_profile.toml");
    if profile_path.exists() {
        let s = std::fs::read_to_string(&profile_path)
            .map_err(|e| anyhow::anyhow!("failed to read agent_profile.toml: {}", e))?;
        let p = MalleableProfile::from_str(&s)?;
        return Ok(Some(p));
    }

    // 3. Embedded TOML (built in at compile time via CLOAKCAT_EMBED_PROFILE)
    let embedded = embedded::EMBEDDED_PROFILE_TOML;
    if !embedded.is_empty() {
        let p = MalleableProfile::from_str(embedded)?;
        return Ok(Some(p));
    }

    Ok(None)
}
