//! Server configuration loaded from `config/server.toml`.
//!
//! Defines the `[[listeners]]` array used to start multiple independent
//! HTTP or HTTPS listeners at server startup.

use serde::{Deserialize, Serialize};

/// A single listener definition from `[[listeners]]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenerEntry {
    /// Unique listener name (used as key in ListenerManager).
    pub name: String,
    /// "http" or "https"
    #[serde(rename = "type")]
    pub listener_type: String,
    /// Bind address (default: "0.0.0.0").
    #[serde(default = "default_host")]
    pub host: String,
    /// TCP port to bind.
    pub port: u16,
    /// Malleable C2 profile name to associate with this listener.
    pub profile: String,
}

fn default_host() -> String {
    "0.0.0.0".to_string()
}

impl ListenerEntry {
    /// Returns `"host:port"` as a string.
    pub fn bind_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// Top-level configuration parsed from `config/server.toml`.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ServerConfig {
    #[serde(default)]
    pub listeners: Vec<ListenerEntry>,
}

impl ServerConfig {
    pub fn from_file(path: &str) -> anyhow::Result<Self> {
        let s = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("cannot read {path}: {e}"))?;
        toml::from_str(&s).map_err(|e| anyhow::anyhow!("parse error in {path}: {e}"))
    }

    /// Load from `SERVER_CONFIG_PATH` env var or fall back to `config/server.toml`.
    pub fn load() -> Self {
        let path = std::env::var("SERVER_CONFIG_PATH")
            .unwrap_or_else(|_| "config/server.toml".to_string());
        match Self::from_file(&path) {
            Ok(c) => {
                println!(
                    "[startup] server config: {} listener(s) from {path}",
                    c.listeners.len()
                );
                c
            }
            Err(e) => {
                eprintln!("[startup] WARNING: no server config ({e}) — using env-var listener");
                Self::default()
            }
        }
    }
}
