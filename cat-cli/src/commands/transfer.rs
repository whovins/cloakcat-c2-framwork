//! Chunked file transfer commands: upload (operator → agent) and download (agent → operator).

use std::thread;
use std::time::Duration;

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use cloakcat_protocol::{CHUNK_SIZE, MAX_TRANSFER_SIZE};
use uuid::Uuid;

use crate::display;
use crate::http::resolve_agent_identifier;

use super::CliCtx;

/// Upload a local file to the agent's target path (chunked, up to 50 MB).
pub fn cmd_upload(
    ctx: &CliCtx,
    agent: &str,
    local_path: &str,
    remote_path: &str,
) -> Result<()> {
    let agent_id = resolve_agent_identifier(ctx.cli, ctx.base, agent)?;

    let data = std::fs::read(local_path)
        .map_err(|e| anyhow!("cannot read {}: {}", local_path, e))?;
    if data.is_empty() {
        return Err(anyhow!("file {} is empty", local_path));
    }
    if data.len() > MAX_TRANSFER_SIZE {
        return Err(anyhow!(
            "file too large ({} MB); max is {} MB",
            data.len() / 1024 / 1024,
            MAX_TRANSFER_SIZE / 1024 / 1024
        ));
    }

    let transfer_id = Uuid::new_v4().to_string();
    let total_chunks = data.len().div_ceil(CHUNK_SIZE);

    println!(
        "[upload] {} → {}:{} ({} bytes, {} chunk{})",
        local_path,
        agent_id,
        remote_path,
        data.len(),
        total_chunks,
        if total_chunks == 1 { "" } else { "s" }
    );

    for (seq, chunk) in data.chunks(CHUNK_SIZE).enumerate() {
        let body = serde_json::json!({
            "transfer_id": transfer_id,
            "path": remote_path,
            "seq": seq,
            "total": total_chunks,
            "data": B64.encode(chunk),
        });
        let res = ctx
            .cli
            .post(format!(
                "{}/v1/transfer/upload-chunk/{}",
                ctx.base, agent_id
            ))
            .json(&body)
            .send()?;
        if !res.status().is_success() {
            return Err(anyhow!(
                "chunk {} upload failed: status={}",
                seq,
                res.status()
            ));
        }
        eprint!("\r[upload] chunk {}/{}", seq + 1, total_chunks);
    }
    eprintln!(); // newline after progress indicator

    display::print_success(&format!(
        "transfer_id={} queued to agent — agent will write to {}",
        transfer_id, remote_path
    ));
    Ok(())
}

/// Request the agent to download a remote file and poll until it arrives (up to 50 MB).
pub fn cmd_download(
    ctx: &CliCtx,
    agent: &str,
    remote_path: &str,
    local_path: Option<&str>,
) -> Result<()> {
    let agent_id = resolve_agent_identifier(ctx.cli, ctx.base, agent)?;
    let transfer_id = Uuid::new_v4().to_string();

    // Derive local save path from remote filename if not provided.
    let save_path = local_path
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            std::path::Path::new(remote_path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("download")
                .to_string()
        });

    // Build DownloadTask payload and queue command to agent.
    let task_payload = serde_json::to_string(&serde_json::json!({
        "transfer_id": transfer_id,
        "path": remote_path,
    }))?;

    let res = ctx
        .cli
        .post(format!("{}/v1/command/{}", ctx.base, agent_id))
        .json(&serde_json::json!({
            "command": task_payload,
            "task_type": "download",
        }))
        .send()?;
    if !res.status().is_success() {
        return Err(anyhow!(
            "failed to queue download task: status={} body={}",
            res.status(),
            res.text()?
        ));
    }

    println!(
        "[download] transfer_id={} — waiting for agent to send {}…",
        transfer_id, remote_path
    );

    // Poll for up to 120 seconds (60 × 2s).
    for attempt in 0..60 {
        thread::sleep(Duration::from_secs(2));

        let res = ctx
            .cli
            .get(format!(
                "{}/v1/transfer/download-result/{}",
                ctx.base, transfer_id
            ))
            .send()?;

        let status = res.status();
        if status.as_u16() == 200 {
            let bytes = res.bytes()?;
            std::fs::write(&save_path, &bytes)
                .map_err(|e| anyhow!("cannot save {}: {}", save_path, e))?;
            display::print_success(&format!(
                "saved {} bytes → {}",
                bytes.len(),
                save_path
            ));
            return Ok(());
        } else if status.as_u16() == 202 {
            eprint!("\r[download] waiting… ({}/60)", attempt + 1);
            continue;
        } else {
            return Err(anyhow!(
                "download-result poll failed: status={}",
                status
            ));
        }
    }
    eprintln!();
    Err(anyhow!("timeout waiting for download result (120 s)"))
}
