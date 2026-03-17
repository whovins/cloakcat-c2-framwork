//! Domain logic layer — sits between HTTP handlers and DB.

use base64::engine::general_purpose::STANDARD_NO_PAD as B64;
use base64::Engine;
use tokio::time::{Duration, Instant};
use uuid::Uuid;

use cloakcat_protocol::{verify_result, Command, RegisterReq, ResultReq};

use crate::db;
use crate::error::ServerError;
use crate::state::{AgentView, AppState, ResultView};

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
    Ok(AgentView::from(record))
}

pub async fn list_agents(state: &AppState) -> Result<Vec<AgentView>, ServerError> {
    let records = db::list_agents(&state.db).await?;
    Ok(records.into_iter().map(AgentView::from).collect())
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
) -> Result<(), ServerError> {
    db::insert_command(&state.db, agent_id, command).await?;

    if let Err(e) = db::insert_audit(
        &state.db,
        "catctl",
        "TASK_CREATE",
        "agent",
        agent_id,
        &serde_json::json!({ "command": command }),
    )
    .await
    {
        eprintln!("[audit] failed to insert audit log: {}", e);
    }

    // Wake up any poll_command waiting for this agent
    state.get_notify(agent_id).await.notify_one();

    println!("Command queued for {}: {}", agent_id, command);
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

async fn fetch_command(
    state: &AppState,
    agent_id: &str,
) -> Result<Option<Command>, ServerError> {
    match db::get_oldest_command_for_agent(&state.db, agent_id).await {
        Ok(Some(cmd_rec)) => {
            let cmd = Command {
                cmd_id: cmd_rec.id.to_string(),
                command: cmd_rec.command,
            };
            println!(
                "[server] poll hit: agent={} -> dispatch cmd {}",
                agent_id, cmd.cmd_id
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
        &state.shared_token,
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
            exit_code: r.exit_code,
            stdout: r.stdout,
            stderr: r.stderr,
            ts_ms: r.created_at.timestamp_millis(),
        })
        .collect())
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
