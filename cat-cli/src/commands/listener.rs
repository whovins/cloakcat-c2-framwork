//! Listener management commands: listeners list/add/remove.

use anyhow::{anyhow, Result};

use crate::display;

use super::CliCtx;

/// GET /v1/admin/listeners — list all active C2 listeners.
pub fn cmd_listeners_list(ctx: &CliCtx) -> Result<()> {
    let res = ctx
        .cli
        .get(format!("{}/v1/admin/listeners", ctx.base))
        .send()?;
    let status = res.status();
    let text = res.text()?;
    if !status.is_success() {
        return Err(anyhow!("listeners list failed: status={} body={}", status, text));
    }
    let items: Vec<serde_json::Value> = serde_json::from_str(&text)?;
    if items.is_empty() {
        println!("no active listeners");
        return Ok(());
    }
    for item in &items {
        let name = item.get("name").and_then(|v| v.as_str()).unwrap_or("?");
        let ltype = item.get("type").and_then(|v| v.as_str()).unwrap_or("?");
        let host = item.get("host").and_then(|v| v.as_str()).unwrap_or("?");
        let port = item.get("port").and_then(|v| v.as_u64()).unwrap_or(0);
        let profile = item.get("profile").and_then(|v| v.as_str()).unwrap_or("?");
        display::print_success(&format!(
            "{name}  {ltype}  {host}:{port}  profile={profile}"
        ));
    }
    Ok(())
}

/// POST /v1/admin/listeners — add a new C2 listener at runtime.
pub fn cmd_listeners_add(
    ctx: &CliCtx,
    name: &str,
    listener_type: &str,
    host: &str,
    port: u16,
    profile: &str,
) -> Result<()> {
    let body = serde_json::json!({
        "name": name,
        "type": listener_type,
        "host": host,
        "port": port,
        "profile": profile,
    });
    let res = ctx
        .cli
        .post(format!("{}/v1/admin/listeners", ctx.base))
        .json(&body)
        .send()?;
    let status = res.status();
    let text = res.text()?;
    if !status.is_success() {
        return Err(anyhow!("listeners add failed: status={} body={}", status, text));
    }
    display::print_success(&format!("listener '{name}' started ({listener_type} {host}:{port})"));
    Ok(())
}

/// DELETE /v1/admin/listeners/{name} — stop and remove a C2 listener.
pub fn cmd_listeners_remove(ctx: &CliCtx, name: &str) -> Result<()> {
    let res = ctx
        .cli
        .delete(format!("{}/v1/admin/listeners/{name}", ctx.base))
        .send()?;
    let status = res.status();
    let text = res.text()?;
    if !status.is_success() {
        return Err(anyhow!("listeners remove failed: status={} body={}", status, text));
    }
    display::print_success(&format!("listener '{name}' stopped"));
    Ok(())
}
