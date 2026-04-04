//! Command execution (shell invocation).

use std::env;
use std::time::Duration;

use anyhow::Context;
use cloakcat_protocol::Command;
use tokio::process::Command as TokioCommand;

/// Maximum time a single command may run before being killed.
const EXEC_TIMEOUT: Duration = Duration::from_secs(300);

/// Maximum bytes kept per stdout/stderr stream (1 MB).
const MAX_OUTPUT_BYTES: usize = 1_024 * 1_024;

/// Truncates a string to at most `max_bytes` (on a char boundary).
fn truncate_output(s: String, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    let mut truncated = s[..end].to_string();
    truncated.push_str("\n...[truncated]");
    truncated
}

/// Executes a command and returns (exit_code, stdout, stderr).
/// Enforces a timeout and output size limit.
pub async fn run_command(cmd: &Command) -> anyhow::Result<(i32, String, String)> {
    let mut output = {
        #[cfg(target_os = "windows")]
        {
            let mut c = TokioCommand::new("cmd");
            c.arg("/C").arg(&cmd.command);
            c
        }
        #[cfg(not(target_os = "windows"))]
        {
            let shell = env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
            let mut c = TokioCommand::new(shell);
            c.arg("-c").arg(&cmd.command);
            c
        }
    };

    let result = tokio::time::timeout(EXEC_TIMEOUT, output.output()).await;

    match result {
        Ok(Ok(out)) => {
            let exit_code = out.status.code().unwrap_or(-1);
            let stdout = truncate_output(
                String::from_utf8_lossy(&out.stdout).to_string(),
                MAX_OUTPUT_BYTES,
            );
            let stderr = truncate_output(
                String::from_utf8_lossy(&out.stderr).to_string(),
                MAX_OUTPUT_BYTES,
            );
            Ok((exit_code, stdout, stderr))
        }
        Ok(Err(e)) => Err(e).with_context(|| {
            format!("[agent] failed to run command: {}", cmd.command)
        }),
        Err(_) => Ok((
            -1,
            String::new(),
            format!("command timed out after {}s", EXEC_TIMEOUT.as_secs()),
        )),
    }
}
