//! Reverse SOCKS5 proxy tunnel.
//!
//! Architecture:
//!   proxychains → SOCKS5 listener (this module) → HTTP tunnel channel → agent TCP relay
//!
//! Each `socks start <agent_id> <port>` spawns a SOCKS5 TCP listener.
//! When a SOCKS5 CONNECT arrives the server:
//!   1. Assigns a `tunnel_id`, creates a `TunnelSession`.
//!   2. Queues an `Open` frame in `pending_opens` for the agent's next poll.
//!   3. Sends the SOCKS5 success reply to the client immediately.
//!   4. Runs a bidirectional relay between the SOCKS5 socket and per-session buffers.
//!
//! The agent picks up the Open frame on its next poll, opens the real TCP connection,
//! and relays data via `POST /v1/tunnel/send` and `GET /v1/tunnel/recv`.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use cloakcat_protocol::{TunnelAction, TunnelData};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Mutex, Notify};
use tokio::time::{sleep, Duration};

/// Maximum simultaneous tunnel sessions per agent.
pub const MAX_SESSIONS_PER_AGENT: usize = 10;
/// Idle session timeout in seconds.
const SESSION_TIMEOUT_SECS: u64 = 300;
/// Read buffer size for SOCKS5 relay.
const READ_BUF: usize = 16_384;

// ─── Session ─────────────────────────────────────────────────────────────────

#[allow(dead_code)]
pub struct TunnelSession {
    pub tunnel_id: u32,
    pub agent_id: String,
    /// "host:port" target requested by SOCKS5 client.
    pub target: String,
    /// Data from SOCKS5 client waiting for agent to pick up.
    pub to_agent: Arc<Mutex<VecDeque<Vec<u8>>>>,
    pub to_agent_notify: Arc<Notify>,
    /// Data from agent waiting for SOCKS5 client to consume.
    pub from_agent: Arc<Mutex<VecDeque<Vec<u8>>>>,
    pub from_agent_notify: Arc<Notify>,
    /// Set to true when either side closes.
    pub closed: Arc<AtomicBool>,
    pub created_at: Instant,
}

// ─── Manager ─────────────────────────────────────────────────────────────────

pub struct TunnelManager {
    /// All live sessions (including recently closed; GC'd lazily).
    pub sessions: HashMap<u32, Arc<TunnelSession>>,
    next_id: u32,
    /// agent_id → listening port.
    pub listeners: HashMap<String, u16>,
    /// Shutdown channels for each active listener.
    shutdown_txs: HashMap<String, watch::Sender<bool>>,
    /// Queued Open frames per agent, delivered on the agent's next poll.
    pub pending_opens: HashMap<String, Vec<TunnelData>>,
}

impl TunnelManager {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            next_id: 1,
            listeners: HashMap::new(),
            shutdown_txs: HashMap::new(),
            pending_opens: HashMap::new(),
        }
    }

    fn alloc_id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        id
    }

    pub fn active_session_count(&self, agent_id: &str) -> usize {
        self.sessions
            .values()
            .filter(|s| s.agent_id == agent_id && !s.closed.load(Ordering::Relaxed))
            .count()
    }

    /// Drain Open frames queued for `agent_id` (called during poll).
    pub fn take_pending_opens(&mut self, agent_id: &str) -> Vec<TunnelData> {
        self.pending_opens.remove(agent_id).unwrap_or_default()
    }

    /// Remove sessions that have been closed for more than a minute.
    pub fn gc(&mut self) {
        let grace = Duration::from_secs(SESSION_TIMEOUT_SECS + 60);
        self.sessions.retain(|_, s| {
            !s.closed.load(Ordering::Relaxed) || s.created_at.elapsed() < grace
        });
    }

    /// Stop the SOCKS5 listener for an agent. Returns the port that was listening.
    pub fn stop_listener(&mut self, agent_id: &str) -> Option<u16> {
        if let Some(tx) = self.shutdown_txs.remove(agent_id) {
            let _ = tx.send(true);
        }
        self.listeners.remove(agent_id)
    }
}

// ─── Public API ──────────────────────────────────────────────────────────────

/// Start a SOCKS5 listener on `port` for `agent_id`.
/// Returns an error if the port is already in use or a listener already exists.
pub async fn start_listener(
    agent_id: String,
    port: u16,
    tunnel_mgr: Arc<Mutex<TunnelManager>>,
    cmd_notify: Arc<Mutex<HashMap<String, Arc<Notify>>>>,
) -> anyhow::Result<()> {
    {
        let mgr = tunnel_mgr.lock().await;
        if mgr.listeners.contains_key(&agent_id) {
            anyhow::bail!(
                "agent {} already has an active SOCKS5 listener on port {}",
                agent_id,
                mgr.listeners[&agent_id]
            );
        }
    }

    let listener = TcpListener::bind(("0.0.0.0", port)).await?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    {
        let mut mgr = tunnel_mgr.lock().await;
        mgr.listeners.insert(agent_id.clone(), port);
        mgr.shutdown_txs.insert(agent_id.clone(), shutdown_tx);
    }

    let tm = tunnel_mgr.clone();
    let cn = cmd_notify.clone();
    let ai = agent_id.clone();
    tokio::spawn(async move {
        run_listener(listener, ai, tm, cn, shutdown_rx).await;
    });

    println!("[tunnel] SOCKS5 listener started: agent={} port={}", agent_id, port);
    Ok(())
}

// ─── Listener loop ───────────────────────────────────────────────────────────

async fn run_listener(
    listener: TcpListener,
    agent_id: String,
    tunnel_mgr: Arc<Mutex<TunnelManager>>,
    cmd_notify: Arc<Mutex<HashMap<String, Arc<Notify>>>>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            accept = listener.accept() => {
                match accept {
                    Ok((stream, peer)) => {
                        let tm = tunnel_mgr.clone();
                        let cn = cmd_notify.clone();
                        let ai = agent_id.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(stream, ai, tm, cn).await {
                                eprintln!("[tunnel] connection from {} error: {}", peer, e);
                            }
                        });
                    }
                    Err(e) => {
                        eprintln!("[tunnel] accept error: {}", e);
                        break;
                    }
                }
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
        }
    }

    // Clean up listener record
    tunnel_mgr.lock().await.listeners.remove(&agent_id);
    println!("[tunnel] SOCKS5 listener stopped: agent={}", agent_id);
}

// ─── SOCKS5 connection handler ────────────────────────────────────────────────

async fn handle_connection(
    mut stream: TcpStream,
    agent_id: String,
    tunnel_mgr: Arc<Mutex<TunnelManager>>,
    cmd_notify: Arc<Mutex<HashMap<String, Arc<Notify>>>>,
) -> anyhow::Result<()> {
    // ── Method negotiation (RFC 1928 §3) ──────────────────────────────────────
    let mut hdr = [0u8; 2];
    stream.read_exact(&mut hdr).await?;
    if hdr[0] != 0x05 {
        anyhow::bail!("not SOCKS5 (VER={})", hdr[0]);
    }
    let nmethods = hdr[1] as usize;
    if nmethods == 0 {
        anyhow::bail!("zero auth methods");
    }
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;

    // Require NO AUTHENTICATION (0x00)
    if !methods.contains(&0x00) {
        stream.write_all(&[0x05, 0xFF]).await?;
        anyhow::bail!("no acceptable auth method");
    }
    stream.write_all(&[0x05, 0x00]).await?;

    // ── CONNECT request (RFC 1928 §4) ─────────────────────────────────────────
    let mut req = [0u8; 4];
    stream.read_exact(&mut req).await?;
    if req[0] != 0x05 {
        anyhow::bail!("bad VER in request");
    }
    if req[1] != 0x01 {
        // Only CONNECT is supported
        stream.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
        anyhow::bail!("unsupported SOCKS5 command: {}", req[1]);
    }
    let atyp = req[3];

    let host = match atyp {
        0x01 => {
            // IPv4
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await?;
            format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3])
        }
        0x03 => {
            // Domain name
            let mut len_byte = [0u8; 1];
            stream.read_exact(&mut len_byte).await?;
            let mut name = vec![0u8; len_byte[0] as usize];
            stream.read_exact(&mut name).await?;
            String::from_utf8(name).map_err(|_| anyhow::anyhow!("invalid domain"))?
        }
        0x04 => {
            // IPv6
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await?;
            std::net::Ipv6Addr::from(addr).to_string()
        }
        _ => anyhow::bail!("unsupported ATYP: {}", atyp),
    };

    let mut port_bytes = [0u8; 2];
    stream.read_exact(&mut port_bytes).await?;
    let port = u16::from_be_bytes(port_bytes);
    let target = format!("{}:{}", host, port);

    // ── Create tunnel session ──────────────────────────────────────────────────
    let session: Arc<TunnelSession> = {
        let mut mgr = tunnel_mgr.lock().await;
        if mgr.active_session_count(&agent_id) >= MAX_SESSIONS_PER_AGENT {
            drop(mgr);
            // Connection refused
            stream.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            anyhow::bail!("max sessions reached for agent {}", agent_id);
        }
        let tunnel_id = mgr.alloc_id();
        let sess = Arc::new(TunnelSession {
            tunnel_id,
            agent_id: agent_id.clone(),
            target: target.clone(),
            to_agent: Arc::new(Mutex::new(VecDeque::new())),
            to_agent_notify: Arc::new(Notify::new()),
            from_agent: Arc::new(Mutex::new(VecDeque::new())),
            from_agent_notify: Arc::new(Notify::new()),
            closed: Arc::new(AtomicBool::new(false)),
            created_at: Instant::now(),
        });
        mgr.sessions.insert(tunnel_id, sess.clone());
        mgr.pending_opens
            .entry(agent_id.clone())
            .or_default()
            .push(TunnelData {
                tunnel_id,
                action: TunnelAction::Open,
                data: target.clone(),
            });
        sess
    };

    // Wake up the poll handler so the agent receives the Open frame promptly.
    {
        let mut cn = cmd_notify.lock().await;
        cn.entry(agent_id.clone())
            .or_insert_with(|| Arc::new(Notify::new()))
            .notify_one();
    }

    // ── SOCKS5 success reply ───────────────────────────────────────────────────
    // BND.ADDR = 0.0.0.0, BND.PORT = 0
    stream
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;

    println!(
        "[tunnel] open: agent={} tunnel_id={} target={}",
        agent_id, session.tunnel_id, target
    );

    // ── Bidirectional relay ───────────────────────────────────────────────────
    let (mut reader, mut writer) = stream.into_split();

    // SOCKS5 client → to_agent buffer
    let to_agent = session.to_agent.clone();
    let ta_notify = session.to_agent_notify.clone();
    let closed_r = session.closed.clone();
    let read_task = tokio::spawn(async move {
        let mut buf = vec![0u8; READ_BUF];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    to_agent.lock().await.push_back(buf[..n].to_vec());
                    ta_notify.notify_one();
                }
            }
        }
        closed_r.store(true, Ordering::Release);
        ta_notify.notify_waiters();
    });

    // from_agent buffer → SOCKS5 client
    let from_agent = session.from_agent.clone();
    let fa_notify = session.from_agent_notify.clone();
    let closed_w = session.closed.clone();
    let write_task = tokio::spawn(async move {
        loop {
            fa_notify.notified().await;
            if closed_w.load(Ordering::Acquire) {
                break;
            }
            let chunks: Vec<Vec<u8>> = {
                let mut q = from_agent.lock().await;
                q.drain(..).collect()
            };
            for chunk in chunks {
                if writer.write_all(&chunk).await.is_err() {
                    closed_w.store(true, Ordering::Release);
                    return;
                }
            }
        }
    });

    let timeout = Duration::from_secs(SESSION_TIMEOUT_SECS);
    tokio::select! {
        _ = read_task => {}
        _ = write_task => {}
        _ = sleep(timeout) => {}
    }

    session.closed.store(true, Ordering::Release);
    session.to_agent_notify.notify_waiters();
    session.from_agent_notify.notify_one();

    println!("[tunnel] close: tunnel_id={}", session.tunnel_id);
    Ok(())
}
