//! Endpoint path construction for C2 protocol.

use crate::profile::{profile_by_name, ListenerProfile};

/// Builds register, poll, and result URLs for an agent.
#[derive(Debug, Clone)]
pub struct Endpoints {
    pub register: String,
    pub poll: String,
    pub result: String,
}

impl Endpoints {
    /// Creates endpoints for the given base URL and agent_id.
    /// Resolves profile_name to a ListenerProfile to determine paths.
    pub fn new(base: &str, profile_name: &str, agent_id: &str) -> Self {
        let profile = profile_by_name(profile_name);
        Self::from_profile(base, &*profile, agent_id)
    }

    /// Creates endpoints from an explicit profile reference.
    pub fn from_profile(base: &str, profile: &dyn ListenerProfile, agent_id: &str) -> Self {
        Self {
            register: profile.register_url(base),
            poll: profile.poll_url(base, agent_id),
            result: profile.result_url(base, agent_id),
        }
    }
}
