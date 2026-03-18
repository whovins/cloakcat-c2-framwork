//! Profile and request validation via ListenerProfile trait.

use axum::http::{self, HeaderMap};
use cloakcat_protocol::profile_by_name;

use crate::error::ServerError;

/// Validates that the request path and User-Agent match the agent's profile.
pub fn validate_profile(
    profile_name: Option<&str>,
    path: &str,
    headers: &HeaderMap,
) -> Result<(), ServerError> {
    let name = profile_name.unwrap_or("default");
    let profile = profile_by_name(name);

    // Default profile allows everything — skip validation.
    if profile.base_path().is_empty() && profile.user_agent().is_none() {
        return Ok(());
    }

    let ua = headers
        .get(http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok());

    if !profile.validate(path, ua) {
        return Err(ServerError::Forbidden("profile_mismatch".into()));
    }
    Ok(())
}
