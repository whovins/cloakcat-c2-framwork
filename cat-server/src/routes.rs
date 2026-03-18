//! Router and route registration.

use axum::{routing::{get, post}, Router};
use cloakcat_protocol::{DefaultProfile, HealthProfile, ListenerProfile};

use crate::handlers;
use crate::state::AppState;

/// API version prefix applied to all routes.
pub const API_VERSION: &str = "/v1";

/// Register agent routes (register/poll/result) for a given profile.
fn agent_routes_for(profile: &dyn ListenerProfile) -> Router<AppState> {
    let base = profile.base_path();
    Router::new()
        .route(&format!("{base}/register"), post(handlers::register_handler))
        .route(&format!("{base}/poll/{{agent_id}}"), get(handlers::poll_handler))
        .route(&format!("{base}/result/{{agent_id}}"), post(handlers::result_handler))
}

pub fn build_router(state: AppState) -> Router {
    // Agent routes — require X-Agent-Token via agent_auth middleware
    let agent_routes = agent_routes_for(&DefaultProfile)
        .merge(agent_routes_for(&HealthProfile))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::middleware::agent_auth,
        ));

    // Operator routes — require X-Operator-Token via operator_auth middleware
    let protected_routes = Router::new()
        .route("/command/{agent_id}", post(handlers::push_command_handler))
        .route("/admin/agents", get(handlers::admin_agents))
        .route(
            "/admin/agents/{agent_id}/alias",
            post(handlers::admin_update_agent_alias),
        )
        .route("/admin/results", get(handlers::admin_results))
        .route("/admin/audit", get(handlers::admin_audit))
        .route("/admin/agents/{agent_id}/tags", get(handlers::admin_agent_tags))
        .route("/admin/agents/{agent_id}/tags", post(handlers::admin_set_agent_tags))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::middleware::operator_auth,
        ));

    // Nest everything under /v1
    let versioned = Router::new()
        .merge(agent_routes)
        .merge(protected_routes);

    // Public (unauthenticated) routes — outside version prefix
    let public_routes = Router::new()
        .route("/ping", get(handlers::ping_handler));

    public_routes
        .nest(API_VERSION, versioned)
        .with_state(state)
}
