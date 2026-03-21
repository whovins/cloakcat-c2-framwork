//! CloakCat C2 server entry point.

mod db;
mod error;
mod handlers;
mod middleware;
mod routes;
mod service;
mod state;
mod tunnel;
mod validation;

use std::net::SocketAddr;

use sqlx::postgres::PgPoolOptions;

use cloakcat_protocol::ListenerProfile as _;

use crate::routes::build_router;
use crate::state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    let shared_token_str = std::env::var("SHARED_TOKEN")
        .expect("SHARED_TOKEN must be set");
    if shared_token_str.len() < 16 {
        panic!("SHARED_TOKEN must be at least 16 characters");
    }
    let operator_token_str = std::env::var("OPERATOR_TOKEN")
        .expect("OPERATOR_TOKEN must be set");
    if operator_token_str.len() < 16 {
        panic!("OPERATOR_TOKEN must be at least 16 characters");
    }

    let derived_keys = cloakcat_protocol::DerivedKeys::from_master(shared_token_str.as_bytes());
    let operator_token = operator_token_str;

    let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    println!("[startup] DATABASE_URL = {db_url}");
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&db_url)
        .await?;
    let db_name: (String,) = sqlx::query_as("select current_database()")
        .fetch_one(&pool)
        .await?;
    println!("[startup] connected to database = {}", db_name.0);

    // Optionally load a malleable C2 profile from disk.
    let malleable_profile = std::env::var("MALLEABLE_PROFILE_PATH").ok().and_then(|path| {
        match cloakcat_protocol::MalleableProfile::from_file(&path) {
            Ok(p) => {
                println!("[startup] malleable profile loaded: name={}", p.name());
                Some(std::sync::Arc::new(p))
            }
            Err(e) => {
                eprintln!("[startup] WARNING: failed to load malleable profile from {:?}: {}", path, e);
                None
            }
        }
    });

    let state = AppState {
        db: pool,
        derived_keys,
        operator_token,
        cmd_notify: std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        upload_buffers: std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        download_buffers: std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        tunnel_mgr: std::sync::Arc::new(tokio::sync::Mutex::new(tunnel::TunnelManager::new())),
        malleable_profile,
    };
    let app = build_router(state)
        .layer(axum::extract::DefaultBodyLimit::max(2 * 1024 * 1024)); // 2 MB

    let cert_path = std::env::var("TLS_CERT_PATH").ok();
    let key_path = std::env::var("TLS_KEY_PATH").ok();

    if let (Some(cert), Some(key)) = (cert_path, key_path) {
        let addr: SocketAddr = std::env::var("LISTEN_ADDR")
            .unwrap_or_else(|_| "0.0.0.0:3443".to_string())
            .parse()?;
        println!("[startup] C2 server running at https://{} (TLS)", addr);

        let config = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key).await?;
        axum_server::bind_rustls(addr, config)
            .serve(app.into_make_service())
            .await?;
    } else {
        let addr: SocketAddr = "127.0.0.1:3000".parse().unwrap();
        eprintln!("[startup] WARNING: Running in HTTP mode. X-Agent-Token will be transmitted in plaintext.");
        eprintln!("[startup] Set TLS_CERT_PATH and TLS_KEY_PATH to enable HTTPS.");
        println!("[startup] C2 server running at http://{} (HTTP)", addr);

        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, app).await?;
    }
    Ok(())
}
