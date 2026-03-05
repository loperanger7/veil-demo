// VEIL — Relay Server
// Tickets: VEIL-301, VEIL-302, VEIL-303, VEIL-304
// Spec reference: Section 2
//
// Untrusted relay server for the Veil protocol.
//
// The server:
//   - Stores and delivers opaque encrypted envelopes
//   - Manages prekey bundles for PQXDH handshakes
//   - Issues anonymous credentials (Ristretto255 blind signatures)
//   - Sends silent push notifications via APNs
//
// The server NEVER:
//   - Sees plaintext message content
//   - Knows who is messaging whom (sealed sender)
//   - Links API requests to user identity (anonymous tokens)
//   - Logs any data that could identify message senders

mod api;
mod auth;
mod config;
mod error;
mod proto;
mod push;
mod sealed_sender;
mod storage;

use crate::api::AppState;
use crate::auth::anonymous_token::{AnonymousTokenService, TokenSigningKey};
use crate::config::ServerConfig;
use crate::storage::Storage;

use axum_server::tls_rustls::RustlsConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::signal;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize structured logging
    // SECURITY: tracing filter ensures no message content is logged
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "veil_relay=info,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer().json())
        .init();

    tracing::info!("Veil Relay Server starting");

    // Load configuration
    let config = ServerConfig::from_env_or_default();
    tracing::info!(
        listen_addr = %config.listen_addr,
        db_path = %config.db_path,
        "configuration loaded"
    );

    // Open storage
    let storage = Storage::open(&config.db_path)?;
    tracing::info!("storage opened");

    // Initialize anonymous token signing key
    // In production, this should be loaded from secure storage
    // and rotated periodically.
    let signing_key = TokenSigningKey::generate()?;
    tracing::info!("token signing key generated");

    let token_service = Arc::new(
        AnonymousTokenService::new(signing_key, &sled::open(&config.db_path)?)?
    );

    // Build application state
    let state = AppState {
        storage,
        token_service,
    };

    // Build router
    let app = api::router(state);

    // Configure TLS 1.3
    let addr: SocketAddr = config.listen_addr.parse()?;

    if config.tls_cert_path.is_some() && config.tls_key_path.is_some() {
        // TLS mode: HTTP/2 over TLS 1.3
        let tls_config = RustlsConfig::from_pem_file(
            config.tls_cert_path.as_ref().unwrap(),
            config.tls_key_path.as_ref().unwrap(),
        )
        .await?;

        tracing::info!(%addr, "listening with TLS 1.3");

        axum_server::bind_rustls(addr, tls_config)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await?;
    } else {
        // Plaintext mode (for development/testing only)
        tracing::warn!(
            %addr,
            "listening WITHOUT TLS — development mode only"
        );

        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    }

    tracing::info!("server shut down gracefully");
    Ok(())
}

/// Wait for SIGINT or SIGTERM for graceful shutdown.
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to listen for ctrl+c");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to listen for SIGTERM")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("shutdown signal received");
}
