mod api;

use axum_server::tls_rustls::RustlsConfig;
use std::net::SocketAddr;
use std::path::PathBuf;
use wolf_net::{wolf_node::WolfNode, WolfConfig};

use crate::api::{create_router, AppState};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    tracing::info!("🐺 Wolf Server initializing...");

    // Load configuration
    // In a real deployment, this would load from a file or environment variables
    let config = WolfConfig::default();

    // Initialize WolfNode
    tracing::info!("Initializing WolfNode...");
    let mut node = WolfNode::new(config).await?;

    // Initialize AppState with shared resources from WolfNode
    let app_state = AppState {
        wolf_state: node.wolf_state.clone(),
        metrics: node.metrics.clone(),
        control: node.get_control(),
        auth_token: node.auth_token.clone(),
    };

    // Start WolfNode in a background task
    tokio::spawn(async move {
        if let Err(e) = node.run().await {
            tracing::error!("WolfNode fatal error: {}", e);
        }
    });

    // Create the router using the centralized configuration in api.rs
    let app = create_router(app_state);

    // Start HTTP Server
    let addr = SocketAddr::from(([0, 0, 0, 0], 3030));

    // TLS Setup
    let cert_dir = PathBuf::from("certs");
    if !cert_dir.exists() {
        std::fs::create_dir_all(&cert_dir)?;
    }
    let cert_path = cert_dir.join("cert.pem");
    let key_path = cert_dir.join("key.pem");

    if !cert_path.exists() || !key_path.exists() {
        tracing::warn!("⚠️ No TLS certificates found. Generating self-signed certificates...");
        let (cert_pem, key_pem) = wolf_den::certs::generate_self_signed_cert(vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
        ])?;
        std::fs::write(&cert_path, cert_pem)?;
        std::fs::write(&key_path, key_pem)?;
        tracing::info!("✅ Generated self-signed certificates in {:?}", cert_dir);
    } else {
        tracing::info!("🔐 Loading TLS certificates from {:?}", cert_dir);
    }

    let tls_config = RustlsConfig::from_pem_file(&cert_path, &key_path).await?;

    tracing::info!("🔒 Secure Wolf Server listening on https://{}", addr);

    // axum-server with Rustls
    axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}
