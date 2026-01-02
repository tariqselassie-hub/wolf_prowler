use axum::{
    extract::{Json, State},
    routing::{get, post},
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use std::net::SocketAddr;
use std::path::PathBuf;
use wolf_net::{
    api::{ApiResponse, BroadcastRequest, ConnectPeerRequest, WolfNodeControl},
    wolf_node::WolfNode,
    WolfConfig,
};

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

    // Get control handle for the API
    let control = node.get_control();

    // Start WolfNode in a background task
    tokio::spawn(async move {
        if let Err(e) = node.run().await {
            tracing::error!("WolfNode fatal error: {}", e);
        }
    });

    // Define API routes
    let app = Router::new()
        .route("/api/v1/status", get(status_handler))
        .route("/api/v1/peers/connect", post(connect_peer_handler))
        .route("/api/v1/messages/broadcast", post(broadcast_handler))
        .route("/api/v1/system/shutdown", post(shutdown_handler))
        .with_state(control);

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

// --- API Handlers ---

async fn status_handler() -> Json<ApiResponse<&'static str>> {
    Json(ApiResponse::success("WolfNode is running"))
}

async fn connect_peer_handler(
    State(control): State<WolfNodeControl>,
    Json(req): Json<ConnectPeerRequest>,
) -> Json<ApiResponse<String>> {
    match control.connect_peer(req.multiaddr).await {
        Ok(_) => Json(ApiResponse::success("Connection initiated".to_string())),
        Err(e) => Json(ApiResponse::error(e.to_string())),
    }
}

async fn broadcast_handler(
    State(control): State<WolfNodeControl>,
    Json(req): Json<BroadcastRequest>,
) -> Json<ApiResponse<String>> {
    match control.broadcast(req.message.into_bytes()).await {
        Ok(_) => Json(ApiResponse::success("Broadcast initiated".to_string())),
        Err(e) => Json(ApiResponse::error(e.to_string())),
    }
}

async fn shutdown_handler(State(control): State<WolfNodeControl>) -> Json<ApiResponse<String>> {
    match control.shutdown().await {
        Ok(_) => Json(ApiResponse::success("Shutdown initiated".to_string())),
        Err(e) => Json(ApiResponse::error(e.to_string())),
    }
}
