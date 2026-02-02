//! Wolf Server
//!
//! The main server component for Wolf Prowler, providing the API and dashboard integration.

mod api;
mod api_middleware;
mod tls;

mod wolfsec_integration;

use axum_server::tls_rustls::RustlsConfig;
use std::net::SocketAddr;
use std::path::PathBuf;
use wolf_net::{wolf_node::WolfNode, WolfConfig};

use crate::api::{create_router, AppState};
use crate::tls::TlsConfig;
use wolf_db::storage::WolfDbStorage;
use wolf_net::wolf_node::WolfNodeEvent;
use wolf_prowler::ingress_validation::{EventValidator, ValidatableEvent, WolfEventValidator};
use wolfsec::{WolfSecurity, WolfSecurityConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    wolf_prowler::utils::logging::init_logging_with_config(
        wolf_prowler::utils::logging::LoggerConfig {
            level: std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string()),
            file_logging: true,
            log_file: Some(PathBuf::from("logs/wolf_server.log")),
            json_format: false,
            console_colors: true,
        },
    )?;

    const VERSION: &str = env!("CARGO_PKG_VERSION");
    tracing::info!("🐺 Wolf Server v{} initializing...", VERSION);

    // Dynamic Version Validation
    // Ensure we are running a supported version
    if VERSION.starts_with("0.0.") {
        tracing::warn!("⚠️ Running unstable development version: {}", VERSION);
    } else {
        tracing::info!("✅ Running stable version: {}", VERSION);
    }

    // Load configuration
    // In a real deployment, this would load from a file or environment variables
    let config = WolfConfig::default();

    // Initialize WolfDb Persistence Layer
    let db_path = PathBuf::from("data/wolf_db");
    let wolf_db = WolfDbStorage::open(db_path.to_str().unwrap())?;
    tracing::info!("💽 WolfDb persistence layer initialized at {:?}", db_path);
    let persistence = std::sync::Arc::new(tokio::sync::RwLock::new(wolf_db));

    // Initialize WolfSecurity
    let mut security_config = WolfSecurityConfig::default();
    security_config.db_path = PathBuf::from("data/wolfsec_db");
    let mut wolf_security = WolfSecurity::create(security_config).await?;
    wolf_security.initialize().await?;
    let security = std::sync::Arc::new(tokio::sync::RwLock::new(wolf_security));
    tracing::info!("🛡️ WolfSecurity engine initialized");

    // Initialize WolfNode
    tracing::info!("Initializing WolfNode...");
    let mut node = WolfNode::new(config).await?;

    // Initialize Security Event Validator
    let event_validator = WolfEventValidator::new();
    tracing::info!("🛡️ Security Event Validator initialized.");

    // Initialize AppState with shared resources from WolfNode
    let app_state = AppState {
        wolf_state: node.wolf_state.clone(),
        metrics: node.metrics.clone(),
        control: node.get_control(),
        auth_token: node.auth_token.clone(),
        persistence: Some(persistence),
        security,
    };

    // Start WolfNode in a background task
    tokio::spawn(async move {
        // Manually start background services since we are taking over the event loop
        if let Some(mut reporting) = node.reporting.take() {
            tokio::spawn(async move {
                reporting.run().await;
            });
        }

        if let Some(hub) = node.hub_orchestration.take() {
            tracing::info!("Initializing Hub Orchestration loop...");
            tokio::spawn(async move {
                if let Err(e) = hub.run().await {
                    tracing::error!("Hub Orchestration failed: {}", e);
                }
            });
        }

        tracing::info!("Starting Discovery Service...");
        if let Err(e) = node.discovery.start() {
            tracing::error!("Failed to start discovery: {}", e);
        }

        while let Some(event) = node.next_event().await {
            // Validate ingress events (Discovery)
            // Internal events (Command, SyncDht, Shutdown) are trusted
            if let WolfNodeEvent::Discovery(peer_info) = &event {
                let adapter = DiscoveryEventAdapter(peer_info);
                if let Err(e) = event_validator.validate_ingress(&adapter) {
                    tracing::warn!("🛡️ Security Alert: Dropped malicious event: {}", e);
                    continue;
                }
            }

            if let Err(e) = node.process_event(event).await {
                tracing::error!("Error processing event: {}", e);
            }
        }
    });

    // Create the router using the centralized configuration in api.rs
    let app = create_router(app_state);

    // Start HTTP Server
    let addr = SocketAddr::from(([0, 0, 0, 0], 3030));

    // TLS Setup
    // Check environment for production certificates first
    let (cert_path, key_path) = match TlsConfig::from_env()? {
        Some(config) => (config.cert_path, config.key_path),
        None => {
            // Fallback to self-signed certificates (Development Mode)
            let cert_dir = PathBuf::from("certs");
            if !cert_dir.exists() {
                std::fs::create_dir_all(&cert_dir)?;
            }
            let cert_path = cert_dir.join("cert.pem");
            let key_path = cert_dir.join("key.pem");

            if !cert_path.exists() || !key_path.exists() {
                tracing::warn!(
                    "⚠️ No TLS certificates found. Generating self-signed certificates..."
                );
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
            (cert_path, key_path)
        }
    };

    let tls_config = RustlsConfig::from_pem_file(&cert_path, &key_path).await?;

    // TLS Hot-Reloading (SIGHUP)
    // Allows rotating certificates without restarting the server
    let tls_config_reload = tls_config.clone();
    let cert_path_reload = cert_path.clone();
    let key_path_reload = key_path.clone();

    tokio::spawn(async move {
        #[cfg(unix)]
        {
            let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
                .expect("Failed to install SIGHUP handler");
            loop {
                sighup.recv().await;
                tracing::info!("🔄 SIGHUP received. Reloading TLS certificates...");
                if let Err(e) = tls_config_reload
                    .reload_from_pem_file(&cert_path_reload, &key_path_reload)
                    .await
                {
                    tracing::error!("❌ Failed to reload TLS certificates: {}", e);
                } else {
                    tracing::info!("✅ TLS certificates reloaded successfully.");
                }
            }
        }
    });

    tracing::info!("🔒 Secure Wolf Server listening on https://{}", addr);

    // axum-server with Rustls
    axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

/// Adapter to allow validating WolfNode events with the security engine
struct DiscoveryEventAdapter<'a>(&'a wolf_net::peer::PeerInfo);

impl<'a> ValidatableEvent for DiscoveryEventAdapter<'a> {
    fn source_peer(&self) -> &str {
        self.0.peer_id.as_str()
    }
    fn payload(&self) -> &[u8] {
        &[]
    }
    fn metadata(&self) -> &str {
        ""
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wolf_net::peer::{PeerId, PeerInfo};

    #[test]
    fn test_discovery_event_validation_integration() {
        let validator = WolfEventValidator::new();

        // 1. Valid Event Simulation
        let valid_peer = PeerInfo::new(PeerId::from_string("QmValidNodeID12345".to_string()));
        let adapter = DiscoveryEventAdapter(&valid_peer);
        assert!(
            validator.validate_ingress(&adapter).is_ok(),
            "Valid peer should pass validation"
        );

        // 2. Invalid Event Simulation (Empty PeerID)
        let invalid_peer = PeerInfo::new(PeerId::from_string("".to_string()));
        let adapter = DiscoveryEventAdapter(&invalid_peer);
        assert!(
            validator.validate_ingress(&adapter).is_err(),
            "Empty PeerID should be rejected"
        );

        // 3. Malicious Event Simulation (Control Characters in ID)
        let malicious_peer = PeerInfo::new(PeerId::from_string("Node\x00Inject".to_string()));
        let adapter = DiscoveryEventAdapter(&malicious_peer);
        assert!(
            validator.validate_ingress(&adapter).is_err(),
            "Malicious PeerID should be rejected"
        );
    }
}
