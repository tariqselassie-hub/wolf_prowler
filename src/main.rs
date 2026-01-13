// FILE: src/main.rs
//! Main entry point for Wolf Prowler.
//!
//! Dashboard modules have been removed. This core server initializes the P2P network,
//! security engine, and a minimal API surface with integrated secrets management.

mod config;
mod secrets;
mod simple_validation;

use anyhow::{Context, Result};
use axum::{response::Html, routing::get, Router};
use std::path::PathBuf;
use tower_http::services::ServeDir;

use config::SecureAppSettings;
use lock_prowler::headless::{HeadlessConfig, HeadlessWolfProwler};
use lock_prowler::storage::WolfStore;
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::{broadcast, RwLock};
use tracing::{error, info};
use wolf_db::storage::WolfDbStorage;
use wolf_net::{SwarmConfig, SwarmManager};
use wolf_prowler::persistence::PersistenceManager;
use wolf_web::dashboard::state::AppState; // For ID generation in bridge

// Use wolfsec types for consistency
use wolfsec::network_security::SecurityManager as NetworkSecurityManager;
use wolfsec::protection::container_security::{
    ContainerSecurityConfig, ContainerSecurityManager,
};
use wolfsec::identity::iam::{AuthenticationManager, IAMConfig};
use wolfsec::threat_detection::{BehavioralAnalyzer, ThreatDetectionConfig, ThreatDetector};
use wolfsec::WolfSecurity;

// Use the simple validation module
use dotenv::dotenv;
use sentinel;
use simple_validation::validate_libraries_simple;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<()> {
    // Load environment variables from .env file
    dotenv().ok();

    // Install default crypto provider
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                tracing_subscriber::EnvFilter::new(
                    "info,wolfsec=warn,wolf_prowler=info,h2=warn,hyper=warn",
                )
            }),
        )
        .init();

    info!(
        "🐺 Starting Wolf Prowler v{} (Headless/Dashboard Reset)",
        env!("CARGO_PKG_VERSION")
    );

    // Validation
    if let Err(e) = validate_libraries_simple().await {
        error!("Validation failed: {}", e);
        // Continue anyway for now, or return Err(e)
    }

    // Load secure configuration with encrypted credentials
    let secure_settings = SecureAppSettings::new()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to load secure configuration: {}", e))?;

    let settings = secure_settings.base_settings;

    // Initialize security policy
    let security_policy = wolf_prowler::core::security_policy::SecurityPolicy::from_stance(
        settings.security.stance.parse().unwrap_or_default(),
    );
    info!("🔒 Security Policy: {}", security_policy.description());

    // Initialize Security Bridge Channel early to pass to Swarm
    // Create a channel for security events from the network layer
    let (security_event_sender, mut security_event_receiver) =
        tokio::sync::mpsc::unbounded_channel();

    // Initialize Core Modules
    let wolfsec_config = wolfsec::WolfSecurityConfig::default();
    let mut wolf_security_instance = WolfSecurity::create(wolfsec_config).await?;
    wolf_security_instance.initialize().await?;
    let wolf_security = Arc::new(RwLock::new(wolf_security_instance));

    // Swarm Manager
    let (_broadcast_tx, _current_rx) = broadcast::channel::<String>(100);

    let swarm_config = SwarmConfig {
        keypair_path: settings.network.keypair_path.clone(),
        max_connections: settings.network.max_peers,
        enable_mdns: settings.network.enable_mdns,
        enable_dht: settings.network.enable_dht,
        security_event_sender: Some(security_event_sender),
        ..Default::default()
    };
    let swarm_manager = Arc::new(SwarmManager::new(swarm_config)?);

    // Bridge Network Security Events
    let wolf_security_bridge = wolf_security.clone();
    // let persistence_bridge = persistence.clone(); // Persistence handled by WolfSecurity

    tokio::spawn(async move {
        info!("🌉 Security Event Bridge active");
        while let Some(net_event) = security_event_receiver.recv().await {
            let wolf_security_bridge = wolf_security_bridge.clone();
            tokio::spawn(async move {
                // Map wolf_net event to wolfsec event
                // Note: Types might differ slightly, manual mapping required
                let severity = match net_event.severity {
                    wolf_net::event::SecuritySeverity::Low => wolfsec::SecuritySeverity::Low,
                    wolf_net::event::SecuritySeverity::Medium => wolfsec::SecuritySeverity::Medium,
                    wolf_net::event::SecuritySeverity::High => wolfsec::SecuritySeverity::High,
                    wolf_net::event::SecuritySeverity::Critical => {
                        wolfsec::SecuritySeverity::Critical
                    }
                };

                let event_type = match net_event.event_type {
                    wolf_net::event::SecurityEventType::Authentication => {
                        wolfsec::SecurityEventType::AuthenticationFailure
                    } // Approximation
                    wolf_net::event::SecurityEventType::Authorization => {
                        wolfsec::SecurityEventType::AuthorizationFailure
                    }
                    wolf_net::event::SecurityEventType::Network => {
                        wolfsec::SecurityEventType::NetworkIntrusion
                    } // Approximation
                    wolf_net::event::SecurityEventType::PolicyViolation => {
                        wolfsec::SecurityEventType::PolicyViolation
                    }
                    wolf_net::event::SecurityEventType::Other(s) => {
                        wolfsec::SecurityEventType::Other(s)
                    }
                    _ => wolfsec::SecurityEventType::SuspiciousActivity,
                };

                let mut sec_event = wolfsec::SecurityEvent::new(
                    event_type,
                    severity,
                    net_event.description.clone(),
                );

                if let Some(peer_id) = net_event.peer_id {
                    sec_event = sec_event.with_peer(peer_id);
                }

                // Feed into Security Engine
                let mut engine = wolf_security_bridge.write().await;
                if let Err(e) = engine.process_security_event(sec_event).await {
                    error!("Security Engine failed to process event: {}", e);
                }
            });
        }
    });

    // Network Security Manager
    let ns_manager = NetworkSecurityManager::new(
        "wolf-peer-dynamic".to_string(), // Simplified peer id gen
        security_policy.wolfsec_level.clone(),
    );
    ns_manager.initialize().await?;
    let _network_security_manager = Arc::new(ns_manager);

    // Persistence
    // WolfDb (PQC-Secured) local storage
    let persistence = PersistenceManager::new(settings.database.path.to_str().unwrap_or("wolf_data/wolf_prowler.db"))
        .await
        .ok() // Fail gracefully
        .map(Arc::new);

    if persistence.is_none() {
        error!("🚨 Persistence Manager unavailable - running in-memory only! Data will be lost on restart.");
    } else {
        info!("💾 Persistence Manager active");
    }

    // Container Security (with feature flag check implicit)
    // Container Security (with feature flag check implicit)
    let container_config = ContainerSecurityConfig::default();
    let _container_manager = ContainerSecurityManager::new(container_config)?;
    // FUTURE: Start container scanning loop if configured
    info!("📦 Container Security Manager initialized");

    // Start Headless Prowler (Hunter Mode)
    // We keep a reference to ensure we can stop it on shutdown
    let headless_prowler =
        if std::env::var("WOLF_HEADLESS").unwrap_or_else(|_| "true".to_string()) == "true" {
            info!("Initializing Headless Wolf Prowler (Hunter Mode)...");
            let store = WolfStore::new(&format!("wolf_data_{}.db", settings.node_id))
                .await
                .context("Failed to init headless store")?;

            let mut headless_config = HeadlessConfig::default();
            if let Ok(paths) = std::env::var("WOLF_SCAN_PATHS") {
                headless_config.scan_paths = paths.split(',').map(|s| s.to_string()).collect();
            }
            // Force WolfPack on for headless to test P2P interaction with main node
            headless_config.enable_wolfpack = true;

            let prowler = HeadlessWolfProwler::new(headless_config, store);
            prowler
                .start()
                .await
                .context("Failed to start headless prowler")?;
            Some(prowler)
        } else {
            None
        };

    // Initialize TersecPot Sentinel
    info!("🛡️ Starting TersecPot Sentinel Daemon...");
    tokio::spawn(async {
        if let Err(e) = sentinel::start_sentinel().await {
            error!("❌ Sentinel Daemon failed: {}", e);
        }
    });

    // Use the secure settings vault that was already initialized
    let _secrets_vault = secure_settings.vault.clone();

    // Initialize dashboard state with real system components
    let auth_manager = AuthenticationManager::new(IAMConfig::default())
        .await
        .unwrap();
    let app_state = AppState::with_system_components(
        ThreatDetector::new(
            ThreatDetectionConfig::default(),
            Arc::new(
                wolfsec::infrastructure::persistence::wolf_db_threat_repository::WolfDbThreatRepository::new(
                    if let Some(pm) = &persistence {
                        pm.get_storage()
                    } else {
                        // Fallback if persistence manager failed to load, though this will likely fail too if lock is issue
                        Arc::new(RwLock::new(
                            WolfDbStorage::open(settings.database.path.to_str().unwrap_or("wolf_data/wolf_prowler.db"))
                                .expect("Failed to open WolfDb for ThreatDetector"),
                        ))
                    },
                ),
            ),
        ),
        BehavioralAnalyzer {
            baseline_window: 100,
            deviation_threshold: 2.0,
            patterns_detected: 0,
        },
        // AnomalyDetector::new(), // Removed from AppState
        auth_manager,
        wolf_security.clone(),
        swarm_manager.clone(),
    );

    // Create dashboard router
    let dashboard_router = wolf_web::dashboard::create_router_with_state(app_state).await;

    // Create app with dashboard and static file serving
    let app = Router::new()
        .route("/", get(|| async { "🐺 Wolf Prowler Dashboard" }))
        .route("/health", get(|| async { "OK" }))
        .nest("/api", dashboard_router)
        .nest_service("/static", ServeDir::new("static"))
        .route(
            "/dashboard",
            get(|| async {
                Html(
                    std::fs::read_to_string("static/dashboard.html").unwrap_or_else(|_| {
                        "<html><body>Dashboard not found</body></html>".to_string()
                    }),
                )
            }),
        );

    let port = settings.dashboard.port;
    let addr = SocketAddr::from(([127, 0, 0, 1], port));

    // TLS Configuration: Check env vars or generate
    let tls_config = if let (Ok(cert_path), Ok(key_path)) =
        (std::env::var("CERT_FILE"), std::env::var("KEY_FILE"))
    {
        info!(
            "🔐 Loading TLS certificates from environment: {}, {}",
            cert_path, key_path
        );
        axum_server::tls_rustls::RustlsConfig::from_pem_file(
            PathBuf::from(cert_path),
            PathBuf::from(key_path),
        )
        .await?
    } else {
        info!("🔐 No certificates provided. Generating self-signed certificates for HTTPS...");
        let (cert_pem, key_pem) = wolf_den::certs::generate_self_signed_cert(vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
        ])
        .expect("Failed to generate self-signed certificates");

        axum_server::tls_rustls::RustlsConfig::from_pem(
            cert_pem.as_bytes().to_vec(),
            key_pem.as_bytes().to_vec(),
        )
        .await?
    };

    info!("🚀 Wolf Prowler Dashboard running at https://{}", addr);
    info!("📊 Dashboard available at https://{}/dashboard", addr);
    info!("🔌 WebSocket available at ws://{}/ws/dashboard", addr);

    // Serve
    // Shutdown Handle
    let handle = axum_server::Handle::new();
    let shutdown_handle = handle.clone();

    // Spawn shutdown listener
    tokio::spawn(async move {
        match tokio::signal::ctrl_c().await {
            Ok(()) => info!("Shutdown signal received, initiating graceful shutdown..."),
            Err(e) => error!("Failed to listen for shutdown signal: {}", e),
        }

        // Stop Headless Prowler if active
        if let Some(headless) = headless_prowler {
            info!("Stopping Headless Prowler...");
            if let Err(e) = headless.stop().await {
                error!("Error stopping headless prowler: {}", e);
            }
        }

        // Stop Web Server
        info!("Stopping Web Server...");
        shutdown_handle.graceful_shutdown(Some(Duration::from_secs(5)));
    });

    // Serve
    axum_server::bind_rustls(addr, tls_config)
        .handle(handle)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}
