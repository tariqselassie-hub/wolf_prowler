// FILE: src/main.rs
//! Main entry point for the consolidated Wolf Prowler dashboard application.
//! This binary serves a comprehensive web dashboard with live P2P network monitoring,
//! cryptographic utilities, and security status endpoints.

mod simple_validation;

use anyhow::Result;
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        DefaultBodyLimit, State,
    },
    http::{header, Method, StatusCode},
    middleware,
    response::{IntoResponse, Redirect},
    routing::{delete, get, post},
    Router,
};

#[cfg(not(feature = "headless-agent"))]
use axum::{extract::ConnectInfo, Json};

#[cfg(not(feature = "headless-agent"))]
use axum_extra::extract::cookie::Cookie;
use axum_extra::extract::CookieJar;
use chrono::Utc;
#[cfg(not(feature = "headless-agent"))]
use sqlx::PgPool;

use wolf_prowler::dashboard::api::{self, *};
use wolf_prowler::dashboard::api_geoip::*;
use wolf_prowler::dashboard::api_health::*;
use wolf_prowler::dashboard::api_territory::*;
use wolf_prowler::dashboard::api_territory_scan::*;
use wolf_prowler::dashboard::handlers;
use wolf_prowler::dashboard::hub_admin;
use wolf_prowler::dashboard::hub_api;
use wolf_prowler::dashboard::state::*;

// use futures::sink::SinkExt;
use wolf_prowler::network_extensions::{
    NetworkSecurityEvent, NetworkSecurityManagerExt, SwarmManagerExt,
};

use serde::Deserialize;
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::{
    signal,
    sync::{broadcast, RwLock},
};
use tower::ServiceBuilder;
use tower_cookies::CookieManagerLayer;
#[cfg(not(feature = "headless-agent"))]
use tower_http::services::ServeDir;
use tracing::{debug, error, info, warn};
use uuid::Uuid;
use wolf_den::CryptoEngine;
use wolf_net::{PeerId, SwarmCommand, SwarmConfig, SwarmManager};
use wolf_prowler::core::{AppSettings, P2PNetwork, ReportingService, WolfRole};
use wolf_prowler::persistence::PersistenceManager;
use wolf_prowler::utils::metrics_simple::{MetricsCollector, SystemEvent};
use wolfsec::network_security::{SecurityManager as NetworkSecurityManager, MEDIUM_SECURITY};
use wolfsec::security::advanced::container_security::{
    ContainerSecurityConfig, ContainerSecurityManager,
};
use wolfsec::security::advanced::SecurityManager;
use wolfsec::WolfSecurity;

// Use the simple validation module
use simple_validation::validate_libraries_simple;

use wolf_prowler::threat_feeds::{ThreatDatabase, ThreatFeedManager};
use wolfsec::security::advanced::compliance::{ComplianceConfig, ComplianceFrameworkManager};
use wolfsec::security::advanced::risk_assessment::{RiskAssessmentConfig, RiskAssessmentManager};

const AUTH_COOKIE_NAME: &str = "wolf_prowler_auth";

fn get_dynamic_peer_id() -> String {
    // Generate a unique peer ID based on system info
    let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string());
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    format!("wolf-{}-{}", hostname, timestamp)
}

use dotenv::dotenv;

#[tokio::main]
async fn main() -> Result<()> {
    // Load environment variables from .env file
    dotenv().ok();

    // Install default crypto provider to avoid panics with rustls 0.23+
    // We ignore the error in case it's already installed
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Initialize logging
    // Initialize logging to stdout
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                tracing_subscriber::EnvFilter::new(
                    "info,wolfsec=warn,wolf_prowler=info,h2=warn,hyper=warn",
                )
            }),
        )
        .init();

    info!("🐺 Starting Wolf Prowler v{}", env!("CARGO_PKG_VERSION"));

    // Run simple startup validation to ensure libraries are linked and basically functional
    match validate_libraries_simple().await {
        Ok(results) => {
            if !results.overall_success {
                error!("- Simple library validation failed. Aborting startup. -");
                for err in results.errors {
                    error!("  - {}", err);
                }
                eprintln!("❌ Startup Failed: Library validation failed. Check logs/wolf_prowler.log for details.");
                return Err(anyhow::anyhow!("Library validation failed"));
            }
        }
        Err(e) => {
            error!(
                "- An error occurred during simple library validation: {} -",
                e
            );
            eprintln!(
                "❌ Startup Failed: Validation error: {}. Check logs/wolf_prowler.log for details.",
                e
            );
            return Err(e);
        }
    }

    // Load configuration
    let settings = match AppSettings::new() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("❌ Failed to load configuration from settings.toml: {}", e);
            return Err(anyhow::anyhow!("Configuration loading failed"));
        }
    };
    info!("📋 Configuration loaded successfully.");

    // Initialize security policy from configuration
    let security_policy = wolf_prowler::core::security_policy::SecurityPolicy::from_stance(
        settings.security.stance.parse().unwrap_or_else(|_| {
            warn!(
                "Invalid security stance '{}' in settings, defaulting to Medium.",
                settings.security.stance
            );
            Default::default()
        }),
    );
    info!("🔒 Security Policy: {}", security_policy.description());

    // Initialize P2P network
    let p2p_network = P2PNetwork::new(&settings.network)?;
    info!(
        "🔗 P2P Network initialized with ID: {}",
        p2p_network.local_peer_id()
    );

    // Initialize other core modules with security policy
    let crypto_engine = Arc::new(CryptoEngine::new(security_policy.wolf_den_level)?);
    let wolfsec_config = wolfsec::WolfSecurityConfig::default();
    let mut wolf_security_instance = WolfSecurity::new(wolfsec_config)?;
    wolf_security_instance.initialize().await?;
    let wolf_security = Arc::new(RwLock::new(wolf_security_instance));
    info!("🔐 Crypto and Security modules initialized");

    // Create a broadcast channel for real-time updates.
    let (broadcast_tx, _) = broadcast::channel(100);

    // Create a channel for security events from the network layer
    let (security_event_sender, mut security_event_receiver) =
        tokio::sync::mpsc::unbounded_channel();

    // Initialize SwarmManager for pack member discovery
    let swarm_config = SwarmConfig {
        keypair_path: settings.network.keypair_path.clone(),
        max_connections: settings.network.max_peers,
        enable_mdns: settings.network.enable_mdns,
        enable_dht: settings.network.enable_dht,
        security_event_sender: Some(security_event_sender),
        ..Default::default()
    };

    let swarm_manager = Arc::new(SwarmManager::new(swarm_config)?);

    // SOAR Integration: Pass swarm command sender to WolfSecurity
    {
        let sender = swarm_manager.command_sender().clone();
        wolf_security.write().await.with_swarm_sender(sender);
    }

    // Bridge Network Security Events to WolfSecurity
    let wolf_security_bridge = wolf_security.clone();
    tokio::spawn(async move {
        info!("🌉 Network Security Event Bridge started");
        while let Some(net_event) = security_event_receiver.recv().await {
            // Map wolf_net::event::SecurityEvent to wolfsec::SecurityEvent

            // Map Severity
            let severity = match net_event.severity {
                wolf_net::event::SecuritySeverity::Low => wolfsec::SecuritySeverity::Low,
                wolf_net::event::SecuritySeverity::Medium => wolfsec::SecuritySeverity::Medium,
                wolf_net::event::SecuritySeverity::High => wolfsec::SecuritySeverity::High,
                wolf_net::event::SecuritySeverity::Critical => wolfsec::SecuritySeverity::Critical,
            };

            // Map Type
            let event_type = match net_event.event_type {
                wolf_net::event::SecurityEventType::Authentication => {
                    wolfsec::SecurityEventType::AuthenticationFailure
                }
                wolf_net::event::SecurityEventType::Authorization => {
                    wolfsec::SecurityEventType::AuthorizationFailure
                }
                wolf_net::event::SecurityEventType::Encryption => {
                    wolfsec::SecurityEventType::Other("EncryptionError".to_string())
                }
                wolf_net::event::SecurityEventType::Network => {
                    wolfsec::SecurityEventType::NetworkIntrusion
                }
                wolf_net::event::SecurityEventType::PolicyViolation => {
                    wolfsec::SecurityEventType::PolicyViolation
                }
                wolf_net::event::SecurityEventType::Other(s) => {
                    wolfsec::SecurityEventType::Other(s)
                }
            };

            let mut sec_event =
                wolfsec::SecurityEvent::new(event_type, severity, net_event.description);

            if let Some(peer) = net_event.peer_id {
                sec_event = sec_event.with_peer(peer);
            }

            // Process in WolfSecurity
            if let Err(e) = wolf_security_bridge
                .write()
                .await
                .process_security_event(sec_event)
                .await
            {
                error!("❌ Failed to process security event in bridge: {}", e);
            }
        }
    });

    // Create the consolidated application state
    let ns_manager = NetworkSecurityManager::new(
        get_dynamic_peer_id().to_string(),
        security_policy.wolfsec_level.clone(),
    );
    ns_manager.initialize().await?;
    let network_security_manager = Arc::new(ns_manager);

    // Create security manager
    // Initialize advanced security configuration
    let mut advanced_security_config = wolfsec::security::advanced::SecurityConfig::default();

    // Configure Generative AI from settings
    if let Some(url) = settings.ai.llm_api_url.clone() {
        if !url.is_empty() {
            info!("🧠 Enabling Generative AI features with LLM at {}", url);
            advanced_security_config.ml_security_config.llm_api_url = Some(url);
        }
    }

    let security_manager = Arc::new(SecurityManager::new(advanced_security_config).await?);

    // Initialize Container Security Manager
    let container_security_config = ContainerSecurityConfig::default();
    let container_security = Arc::new(RwLock::new(ContainerSecurityManager::new(
        container_security_config,
    )?));

    // Initialize Risk Assessment Manager
    let risk_config = RiskAssessmentConfig::default();
    let risk_manager = Arc::new(RwLock::new(RiskAssessmentManager::new(risk_config)?));

    // Initialize Compliance Manager
    let compliance_config = ComplianceConfig::default();
    let compliance_manager = Arc::new(RwLock::new(ComplianceFrameworkManager::new(
        compliance_config,
    )?));

    // Initialize Persistence Manager
    let persistence = match PersistenceManager::new(&settings.database.url).await {
        Ok(pm) => {
            info!("🗄️ Persistence Manager initialized");
            Some(Arc::new(pm))
        }
        Err(e) => {
            error!("❌ Failed to initialize Persistence Manager: {}", e);
            None
        }
    };

    #[cfg(feature = "advanced_reporting")]
    let db_pool = persistence.as_ref().map(|pm| pm.pool().clone());

    // Initialize Threat Intelligence Database & Manager
    let threat_db = Arc::new(RwLock::new(ThreatDatabase::default()));
    let threat_feed_manager = ThreatFeedManager::new(threat_db.clone());
    threat_feed_manager.start_background_updates().await;

    // Initialize security events early to share across services
    let security_events_global = Arc::new(RwLock::new(Vec::new()));

    // Initialize HowlService
    let howl_service = Arc::new(HowlService {
        howl_messages: Arc::new(RwLock::new(Vec::new())),
        howl_channels: Arc::new(RwLock::new(HashMap::new())),
        message_routes: Arc::new(RwLock::new(HashMap::new())),
        active_sessions: Arc::new(RwLock::new(HashMap::new())),
        network_security: network_security_manager.clone(),
        security_events: security_events_global.clone(),
        message_store: Arc::new(RwLock::new(Vec::new())),
        message_metadata: Arc::new(RwLock::new(HashMap::new())),
        swarm_manager: swarm_manager.clone(),
    });

    // Initialize ThreatService
    let threat_service = Arc::new(ThreatService {
        threat_db: threat_db.clone(),
        wolf_security: wolf_security.clone(),
        security_events: security_events_global.clone(),
    });

    // Initialize VaultService
    let vault_service = Arc::new(VaultService {
        vault: Arc::new(RwLock::new(Vec::new())),
        unlocked_key: Arc::new(RwLock::new(None)),
        crypto: crypto_engine.clone(),
        config: Arc::new(RwLock::new(settings.clone())),
    });

    let settings_arc = Arc::new(RwLock::new(settings.clone()));

    let app_state = AppState::new(wolf_prowler::dashboard::state::AppStateInner {
        config: settings_arc.clone(),
        network: Arc::new(RwLock::new(p2p_network)),
        security_events: security_events_global,
        crypto: crypto_engine,
        wolf_security,
        security_manager,
        broadcast_tx: broadcast_tx.clone(),
        peers: Arc::new(RwLock::new(HashMap::new())),
        sessions: Arc::new(RwLock::new(HashMap::new())),
        swarm_manager,
        metrics: Arc::new(MetricsCollector::new()),
        security_level: Arc::new(MEDIUM_SECURITY),
        container_security,
        system_metrics: Arc::new(RwLock::new(SystemMetricsData::default())),
        risk_manager,
        compliance_manager,
        howl_service,
        vault_service,
        threat_service,
        #[cfg(feature = "advanced_reporting")]
        db_pool,
        persistence,
        security_policy: Arc::new(RwLock::new(security_policy)),
        wolf_brain: Arc::new(wolf_prowler::wolf_brain::LlamaClient::new(
            settings_arc,
            Some(settings.ai.model_name.clone()),
        )),
        login_attempts: Arc::new(RwLock::new(HashMap::new())),
    });
    info!("✅ Application state created");

    // Start background task for system metrics collection with real sysinfo data
    let system_metrics_clone = app_state.system_metrics.clone();
    tokio::spawn(async move {
        wolf_prowler::dashboard::system_monitor::system_metrics_collector(system_metrics_clone)
            .await;
    });

    // Start background tasks for monitoring and broadcasting events.
    let state_clone_for_monitoring = app_state.clone();
    tokio::spawn(async move {
        monitor_and_broadcast(state_clone_for_monitoring).await;
    });

    // Start background task for network message handling
    let state_clone_for_network = app_state.clone();
    tokio::spawn(async move {
        handle_network_messages(state_clone_for_network).await;
    });

    // SaaS Hub Reporting Service (Agent role)
    let reporting_service = Arc::new(ReportingService::new(
        app_state.config.clone(),
        app_state.system_metrics.clone(),
    ));
    let reporting_clone = reporting_service.clone();
    tokio::spawn(async move {
        reporting_clone.start().await;
    });

    // Protected API and WebSocket routes that require authentication
    let protected_api_routes = Router::new()
        .route("/ws", get(websocket_handler))
        .route("/logout", get(handlers::logout_handler))
        // Navigation Hub (authenticated)
        .route("/nav", get(handlers::nav_hub_handler))
        .route("/dashboard", get(handlers::dashboard_handler))
        .route("/api/dashboard", get(api::api_dashboard_data)) // New dashboard data endpoint
        .route("/crypto", get(handlers::crypto_handler))
        .route("/settings", get(handlers::settings_handler))
        .route("/logs", get(handlers::logs_handler))
        .route("/monitoring", get(handlers::monitoring_handler))
        .route("/p2p", get(handlers::p2p_handler))
        .route("/packs", get(handlers::packs_handler))
        .route("/howl", get(handlers::howl_handler))
        .route("/network", get(handlers::network_handler))
        .route("/security", get(handlers::security_handler))
        .route("/threats", get(handlers::threat_detection_handler))
        .route("/compliance", get(handlers::compliance_handler))
        .route("/neural", get(handlers::neural_center_handler))
        .route(
            "/api/v1/compliance/run_assessment",
            post(api_compliance_run_assessment),
        )
        .route(
            "/api/v1/compliance/export/pdf",
            get(api_compliance_export_pdf),
        )
        .route("/api/v1/compliance/verify", post(api_compliance_verify))
        .route("/api/v1/auth/unblock", post(api_v1_auth_unblock))
        .route("/api/v1/neural/state", get(api_neural_network_state))
        .route(
            "/api/v1/neural/summarize",
            get(api::api_v1_neural_summarize),
        )
        .route(
            "/api/v1/neural/suggest_rules",
            get(api::api_v1_neural_suggest_rules),
        )
        .route(
            "/static/timezone_settings.html",
            get(handlers::timezone_settings_handler),
        )
        .route(
            "/static/scent_trails.html",
            get(handlers::scent_trails_handler),
        )
        .route(
            "/static/lunar_calendar.html",
            get(handlers::lunar_calendar_handler),
        )
        .route(
            "/static/territory_marking.html",
            get(handlers::territory_marking_handler),
        )
        // Cloud Security
        .route("/cloud", get(handlers::cloud_security_handler))
        .route("/api/cloud/aws/scan", post(api_cloud_scan_aws))
        .route("/api/cloud/status", get(api_cloud_status))
        // Security Policy
        .route("/security_policy", get(handlers::security_policy_handler))
        .route("/api/security/policy", get(api::api_security_policy_get))
        .route("/api/security/policy", post(api::api_security_policy_set))
        .route("/api/security/stances", get(api::api_security_stances))
        // System APIs
        .route("/api/status", get(api_status))
        .route("/api/peers", get(api_peers))
        .route("/api/territory/peers", get(api_territory_peers))
        .route("/api/territory/scan", post(api_territory_scan))
        .route("/api/territory/interfaces", get(api_list_interfaces))
        .route("/api/geoip/resolve", post(api_geoip_resolve))
        .route("/api/geoip/stats", get(api_geoip_stats))
        .route("/api/health", get(api_health)) // Health monitoring endpoint
        .route("/api/peer_status", get(api_peer_status))
        .route("/api/events", get(api_events))
        .route("/api/role", get(api_user_role))
        .route(
            "/api/settings",
            get(api_settings_get).post(api_settings_update),
        )
        // Wolf Den Vault APIs
        .route("/api/vault/unlock", post(api_vault_unlock))
        .route("/api/vault/contents", get(api_vault_contents))
        .route("/api/vault/add", post(api_vault_add))
        .route("/api/vault/delete", delete(api_vault_delete))
        .route("/api/vault/export", get(api_vault_export))
        .route("/api/vault/clear", delete(api_vault_clear))
        // Wolf Howl Communication APIs
        .route("/api/howl/send", post(api_howl_send))
        .route("/api/howl/broadcast", post(api_howl_broadcast))
        .route("/api/howl/messages", get(api_howl_messages))
        .route("/api/howl/channels", get(api_howl_channels))
        // Crypto APIs
        .route("/api/crypto/hash", post(api_hash))
        .route("/api/crypto/kdf", post(api_kdf))
        .route("/api/crypto/mac", post(api_mac))
        // Security APIs
        .route("/api/security/status", get(api_security_status))
        .route("/api/security/events", get(api_security_events))
        .route("/api/security/threats", get(api_security_threats))
        // Placeholder APIs for unimplemented features
        .route("/api/threat/intelligence", get(api_threat_intelligence))
        .route("/api/cve/feed", get(api_cve_feed))
        .route("/api/zero/trust", get(api_zero_trust))
        .route("/api/siem/analytics", get(api_siem_analytics))
        // API v1 endpoints
        .route("/api/v1/system/metrics", get(api_system_metrics))
        .route("/api/v1/network/status", get(api_v1_network_status))
        .route("/api/v1/security/metrics", get(api_v1_security_metrics))
        .route("/api/v1/behavioral/metrics", get(api_v1_behavioral_metrics))
        .route("/api/v1/peer/:id/behavior", get(api_v1_peer_behavior))
        .route("/api/v1/crypto/metrics", get(api_v1_crypto_metrics))
        .route(
            "/api/v1/system/metrics/history",
            get(api_v1_system_metrics_history),
        )
        .route("/api/v1/crypto/status", get(api_v1_crypto_status))
        // New Advanced Endpoints
        .route("/api/v1/risk/assessment", get(api_risk_assessment))
        .route("/api/v1/compliance/status", get(api_compliance_status))
        .route(
            "/api/v1/threat/intelligence",
            get(api_v1_threat_intelligence),
        )
        .route("/api/v1/cve/feed", get(api_cve_feed))
        .route("/api/v1/zero/trust", get(api_zero_trust))
        .route("/api/v1/siem/analytics", get(api_siem_analytics))
        .route("/api/v1/active/threats", get(api_v1_active_threats))
        .route("/api/v1/threat/:id", get(api_v1_threat_details))
        .route("/api/v1/threat/resolve", post(api_v1_threat_resolve))
        .route("/api/v1/threat/ignore", post(api_v1_threat_ignore))
        .route("/api/v1/threat/history", get(api_v1_threat_history))
        .route("/api/v1/threat/export", get(api_v1_threat_export))
        .route("/api/v1/threat/stats", get(api_v1_threat_stats))
        .route("/api/v1/threat/timeline", get(api_v1_threat_timeline))
        .route("/api/v1/threat/feed/status", get(api_v1_threat_feed_status))
        .route(
            "/api/v1/threat/feed/refresh",
            post(api_v1_threat_feed_refresh),
        )
        .route(
            "/api/v1/threat/feed/config",
            post(api_v1_threat_feed_config),
        )
        .route("/api/v1/threat/feed/reset", post(api_v1_threat_feed_reset))
        .route(
            "/api/v1/threat/feed/validate",
            post(api_v1_threat_feed_validate),
        )
        .route("/api/v1/threat/feed/backup", get(api_v1_threat_feed_backup))
        .route(
            "/api/v1/threat/feed/restore",
            post(api_v1_threat_feed_restore),
        )
        .route("/api/v1/threat/block_ip", post(api_v1_threat_block_ip))
        .route("/api/v1/threat/unblock_ip", post(api_v1_threat_unblock_ip))
        .route("/api/v1/threat/search", get(api_v1_threat_search))
        .route("/api/v1/threat/report", get(api_v1_threat_report))
        .route("/api/v1/scan/trigger", post(api_v1_scan_trigger))
        .route(
            "/api/v1/ai/connection/test",
            post(api_v1_test_ai_connection),
        )
        .route("/api/v1/neural/command", post(api_v1_neural_command))
        .route("/api/v1/threat/scan", post(api_v1_threat_scan_trigger))
        .route("/api/system/metrics", get(api_system_metrics))
        .route("/api/network/status", get(api_network_status))
        .route("/api/network/peers", get(api_network_peers))
        .route("/api/network/peer/:id", get(api_network_peer_details))
        .route("/api/network/peer/:id", delete(api_network_block))
        .route("/api/network/metrics", get(api_network_metrics))
        .route("/api/network/dial", post(api_network_dial))
        .route("/api/network/topology", get(api_network_topology))
        // Firewall APIs
        .route("/api/v1/firewall/rules", get(api_firewall_get_rules))
        .route("/api/v1/firewall/rules/add", post(api_firewall_add_rule))
        .route(
            "/api/v1/firewall/rules/delete",
            post(api_firewall_delete_rule),
        )
        .route("/api/v1/firewall/toggle", post(api_firewall_toggle))
        // Consensus APIs
        .route("/api/v1/consensus/status", get(api_consensus_status))
        .route("/api/v1/consensus/state", get(api_consensus_state))
        .route("/api/v1/consensus/propose", post(api_consensus_propose))
        .route("/api/v1/system/panic", post(handlers::api_system_panic))
        .route("/api/wolf_pack/state", get(api_wolf_pack_state))
        .route("/api/wolf_pack/hunts", get(api_wolf_pack_hunts))
        .route(
            "/api/wolf_pack/initiate_hunt",
            post(api_wolf_pack_initiate_hunt),
        )
        .route("/api/wolf_pack/peers", get(api_wolf_pack_peers))
        // OMEGA CONTROL DOMINANCE APIs
        .route("/api/user/role", get(api_omega_user_role))
        .route("/api/omega/force_rank", post(api_omega_force_rank))
        .route("/api/omega/force_prestige", post(api_omega_force_prestige))
        // Auth middleware enabled for protected routes
        .route_layer(axum::middleware::from_fn_with_state(
            app_state.clone(),
            auth_middleware,
        ))
        .with_state(app_state.clone());

    // Create the main application router
    let mut app = Router::new();

    // Only include Web UI and static assets if NOT in headless-agent mode
    #[cfg(not(feature = "headless-agent"))]
    {
        info!("🖥️ Dashboard UI enabled - serving static assets");
        app = app
            .route("/", get(handlers::root_handler))
            .route(
                "/login",
                post(handlers::login_handler).layer(axum::middleware::from_fn_with_state(
                    app_state.clone(),
                    login_rate_limit_middleware,
                )),
            )
            .route(
                "/api/v1/login",
                post(api::api_login_json).layer(axum::middleware::from_fn_with_state(
                    app_state.clone(),
                    login_rate_limit_middleware,
                )),
            )
            .route(
                "/security-dashboard",
                get(handlers::security_dashboard_handler),
            )
            .nest_service("/static", ServeDir::new("wolf_web/static"))
            .fallback_service(
                ServeDir::new("wolf_web/static").append_index_html_on_directories(true),
            )
            .route("/network-map", get(handlers::network_map_handler))
            .route("/consensus", get(handlers::consensus_handler))
            .route(
                "/hub/organizations",
                get(handlers::hub_organizations_handler),
            );
    }

    #[cfg(feature = "headless-agent")]
    {
        info!("🧥 Headless Agent mode enabled - UI disabled");
        app = app.route(
            "/",
            get(|| async { "Wolf Prowler Headless Agent is running." }),
        );
    }

    let hub_api_routes = Router::new()
        .route("/api/v1/agent/login", post(hub_api::hub_agent_login))
        .route("/api/v1/agent/register", post(hub_api::hub_agent_register))
        .route("/api/v1/agent/policy", get(hub_api::hub_agent_policy))
        .route("/api/v1/agent/report", post(hub_api::hub_agent_report))
        .route("/api/v1/agent/alert", post(hub_api::hub_agent_alert))
        .with_state(app_state.clone());

    let hub_admin_routes = Router::new()
        .route(
            "/api/admin/organizations",
            post(hub_admin::admin_create_organization),
        )
        .route(
            "/api/admin/organizations",
            get(hub_admin::admin_list_organizations),
        )
        .route(
            "/api/admin/organizations/:id/stats",
            get(hub_admin::admin_get_organization_stats),
        )
        .with_state(app_state.clone());

    let app = app
        .merge(protected_api_routes)
        .merge(hub_api_routes)
        .merge(hub_admin_routes)
        .with_state(app_state.clone())
        .layer(
            ServiceBuilder::new()
                .layer(DefaultBodyLimit::max(1024 * 1024 * 2))
                .layer(middleware::from_fn(security_headers_layer))
                .layer(tower_http::trace::TraceLayer::new_for_http())
                .layer(
                    tower_http::cors::CorsLayer::new()
                        .allow_origin([
                            "http://localhost:3000"
                                .parse::<axum::http::HeaderValue>()
                                .unwrap(),
                            "https://localhost:3030"
                                .parse::<axum::http::HeaderValue>()
                                .unwrap(),
                        ])
                        .allow_methods([
                            Method::GET,
                            Method::POST,
                            Method::PUT,
                            Method::DELETE,
                            Method::OPTIONS,
                        ])
                        .allow_headers([
                            header::AUTHORIZATION,
                            header::CONTENT_TYPE,
                            header::ACCEPT,
                            "x-api-key".parse::<header::HeaderName>().unwrap(),
                        ])
                        .allow_credentials(true),
                )
                .layer(CookieManagerLayer::new()),
        );

    // Generate Self-Signed Certificates using Wolf Den
    info!("🔐 Generating self-signed certificates for HTTPS...");
    let (cert_pem, key_pem) = wolf_den::certs::generate_self_signed_cert(vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ])
    .expect("Failed to generate self-signed certificates");

    // Configure the server address
    let port = settings.dashboard.port;
    let addr = SocketAddr::from(([127, 0, 0, 1], port));

    info!(
        "🚀 Wolf Prowler server running at https://127.0.0.1:{}",
        port
    );
    info!("📊 Dashboard available at https://localhost:{}", port);
    info!("📡 WebSocket endpoint: wss://localhost:{}/ws", port);
    info!("🔗 P2P Network listening on port {}", settings.network.port);

    // Configure TLS
    let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem(
        cert_pem.as_bytes().to_vec(),
        key_pem.as_bytes().to_vec(),
    )
    .await
    .expect("Failed to create TLS config");

    // Spawn the HTTPS server in the background
    tokio::spawn(async move {
        info!("🔒 Starting HTTPS server...");
        if let Err(e) = axum_server::bind_rustls(addr, tls_config)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await
        {
            error!("Server error: {}", e);
        }
    });

    // Start the server and wait for shutdown signal
    info!("🐺 Wolf Prowler Headless Server Running. Press Ctrl+C to stop.");
    match signal::ctrl_c().await {
        Ok(()) => {
            info!("🛑 Shutdown signal received.");
        }
        Err(err) => {
            error!("Unable to listen for shutdown signal: {}", err);
        }
    }

    // Graceful shutdown
    info!("🛑 Initiating graceful shutdown...");
    if let Err(e) = app_state
        .swarm_manager
        .command_sender()
        .send(SwarmCommand::Shutdown)
        .await
    {
        error!("Failed to send shutdown command to swarm: {}", e);
    }

    Ok(())
}

/// Middleware to rate limit login attempts per IP address.
#[cfg(not(feature = "headless-agent"))]
async fn login_rate_limit_middleware(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: axum::extract::Request,
    next: middleware::Next,
) -> impl IntoResponse {
    let ip = addr.ip();
    let now = std::time::Instant::now();

    // Check limits before processing
    {
        let mut attempts = state.login_attempts.write().await;
        let (count, last_attempt) = attempts.entry(ip).or_insert((0, now));

        // Reset count if last attempt was more than 15 minutes ago
        if now.duration_since(*last_attempt) > std::time::Duration::from_secs(900) {
            *count = 0;
        }

        if *count >= 5 {
            warn!("🚫 Rate limit exceeded for login from IP: {}", ip);
            // Log a high-severity security event for the SIEM dashboard on the initial block
            if *count == 5 {
                let event = SystemEvent {
                    id: Uuid::new_v4(),
                    timestamp: Utc::now(),
                    event_type: "auth_brute_force_blocked".to_string(),
                    message: format!("IP {} blocked after 5 failed login attempts", ip),
                    severity: "high".to_string(),
                    source: "rate_limiter".to_string(),
                    user_id: None,
                    ip_address: Some(ip.to_string()),
                    metadata: HashMap::from([
                        ("attempt_count".to_string(), count.to_string()),
                        ("action".to_string(), "temporary_block".to_string()),
                    ]),
                    correlation_id: None,
                };
                let mut security_events: tokio::sync::RwLockWriteGuard<'_, Vec<SystemEvent>> =
                    state.security_events.write().await;
                security_events.push(event.clone());

                // Broadcast event to SIEM dashboard
                if state.broadcast_tx.receiver_count() > 0 {
                    let _ = state.broadcast_tx.send(
                        serde_json::json!({
                            "type": "security_event",
                            "data": event
                        })
                        .to_string(),
                    );
                }
            }

            let error_msg = "Too many login attempts. Please try again in 15 minutes.";

            if req
                .headers()
                .get(header::ACCEPT)
                .and_then(|h| h.to_str().ok())
                .map_or(false, |s| s.contains("application/json"))
            {
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(serde_json::json!({ "success": false, "error": error_msg })),
                )
                    .into_response();
            }
            return (StatusCode::TOO_MANY_REQUESTS, error_msg).into_response();
        }
    }

    // Process the request
    let response = next.run(req).await;

    // Post-process: Check outcome and update rate limit stats
    {
        let mut attempts = state.login_attempts.write().await;
        let (count, last_attempt) = attempts.entry(ip).or_insert((0, now));

        if response.status().is_success() {
            // Success! Reset attempts.
            *count = 0;
        } else {
            // Failure (Auth error), increment attempts
            *count += 1;
            *last_attempt = std::time::Instant::now(); // Update timestamp of last failed attempt
            warn!("⚠️ Failed login attempt {} from IP: {}", count, ip);
        }
    }

    response.into_response()
}

/// Saves the runtime settings to a JSON file.
#[allow(dead_code)]
async fn save_runtime_settings(settings: &RuntimeSettings) -> Result<()> {
    let data = serde_json::to_string_pretty(settings)?;
    tokio::fs::write("runtime_settings.json", data).await?;
    Ok(())
}

/// Background task to monitor various system components and broadcast updates.
async fn monitor_and_broadcast(state: AppState) {
    let mut metrics_interval = tokio::time::interval(tokio::time::Duration::from_secs(2));
    let mut p2p_interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
    let mut discovery_interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
    let mut security_interval = tokio::time::interval(tokio::time::Duration::from_secs(3));

    let mut last_sec_event_count = state
        .wolf_security
        .read()
        .await
        .monitor
        .get_events()
        .await
        .len();

    loop {
        tokio::select! {
            // Broadcast system metrics
            _ = metrics_interval.tick() => {
                if state.broadcast_tx.receiver_count() > 0 {
                    let metrics_payload = {
                        let metrics: tokio::sync::RwLockReadGuard<'_, SystemMetricsData> = state.system_metrics.read().await;
                        serde_json::json!({
                        "cpu_usage": metrics.current_cpu_usage,
                        "memory_usage": metrics.current_memory_usage,
                        "network_sent_gb": 1.5,
                        "network_recv_gb": 1.1,
                        "process_count": 160
                    });
                    };

                    if let Err(e) = state.broadcast_tx.send(serde_json::json!({
                        "type": "metrics_update",
                        "data": metrics_payload
                    }).to_string()) {
                        warn!("Failed to broadcast metrics update: {}", e);
                    } else {
                        debug!("Broadcasted metrics update to {} receivers", state.broadcast_tx.receiver_count());
                    }
                }
            }

            // Monitor P2P network stats
            _ = p2p_interval.tick() => {
                let (app_peers, peer_count, stats) = {
                    let network: tokio::sync::RwLockReadGuard<'_, P2PNetwork> = state.network.read().await;
                    let peer_list = network.get_connected_peers().iter().map(|p| ApiPeerInfo {
                        id: p.peer_id.clone(),
                        address: p.address.clone(),
                        connected_since: Utc::now().to_rfc3339(),
                        trust_level: p.trust_level,
                        status: "connected".to_string(),
                    }).collect::<Vec<_>>();
                    (peer_list, network.peer_count(), network.get_stats())
                };

                // Update peer list
                for app_peer in app_peers {
                    state.add_peer(app_peer).await;
                }

                // Broadcast peer update
                let peer_msg = serde_json::json!({ "peer_count": peer_count });
                if state.broadcast_tx.receiver_count() > 0 {
                    if let Err(e) = state.broadcast_tx.send(serde_json::json!({
                        "type": "peer_update",
                        "data": peer_msg
                    }).to_string()) {
                        warn!("Failed to broadcast peer update: {}", e);
                    }

                    // New: Broadcast detailed wolf_net swarm status
                    if let Ok(stats) = state.swarm_manager.get_stats().await {
                        let _ = state.broadcast_tx.send(serde_json::json!({
                            "type": "network_status_update",
                            "data": {
                                "connected_peers": stats.connected_peers,
                                "total_bytes_sent": stats.metrics.total_bytes_sent,
                                "total_bytes_received": stats.metrics.total_bytes_received,
                                "active_connections": stats.metrics.active_connections,
                            }
                        }).to_string());
                    }
                }

                // Add network statistics event to the internal log
                let event = SystemEvent {
                    id: Uuid::new_v4(),
                    timestamp: Utc::now(),
                    event_type: "network_stats".to_string(),
                    message: format!(
                        "Network: {} peers, {} msgs sent, {} msgs received",
                        peer_count, stats.messages_sent, stats.messages_received
                    ),
                    severity: "info".to_string(),
                    source: "wolf_prowler".to_string(),
                    user_id: None,
                    ip_address: None,
                    metadata: HashMap::new(),
                    correlation_id: None,
                };
                let mut security_events: tokio::sync::RwLockWriteGuard<'_, Vec<SystemEvent>> = state.security_events.write().await;
                security_events.push(event);
            }

            // Poll for new security events and broadcast them
            _ = security_interval.tick() => {
                let sec_events = state.wolf_security.read().await.monitor.get_events().await;
                if sec_events.len() > last_sec_event_count {
                    for event in sec_events.iter().skip(last_sec_event_count) {
                        if state.broadcast_tx.receiver_count() > 0 {
                            if let Err(e) = state.broadcast_tx.send(serde_json::json!({
                                "type": "security_event",
                                "data": event
                            }).to_string()) {
                                warn!("Failed to broadcast security event: {}", e);
                            } else {
                                debug!("Broadcasted security event to {} receivers", state.broadcast_tx.receiver_count());
                            }
                        }
                    }
                    last_sec_event_count = sec_events.len();
                }
            }

            // Simulate peer discovery
            _ = discovery_interval.tick() => {
                if let Err(e) = discover_and_connect_peers(&state).await {
                    tracing::error!("Peer discovery failed: {}", e);
                }
            }
        }
    }
}

/// Pack member discovery using SwarmManager
async fn discover_and_connect_peers(state: &AppState) -> Result<()> {
    // Use SwarmManager for pack member discovery
    let discovered_peers = state.swarm_manager.discover_peers().await?;

    let current_peers: Vec<String> = {
        let network: tokio::sync::RwLockReadGuard<'_, P2PNetwork> = state.network.read().await;
        network
            .get_connected_peers()
            .iter()
            .map(|p| p.peer_id.clone())
            .collect()
    };

    for discovered_peer in discovered_peers {
        let peer_id = discovered_peer.id.to_string();
        let address = discovered_peer.address;

        if !current_peers.contains(&peer_id) {
            // Connect to discovered pack member
            if let Ok(()) = {
                let mut network: tokio::sync::RwLockWriteGuard<'_, P2PNetwork> =
                    state.network.write().await;
                network.connect_to_peer(peer_id.clone(), address.clone())
            } {
                tracing::info!(
                    "🔗 Discovered and connected to peer: {} at {}",
                    peer_id,
                    address
                );

                // Add discovery event
                let event = SystemEvent {
                    id: Uuid::new_v4(),
                    timestamp: Utc::now(),
                    event_type: "peer_discovered".to_string(),
                    message: format!("Discovered new peer: {} at {}", peer_id, address),
                    severity: "info".to_string(),
                    source: "wolf_prowler".to_string(),
                    user_id: None,
                    ip_address: None,
                    metadata: HashMap::new(),
                    correlation_id: None,
                };

                let mut security_events: tokio::sync::RwLockWriteGuard<'_, Vec<SystemEvent>> =
                    state.security_events.write().await;
                security_events.push(event.clone());

                // Broadcast discovery to SIEM dashboard
                if state.broadcast_tx.receiver_count() > 0 {
                    let _ = state.broadcast_tx.send(
                        serde_json::json!({
                            "type": "security_event",
                            "data": event
                        })
                        .to_string(),
                    );
                }
            }
        }
    }

    Ok(())
}

/// Background task to handle incoming network messages and real-time delivery
async fn handle_network_messages(state: AppState) {
    // Subscribe to network security events
    let mut network_events: broadcast::Receiver<NetworkSecurityEvent> =
        state.howl_service.network_security.subscribe_events().await;

    loop {
        match network_events.recv().await {
            Ok(event) => {
                match event.event_type.as_str() {
                    "message_received" => {
                        if let Some(peer_id) = &event.peer_id {
                            if let Some(message_data) = &event.data {
                                // Decrypt the received message
                                let session_id = format!("session_{}", peer_id);
                                if let Ok(decrypted_message) = state
                                    .howl_service
                                    .network_security
                                    .decrypt_message(&session_id, message_data)
                                    .await
                                {
                                    // Parse the howl message
                                    if let Ok(howl_msg) =
                                        serde_json::from_slice::<HowlMessage>(&decrypted_message)
                                    {
                                        // Store the message
                                        let stored_msg = StoredHowlMessage {
                                            id: howl_msg.id.clone(),
                                            encrypted_content: hex::encode(&decrypted_message),
                                            channel: howl_msg.channel.clone(),
                                            recipient: howl_msg.recipient.clone(),
                                            sender: howl_msg.sender.clone(),
                                            priority: howl_msg.priority.clone(),
                                            timestamp: howl_msg.timestamp.clone(),
                                            message_id: howl_msg.id.clone(),
                                        };

                                        if let Ok(()) =
                                            state.howl_service.store_message(stored_msg).await
                                        {
                                            // Broadcast to WebSocket clients
                                            if let Ok(broadcast_msg) = serde_json::to_string(
                                                &serde_json::json!({
                                                    "type": "howl_received",
                                                    "channel": howl_msg.channel,
                                                    "message": howl_msg.message.chars().take(50).collect::<String>() + "...",
                                                    "sender": howl_msg.sender,
                                                    "priority": howl_msg.priority
                                                }),
                                            ) {
                                                let _ = state.broadcast_tx.send(broadcast_msg);
                                            }

                                            // Update message metadata
                                            let metadata = MessageMetadata {
                                                delivery_status: "delivered".to_string(),
                                                delivery_attempts: 1,
                                                last_attempt: Utc::now().to_rfc3339(),
                                                target_peers: vec![peer_id.clone()],
                                            };
                                            state
                                                .howl_service
                                                .update_message_metadata(&howl_msg.id, metadata)
                                                .await;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    "peer_connected" => {
                        // Update routing table for new pack member
                        if let Some(peer_id) = &event.peer_id {
                            // Check for malicious IP
                            let pid = PeerId::from_string(peer_id.clone());
                            let mut blocked = false;

                            if let Ok(Some(info)) =
                                state.swarm_manager.get_peer_info(pid.clone()).await
                            {
                                let db: tokio::sync::RwLockReadGuard<'_, ThreatDatabase> =
                                    state.threat_service.threat_db.read().await;
                                for addr in &info.addresses {
                                    let addr_str = addr.to_string();
                                    if let Some(bad_ip) =
                                        db.malicious_ips.iter().find(|ip| addr_str.contains(*ip))
                                    {
                                        warn!(
                                            "🚫 Blocking malicious peer {} connecting from {}",
                                            peer_id, bad_ip
                                        );

                                        let _ = state
                                            .swarm_manager
                                            .command_sender()
                                            .send(SwarmCommand::BlockPeer {
                                                peer_id: pid.clone(),
                                            })
                                            .await;

                                        let event = SystemEvent {
                                            id: Uuid::new_v4(),
                                            timestamp: Utc::now(),
                                            event_type: "threat_blocked".to_string(),
                                            message: format!(
                                                "Blocked connection from malicious IP: {}",
                                                bad_ip
                                            ),
                                            severity: "critical".to_string(),
                                            source: "threat_defense".to_string(),
                                            user_id: None,
                                            ip_address: Some(bad_ip.clone()),
                                            metadata: HashMap::from([
                                                ("peer_id".to_string(), peer_id.clone()),
                                                ("address".to_string(), addr_str.clone()),
                                            ]),
                                            correlation_id: None,
                                        };
                                        {
                                            let mut events: tokio::sync::RwLockWriteGuard<
                                                '_,
                                                Vec<SystemEvent>,
                                            > = state.security_events.write().await;
                                            events.push(event.clone());
                                        }

                                        // Broadcast threat block to SIEM dashboard
                                        if state.broadcast_tx.receiver_count() > 0 {
                                            let _ = state.broadcast_tx.send(
                                                serde_json::json!({
                                                    "type": "security_event",
                                                    "data": event
                                                })
                                                .to_string(),
                                            );
                                        }

                                        // Feed into Wolf Security Core Engine
                                        let security_event = wolfsec::SecurityEvent::new(
                                            wolfsec::SecurityEventType::NetworkIntrusion,
                                            wolfsec::SecuritySeverity::Critical,
                                            format!(
                                                "Blocked connection from malicious IP: {}",
                                                bad_ip
                                            ),
                                        )
                                        .with_peer(peer_id.clone())
                                        .with_metadata("ip".to_string(), bad_ip.clone());

                                        let mut wolf_sec = state.wolf_security.write().await;
                                        if let Err(e) =
                                            wolf_sec.process_security_event(security_event).await
                                        {
                                            tracing::warn!("Failed to process security event in core engine: {}", e);
                                        }
                                        blocked = true;
                                        break;
                                    }
                                }
                            }

                            if blocked {
                                continue;
                            }

                            let mut routes: tokio::sync::RwLockWriteGuard<
                                '_,
                                HashMap<String, Vec<String>>,
                            > = state.howl_service.message_routes.write().await;
                            // Add peer to all channels they should receive
                            for channel in ["alpha", "beta", "gamma", "delta"] {
                                routes
                                    .entry(channel.to_string())
                                    .or_insert_with(Vec::new)
                                    .push(peer_id.clone());
                            }

                            // Notify container security of new peer connection
                            let mut container_sec: tokio::sync::RwLockWriteGuard<
                                ContainerSecurityManager,
                            > = state.container_security.write().await;
                            container_sec
                                .process_network_event("peer_connected", peer_id, "")
                                .await;
                        }
                    }
                    "peer_disconnected" => {
                        // Remove peer from routing table
                        if let Some(peer_id) = &event.peer_id {
                            let mut routes: tokio::sync::RwLockWriteGuard<
                                '_,
                                HashMap<String, Vec<String>>,
                            > = state.howl_service.message_routes.write().await;
                            for (_, peers) in routes.iter_mut() {
                                peers.retain(|p| p != peer_id);
                            }
                        }
                    }
                    _ => {}
                }
            }
            Err(_) => {
                // Handle channel closed error
                tracing::warn!("Network events channel closed, restarting subscription...");
                // Re-subscribe to events
                network_events = state.howl_service.network_security.subscribe_events().await;
            }
        }
    }
}

/// Handles logout by removing the authentication cookie.
#[cfg(not(feature = "headless-agent"))]
async fn logout_handler(jar: CookieJar) -> (CookieJar, Redirect) {
    info!("User logged out");
    let jar = jar.remove(Cookie::from(AUTH_COOKIE_NAME));
    (jar, Redirect::to("/"))
}

/// Middleware to add security headers to all responses
async fn security_headers_layer(
    req: axum::extract::Request,
    next: middleware::Next,
) -> impl IntoResponse {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();

    // Security Headers
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    headers.insert(header::X_FRAME_OPTIONS, "SAMEORIGIN".parse().unwrap());
    headers.insert(header::X_XSS_PROTECTION, "1; mode=block".parse().unwrap());
    headers.insert(
        header::STRICT_TRANSPORT_SECURITY,
        "max-age=31536000; includeSubDomains".parse().unwrap(),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://unpkg.com https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data:; connect-src 'self' wss: ws:; font-src 'self' https://fonts.gstatic.com; object-src 'none'; frame-ancestors 'self';".parse().unwrap(),
    );

    response
}

// --- Auth Middleware ---

/// Authentication middleware to protect routes with role-based access control.
/// Authentication middleware to protect routes with role-based access control.
async fn auth_middleware(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: axum::http::HeaderMap,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> impl IntoResponse {
    // 1. Check for API Key first (for authenticated API calls)
    if let Some(api_key) = headers.get("X-API-Key") {
        if let Ok(key_str) = api_key.to_str() {
            // Check against environment variable
            let valid_key = std::env::var("WOLF_PROWLER_API_KEY").unwrap_or_default();
            if !valid_key.is_empty() && key_str == valid_key {
                // API Key valid, assume full access or specific role (e.g. Alpha)
                // For simplicity, we grant access. In a real system, map key to role.
                return next.run(req).await;
            }
        }
    }

    // 2. Fallback to Session Cookie
    if let Some(cookie) = jar.get(AUTH_COOKIE_NAME) {
        if let Some((value, mac)) = cookie.value().split_once('.') {
            if let Ok(mac_bytes) = hex::decode(mac) {
                if let Ok(valid) = state.crypto.verify_mac(value.as_bytes(), &mac_bytes).await {
                    if valid {
                        // Parse session data to extract role
                        if let Some((_session_token, role_str)) = value.split_once(':') {
                            let user_role = match role_str {
                                "omega" => WolfRole::Omega,
                                "alpha" => WolfRole::Alpha,
                                "gamma" => WolfRole::Gamma,
                                "beta" => WolfRole::Beta,
                                _ => WolfRole::Beta,
                            };

                            let path = req.uri().path();

                            // Omega and Alpha have full access.
                            // Beta and Gamma have limited access to admin endpoints.
                            if (user_role == WolfRole::Beta || user_role == WolfRole::Gamma)
                                && (path.starts_with("/api/admin/") || path.starts_with("/admin/"))
                            {
                                return StatusCode::FORBIDDEN.into_response();
                            }

                            return next.run(req).await;
                        }
                    }
                }
            }
        }
    }

    // If we get here, authentication failed
    if req.uri().path().starts_with("/api/") {
        // Return 401 for API requests
        StatusCode::UNAUTHORIZED.into_response()
    } else {
        // Redirect to login for web requests
        Redirect::to("/").into_response()
    }
}

// --- WebSocket Handlers ---

/// Commands sent from WebSocket clients
#[derive(Deserialize, Debug)]
#[serde(tag = "command", content = "params")]
enum ClientCommand {
    /// Request immediate system status update
    GetStatus,
    /// Request recent security events
    GetRecentEvents { limit: usize },
    /// Trigger behavioral analysis on a peer
    TriggerBehavioralAnalysis { peer_id: String },
    /// Ping for keepalive
    Ping,
}

/// Handles WebSocket upgrade requests.
async fn websocket_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> axum::response::Response {
    ws.on_upgrade(move |socket| handle_websocket_connection(socket, state))
}

/// Manages a single WebSocket connection, sending event-driven updates.
async fn handle_websocket_connection(mut socket: WebSocket, state: AppState) {
    info!("📡 WebSocket client connected");

    // Subscribe to the broadcast channel.
    let mut rx = state.broadcast_tx.subscribe();

    // This loop will now react to broadcast events and client messages.
    loop {
        tokio::select! {
            // Forward broadcast messages to the client
            result = rx.recv() => {
                if let Ok(msg_text) = result {
                    // Parse the JSON string to determine the message type
                    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&msg_text) {
                        if let Some(msg_type) = parsed.get("type").and_then(|v| v.as_str()) {
                            match msg_type {
                                "metrics_update" => {
                                    // Already formatted as JSON
                                },
                                "peer_update" => {
                                    // Already formatted as JSON
                                },
                                "security_event" => {
                                    // Already formatted as JSON
                                },
                                _ => {
                                    // Unknown message type
                                }
                            }
                        }
                    }

                    if socket.send(Message::Text(msg_text.to_string())).await.is_err() {
                        // Client disconnected.
                        break;
                    }
                }
            }

            // Handle incoming messages from the client
            Some(Ok(msg)) = socket.recv() => {
                if let Message::Text(text) = msg {
                    // Try to parse as ClientCommand
                    if let Ok(cmd) = serde_json::from_str::<ClientCommand>(&text) {
                        debug!("Processing client command: {:?}", cmd);
                        match cmd {
                            ClientCommand::Ping => {
                                let _ = socket.send(Message::Text(serde_json::json!({
                                    "type": "pong",
                                    "timestamp": Utc::now().to_rfc3339()
                                }).to_string())).await;
                            }
                            ClientCommand::GetStatus => {
                                let peers_count = state.peers.read().await.len();
                                let events_count = {
                            let events: tokio::sync::RwLockReadGuard<'_, Vec<SystemEvent>> = state.security_events.read().await;
                            events.len()
                        };
                                let uptime = Utc::now().signed_duration_since(state.metrics.start_time).num_seconds();

                                let response = serde_json::json!({
                                    "type": "status_response",
                                    "data": {
                                        "peers": peers_count,
                                        "events": events_count,
                                        "uptime_seconds": uptime,
                                        "status": "operational"
                                    }
                                });
                                let _ = socket.send(Message::Text(response.to_string())).await;
                            }
                            ClientCommand::GetRecentEvents { limit } => {
                                let recent: Vec<_> = {
                            let events: tokio::sync::RwLockReadGuard<'_, Vec<SystemEvent>> = state.security_events.read().await;
                            events.iter().rev().take(limit.min(100)).cloned().collect()
                        };
                                let response = serde_json::json!({
                                    "type": "recent_events_response",
                                    "data": recent
                                });
                                let _ = socket.send(Message::Text(response.to_string())).await;
                            }
                            ClientCommand::TriggerBehavioralAnalysis { peer_id } => {
                                let analysis_result = state
                                    .wolf_security
                                    .read()
                                    .await
                                    .threat_detector
                                    .analyze_peer_behavior(&peer_id)
                                    .await;

                                let response = match analysis_result {
                                    Some((score, findings)) => serde_json::json!({
                                        "type": "behavioral_analysis_response",
                                        "data": {
                                            "risk_score": score,
                                            "anomalies": findings
                                        }
                                    }),
                                    None => serde_json::json!({
                                        "type": "error",
                                        "message": "Analysis failed"
                                    }),
                                };
                                let _ = socket.send(Message::Text(response.to_string())).await;
                            }
                        }
                    } else {
                        info!("Received WebSocket message from client: {}", text);
                    }
                } else if matches!(msg, Message::Close(_)) {
                    break;
                }
            }

            // Stop the loop if the client disconnects or the broadcast channel lags.
            _ = tokio::time::sleep(tokio::time::Duration::from_millis(100)) => {
                // Check if the receiver is closed
                if rx.is_closed() {
                    break;
                }
            }
        }
    }
    info!("📡 WebSocket client disconnected.");
}
