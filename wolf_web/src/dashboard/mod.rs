//! Dashboard Module for Wolf Prowler
//!
//! This module provides a comprehensive dashboard system for monitoring and managing
//! the Wolf Prowler security network. It includes:
//! - API endpoints for accessing security data
//! - Real-time monitoring of threats and anomalies
//! - Behavioral analysis visualization
//! - Cryptographic operations monitoring
//! - Peer network analysis
//! - Security metrics and analytics

use crate::dashboard::state::AppState;
use axum::Router;
use std::sync::Arc;

pub mod api;
pub mod middleware;
pub mod state;
pub mod websocket;

// use crate::dashboard::websocket::start_system_monitoring_task;
use async_trait::async_trait;
use uuid::Uuid;
use wolfsec::domain::entities::Threat;
use wolfsec::domain::error::DomainError;
use wolfsec::domain::repositories::ThreatRepository;
use wolfsec::security::advanced::iam::{AuthenticationManager, IAMConfig};
use wolfsec::threat_detection::{BehavioralAnalyzer, ThreatDetectionConfig, ThreatDetector};

/// Mock Threat Repository for dashboard initialization
pub struct MockThreatRepository;

#[async_trait]
impl ThreatRepository for MockThreatRepository {
    async fn save(&self, _threat: &Threat) -> Result<(), DomainError> {
        Ok(())
    }

    async fn find_by_id(&self, _id: &Uuid) -> Result<Option<Threat>, DomainError> {
        Ok(None)
    }
}

/// Dashboard configuration
#[derive(Debug, Clone)]
pub struct DashboardConfig {
    /// Enable API endpoints
    pub enable_api: bool,
    /// API base path
    pub api_base_path: String,
    /// Enable real-time monitoring
    pub enable_realtime: bool,
    /// Maximum history retention
    pub max_history: usize,
}

impl Default for DashboardConfig {
    fn default() -> Self {
        Self {
            enable_api: true,
            api_base_path: "/api/v1".to_string(),
            enable_realtime: true,
            max_history: 1000,
        }
    }
}

/// Main dashboard state
#[derive(Clone)]
pub struct DashboardState {
    /// Threat detection engine
    pub threat_engine: Arc<ThreatDetector>,
    /// Behavioral analysis engine
    pub behavioral_engine: Arc<BehavioralAnalyzer>,
    /// Dashboard configuration
    pub config: DashboardConfig,
}

impl DashboardState {
    /// Create new dashboard state
    pub fn new(threat_engine: ThreatDetector, behavioral_engine: BehavioralAnalyzer) -> Self {
        Self {
            threat_engine: Arc::new(threat_engine),
            behavioral_engine: Arc::new(behavioral_engine),
            config: DashboardConfig::default(),
        }
    }

    /// Initialize dashboard with default engines
    pub fn init_default() -> Self {
        let threat_repo = Arc::new(MockThreatRepository);
        let threat_engine = ThreatDetector::new(ThreatDetectionConfig::default(), threat_repo);
        let behavioral_engine = BehavioralAnalyzer {
            baseline_window: 100,
            deviation_threshold: 2.0,
            patterns_detected: 0,
        };
        Self::new(threat_engine, behavioral_engine)
    }
}

/// Initialize the dashboard module
pub async fn init() -> DashboardState {
    tracing::info!("Initializing dashboard module...");

    let dashboard_state = DashboardState::init_default();

    tracing::info!("Dashboard module initialized successfully");
    tracing::info!("Available endpoints:");
    tracing::info!("- Behavioral analysis: /api/v1/behavioral");
    tracing::info!("- Cryptographic operations: /api/v1/crypto");
    tracing::info!("- Peer network analysis: /api/v1/peers");
    tracing::info!("- Threat detection: /api/v1/threats");
    tracing::info!("- Security metrics: /api/v1/security");
    tracing::info!("- System metrics: /api/v1/metrics");
    tracing::info!("- WebSocket: /ws/dashboard");

    // Initialize dashboard state with WebSocket support
    let auth_manager: AuthenticationManager = AuthenticationManager::new(IAMConfig::default())
        .await
        .unwrap();

    let app_state = crate::dashboard::state::AppState::new(
        dashboard_state.threat_engine.as_ref().clone(),
        dashboard_state.behavioral_engine.as_ref().clone(),
        auth_manager,
    );

    // Start WebSocket system monitoring task with real system components
    crate::dashboard::websocket::start_system_monitoring_task(
        app_state.websocket_state.tx.clone(),
        app_state.wolf_security.clone(),
        app_state.swarm_manager.clone(),
    );

    dashboard_state
}

/// Create dashboard API router
pub async fn create_router(state: DashboardState) -> Router {
    let app_state = crate::dashboard::state::AppState::new(
        state.threat_engine.as_ref().clone(),
        state.behavioral_engine.as_ref().clone(),
        AuthenticationManager::new(IAMConfig::default())
            .await
            .unwrap(),
    );

    // Combine API and WebSocket routers
    let api_router = crate::dashboard::api::create_api_router(Arc::new(app_state.clone()));
    let ws_router = crate::dashboard::websocket::create_websocket_router(Arc::new(app_state));

    Router::new().nest("/v1", api_router).nest("/ws", ws_router)
}

/// Create dashboard API router with provided app state
pub async fn create_router_with_state(app_state: AppState) -> Router {
    // Combine API and WebSocket routers
    let api_router =
        crate::dashboard::api::create_api_router_with_state(Arc::new(app_state.clone()));
    let ws_router = crate::dashboard::websocket::create_websocket_router(Arc::new(app_state));

    Router::new().nest("/v1", api_router).nest("/ws", ws_router)
}
