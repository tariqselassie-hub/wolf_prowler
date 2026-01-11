//! Dashboard State Management
//!
//! This module provides state management for the dashboard, including
//! shared state for API endpoints and real-time monitoring.

use std::sync::Arc;
use tokio::sync::Mutex;

use crate::dashboard::websocket::WebSocketState;
use tokio::sync::RwLock;
use wolf_net::SwarmManager;
use wolfsec::security::advanced::iam::AuthenticationManager;
use wolfsec::threat_detection::{BehavioralAnalyzer, ThreatDetector};
use wolfsec::WolfSecurity;

/// Dashboard application state
#[derive(Clone)]
pub struct AppState {
    /// Threat detection engine
    pub threat_engine: Arc<Mutex<ThreatDetector>>,
    /// Behavioral analysis engine
    pub behavioral_engine: Arc<Mutex<BehavioralAnalyzer>>,
    // Anomaly detection is inside ThreatDetector
    // pub anomaly_engine: Arc<Mutex<AnomalyDetector>>,
    /// Request counter
    pub request_count: Arc<Mutex<u64>>,
    /// WebSocket state for real-time updates
    pub websocket_state: Arc<WebSocketState>,
    /// Authentication manager
    pub auth_manager: Arc<Mutex<AuthenticationManager>>,
    /// Wolf Security instance (real system data)
    pub wolf_security: Option<Arc<RwLock<WolfSecurity>>>,
    /// Swarm Manager (real network data)
    pub swarm_manager: Option<Arc<SwarmManager>>,
}

impl AppState {
    /// Create new application state
    pub fn new(
        threat_engine: ThreatDetector,
        behavioral_engine: BehavioralAnalyzer,
        // anomaly_engine: AnomalyDetector,
        auth_manager: AuthenticationManager,
    ) -> Self {
        Self {
            threat_engine: Arc::new(Mutex::new(threat_engine)),
            behavioral_engine: Arc::new(Mutex::new(behavioral_engine)),
            // anomaly_engine: Arc::new(Mutex::new(anomaly_engine)),
            request_count: Arc::new(Mutex::new(0)),
            websocket_state: Arc::new(WebSocketState::new()),
            auth_manager: Arc::new(Mutex::new(auth_manager)),
            wolf_security: None,
            swarm_manager: None,
        }
    }

    /// Create new application state with real system components
    pub fn with_system_components(
        threat_engine: ThreatDetector,
        behavioral_engine: BehavioralAnalyzer,
        // anomaly_engine: AnomalyDetector,
        auth_manager: AuthenticationManager,
        wolf_security: Arc<RwLock<WolfSecurity>>,
        swarm_manager: Arc<SwarmManager>,
    ) -> Self {
        Self {
            threat_engine: Arc::new(Mutex::new(threat_engine)),
            behavioral_engine: Arc::new(Mutex::new(behavioral_engine)),
            // anomaly_engine: Arc::new(Mutex::new(anomaly_engine)),
            request_count: Arc::new(Mutex::new(0)),
            websocket_state: Arc::new(WebSocketState::new()),
            auth_manager: Arc::new(Mutex::new(auth_manager)),
            wolf_security: Some(wolf_security),
            swarm_manager: Some(swarm_manager),
        }
    }

    /// Increment request counter
    pub async fn increment_request_count(&self) {
        let mut count = self.request_count.lock().await;
        *count += 1;
    }

    /// Get current request count
    pub async fn get_request_count(&self) -> u64 {
        *self.request_count.lock().await
    }
}
