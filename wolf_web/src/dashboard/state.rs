//! Dashboard State Management
//!
//! This module provides state management for the dashboard, including
//! shared state for API endpoints and real-time monitoring.

use std::sync::Arc;
use tokio::sync::Mutex;

use crate::dashboard::websocket::WebSocketState;
use tokio::sync::RwLock;
use wolf_net::SwarmManager;
use wolfsec::identity::iam::AuthenticationManager;
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

    /// Get the real `WolfSecurity` instance if available
    pub fn get_wolf_security(&self) -> Option<Arc<RwLock<WolfSecurity>>> {
        self.wolf_security.clone()
    }

    /// Get the swarm manager instance if available
    pub fn get_swarm_manager(&self) -> Option<Arc<SwarmManager>> {
        self.swarm_manager.clone()
    }

    /// Get a unified security status from the real engine if available,
    /// otherwise fall back to the standalone threat engine.
    pub async fn get_unified_status(&self) -> wolfsec::WolfSecurityStatus {
        if let Some(wolf_sec) = &self.wolf_security {
            let security = wolf_sec.read().await;
            security.get_status().await
        } else {
            // Fallback status constructed from available engines
            let threat_lock = self.threat_engine.lock().await;
            let threat_status = threat_lock.get_status().await;

            // Construct a partial status
            wolfsec::WolfSecurityStatus {
                network_security: wolfsec::protection::network_security::SecurityStats::default(),
                crypto: wolfsec::identity::crypto::CryptoStatus::default(),
                threat_detection: threat_status,
                authentication: wolfsec::auth::AuthStatus {
                    active_sessions: 0,
                    total_users: 0,
                    auth_failures: 0,
                },
                key_management: wolfsec::identity::key_management::KeyManagementStatus::default(),
                monitoring: wolfsec::observability::monitoring::MonitoringStatus::default(),
            }
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
