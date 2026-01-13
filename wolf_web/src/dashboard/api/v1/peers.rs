//! Peer Network Analysis API Endpoints
//!
//! This module provides API endpoints for analyzing peer network data
//! and monitoring peer activities.

use axum::extract::State;
use axum::{routing::get, Json, Router};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::dashboard::state::AppState;

/// Peer network response
#[derive(Debug, Serialize, Deserialize)]
pub struct PeersResponse {
    /// Total peer count
    pub total_peers: usize,
    /// Active peer count
    pub active_peers: usize,
    /// Trusted peer count
    pub trusted_peers: usize,
    /// Suspicious peer count
    pub suspicious_peers: usize,
    /// Average reputation score
    pub average_reputation: f64,
    /// Network health score
    pub network_health: f64,
}

/// Peer detail response
#[derive(Debug, Serialize, Deserialize)]
pub struct PeerDetailResponse {
    /// Peer ID
    pub peer_id: String,
    /// Peer reputation
    pub reputation: f64,
    /// Connection status
    pub connected: bool,
    /// Whether the peer is blocked
    pub blocked: bool,
    /// Last seen timestamp
    pub last_seen: String,
    /// Message count
    pub message_count: u64,
    /// Threat count
    pub threat_count: usize,
    /// Last reputation update
    pub last_updated: String,
}

/// Create peer network router
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(get_peer_network_stats))
        .route("/:peer_id", get(get_peer_details))
        .route("/reputation", get(get_peer_reputation))
        .with_state(state)
}

/// Get overall peer network statistics
async fn get_peer_network_stats(State(state): State<Arc<AppState>>) -> Json<PeersResponse> {
    state.increment_request_count().await;

    let threat_engine = state.threat_engine.lock().await;
    let reputation_system = threat_engine.reputation_system();
    let peer_count = reputation_system.peer_count().await;
    let avg_reputation = reputation_system.average_reputation().await;

    // Get real peer counts from reputation system
    let trusted_peers = reputation_system.trusted_peer_count().await;
    let suspicious_peers = reputation_system.suspicious_peer_count().await;
    let active_peers = reputation_system.active_peer_count().await;

    Json(PeersResponse {
        total_peers: peer_count,
        active_peers,
        trusted_peers,
        suspicious_peers,
        average_reputation: avg_reputation,
        network_health: calculate_network_health(avg_reputation),
    })
}

/// Calculate network health based on average reputation
fn calculate_network_health(avg_reputation: f64) -> f64 {
    // Simple calculation: higher reputation = better health
    (avg_reputation * 0.8 + 0.2).min(1.0)
}

/// Get details for specific peer
async fn get_peer_details(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(peer_id): axum::extract::Path<String>,
) -> Result<Json<PeerDetailResponse>, crate::dashboard::api::ApiError> {
    state.increment_request_count().await;

    let mut blocked = false;
    if let Some(wolf_security_arc) = state.get_wolf_security() {
        let security = wolf_security_arc.read().await;
        if let Some(peer) = security.threat_detector.get_peer_info(&peer_id).await {
            blocked = peer.flags.blocked;
        }
    }

    let threat_engine = state.threat_engine.lock().await;
    let reputation_system = threat_engine.reputation_system();

    // Get real peer data from reputation system
    let reputation = reputation_system.get_peer_reputation(&peer_id).await;
    let message_count = reputation_system.get_peer_message_count(&peer_id).await;
    let threat_count = reputation_system.get_peer_threat_count(&peer_id).await;
    let last_seen = reputation_system.get_peer_last_seen(&peer_id).await;
    let last_updated = reputation_system.get_peer_last_updated(&peer_id).await;

    Ok(Json(PeerDetailResponse {
        peer_id: peer_id.clone(),
        reputation,
        connected: reputation_system.is_peer_connected(&peer_id).await,
        blocked,
        last_seen: last_seen
            .map(|d| d.to_rfc3339())
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339()),
        message_count: message_count as u64,
        threat_count,
        last_updated: last_updated
            .map(|d| d.to_rfc3339())
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339()),
    }))
}

/// Get peer reputation data
async fn get_peer_reputation(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    state.increment_request_count().await;

    let threat_engine = state.threat_engine.lock().await;
    let reputation_system = threat_engine.reputation_system();

    // Get real reputation data from the system
    let trends = reputation_system.get_trends().await;
    let average_reputation = reputation_system.average_reputation().await;
    let peer_count = reputation_system.peer_count().await;
    let trusted_count = reputation_system.trusted_peer_count().await;
    let suspicious_count = reputation_system.suspicious_peer_count().await;

    Json(serde_json::json!({
        "reputation_trends": trends,
        "average_reputation": average_reputation,
        "peer_count": peer_count,
        "trusted_peers": trusted_count,
        "suspicious_peers": suspicious_count,
        "health_status": if average_reputation > 0.7 {
            "healthy"
        } else if average_reputation > 0.5 {
            "moderate"
        } else {
            "unhealthy"
        }
    }))
}
