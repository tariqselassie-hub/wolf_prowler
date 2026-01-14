//! Network Operations API Endpoints
//!
//! This module provides API endpoints for accessing network operations data
//! including P2P networking, peer management, and `HyperPulse` transport metrics.

use axum::extract::State;
use axum::{routing::get, Json, Router};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::dashboard::state::AppState;

/// Network status response
#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkStatusResponse {
    /// Connected peers count
    pub connected_peers: usize,
    /// Total known peers
    pub total_peers: usize,
    /// Network latency (ms)
    pub network_latency: f64,
    /// Average latency (ms)
    pub average_latency: f64,
    /// Data transfer (MB)
    pub data_transfer: f64,
    /// Active sessions (encrypted)
    pub active_sessions: usize,
    /// Total security rules/keys
    pub security_key_count: usize,
    /// `HyperPulse` status
    pub hyperpulse_status: String,
    /// Active streams
    pub active_streams: usize,
    /// Network health percentage
    pub network_health: f64,
}

/// Peer information
#[derive(Debug, Serialize, Deserialize)]
pub struct PeerInfo {
    /// Peer ID
    pub peer_id: String,
    /// Connection status
    pub status: String,
    /// Latency (ms)
    pub latency: f64,
    /// Last seen
    pub last_seen: String,
    /// Data transferred (MB)
    pub data_transferred: f64,
}

/// Connection metrics
#[derive(Debug, Serialize, Deserialize)]
pub struct ConnectionMetrics {
    /// Total connections
    pub total_connections: usize,
    /// Active connections
    pub active_connections: usize,
    /// Failed connections
    pub failed_connections: usize,
    /// Connection success rate
    pub success_rate: f64,
}

/// Create network router
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/status", get(get_network_status))
        .route("/peers", get(get_peers))
        .route("/connections", get(get_connection_metrics))
        .route("/topology", get(get_topology))
        .with_state(state)
}

/// Get network status
async fn get_network_status(State(state): State<Arc<AppState>>) -> Json<NetworkStatusResponse> {
    state.increment_request_count().await;

    let mut response = NetworkStatusResponse {
        connected_peers: 0,
        total_peers: 0,
        network_latency: 0.0,
        average_latency: 0.0,
        data_transfer: 0.0,
        active_sessions: 0,
        security_key_count: 0,
        hyperpulse_status: "Initializing".to_string(),
        active_streams: 0,
        network_health: 50.0,
    };

    // Try to get real security data from WolfSecurity
    if let Some(wolf_security_arc) = state.get_wolf_security() {
        let security = wolf_security_arc.read().await;
        let stats = security.network_security.get_stats().await;
        response.active_sessions = stats.active_sessions;
        response.security_key_count = stats.total_keypairs;
    }

    // Try to get real data from SwarmManager
    if let Some(swarm_manager) = &state.swarm_manager {
        // Get real network metrics from SwarmManager
        let metrics = swarm_manager.get_metrics().await;
        response.connected_peers = metrics.connected_peers;
        response.total_peers = metrics.known_peers;
        response.network_latency = metrics.average_latency;
        response.average_latency = metrics.average_latency;
        response.data_transfer = metrics.total_data_transferred as f64;
        response.hyperpulse_status = "Active".to_string();
        response.active_streams = metrics.active_streams;
        response.network_health = metrics.network_health;
    }

    Json(response)
}

/// Get peer list
async fn get_peers(State(state): State<Arc<AppState>>) -> Json<Vec<PeerInfo>> {
    state.increment_request_count().await;

    let mut peers = Vec::new();

    // Try to get real peer data from SwarmManager
    if let Some(swarm_manager) = &state.swarm_manager {
        // Use get_stats to get connected peers list
        if let Ok(stats) = swarm_manager.get_stats().await {
            for peer_id in stats.connected_peers_list {
                peers.push(PeerInfo {
                    peer_id: peer_id.to_string(),
                    status: "Connected".to_string(),
                    latency: 0.0, // Not available in basic stats
                    last_seen: chrono::Utc::now().to_rfc3339(),
                    data_transferred: 0.0, // Not available in basic stats
                });
            }
        }
    }

    Json(peers)
}

/// Get connection metrics
async fn get_connection_metrics(State(state): State<Arc<AppState>>) -> Json<ConnectionMetrics> {
    state.increment_request_count().await;

    let mut metrics = ConnectionMetrics {
        total_connections: 0,
        active_connections: 0,
        failed_connections: 0,
        success_rate: 0.0,
    };

    // Try to get real connection metrics from SwarmManager
    if let Some(swarm_manager) = &state.swarm_manager {
        let conn_metrics = swarm_manager.get_metrics().await;
        metrics.total_connections = conn_metrics.active_connections; // Approximation
        metrics.active_connections = conn_metrics.active_connections;
        metrics.failed_connections = conn_metrics.connection_failures as usize;
        metrics.success_rate = if conn_metrics.connection_attempts > 0 {
            1.0 - (conn_metrics.connection_failures as f64
                / conn_metrics.connection_attempts as f64)
        } else {
            1.0
        };
    }

    Json(metrics)
}

/// Get network topology data
async fn get_topology(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    state.increment_request_count().await;

    let mut topology = serde_json::json!({
        "nodes": [],
        "edges": []
    });

    // Try to get real topology data from SwarmManager
    if let Some(swarm_manager) = &state.swarm_manager {
        let mut nodes = Vec::new();
        let mut edges = Vec::new();

        // Add local node
        nodes.push(serde_json::json!({
            "id": "local",
            "label": "Local Node",
            "group": "local"
        }));

        if let Ok(stats) = swarm_manager.get_stats().await {
            for peer_id in stats.connected_peers_list {
                let pid_str = peer_id.to_string();
                nodes.push(serde_json::json!({
                    "id": pid_str,
                    "label": format!("Peer {}", pid_str.chars().take(8).collect::<String>()),
                    "group": "connected"
                }));

                // Add edge from local to peer
                edges.push(serde_json::json!({
                    "from": "local",
                    "to": pid_str,
                    "value": 10
                }));
            }
        }

        topology["nodes"] = serde_json::Value::Array(nodes);
        topology["edges"] = serde_json::Value::Array(edges);
    }

    Json(topology)
}
