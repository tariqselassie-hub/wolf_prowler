//! WebSocket Module for Real-time Dashboard Updates
//!
//! This module provides WebSocket functionality for real-time monitoring
//! and updates in the Wolf Prowler dashboard.

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    response::Response,
    routing::get,
    Router,
};
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::dashboard::state::AppState;
use wolf_net::{swarm::NetworkMetrics, SwarmManager};
use wolfsec::security::advanced::iam::{
    ApiKeyValidationResult, AuthenticationMethod, SessionValidationResult,
};
use wolfsec::WolfSecurity;

/// WebSocket connection state
#[derive(Debug)]
pub struct WebSocketState {
    /// Broadcast sender for real-time updates
    pub tx: broadcast::Sender<String>,
    /// Broadcast receiver for real-time updates
    pub rx: broadcast::Receiver<String>,
}

impl Clone for WebSocketState {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
            rx: self.tx.subscribe(),
        }
    }
}

impl WebSocketState {
    /// Create a new WebSocket state
    pub fn new() -> Self {
        let (tx, rx) = broadcast::channel(100);
        Self { tx, rx }
    }
}

/// WebSocket message types
#[derive(Debug, Serialize, Deserialize)]
pub enum DashboardMessage {
    /// System metrics update
    #[serde(rename = "system_metrics")]
    SystemMetrics {
        /// CPU usage percentage
        cpu: f64,
        /// Memory usage percentage
        memory: f64,
        /// System uptime in seconds
        uptime: u64
    },

    /// Network status update
    #[serde(rename = "network_status")]
    NetworkStatus {
        /// Number of connected peers
        peers: usize,
        /// Number of active connections
        connections: usize,
        /// Network health score (0-100)
        health: f64,
    },

    /// Security alert
    #[serde(rename = "security_alert")]
    SecurityAlert {
        /// Alert severity level
        severity: String,
        /// Alert message content
        message: String,
        /// Timestamp of the alert
        timestamp: String,
    },

    /// Threat detection update
    #[serde(rename = "threat_update")]
    ThreatUpdate {
        /// Type of threat detected
        threat_type: String,
        /// Number of threats of this type
        count: usize,
        /// Timestamp of the update
        timestamp: String,
    },

    /// General notification
    #[serde(rename = "notification")]
    Notification {
        /// Notification title
        title: String,
        /// Notification message
        message: String
    },
}

/// WebSocket handler for dashboard updates
pub async fn dashboard_ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Response {
    // Extract authentication parameters
    let api_key = params.get("api_key").cloned();
    let session_id = params.get("session_id").cloned();

    // Validate authentication
    let user_id = {
        let auth_manager = state.auth_manager.lock().await;
        match (api_key, session_id) {
            (Some(key), _) => {
                // Try API key authentication
                let validation_result: ApiKeyValidationResult =
                    match auth_manager.validate_api_key(&key).await {
                        Ok(result) => result,
                        Err(_) => {
                            return Response::builder()
                                .status(500)
                                .body(axum::body::Body::from("API key validation failed"))
                                .unwrap();
                        }
                    };

                if !validation_result.valid {
                    return Response::builder()
                        .status(401)
                        .body(axum::body::Body::from(
                            validation_result
                                .error_message
                                .unwrap_or_else(|| "Invalid API key".to_string()),
                        ))
                        .unwrap();
                }

                validation_result.user_id
            }
            (None, Some(session_id_str)) => {
                // Try session authentication
                let session_uuid = match Uuid::parse_str(&session_id_str) {
                    Ok(uuid) => uuid,
                    Err(_) => {
                        return Response::builder()
                            .status(401)
                            .body(axum::body::Body::from("Invalid session ID format"))
                            .unwrap();
                    }
                };

                let validation_result: SessionValidationResult =
                    match auth_manager.validate_session(session_uuid).await {
                        Ok(result) => result,
                        Err(_) => {
                            return Response::builder()
                                .status(500)
                                .body(axum::body::Body::from("Session validation failed"))
                                .unwrap();
                        }
                    };

                if !validation_result.valid {
                    return Response::builder()
                        .status(401)
                        .body(axum::body::Body::from(
                            validation_result
                                .error_message
                                .unwrap_or_else(|| "Invalid session".to_string()),
                        ))
                        .unwrap();
                }

                validation_result.user_id
            }
            (None, None) => {
                return Response::builder()
                    .status(401)
                    .body(axum::body::Body::from(
                        "Authentication required: provide either api_key or session_id",
                    ))
                    .unwrap();
            }
        }
    };

    // Authentication successful, proceed with WebSocket upgrade
    // Clone state for the WebSocket handler
    let state_clone = state.clone();
    ws.on_upgrade(move |socket| handle_socket(socket, state_clone, user_id))
}

/// Handle WebSocket connection
async fn handle_socket(socket: WebSocket, state: Arc<AppState>, user_id: Option<Uuid>) {
    let (mut sender, mut receiver) = socket.split();

    // Send initial welcome message with user info
    let welcome_message = if let Some(user_id) = user_id {
        format!("Welcome to Wolf Prowler Dashboard, User: {}", user_id)
    } else {
        "Welcome to Wolf Prowler Dashboard".to_string()
    };

    let welcome_msg = serde_json::to_string(&DashboardMessage::Notification {
        title: "Connected".to_string(),
        message: welcome_message,
    })
    .unwrap();

    if sender.send(Message::Text(welcome_msg)).await.is_err() {
        return;
    }

    // Spawn task to handle incoming messages from broadcast
    let tx_clone = state.websocket_state.tx.clone();
    let mut sender_for_broadcast = sender;
    let send_task = tokio::spawn(async move {
        let mut rx = tx_clone.subscribe();
        while let Ok(msg) = rx.recv().await {
            if sender_for_broadcast.send(Message::Text(msg)).await.is_err() {
                break;
            }
        }
    });

    // Handle incoming messages from client
    while let Some(Ok(message)) = receiver.next().await {
        match message {
            Message::Text(text) => {
                // Handle text messages (could be commands, etc.)
                tracing::debug!("Received WebSocket message: {}", text);

                // Echo back for now
                if send_task.is_finished() {
                    break;
                }
            }
            Message::Close(_) => {
                break;
            }
            _ => {}
        }
    }

    // Cleanup
    send_task.abort();
}

/// Create WebSocket router
pub fn create_websocket_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/dashboard", get(dashboard_ws_handler))
        .with_state(state)
}

/// Broadcast system metrics update
pub async fn broadcast_system_metrics(
    tx: &broadcast::Sender<String>,
    cpu: f64,
    memory: f64,
    uptime: u64,
) {
    let message = DashboardMessage::SystemMetrics {
        cpu,
        memory,
        uptime,
    };
    let json = serde_json::to_string(&message).unwrap();
    let _ = tx.send(json);
}

/// Broadcast network status update
pub async fn broadcast_network_status(
    tx: &broadcast::Sender<String>,
    peers: usize,
    connections: usize,
    health: f64,
) {
    let message = DashboardMessage::NetworkStatus {
        peers,
        connections,
        health,
    };
    let json = serde_json::to_string(&message).unwrap();
    let _ = tx.send(json);
}

/// Broadcast security alert
pub async fn broadcast_security_alert(
    tx: &broadcast::Sender<String>,
    severity: String,
    message: String,
) {
    let timestamp = chrono::Utc::now().to_rfc3339();
    let alert = DashboardMessage::SecurityAlert {
        severity,
        message,
        timestamp,
    };
    let json = serde_json::to_string(&alert).unwrap();
    let _ = tx.send(json);
}

/// Broadcast threat update
pub async fn broadcast_threat_update(
    tx: &broadcast::Sender<String>,
    threat_type: String,
    count: usize,
) {
    let timestamp = chrono::Utc::now().to_rfc3339();
    let update = DashboardMessage::ThreatUpdate {
        threat_type,
        count,
        timestamp,
    };
    let json = serde_json::to_string(&update).unwrap();
    let _ = tx.send(json);
}

/// Calculate network health based on metrics
fn calculate_network_health(metrics: &NetworkMetrics) -> f64 {
    let total_connections = metrics.active_connections.max(1);
    let failure_rate =
        metrics.connection_failures as f64 / (metrics.connection_attempts.max(1)) as f64;

    // Simple health calculation: higher connections and lower failure rate = better health
    let connection_score = (total_connections as f64 / 100.0).min(1.0); // Cap at 100 connections
    let reliability_score = (1.0 - failure_rate).max(0.0);

    (connection_score * 0.6 + reliability_score * 0.4) * 100.0
}

/// Start background task to monitor real system events and forward to WebSocket
pub fn start_system_monitoring_task(
    tx: broadcast::Sender<String>,
    wolf_security: Option<Arc<tokio::sync::RwLock<WolfSecurity>>>,
    swarm_manager: Option<Arc<SwarmManager>>,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));

        loop {
            interval.tick().await;

            // Monitor real system metrics from WolfSecurity with error handling
            if let Some(wolf_sec) = &wolf_security {
                let wolf_sec_read = wolf_sec.read().await;

                // Get system metrics with error handling
                match wolf_sec_read.get_metrics().await {
                    Ok(metrics) => {
                        let cpu = metrics.system.cpu_usage;
                        let memory = metrics.system.memory_usage;
                        let uptime = 0; // metrics.system.uptime not available

                        broadcast_system_metrics(&tx, cpu, memory, uptime).await;
                    }
                    Err(e) => {
                        tracing::error!("Failed to get system metrics: {}", e);
                        broadcast_security_alert(
                            &tx,
                            "error".to_string(),
                            format!("System metrics error: {}", e),
                        )
                        .await;
                    }
                }

                // Get security alerts
                let alerts = wolf_sec_read.get_recent_alerts().await;
                for alert_msg in alerts {
                    broadcast_security_alert(
                        &tx,
                        "info".to_string(), // Default severity since we only have a string
                        alert_msg,
                    )
                    .await;
                }

                // Get threat updates
                let threats = wolf_sec_read.get_recent_threats().await;
                for threat_msg in threats {
                    broadcast_threat_update(
                        &tx, threat_msg, 1, // Default count
                    )
                    .await;
                }
                // No error handling needed for lock acquisition
            } else {
                tracing::warn!("WolfSecurity component not available - using fallback metrics");
                // Provide fallback metrics when real system is not available
                broadcast_system_metrics(&tx, 0.0, 0.0, 0).await;
            }

            // Monitor real network metrics from SwarmManager with error handling
            if let Some(swarm) = &swarm_manager {
                let metrics = swarm.get_metrics().await;
                let peers = metrics.connected_peers;
                let connections = metrics.active_connections;
                let health = metrics.network_health;

                broadcast_network_status(&tx, peers, connections, health).await;

                // Get swarm stats with error handling
                match swarm.get_stats().await {
                    Ok(stats) => {
                        // Broadcast any important network events
                        if stats.metrics.connection_failures > 0 {
                            broadcast_security_alert(
                                &tx,
                                "warning".to_string(),
                                format!(
                                    "Network errors detected: {}",
                                    stats.metrics.connection_failures
                                ),
                            )
                            .await;
                        }
                    }
                    Err(e) => {
                        tracing::error!("Failed to get swarm stats: {}", e);
                        broadcast_security_alert(
                            &tx,
                            "warning".to_string(),
                            "Network monitoring error".to_string(),
                        )
                        .await;
                    }
                }
            } else {
                tracing::warn!(
                    "SwarmManager component not available - using fallback network metrics"
                );
                // Provide fallback network metrics when real network is not available
                broadcast_network_status(&tx, 0, 0, 0.0).await;
            }
        }
    });
}
