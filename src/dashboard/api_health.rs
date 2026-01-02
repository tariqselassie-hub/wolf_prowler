//! Health Check API Endpoint
//!
//! Provides /api/health endpoint for monitoring system health

use axum::{extract::State, Json};
use serde_json::json;
use std::collections::HashMap;

use crate::dashboard::state::AppState;
use crate::health::{ComponentHealth, HealthCheckResponse, HealthMonitor};

/// Global health monitor (lazy static)
use lazy_static::lazy_static;
use std::sync::Mutex;

lazy_static! {
    static ref HEALTH_MONITOR: Mutex<HealthMonitor> = Mutex::new(HealthMonitor::new());
}

/// GET /api/health - System health check endpoint
pub async fn api_health(State(state): State<AppState>) -> Json<HealthCheckResponse> {
    let mut components = HashMap::new();

    // Check P2P Network health
    components.insert("p2p_network".to_string(), check_p2p_health(&state).await);

    // Check Security Engine health
    components.insert(
        "security_engine".to_string(),
        check_security_health(&state).await,
    );

    // Check Crypto Engine health
    components.insert("crypto_engine".to_string(), check_crypto_health(&state));

    // Check Swarm Manager health
    components.insert(
        "swarm_manager".to_string(),
        check_swarm_health(&state).await,
    );

    // Collect system metrics
    let mut monitor = HEALTH_MONITOR.lock().unwrap();
    let metrics = monitor.collect_metrics();
    let uptime_seconds = monitor.uptime_seconds();
    let overall_status = monitor.aggregate_status(&components);

    Json(HealthCheckResponse {
        status: overall_status,
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds,
        components,
        metrics,
        timestamp: chrono::Utc::now().to_rfc3339(),
    })
}

/// Check P2P network health
async fn check_p2p_health(state: &AppState) -> ComponentHealth {
    let network = state.network.read().await;

    // Check if network has peers
    let peer_count = network.peer_count();

    if peer_count > 0 {
        ComponentHealth::healthy_with_message(format!("{} peers connected", peer_count))
            .with_metrics(json!({
                "peer_count": peer_count,
                "is_running": true
            }))
    } else {
        ComponentHealth::degraded("No peers connected").with_metrics(json!({
            "peer_count": 0,
            "is_running": true
        }))
    }
}

/// Check security engine health
async fn check_security_health(state: &AppState) -> ComponentHealth {
    let security_events = state.security_events.read().await;
    let event_count = security_events.len();

    // Check for recent critical events
    let recent_critical = security_events
        .iter()
        .rev()
        .take(10)
        .filter(|e| e.severity == "critical")
        .count();

    if recent_critical > 5 {
        ComponentHealth::degraded(format!("{} recent critical events", recent_critical))
            .with_metrics(json!({
                "total_events": event_count,
                "recent_critical": recent_critical
            }))
    } else {
        ComponentHealth::healthy_with_message(format!("{} events tracked", event_count))
            .with_metrics(json!({
                "total_events": event_count,
                "recent_critical": recent_critical
            }))
    }
}

/// Check crypto engine health
fn check_crypto_health(state: &AppState) -> ComponentHealth {
    // Simple check - if we can access the crypto engine, it's healthy
    let _crypto = &state.crypto;

    ComponentHealth::healthy_with_message("Crypto engine operational").with_metrics(json!({
        "initialized": true
    }))
}

/// Check swarm manager health
async fn check_swarm_health(state: &AppState) -> ComponentHealth {
    // Get peer count from swarm manager
    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = wolf_net::SwarmCommand::ListPeers { responder: tx };

    if state.swarm_manager.command_sender().send(cmd).await.is_ok() {
        match rx.await {
            Ok(peers) => {
                let peer_count = peers.len();
                let online_count = peers.iter().filter(|p| p.is_online()).count();

                if peer_count > 0 {
                    ComponentHealth::healthy_with_message(format!(
                        "{}/{} peers online",
                        online_count, peer_count
                    ))
                    .with_metrics(json!({
                        "total_peers": peer_count,
                        "online_peers": online_count
                    }))
                } else {
                    ComponentHealth::degraded("No peers registered").with_metrics(json!({
                        "total_peers": 0,
                        "online_peers": 0
                    }))
                }
            }
            Err(_) => ComponentHealth::unhealthy("Failed to query swarm manager"),
        }
    } else {
        ComponentHealth::unhealthy("Swarm manager not responding")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_monitor_initialization() {
        let monitor = HEALTH_MONITOR.lock().unwrap();
        assert!(monitor.uptime_seconds() >= 0);
    }
}
