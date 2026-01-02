use axum::{extract::State, Json};
use serde_json::json;
use std::sync::Arc;

use crate::dashboard::AppState;

/// Standard metrics response for the dashboard.
pub async fn get_metrics(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let swarm_stats = match state.swarm_manager.get_stats().await {
        Ok(stats) => stats,
        Err(_) => return Json(json!({"error": "Failed to fetch swarm stats"})),
    };
    
    let mut metrics: tokio::sync::MutexGuard<crate::utils::metrics_simple::MetricsCollector> = state.metrics_collector.lock().await;
    metrics.update_system_metrics();
    let net_snapshot = metrics.get_network_snapshot();
    let sys_snapshot = metrics.get_system_snapshot();

    Json(json!({
        "network": {
            "active_connections": swarm_stats.connected_peers,
            "total_bytes_sent": swarm_stats.metrics.total_bytes_sent,
            "total_bytes_received": swarm_stats.metrics.total_bytes_received,
            "avg_latency_ms": net_snapshot.avg_message_latency,
            "avg_connection_duration_s": net_snapshot.avg_connection_duration,
        },
        "system": {
            "cpu_usage_percent": sys_snapshot.cpu_usage,
            "memory_usage_percent": sys_snapshot.memory_usage,
            "uptime_seconds": chrono::Utc::now().signed_duration_since(metrics.start_time).num_seconds(),
        },
        "connected_peers": swarm_stats.connected_peers_list
    }))
}
