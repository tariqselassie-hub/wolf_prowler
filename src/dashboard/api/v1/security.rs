use crate::dashboard::AppState;
use axum::{extract::State, Json};
use std::sync::Arc;

pub async fn get_security_metrics(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    // Get real security metrics from SecurityManager
    let security_stats = state.security.get_security_stats();
    
    // Get threat detection metrics
    let threat_stats = state.core.threat_detection().get_detection_stats();
    
    let resp = serde_json::json!({
        "threat_detection": {
            "total_detections": threat_stats.total_detections,
            "recent_detections": threat_stats.recent_detections,
            "unique_peers_with_threats": threat_stats.unique_peers_with_threats,
            "average_confidence": threat_stats.average_confidence,
            "detection_types": threat_stats.detection_types
        },
        "security_level": if security_stats.active_threats > 0 { "HIGH" } else { "LOW" },
        "active_threats": security_stats.active_threats,
        "trusted_peers": security_stats.trusted_peers,
        "suspicious_peers": security_stats.suspicious_peers
    });
    Json(resp)
}
