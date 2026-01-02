use crate::dashboard::AppState;
use axum::{extract::State, Json};
use std::sync::Arc;

pub async fn get_behavioral_metrics(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    // Get behavioral analysis metrics from threat detection engine
    let threat_engine = state.core.threat_detection();
    
    let metrics = serde_json::json!({
        "behavioral_analysis": {
            "pattern_matchers": threat_engine.behavioral_analyzer().pattern_count(),
            "active_patterns": threat_engine.behavioral_analyzer().active_pattern_count(),
            "analysis_window": "3600s",
            "recent_detections": threat_engine.behavioral_analyzer().recent_detection_count()
        },
        "anomaly_detection": {
            "algorithms_active": threat_engine.anomaly_detector().algorithm_count(),
            "statistical_models": threat_engine.anomaly_detector().model_count(),
            "baseline_established": true
        },
        "reputation_system": {
            "peers_tracked": threat_engine.reputation_system().peer_count(),
            "average_reputation": threat_engine.reputation_system().average_reputation(),
            "reputation_trends": threat_engine.reputation_system().get_trends()
        }
    });
    
    Json(metrics)
}

pub async fn get_peer_behavior(State(state): State<Arc<AppState>>, axum::extract::Path(peer_id): axum::extract::Path<String>) -> Json<serde_json::Value> {
    let threat_engine = state.core.threat_detection();
    
    // Get peer-specific behavioral data
    let peer_behavior = serde_json::json!({
        "peer_id": peer_id,
        "behavioral_score": threat_engine.behavioral_analyzer().get_peer_score(&peer_id),
        "reputation_score": threat_engine.reputation_system().get_peer_reputation(&peer_id),
        "anomaly_score": threat_engine.anomaly_detector().get_peer_anomaly_score(&peer_id),
        "last_analysis": chrono::Utc::now().to_rfc3339()
    });
    
    Json(peer_behavior)
}
