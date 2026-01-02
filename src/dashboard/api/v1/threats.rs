use crate::dashboard::AppState;
use axum::{extract::State, Json};
use std::sync::Arc;

pub async fn get_threat_intelligence(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let threat_engine = state.core.threat_detection();

    let intelligence = serde_json::json!({
        "threat_feeds": {
            "active_feeds": threat_engine.threat_intelligence().feed_count(),
            "last_update": chrono::Utc::now().to_rfc3339(),
            "indicators_count": threat_engine.threat_intelligence().indicator_count()
        },
        "incident_response": {
            "active_responses": threat_engine.incident_response().active_response_count(),
            "escalation_conditions": threat_engine.incident_response().escalation_condition_count(),
            "response_policies": threat_engine.incident_response().policy_count()
        },
        "detection_events": {
            "total_events": threat_engine.get_detection_stats().total_detections,
            "recent_events": threat_engine.get_detection_stats().recent_detections,
            "unique_threats": threat_engine.get_detection_stats().unique_peers_with_threats
        }
    });

    Json(intelligence)
}

pub async fn get_active_threats(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let threats = state
        .wolf_security
        .threat_detector
        .get_active_threats()
        .await;

    let active_threats = serde_json::json!({
        "active_threats": threats,
        "count": threats.len(),
        "timestamp": chrono::Utc::now()
    });

    Json(active_threats)
}
