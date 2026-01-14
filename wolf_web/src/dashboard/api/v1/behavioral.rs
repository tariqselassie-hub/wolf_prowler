//! Behavioral Analysis API Endpoints
//!
//! This module provides API endpoints for accessing behavioral analysis data
//! and performing behavioral analysis operations.

use axum::extract::State;
use axum::{routing::get, Json, Router};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::dashboard::api::ApiError;
use crate::dashboard::state::AppState;

/// Behavioral analysis response
#[derive(Debug, Serialize, Deserialize)]
pub struct BehavioralResponse {
    /// Peer ID
    pub peer_id: String,
    /// Behavioral score (0.0 - 1.0)
    pub behavioral_score: f64,
    /// Risk level classification
    pub risk_level: String,
    /// Priority for mitigation (1-10)
    pub mitigation_priority: u8,
    /// Specific risk factors identified
    pub risk_factors: Vec<RiskFactorInfo>,
    /// Recent activity count
    pub activity_count: usize,
    /// Average peer score in the swarm
    pub avg_peer_score: f64,
}

/// Information about a specific risk factor identified in behavioral analysis
#[derive(Debug, Serialize, Deserialize)]
pub struct RiskFactorInfo {
    /// The type of risk (e.g., `AnomalousTraffic`, `HighEntropy`)
    pub factor_type: String,
    /// The weight/significance of this factor (0.0 - 1.0)
    pub weight: f64,
    /// The actual value or score for this factor
    pub value: f64,
    /// A human-readable description of why this factor was flagged
    pub description: String,
}

/// Create behavioral analysis router
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(get_behavioral_analysis))
        .route("/:peer_id", get(get_peer_behavioral_analysis))
        .with_state(state)
}

/// Get overall behavioral analysis
async fn get_behavioral_analysis(
    State(state): State<Arc<AppState>>,
) -> Result<Json<BehavioralResponse>, ApiError> {
    state.increment_request_count().await;

    let wolf_sec_arc = state.get_wolf_security();

    if let Some(wolf_sec) = wolf_sec_arc {
        let security = wolf_sec.read().await;
        let threat_detector = &security.threat_detector;

        let _behavioral_score = threat_detector.config().security_config.trust_threshold; // Fallback to threshold

        // In a real scenario, we'd aggregate across all peers
        // Here we'll return a summary
        return Ok(Json(BehavioralResponse {
            peer_id: "swarm".to_string(),
            behavioral_score: 0.85,
            risk_level: "Low".to_string(),
            mitigation_priority: 1,
            risk_factors: vec![],
            activity_count: 0,
            avg_peer_score: 0.9,
        }));
    }

    // Fallback to legacy engine if WolfSecurity is not available
    let behavioral_engine = state.behavioral_engine.lock().await;

    Ok(Json(BehavioralResponse {
        peer_id: "overall".to_string(),
        behavioral_score: behavioral_engine.get_overall_score(),
        risk_level: "Low".to_string(),
        mitigation_priority: 1,
        risk_factors: vec![],
        activity_count: behavioral_engine.pattern_count(),
        avg_peer_score: behavioral_engine.get_average_peer_score(),
    }))
}

/// Get behavioral analysis for specific peer
async fn get_peer_behavioral_analysis(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(peer_id): axum::extract::Path<String>,
) -> Result<Json<BehavioralResponse>, ApiError> {
    state.increment_request_count().await;

    if let Some(wolf_sec_arc) = state.get_wolf_security() {
        let security = wolf_sec_arc.read().await;
        if let Some(peer_info) = security.threat_detector.get_peer_info(&peer_id).await {
            return Ok(Json(BehavioralResponse {
                peer_id: peer_id.clone(),
                behavioral_score: peer_info.behavioral_profile.behavioral_score,
                risk_level: format!("{:?}", peer_info.risk_assessment.risk_level),
                mitigation_priority: peer_info.risk_assessment.mitigation_priority,
                risk_factors: peer_info
                    .behavioral_profile
                    .risk_factors
                    .iter()
                    .map(|f| RiskFactorInfo {
                        factor_type: f.factor_type.clone(),
                        weight: f.weight,
                        value: f.value,
                        description: f.description.clone(),
                    })
                    .collect(),
                activity_count: peer_info.behavioral_profile.activity_timeline.len(),
                avg_peer_score: 0.9, // This would be better if calculated
            }));
        }
    }

    // Fallback or Not Found
    let behavioral_engine = state.behavioral_engine.lock().await;
    let behavioral_score = behavioral_engine.get_peer_score(&peer_id);

    Ok(Json(BehavioralResponse {
        peer_id,
        behavioral_score,
        risk_level: "Unknown".to_string(),
        mitigation_priority: 0,
        risk_factors: vec![],
        activity_count: 0,
        avg_peer_score: behavioral_engine.get_average_peer_score(),
    }))
}
