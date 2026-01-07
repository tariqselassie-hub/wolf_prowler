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
    /// Pattern count
    pub pattern_count: usize,
    /// Active pattern count
    pub active_pattern_count: usize,
    /// Recent detection count
    pub recent_detection_count: usize,
    /// Peer behavioral score
    pub peer_score: f64,
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

    let behavioral_engine = state.behavioral_engine.lock().await;

    // Get real behavioral data from the engine
    let behavioral_score = behavioral_engine.get_overall_score();
    let pattern_count = behavioral_engine.pattern_count();
    let active_pattern_count = behavioral_engine.active_pattern_count();
    let recent_detection_count = behavioral_engine.recent_detection_count();
    let peer_score = behavioral_engine.get_average_peer_score();

    tracing::debug!(
        "Retrieved behavioral analysis: score={}, patterns={}, active={}, recent={}",
        behavioral_score,
        pattern_count,
        active_pattern_count,
        recent_detection_count
    );

    Ok(Json(BehavioralResponse {
        peer_id: "overall".to_string(),
        behavioral_score,
        pattern_count,
        active_pattern_count,
        recent_detection_count,
        peer_score,
    }))
}

/// Get behavioral analysis for specific peer
async fn get_peer_behavioral_analysis(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(peer_id): axum::extract::Path<String>,
) -> Result<Json<BehavioralResponse>, ApiError> {
    state.increment_request_count().await;

    // Validate peer ID format
    if peer_id.is_empty() || peer_id.len() > 100 {
        return Err(ApiError::ValidationError(
            "Invalid peer ID format".to_string(),
        ));
    }

    let behavioral_engine = state.behavioral_engine.lock().await;

    // Get peer-specific behavioral data
    let behavioral_score = behavioral_engine.get_peer_score(&peer_id);
    let pattern_count = behavioral_engine.pattern_count();
    let active_pattern_count = behavioral_engine.active_pattern_count();
    let recent_detection_count = behavioral_engine.recent_detection_count();

    tracing::debug!(
        "Retrieved behavioral analysis for peer {}: score={}, patterns={}, active={}, recent={}",
        peer_id,
        behavioral_score,
        pattern_count,
        active_pattern_count,
        recent_detection_count
    );

    Ok(Json(BehavioralResponse {
        peer_id: peer_id.clone(),
        behavioral_score,
        pattern_count,
        active_pattern_count,
        recent_detection_count,
        peer_score: behavioral_score, // For individual peer, use the same score
    }))
}
