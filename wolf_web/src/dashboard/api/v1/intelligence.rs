//! Threat Intelligence API Endpoints
//!
//! This module provides API endpoints for threat intelligence including
//! CVE feeds, AI threat predictions, and threat indicators.

use axum::extract::State;
use axum::{routing::get, Json, Router};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::dashboard::state::AppState;

/// Intelligence status response
#[derive(Debug, Serialize, Deserialize)]
pub struct IntelligenceStatusResponse {
    /// Critical CVEs count
    pub critical_cves: usize,
    /// CVEs this week
    pub cve_week: usize,
    /// AI predictions count
    pub ai_predictions: usize,
    /// Prediction accuracy percentage
    pub prediction_accuracy: f64,
    /// Active threat indicators
    pub threat_indicators: usize,
    /// Active indicators count
    pub active_indicators: usize,
    /// Intelligence feeds count
    pub intelligence_feeds: usize,
    /// Last feed update
    pub last_feed_update: String,
}

/// CVE information
#[derive(Debug, Serialize, Deserialize)]
pub struct CVEInfo {
    /// CVE ID
    pub cve_id: String,
    /// Severity
    pub severity: String,
    /// CVSS score
    pub cvss_score: f64,
    /// Description
    pub description: String,
    /// Published date
    pub published_date: String,
    /// Last modified
    pub last_modified: String,
}

/// Threat indicator
#[derive(Debug, Serialize, Deserialize)]
pub struct ThreatIndicator {
    /// Indicator ID
    pub indicator_id: String,
    /// Indicator type
    pub indicator_type: String,
    /// Value
    pub value: String,
    /// Confidence
    pub confidence: f64,
    /// Source
    pub source: String,
    /// Last seen
    pub last_seen: String,
}

/// AI prediction
#[derive(Debug, Serialize, Deserialize)]
pub struct AIPrediction {
    /// Prediction ID
    pub prediction_id: String,
    /// Threat type
    pub threat_type: String,
    /// Confidence score
    pub confidence: f64,
    /// Predicted impact
    pub predicted_impact: String,
    /// Time to impact
    pub time_to_impact: String,
    /// Timestamp
    pub timestamp: String,
}

/// Intelligence feed
#[derive(Debug, Serialize, Deserialize)]
pub struct IntelligenceFeed {
    /// Feed name
    pub name: String,
    /// Feed type
    pub feed_type: String,
    /// Status
    pub status: String,
    /// Last update
    pub last_update: String,
    /// Indicators count
    pub indicators_count: usize,
}

/// Create intelligence router
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/status", get(get_intelligence_status))
        .route("/cves", get(get_cves))
        .route("/indicators", get(get_threat_indicators))
        .route("/predictions", get(get_ai_predictions))
        .route("/feeds", get(get_intelligence_feeds))
        .with_state(state)
}

/// Get intelligence status
async fn get_intelligence_status(
    State(state): State<Arc<AppState>>,
) -> Json<IntelligenceStatusResponse> {
    state.increment_request_count().await;

    Json(IntelligenceStatusResponse {
        critical_cves: 0,
        cve_week: 0,
        ai_predictions: 0,
        prediction_accuracy: 0.0,
        threat_indicators: 0,
        active_indicators: 0,
        intelligence_feeds: 0,
        last_feed_update: chrono::Utc::now().to_rfc3339(),
    })
}

/// Get recent CVEs
async fn get_cves(State(state): State<Arc<AppState>>) -> Json<Vec<CVEInfo>> {
    state.increment_request_count().await;
    // Return empty list until implemented in threat engine
    Json(Vec::new())
}

/// Get threat indicators
async fn get_threat_indicators(State(state): State<Arc<AppState>>) -> Json<Vec<ThreatIndicator>> {
    state.increment_request_count().await;
    // Return empty list until implemented in threat engine
    Json(Vec::new())
}

/// Get AI predictions
async fn get_ai_predictions(State(state): State<Arc<AppState>>) -> Json<Vec<AIPrediction>> {
    state.increment_request_count().await;
    // Return empty list until implemented in threat engine
    Json(Vec::new())
}

/// Get intelligence feeds
async fn get_intelligence_feeds(State(state): State<Arc<AppState>>) -> Json<Vec<IntelligenceFeed>> {
    state.increment_request_count().await;
    // Return empty list until implemented in threat engine
    Json(Vec::new())
}
