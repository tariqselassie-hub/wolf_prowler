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

    let mut response = IntelligenceStatusResponse {
        critical_cves: 0,
        cve_week: 0,
        ai_predictions: 0,
        prediction_accuracy: 0.92,
        threat_indicators: 0,
        active_indicators: 0,
        intelligence_feeds: 0,
        last_feed_update: chrono::Utc::now().to_rfc3339(),
    };

    if let Some(wolf_security_arc) = state.get_wolf_security() {
        let security = wolf_security_arc.read().await;

        // Use vulnerability scanner data
        let vulnerabilities = security.vulnerability_scanner.get_vulnerabilities().await;
        response.critical_cves = vulnerabilities
            .iter()
            .filter(|v| v.severity == wolfsec::SecuritySeverity::Critical)
            .count();
        response.cve_week = vulnerabilities.len();

        // Use AI models data
        if let Some(ref ai_models) = security.threat_detector.ai_models {
            let ai_status = ai_models.get_status();
            response.ai_predictions = ai_status.prediction_count as usize;
            response.prediction_accuracy = ai_status.average_accuracy;
        }

        // Use SIEM statistics for indicators
        let siem_stats = security.siem.get_statistics();
        response.threat_indicators = siem_stats.total_events_processed as usize;
        response.active_indicators = siem_stats.alerts_generated as usize;
        response.intelligence_feeds = 3; // Standard feeds
    }

    Json(response)
}

/// Get recent CVEs
async fn get_cves(State(state): State<Arc<AppState>>) -> Json<Vec<CVEInfo>> {
    state.increment_request_count().await;

    let mut cves = Vec::new();

    if let Some(wolf_security_arc) = state.get_wolf_security() {
        let security = wolf_security_arc.read().await;
        let vulnerabilities = security.vulnerability_scanner.get_vulnerabilities().await;

        for v in vulnerabilities {
            if let Some(cve_id) = v.cve_id {
                cves.push(CVEInfo {
                    cve_id,
                    severity: format!("{:?}", v.severity),
                    cvss_score: v.cvss_score.unwrap_or(0.0),
                    description: v.description,
                    published_date: chrono::Utc::now().to_rfc3339(), // Placeholder date
                    last_modified: chrono::Utc::now().to_rfc3339(),
                });
            }
        }
    }

    Json(cves)
}

/// Get threat indicators
async fn get_threat_indicators(State(state): State<Arc<AppState>>) -> Json<Vec<ThreatIndicator>> {
    state.increment_request_count().await;

    let mut indicators = Vec::new();

    if let Some(wolf_security_arc) = state.get_wolf_security() {
        let security = wolf_security_arc.read().await;
        let incidents = security.get_recent_threats().await; // This returns Strings currently, maybe expand later

        for (i, incident) in incidents.into_iter().enumerate() {
            indicators.push(ThreatIndicator {
                indicator_id: format!("IND-{i}"),
                indicator_type: "Network".to_string(),
                value: incident,
                confidence: 0.85,
                source: "Wolf SIEM".to_string(),
                last_seen: chrono::Utc::now().to_rfc3339(),
            });
        }
    }

    Json(indicators)
}

/// Get AI predictions
async fn get_ai_predictions(State(state): State<Arc<AppState>>) -> Json<Vec<AIPrediction>> {
    state.increment_request_count().await;

    let mut predictions = Vec::new();

    if let Some(wolf_security_arc) = state.get_wolf_security() {
        let security = wolf_security_arc.read().await;
        if let Some(ref ai_models) = security.threat_detector.ai_models {
            let ai_status = ai_models.get_status();

            // If we had a list of predictions, we'd add them here
            // For now, return a sample based on status
            if ai_status.prediction_count > 0 {
                predictions.push(AIPrediction {
                    prediction_id: "PRED-001".to_string(),
                    threat_type: "Anomalous Traffic".to_string(),
                    confidence: ai_status.average_accuracy,
                    predicted_impact: "Medium".to_string(),
                    time_to_impact: "T+2h".to_string(),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                });
            }
        }
    }

    Json(predictions)
}

/// Get intelligence feeds
async fn get_intelligence_feeds(State(state): State<Arc<AppState>>) -> Json<Vec<IntelligenceFeed>> {
    state.increment_request_count().await;

    let feeds = vec![
        IntelligenceFeed {
            name: "NVD CVE Feed".to_string(),
            feed_type: "Vulnerability".to_string(),
            status: "Online".to_string(),
            last_update: chrono::Utc::now().to_rfc3339(),
            indicators_count: 1542,
        },
        IntelligenceFeed {
            name: "Wolf Swarm Intel".to_string(),
            feed_type: "P2P Threat".to_string(),
            status: "Active".to_string(),
            last_update: chrono::Utc::now().to_rfc3339(),
            indicators_count: 87,
        },
    ];

    Json(feeds)
}
