//! Threat Detection API Endpoints
//!
//! This module provides API endpoints for accessing threat detection data
//! and monitoring security threats.

use axum::extract::State;
use axum::{routing::get, Json, Router};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::dashboard::state::AppState;
use wolfsec::threat_detection::{Threat, ThreatStatus};

/// Create threat detection router
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(get_threat_stats))
        .route("/recent", get(get_recent_threats))
        .route("/:peer_id", get(get_threats_by_peer))
        .with_state(state)
}

/// Get overall threat statistics
async fn get_threat_stats(State(state): State<Arc<AppState>>) -> Json<ThreatsResponse> {
    state.increment_request_count().await;

    let threat_engine: tokio::sync::MutexGuard<'_, wolfsec::threat_detection::ThreatDetector> =
        state.threat_engine.lock().await;
    let status = threat_engine.get_status().await;
    let metrics = status.metrics;

    // Get real threat counts by severity from the threat engine
    let threats = threat_engine.get_active_threats().await;
    let (critical_threats, high_threats, medium_threats, low_threats) =
        threats.iter().fold((0, 0, 0, 0), |mut counts, threat| {
            match threat.severity {
                wolfsec::SecuritySeverity::Critical => counts.0 += 1,
                wolfsec::SecuritySeverity::High => counts.1 += 1,
                wolfsec::SecuritySeverity::Medium => counts.2 += 1,
                wolfsec::SecuritySeverity::Low => counts.3 += 1,
            }
            counts
        });

    Json(ThreatsResponse {
        total_threats: threats.len(),
        active_threats: metrics.active_threats as usize,
        critical_threats,
        high_threats,
        medium_threats,
        low_threats,
        average_confidence: metrics.average_confidence,
        detection_rate: metrics.active_threats as f64 / status.uptime.max(1) as f64,
    })
}

/// Get recent threats
async fn get_recent_threats(State(state): State<Arc<AppState>>) -> Json<Vec<ThreatDetailResponse>> {
    state.increment_request_count().await;

    let threat_engine: tokio::sync::MutexGuard<'_, wolfsec::threat_detection::ThreatDetector> =
        state.threat_engine.lock().await;
    let threats: Vec<Threat> = threat_engine.get_active_threats().await;

    let responses: Vec<ThreatDetailResponse> = threats
        .into_iter()
        .map(|t| ThreatDetailResponse {
            threat_id: t.id,
            threat_type: format!("{:?}", t.threat_type),
            source_peer: t.source_peer.unwrap_or_default(),
            severity: format!("{:?}", t.severity),
            confidence: t.confidence,
            description: t.description,
            detected_at: t.detected_at.to_rfc3339(),
            status: format!("{:?}", t.status),
        })
        .collect();

    Json(responses)
}

/// Get threats by specific peer
async fn get_threats_by_peer(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(peer_id): axum::extract::Path<String>,
) -> Json<Vec<ThreatDetailResponse>> {
    state.increment_request_count().await;

    let threat_engine: tokio::sync::MutexGuard<'_, wolfsec::threat_detection::ThreatDetector> =
        state.threat_engine.lock().await;
    let threats: Vec<Threat> = threat_engine.get_active_threats().await;

    // Filter by peer_id
    let peer_threats: Vec<ThreatDetailResponse> = threats
        .into_iter()
        .filter(|t| t.source_peer.as_deref() == Some(&peer_id))
        .map(|t| ThreatDetailResponse {
            threat_id: t.id,
            threat_type: format!("{:?}", t.threat_type),
            source_peer: t.source_peer.unwrap_or_default(),
            severity: format!("{:?}", t.severity),
            confidence: t.confidence,
            description: t.description,
            detected_at: t.detected_at.to_rfc3339(),
            status: format!("{:?}", t.status),
        })
        .collect();

    Json(peer_threats)
}

#[derive(Serialize)]
pub struct ThreatsResponse {
    pub total_threats: usize,
    pub active_threats: usize,
    pub critical_threats: usize,
    pub high_threats: usize,
    pub medium_threats: usize,
    pub low_threats: usize,
    pub average_confidence: f64,
    pub detection_rate: f64,
}

#[derive(Serialize)]
pub struct ThreatDetailResponse {
    pub threat_id: String,
    pub threat_type: String,
    pub source_peer: String,
    pub severity: String,
    pub confidence: f64,
    pub description: String,
    pub detected_at: String,
    pub status: String,
}
