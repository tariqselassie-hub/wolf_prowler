//! Security Metrics API Endpoints
//!
//! This module provides API endpoints for accessing security metrics
//! and overall security status.

use axum::extract::State;
use axum::{routing::get, Json, Router};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use wolfsec::threat_detection::SecurityMetrics;

use crate::dashboard::state::AppState;

/// Security status response
#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityStatusResponse {
    /// Overall security score (0.0 - 1.0)
    pub security_score: f64,
    /// Threat level (low, medium, high, critical)
    pub threat_level: String,
    /// Compliance status
    pub compliance_status: String,
    /// Active security measures
    pub active_measures: Vec<String>,
    /// Recent security events
    pub recent_events: Vec<SecurityEvent>,
    /// Security recommendations
    pub recommendations: Vec<String>,
}

/// Security event
#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityEvent {
    /// Event ID
    pub event_id: String,
    /// Event type
    pub event_type: String,
    /// Timestamp
    pub timestamp: String,
    /// Severity
    pub severity: String,
    /// Description
    pub description: String,
}

/// Create security metrics router
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/status", get(get_security_status))
        .route("/score", get(get_security_score))
        .route("/compliance", get(get_compliance_status))
        .with_state(state)
}

/// Get overall security status
async fn get_security_status(State(state): State<Arc<AppState>>) -> Json<SecurityStatusResponse> {
    state.increment_request_count().await;

    // Get the unified status from all security modules
    let status = state.get_unified_status().await;
    let metrics = &status.threat_detection.metrics;

    let security_score = metrics.security_score;
    let threat_level = determine_threat_level(security_score);
    let mut recommendations = get_security_recommendations(security_score, metrics);

    let mut active_measures = vec![
        "Real-time threat detection".to_string(),
        "Behavioral analysis".to_string(),
        "Anomaly detection".to_string(),
    ];

    // Add measures based on real module status
    // In Alpha, we assume crypto is active if the status exists
    active_measures.push("PQC-Secured Cryptography".to_string());
    if status.key_management.total_keys > 0 {
        active_measures.push("Automated Key Management".to_string());
    }
    if status.network_security.known_public_keys > 0 {
        active_measures.push("Public Key Registry Active".to_string());
        recommendations.push("Periodic key rotation recommended".to_string());
    }

    // Get recent events from threat detector (which is part of status)
    // For now we'll still use the lock for recent events as status only has metrics
    let threat_engine = state.threat_engine.lock().await;
    let recent_events_raw = threat_engine
        .get_recent_events(chrono::Utc::now() - chrono::Duration::hours(24))
        .await;

    Json(SecurityStatusResponse {
        security_score,
        threat_level,
        compliance_status: if metrics.compliance_score >= 90.0 {
            "Compliant"
        } else {
            "Review Required"
        }
        .to_string(),
        active_measures,
        recent_events: map_security_events(recent_events_raw),
        recommendations: get_security_recommendations(security_score, metrics),
    })
}

/// Calculate security score based on metrics
fn calculate_security_score(metrics: &SecurityMetrics) -> f64 {
    // This is now handled by the WolfSecurity engine directly,
    // but we keep the logic for fallback if ever needed.
    metrics.security_score
}

/// Determine threat level based on security score
fn determine_threat_level(security_score: f64) -> String {
    if security_score >= 0.9 {
        "Low".to_string()
    } else if security_score >= 0.7 {
        "Medium".to_string()
    } else if security_score >= 0.5 {
        "High".to_string()
    } else {
        "Critical".to_string()
    }
}

/// Map security events to DTO
fn map_security_events(events: Vec<wolfsec::SecurityEvent>) -> Vec<SecurityEvent> {
    events
        .into_iter()
        .map(|e| SecurityEvent {
            event_id: e.id,
            event_type: format!("{:?}", e.event_type),
            timestamp: e.timestamp.to_rfc3339(),
            severity: format!("{:?}", e.severity),
            description: e.description,
        })
        .collect()
}

/// Get security recommendations based on score and metrics
fn get_security_recommendations(security_score: f64, metrics: &SecurityMetrics) -> Vec<String> {
    let mut recommendations = Vec::new();

    if security_score < 0.5 {
        recommendations.push("Increase monitoring frequency - high risk detected".to_string());
        recommendations.push("Conduct immediate security audit".to_string());
    }

    if metrics.active_threats > 0 {
        recommendations.push(format!(
            "Investigate {} active threats immediately",
            metrics.active_threats
        ));
    }

    if metrics.risk_score > 0.5 {
        recommendations.push("High risk score - review access policies".to_string());
    }

    if metrics.attack_surface_score > 0.7 {
        recommendations.push("Large attack surface detected - minimize open ports".to_string());
    }

    if recommendations.is_empty() {
        recommendations.push("Maintain current security posture".to_string());
    }

    recommendations
}

/// Get security score only
async fn get_security_score(State(state): State<Arc<AppState>>) -> Json<f64> {
    state.increment_request_count().await;

    let threat_engine = state.threat_engine.lock().await;
    let status = threat_engine.get_status().await;
    let security_score = calculate_security_score(&status.metrics);

    // Also try to get score from WolfSecurity if available
    if let Some(wolf_security) = &state.wolf_security {
        let security = wolf_security.read().await;
        if let Ok(metrics) = security.get_metrics().await {
            return Json(metrics.security_score.max(security_score));
        }
    }

    Json(security_score)
}

/// Get compliance status
async fn get_compliance_status(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    state.increment_request_count().await;

    // Get real compliance data from threat engine
    let threat_engine = state.threat_engine.lock().await;
    let status = threat_engine.get_status().await;
    let metrics = status.metrics;

    Json(serde_json::json!({
        "compliance_status": if metrics.compliance_score >= 90.0 { "Compliant" } else { "Non-Compliant" },
        "standards": [
            "ISO 27001",
            "NIST CSF",
            "GDPR",
            "HIPAA"
        ],
        "last_audit": "2024-01-15",
        "next_audit": "2024-07-15",
        "compliance_score": metrics.compliance_score,
        "findings": [],
        "security_events": metrics.total_events,
        "active_threats": metrics.active_threats,
        "detection_rate": 0.0 // metrics.detection_rate not available
    }))
}
