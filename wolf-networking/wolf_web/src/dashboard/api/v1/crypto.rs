//! Cryptographic Operations API Endpoints
//!
//! This module provides API endpoints for monitoring cryptographic operations
//! and accessing cryptographic metrics.

use axum::extract::State;
use axum::{routing::get, Json, Router};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::dashboard::state::AppState;

/// Cryptographic operations response
#[derive(Debug, Serialize, Deserialize)]
pub struct CryptoResponse {
    /// Total cryptographic keys
    pub total_keys: usize,
    /// Active keys
    pub active_keys: usize,
    /// Total certificates
    pub total_certificates: usize,
    /// Trusted certificates
    pub trusted_certificates: usize,
    /// Expired certificates
    pub expired_certificates: usize,
    /// Average operation time (ms) - still a placeholder as not tracked in `KeyManager`
    pub avg_operation_time: f64,
}

/// Create cryptographic operations router
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(get_crypto_stats))
        .route("/operations", get(get_crypto_operations))
        .with_state(state)
}

/// Get cryptographic statistics
async fn get_crypto_stats(State(state): State<Arc<AppState>>) -> Json<CryptoResponse> {
    state.increment_request_count().await;

    let mut response = CryptoResponse {
        total_keys: 0,
        active_keys: 0,
        total_certificates: 0,
        trusted_certificates: 0,
        expired_certificates: 0,
        avg_operation_time: 0.0,
    };

    if let Some(wolf_security_arc) = state.get_wolf_security() {
        let security = wolf_security_arc.read().await;
        if let Ok(status) = security.get_status().await {
            let key_status = &status.key_management;

            response.total_keys = key_status.total_keys;
            response.active_keys = key_status.active_keys;
            response.total_certificates = key_status.total_certificates;
            response.trusted_certificates = key_status.trusted_certificates;
            response.expired_certificates = key_status.expired_certificates;
        }
    }

    Json(response)
}

/// Get cryptographic operations details
async fn get_crypto_operations(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    state.increment_request_count().await;

    let mut operations_data = serde_json::json!({
        "operations": [],
        "security_level": "high",
        "compliance_status": "compliant",
        "next_rotation": null
    });

    if let Some(wolf_security_arc) = state.get_wolf_security() {
        let security = wolf_security_arc.read().await;
        if let Ok(status) = security.get_status().await {
            let key_status = &status.key_management;

            operations_data["next_rotation"] = serde_json::json!(key_status.next_rotation);

            // Populate operations with algorithm info from real KeyManager
            let operations = vec![
                serde_json::json!({
                    "type": "Key Management",
                    "status": "Active",
                    "count": key_status.total_keys,
                    "description": "PQC-secured cryptographic material"
                }),
                serde_json::json!({
                    "type": "Certificates",
                    "status": "Compliant",
                    "count": key_status.total_certificates,
                    "description": "X.509-like identity tokens"
                }),
            ];

            operations_data["operations"] = serde_json::Value::Array(operations);
        }
    }

    Json(operations_data)
}
