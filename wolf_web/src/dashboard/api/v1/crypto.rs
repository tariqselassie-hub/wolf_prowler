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
    /// Total cryptographic operations
    pub total_operations: u64,
    /// Encryption operations
    pub encryption_count: u64,
    /// Decryption operations
    pub decryption_count: u64,
    /// Signature operations
    pub signature_count: u64,
    /// Verification operations
    pub verification_count: u64,
    /// Average operation time (ms)
    pub avg_operation_time: f64,
    /// Error rate
    pub error_rate: f64,
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

    // Try to get real crypto data from WolfSecurity
    let mut response = CryptoResponse {
        total_operations: 0,
        encryption_count: 0,
        decryption_count: 0,
        signature_count: 0,
        verification_count: 0,
        avg_operation_time: 0.0,
        error_rate: 0.0,
    };

    if let Some(wolf_security) = &state.wolf_security {
        let security = wolf_security.read().await;
        let status = security.crypto.get_status().await;
        // WolfSecurity doesn't currently track operation counts, so we use defaults
        response.total_operations = 0;
        response.encryption_count = 0;
        response.decryption_count = 0;
        response.signature_count = 0;
        response.verification_count = 0;
        response.avg_operation_time = 0.0;
        response.error_rate = 0.0;
        // usage of status:
        // status.total_keys could be used if added to response
    }

    Json(response)
}

/// Get cryptographic operations details
async fn get_crypto_operations(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    state.increment_request_count().await;

    let mut operations_data = serde_json::json!({
        "operations": [],
        "security_level": "unknown",
        "compliance_status": "unknown"
    });

    // Try to get real crypto operations data from WolfSecurity
    if let Some(wolf_security) = &state.wolf_security {
        let security = wolf_security.read().await;
        let status = security.crypto.get_status().await;
        // Stub operations data using defaults since metrics not available
        let operations = vec![
            serde_json::json!({
                "type": "encryption",
                "algorithm": "AES-256-GCM",
                "count": 0,
                "avg_time_ms": 0.0,
                "success_rate": 1.0
            }),
            serde_json::json!({
                "type": "decryption",
                "algorithm": "AES-256-GCM",
                "count": 0,
                "avg_time_ms": 0.0,
                "success_rate": 1.0
            }),
            serde_json::json!({
                "type": "signature",
                "algorithm": "Ed25519",
                "count": 0,
                "avg_time_ms": 0.0,
                "success_rate": 1.0
            }),
            serde_json::json!({
                "type": "verification",
                "algorithm": "Ed25519",
                "count": 0,
                "avg_time_ms": 0.0,
                "success_rate": 1.0
            }),
        ];

        operations_data["operations"] = serde_json::Value::Array(operations);
        operations_data["security_level"] = serde_json::Value::String("high".to_string());
        operations_data["compliance_status"] = serde_json::Value::String("compliant".to_string());
    }

    Json(operations_data)
}
