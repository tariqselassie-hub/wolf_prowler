use crate::dashboard::AppState;
use axum::{extract::State, Json};
use std::sync::Arc;

pub async fn get_crypto_metrics(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    // Get crypto engine metrics
    let crypto_info = serde_json::json!({
        "algorithm": state.crypto.algorithm_name(),
        "public_key_length": state.crypto.signing_public_key().len(),
        "key_pair_status": "active",
        "encryption_enabled": true,
        "signing_enabled": true,
        "verification_enabled": true
    });
    
    Json(crypto_info)
}

pub async fn get_crypto_status(State(_state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let status = serde_json::json!({
        "crypto_engine": "operational",
        "key_management": "secure",
        "encryption_status": "available",
        "signature_status": "available"
    });
    
    Json(status)
}
