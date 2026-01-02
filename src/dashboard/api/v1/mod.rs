// FILE: src/dashboard/api/v1/mod.rs
// API v1 endpoints implementation.

use axum::{
    routing::get,
    Router,
};
use std::sync::Arc;

use crate::dashboard::AppState;

mod behavioral;
mod crypto;
mod health;
mod metrics;
mod peers;
mod security;
mod threats;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/metrics", get(metrics::get_metrics))
        .route("/api/peers", get(peers::get_peers))
        .route("/api/security/metrics", get(security::get_security_metrics))
        .route("/api/crypto/metrics", get(crypto::get_crypto_metrics))
        .route("/api/crypto/status", get(crypto::get_crypto_status))
        .route("/api/behavioral/metrics", get(behavioral::get_behavioral_metrics))
        .route("/api/behavioral/peer/:peer_id", get(behavioral::get_peer_behavior))
        .route("/api/threats/intelligence", get(threats::get_threat_intelligence))
        .route("/api/threats/active", get(threats::get_active_threats))
        .route("/api/health", get(health::health_ok))
}
