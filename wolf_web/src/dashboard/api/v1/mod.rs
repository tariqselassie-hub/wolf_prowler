//! Dashboard API v1 Module
//!
//! This module provides version 1 of the dashboard API endpoints.

use axum::{routing::get, Router};
use std::sync::Arc;

use crate::dashboard::state::AppState;

/// API status endpoint
async fn api_status() -> String {
    "Dashboard API v1 is operational".to_string()
}

pub mod auth;
pub mod behavioral;
pub mod compliance;
pub mod containers;
pub mod crypto;
pub mod intelligence;
pub mod metrics;
pub mod network;
pub mod peers;
pub mod security;
pub mod soar;
pub mod system;
pub mod threats;

/// Create the v1 API router
pub fn create_v1_router(state: Arc<AppState>) -> Router {
    Router::new()
        .nest("/auth", auth::create_router(state.clone()))
        .nest("/behavioral", behavioral::create_router(state.clone()))
        .nest("/compliance", compliance::create_router(state.clone()))
        .nest("/crypto", crypto::create_router(state.clone()))
        .nest("/intelligence", intelligence::create_router(state.clone()))
        .nest("/network", network::create_router(state.clone()))
        .nest("/peers", peers::create_router(state.clone()))
        .nest("/system", system::create_router(state.clone()))
        .nest("/threats", threats::create_router(state.clone()))
        .nest("/security", security::create_router(state.clone()))
        .nest("/soar", soar::create_router(state.clone()))
        .nest("/containers", containers::create_router(state.clone()))
        .nest("/metrics", metrics::create_router(state))
        .route("/status", get(api_status))
}
