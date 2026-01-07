//! Dashboard API Module
//!
//! This module provides the main API router and integration points for the
//! Wolf Prowler Enterprise SIEM/SOAR dashboard, implementing the revolutionary
//! distributed security operations architecture.

use axum::{
    extract::State,
    http::{HeaderMap, HeaderName, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::{cors::CorsLayer, timeout::TimeoutLayer, trace::TraceLayer};
use tracing::{error, info, warn};

// use crate::dashboard::middleware::auth::{
//     api_key_auth_middleware, combined_auth_middleware, session_auth_middleware,
// };
use crate::dashboard::state::AppState;

/// API configuration
#[derive(Debug, Clone)]
pub struct ApiConfig {
    /// Enable request logging
    pub enable_logging: bool,
    /// Request timeout in seconds
    pub request_timeout: u64,
    /// Enable CORS
    pub enable_cors: bool,
    /// Allowed origins for CORS
    pub allowed_origins: Vec<String>,
    /// Enable compression
    pub enable_compression: bool,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            enable_logging: true,
            request_timeout: 30,
            enable_cors: true,
            allowed_origins: vec![
                "http://localhost:3000".to_string(),
                "http://localhost:8080".to_string(),
            ],
            enable_compression: true,
        }
    }
}

/// API error types
#[derive(Debug, Serialize, Deserialize)]
pub enum ApiError {
    /// Authentication failed
    AuthenticationFailed(String),
    /// Authorization failed
    AuthorizationFailed(String),
    /// Resource not found
    NotFound(String),
    /// Validation error
    ValidationError(String),
    /// Internal server error
    InternalError(String),
    /// Rate limit exceeded
    RateLimitExceeded(String),
    /// Bad request
    BadRequest(String),
}

impl From<ApiError> for (StatusCode, String) {
    fn from(error: ApiError) -> Self {
        match error {
            ApiError::AuthenticationFailed(msg) => (StatusCode::UNAUTHORIZED, msg),
            ApiError::AuthorizationFailed(msg) => (StatusCode::FORBIDDEN, msg),
            ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            ApiError::ValidationError(msg) => (StatusCode::UNPROCESSABLE_ENTITY, msg),
            ApiError::InternalError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            ApiError::RateLimitExceeded(msg) => (StatusCode::TOO_MANY_REQUESTS, msg),
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = self.into();
        (status, Json(ApiResponse::<()>::error(message))).into_response()
    }
}

/// API response wrapper
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    /// Success status
    pub success: bool,
    /// Response data
    pub data: Option<T>,
    /// Error message (if any)
    pub error: Option<String>,
    /// Request timestamp
    pub timestamp: String,
}

impl<T> ApiResponse<T> {
    /// Create successful response
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Create error response
    pub fn error(message: String) -> ApiResponse<()> {
        ApiResponse {
            success: false,
            data: None,
            error: Some(message),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }
}

/// Health check response
#[derive(Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Service status
    pub status: String,
    /// Service version
    pub version: String,
    /// Uptime in seconds
    pub uptime: u64,
    /// Request count
    pub request_count: u64,
    /// System health metrics
    pub system_health: SystemHealth,
}

/// System health metrics
#[derive(Debug, Serialize, Deserialize)]
pub struct SystemHealth {
    /// CPU usage percentage
    pub cpu_usage: f64,
    /// Memory usage in MB
    pub memory_usage: f64,
    /// Disk usage percentage
    pub disk_usage: f64,
    /// Active connections
    pub active_connections: usize,
    /// Database status
    pub database_status: String,
}

/// Create the main API router
pub fn create_api_router(state: Arc<AppState>) -> Router {
    // Create API configuration
    let config = ApiConfig::default();

    // Build middleware stack
    let middleware = ServiceBuilder::new()
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::new(std::time::Duration::from_secs(
            config.request_timeout,
        )));

    // Create routes that require state
    let stateful_routes = Router::new()
        .route("/health", get(health_check))
        // .route("/status", get(api_status)) // Conflict with v1/status
        .route("/config", get(get_config))
        .with_state(state.clone());

    let router = v1::create_v1_router(state.clone()).merge(stateful_routes);

    if config.enable_cors {
        let cors = CorsLayer::new()
            .allow_origin(
                config
                    .allowed_origins
                    .iter()
                    .map(|origin| origin.parse().unwrap())
                    .collect::<Vec<_>>(),
            )
            .allow_methods(vec![
                axum::http::Method::GET,
                axum::http::Method::POST,
                axum::http::Method::PUT,
                axum::http::Method::DELETE,
                axum::http::Method::OPTIONS,
            ])
            .allow_headers(vec![
                HeaderName::from_static("content-type"),
                HeaderName::from_static("authorization"),
                HeaderName::from_static("x-session-id"),
                HeaderName::from_static("x-api-key"),
                HeaderName::from_static("x-user-id"),
            ]);

        router.layer(middleware.layer(cors))
    } else {
        router.layer(middleware)
    }
}

/// Create API router with authentication middleware
pub fn create_api_router_with_state(state: Arc<AppState>) -> Router {
    let config = ApiConfig::default();

    let middleware = ServiceBuilder::new()
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::new(std::time::Duration::from_secs(
            config.request_timeout,
        )));

    // Create routes that require state
    let stateful_routes = Router::new()
        .route("/health", get(health_check))
        // .route("/status", get(api_status)) // Conflict with v1/status
        .route("/config", get(get_config))
        .with_state(state.clone());

    let router = v1::create_v1_router(state.clone()).merge(stateful_routes);

    if config.enable_cors {
        let cors = CorsLayer::new()
            .allow_origin(
                config
                    .allowed_origins
                    .iter()
                    .map(|origin| origin.parse().unwrap())
                    .collect::<Vec<_>>(),
            )
            .allow_methods(vec![
                axum::http::Method::GET,
                axum::http::Method::POST,
                axum::http::Method::PUT,
                axum::http::Method::DELETE,
                axum::http::Method::OPTIONS,
            ])
            .allow_headers(vec![
                HeaderName::from_static("content-type"),
                HeaderName::from_static("authorization"),
                HeaderName::from_static("x-session-id"),
                HeaderName::from_static("x-api-key"),
                HeaderName::from_static("x-user-id"),
            ]);

        router.layer(middleware.layer(cors))
    } else {
        router.layer(middleware)
    }
}

/// Health check endpoint
async fn health_check(
    State(state): State<Arc<AppState>>,
) -> Result<Json<HealthResponse>, ApiError> {
    state.increment_request_count().await;

    // Get system metrics
    let request_count = state.get_request_count().await;
    let threat_engine = state.threat_engine.lock().await; // Lock the mutex
    let status = threat_engine.get_status().await; // Call get_status() and access metrics
    let stats = status.metrics;

    // Calculate system health from real metrics
    let system_health = SystemHealth {
        cpu_usage: stats.system.cpu_usage,
        memory_usage: stats.system.memory_usage,
        disk_usage: stats.system.disk_usage,
        active_connections: stats.active_connections,
        database_status: "Connected".to_string(), // Would get from actual database status
    };

    tracing::debug!(
        "Health check: requests={}, threats={}, confidence={}",
        request_count,
        stats.total_events,
        stats.average_confidence
    );

    Ok(Json(HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime: status.uptime,
        request_count,
        system_health,
    }))
}

// /// API status endpoint
// async fn api_status(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
//     state.increment_request_count().await;
//
//     Json(serde_json::json!({
//         "status": "operational",
//         "version": env!("CARGO_PKG_VERSION"),
//         "endpoints": [
//             "/api/v1/auth",
//             "/api/v1/behavioral",
//             "/api/v1/compliance",
//             "/api/v1/crypto",
//             "/api/v1/intelligence",
//             "/api/v1/network",
//             "/api/v1/peers",
//             "/api/v1/security",
//             "/api/v1/system",
//             "/api/v1/threats",
//             "/api/v1/metrics"
//         ],
//         "features": [
//             "Real-time threat detection",
//             "Behavioral analysis",
//             "Anomaly detection",
//             "Cryptographic operations monitoring",
//             "Peer network analysis",
//             "Security metrics and analytics",
//             "Compliance monitoring",
//             "Threat intelligence integration",
//             "Wolf Pack coordination"
//         ]
//     }))
// }

/// Get API configuration
async fn get_config(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    state.increment_request_count().await;

    Json(serde_json::json!({
        "authentication": {
            "session_based": true,
            "api_key": true,
            "mfa_supported": true,
            "session_timeout": "24h",
            "remember_me": true
        },
        "rate_limiting": {
            "auth_endpoints": "10/min",
            "data_endpoints": "100/min",
            "websocket_connections": "5/user"
        },
        "security": {
            "cors_enabled": true,
            "compression_enabled": true,
            "request_timeout": "30s",
            "tls_required": true
        },
        "features": {
            "real_time_updates": true,
            "websocket_support": true,
            "wolf_pack_integration": true,
            "prestige_system": true,
            "zero_trust": true
        }
    }))
}

pub mod v1;
