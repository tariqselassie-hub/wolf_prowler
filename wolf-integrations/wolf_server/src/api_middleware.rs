//! API Middleware and Utilities for Wolf Prowler
//!
//! This module provides common middleware, utilities, and helpers
//! for building robust, secure, and well-documented APIs.

use axum::{
    extract::Request,
    http::{header, Method, StatusCode},
    middleware::Next,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use tower_http::cors::{Any, CorsLayer};
use tracing::{debug, error, warn};

/// Standard API response wrapper
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<ApiError>,
    pub meta: ResponseMeta,
}

/// Standard error response
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiError {
    pub code: String,
    pub message: String,
    pub details: Option<serde_json::Value>,
}

/// Response metadata
#[derive(Debug, Serialize, Deserialize)]
pub struct ResponseMeta {
    pub timestamp: String,
    pub request_id: String,
    pub version: String,
    pub processing_time_ms: Option<u64>,
}

/// Pagination information
#[derive(Debug, Serialize, Deserialize)]
pub struct PaginationMeta {
    pub page: u32,
    pub limit: u32,
    pub total: u64,
    pub total_pages: u32,
    pub has_next: bool,
    pub has_prev: bool,
}

/// Paginated response wrapper
#[derive(Debug, Serialize, Deserialize)]
pub struct PaginatedResponse<T> {
    pub success: bool,
    pub data: Vec<T>,
    pub pagination: PaginationMeta,
    pub meta: ResponseMeta,
}

/// Request logging middleware
pub async fn request_logger(
    req: Request,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let start = Instant::now();
    let method = req.method().clone();
    let uri = req.uri().clone();
    let version = req.version();

    debug!("→ {} {} {:?}", method, uri, version);

    let response = next.run(req).await;
    let duration = start.elapsed();

    let status = response.status();
    if status.is_success() {
        debug!("← {} {} {} in {:?}", method, uri, status, duration);
    } else if status.is_client_error() {
        warn!("← {} {} {} in {:?}", method, uri, status, duration);
    } else {
        error!("← {} {} {} in {:?}", method, uri, status, duration);
    };

    Ok(response)
}

/// Security headers middleware
pub async fn security_headers(
    req: Request,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let mut response = next.run(req).await;

    let headers = response.headers_mut();
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    headers.insert(header::X_FRAME_OPTIONS, "DENY".parse().unwrap());
    headers.insert(header::X_XSS_PROTECTION, "1; mode=block".parse().unwrap());
    headers.insert(
        header::STRICT_TRANSPORT_SECURITY,
        "max-age=31536000".parse().unwrap(),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        "default-src 'self'".parse().unwrap(),
    );

    Ok(response)
}

/// CORS configuration for API
pub fn create_cors_layer() -> CorsLayer {
    CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::PATCH,
        ])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::ACCEPT,
            "x-api-key".parse().unwrap(),
            "x-request-id".parse().unwrap(),
        ])
        .max_age(Duration::from_secs(86400)) // 24 hours
}

/// Rate limiting state (simplified in-memory version)
#[derive(Debug)]
pub struct RateLimiter {
    requests: std::sync::Mutex<std::collections::HashMap<String, Vec<Instant>>>,
    max_requests: u32,
    window: Duration,
}

impl RateLimiter {
    pub fn new(max_requests: u32, window: Duration) -> Self {
        Self {
            requests: std::sync::Mutex::new(std::collections::HashMap::new()),
            max_requests,
            window,
        }
    }

    pub fn check(&self, key: &str) -> bool {
        let mut requests = self.requests.lock().unwrap();
        let now = Instant::now();

        let user_requests = requests.entry(key.to_string()).or_insert_with(Vec::new);

        // Remove old requests outside the window
        user_requests.retain(|&time| now.duration_since(time) < self.window);

        // Check if under limit
        if user_requests.len() >= self.max_requests as usize {
            return false;
        }

        // Add current request
        user_requests.push(now);
        true
    }
}

/// Rate limiting middleware
pub async fn rate_limit(
    req: Request,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    // Simple IP-based rate limiting (in production, use a proper rate limiter)
    let client_ip = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown");

    // This is a simplified example - in production, use a proper rate limiter
    // For now, we'll just log and continue
    debug!("Rate limit check for IP: {}", client_ip);

    Ok(next.run(req).await)
}

/// Authentication middleware
pub async fn authenticate(
    req: Request,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    // Check for API key in header
    let api_key = req
        .headers()
        .get("x-api-key")
        .or_else(|| req.headers().get(header::AUTHORIZATION))
        .and_then(|v| v.to_str().ok());

    match api_key {
        Some(key) => {
            // In production, validate the API key against a database/cache
            if validate_api_key(key).await {
                Ok(next.run(req).await)
            } else {
                Err((StatusCode::UNAUTHORIZED, "Invalid API key".to_string()))
            }
        }
        None => Err((StatusCode::UNAUTHORIZED, "API key required".to_string())),
    }
}

/// Validate API key (placeholder implementation)
async fn validate_api_key(_key: &str) -> bool {
    // Basic validation: check if key is non-empty and has a minimum length
    // In production, this would query a database or cache
    !_key.is_empty() && _key.len() >= 16
}

/// Request ID middleware
pub async fn request_id(
    mut req: Request,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let request_id = uuid::Uuid::new_v4().to_string();

    // Add request ID to request extensions
    req.extensions_mut().insert(request_id.clone());

    let mut response = next.run(req).await;

    // Add request ID to response headers
    response
        .headers_mut()
        .insert("x-request-id", request_id.parse().unwrap());

    Ok(response)
}

/// Utility functions for creating standardized responses

pub fn success_response<T: Serialize>(data: T, request_id: String) -> ApiResponse<T> {
    ApiResponse {
        success: true,
        data: Some(data),
        error: None,
        meta: ResponseMeta {
            timestamp: chrono::Utc::now().to_rfc3339(),
            request_id,
            version: "v1".to_string(),
            processing_time_ms: None,
        },
    }
}

pub fn error_response(code: &str, message: &str, request_id: String) -> ApiResponse<()> {
    ApiResponse {
        success: false,
        data: None,
        error: Some(ApiError {
            code: code.to_string(),
            message: message.to_string(),
            details: None,
        }),
        meta: ResponseMeta {
            timestamp: chrono::Utc::now().to_rfc3339(),
            request_id,
            version: "v1".to_string(),
            processing_time_ms: None,
        },
    }
}

pub fn paginated_response<T: Serialize>(
    data: Vec<T>,
    page: u32,
    limit: u32,
    total: u64,
    request_id: String,
) -> PaginatedResponse<T> {
    let total_pages = ((total as f64) / (limit as f64)).ceil() as u32;

    PaginatedResponse {
        success: true,
        data,
        pagination: PaginationMeta {
            page,
            limit,
            total,
            total_pages,
            has_next: page < total_pages,
            has_prev: page > 1,
        },
        meta: ResponseMeta {
            timestamp: chrono::Utc::now().to_rfc3339(),
            request_id,
            version: "v1".to_string(),
            processing_time_ms: None,
        },
    }
}

pub fn validate_id(id: &str) -> Result<(), String> {
    if id.is_empty() {
        return Err("ID cannot be empty".to_string());
    }

    if id.len() > 100 {
        return Err("ID too long".to_string());
    }

    // Basic alphanumeric check
    if !id
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return Err("ID contains invalid characters".to_string());
    }

    Ok(())
}

/// Common query parameters
#[derive(Debug, Deserialize)]
pub struct PaginationQuery {
    #[serde(default = "default_page")]
    pub page: u32,
    #[serde(default = "default_limit")]
    pub limit: u32,
}

fn default_page() -> u32 {
    1
}

fn default_limit() -> u32 {
    50
}

#[derive(Debug, Deserialize)]
pub struct FilterQuery {
    pub status: Option<String>,
    pub severity: Option<String>,
    pub from_date: Option<String>,
    pub to_date: Option<String>,
}

/// Health check response
#[derive(Debug, Serialize)]
pub struct HealthStatus {
    pub status: String,
    pub version: String,
    pub uptime: u64,
    pub services: std::collections::HashMap<String, String>,
}

impl Default for HealthStatus {
    fn default() -> Self {
        Self {
            status: "healthy".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime: 0, // Would be calculated from start time
            services: std::collections::HashMap::new(),
        }
    }
}
