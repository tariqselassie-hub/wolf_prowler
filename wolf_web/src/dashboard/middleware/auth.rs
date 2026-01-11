//! Authentication Middleware
//!
//! This module provides authentication middleware for protecting API endpoints.

use axum::{
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;
use uuid::Uuid;

use crate::dashboard::state::AppState;
use wolfsec::security::advanced::iam::{ApiKeyValidationResult, SessionValidationResult};

/// Authentication middleware for session-based authentication
pub async fn session_auth_middleware(
    headers: HeaderMap,
    State(state): axum::extract::State<Arc<AppState>>,
    request: Request<Body>,
    next: Next,
) -> Result<Response<Body>, (StatusCode, String)> {
    // Extract session ID from headers
    let session_id = match headers.get("X-Session-ID") {
        Some(header) => match header.to_str() {
            Ok(id) => match Uuid::parse_str(id) {
                Ok(uuid) => uuid,
                Err(_) => {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        "Invalid session ID format".to_string(),
                    ))
                }
            },
            Err(_) => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "Invalid session ID header".to_string(),
                ))
            }
        },
        None => return Err((StatusCode::UNAUTHORIZED, "Session ID required".to_string())),
    };

    let auth_manager = state.auth_manager.lock().await;
    let validation_result: SessionValidationResult = auth_manager
        .validate_session(session_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Session validation failed: {}", e),
            )
        })?;

    if !validation_result.valid {
        return Err((
            StatusCode::UNAUTHORIZED,
            validation_result
                .error_message
                .unwrap_or_else(|| "Invalid session".to_string()),
        ));
    }

    // Add user ID to headers for downstream handlers
    let mut headers = headers.clone();
    if let Some(user_id) = validation_result.user_id {
        headers.insert(
            "X-User-ID",
            HeaderValue::from_str(&user_id.to_string()).map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to set user ID header".to_string(),
                )
            })?,
        );
    }

    // Continue to the next handler
    Ok(next.run(request).await)
}

/// Authentication middleware for API key authentication
pub async fn api_key_auth_middleware(
    headers: HeaderMap,
    State(state): axum::extract::State<Arc<AppState>>,
    request: Request<Body>,
    next: Next,
) -> Result<Response<Body>, (StatusCode, String)> {
    // Extract API key from headers
    let api_key = match headers.get("X-API-Key") {
        Some(header) => match header.to_str() {
            Ok(key) => key,
            Err(_) => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "Invalid API key header".to_string(),
                ))
            }
        },
        None => return Err((StatusCode::UNAUTHORIZED, "API key required".to_string())),
    };

    let auth_manager = state.auth_manager.lock().await;
    let validation_result: ApiKeyValidationResult =
        auth_manager.validate_api_key(api_key).await.map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("API key validation failed: {}", e),
            )
        })?;

    if !validation_result.valid {
        return Err((
            StatusCode::UNAUTHORIZED,
            validation_result
                .error_message
                .unwrap_or_else(|| "Invalid API key".to_string()),
        ));
    }

    // Add user ID and key ID to headers for downstream handlers
    let mut headers = headers.clone();
    if let Some(user_id) = validation_result.user_id {
        headers.insert(
            "X-User-ID",
            HeaderValue::from_str(&user_id.to_string()).map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to set user ID header".to_string(),
                )
            })?,
        );
    }
    if let Some(key_id) = validation_result.key_id {
        headers.insert(
            "X-Key-ID",
            HeaderValue::from_str(&key_id.to_string()).map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to set key ID header".to_string(),
                )
            })?,
        );
    }

    // Continue to the next handler
    Ok(next.run(request).await)
}

/// Combined authentication middleware that supports both session and API key auth
pub async fn combined_auth_middleware(
    headers: HeaderMap,
    State(state): axum::extract::State<Arc<AppState>>,
    request: Request<Body>,
    next: Next,
) -> Result<Response<Body>, (StatusCode, String)> {
    // Try session authentication first
    if let Some(session_id) = headers
        .get("X-Session-ID")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| Uuid::parse_str(s).ok())
    {
        let auth_manager = state.auth_manager.lock().await;
        let validation_result: SessionValidationResult = auth_manager
            .validate_session(session_id)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Session validation failed: {}", e),
                )
            })?;

        if validation_result.valid {
            // Add user ID to headers
            let mut headers = headers.clone();
            if let Some(user_id) = validation_result.user_id {
                headers.insert(
                    "X-User-ID",
                    HeaderValue::from_str(&user_id.to_string()).map_err(|_| {
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Failed to set user ID header".to_string(),
                        )
                    })?,
                );
            }
            return Ok(next.run(request).await);
        }
    }

    // Try API key authentication
    if let Some(api_key) = headers.get("X-API-Key").and_then(|h| h.to_str().ok()) {
        let auth_manager = state.auth_manager.lock().await;
        let validation_result: ApiKeyValidationResult =
            auth_manager.validate_api_key(api_key).await.map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("API key validation failed: {}", e),
                )
            })?;

        if validation_result.valid {
            // Add user ID and key ID to headers
            let mut headers = headers.clone();
            if let Some(user_id) = validation_result.user_id {
                headers.insert(
                    "X-User-ID",
                    HeaderValue::from_str(&user_id.to_string()).map_err(|_| {
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Failed to set user ID header".to_string(),
                        )
                    })?,
                );
            }
            if let Some(key_id) = validation_result.key_id {
                headers.insert(
                    "X-Key-ID",
                    HeaderValue::from_str(&key_id.to_string()).map_err(|_| {
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Failed to set key ID header".to_string(),
                        )
                    })?,
                );
            }
            return Ok(next.run(request).await);
        }
    }

    // Neither authentication method worked
    Err((
        StatusCode::UNAUTHORIZED,
        "Authentication required".to_string(),
    ))
}
