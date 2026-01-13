//! Authentication API Endpoints
//!
//! This module provides API endpoints for authentication and session management.

use axum::{
    extract::State,
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::dashboard::api::ApiError;
use crate::dashboard::state::AppState;
use wolfsec::identity::iam::{
    AuthenticationRequest, AuthenticationResult, ClientInfo, SessionRequest,
    SessionValidationResult,
};

/// Authentication response
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthResponse {
    /// Authentication success
    pub success: bool,
    /// User ID
    pub user_id: Option<Uuid>,
    /// Session ID
    pub session_id: Option<Uuid>,
    /// Authentication token (for session-based auth)
    pub token: Option<String>,
    /// Error message
    pub error: Option<String>,
    /// MFA required
    pub mfa_required: bool,
}

/// Session validation response
#[derive(Debug, Serialize, Deserialize)]
pub struct SessionValidationResponse {
    /// Session valid
    pub valid: bool,
    /// User ID
    pub user_id: Option<Uuid>,
    /// Session expires at
    pub expires_at: Option<String>,
    /// Error message
    pub error: Option<String>,
}

/// Login request
#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    /// Username
    pub username: String,
    /// Password
    pub password: String,
    /// Remember me (longer session)
    pub remember_me: Option<bool>,
}

/// Create authentication router
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/login", post(login_handler))
        .route("/logout", post(logout_handler))
        .route("/validate-session", get(validate_session_handler))
        .route("/validate-api-key", get(validate_api_key_handler))
        .route("/status", get(get_auth_status_handler))
        .with_state(state)
}

/// Login handler
async fn login_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, ApiError> {
    // Validate input
    if request.username.is_empty() || request.password.is_empty() {
        return Err(ApiError::ValidationError(
            "Username and password are required".to_string(),
        ));
    }

    let auth_manager = state.auth_manager.lock().await;

    // Create authentication request with real client info
    let auth_request = AuthenticationRequest {
        username: request.username,
        password: Some(request.password),
        mfa_token: None,
        identity_provider: None,
        client_info: ClientInfo {
            ip_address: headers
                .get("X-Real-IP")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("127.0.0.1")
                .to_string(),
            user_agent: headers
                .get("User-Agent")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("Unknown")
                .to_string(),
            device_id: None,
            location: None,
        },
    };

    // Authenticate user
    let auth_result: AuthenticationResult = auth_manager
        .authenticate(auth_request)
        .await
        .map_err(|e| ApiError::InternalError(format!("Authentication failed: {}", e)))?;

    if !auth_result.success {
        return Ok(Json(AuthResponse {
            success: false,
            user_id: Some(auth_result.user_id),
            session_id: None,
            token: None,
            error: auth_result.error_message,
            mfa_required: auth_result.mfa_required,
        }));
    }

    // Create session with real client info
    let session_request = SessionRequest {
        ip_address: headers
            .get("X-Real-IP")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("127.0.0.1")
            .to_string(),
        user_agent: headers
            .get("User-Agent")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("Unknown")
            .to_string(),
        remember_me: request.remember_me.unwrap_or(false),
    };

    let session = auth_manager
        .create_session(auth_result.user_id, session_request)
        .await
        .map_err(|e| ApiError::InternalError(format!("Session creation failed: {}", e)))?;

    tracing::info!("User {} logged in successfully", auth_result.user_id);

    Ok(Json(AuthResponse {
        success: true,
        user_id: Some(auth_result.user_id),
        session_id: Some(session.id),
        token: Some(session.id.to_string()), // Using session ID as token for simplicity
        error: None,
        mfa_required: auth_result.mfa_required,
    }))
}

/// Logout handler
async fn logout_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Extract session ID from headers
    let session_id = match headers.get("X-Session-ID") {
        Some(header) => match header.to_str() {
            Ok(id) => match Uuid::parse_str(id) {
                Ok(uuid) => uuid,
                Err(_) => {
                    return Err(ApiError::ValidationError(
                        "Invalid session ID format".to_string(),
                    ))
                }
            },
            Err(_) => {
                return Err(ApiError::ValidationError(
                    "Invalid session ID header".to_string(),
                ))
            }
        },
        None => return Err(ApiError::ValidationError("Session ID required".to_string())),
    };

    let auth_manager = state.auth_manager.lock().await;
    auth_manager
        .terminate_session(session_id)
        .await
        .map_err(|e| ApiError::InternalError(format!("Logout failed: {}", e)))?;

    tracing::info!("Session {} terminated successfully", session_id);

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Logged out successfully"
    })))
}

/// Session validation handler
async fn validate_session_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<SessionValidationResponse>, ApiError> {
    // Extract session ID from headers
    let session_id = match headers.get("X-Session-ID") {
        Some(header) => match header.to_str() {
            Ok(id) => match Uuid::parse_str(id) {
                Ok(uuid) => uuid,
                Err(_) => {
                    return Err(ApiError::ValidationError(
                        "Invalid session ID format".to_string(),
                    ))
                }
            },
            Err(_) => {
                return Err(ApiError::ValidationError(
                    "Invalid session ID header".to_string(),
                ))
            }
        },
        None => return Err(ApiError::ValidationError("Session ID required".to_string())),
    };

    let auth_manager = state.auth_manager.lock().await;
    let validation_result: SessionValidationResult = auth_manager
        .validate_session(session_id)
        .await
        .map_err(|e| ApiError::InternalError(format!("Session validation failed: {}", e)))?;

    Ok(Json(SessionValidationResponse {
        valid: validation_result.valid,
        user_id: validation_result.user_id,
        expires_at: validation_result
            .expires_at
            .map(|dt: chrono::DateTime<chrono::Utc>| dt.to_rfc3339()),
        error: validation_result.error_message,
    }))
}

/// API key validation handler
async fn validate_api_key_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Extract API key from headers
    let api_key = match headers.get("X-API-Key") {
        Some(header) => match header.to_str() {
            Ok(key) => key,
            Err(_) => {
                return Err(ApiError::ValidationError(
                    "Invalid API key header".to_string(),
                ))
            }
        },
        None => return Err(ApiError::ValidationError("API key required".to_string())),
    };

    let auth_manager = state.auth_manager.lock().await;
    let validation_result: wolfsec::identity::iam::ApiKeyValidationResult = auth_manager
        .validate_api_key(api_key)
        .await
        .map_err(|e| ApiError::InternalError(format!("API key validation failed: {}", e)))?;

    if !validation_result.valid {
        return Err(ApiError::AuthenticationFailed(
            validation_result
                .error_message
                .unwrap_or_else(|| "Invalid API key".to_string()),
        ));
    }

    tracing::info!(
        "API key {} validated successfully",
        validation_result.key_id.unwrap_or_default()
    );

    Ok(Json(serde_json::json!({
        "valid": true,
        "user_id": validation_result.user_id,
        "key_id": validation_result.key_id,
        "permissions": validation_result.permissions,
        "message": "API key is valid"
    })))
}
/// Get authentication analytics and session counts
async fn get_auth_status_handler(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    state.increment_request_count().await;

    let mut auth_status = serde_json::json!({
        "active_sessions": 0,
        "total_users": 0,
        "auth_failures": 0,
        "mfa_usage": 0.0,
        "system_health": "good"
    });

    if let Some(wolf_security_arc) = state.get_wolf_security() {
        let security = wolf_security_arc.read().await;
        let status = security.get_status().await;
        let auth = &status.authentication;

        auth_status["active_sessions"] = serde_json::json!(auth.active_sessions);
        auth_status["total_users"] = serde_json::json!(auth.total_users);
        auth_status["auth_failures"] = serde_json::json!(auth.auth_failures);
    }

    Json(auth_status)
}
