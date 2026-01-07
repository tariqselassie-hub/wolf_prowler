//! Enhanced Authentication Middleware
//!
//! Comprehensive authentication middleware with JWT, OAuth2/OIDC, MFA, and session management.
//! Uses wolf pack principles for secure authentication flows.

use axum::{
    extract::{Request, State},
    http::{header, HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::dashboard::state::AppState;
use wolfsec::security::advanced::iam::{
    AuthenticationManager, AuthenticationMethod, AuthenticationResult, ClientInfo, IAMConfig,
    JWTAuthenticationManager, JWTValidationResult, MFAManager, MFAmethod, RBACManager, RBACQuery,
    RBACQuery, SSOIntegrationManager, SessionManager, SessionValidationResult, UserStatus,
};

/// Authentication context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthContext {
    /// User ID
    pub user_id: Uuid,
    /// Username
    pub username: String,
    /// User roles
    pub roles: Vec<String>,
    /// User permissions
    pub permissions: Vec<String>,
    /// Authentication method
    pub auth_method: AuthenticationMethod,
    /// MFA verified
    pub mfa_verified: bool,
    /// Session ID
    pub session_id: Option<Uuid>,
    /// JWT token
    pub jwt_token: Option<String>,
    /// Client info
    pub client_info: ClientInfo,
    /// Risk score
    pub risk_score: u8,
}

/// Authentication error types
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Authentication required")]
    AuthenticationRequired,
    #[error("Invalid token")]
    InvalidToken,
    #[error("Session expired")]
    SessionExpired,
    #[error("MFA required")]
    MFARequired,
    #[error("Access denied")]
    AccessDenied,
    #[error("Internal server error")]
    InternalError,
}

/// Authentication middleware state
#[derive(Debug, Clone)]
pub struct AuthMiddlewareState {
    /// JWT authentication manager
    pub jwt_manager: Arc<JWTAuthenticationManager>,
    /// Session manager
    pub session_manager: Arc<SessionManager>,
    /// MFA manager
    pub mfa_manager: Arc<MFAManager>,
    /// RBAC manager
    pub rbac_manager: Arc<RBACManager>,
    /// SSO manager
    pub sso_manager: Arc<SSOIntegrationManager>,
    /// Configuration
    pub config: IAMConfig,
}

/// Authentication middleware
pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    mut request: Request,
    next: Next,
) -> Result<Response, AuthError> {
    debug!("🔐 Processing authentication middleware");

    // Extract client info from request
    let client_info = extract_client_info(&request.headers());

    // Try to authenticate using various methods
    let auth_result = authenticate_request(&state, &request, client_info).await?;

    // Validate permissions for the requested resource
    let resource = extract_resource_from_request(&request);
    let action = extract_action_from_request(&request);

    let rbac_query = RBACQuery {
        user_id: auth_result.user_id,
        resource_type: resource,
        action,
        resource_id: None,
        client_info: Some(client_info),
    };

    let access_decision = state
        .rbac_manager
        .check_access(rbac_query)
        .await
        .map_err(|e| {
            error!("RBAC check failed: {}", e);
            AuthError::InternalError
        })?;

    if access_decision.decision != wolfsec::security::advanced::iam::AccessDecisionType::Allow {
        return Err(AuthError::AccessDenied);
    }

    // Add authentication context to request extensions
    let auth_context = AuthContext {
        user_id: auth_result.user_id,
        username: auth_result.user_id.to_string(), // In production, this would be looked up
        roles: vec![],                             // Would be populated from user data
        permissions: access_decision
            .applied_permissions
            .iter()
            .map(|id| format!("permission_{}", id))
            .collect(),
        auth_method: auth_result.method,
        mfa_verified: auth_result.mfa_completed,
        session_id: auth_result.session_id,
        jwt_token: None, // Would be extracted from request
        client_info,
        risk_score: 0, // Would be calculated from session security
    };

    request.extensions_mut().insert(auth_context);

    info!(
        "✅ Authentication successful for user: {}",
        auth_result.user_id
    );
    Ok(next.run(request).await)
}

/// Authenticate request using various methods
async fn authenticate_request(
    state: &Arc<AppState>,
    request: &Request,
    client_info: ClientInfo,
) -> Result<AuthenticationResult, AuthError> {
    // Try JWT authentication first
    if let Some(jwt_token) = extract_jwt_from_request(request) {
        let jwt_result = state
            .jwt_manager
            .validate_token(&jwt_token)
            .await
            .map_err(|e| {
                error!("JWT validation failed: {}", e);
                AuthError::InvalidToken
            })?;

        if jwt_result.valid {
            if let Some(claims) = jwt_result.claims {
                // Check if MFA is required for this user/operation
                if claims.mfa_verified || !is_mfa_required(&claims) {
                    return Ok(AuthenticationResult {
                        id: Uuid::new_v4(),
                        user_id: Uuid::parse_str(&claims.sub)
                            .map_err(|_| AuthError::InvalidToken)?,
                        method: AuthenticationMethod::JWT,
                        success: true,
                        timestamp: chrono::Utc::now(),
                        ip_address: client_info.ip_address,
                        user_agent: client_info.user_agent,
                        mfa_required: false,
                        mfa_completed: claims.mfa_verified,
                        session_id: claims
                            .session_id
                            .map(|s| Uuid::parse_str(&s))
                            .transpose()
                            .map_err(|_| AuthError::InvalidToken)?,
                        error_message: None,
                    });
                } else {
                    return Err(AuthError::MFARequired);
                }
            }
        }
    }

    // Try session authentication
    if let Some(session_id) = extract_session_from_request(request) {
        let session_result = state
            .session_manager
            .validate_session(session_id)
            .await
            .map_err(|e| {
                error!("Session validation failed: {}", e);
                AuthError::SessionExpired
            })?;

        if session_result.valid {
            if let Some(user_id) = session_result.user_id {
                return Ok(AuthenticationResult {
                    id: Uuid::new_v4(),
                    user_id,
                    method: AuthenticationMethod::Session,
                    success: true,
                    timestamp: chrono::Utc::now(),
                    ip_address: client_info.ip_address,
                    user_agent: client_info.user_agent,
                    mfa_required: false,
                    mfa_completed: true, // Sessions assume MFA was completed
                    session_id: Some(session_id),
                    error_message: None,
                });
            }
        }
    }

    // Try API key authentication
    if let Some(api_key) = extract_api_key_from_request(request) {
        let api_result = state
            .auth_manager
            .lock()
            .await
            .validate_api_key(&api_key)
            .await
            .map_err(|e| {
                error!("API key validation failed: {}", e);
                AuthError::InvalidToken
            })?;

        if api_result.valid {
            if let Some(user_id) = api_result.user_id {
                return Ok(AuthenticationResult {
                    id: Uuid::new_v4(),
                    user_id,
                    method: AuthenticationMethod::APIKey,
                    success: true,
                    timestamp: chrono::Utc::now(),
                    ip_address: client_info.ip_address,
                    user_agent: client_info.user_agent,
                    mfa_required: false,
                    mfa_completed: true,
                    session_id: None,
                    error_message: None,
                });
            }
        }
    }

    Err(AuthError::AuthenticationRequired)
}

/// Extract client info from request headers
fn extract_client_info(headers: &HeaderMap) -> ClientInfo {
    ClientInfo {
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
        device_id: headers
            .get("X-Device-ID")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string()),
        location: headers
            .get("X-Location")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string()),
    }
}

/// Extract JWT token from request
fn extract_jwt_from_request(request: &Request) -> Option<String> {
    request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|auth_header| auth_header.to_str().ok())
        .and_then(|auth_str| {
            if auth_str.starts_with("Bearer ") {
                Some(auth_str[7..].to_string())
            } else {
                None
            }
        })
}

/// Extract session ID from request
fn extract_session_from_request(request: &Request) -> Option<Uuid> {
    request
        .headers()
        .get("X-Session-ID")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| Uuid::parse_str(s).ok())
}

/// Extract API key from request
fn extract_api_key_from_request(request: &Request) -> Option<String> {
    request
        .headers()
        .get("X-API-Key")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
}

/// Extract resource type from request
fn extract_resource_from_request(
    request: &Request,
) -> wolfsec::security::advanced::iam::ResourceType {
    let path = request.uri().path();

    if path.starts_with("/api/v1/dashboard") {
        wolfsec::security::advanced::iam::ResourceType::Dashboard
    } else if path.starts_with("/api/v1/network") {
        wolfsec::security::advanced::iam::ResourceType::Network
    } else if path.starts_with("/api/v1/security") {
        wolfsec::security::advanced::iam::ResourceType::Security
    } else if path.starts_with("/api/v1/system") {
        wolfsec::security::advanced::iam::ResourceType::System
    } else if path.starts_with("/api/v1/users") {
        wolfsec::security::advanced::iam::ResourceType::UserManagement
    } else if path.starts_with("/api/v1/audit") {
        wolfsec::security::advanced::iam::ResourceType::Audit
    } else {
        wolfsec::security::advanced::iam::ResourceType::Custom("unknown".to_string())
    }
}

/// Extract action from request method
fn extract_action_from_request(
    request: &Request,
) -> wolfsec::security::advanced::iam::ResourceAction {
    match request.method().as_str() {
        "GET" => wolfsec::security::advanced::iam::ResourceAction::Read,
        "POST" => wolfsec::security::advanced::iam::ResourceAction::Write,
        "PUT" | "PATCH" => wolfsec::security::advanced::iam::ResourceAction::Write,
        "DELETE" => wolfsec::security::advanced::iam::ResourceAction::Delete,
        "ADMIN" => wolfsec::security::advanced::iam::ResourceAction::Admin,
        _ => wolfsec::security::advanced::iam::ResourceAction::Custom("unknown".to_string()),
    }
}

/// Check if MFA is required for the user/operation
fn is_mfa_required(claims: &wolfsec::security::advanced::iam::JWTCustomClaims) -> bool {
    // In production, this would check user roles, operation sensitivity, etc.
    claims.roles.iter().any(|role| role.contains("admin"))
        || claims.permissions.iter().any(|perm| perm.contains("admin"))
}

/// Authentication response for error cases
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthErrorResponse {
    /// Error message
    pub error: String,
    /// Error code
    pub code: String,
    /// Documentation URL
    pub documentation_url: Option<String>,
}

/// Create authentication error response
pub fn create_auth_error_response(error: AuthError) -> (StatusCode, Json<AuthErrorResponse>) {
    let (status, error_msg, error_code) = match error {
        AuthError::AuthenticationRequired => (
            StatusCode::UNAUTHORIZED,
            "Authentication required",
            "AUTH_REQUIRED",
        ),
        AuthError::InvalidToken => (
            StatusCode::UNAUTHORIZED,
            "Invalid or expired token",
            "INVALID_TOKEN",
        ),
        AuthError::SessionExpired => (
            StatusCode::UNAUTHORIZED,
            "Session has expired",
            "SESSION_EXPIRED",
        ),
        AuthError::MFARequired => (
            StatusCode::UNAUTHORIZED,
            "Multi-factor authentication required",
            "MFA_REQUIRED",
        ),
        AuthError::AccessDenied => (StatusCode::FORBIDDEN, "Access denied", "ACCESS_DENIED"),
        AuthError::InternalError => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal server error",
            "INTERNAL_ERROR",
        ),
    };

    let response = AuthErrorResponse {
        error: error_msg.to_string(),
        code: error_code.to_string(),
        documentation_url: Some("https://wolf-prowler.com/docs/authentication".to_string()),
    };

    (status, Json(response))
}

/// Authentication middleware builder
pub struct AuthMiddlewareBuilder {
    /// JWT manager
    jwt_manager: Option<Arc<JWTAuthenticationManager>>,
    /// Session manager
    session_manager: Option<Arc<SessionManager>>,
    /// MFA manager
    mfa_manager: Option<Arc<MFAManager>>,
    /// RBAC manager
    rbac_manager: Option<Arc<RBACManager>>,
    /// SSO manager
    sso_manager: Option<Arc<SSOIntegrationManager>>,
    /// Configuration
    config: Option<IAMConfig>,
}

impl AuthMiddlewareBuilder {
    /// Create new builder
    pub fn new() -> Self {
        Self {
            jwt_manager: None,
            session_manager: None,
            mfa_manager: None,
            rbac_manager: None,
            sso_manager: None,
            config: None,
        }
    }

    /// Set JWT manager
    pub fn with_jwt_manager(mut self, manager: Arc<JWTAuthenticationManager>) -> Self {
        self.jwt_manager = Some(manager);
        self
    }

    /// Set session manager
    pub fn with_session_manager(mut self, manager: Arc<SessionManager>) -> Self {
        self.session_manager = Some(manager);
        self
    }

    /// Set MFA manager
    pub fn with_mfa_manager(mut self, manager: Arc<MFAManager>) -> Self {
        self.mfa_manager = Some(manager);
        self
    }

    /// Set RBAC manager
    pub fn with_rbac_manager(mut self, manager: Arc<RBACManager>) -> Self {
        self.rbac_manager = Some(manager);
        self
    }

    /// Set SSO manager
    pub fn with_sso_manager(mut self, manager: Arc<SSOIntegrationManager>) -> Self {
        self.sso_manager = Some(manager);
        self
    }

    /// Set configuration
    pub fn with_config(mut self, config: IAMConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// Build authentication middleware state
    pub fn build(self) -> Result<AuthMiddlewareState, &'static str> {
        let jwt_manager = self.jwt_manager.ok_or("JWT manager required")?;
        let session_manager = self.session_manager.ok_or("Session manager required")?;
        let mfa_manager = self.mfa_manager.ok_or("MFA manager required")?;
        let rbac_manager = self.rbac_manager.ok_or("RBAC manager required")?;
        let sso_manager = self.sso_manager.ok_or("SSO manager required")?;
        let config = self.config.ok_or("Configuration required")?;

        Ok(AuthMiddlewareState {
            jwt_manager,
            session_manager,
            mfa_manager,
            rbac_manager,
            sso_manager,
            config,
        })
    }
}
