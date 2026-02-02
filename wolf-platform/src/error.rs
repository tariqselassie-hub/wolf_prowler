//! Centralized Error Handling for Wolf Prowler
//!
//! This module provides a unified error type system for the entire application,
//! replacing panic-prone unwrap() calls with proper error propagation.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

/// Main error type for Wolf Prowler
#[derive(Debug, thiserror::Error)]
pub enum WolfError {
    /// Network-related errors (P2P, connections, etc.)
    #[error("Network error: {0}")]
    Network(String),

    /// Security violations and authentication failures
    #[error("Security violation: {0}")]
    Security(String),

    /// Configuration errors (invalid config, missing files, etc.)
    #[error("Configuration error: {0}")]
    Config(String),

    /// Database and persistence errors
    #[error("Database error: {0}")]
    Database(String),

    /// Cryptographic operation failures
    #[error("Cryptography error: {0}")]
    Crypto(String),

    /// API request validation failures
    #[error("Validation error: {0}")]
    Validation(String),

    /// External service failures (GeoIP, etc.)
    #[error("External service error: {0}")]
    ExternalService(String),

    /// Internal server errors
    #[error("Internal error: {0}")]
    Internal(String),

    /// Resource not found
    #[error("Not found: {0}")]
    NotFound(String),

    /// Operation timeout
    #[error("Timeout: {0}")]
    Timeout(String),
}

/// Result type alias for Wolf Prowler operations
pub type WolfResult<T> = Result<T, WolfError>;

impl WolfError {
    /// Get the HTTP status code for this error
    pub fn status_code(&self) -> StatusCode {
        match self {
            WolfError::Network(_) => StatusCode::SERVICE_UNAVAILABLE,
            WolfError::Security(_) => StatusCode::FORBIDDEN,
            WolfError::Config(_) => StatusCode::INTERNAL_SERVER_ERROR,
            WolfError::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
            WolfError::Crypto(_) => StatusCode::INTERNAL_SERVER_ERROR,
            WolfError::Validation(_) => StatusCode::BAD_REQUEST,
            WolfError::ExternalService(_) => StatusCode::BAD_GATEWAY,
            WolfError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            WolfError::NotFound(_) => StatusCode::NOT_FOUND,
            WolfError::Timeout(_) => StatusCode::GATEWAY_TIMEOUT,
        }
    }

    /// Get a user-friendly error message (without sensitive details)
    pub fn user_message(&self) -> String {
        match self {
            WolfError::Network(_) => "Network service temporarily unavailable".to_string(),
            WolfError::Security(_) => "Access denied".to_string(),
            WolfError::Config(_) => "System configuration error".to_string(),
            WolfError::Database(_) => "Database operation failed".to_string(),
            WolfError::Crypto(_) => "Cryptographic operation failed".to_string(),
            WolfError::Validation(msg) => format!("Invalid input: {}", msg),
            WolfError::ExternalService(_) => "External service unavailable".to_string(),
            WolfError::Internal(_) => "Internal server error".to_string(),
            WolfError::NotFound(msg) => format!("Not found: {}", msg),
            WolfError::Timeout(_) => "Request timeout".to_string(),
        }
    }

    /// Check if this error should be logged as critical
    pub fn is_critical(&self) -> bool {
        matches!(
            self,
            WolfError::Security(_) | WolfError::Crypto(_) | WolfError::Database(_)
        )
    }
}

/// Implement IntoResponse for Axum integration
impl IntoResponse for WolfError {
    fn into_response(self) -> Response {
        let status = self.status_code();

        // Log critical errors
        if self.is_critical() {
            tracing::error!("Critical error: {}", self);
        } else {
            tracing::warn!("Error: {}", self);
        }

        // Return JSON error response
        let body = Json(json!({
            "error": self.user_message(),
            "status": status.as_u16(),
        }));

        (status, body).into_response()
    }
}

/// Conversion from anyhow::Error
impl From<anyhow::Error> for WolfError {
    fn from(err: anyhow::Error) -> Self {
        WolfError::Internal(err.to_string())
    }
}

/// Conversion from std::io::Error
impl From<std::io::Error> for WolfError {
    fn from(err: std::io::Error) -> Self {
        WolfError::Internal(format!("IO error: {}", err))
    }
}

/// Conversion from serde_json::Error
impl From<serde_json::Error> for WolfError {
    fn from(err: serde_json::Error) -> Self {
        WolfError::Validation(format!("JSON error: {}", err))
    }
}

/// Conversion from tokio::time::error::Elapsed
impl From<tokio::time::error::Elapsed> for WolfError {
    fn from(err: tokio::time::error::Elapsed) -> Self {
        WolfError::Timeout(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_status_codes() {
        assert_eq!(
            WolfError::Network("test".to_string()).status_code(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            WolfError::Security("test".to_string()).status_code(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            WolfError::Validation("test".to_string()).status_code(),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn test_user_messages() {
        let err = WolfError::Security("internal details".to_string());
        assert_eq!(err.user_message(), "Access denied");

        let err = WolfError::Validation("bad input".to_string());
        assert!(err.user_message().contains("Invalid input"));
    }

    #[test]
    fn test_critical_errors() {
        assert!(WolfError::Security("test".to_string()).is_critical());
        assert!(WolfError::Crypto("test".to_string()).is_critical());
        assert!(!WolfError::Validation("test".to_string()).is_critical());
    }
}
