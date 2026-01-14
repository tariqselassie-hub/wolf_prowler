//! Error types for TersecPot
//!
//! This module provides a centralized error type for all TersecPot operations.

use thiserror::Error;

/// Main error type for TersecPot operations
#[derive(Error, Debug)]
pub enum TersecError {
    /// Validation error (e.g., command too long, invalid characters)
    #[error("Validation error: {0}")]
    Validation(String),

    /// Cryptographic operation failed
    #[error("Cryptographic operation failed: {0}")]
    Crypto(String),

    /// Network or I/O error
    #[error("Network/IO error: {0}")]
    Network(#[from] std::io::Error),

    /// Storage or file system error
    #[error("Storage error: {0}")]
    Storage(String),

    /// Protocol error (e.g., invalid message format)
    #[error("Protocol error: {0}")]
    Protocol(String),

    /// Internal error (unexpected state)
    #[error("Internal error: {0}")]
    Internal(String),

    /// Serialization/deserialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Policy enforcement error
    #[error("Policy error: {0}")]
    Policy(String),

    /// Authentication/authorization error
    #[error("Authentication error: {0}")]
    Auth(String),
}

/// Result type alias for TersecPot operations
pub type Result<T> = std::result::Result<T, TersecError>;

// Implement From for common error types
impl From<serde_json::Error> for TersecError {
    fn from(err: serde_json::Error) -> Self {
        Self::Serialization(err.to_string())
    }
}

impl From<toml::de::Error> for TersecError {
    fn from(err: toml::de::Error) -> Self {
        Self::Serialization(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = TersecError::Validation("Command too long".to_string());
        assert_eq!(err.to_string(), "Validation error: Command too long");
    }

    #[test]
    fn test_io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "File not found");
        let tersec_err: TersecError = io_err.into();
        assert!(tersec_err.to_string().contains("File not found"));
    }
}
