// /home/t4riq/Desktop/Rust/wolf_prowler/wolfsec/src/domain/error.rs
use thiserror::Error;

/// Represents errors that can occur within the domain layer.
/// These are specific business logic errors that the application layer can handle.
#[derive(Debug, Error)]
pub enum DomainError {
    #[error("Invalid input for field '{field}': {reason}")]
    InvalidInput { field: &'static str, reason: String },

    #[error("Entity '{entity_type}' with ID '{id}' not found.")]
    NotFound {
        entity_type: &'static str,
        id: String,
    },

    #[error("A cryptographic operation failed: {0}")]
    CryptoOperationFailed(String),

    #[error("A threat detection operation failed: {0}")]
    ThreatDetectionError(String),

    #[error("An unexpected error occurred: {0}")]
    Unexpected(String),
}

// TEMPORARILY DISABLED - Migrating to WolfDb
// impl From<sqlx::Error> for DomainError {
//     fn from(e: sqlx::Error) -> Self {
//         DomainError::Unexpected(e.to_string())
//     }
// }

impl From<serde_json::Error> for DomainError {
    fn from(e: serde_json::Error) -> Self {
        DomainError::Unexpected(e.to_string())
    }
}
