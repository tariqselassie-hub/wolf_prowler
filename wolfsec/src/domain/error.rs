// /home/t4riq/Desktop/Rust/wolf_prowler/wolfsec/src/domain/error.rs
use thiserror::Error;

/// Represents errors that can occur within the domain layer.
/// These are specific business logic errors that the application layer can handle.
#[derive(Debug, Error)]
pub enum DomainError {
    /// Invalid input provided for a specific field.
    #[error("Invalid input for field '{field}': {reason}")]
    InvalidInput {
        /// The name of the invalid field.
        field: &'static str,
        /// The reason for the validation failure.
        reason: String,
    },

    /// The requested entity was not found.
    #[error("Entity '{entity_type}' with ID '{id}' not found.")]
    NotFound {
        /// The type/category of the missing entity.
        entity_type: &'static str,
        /// The unique identifier of the missing entity.
        id: String,
    },

    /// A cryptographic operation failed.
    #[error("A cryptographic operation failed: {0}")]
    CryptoOperationFailed(String),

    /// A threat detection operation failed.
    #[error("A threat detection operation failed: {0}")]
    ThreatDetectionError(String),

    /// An unexpected error occurred.
    #[error("An unexpected error occurred: {0}")]
    Unexpected(String),
}

impl From<serde_json::Error> for DomainError {
    fn from(e: serde_json::Error) -> Self {
        DomainError::Unexpected(e.to_string())
    }
}
