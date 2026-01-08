use thiserror::Error;

/// Application-level error types.
#[derive(Debug, Error)]
pub enum ApplicationError {
    /// Error originating from the domain layer.
    #[error("Domain Error: {0}")]
    Domain(#[from] crate::domain::error::DomainError),

    /// Validation failure for a command or query.
    #[error("Validation Error: {0}")]
    Validation(String),

    /// Other general errors.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
