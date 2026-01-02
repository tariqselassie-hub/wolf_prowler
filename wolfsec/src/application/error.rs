use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApplicationError {
    #[error("Domain error: {0}")]
    Domain(#[from] crate::domain::error::DomainError),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
