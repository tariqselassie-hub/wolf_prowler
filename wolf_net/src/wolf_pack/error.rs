use crate::peer::PeerId;
use thiserror::Error;

/// Defines the specific errors that can occur within the Wolf Pack logic.
#[derive(Debug, Error)]
pub enum WolfPackError {
    #[error("Pack Partition: Quorum lost for Hunt '{0}'")]
    PartitionLost(String),

    #[error("Hunt Timeout: Target '{0}' evaded verification")]
    HuntTimeout(String),

    #[error("Prestige Insufficient: Node {0:?} attempted an unauthorized action")]
    UnauthorizedAction(PeerId),

    #[error("Territory Conflict: {0}")]
    TerritoryConflict(String),

    /// This should conceptually never happen in Safe Rust, but we track it
    /// to catch logical violations of the actor model before they become panics.
    #[error("Critical Memory Logic: {0}")]
    MemorySafetyViolation(String),

    #[error("Election Error: {0}")]
    ElectionError(String),

    #[error("Coordination Error: {0}")]
    CoordinationError(String),

    #[error("Network Error: {0}")]
    NetworkError(String),

    #[error("Hunt '{0}' not found")]
    HuntNotFound(String),
}

pub type Result<T> = std::result::Result<T, WolfPackError>;
