use crate::peer::PeerId;
use thiserror::Error;

/// Defines the specific errors that can occur within the Wolf Pack logic.
#[derive(Debug, Error)]
pub enum WolfPackError {
    /// Quorum could not be reached or maintained
    #[error("Pack Partition: Quorum lost for Hunt '{0}'")]
    PartitionLost(String),

    /// Operation timed out
    #[error("Hunt Timeout: Target '{0}' evaded verification")]
    HuntTimeout(String),

    /// Node attempted action above its station
    #[error("Prestige Insufficient: Node {0:?} attempted an unauthorized action")]
    UnauthorizedAction(PeerId),

    /// Conflicting claims on territory
    #[error("Territory Conflict: {0}")]
    TerritoryConflict(String),

    /// This should conceptually never happen in Safe Rust, but we track it
    /// to catch logical violations of the actor model before they become panics.
    #[error("Critical Memory Logic: {0}")]
    MemorySafetyViolation(String),

    /// Issues with Alpha election
    #[error("Election Error: {0}")]
    ElectionError(String),

    /// General coordination failure
    #[error("Coordination Error: {0}")]
    CoordinationError(String),

    /// Networking failure
    #[error("Network Error: {0}")]
    NetworkError(String),

    /// Requested hunt does not exist
    #[error("Hunt '{0}' not found")]
    HuntNotFound(String),
}

/// Convenience Result type for WolfPack operations
pub type Result<T> = std::result::Result<T, WolfPackError>;
