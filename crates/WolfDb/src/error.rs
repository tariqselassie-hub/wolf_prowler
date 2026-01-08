use thiserror::Error;

/// Comprehensive error type for all `WolfDb` operations
#[derive(Error, Debug)]
pub enum WolfDbError {
    /// Standard IO errors
    #[error("IO Error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization/Deserialization errors (Bincode)
    #[error("Serialization Error: {0}")]
    Serialization(#[from] bincode::Error),

    /// Errors from the underlying storage engine (Sled)
    #[error("Storage Engine Error: {0}")]
    Storage(String),

    /// Cryptographic operation failures
    #[error("Crypto Error: {0}")]
    Crypto(String),

    /// Operation attempted while the database is locked
    #[error("Database Locked")]
    Locked,

    /// Record could not be found with the given key
    #[error("Record Not Found: {0}")]
    NotFound(String),

    /// Invalid or unsupported storage partition
    #[error("Invalid Partition: {0}")]
    InvalidPartition(String),

    /// Failures in vector indexing or search
    #[error("Vector Error: {0}")]
    Vector(String),

    /// Errors during data import
    #[error("Import Error: {0}")]
    Import(String),

    /// Tokio async task failures
    #[error("Async task error: {0}")]
    Join(#[from] tokio::task::JoinError),

    /// String conversion errors
    #[error("UTF-8 Error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),

    /// Catch-all for other errors
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

/// Result type used throughout `WolfDb`, defaulting to `WolfDbError`
pub type Result<T> = std::result::Result<T, WolfDbError>;
