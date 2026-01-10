use thiserror::Error;

#[derive(Error, Debug)]
pub enum AirGapError {
    #[error("IO Error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Crypto Error: {0}")]
    Crypto(String),
    #[error("Permission Denied: {0}")]
    PermissionDenied(String),
    #[error("Other: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, AirGapError>;
