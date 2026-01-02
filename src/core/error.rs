//! Core error types for Wolf Prowler

use thiserror::Error;

#[derive(Error, Debug)]
pub enum WolfError {
    #[error("Network error: {0}")]
    Network(String),
    
    #[error("Security error: {0}")]
    Security(String),
    
    #[error("Configuration error: {0}")]
    Config(String),
    
    #[error("Database error: {0}")]
    Database(String),
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Other error: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, WolfError>;
