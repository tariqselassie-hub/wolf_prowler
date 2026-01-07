//! Dashboard Database Connection Module
//!
//! This module provides the dashboard with a clean interface for connecting
//! to and managing the WolfDbStorage backend.

use lock_prowler::storage::WolfStore;
use once_cell::sync::Lazy;
use std::sync::Mutex;
use thiserror::Error;

pub static WOLF_STORE: Lazy<Mutex<WolfStore>> = Lazy::new(|| {
    Mutex::new(
        WolfStore::new("./wolf_data")
            .expect("Failed to initialize WolfStore")
    )
});

#[derive(Debug, Clone, PartialEq)]
pub enum DbStatus {
    NotInitialized,
    Locked,
    Unlocked,
    Error(String),
}

#[derive(Error, Debug)]
pub enum DbError {
    #[error("Failed to lock store: {0}")]
    LockError(String),
    
    #[error("Database not initialized")]
    NotInitialized,
    
    #[error("Invalid password")]
    InvalidPassword,
    
    #[error("Operation failed: {0}")]
    OperationError(String),
}

/// Initialize the database connection
pub fn initialize_db_connection() -> Result<DbStatus, DbError> {
    let store = WOLF_STORE.lock()
        .map_err(|e| DbError::LockError(e.to_string()))?;
    
    if store.is_initialized() {
        // Check if we can get info (which requires unlock)
        match store.get_info() {
            Ok(_) => Ok(DbStatus::Unlocked),
            Err(_) => Ok(DbStatus::Locked),
        }
    } else {
        Ok(DbStatus::NotInitialized)
    }
}

/// Initialize the database with a password
pub fn db_initialize(password: &str) -> Result<String, DbError> {
    let mut store = WOLF_STORE.lock()
        .map_err(|e| DbError::LockError(e.to_string()))?;
    
    if store.is_initialized() {
        return Ok("Database already initialized".to_string());
    }
    
    store.initialize(password)
        .map_err(|e| DbError::OperationError(e.to_string()))?;
    
    Ok("Database initialized successfully".to_string())
}

/// Unlock the database with a password
pub fn db_unlock(password: &str) -> Result<String, DbError> {
    let mut store = WOLF_STORE.lock()
        .map_err(|e| DbError::LockError(e.to_string()))?;
    
    if !store.is_initialized() {
        return Err(DbError::NotInitialized);
    }
    
    store.unlock(password)
        .map_err(|e| DbError::InvalidPassword)?;
    
    Ok("Database unlocked successfully".to_string())
}

/// Get the current database status
pub fn get_db_status() -> DbStatus {
    let store = match WOLF_STORE.lock() {
        Ok(s) => s,
        return DbStatus::Error("Failed to lock store".to_string()),
    };
    
    if !store.is_initialized() {
        return DbStatus::NotInitialized;
    }
    
    // Try to get info to check if unlocked
    match store.get_info() {
        Ok(_) => DbStatus::Unlocked,
        Err(_) => DbStatus::Locked,
    }
}

/// Check if the database is connected and ready
pub fn is_db_ready() -> bool {
    let store = match WOLF_STORE.lock() {
        Ok(s) => s,
        return false,
    };
    
    store.is_initialized() && store.get_info().is_ok()
}

/// Get database info
pub fn get_db_info() -> Result<serde_json::Value, DbError> {
    let store = WOLF_STORE.lock()
        .map_err(|e| DbError::LockError(e.to_string()))?;
    
    store.get_info()
        .map_err(|e| DbError::OperationError(e.to_string()))
}
