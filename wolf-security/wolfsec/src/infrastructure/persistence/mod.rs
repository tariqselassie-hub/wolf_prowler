//! Persistence Infrastructure
//!
//! Contains concrete database and storage implementations.

pub mod wolf_db_alert_repository;
pub mod wolf_db_auth_repository;
pub mod wolf_db_monitoring_repository;
pub mod wolf_db_storage;
pub mod wolf_db_threat_repository;

// For backward compatibility
pub use wolf_db_storage::WolfDbStorage;
