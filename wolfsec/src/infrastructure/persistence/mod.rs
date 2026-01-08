//! Persistence implementations for the wolfsec domain.
//!
//! This module provides repository implementations that use WolfDb as the
//! underlying storage engine for alerts, authentication data, monitoring events,
//! and threat intelligence.

pub mod wolf_db_alert_repository;
pub mod wolf_db_auth_repository;
pub mod wolf_db_monitoring_repository;
pub mod wolf_db_threat_repository;

pub use wolf_db_alert_repository::WolfDbAlertRepository;
pub use wolf_db_auth_repository::WolfDbAuthRepository;
pub use wolf_db_monitoring_repository::WolfDbMonitoringRepository;
pub use wolf_db_threat_repository::WolfDbThreatRepository;
