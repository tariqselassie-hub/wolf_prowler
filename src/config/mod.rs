//! Configuration Module
//!
//! This module provides secure configuration loading using the Wolf Den secrets vault
//! instead of hardcoded values. It integrates with the existing AppSettings system
//! while providing encrypted credential storage.

pub mod secure_config;

pub use secure_config::{
    AppSettings, DashboardConfig, DatabaseConfig, NetworkConfig, SecureAppSettings, SecurityConfig,
};
