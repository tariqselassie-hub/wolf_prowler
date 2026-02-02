//! Configuration Module
//!
//! This module provides configuration loading. Currently uses simplified direct TOML loading
//! to get the system running. Secure vault-based config will be added later.

pub mod secure_config;
pub mod simple_config;

pub use simple_config::SimpleAppSettings;
// pub use secure_config::SecureAppSettings; // TODO: Re-enable when vault integration is added
