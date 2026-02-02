//! Simplified Configuration Loader
//!
//! This is a temporary simplified version that loads directly from settings.toml
//! without the complex vault system. This allows us to get the system running
//! first, then add security layers later.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Simplified configuration that loads directly from TOML
#[derive(Debug, Clone)]
pub struct SimpleAppSettings {
    /// Base application settings
    pub base_settings: AppSettings,
}

/// Base application settings loaded from settings.toml
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    pub node_id: String,
    pub dashboard: DashboardConfig,
    pub network: NetworkConfig,
    pub security: SecurityConfig,
    pub database: DatabaseConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardConfig {
    pub port: u16,
    pub enabled: bool,
    pub admin_username: String,
    pub admin_password: String,
    pub admin_role: String,
    pub secret_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub port: u16,
    pub max_peers: usize,
    pub bootstrap_nodes: Vec<String>,
    pub enable_mdns: bool,
    pub enable_dht: bool,
    pub keypair_path: PathBuf,
    pub heartbeat_interval_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub stance: String,
    pub api_key: String,
    pub private_key_path: Option<String>,
    pub threat_threshold: f64,
    pub auto_response: bool,
    pub pack_coordination: bool,
    pub max_peers: usize,
    pub trust_threshold: f64,
    pub rate_limit_messages: usize,
    pub rate_limit_window_secs: u64,
    pub threat_detection_enabled: bool,
    pub auto_mitigation_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub path: PathBuf,
}

impl SimpleAppSettings {
    /// Create a new simplified configuration
    pub fn new() -> Result<Self> {
        let base_settings = Self::load_settings()?;
        Ok(Self { base_settings })
    }

    /// Load settings from settings.toml
    fn load_settings() -> Result<AppSettings> {
        let content = std::fs::read_to_string("settings.toml")
            .context("Failed to read settings.toml file")?;

        toml::from_str(&content).context("Failed to parse settings.toml")
    }
}
