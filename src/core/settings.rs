//! Centralized application settings module.
//!
//! This module defines a unified `AppSettings` struct that is loaded from
//! a TOML file, providing a single source of truth for all configuration.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use wolf_net::firewall::FirewallRule;
use wolfsec::external_feeds::ExternalFeedsConfig;

/// Wolf Pack Hierarchy Roles
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum WolfRole {
    /// Omega - Pack Leader (Head/Administrator)
    Omega,
    /// Alpha - Network Administrators and Assigned Techs
    Alpha,
    /// Beta - End Users and Devices on the Network
    Beta,
    /// Gamma - Specialists and Advanced Users
    Gamma,
}

impl Default for WolfRole {
    fn default() -> Self {
        WolfRole::Beta
    }
}

impl std::fmt::Display for WolfRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WolfRole::Omega => write!(f, "omega"),
            WolfRole::Alpha => write!(f, "alpha"),
            WolfRole::Beta => write!(f, "beta"),
            WolfRole::Gamma => write!(f, "gamma"),
        }
    }
}

impl std::str::FromStr for WolfRole {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "omega" => Ok(Self::Omega),
            "alpha" => Ok(Self::Alpha),
            "beta" => Ok(Self::Beta),
            "gamma" => Ok(Self::Gamma),
            _ => Err(format!("Invalid wolf role: {}", s)),
        }
    }
}

/// Main application settings struct, loaded from a TOML file.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AppSettings {
    pub dashboard: DashboardConfig,
    pub network: NetworkConfig,
    pub security: SecurityConfig,
    pub ai: AiConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub crypto: CryptoConfig,
    #[serde(default)]
    pub database: DatabaseConfig,
    #[serde(default)]
    pub external_feeds: ExternalFeedsConfig,
    #[serde(default)]
    pub firewall_rules: Vec<FirewallRule>,

    // SaaS Central Hub Configuration
    #[serde(default)]
    pub hub_url: Option<String>,
    #[serde(default)]
    pub org_key: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DashboardConfig {
    pub port: u16,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub web_dir: Option<PathBuf>,
    #[serde(default = "default_admin_username")]
    pub admin_username: String,
    pub admin_password: String,
    pub admin_email: Option<String>,
    #[serde(default)]
    pub admin_role: WolfRole,
    #[serde(default = "default_secret_key")]
    pub secret_key: String,
}

fn default_true() -> bool {
    true
}

fn default_admin_username() -> String {
    std::env::var("WOLF_ADMIN_USERNAME").unwrap_or_else(|_| "Cyberwolf".to_string())
}

fn default_secret_key() -> String {
    std::env::var("WOLF_SECRET_KEY").expect("WOLF_SECRET_KEY must be set")
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NetworkConfig {
    pub port: u16,
    #[serde(default = "default_max_peers")]
    pub max_peers: usize,
    pub bootstrap_nodes: Vec<String>,
    #[serde(default = "default_enable_mdns")]
    pub enable_mdns: bool,
    #[serde(default = "default_enable_dht")]
    pub enable_dht: bool,
    #[serde(default = "default_keypair_path")]
    pub keypair_path: PathBuf,
    #[serde(default = "default_heartbeat_interval_secs")]
    pub heartbeat_interval_secs: u64,
}

fn default_keypair_path() -> PathBuf {
    "wolf_prowler_keys.json".into()
}

fn default_max_peers() -> usize {
    50
}

fn default_enable_mdns() -> bool {
    true
}

fn default_enable_dht() -> bool {
    true
}

fn default_heartbeat_interval_secs() -> u64 {
    30
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SecurityConfig {
    pub stance: String, // "Low", "Medium", "High", "Paranoid"
    #[serde(default = "default_api_key")]
    pub api_key: String,
    pub private_key_path: Option<PathBuf>,
    #[serde(default = "default_threat_threshold")]
    pub threat_threshold: f64,
    #[serde(default = "default_true")]
    pub auto_response: bool,
    #[serde(default = "default_true")]
    pub pack_coordination: bool,
    #[serde(default = "default_max_peers")]
    pub max_peers: usize,
    #[serde(default = "default_trust_threshold")]
    pub trust_threshold: f64,
    #[serde(default = "default_rate_limit_messages")]
    pub rate_limit_messages: u32,
    #[serde(default = "default_rate_limit_window_secs")]
    pub rate_limit_window_secs: u64,
    #[serde(default = "default_true")]
    pub threat_detection_enabled: bool,
    #[serde(default = "default_true")]
    pub auto_mitigation_enabled: bool,
}

fn default_api_key() -> String {
    std::env::var("WOLF_API_KEY").unwrap_or_else(|_| "dev-key-12345".to_string())
}

fn default_threat_threshold() -> f64 {
    0.7
}

fn default_trust_threshold() -> f64 {
    0.7
}

fn default_rate_limit_messages() -> u32 {
    100
}

fn default_rate_limit_window_secs() -> u64 {
    60
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AiConfig {
    #[serde(default)]
    pub llm_api_url: Option<String>,
    #[serde(default = "default_model_name")]
    pub model_name: String,
}

fn default_model_name() -> String {
    "llama3".to_string()
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default)]
    pub file_logging: bool,
    #[serde(default)]
    pub log_file: Option<PathBuf>,
    #[serde(default)]
    pub json_format: bool,
}

fn default_log_level() -> String {
    "info".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoConfig {
    #[serde(default = "default_cipher_suite")]
    pub cipher_suite: String,
    #[serde(default = "default_hash_function")]
    pub hash_function: String,
    #[serde(default = "default_security_level")]
    pub security_level: u32,
    #[serde(default = "default_memory_protection")]
    pub memory_protection: u32,
    #[serde(default = "default_randomness_source")]
    pub randomness_source: String,
    #[serde(default = "default_true")]
    pub enable_key_rotation: bool,
    #[serde(default = "default_key_rotation_interval")]
    pub key_rotation_interval: u64,
    #[serde(default = "default_true")]
    pub enable_perfect_forward_secrecy: bool,
    #[serde(default = "default_max_session_duration")]
    pub max_session_duration: u64,
    #[serde(default = "default_true")]
    pub enable_audit_logging: bool,
}

fn default_cipher_suite() -> String {
    "chacha20poly1305".to_string()
}

fn default_hash_function() -> String {
    "blake3".to_string()
}

fn default_security_level() -> u32 {
    256
}

fn default_memory_protection() -> u32 {
    2
}

fn default_randomness_source() -> String {
    "hybrid".to_string()
}

fn default_key_rotation_interval() -> u64 {
    3600
}

fn default_max_session_duration() -> u64 {
    86400
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            cipher_suite: default_cipher_suite(),
            hash_function: default_hash_function(),
            security_level: default_security_level(),
            memory_protection: default_memory_protection(),
            randomness_source: default_randomness_source(),
            enable_key_rotation: true,
            key_rotation_interval: default_key_rotation_interval(),
            enable_perfect_forward_secrecy: true,
            max_session_duration: default_max_session_duration(),
            enable_audit_logging: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: std::env::var("WOLF_DATABASE_URL").expect("WOLF_DATABASE_URL must be set"),
        }
    }
}

impl AppSettings {
    /// Loads configuration from a TOML file and merges with environment variables.
    pub fn new() -> std::result::Result<Self, config::ConfigError> {
        let builder = config::Config::builder()
            // 1. Load from `settings.toml` (optional)
            .add_source(config::File::with_name("settings").required(false))
            // 2. Load from `settings.local.toml` for local overrides (optional)
            .add_source(config::File::with_name("settings.local").required(false))
            // 3. Load from environment variables (e.g., WOLF_DASHBOARD__PORT=8081)
            // `WOLF_` prefix, `__` separator for nested keys
            .add_source(config::Environment::with_prefix("WOLF").separator("__"));

        let settings = builder.build()?;
        settings.try_deserialize()
    }

    /// Persists the current settings to settings.toml
    pub async fn save(&self) -> Result<()> {
        let toml_string = toml::to_string_pretty(self)?;
        tokio::fs::write("settings.toml", toml_string).await?;
        Ok(())
    }
}

impl Default for AppSettings {
    fn default() -> Self {
        // A direct default implementation to avoid unwrap panics if builder fails
        Self {
            dashboard: DashboardConfig {
                port: 3031,
                enabled: true,
                web_dir: None,
                admin_username: default_admin_username(),
                admin_password: std::env::var("WOLF_ADMIN_PASSWORD").expect("WOLF_ADMIN_PASSWORD must be set"),
                admin_email: None,
                admin_role: WolfRole::Omega,
                secret_key: default_secret_key(),
            },
            network: NetworkConfig {
                port: 3030,
                max_peers: 50,
                bootstrap_nodes: Vec::new(),
                enable_mdns: true,
                enable_dht: true,
                keypair_path: default_keypair_path(),
                heartbeat_interval_secs: 30,
            },
            security: SecurityConfig {
                stance: "medium".to_string(),
                api_key: default_api_key(),
                private_key_path: None,
                threat_threshold: 0.7,
                auto_response: true,
                pack_coordination: true,
                max_peers: 50,
                trust_threshold: 0.7,
                rate_limit_messages: 100,
                rate_limit_window_secs: 60,
                threat_detection_enabled: true,
                auto_mitigation_enabled: true,
            },
            ai: AiConfig {
                llm_api_url: Some("http://localhost:11434/api/generate".to_string()),
                model_name: "llama3".to_string(),
            },
            logging: LoggingConfig::default(),
            crypto: CryptoConfig::default(),
            database: DatabaseConfig::default(),
            external_feeds: ExternalFeedsConfig::default(),
            firewall_rules: Vec::new(),
            hub_url: None,
            org_key: None,
        }
    }
}
