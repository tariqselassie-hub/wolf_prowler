//! Secure Configuration Loader
//!
//! This module provides secure configuration loading using the Wolf Den secrets vault
//! instead of hardcoded values in settings.toml. It integrates with the existing
//! AppSettings system while providing encrypted credential storage.

use anyhow::{Context, Result};
use secrets::{SecretsVault, VaultConfig};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// Secure configuration that loads credentials from the vault
#[derive(Debug, Clone)]
pub struct SecureAppSettings {
    /// Base application settings
    pub base_settings: AppSettings,
    /// Secrets vault for secure credential storage
    pub vault: Arc<SecretsVault>,
}

/// Base application settings (simplified version of AppSettings)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
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
    pub admin_password: String, // Will be loaded from vault
    pub admin_role: String,
    pub secret_key: String, // Will be loaded from vault
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
    pub api_key: String, // Will be loaded from vault
    pub private_key_path: Option<PathBuf>,
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
    pub url: String,
}

impl SecureAppSettings {
    /// Create a new secure configuration
    pub async fn new() -> Result<Self> {
        // Load base settings from TOML (non-sensitive configuration)
        let base_settings = Self::load_base_settings()?;

        // Initialize secrets vault
        let vault_config = VaultConfig {
            storage_path: PathBuf::from("wolf_vault.json"),
            security_level: wolf_den::SecurityLevel::Maximum,
            master_key: vec![],
            rotation_interval: Duration::from_secs(86400),
            memory_protection: wolf_den::memory::MemoryProtection::Strict,
        };

        let vault = Arc::new(SecretsVault::new(vault_config).await?);

        // Initialize vault with passphrase from environment
        let vault_passphrase = std::env::var("WOLF_VAULT_PASSPHRASE")
            .unwrap_or_else(|_| "wolf_prowler_secure_passphrase_2024".to_string());

        vault.initialize(&vault_passphrase).await?;

        // Secure the configuration by loading credentials from vault
        let secure_settings = Self {
            base_settings: Self::secure_credentials(base_settings, &vault).await?,
            vault,
        };

        Ok(secure_settings)
    }

    /// Load base settings from TOML file (non-sensitive configuration)
    fn load_base_settings() -> Result<AppSettings> {
        // Try to load from settings.toml
        if let Ok(content) = std::fs::read_to_string("settings.toml") {
            let mut settings: AppSettings =
                toml::from_str(&content).context("Failed to parse settings.toml")?;

            // Override with environment variables if present
            if let Ok(port) = std::env::var("DASHBOARD_PORT") {
                settings.dashboard.port = port.parse().context("Invalid DASHBOARD_PORT")?;
            }

            if let Ok(enabled) = std::env::var("DASHBOARD_ENABLED") {
                settings.dashboard.enabled =
                    enabled.parse().context("Invalid DASHBOARD_ENABLED")?;
            }

            if let Ok(network_port) = std::env::var("NETWORK_PORT") {
                settings.network.port = network_port.parse().context("Invalid NETWORK_PORT")?;
            }

            if let Ok(max_peers) = std::env::var("MAX_PEERS") {
                settings.network.max_peers = max_peers.parse().context("Invalid MAX_PEERS")?;
            }

            if let Ok(stance) = std::env::var("SECURITY_STANCE") {
                settings.security.stance = stance;
            }

            if let Ok(threat_threshold) = std::env::var("THREAT_THRESHOLD") {
                settings.security.threat_threshold = threat_threshold
                    .parse()
                    .context("Invalid THREAT_THRESHOLD")?;
            }

            if let Ok(db_url) = std::env::var("DATABASE_URL") {
                settings.database.url = db_url;
            }

            return Ok(settings);
        }

        // Fallback to defaults if no settings.toml exists
        Ok(Self::default_settings())
    }

    /// Secure the configuration by loading credentials from the vault
    async fn secure_credentials(
        mut settings: AppSettings,
        vault: &SecretsVault,
    ) -> Result<AppSettings> {
        // Load admin password from vault
        match vault.retrieve_secret("admin_password").await {
            Ok(password) => {
                settings.dashboard.admin_password =
                    String::from_utf8(password).context("Invalid admin password encoding")?;
            }
            Err(_) => {
                // Store default password in vault if it doesn't exist
                vault
                    .store_secret("admin_password", b"secure_admin_password_123")
                    .await?;
                settings.dashboard.admin_password = "secure_admin_password_123".to_string();
            }
        }

        // Load secret key from vault
        match vault.retrieve_secret("dashboard_secret_key").await {
            Ok(secret_key) => {
                settings.dashboard.secret_key =
                    String::from_utf8(secret_key).context("Invalid secret key encoding")?;
            }
            Err(_) => {
                // Generate and store a secure secret key
                let secret_key = Self::generate_secure_key();
                vault
                    .store_secret("dashboard_secret_key", secret_key.as_bytes())
                    .await?;
                settings.dashboard.secret_key = secret_key;
            }
        }

        // Load API key from vault
        match vault.retrieve_secret("api_key").await {
            Ok(api_key) => {
                settings.security.api_key =
                    String::from_utf8(api_key).context("Invalid API key encoding")?;
            }
            Err(_) => {
                // Store default API key in vault if it doesn't exist
                vault.store_secret("api_key", b"dev-key-12345").await?;
                settings.security.api_key = "dev-key-12345".to_string();
            }
        }

        Ok(settings)
    }

    /// Generate a secure random key
    fn generate_secure_key() -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        (0..64)
            .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
            .collect()
    }

    /// Get default settings
    fn default_settings() -> AppSettings {
        AppSettings {
            dashboard: DashboardConfig {
                port: 3031,
                enabled: true,
                admin_username: "Cyberwolf".to_string(),
                admin_password: "secure_admin_password_123".to_string(), // Will be overridden by vault
                admin_role: "Omega".to_string(),
                secret_key: "secure_secret_key_256_bits".to_string(), // Will be overridden by vault
            },
            network: NetworkConfig {
                port: 3030,
                max_peers: 50,
                bootstrap_nodes: vec![],
                enable_mdns: true,
                enable_dht: true,
                keypair_path: PathBuf::from("wolf_prowler_keys.json"),
                heartbeat_interval_secs: 30,
            },
            security: SecurityConfig {
                stance: "medium".to_string(),
                api_key: "dev-key-12345".to_string(), // Will be overridden by vault
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
            database: DatabaseConfig {
                url: "postgres://wolf_admin:wolf_secure_pass_2024@localhost/wolf_prowler"
                    .to_string(),
            },
        }
    }

    /// Update a secret in the vault
    pub async fn update_secret(&self, name: &str, value: &[u8]) -> Result<()> {
        self.vault
            .rotate_secret(name, value)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to update secret {}: {}", name, e))
    }

    /// Get a secret from the vault
    pub async fn get_secret(&self, name: &str) -> Result<String> {
        let secret = self
            .vault
            .retrieve_secret(name)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to retrieve secret {}: {}", name, e))?;

        String::from_utf8(secret)
            .map_err(|e| anyhow::anyhow!("Invalid secret encoding for {}: {}", name, e))
    }

    /// List all stored secrets
    pub async fn list_secrets(&self) -> Result<Vec<String>> {
        let secrets = self
            .vault
            .list_secrets()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to list secrets: {}", e))?;

        Ok(secrets.into_iter().map(|s| s.name).collect())
    }

    /// Generate a certificate using the vault
    pub async fn generate_certificate(&self, common_name: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        let (keypair, cert) = self
            .vault
            .generate_certificate(common_name)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to generate certificate: {}", e))?;

        Ok((keypair.to_bytes().to_vec(), cert))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_secure_config() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("test_vault.json");

        // Create a test vault config
        let vault_config = VaultConfig {
            storage_path: vault_path,
            security_level: wolf_den::SecurityLevel::Standard,
            master_key: vec![],
            rotation_interval: Duration::from_secs(3600),
            memory_protection: wolf_den::memory::MemoryProtection::Basic,
        };

        let vault = SecretsVault::new(vault_config).await.unwrap();
        vault.initialize("test_passphrase").await.unwrap();

        // Test credential storage and retrieval
        let mut settings = SecureAppSettings::default_settings();
        let secured = SecureAppSettings::secure_credentials(settings, &vault)
            .await
            .unwrap();

        assert!(!secured.dashboard.admin_password.is_empty());
        assert!(!secured.dashboard.secret_key.is_empty());
        assert!(!secured.security.api_key.is_empty());

        // Test secret updates
        vault
            .store_secret("test_secret", b"new_value")
            .await
            .unwrap();
        let retrieved = vault.retrieve_secret("test_secret").await.unwrap();
        assert_eq!(retrieved, b"new_value");
    }
}
