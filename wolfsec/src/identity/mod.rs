//! Identity Module
//!
//! Provides comprehensive identity and access management for Wolf Prowler.
//!
//! # Features
//!
//! - **Authentication**: User authentication with multi-factor support
//! - **Authorization**: Role-based access control (RBAC) and permissions
//! - **Cryptography**: Post-quantum cryptography and secure operations
//! - **Key Management**: Secure key generation, rotation, and storage
//! - **Zero Trust**: Zero-trust security architecture implementation
//! - **IAM**: Identity and Access Management with policy enforcement
//!
//! # Example
//!
//! ```rust
//! use wolfsec::identity::{IdentityManager, IdentityConfig};
//!
//! # async fn example() -> anyhow::Result<()> {
//! let config = IdentityConfig::default();
//! let identity_manager = IdentityManager::new(config).await?;
//! # Ok(())
//! # }
//! ```

pub mod auth;
pub mod crypto;
pub mod key_management;

// Advanced Identity
pub mod crypto_utils;
pub mod iam;
pub mod zero_trust;

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use uuid::Uuid;

/// System identity with persistent storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemIdentity {
    /// Unique identifier for the system
    pub id: Uuid,
    /// Human-readable name
    pub name: String,
    /// Cryptographic key material
    pub key_material: Vec<u8>,
    /// Identity creation timestamp
    pub created_at: DateTime<Utc>,
    /// Identity last validation timestamp
    pub last_validated: DateTime<Utc>,
    /// Identity version for compatibility
    pub version: u32,
}

/// Identity configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityConfig {
    /// Path to store identity file
    pub identity_file: String,
    /// Minimum key material length
    pub min_key_length: usize,
    /// Maximum key material length
    pub max_key_length: usize,
    /// Identity name
    pub system_name: String,
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            identity_file: "wolfsec_identity.json".to_string(),
            min_key_length: 32,
            max_key_length: 64,
            system_name: "WolfSec System".to_string(),
        }
    }
}

impl SystemIdentity {
    /// Create a new system identity
    pub fn new(config: &IdentityConfig) -> Result<Self> {
        // Generate cryptographically secure key material
        let key_material = Self::generate_key_material(config.min_key_length)?;

        Ok(Self {
            id: Uuid::new_v4(),
            name: config.system_name.clone(),
            key_material,
            created_at: Utc::now(),
            last_validated: Utc::now(),
            version: 1,
        })
    }

    /// Generate cryptographically secure key material
    fn generate_key_material(length: usize) -> Result<Vec<u8>> {
        let mut key = vec![0u8; length];
        getrandom::getrandom(&mut key)
            .map_err(|e| anyhow!("Failed to generate key material: {}", e))?;
        Ok(key)
    }

    /// Validate the identity
    pub fn validate(&self, config: &IdentityConfig) -> Result<()> {
        // Check ID is valid
        if self.id.is_nil() {
            return Err(anyhow!("Invalid identity ID"));
        }

        // Check name is not empty
        if self.name.trim().is_empty() {
            return Err(anyhow!("Identity name cannot be empty"));
        }

        // Check key material length
        if self.key_material.len() < config.min_key_length {
            return Err(anyhow!(
                "Key material too short: {} < {}",
                self.key_material.len(),
                config.min_key_length
            ));
        }

        if self.key_material.len() > config.max_key_length {
            return Err(anyhow!(
                "Key material too long: {} > {}",
                self.key_material.len(),
                config.max_key_length
            ));
        }

        // Check timestamps are valid
        if self.created_at > Utc::now() {
            return Err(anyhow!("Created timestamp is in the future"));
        }

        if self.last_validated > Utc::now() {
            return Err(anyhow!("Last validated timestamp is in the future"));
        }

        // Check version compatibility
        if self.version == 0 {
            return Err(anyhow!("Invalid identity version"));
        }

        Ok(())
    }

    /// Update last validation timestamp
    pub fn update_validation(&mut self) {
        self.last_validated = Utc::now();
    }

    /// Save identity to persistent storage
    pub fn save(&self, config: &IdentityConfig) -> Result<()> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| anyhow!("Failed to serialize identity: {}", e))?;

        fs::write(&config.identity_file, json)
            .map_err(|e| anyhow!("Failed to write identity file: {}", e))?;

        Ok(())
    }

    /// Load identity from persistent storage
    pub fn load(config: &IdentityConfig) -> Result<Self> {
        if !Path::new(&config.identity_file).exists() {
            return Err(anyhow!("Identity file does not exist"));
        }

        let json = fs::read_to_string(&config.identity_file)
            .map_err(|e| anyhow!("Failed to read identity file: {}", e))?;

        let identity: Self = serde_json::from_str(&json)
            .map_err(|e| anyhow!("Failed to parse identity file: {}", e))?;

        // Validate loaded identity
        identity.validate(config)?;

        Ok(identity)
    }

    /// Create or load identity (persistent identity management)
    pub fn create_or_load(config: &IdentityConfig) -> Result<Self> {
        if Path::new(&config.identity_file).exists() {
            match Self::load(config) {
                Ok(identity) => {
                    tracing::info!("Loaded existing identity: {}", identity.id);
                    Ok(identity)
                }
                Err(e) => {
                    tracing::warn!("Failed to load existing identity: {}, creating new one", e);
                    let identity = Self::new(config)?;
                    identity.save(config)?;
                    tracing::info!("Created new identity: {}", identity.id);
                    Ok(identity)
                }
            }
        } else {
            let identity = Self::new(config)?;
            identity.save(config)?;
            tracing::info!("Created new identity: {}", identity.id);
            Ok(identity)
        }
    }

    /// Get identity fingerprint (hash of key material)
    pub fn fingerprint(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&self.key_material);
        let hash = hasher.finalize();
        format!("{:x}", hash)
    }

    /// Get short identifier for display
    pub fn short_id(&self) -> String {
        self.id.to_string()[..8].to_string()
    }
}

/// Identity manager for system-wide identity management
pub struct IdentityManager {
    config: IdentityConfig,
    identity: Option<SystemIdentity>,
}

impl IdentityManager {
    /// Create new identity manager
    pub fn new(config: IdentityConfig) -> Self {
        Self {
            config,
            identity: None,
        }
    }

    /// Initialize identity (create or load)
    pub fn initialize(&mut self) -> Result<&SystemIdentity> {
        if self.identity.is_none() {
            self.identity = Some(SystemIdentity::create_or_load(&self.config)?);
        }
        Ok(self.identity.as_ref().unwrap())
    }

    /// Get current identity
    pub fn get_identity(&self) -> Result<&SystemIdentity> {
        self.identity
            .as_ref()
            .ok_or_else(|| anyhow!("Identity not initialized"))
    }

    /// Validate current identity
    pub fn validate_identity(&self) -> Result<()> {
        let identity = self.get_identity()?;
        identity.validate(&self.config)
    }

    /// Update identity validation timestamp
    pub fn update_validation(&mut self) -> Result<()> {
        if let Some(identity) = &mut self.identity {
            identity.update_validation();
            identity.save(&self.config)?;
        }
        Ok(())
    }

    /// Get identity fingerprint
    pub fn get_fingerprint(&self) -> Result<String> {
        let identity = self.get_identity()?;
        Ok(identity.fingerprint())
    }

    /// Get short identity ID
    pub fn get_short_id(&self) -> Result<String> {
        let identity = self.get_identity()?;
        Ok(identity.short_id())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_identity_creation() {
        let temp_file = NamedTempFile::new().unwrap();
        let mut config = IdentityConfig::default();
        config.identity_file = temp_file.path().to_string_lossy().to_string();

        let identity = SystemIdentity::new(&config).expect("Failed to create identity");

        assert!(!identity.id.is_nil());
        assert_eq!(identity.name, "WolfSec System");
        assert_eq!(identity.key_material.len(), 32);
        assert!(identity.created_at <= Utc::now());
        assert!(identity.last_validated <= Utc::now());
        assert_eq!(identity.version, 1);
    }

    #[test]
    fn test_identity_validation() {
        let temp_file = NamedTempFile::new().unwrap();
        let mut config = IdentityConfig::default();
        config.identity_file = temp_file.path().to_string_lossy().to_string();

        let identity = SystemIdentity::new(&config).expect("Failed to create identity");
        identity
            .validate(&config)
            .expect("Identity validation failed");
    }

    #[test]
    fn test_identity_persistence() {
        let temp_file = NamedTempFile::new().unwrap();
        let mut config = IdentityConfig::default();
        config.identity_file = temp_file.path().to_string_lossy().to_string();

        // Create and save identity
        let identity1 = SystemIdentity::new(&config).expect("Failed to create identity");
        identity1.save(&config).expect("Failed to save identity");

        // Load identity
        let identity2 = SystemIdentity::load(&config).expect("Failed to load identity");

        assert_eq!(identity1.id, identity2.id);
        assert_eq!(identity1.name, identity2.name);
        assert_eq!(identity1.key_material, identity2.key_material);
        assert_eq!(identity1.version, identity2.version);
    }

    #[test]
    fn test_identity_fingerprint() {
        let temp_file = NamedTempFile::new().unwrap();
        let mut config = IdentityConfig::default();
        config.identity_file = temp_file.path().to_string_lossy().to_string();

        let identity = SystemIdentity::new(&config).expect("Failed to create identity");
        let fingerprint = identity.fingerprint();

        assert!(!fingerprint.is_empty());
        assert_eq!(fingerprint.len(), 64); // SHA-256 hex string
    }

    #[test]
    fn test_identity_manager() {
        let temp_file = NamedTempFile::new().unwrap();
        let mut config = IdentityConfig::default();
        config.identity_file = temp_file.path().to_string_lossy().to_string();

        let mut manager = IdentityManager::new(config);
        let identity = manager.initialize().expect("Failed to initialize identity");

        assert!(!identity.id.is_nil());
        assert_eq!(identity.name, "WolfSec System");

        // Test validation
        manager
            .validate_identity()
            .expect("Identity validation failed");

        // Test fingerprint
        let fingerprint = manager
            .get_fingerprint()
            .expect("Failed to get fingerprint");
        assert!(!fingerprint.is_empty());

        // Test short ID
        let short_id = manager.get_short_id().expect("Failed to get short ID");
        assert_eq!(short_id.len(), 8);
    }
}
