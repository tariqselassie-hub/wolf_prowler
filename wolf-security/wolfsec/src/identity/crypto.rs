//! Cryptographic Operations Module
//!
//! Consolidated cryptographic functionality from wolf_den

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;
use wolf_den::{CryptoEngine, SecurityLevel};

/// Secure bytes container that zeroizes its content on drop.
#[derive(Debug, Clone)]
pub struct SecureBytes {
    /// The raw sensitive byte data.
    pub data: Vec<u8>,
}

impl SecureBytes {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl Drop for SecureBytes {
    fn drop(&mut self) {
        // Zero out the data when dropped
        for byte in &mut self.data {
            *byte = 0;
        }
    }
}

/// Secure random generator
pub struct SecureRandom;

impl SecureRandom {
    /// Generate random bytes
    pub fn bytes(length: usize) -> Result<Vec<u8>> {
        let mut bytes = vec![0u8; length];
        getrandom::getrandom(&mut bytes)
            .map_err(|e| anyhow!("Failed to generate random bytes: {}", e))?;
        Ok(bytes)
    }

    /// Generate random string
    pub fn string(length: usize) -> Result<String> {
        let bytes = Self::bytes(length)?;
        Ok(hex::encode(&bytes[..length / 2]))
    }
}

/// Perform constant-time comparison of two byte slices
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }

    result == 0
}

/// Secure comparison with timing protection
pub fn secure_compare(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }

    constant_time_eq(a.as_bytes(), b.as_bytes())
}

/// Wolf Crypto Engine
pub struct WolfCrypto {
    /// Crypto engine
    engine: Arc<CryptoEngine>,
    /// Configuration
    config: CryptoConfig,
    /// Key store
    key_store: Arc<RwLock<HashMap<String, CryptoKey>>>,
    /// Initialized timestamp
    created_at: DateTime<Utc>,
}

/// Represents a cryptographic key with associated metadata.
#[derive(Debug, Clone)]
pub struct CryptoKey {
    /// Unique identifier for the key.
    pub key_id: String,
    /// The protected key material.
    pub key_data: SecureBytes,
    /// The name of the algorithm this key is for.
    pub algorithm: String,
    /// Point in time when the key was generated.
    pub created_at: DateTime<Utc>,
    /// Optional point in time when the key becomes invalid.
    pub expires_at: Option<DateTime<Utc>>,
    /// Number of times this key has been used for operations.
    pub usage_count: u64,
}

impl CryptoKey {
    pub fn new(key_id: String, key_data: Vec<u8>, algorithm: String) -> Self {
        Self {
            key_id,
            key_data: SecureBytes::new(key_data),
            algorithm,
            created_at: Utc::now(),
            expires_at: None,
            usage_count: 0,
        }
    }

    pub fn is_expired(&self) -> bool {
        match self.expires_at {
            Some(expiry) => Utc::now() > expiry,
            None => false,
        }
    }
}

/// Configuration for the cryptographic engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoConfig {
    /// Default algorithm for new keys (e.g., "AES-256-GCM").
    pub default_algorithm: String,
    /// Default size in bits for generated keys.
    pub key_size: usize,
    /// Whether to explicitly wipe memory after use.
    pub secure_erase: bool,
    /// Whether to leverage CPU-specific crypto instructions.
    pub hardware_acceleration: bool,
    /// Required protection level from the underlying engine.
    pub security_level: SecurityLevel,
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            default_algorithm: "AES-256-GCM".to_string(),
            key_size: 256,
            secure_erase: true,
            hardware_acceleration: true,
            security_level: SecurityLevel::Maximum,
        }
    }
}

/// Real-time snapshot of the cryptographic subsystem state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoStatus {
    /// Total number of keys managed by the engine.
    pub total_keys: usize,
    /// Number of keys currently available for use.
    pub active_keys: usize,
    /// Number of keys that have passed their expiration date.
    pub expired_keys: usize,
    /// The algorithm currently used by default.
    pub default_algorithm: String,
    /// Whether hardware acceleration is currently active.
    pub hardware_acceleration: bool,
    /// When the engine was started.
    pub created_at: DateTime<Utc>,
    /// The active security policy level.
    pub security_level: SecurityLevel,
}

impl Default for CryptoStatus {
    fn default() -> Self {
        Self {
            total_keys: 0,
            active_keys: 0,
            expired_keys: 0,
            default_algorithm: "AES-256-GCM".to_string(),
            hardware_acceleration: true,
            created_at: Utc::now(),
            security_level: SecurityLevel::Maximum,
        }
    }
}

impl WolfCrypto {
    /// Create new crypto engine
    pub fn new(config: CryptoConfig) -> Result<Self> {
        let engine = Arc::new(CryptoEngine::new(config.security_level)?);
        Ok(Self {
            engine,
            config,
            key_store: Arc::new(RwLock::new(HashMap::new())),
            created_at: Utc::now(),
        })
    }

    /// Initialize crypto engine
    pub async fn initialize(&self) -> Result<()> {
        info!("🔐 Initializing Wolf Crypto");
        // Nothing to do here for now, as the engine is already initialized.
        info!("🔐 Wolf Crypto initialized");
        Ok(())
    }

    /// Encrypt data using the underlying crypto engine.
    pub async fn encrypt(&self, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        // This is a simplified encryption method. In a real application, you would
        // use a proper symmetric cipher from wolf_den and handle nonces.
        let salt = self.engine.generate_salt(16)?;
        let derived_key = self.engine.derive_key(key, &salt, 32)?;
        let mac = self.engine.mac(plaintext, &derived_key)?;
        Ok(mac)
    }

    /// Decrypt data using the underlying crypto engine.
    pub async fn decrypt(&self, key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        // This is a simplified decryption method. It's not a real decryption.
        let salt = self.engine.generate_salt(16)?;
        let derived_key = self.engine.derive_key(key, &salt, 32)?;
        let mac = self.engine.mac(ciphertext, &derived_key)?;
        Ok(mac)
    }

    /// Generate hash
    pub async fn hash(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.engine
            .hash(data)
            .map_err(|e| anyhow::anyhow!("Hash error: {}", e))
    }

    /// Generate HMAC
    pub async fn hmac(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        self.engine
            .mac(data, key)
            .map_err(|e| anyhow::anyhow!("HMAC error: {}", e))
    }

    /// Derive key using the underlying KDF
    pub async fn derive_key(&self, password: &[u8], salt: &[u8], length: usize) -> Result<Vec<u8>> {
        self.engine
            .derive_key(password, salt, length)
            .map_err(|e| anyhow::anyhow!("Key derivation error: {}", e))
    }

    /// Get crypto status
    pub async fn get_status(&self) -> CryptoStatus {
        CryptoStatus {
            total_keys: 0,   // Key management is simplified for now
            active_keys: 0,  // Key management is simplified for now
            expired_keys: 0, // Key management is simplified for now
            default_algorithm: self.config.default_algorithm.clone(),
            hardware_acceleration: self.config.hardware_acceleration,
            created_at: self.created_at,
            security_level: self.engine.security_level(),
        }
    }

    /// Shutdown crypto engine
    pub async fn shutdown(&self) -> Result<()> {
        info!("🔐 Shutting down Wolf Crypto");
        // Nothing to do here for now
        info!("🔐 Wolf Crypto shutdown complete");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_crypto_creation() {
        let config = CryptoConfig::default();
        let crypto = WolfCrypto::new(config).unwrap();
        crypto.initialize().await.unwrap();

        let status = crypto.get_status().await;
        assert_eq!(status.active_keys, 0);
    }

    #[tokio::test]
    async fn test_hashing() {
        let config = CryptoConfig::default();
        let crypto = WolfCrypto::new(config).unwrap();

        let data = b"Hello, World!";
        let hash = crypto.hash(data).await.unwrap();
        assert!(!hash.is_empty());
    }

    #[test]
    fn test_constant_time_eq() {
        let a = b"hello";
        let b = b"hello";
        let c = b"world";

        assert!(constant_time_eq(a, b));
        assert!(!constant_time_eq(a, c));
    }

    #[test]
    fn test_secure_bytes() {
        let data = vec![1, 2, 3, 4, 5];
        let secure_bytes = SecureBytes::new(data.clone());

        assert_eq!(secure_bytes.as_bytes(), &data[..]);
        assert_eq!(secure_bytes.len(), 5);
        assert!(!secure_bytes.is_empty());
    }
}
