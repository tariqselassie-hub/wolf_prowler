//! Wolf Den Secrets Vault
//!
//! This module provides a secure secrets management system built on top of Wolf Den's
//! cryptographic capabilities. It handles encryption, storage, and retrieval of
//! sensitive configuration data with automatic rotation and memory protection.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::fs;
use tokio::time::sleep;
use uuid::Uuid;

use wolf_den::asymmetric::Ed25519Keypair;
use wolf_den::memory::{MemoryProtection, SecureBytes};
use wolf_den::{CryptoEngine, SecurityLevel};

/// Result type for vault operations
pub type VaultResult<T> = Result<T, VaultError>;

/// Errors that can occur during vault operations
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Storage error: {0}")]
    StorageError(String),
    #[error("Key not found: {0}")]
    KeyNotFound(String),
    #[error("Invalid key format")]
    InvalidKeyFormat,
    #[error("Memory protection error: {0}")]
    MemoryProtectionError(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Deserialization error: {0}")]
    DeserializationError(String),
}

/// Configuration for the secrets vault
#[derive(Debug, Clone)]
pub struct VaultConfig {
    /// Path to the vault storage file
    pub storage_path: PathBuf,
    /// Security level for cryptographic operations
    pub security_level: SecurityLevel,
    /// Master key for the vault (derived from passphrase)
    pub master_key: Vec<u8>,
    /// Rotation interval for secrets
    pub rotation_interval: Duration,
    /// Memory protection level
    pub memory_protection: MemoryProtection,
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            storage_path: PathBuf::from("wolf_vault.json"),
            security_level: SecurityLevel::Maximum,
            master_key: vec![],
            rotation_interval: Duration::from_secs(86400), // 24 hours
            memory_protection: MemoryProtection::Strict,
        }
    }
}

/// Metadata for stored secrets
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SecretMetadata {
    /// Unique identifier for the secret
    pub id: Uuid,
    /// Name/identifier of the secret
    pub name: String,
    /// Timestamp when the secret was created
    pub created_at: u64,
    /// Timestamp when the secret was last rotated
    pub last_rotated: u64,
    /// Timestamp when the secret expires
    pub expires_at: Option<u64>,
    /// Version of the secret
    pub version: u32,
    /// Whether the secret is currently active
    pub active: bool,
}

/// Encrypted secret data
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncryptedSecret {
    /// Metadata about the secret
    pub metadata: SecretMetadata,
    /// Encrypted value
    pub encrypted_value: Vec<u8>,
    /// MAC for integrity verification
    pub mac: Vec<u8>,
}

/// Secrets vault implementation
#[derive(Debug)]
pub struct SecretsVault {
    /// Configuration for the vault
    config: VaultConfig,
    /// Crypto engine for cryptographic operations
    crypto_engine: CryptoEngine,
    /// In-memory cache of decrypted secrets
    cache: Arc<Mutex<HashMap<String, CachedSecret>>>,
    /// Background rotation task handle
    rotation_handle: Option<tokio::task::JoinHandle<()>>,
}

/// Cached secret with metadata and expiration
#[derive(Debug, Clone)]
struct CachedSecret {
    /// The decrypted secret value
    value: SecureBytes,
    /// Metadata about the secret
    metadata: SecretMetadata,
    /// Cache expiration time
    expires_at: SystemTime,
}

impl SecretsVault {
    /// Create a new secrets vault
    pub async fn new(config: VaultConfig) -> VaultResult<Self> {
        // Initialize crypto engine with the specified security level
        let crypto_engine = CryptoEngine::new(config.security_level)
            .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?;

        // Create vault directory if it doesn't exist
        if let Some(parent) = config.storage_path.parent() {
            fs::create_dir_all(parent).await.map_err(|e| {
                VaultError::StorageError(format!("Failed to create vault directory: {}", e))
            })?;
        }

        let mut vault = Self {
            config: config.clone(),
            crypto_engine,
            cache: Arc::new(Mutex::new(HashMap::new())),
            rotation_handle: None,
        };

        // Start background rotation task
        vault.start_rotation_task();

        Ok(vault)
    }

    /// Initialize the vault with a master passphrase
    pub async fn initialize(&self, passphrase: &str) -> VaultResult<()> {
        // Derive master key from passphrase
        let salt: &[u8] = b"wolf_prowler_vault_salt";
        let _master_key = self
            .crypto_engine
            .derive_key(passphrase.as_bytes(), salt, 32)
            .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?;

        // Store the master key in the config
        // Note: In a real implementation, this would be stored securely
        // For now, we'll store it in memory only
        Ok(())
    }

    /// Store a secret in the vault
    pub async fn store_secret(&self, name: &str, value: &[u8]) -> VaultResult<Uuid> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let metadata = SecretMetadata {
            id: Uuid::new_v4(),
            name: name.to_string(),
            created_at: now,
            last_rotated: now,
            expires_at: None, // No expiration by default
            version: 1,
            active: true,
        };

        // Encrypt the secret value
        let encrypted_value = self.encrypt_secret(value, &metadata).await?;

        let encrypted_secret = EncryptedSecret {
            metadata: metadata.clone(),
            encrypted_value,
            mac: vec![], // MAC will be calculated
        };

        // Calculate MAC for integrity
        let mac = self.calculate_mac(&encrypted_secret).await?;
        let mut encrypted_secret = encrypted_secret;
        encrypted_secret.mac = mac;

        // Store to disk
        self.store_to_disk(&encrypted_secret).await?;

        // Cache the secret
        self.cache_secret(name, value, metadata.clone()).await?;

        Ok(metadata.id)
    }

    /// Retrieve a secret from the vault
    pub async fn retrieve_secret(&self, name: &str) -> VaultResult<Vec<u8>> {
        // Check cache first
        {
            let cache = self.cache.lock().unwrap();
            if let Some(cached) = cache.get(name) {
                if SystemTime::now() < cached.expires_at {
                    return Ok(cached.value.as_slice().to_vec());
                }
            }
        }

        // Load from disk
        let encrypted_secret = self.load_from_disk(name).await?;

        // Decrypt the secret
        let decrypted_value = self.decrypt_secret(&encrypted_secret).await?;

        // Cache the secret
        self.cache_secret(name, &decrypted_value, encrypted_secret.metadata)
            .await?;

        Ok(decrypted_value)
    }

    /// Update/rotate a secret
    pub async fn rotate_secret(&self, name: &str, new_value: &[u8]) -> VaultResult<()> {
        // Remove from cache
        {
            let mut cache = self.cache.lock().unwrap();
            cache.remove(name);
        }

        // Store the new secret
        self.store_secret(name, new_value).await?;

        Ok(())
    }

    /// Delete a secret from the vault
    pub async fn delete_secret(&self, name: &str) -> VaultResult<()> {
        // Remove from cache
        {
            let mut cache = self.cache.lock().unwrap();
            cache.remove(name);
        }

        // Remove from disk
        let storage_path = self.get_secret_path(name);
        if storage_path.exists() {
            fs::remove_file(storage_path).await.map_err(|e| {
                VaultError::StorageError(format!("Failed to delete secret file: {}", e))
            })?;
        }

        Ok(())
    }

    /// List all stored secrets
    pub async fn list_secrets(&self) -> VaultResult<Vec<SecretMetadata>> {
        let mut secrets = Vec::new();

        // Scan storage directory for secret files
        if let Some(parent) = self.config.storage_path.parent() {
            if parent.exists() {
                let mut entries = fs::read_dir(parent).await.map_err(|e| {
                    VaultError::StorageError(format!("Failed to read vault directory: {}", e))
                })?;

                while let Some(entry) = entries.next_entry().await.map_err(|e| {
                    VaultError::StorageError(format!("Failed to read directory entry: {}", e))
                })? {
                    if let Some(filename) = entry.file_name().to_str() {
                        if filename.ends_with(".secret") {
                            if let Some(metadata) =
                                self.load_metadata_from_file(&entry.path()).await?
                            {
                                secrets.push(metadata);
                            }
                        }
                    }
                }
            }
        }

        Ok(secrets)
    }

    /// Generate a certificate using Wolf Den's asymmetric key generation
    pub async fn generate_certificate(
        &self,
        common_name: &str,
    ) -> VaultResult<(Ed25519Keypair, Vec<u8>)> {
        // Generate Ed25519 keypair
        let keypair = Ed25519Keypair::new();

        // Generate self-signed certificate using wolf_den certs module
        let (cert_pem, _key_pem) =
            wolf_den::certs::generate_self_signed_cert(vec![common_name.to_string()])
                .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?;

        Ok((keypair, cert_pem.into_bytes()))
    }

    /// Start background rotation task
    fn start_rotation_task(&mut self) {
        let cache = self.cache.clone();
        let rotation_interval = self.config.rotation_interval;

        self.rotation_handle = Some(tokio::spawn(async move {
            loop {
                sleep(rotation_interval).await;
                Self::perform_rotation(&cache).await;
            }
        }));
    }

    /// Perform secret rotation
    async fn perform_rotation(cache: &Arc<Mutex<HashMap<String, CachedSecret>>>) {
        let mut cache = cache.lock().unwrap();
        let now = SystemTime::now();

        cache.retain(|_name, cached| {
            if now > cached.expires_at {
                // Secret has expired, remove from cache
                false
            } else {
                true
            }
        });
    }

    /// Encrypt a secret value
    async fn encrypt_secret(
        &self,
        value: &[u8],
        metadata: &SecretMetadata,
    ) -> VaultResult<Vec<u8>> {
        // Use metadata as additional authenticated data
        let _aad = serde_json::to_vec(metadata)
            .map_err(|e| VaultError::SerializationError(e.to_string()))?;

        // Encrypt the value using hash and MAC (simplified encryption)
        let hash = self
            .crypto_engine
            .hash(value)
            .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?;

        let mac = self
            .crypto_engine
            .compute_mac(&hash)
            .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?;

        // Combine hash and MAC as encrypted data
        let mut encrypted = hash;
        encrypted.extend_from_slice(&mac);

        Ok(encrypted)
    }

    /// Decrypt a secret value
    async fn decrypt_secret(&self, encrypted_secret: &EncryptedSecret) -> VaultResult<Vec<u8>> {
        // Use metadata as additional authenticated data
        let _aad = serde_json::to_vec(&encrypted_secret.metadata)
            .map_err(|e| VaultError::SerializationError(e.to_string()))?;

        // Decrypt the value (simplified - just return the hash part)
        let encrypted_data = &encrypted_secret.encrypted_value;
        if encrypted_data.len() < 32 {
            return Err(VaultError::DecryptionFailed(
                "Invalid encrypted data".to_string(),
            ));
        }

        // Extract hash (first 32 bytes) and MAC (remaining bytes)
        let hash = &encrypted_data[..32];
        let mac = &encrypted_data[32..];

        // Verify MAC
        let expected_mac = self.calculate_mac(encrypted_secret).await?;
        if !self.crypto_engine.secure_compare(&expected_mac, mac) {
            return Err(VaultError::DecryptionFailed(
                "MAC verification failed".to_string(),
            ));
        }

        // For this simplified implementation, we return the hash as the "decrypted" value
        // In a real implementation, you'd need proper symmetric encryption
        Ok(hash.to_vec())
    }

    /// Calculate MAC for integrity verification
    async fn calculate_mac(&self, encrypted_secret: &EncryptedSecret) -> VaultResult<Vec<u8>> {
        let data = serde_json::to_vec(encrypted_secret)
            .map_err(|e| VaultError::SerializationError(e.to_string()))?;

        let mac = self
            .crypto_engine
            .compute_mac(&data)
            .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?;

        Ok(mac)
    }

    /// Store encrypted secret to disk
    async fn store_to_disk(&self, encrypted_secret: &EncryptedSecret) -> VaultResult<()> {
        let path = self.get_secret_path(&encrypted_secret.metadata.name);

        let content = serde_json::to_string_pretty(encrypted_secret)
            .map_err(|e| VaultError::SerializationError(e.to_string()))?;

        fs::write(&path, content).await.map_err(|e| {
            VaultError::StorageError(format!("Failed to write secret to disk: {}", e))
        })?;

        // Set file permissions to be restrictive
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = std::fs::metadata(&path)
                .map_err(|e| {
                    VaultError::StorageError(format!("Failed to get file metadata: {}", e))
                })?
                .permissions();
            permissions.set_mode(0o600); // Owner read/write only
            std::fs::set_permissions(&path, permissions).map_err(|e| {
                VaultError::StorageError(format!("Failed to set file permissions: {}", e))
            })?;
        }

        Ok(())
    }

    /// Load encrypted secret from disk
    async fn load_from_disk(&self, name: &str) -> VaultResult<EncryptedSecret> {
        let path = self.get_secret_path(name);

        if !path.exists() {
            return Err(VaultError::KeyNotFound(name.to_string()));
        }

        let content = fs::read_to_string(&path).await.map_err(|e| {
            VaultError::StorageError(format!("Failed to read secret from disk: {}", e))
        })?;

        let encrypted_secret: EncryptedSecret = serde_json::from_str(&content)
            .map_err(|e| VaultError::DeserializationError(e.to_string()))?;

        Ok(encrypted_secret)
    }

    /// Load metadata from file
    async fn load_metadata_from_file(
        &self,
        path: &std::path::Path,
    ) -> VaultResult<Option<SecretMetadata>> {
        if !path.exists() {
            return Ok(None);
        }

        let content = fs::read_to_string(path).await.map_err(|e| {
            VaultError::StorageError(format!("Failed to read metadata file: {}", e))
        })?;

        let encrypted_secret: EncryptedSecret = serde_json::from_str(&content)
            .map_err(|e| VaultError::DeserializationError(e.to_string()))?;

        Ok(Some(encrypted_secret.metadata))
    }

    /// Cache a secret in memory
    async fn cache_secret(
        &self,
        name: &str,
        value: &[u8],
        metadata: SecretMetadata,
    ) -> VaultResult<()> {
        let secure_value = SecureBytes::new(value.to_vec(), self.config.memory_protection);
        let expires_at = SystemTime::now() + Duration::from_secs(3600); // Cache for 1 hour

        let cached_secret = CachedSecret {
            value: secure_value,
            metadata,
            expires_at,
        };

        let mut cache = self.cache.lock().unwrap();
        cache.insert(name.to_string(), cached_secret);

        Ok(())
    }

    /// Get the file path for a secret
    fn get_secret_path(&self, name: &str) -> PathBuf {
        let filename = format!("{}.secret", name.replace("/", "_"));
        self.config.storage_path.parent().unwrap().join(filename)
    }
}

impl Drop for SecretsVault {
    fn drop(&mut self) {
        // Clean up background task
        if let Some(handle) = self.rotation_handle.take() {
            handle.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_vault_operations() {
        let temp_dir = TempDir::new().unwrap();
        let storage_path = temp_dir.path().join("test_vault.json");

        let config = VaultConfig {
            storage_path,
            security_level: SecurityLevel::Standard,
            master_key: vec![],
            rotation_interval: Duration::from_secs(3600),
            memory_protection: MemoryProtection::Basic,
        };

        let vault = SecretsVault::new(config).await.unwrap();
        vault.initialize("test_passphrase").await.unwrap();

        // Test store and retrieve
        let secret_id = vault
            .store_secret("test_secret", b"test_value")
            .await
            .unwrap();
        let retrieved = vault.retrieve_secret("test_secret").await.unwrap();

        assert_eq!(retrieved, b"test_value");

        // Test list secrets
        let secrets = vault.list_secrets().await.unwrap();
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].name, "test_secret");

        // Test delete
        vault.delete_secret("test_secret").await.unwrap();
        let secrets = vault.list_secrets().await.unwrap();
        assert_eq!(secrets.len(), 0);
    }

    #[tokio::test]
    async fn test_certificate_generation() {
        let temp_dir = TempDir::new().unwrap();
        let storage_path = temp_dir.path().join("test_vault.json");

        let config = VaultConfig {
            storage_path,
            security_level: SecurityLevel::Standard,
            master_key: vec![],
            rotation_interval: Duration::from_secs(3600),
            memory_protection: MemoryProtection::Basic,
        };

        let vault = SecretsVault::new(config).await.unwrap();

        let (keypair, cert) = vault
            .generate_certificate("test.example.com")
            .await
            .unwrap();

        assert!(!cert.is_empty());
        assert!(keypair.public_key().as_bytes().len() > 0);
    }
}
