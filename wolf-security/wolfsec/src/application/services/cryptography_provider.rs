// /home/t4riq/Desktop/Rust/wolf_prowler/wolfsec/src/domain/services/cryptography_provider.rs
use crate::domain::entities::crypto::{EncryptedData, HashedData, SecretKey};
use crate::domain::error::DomainError;
use async_trait::async_trait;

/// A domain service trait defining cryptographic operations.
/// This acts as a port for the application layer.
#[async_trait]
pub trait CryptographyProvider: Send + Sync {
    /// Encrypts plaintext data using a secret key.
    async fn encrypt(
        &self,
        plaintext: &[u8],
        key: &SecretKey,
    ) -> Result<EncryptedData, DomainError>;

    /// Decrypts an `EncryptedData` struct using a secret key.
    async fn decrypt(
        &self,
        encrypted: &EncryptedData,
        key: &SecretKey,
    ) -> Result<Vec<u8>, DomainError>;

    /// Hashes data using the configured primary hash algorithm.
    async fn hash(&self, data: &[u8]) -> Result<HashedData, DomainError>;

    /// Verifies if the data matches a given hash.
    async fn verify_hash(&self, data: &[u8], hashed: &HashedData) -> Result<bool, DomainError>;

    /// Generates a new secret key of a specified length.
    async fn generate_key(&self, length_bytes: usize) -> Result<SecretKey, DomainError>;
}
