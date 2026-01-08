// /home/t4riq/Desktop/Rust/wolf_prowler/wolfsec/src/infrastructure/services/wolf_den_cryptography_provider.rs
use crate::domain::entities::crypto::{EncryptedData, HashedData, SecretKey};
use crate::domain::error::DomainError;
use crate::application::services::CryptographyProvider;
use aes_gcm_siv::{
    aead::{Aead, KeyInit},
    Aes256GcmSiv, Nonce,
};
use async_trait::async_trait;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::sync::Arc;
use wolf_den::CryptoEngine;

/// A cryptography provider that leverages the `wolf_den` crate for cryptographic operations.
pub struct WolfDenCryptographyProvider {
    /// The underlying cryptographic engine from `wolf_den`.
    pub engine: Arc<CryptoEngine>,
}

impl WolfDenCryptographyProvider {
    /// Creates a new instance of `WolfDenCryptographyProvider`.
    ///
    /// # Arguments
    /// * `engine` - An `Arc<CryptoEngine>` to be used for cryptographic operations.
    pub fn new(engine: Arc<CryptoEngine>) -> Self {
        Self { engine }
    }
}

#[async_trait]
impl CryptographyProvider for WolfDenCryptographyProvider {
    async fn encrypt(
        &self,
        plaintext: &[u8],
        key: &SecretKey,
    ) -> Result<EncryptedData, DomainError> {
        let key_bytes = key.as_ref();
        if key_bytes.len() != 32 {
            return Err(DomainError::CryptoOperationFailed(
                "Invalid key length for AES-256-GCM-SIV (expected 32 bytes)".to_string(),
            ));
        }

        let cipher = Aes256GcmSiv::new_from_slice(key_bytes).map_err(|e| {
            DomainError::CryptoOperationFailed(format!("Failed to create cipher: {}", e))
        })?;

        // Generate a random 96-bit nonce
        let mut nonce_bytes = [0u8; 12];
        let mut rng = ChaCha20Rng::from_entropy();
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let mut ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| DomainError::CryptoOperationFailed(format!("Encryption failed: {}", e)))?;

        // AES-GCM-SIV appends the tag to the end of the ciphertext
        if ciphertext.len() < 16 {
            return Err(DomainError::CryptoOperationFailed(
                "Ciphertext too short".to_string(),
            ));
        }

        let split_idx = ciphertext.len() - 16;
        let tag = ciphertext.split_off(split_idx);

        Ok(EncryptedData {
            ciphertext,
            nonce: nonce_bytes.to_vec(),
            tag,
        })
    }

    async fn decrypt(
        &self,
        encrypted: &EncryptedData,
        key: &SecretKey,
    ) -> Result<Vec<u8>, DomainError> {
        let key_bytes = key.as_ref();
        if key_bytes.len() != 32 {
            return Err(DomainError::CryptoOperationFailed(
                "Invalid key length".to_string(),
            ));
        }

        let cipher = Aes256GcmSiv::new_from_slice(key_bytes).map_err(|e| {
            DomainError::CryptoOperationFailed(format!("Failed to create cipher: {}", e))
        })?;

        let nonce = Nonce::from_slice(&encrypted.nonce);

        // Reconstruct payload (ciphertext + tag) for the crate
        let mut payload_vec = Vec::with_capacity(encrypted.ciphertext.len() + encrypted.tag.len());
        payload_vec.extend_from_slice(&encrypted.ciphertext);
        payload_vec.extend_from_slice(&encrypted.tag);

        let plaintext = cipher
            .decrypt(nonce, payload_vec.as_ref())
            .map_err(|e| DomainError::CryptoOperationFailed(format!("Decryption failed: {}", e)))?;

        Ok(plaintext)
    }

    async fn hash(&self, data: &[u8]) -> Result<HashedData, DomainError> {
        let hash =
            self.engine.hash(data).await.map_err(|e| {
                DomainError::CryptoOperationFailed(format!("Hashing failed: {}", e))
            })?;

        Ok(HashedData {
            hash,
            algorithm: "BLAKE3".to_string(),
        })
    }

    async fn verify_hash(&self, data: &[u8], hashed: &HashedData) -> Result<bool, DomainError> {
        let new_hash = self.hash(data).await?;
        Ok(crate::crypto::constant_time_eq(
            &new_hash.hash,
            &hashed.hash,
        ))
    }

    async fn generate_key(&self, length_bytes: usize) -> Result<SecretKey, DomainError> {
        let key_bytes = self.engine.generate_key(length_bytes).map_err(|e| {
            DomainError::CryptoOperationFailed(format!("Key generation failed: {}", e))
        })?;
        Ok(SecretKey(key_bytes))
    }
}
