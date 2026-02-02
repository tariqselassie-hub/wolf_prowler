use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

// New imports for secure crypto
use aes_gcm_siv::{
    aead::{Aead, KeyInit, OsRng},
    Aes256GcmSiv, Nonce,
};
use chacha20poly1305::XChaCha20Poly1305;
use rand::RngCore;
use sha2::{Digest, Sha256, Sha512};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CryptoAlgorithm {
    AES256GCM,
    ChaCha20Poly1305,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HashFunction {
    SHA256,
    SHA512,
    BLAKE3,
}

// MODIFIED: CryptoKey now holds the secret key material and uses Zeroize.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct CryptoKey {
    pub id: Uuid,
    pub algorithm: CryptoAlgorithm,
    #[serde(skip)] // IMPORTANT: Prevent key material from being serialized.
    pub secret: Vec<u8>,
}

// Manual implementation of Debug to avoid leaking secret.
impl fmt::Debug for CryptoKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CryptoKey")
            .field("id", &self.id)
            .field("algorithm", &self.algorithm)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

impl CryptoKey {
    // MODIFIED: Constructor now takes the secret key material.
    pub fn new(algorithm: CryptoAlgorithm, secret: Vec<u8>) -> Self {
        Self {
            id: Uuid::new_v4(),
            algorithm,
            secret,
        }
    }
}

#[derive(Default)]
pub struct CryptoEngine;

impl CryptoEngine {
    pub fn new() -> Self {
        Self
    }

    // MODIFIED: Generates a cryptographically secure random key.
    pub async fn generate_key(&self, algorithm: CryptoAlgorithm) -> Result<CryptoKey> {
        let mut key_bytes = vec![0u8; 32]; // 32 bytes for AES-256 and ChaCha20
        OsRng.fill_bytes(&mut key_bytes);
        Ok(CryptoKey::new(algorithm, key_bytes))
    }

    // MODIFIED: Calls the new `perform_encrypt` function.
    pub async fn encrypt(&self, key: &CryptoKey, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.perform_encrypt(key, plaintext)
    }

    // MODIFIED: Calls the new `perform_decrypt` function.
    pub async fn decrypt(&self, key: &CryptoKey, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.perform_decrypt(key, ciphertext)
    }

    // NEW: Replaces insecure XOR with AES-GCM-SIV or XChaCha20-Poly1305.
    fn perform_encrypt(&self, key: &CryptoKey, plaintext: &[u8]) -> Result<Vec<u8>> {
        match key.algorithm {
            CryptoAlgorithm::AES256GCM => {
                let cipher = Aes256GcmSiv::new_from_slice(&key.secret)
                    .map_err(|e| anyhow!("Failed to create AES-GCM-SIV cipher: {}", e))?;
                let mut nonce_bytes = [0u8; 12];
                OsRng.fill_bytes(&mut nonce_bytes);
                let nonce = Nonce::from_slice(&nonce_bytes);

                let ciphertext = cipher
                    .encrypt(nonce, plaintext)
                    .map_err(|e| anyhow!("AES-GCM-SIV encryption failed: {}", e))?;

                // Prepend nonce to ciphertext
                let mut result = Vec::with_capacity(nonce.len() + ciphertext.len());
                result.extend_from_slice(nonce);
                result.extend_from_slice(&ciphertext);
                Ok(result)
            }
            CryptoAlgorithm::ChaCha20Poly1305 => {
                // Using XChaCha20 for better nonce safety with random nonces
                let cipher = XChaCha20Poly1305::new_from_slice(&key.secret)
                    .map_err(|e| anyhow!("Failed to create XChaCha20Poly1305 cipher: {}", e))?;
                let mut nonce_bytes = [0u8; 24]; // XChaCha20 uses a 24-byte nonce
                OsRng.fill_bytes(&mut nonce_bytes);
                let nonce = chacha20poly1305::XNonce::from_slice(&nonce_bytes);

                let ciphertext = cipher
                    .encrypt(nonce, plaintext)
                    .map_err(|e| anyhow!("XChaCha20Poly1305 encryption failed: {}", e))?;

                // Prepend nonce to ciphertext
                let mut result = Vec::with_capacity(nonce.len() + ciphertext.len());
                result.extend_from_slice(nonce);
                result.extend_from_slice(&ciphertext);
                Ok(result)
            }
        }
    }

    // NEW: Replaces insecure XOR with AES-GCM-SIV or XChaCha20-Poly1305.
    fn perform_decrypt(&self, key: &CryptoKey, data: &[u8]) -> Result<Vec<u8>> {
        match key.algorithm {
            CryptoAlgorithm::AES256GCM => {
                if data.len() < 12 {
                    return Err(anyhow!("Invalid ciphertext: too short for AES-GCM-SIV"));
                }
                let (nonce_bytes, ciphertext) = data.split_at(12);
                let nonce = Nonce::from_slice(nonce_bytes);
                let cipher = Aes256GcmSiv::new_from_slice(&key.secret)
                    .map_err(|e| anyhow!("Failed to create AES-GCM-SIV cipher: {}", e))?;

                cipher
                    .decrypt(nonce, ciphertext)
                    .map_err(|e| anyhow!("AES-GCM-SIV decryption failed: {}", e))
            }
            CryptoAlgorithm::ChaCha20Poly1305 => {
                if data.len() < 24 {
                    return Err(anyhow!(
                        "Invalid ciphertext: too short for XChaCha20Poly1305"
                    ));
                }
                let (nonce_bytes, ciphertext) = data.split_at(24);
                let nonce = chacha20poly1305::XNonce::from_slice(nonce_bytes);
                let cipher = XChaCha20Poly1305::new_from_slice(&key.secret)
                    .map_err(|e| anyhow!("Failed to create XChaCha20Poly1305 cipher: {}", e))?;

                cipher
                    .decrypt(nonce, ciphertext)
                    .map_err(|e| anyhow!("XChaCha20Poly1305 decryption failed: {}", e))
            }
        }
    }

    // MODIFIED: Renamed from simulate_hash and uses real hashing.
    pub async fn hash(&self, data: &[u8], function: HashFunction) -> Result<Vec<u8>> {
        self.perform_hash(data, function)
    }

    pub async fn compute_mac(&self, data: &[u8]) -> Result<Vec<u8>> {
        // System-wide integrity MAC using a fixed internal key
        self.mac(data, b"wolf_prowler_internal_integrity_v1").await
    }

    pub async fn verify_mac(&self, data: &[u8], signature: &[u8]) -> Result<bool> {
        let expected = self.compute_mac(data).await?;
        Ok(self.secure_compare(&expected, signature))
    }

    pub async fn mac(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        // Simple HMAC-like construction using SHA256
        let mut hasher = Sha256::new();
        hasher.update(key);
        hasher.update(data);
        Ok(hasher.finalize().to_vec())
    }

    pub fn secure_compare(&self, a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        let mut res = 0;
        for (x, y) in a.iter().zip(b.iter()) {
            res |= x ^ y;
        }
        res == 0
    }

    // NEW: Replaces dummy hash with real hashing algorithms.
    fn perform_hash(&self, data: &[u8], function: HashFunction) -> Result<Vec<u8>> {
        match function {
            HashFunction::SHA256 => {
                let mut hasher = Sha256::new();
                hasher.update(data);
                Ok(hasher.finalize().to_vec())
            }
            HashFunction::SHA512 => {
                let mut hasher = Sha512::new();
                hasher.update(data);
                Ok(hasher.finalize().to_vec())
            }
            HashFunction::BLAKE3 => {
                let hash = blake3::hash(data);
                Ok(hash.as_bytes().to_vec())
            }
        }
    }
}

// NEW: Test module to verify encryption/decryption roundtrip.
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_aes_gcm_siv_roundtrip() {
        let engine = CryptoEngine::new();
        let key = engine
            .generate_key(CryptoAlgorithm::AES256GCM)
            .await
            .unwrap();
        let plaintext = b"wolf prowler secret message";

        // Encrypt
        let ciphertext = engine.encrypt(&key, plaintext).await.unwrap();
        assert_ne!(
            plaintext.to_vec(),
            ciphertext,
            "Ciphertext should not be the same as plaintext"
        );

        // Decrypt
        let decrypted_plaintext = engine.decrypt(&key, &ciphertext).await.unwrap();
        assert_eq!(
            plaintext.to_vec(),
            decrypted_plaintext,
            "Decrypted plaintext should match original"
        );
    }

    #[tokio::test]
    async fn test_chacha20poly1305_roundtrip() {
        let engine = CryptoEngine::new();
        let key = engine
            .generate_key(CryptoAlgorithm::ChaCha20Poly1305)
            .await
            .unwrap();
        let plaintext = b"another wolf prowler secret";

        // Encrypt
        let ciphertext = engine.encrypt(&key, plaintext).await.unwrap();
        assert_ne!(
            plaintext.to_vec(),
            ciphertext,
            "Ciphertext should not be the same as plaintext"
        );

        // Decrypt
        let decrypted_plaintext = engine.decrypt(&key, &ciphertext).await.unwrap();
        assert_eq!(
            plaintext.to_vec(),
            decrypted_plaintext,
            "Decrypted plaintext should match original"
        );
    }

    #[tokio::test]
    async fn test_decrypt_with_wrong_key_fails() {
        let engine = CryptoEngine::new();
        let key1 = engine
            .generate_key(CryptoAlgorithm::AES256GCM)
            .await
            .unwrap();
        let key2 = engine
            .generate_key(CryptoAlgorithm::AES256GCM)
            .await
            .unwrap();
        let plaintext = b"message for key1";

        let ciphertext = engine.encrypt(&key1, plaintext).await.unwrap();

        // Attempt to decrypt with key2
        let result = engine.decrypt(&key2, &ciphertext).await;
        assert!(result.is_err(), "Decryption with the wrong key should fail");
    }

    #[tokio::test]
    async fn test_hash_functions() {
        let engine = CryptoEngine::new();
        let data = b"some data to hash";

        let sha256_hash = engine.hash(data, HashFunction::SHA256).await.unwrap();
        assert_eq!(sha256_hash.len(), 32);

        let sha512_hash = engine.hash(data, HashFunction::SHA512).await.unwrap();
        assert_eq!(sha512_hash.len(), 64);

        let blake3_hash = engine.hash(data, HashFunction::BLAKE3).await.unwrap();
        assert_eq!(blake3_hash.len(), 32);
    }
}
