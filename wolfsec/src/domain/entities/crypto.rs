// /home/t4riq/Desktop/Rust/wolf_prowler/wolfsec/src/domain/entities/crypto.rs
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// A wrapper for a cryptographic key that ensures it's zeroed on drop.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct SecretKey(pub Vec<u8>);

impl AsRef<[u8]> for SecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Represents data that has been encrypted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub tag: Vec<u8>, // For AEAD ciphers like AES-GCM
}

/// Represents the result of a hashing operation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HashedData {
    pub hash: Vec<u8>,
    pub algorithm: String,
}
