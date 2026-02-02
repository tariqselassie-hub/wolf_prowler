// /home/t4riq/Desktop/Rust/wolf_prowler/wolfsec/src/domain/entities/crypto.rs
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// A wrapper for a cryptographic key that ensures it's zeroed on drop.
///
/// This structure provides a secure container for sensitive material,
/// leveraging the `zeroize` crate to ensure the memory is wiped when
/// the key is no longer in use.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct SecretKey(
    /// The raw byte representation of the secret material.
    pub Vec<u8>,
);

impl AsRef<[u8]> for SecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Represents data that has been transformed into a secure, unintelligible format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    /// The encrypted byte stream.
    pub ciphertext: Vec<u8>,
    /// The initialization vector or nonce used for this specific encryption operation.
    pub nonce: Vec<u8>,
    /// The message authentication tag ensuring data integrity and authenticity.
    pub tag: Vec<u8>, // For AEAD ciphers like AES-GCM
}

/// Represents the fixed-size cryptographic digest of arbitrary input data.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HashedData {
    /// The raw bytes resulting from the hashing operation.
    pub hash: Vec<u8>,
    /// The identifier of the hashing algorithm used (e.g., "BLAKE3", "SHA-256").
    pub algorithm: String,
}
