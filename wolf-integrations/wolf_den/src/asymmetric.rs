//! Asymmetric Cryptography for Wolf Den
//!
//! This module provides functionality for digital signatures using Ed25519.

use crate::error::{Error, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;

/// An Ed25519 keypair for signing and verification.
#[derive(Debug)]
pub struct Ed25519Keypair {
    signing_key: SigningKey,
}

impl Ed25519Keypair {
    /// Generates a new Ed25519 keypair.
    #[must_use]
    pub fn new() -> Self {
        let mut csprng = OsRng {};
        let signing_key: SigningKey = SigningKey::generate(&mut csprng);
        Self { signing_key }
    }

    /// Signs a message with the secret key.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    /// Verifies a signature on a message with the public key.
    ///
    /// # Errors
    ///
    /// Returns an error if signature verification fails.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<()> {
        self.signing_key
            .verifying_key()
            .verify(message, signature)
            .map_err(|_| Error::signature_verification("Signature verification failed"))
    }

    /// Returns the public key.
    #[must_use]
    pub fn public_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Returns the secret key.
    #[must_use]
    pub const fn secret_key(&self) -> &SigningKey {
        &self.signing_key
    }
    /// Returns the keypair as raw bytes (seed).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Creates a keypair from raw bytes (seed).
    ///
    /// # Errors
    ///
    /// Returns an error if the key length is invalid.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
            Error::key_derivation(
                "Ed25519",
                "Invalid key length, expected 32 bytes".to_string(),
            )
        })?;
        let signing_key = SigningKey::from_bytes(&bytes);
        Ok(Self { signing_key })
    }
}

impl Default for Ed25519Keypair {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = Ed25519Keypair::new();
        assert_eq!(keypair.to_bytes().len(), 32);
    }

    #[test]
    fn test_signing_verification() {
        let keypair = Ed25519Keypair::new();
        let message = b"Hello, World!";
        let signature = keypair.sign(message);
        assert!(keypair.verify(message, &signature).is_ok());

        let bad_message = b"Hello, World?";
        assert!(keypair.verify(bad_message, &signature).is_err());
    }

    #[test]
    fn test_serialization() {
        let keypair = Ed25519Keypair::new();
        let bytes = keypair.to_bytes();
        let loaded = Ed25519Keypair::from_bytes(&bytes).unwrap();

        let message = b"Persistence test";
        let signature = keypair.sign(message);
        assert!(loaded.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_invalid_key_length() {
        let bad_bytes = [0u8; 31];
        assert!(Ed25519Keypair::from_bytes(&bad_bytes).is_err());
    }

    #[test]
    fn test_public_key_access() {
        let keypair = Ed25519Keypair::new();
        let pk = keypair.public_key();
        assert_eq!(pk.as_bytes().len(), 32);
    }
}
