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
            Error::key_derivation("Ed25519", "Invalid key length, expected 32 bytes".to_string())
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
