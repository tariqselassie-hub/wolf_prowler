//! Unified Crypto Engine for Wolf Den
//!
//! This module provides a high-level interface that combines all cryptographic
//! operations (hashing, key derivation, MAC) into a single, easy-to-use engine.

use crate::asymmetric::Ed25519Keypair;
use crate::error::{Error, Result};
use crate::hash::{create_hasher, HashFunction, HasherEnum};
use crate::kdf::{create_kdf, KdfEnum, KdfType};
use crate::mac::{create_mac, MacEnum, MacType};
use crate::security::constant_time_eq;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand::RngCore;

/// Unified cryptographic engine
#[derive(Debug)]
pub struct CryptoEngine {
    pub(crate) hasher: HasherEnum,
    pub(crate) kdf: KdfEnum,
    pub(crate) mac: MacEnum,
    pub(crate) security_level: crate::SecurityLevel,
    pub(crate) signing_keypair: Ed25519Keypair,
}

impl CryptoEngine {
    /// Create a new `CryptoEngine`
    pub(crate) fn create(
        hasher: HasherEnum,
        kdf: KdfEnum,
        mac: MacEnum,
        security_level: crate::SecurityLevel,
    ) -> Self {
        Self {
            hasher,
            kdf,
            mac,
            security_level,
            signing_keypair: Ed25519Keypair::new(),
        }
    }

    /// Create a new crypto engine with default settings
    ///
    /// # Errors
    ///
    /// Returns an error if initialization fails.
    pub fn new(security_level: crate::SecurityLevel) -> Result<Self> {
        let hasher = create_hasher(HashFunction::Blake3, security_level)?;
        let kdf = create_kdf(KdfType::Argon2, security_level)?;
        let mut mac_key = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut mac_key);
        let mac = create_mac(MacType::Hmac, &mac_key, security_level)?;

        Ok(Self {
            hasher,
            kdf,
            mac,
            security_level,
            signing_keypair: Ed25519Keypair::new(),
        })
    }

    /// Create a new crypto engine with a specific keypair (for persistence)
    ///
    /// # Errors
    ///
    /// Returns an error if initialization or keypair loading fails.
    pub fn with_keypair(security_level: crate::SecurityLevel, keypair_bytes: &[u8]) -> Result<Self> {
        let hasher = create_hasher(HashFunction::Blake3, security_level)?;
        let kdf = create_kdf(KdfType::Argon2, security_level)?;
        
        // Generate random MAC key
        let mut mac_key = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut mac_key);
        let mac = create_mac(MacType::Hmac, &mac_key, security_level)?;

        Ok(Self {
            hasher,
            kdf,
            mac,
            security_level,
            signing_keypair: Ed25519Keypair::from_bytes(keypair_bytes)?,
        })
    }

    /// Get the signing keypair bytes for persistence
    #[must_use]
    pub fn export_identity(&self) -> [u8; 32] {
        self.signing_keypair.to_bytes()
    }

    /// Hash data using the configured hasher
    ///
    /// # Errors
    ///
    /// Returns an error if hashing fails.
    pub fn hash(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.hasher.digest(data)
    }

    /// Hash data with custom output length
    ///
    /// # Errors
    ///
    /// Returns an error if hashing fails.
    pub fn hash_with_length(&self, data: &[u8], output_length: usize) -> Result<Vec<u8>> {
        self.hasher.digest_with_length(data, output_length)
    }

    /// Derive a key using the configured KDF
    ///
    /// # Errors
    ///
    /// Returns an error if key derivation fails.
    pub fn derive_key(&self, password: &[u8], salt: &[u8], length: usize) -> Result<Vec<u8>> {
        self.kdf.derive_key(password, salt, length)
    }

    /// Compute MAC using the configured MAC algorithm
    ///
    /// # Errors
    ///
    /// Returns an error if MAC computation fails.
    pub fn compute_mac(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.mac.compute(data)
    }

    /// Compute MAC using the configured MAC algorithm with a specific key
    ///
    /// # Errors
    ///
    /// Returns an error if MAC computation fails.
    pub fn mac(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        let mac_instance = self.mac.new_mac(key)?;
        mac_instance.compute(data)
    }

    /// Verify MAC using the configured MAC algorithm
    ///
    /// # Errors
    ///
    /// Returns an error if verification fails.
    pub fn verify_mac(&self, data: &[u8], tag: &[u8]) -> Result<bool> {
        self.mac.verify(data, tag)
    }

    /// Hash data and then compute MAC of the hash (hash-then-MAC)
    ///
    /// # Errors
    ///
    /// Returns an error if hashing or MAC computation fails.
    pub fn hash_and_mac(&self, data: &[u8]) -> Result<Vec<u8>> {
        let hash: Vec<u8> = self.hash(data)?;
        self.mac.compute(&hash)
    }

    /// Derive key and then hash the result (KDF-then-hash)
    ///
    /// # Errors
    ///
    /// Returns an error if key derivation or hashing fails.
    pub fn derive_and_hash(
        &self,
        password: &[u8],
        salt: &[u8],
        length: usize,
    ) -> Result<Vec<u8>> {
        let key: Vec<u8> = self.derive_key(password, salt, length)?;
        self.hash(&key)
    }

    /// Constant-time comparison of two byte arrays
    #[must_use]
    pub fn secure_compare(&self, data1: &[u8], data2: &[u8]) -> bool {
        constant_time_eq(data1, data2)
    }

    /// Generate a secure random key of specified length
    ///
    /// # Errors
    ///
    /// Returns an error if random generation fails.
    pub fn generate_key(&self, length: usize) -> Result<Vec<u8>> {
        use rand::RngCore;
        let mut key = vec![0u8; length];
        rand::thread_rng().fill_bytes(&mut key);
        Ok(key)
    }

    /// Generate a secure random salt
    ///
    /// # Errors
    ///
    /// Returns an error if random generation fails.
    pub fn generate_salt(&self, length: usize) -> Result<Vec<u8>> {
        self.generate_key(length)
    }

    /// Get the security level
    #[must_use]
    pub const fn security_level(&self) -> crate::SecurityLevel {
        self.security_level
    }

    /// Get hasher name
    #[must_use]
    pub const fn hasher_name(&self) -> &'static str {
        self.hasher.name()
    }

    /// Get KDF name
    #[must_use]
    pub const fn kdf_name(&self) -> &'static str {
        self.kdf.name()
    }

    /// Get MAC name
    #[must_use]
    pub const fn mac_name(&self) -> &'static str {
        self.mac.name()
    }

    /// Check if KDF is memory-hard
    #[must_use]
    pub const fn is_memory_hard_kdf(&self) -> bool {
        self.kdf.is_memory_hard()
    }

    /// Get hasher output length
    #[must_use]
    pub const fn hash_output_length(&self) -> usize {
        self.hasher.output_length()
    }

    /// Get MAC output length
    #[must_use]
    pub const fn mac_output_length(&self) -> usize {
        self.mac.mac_length()
    }

    /// Get KDF recommended minimum salt length
    #[must_use]
    pub const fn kdf_min_salt_length(&self) -> usize {
        16 // Default minimum salt length
    }

    // Stub implementations for signature methods (to be implemented properly later)
    /// Generate a challenge
    ///
    /// # Errors
    ///
    /// Returns an error if random generation fails.
    pub fn generate_challenge(&self) -> Result<Vec<u8>> {
        self.generate_salt(32)
    }

    /// Get the public key
    #[must_use]
    pub fn get_public_key(&self) -> VerifyingKey {
        self.signing_keypair.public_key()
    }

    /// Sign a message
    pub fn sign_message(&self, message: &[u8]) -> Signature {
        self.signing_keypair.sign(message)
    }

    /// Verify a signature
    ///
    /// # Errors
    ///
    /// Returns an error if the signature is invalid.
    pub fn verify_signature(
        &self,
        message: &[u8],
        signature: &Signature,
        public_key: &VerifyingKey,
    ) -> Result<()> {
        public_key
            .verify(message, signature)
            .map_err(|_| Error::signature_verification("Signature verification failed"))
    }
}

impl Default for CryptoEngine {
    fn default() -> Self {
        #[allow(clippy::expect_used)]
        Self::new(crate::SecurityLevel::Standard).expect("Failed to create default CryptoEngine")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_crypto_engine_basic_operations() {
        let engine = CryptoEngine::new(crate::SecurityLevel::Standard).unwrap();
        let data = b"Hello, Crypto Engine!";

        // Test hashing
        let hash = engine.hash(data).unwrap();
        assert_eq!(hash.len(), engine.hash_output_length());

        // Test MAC computation
        let mac = engine.compute_mac(data).unwrap();
        assert_eq!(mac.len(), engine.mac_output_length());

        // Test MAC verification
        let verified = engine.verify_mac(data, &mac).unwrap();
        assert!(verified);

        // Test key derivation
        let password = b"secure_password";
        let salt = engine.generate_salt(16).unwrap();
        let key = engine.derive_key(password, &salt, 32).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_signing_and_verification() {
        let engine = CryptoEngine::new(crate::SecurityLevel::Standard).unwrap();
        let data = b"This message is signed";

        let signature = engine.sign_message(data);
        let public_key = engine.get_public_key();

        let verification_result = engine.verify_signature(data, &signature, &public_key);
        assert!(verification_result.is_ok());
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_hash_and_mac() {
        let engine = CryptoEngine::new(crate::SecurityLevel::Standard).unwrap();
        let data = b"Test data for hash-then-MAC";

        let result = engine.hash_and_mac(data).unwrap();
        assert!(!result.is_empty());

        // Verify the result is consistent
        let result2 = engine.hash_and_mac(data).unwrap();
        assert_eq!(result, result2);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_derive_and_hash() {
        let engine = CryptoEngine::new(crate::SecurityLevel::Standard).unwrap();
        let password = b"test_password";
        let salt = engine.generate_salt(16).unwrap();

        let result = engine.derive_and_hash(password, &salt, 32).unwrap();
        assert_eq!(result.len(), engine.hash_output_length());
    }

    #[test]
    fn test_secure_compare() {
        let engine = CryptoEngine::new(crate::SecurityLevel::Standard).unwrap();
        let data1 = b"same data";
        let data2 = b"same data";
        let data3 = b"different data";

        assert!(engine.secure_compare(data1, data2));
        assert!(!engine.secure_compare(data1, data3));
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_key_generation() {
        let engine = CryptoEngine::new(crate::SecurityLevel::Standard).unwrap();

        let key1 = engine.generate_key(32).unwrap();
        let key2 = engine.generate_key(32).unwrap();

        assert_eq!(key1.len(), 32);
        assert_eq!(key2.len(), 32);
        assert_ne!(key1, key2); // Keys should be different
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_engine_info() {
        let engine = CryptoEngine::new(crate::SecurityLevel::Maximum).unwrap();

        assert_eq!(engine.security_level(), crate::SecurityLevel::Maximum);
        assert_eq!(engine.hasher_name(), "BLAKE3");
        assert_eq!(engine.kdf_name(), "Argon2id");
        assert_eq!(engine.mac_name(), "HMAC");
        assert!(engine.is_memory_hard_kdf());
        assert_eq!(engine.hash_output_length(), 32);
        assert_eq!(engine.mac_output_length(), 32);
    }
}
