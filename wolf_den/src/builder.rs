//! Configuration Builder for Wolf Den Crypto Engine
//!
//! This module provides a fluent builder pattern for configuring cryptographic
//! engines with custom algorithms and security levels.

use crate::engine::CryptoEngine;
use crate::error::Result;
use crate::hash::{create_hasher, HashFunction};
use crate::kdf::{create_kdf, KdfType};
use crate::mac::{create_mac, MacType};

/// Builder for creating configured CryptoEngine instances
#[derive(Debug, Clone)]
pub struct CryptoEngineBuilder {
    hash_function: Option<HashFunction>,
    kdf_type: Option<KdfType>,
    mac_type: Option<MacType>,
    mac_key: Option<Vec<u8>>,
    security_level: crate::SecurityLevel,
}

impl Default for CryptoEngineBuilder {
    fn default() -> Self {
        Self {
            hash_function: None,
            kdf_type: None,
            mac_type: None,
            mac_key: None,
            security_level: crate::SecurityLevel::Standard,
        }
    }
}

impl CryptoEngineBuilder {
    /// Create a new builder with default settings
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the hash function to use
    pub fn with_hash_function(mut self, func: HashFunction) -> Self {
        self.hash_function = Some(func);
        self
    }

    /// Set the key derivation function to use
    pub fn with_kdf(mut self, kdf: KdfType) -> Self {
        self.kdf_type = Some(kdf);
        self
    }

    /// Set the MAC algorithm to use
    pub fn with_mac(mut self, mac: MacType) -> Self {
        self.mac_type = Some(mac);
        self
    }

    /// Set the MAC key (required for MAC operations)
    pub fn with_mac_key(mut self, key: Vec<u8>) -> Self {
        self.mac_key = Some(key);
        self
    }

    /// Set the security level
    pub fn with_security_level(mut self, level: crate::SecurityLevel) -> Self {
        self.security_level = level;
        self
    }

    /// Build the CryptoEngine with the configured settings
    pub fn build(self) -> Result<CryptoEngine> {
        let hasher = create_hasher(
            self.hash_function.unwrap_or(HashFunction::Blake3),
            self.security_level,
        )?;

        let kdf = create_kdf(
            self.kdf_type.unwrap_or(KdfType::Argon2),
            self.security_level,
        )?;

        let mac_key = self.mac_key.unwrap_or_else(|| vec![0x00u8; 32]);
        let mac = create_mac(
            self.mac_type.unwrap_or(MacType::Hmac),
            &mac_key,
            self.security_level,
        )?;

        Ok(CryptoEngine::create(hasher, kdf, mac, self.security_level))
    }

    /// Build with maximum security settings
    pub fn maximum_security() -> Self {
        Self::default()
            .with_hash_function(HashFunction::Blake3)
            .with_kdf(KdfType::Argon2)
            .with_mac(MacType::Hmac)
            .with_security_level(crate::SecurityLevel::Maximum)
    }

    /// Build with balanced security and performance
    pub fn balanced() -> Self {
        Self::default()
            .with_hash_function(HashFunction::Sha256)
            .with_kdf(KdfType::Pbkdf2)
            .with_mac(MacType::Hmac)
            .with_security_level(crate::SecurityLevel::Standard)
    }

    /// Build with minimum security (fastest performance)
    pub fn minimum_security() -> Self {
        Self::default()
            .with_hash_function(HashFunction::Sha256)
            .with_kdf(KdfType::Pbkdf2)
            .with_mac(MacType::Hmac)
            .with_security_level(crate::SecurityLevel::Minimum)
    }

    /// Build for high-performance scenarios
    pub fn high_performance() -> Self {
        Self::default()
            .with_hash_function(HashFunction::Blake3)
            .with_kdf(KdfType::Pbkdf2)
            .with_mac(MacType::Poly1305)
            .with_security_level(crate::SecurityLevel::Standard)
    }

    /// Build for memory-constrained environments
    pub fn memory_constrained() -> Self {
        Self::default()
            .with_hash_function(HashFunction::Sha256)
            .with_kdf(KdfType::Pbkdf2)
            .with_mac(MacType::Hmac)
            .with_security_level(crate::SecurityLevel::Minimum)
    }
}

/// Extension trait to add builder methods to CryptoEngine
pub trait CryptoEngineExt {
    /// Create a new builder
    fn builder() -> CryptoEngineBuilder {
        CryptoEngineBuilder::new()
    }

    /// Create a builder with maximum security
    fn maximum_security() -> CryptoEngineBuilder {
        CryptoEngineBuilder::maximum_security()
    }

    /// Create a builder with balanced settings
    fn balanced() -> CryptoEngineBuilder {
        CryptoEngineBuilder::balanced()
    }

    /// Create a builder with minimum security
    fn minimum_security() -> CryptoEngineBuilder {
        CryptoEngineBuilder::minimum_security()
    }

    /// Create a builder for high performance
    fn high_performance() -> CryptoEngineBuilder {
        CryptoEngineBuilder::high_performance()
    }

    /// Create a builder for memory constrained environments
    fn memory_constrained() -> CryptoEngineBuilder {
        CryptoEngineBuilder::memory_constrained()
    }
}

impl CryptoEngineExt for CryptoEngine {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_default() {
        let engine = CryptoEngineBuilder::new().build().unwrap();
        assert_eq!(engine.hasher_name(), "BLAKE3");
        assert_eq!(engine.kdf_name(), "Argon2id");
        assert_eq!(engine.mac_name(), "HMAC");
        assert_eq!(engine.security_level(), crate::SecurityLevel::Standard);
    }

    #[test]
    fn test_builder_custom_settings() {
        let engine = CryptoEngineBuilder::new()
            .with_hash_function(HashFunction::Sha256)
            .with_kdf(KdfType::Scrypt)
            .with_mac(MacType::Poly1305)
            .with_mac_key(vec![0x42u8; 32])
            .with_security_level(crate::SecurityLevel::Maximum)
            .build()
            .unwrap();

        assert_eq!(engine.hasher_name(), "SHA-256");
        assert_eq!(engine.kdf_name(), "Scrypt");
        assert_eq!(engine.mac_name(), "Poly1305");
        assert_eq!(engine.security_level(), crate::SecurityLevel::Maximum);
    }

    #[test]
    fn test_builder_presets() {
        let max_engine = CryptoEngine::maximum_security().build().unwrap();
        assert_eq!(max_engine.security_level(), crate::SecurityLevel::Maximum);
        assert!(max_engine.is_memory_hard_kdf());

        let balanced_engine = CryptoEngine::balanced().build().unwrap();
        assert_eq!(
            balanced_engine.security_level(),
            crate::SecurityLevel::Standard
        );

        let min_engine = CryptoEngine::minimum_security().build().unwrap();
        assert_eq!(min_engine.security_level(), crate::SecurityLevel::Minimum);

        let perf_engine = CryptoEngine::high_performance().build().unwrap();
        assert_eq!(perf_engine.hasher_name(), "BLAKE3");
        assert_eq!(perf_engine.mac_name(), "Poly1305");

        let mem_engine = CryptoEngine::memory_constrained().build().unwrap();
        assert_eq!(mem_engine.security_level(), crate::SecurityLevel::Minimum);
        assert_eq!(mem_engine.hasher_name(), "SHA-256");
    }

    #[tokio::test]
    async fn test_builder_functionality() {
        let engine = CryptoEngine::high_performance()
            .with_mac_key(vec![0x42u8; 32])
            .build()
            .unwrap();

        let data = b"test data";
        let hash = engine.hash(data).await.unwrap();
        let mac = engine.compute_mac(data).await.unwrap();

        assert!(!hash.is_empty());
        assert!(!mac.is_empty());
        assert_ne!(hash, mac);
    }

    #[test]
    fn test_builder_chainability() {
        let engine = CryptoEngineBuilder::new()
            .with_hash_function(HashFunction::Sha512)
            .with_kdf(KdfType::Hkdf)
            .with_mac(MacType::Hmac)
            .with_security_level(crate::SecurityLevel::Maximum)
            .build()
            .unwrap();

        assert_eq!(engine.hasher_name(), "SHA-512");
        assert_eq!(engine.kdf_name(), "HKDF");
        assert_eq!(engine.mac_name(), "HMAC");
        assert_eq!(engine.security_level(), crate::SecurityLevel::Maximum);
    }
}
