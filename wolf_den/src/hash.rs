//! Hash functions for Wolf Den
//!
//! This module provides various hash functions including:

//! - BLAKE3
//! - SHA-2 family (SHA-256, SHA-512)
//! - SHA-3 family (SHA3-256, SHA3-512)

use crate::error::{Error, Result};
use std::fmt;

/// Hash function types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HashFunction {
    /// BLAKE3 hash function - fast, secure, and supports extendable output
    #[default]
    Blake3,
    /// SHA-256 hash function - widely used, 256-bit output
    Sha256,
    /// SHA-512 hash function - widely used, 512-bit output
    Sha512,
    /// SHA3-256 hash function - SHA-3 with 256-bit output
    Sha3_256,
    /// SHA3-512 hash function - SHA-3 with 512-bit output
    Sha3_512,
}

impl fmt::Display for HashFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HashFunction::Blake3 => write!(f, "BLAKE3"),
            HashFunction::Sha256 => write!(f, "SHA-256"),
            HashFunction::Sha512 => write!(f, "SHA-512"),
            HashFunction::Sha3_256 => write!(f, "SHA3-256"),
            HashFunction::Sha3_512 => write!(f, "SHA3-512"),
        }
    }
}

/// Trait for common hash algorithm operations
pub trait HashAlgorithm: Send + Sync + std::fmt::Debug {
    /// Creates a new instance of the hash algorithm.
    fn new(security_level: crate::SecurityLevel) -> Result<Self>
    where
        Self: Sized;

    /// Returns the name of the hash algorithm.
    fn name(&self) -> &'static str;

    /// Returns the standard output length of the hash algorithm in bytes.
    /// This is the fixed output length for non-XOFs, or the default for XOFs.
    fn output_length(&self) -> usize;

    /// Returns the block size of the hash algorithm in bytes.
    fn block_size(&self) -> usize;

    /// Returns the security level configured for this hasher.
    fn security_level(&self) -> crate::SecurityLevel;

    /// Returns the HashFunction enum variant corresponding to this hasher.
    fn as_hash_function(&self) -> HashFunction;
}

/// Hash function enum for type-safe hashing, using enum instead of trait object.
#[derive(Debug)]
pub enum HasherEnum {
    Blake3(Blake3Hasher),
    Sha256(Sha256Hasher),
    Sha512(Sha512Hasher),
    Sha3_256(Sha3_256Hasher),
    Sha3_512(Sha3_512Hasher),
}

impl From<Blake3Hasher> for HasherEnum {
    fn from(hasher: Blake3Hasher) -> Self {
        HasherEnum::Blake3(hasher)
    }
}

impl From<Sha256Hasher> for HasherEnum {
    fn from(hasher: Sha256Hasher) -> Self {
        HasherEnum::Sha256(hasher)
    }
}

impl From<Sha512Hasher> for HasherEnum {
    fn from(hasher: Sha512Hasher) -> Self {
        HasherEnum::Sha512(hasher)
    }
}

impl From<Sha3_256Hasher> for HasherEnum {
    fn from(hasher: Sha3_256Hasher) -> Self {
        HasherEnum::Sha3_256(hasher)
    }
}

impl From<Sha3_512Hasher> for HasherEnum {
    fn from(hasher: Sha3_512Hasher) -> Self {
        HasherEnum::Sha3_512(hasher)
    }
}

impl HasherEnum {
    /// Get hash name
    pub fn name(&self) -> &'static str {
        match self {
            HasherEnum::Blake3(h) => h.name(),
            HasherEnum::Sha256(h) => h.name(),
            HasherEnum::Sha512(h) => h.name(),
            HasherEnum::Sha3_256(h) => h.name(),
            HasherEnum::Sha3_512(h) => h.name(),
        }
    }

    /// Get output length
    pub fn output_length(&self) -> usize {
        match self {
            HasherEnum::Blake3(h) => h.output_length(),
            HasherEnum::Sha256(h) => h.output_length(),
            HasherEnum::Sha512(h) => h.output_length(),
            HasherEnum::Sha3_256(h) => h.output_length(),
            HasherEnum::Sha3_512(h) => h.output_length(),
        }
    }

    /// Get block size
    pub fn block_size(&self) -> usize {
        match self {
            HasherEnum::Blake3(h) => h.block_size(),
            HasherEnum::Sha256(h) => h.block_size(),
            HasherEnum::Sha512(h) => h.block_size(),
            HasherEnum::Sha3_256(h) => h.block_size(),
            HasherEnum::Sha3_512(h) => h.block_size(),
        }
    }

    /// Get security level
    pub fn security_level(&self) -> crate::SecurityLevel {
        match self {
            HasherEnum::Blake3(h) => h.security_level(),
            HasherEnum::Sha256(h) => h.security_level(),
            HasherEnum::Sha512(h) => h.security_level(),
            HasherEnum::Sha3_256(h) => h.security_level(),
            HasherEnum::Sha3_512(h) => h.security_level(),
        }
    }

    /// Get hash function type
    pub fn as_hash_function(&self) -> HashFunction {
        match self {
            HasherEnum::Blake3(h) => h.as_hash_function(),
            HasherEnum::Sha256(h) => h.as_hash_function(),
            HasherEnum::Sha512(h) => h.as_hash_function(),
            HasherEnum::Sha3_256(h) => h.as_hash_function(),
            HasherEnum::Sha3_512(h) => h.as_hash_function(),
        }
    }

    /// Create a new hasher of the same type
    pub fn new_hasher(&self) -> Result<HasherEnum> {
        match self {
            HasherEnum::Blake3(h) => Ok(Blake3Hasher::new(h.security_level())?.into()),
            HasherEnum::Sha256(h) => Ok(Sha256Hasher::new(h.security_level())?.into()),
            HasherEnum::Sha512(h) => Ok(Sha512Hasher::new(h.security_level())?.into()),
            HasherEnum::Sha3_256(h) => Ok(Sha3_256Hasher::new(h.security_level())?.into()),
            HasherEnum::Sha3_512(h) => Ok(Sha3_512Hasher::new(h.security_level())?.into()),
        }
    }

    /// Compute hash of data
    pub async fn digest(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            HasherEnum::Blake3(h) => h.digest(data).await,
            HasherEnum::Sha256(h) => h.digest(data).await,
            HasherEnum::Sha512(h) => h.digest(data).await,
            HasherEnum::Sha3_256(h) => h.digest(data).await,
            HasherEnum::Sha3_512(h) => h.digest(data).await,
        }
    }

    /// Compute hash of data with custom output length (for XOFs)
    pub async fn digest_with_length(&self, data: &[u8], output_length: usize) -> Result<Vec<u8>> {
        match self {
            HasherEnum::Blake3(h) => h.digest_with_length(data, output_length).await,
            HasherEnum::Sha256(h) => h.digest_with_length(data, output_length).await,
            HasherEnum::Sha512(h) => h.digest_with_length(data, output_length).await,
            HasherEnum::Sha3_256(h) => h.digest_with_length(data, output_length).await,
            HasherEnum::Sha3_512(h) => h.digest_with_length(data, output_length).await,
        }
    }
}

/// Create a hasher instance
pub fn create_hasher(
    hash_function: crate::HashFunction,
    security_level: crate::SecurityLevel,
) -> Result<HasherEnum> {
    match hash_function {
        crate::HashFunction::Blake3 => Ok(Blake3Hasher::new(security_level)?.into()),
        crate::HashFunction::Sha256 => Ok(Sha256Hasher::new(security_level)?.into()),
        crate::HashFunction::Sha512 => Ok(Sha512Hasher::new(security_level)?.into()),
        crate::HashFunction::Sha3_256 => Ok(Sha3_256Hasher::new(security_level)?.into()),
        crate::HashFunction::Sha3_512 => Ok(Sha3_512Hasher::new(security_level)?.into()),
    }
}

/// BLAKE3 hasher implementation
#[derive(Debug)]
pub struct Blake3Hasher {
    security_level: crate::SecurityLevel,
    hash_count: std::sync::atomic::AtomicU64,
}

impl Blake3Hasher {
    // The methods below are part of the public API of Blake3Hasher,
    // including async hashing operations.
    pub async fn digest(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(data);
        let hash = hasher.finalize();

        self.hash_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(hash.as_bytes().to_vec())
    }

    pub async fn digest_with_length(&self, data: &[u8], output_length: usize) -> Result<Vec<u8>> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(data);
        let mut output = vec![0u8; output_length];
        hasher.finalize_xof().fill(&mut output);

        self.hash_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(output)
    }

    pub async fn hash_count(&self) -> u64 {
        self.hash_count.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl HashAlgorithm for Blake3Hasher {
    fn new(security_level: crate::SecurityLevel) -> Result<Self> {
        Ok(Self {
            security_level,
            hash_count: std::sync::atomic::AtomicU64::new(0),
        })
    }
    fn name(&self) -> &'static str {
        "BLAKE3"
    }
    fn output_length(&self) -> usize {
        32
    }
    fn block_size(&self) -> usize {
        64
    }
    fn security_level(&self) -> crate::SecurityLevel {
        self.security_level
    }
    fn as_hash_function(&self) -> HashFunction {
        HashFunction::Blake3
    }
}

/// SHA-256 hasher implementation
#[derive(Debug)]
pub struct Sha256Hasher {
    security_level: crate::SecurityLevel,
    hash_count: std::sync::atomic::AtomicU64,
}

impl Sha256Hasher {
    pub async fn digest(&self, data: &[u8]) -> Result<Vec<u8>> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize();

        self.hash_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(hash.to_vec())
    }

    pub async fn digest_with_length(&self, data: &[u8], output_length: usize) -> Result<Vec<u8>> {
        if output_length != 32 {
            return Err(Error::hash(
                "SHA-256",
                "does not support custom output length",
            ));
        }
        self.digest(data).await
    }

    pub async fn hash_count(&self) -> u64 {
        self.hash_count.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl HashAlgorithm for Sha256Hasher {
    fn new(security_level: crate::SecurityLevel) -> Result<Self> {
        Ok(Self {
            security_level,
            hash_count: std::sync::atomic::AtomicU64::new(0),
        })
    }
    fn name(&self) -> &'static str {
        "SHA-256"
    }
    fn output_length(&self) -> usize {
        32
    }
    fn block_size(&self) -> usize {
        64
    }
    fn security_level(&self) -> crate::SecurityLevel {
        self.security_level
    }
    fn as_hash_function(&self) -> HashFunction {
        HashFunction::Sha256
    }
}

/// SHA-512 hasher implementation
#[derive(Debug)]
pub struct Sha512Hasher {
    security_level: crate::SecurityLevel,
    hash_count: std::sync::atomic::AtomicU64,
}

impl Sha512Hasher {
    pub async fn digest(&self, data: &[u8]) -> Result<Vec<u8>> {
        use sha2::{Digest, Sha512};
        let mut hasher = Sha512::new();
        hasher.update(data);
        let hash = hasher.finalize();

        self.hash_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(hash.to_vec())
    }

    pub async fn digest_with_length(&self, data: &[u8], output_length: usize) -> Result<Vec<u8>> {
        if output_length != 64 {
            return Err(Error::hash(
                "SHA-512",
                "does not support custom output length",
            ));
        }
        self.digest(data).await
    }

    pub async fn hash_count(&self) -> u64 {
        self.hash_count.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl HashAlgorithm for Sha512Hasher {
    fn new(security_level: crate::SecurityLevel) -> Result<Self> {
        Ok(Self {
            security_level,
            hash_count: std::sync::atomic::AtomicU64::new(0),
        })
    }
    fn name(&self) -> &'static str {
        "SHA-512"
    }
    fn output_length(&self) -> usize {
        64
    }
    fn block_size(&self) -> usize {
        128
    }
    fn security_level(&self) -> crate::SecurityLevel {
        self.security_level
    }
    fn as_hash_function(&self) -> HashFunction {
        HashFunction::Sha512
    }
}

/// SHA3-256 hasher implementation
#[derive(Debug)]
pub struct Sha3_256Hasher {
    security_level: crate::SecurityLevel,
    hash_count: std::sync::atomic::AtomicU64,
}

impl Sha3_256Hasher {
    pub async fn digest(&self, data: &[u8]) -> Result<Vec<u8>> {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        let hash = hasher.finalize();

        self.hash_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(hash.to_vec())
    }

    pub async fn digest_with_length(&self, data: &[u8], output_length: usize) -> Result<Vec<u8>> {
        if output_length != 32 {
            return Err(Error::hash(
                "SHA3-256",
                "does not support custom output length",
            ));
        }
        self.digest(data).await
    }

    pub async fn hash_count(&self) -> u64 {
        self.hash_count.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl HashAlgorithm for Sha3_256Hasher {
    fn new(security_level: crate::SecurityLevel) -> Result<Self> {
        Ok(Self {
            security_level,
            hash_count: std::sync::atomic::AtomicU64::new(0),
        })
    }
    fn name(&self) -> &'static str {
        "SHA3-256"
    }
    fn output_length(&self) -> usize {
        32
    }
    fn block_size(&self) -> usize {
        136
    }
    fn security_level(&self) -> crate::SecurityLevel {
        self.security_level
    }
    fn as_hash_function(&self) -> HashFunction {
        HashFunction::Sha3_256
    }
}

/// SHA3-512 hasher implementation
#[derive(Debug)]
pub struct Sha3_512Hasher {
    security_level: crate::SecurityLevel,
    hash_count: std::sync::atomic::AtomicU64,
}

impl Sha3_512Hasher {
    pub async fn digest(&self, data: &[u8]) -> Result<Vec<u8>> {
        use sha3::{Digest, Sha3_512};
        let mut hasher = Sha3_512::new();
        hasher.update(data);
        let hash = hasher.finalize();

        self.hash_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(hash.to_vec())
    }

    pub async fn digest_with_length(&self, data: &[u8], output_length: usize) -> Result<Vec<u8>> {
        if output_length != 64 {
            return Err(Error::hash(
                "SHA3-512",
                "does not support custom output length",
            ));
        }
        self.digest(data).await
    }

    pub async fn hash_count(&self) -> u64 {
        self.hash_count.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl HashAlgorithm for Sha3_512Hasher {
    fn new(security_level: crate::SecurityLevel) -> Result<Self> {
        Ok(Self {
            security_level,
            hash_count: std::sync::atomic::AtomicU64::new(0),
        })
    }
    fn name(&self) -> &'static str {
        "SHA3-512"
    }
    fn output_length(&self) -> usize {
        64
    }
    fn block_size(&self) -> usize {
        72
    }
    fn security_level(&self) -> crate::SecurityLevel {
        self.security_level
    }
    fn as_hash_function(&self) -> HashFunction {
        HashFunction::Sha3_512
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_blake3_hasher() {
        let hasher = Blake3Hasher::new(crate::SecurityLevel::Maximum).unwrap();
        let data = b"Hello, BLAKE3!";

        let hash = hasher.digest(data).await.unwrap();
        assert_eq!(hash.len(), 32);
        assert_eq!(hasher.name(), "BLAKE3");
        assert_eq!(hasher.output_length(), 32);
        assert_eq!(hasher.block_size(), 64);
    }

    #[tokio::test]
    async fn test_blake3_custom_length() {
        let hasher = Blake3Hasher::new(crate::SecurityLevel::Maximum).unwrap();
        let data = b"Hello, BLAKE3!";

        let hash = hasher.digest_with_length(data, 64).await.unwrap();
        assert_eq!(hash.len(), 64);
    }

    #[tokio::test]
    async fn test_sha256_hasher() {
        let hasher = Sha256Hasher::new(crate::SecurityLevel::Maximum).unwrap();
        let data = b"Hello, SHA-256!";

        let hash = hasher.digest(data).await.unwrap();
        assert_eq!(hash.len(), 32);
        assert_eq!(hasher.name(), "SHA-256");
        assert_eq!(hasher.output_length(), 32);
        assert_eq!(hasher.block_size(), 64);
    }

    #[tokio::test]
    async fn test_sha512_hasher() {
        let hasher = Sha512Hasher::new(crate::SecurityLevel::Maximum).unwrap();
        let data = b"Hello, SHA-512!";

        let hash = hasher.digest(data).await.unwrap();
        assert_eq!(hash.len(), 64);
        assert_eq!(hasher.name(), "SHA-512");
        assert_eq!(hasher.output_length(), 64);
        assert_eq!(hasher.block_size(), 128);
    }

    #[tokio::test]
    async fn test_sha3_256_hasher() {
        let hasher = Sha3_256Hasher::new(crate::SecurityLevel::Maximum).unwrap();
        let data = b"Hello, SHA3-256!";

        let hash = hasher.digest(data).await.unwrap();
        assert_eq!(hash.len(), 32);
        assert_eq!(hasher.name(), "SHA3-256");
        assert_eq!(hasher.output_length(), 32);
        assert_eq!(hasher.block_size(), 136);
    }

    #[tokio::test]
    async fn test_sha3_512_hasher() {
        let hasher = Sha3_512Hasher::new(crate::SecurityLevel::Maximum).unwrap();
        let data = b"Hello, SHA3-512!";

        let hash = hasher.digest(data).await.unwrap();
        assert_eq!(hash.len(), 64);
        assert_eq!(hasher.name(), "SHA3-512");
        assert_eq!(hasher.output_length(), 64);
        assert_eq!(hasher.block_size(), 72);
    }

    #[tokio::test]
    async fn test_create_hasher() {
        let hasher = create_hasher(crate::HashFunction::Blake3, crate::SecurityLevel::Maximum).unwrap();
        assert_eq!(hasher.name(), "BLAKE3");

        let hasher = create_hasher(crate::HashFunction::Sha256, crate::SecurityLevel::Maximum).unwrap();
        assert_eq!(hasher.name(), "SHA-256");

        let hasher = create_hasher(crate::HashFunction::Sha512, crate::SecurityLevel::Maximum).unwrap();
        assert_eq!(hasher.name(), "SHA-512");

        let hasher = create_hasher(crate::HashFunction::Sha3_256, crate::SecurityLevel::Maximum).unwrap();
        assert_eq!(hasher.name(), "SHA3-256");

        let hasher = create_hasher(crate::HashFunction::Sha3_512, crate::SecurityLevel::Maximum).unwrap();
        assert_eq!(hasher.name(), "SHA3-512");
    }

    #[tokio::test]
    async fn test_hasher_counts() {
        let hasher = Blake3Hasher::new(crate::SecurityLevel::Maximum).unwrap();
        let data = b"Hello, World!";

        assert_eq!(hasher.hash_count().await, 0);

        let _hash = hasher.digest(data).await.unwrap();
        assert_eq!(hasher.hash_count().await, 1);

        let _hash = hasher.digest(data).await.unwrap();
        assert_eq!(hasher.hash_count().await, 2);
    }

    #[tokio::test]
    async fn test_hasher_new_hasher() {
        let hasher = create_hasher(crate::HashFunction::Blake3, crate::SecurityLevel::Maximum).unwrap();
        let new_hasher = hasher.new_hasher().unwrap();

        assert_eq!(hasher.name(), new_hasher.name());
        assert_eq!(hasher.output_length(), new_hasher.output_length());
        assert_eq!(hasher.block_size(), new_hasher.block_size());
    }

    #[tokio::test]
    async fn test_hash_consistency() {
        let hasher = Blake3Hasher::new(crate::SecurityLevel::Maximum).unwrap();
        let data = b"Hello, World!";

        let hash1 = hasher.digest(data).await.unwrap();
        let hash2 = hasher.digest(data).await.unwrap();

        assert_eq!(hash1, hash2);
    }

    #[tokio::test]
    async fn test_different_hashers_different_outputs() {
        let data = b"Hello, World!";

        let blake3 = Blake3Hasher::new(crate::SecurityLevel::Maximum).unwrap();
        let sha256 = Sha256Hasher::new(crate::SecurityLevel::Maximum).unwrap();

        let blake3_hash = blake3.digest(data).await.unwrap();
        let sha256_hash = sha256.digest(data).await.unwrap();

        assert_ne!(blake3_hash, sha256_hash);
    }

    #[tokio::test]
    async fn test_custom_length_error() {
        let hasher = Sha256Hasher::new(crate::SecurityLevel::Maximum).unwrap();
        let data = b"Hello, World!";

        let result = hasher.digest_with_length(data, 64).await;
        assert!(result.is_err());
    }
}
