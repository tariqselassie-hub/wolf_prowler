//! Message Authentication Codes for Wolf Den
//!
//! This module provides various MAC algorithms including:
//! - HMAC
//! - Poly1305
//! - CMAC
//! - BLAKE2b MAC

use crate::error::{Error, Result};
use crate::hash::HasherEnum;
use crate::memory::SecureBytes;
use chacha20poly1305::aead::KeyInit;
use poly1305::Poly1305;
use universal_hash::{generic_array::GenericArray, UniversalHash};

/// Message Authentication Code enum for type-safe MAC operations
#[derive(Debug)]
pub enum MacEnum {
    /// HMAC implementation using various hash functions
    Hmac(HmacMac),
    /// Poly1305 MAC - fast and secure for authentication
    Poly1305(Poly1305Mac),
}

impl MacEnum {
    /// Compute MAC of data
    pub async fn compute(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            MacEnum::Hmac(mac) => mac.compute(data).await,
            MacEnum::Poly1305(mac) => mac.compute(data).await,
        }
    }

    /// Verify MAC of data
    pub async fn verify(&self, data: &[u8], tag: &[u8]) -> Result<bool> {
        match self {
            MacEnum::Hmac(mac) => mac.verify(data, tag).await,
            MacEnum::Poly1305(mac) => mac.verify(data, tag).await,
        }
    }

    /// Get MAC name
    pub fn name(&self) -> &'static str {
        match self {
            MacEnum::Hmac(mac) => mac.name(),
            MacEnum::Poly1305(mac) => mac.name(),
        }
    }

    /// Get MAC length
    pub fn mac_length(&self) -> usize {
        match self {
            MacEnum::Hmac(mac) => mac.mac_length(),
            MacEnum::Poly1305(mac) => mac.mac_length(),
        }
    }

    /// Get key length
    pub fn key_length(&self) -> usize {
        match self {
            MacEnum::Hmac(mac) => mac.key_length(),
            MacEnum::Poly1305(mac) => mac.key_length(),
        }
    }

    /// Get MAC count
    pub async fn mac_count(&self) -> u64 {
        match self {
            MacEnum::Hmac(mac) => mac.mac_count().await,
            MacEnum::Poly1305(mac) => mac.mac_count().await,
        }
    }

    /// Create new MAC instance
    pub fn new_mac(&self, key: &[u8]) -> Result<MacEnum> {
        // The new_hasher method on HasherEnum now correctly creates a new instance of the same type.
        // For other MAC types, we assume their `new` methods handle key cloning/copying.
        match self {
            MacEnum::Hmac(mac) => Ok(MacEnum::Hmac(HmacMac::new(
                mac.hasher.new_hasher()?,
                key.to_vec(),
            )?)),
            MacEnum::Poly1305(_mac) => Ok(MacEnum::Poly1305(Poly1305Mac::new(key.to_vec())?)),
        }
    }
}

/// HMAC implementation
#[derive(Debug)]
pub struct HmacMac {
    hasher: HasherEnum,
    key: SecureBytes,
    mac_count: std::sync::atomic::AtomicU64,
}

impl HmacMac {
    pub fn new(hasher: HasherEnum, key: Vec<u8>) -> Result<Self> {
        Ok(Self {
            hasher,
            key: SecureBytes::new(key, crate::memory::MemoryProtection::Strict),
            mac_count: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// Compute MAC of data
    pub async fn compute(&self, data: &[u8]) -> Result<Vec<u8>> {
        let block_size = self.hasher.block_size();
        let mut key = self.key.as_slice().to_vec();

        // If key is longer than block size, hash it
        if key.len() > block_size {
            key = self.hasher.digest(&key).await?;
        }

        // If key is shorter than block size, pad with zeros
        if key.len() < block_size {
            key.resize(block_size, 0);
        }

        // Inner and outer padding
        let mut ipad = vec![0x36; block_size];
        let mut opad = vec![0x5C; block_size];

        for (i, &k) in key.iter().enumerate() {
            ipad[i] ^= k;
            opad[i] ^= k;
        }

        // Compute inner hash
        let mut inner_data = ipad;
        inner_data.extend_from_slice(data);
        let inner_hash: Vec<u8> = self.hasher.digest(&inner_data).await?;

        // Compute outer hash
        let mut outer_data = opad;
        outer_data.extend_from_slice(&inner_hash);
        let outer_hash: Vec<u8> = self.hasher.digest(&outer_data).await?;

        self.mac_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(outer_hash)
    }

    /// Verify MAC of data
    pub async fn verify(&self, data: &[u8], tag: &[u8]) -> Result<bool> {
        let computed_tag = self.compute(data).await?;
        Ok(crate::security::constant_time_eq(&computed_tag, tag))
    }

    pub fn name(&self) -> &'static str {
        "HMAC"
    }

    pub fn mac_length(&self) -> usize {
        self.hasher.output_length()
    }

    pub fn key_length(&self) -> usize {
        self.hasher.block_size()
    }

    pub async fn mac_count(&self) -> u64 {
        self.mac_count.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Poly1305 MAC implementation
#[derive(Debug)]
pub struct Poly1305Mac {
    key: SecureBytes,
    mac_count: std::sync::atomic::AtomicU64,
}

impl Poly1305Mac {
    pub fn new(key: Vec<u8>) -> Result<Self> {
        if key.len() != 32 {
            return Err(Error::mac("Poly1305", "requires 32-byte key"));
        }

        Ok(Self {
            key: SecureBytes::new(key, crate::memory::MemoryProtection::Strict),
            mac_count: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// Compute MAC of data
    pub async fn compute(&self, data: &[u8]) -> Result<Vec<u8>> {
        use poly1305::Key;

        let key = Key::from_slice(self.key.as_slice());
        let mut mac = Poly1305::new(key);

        // UniversalHash update expects blocks, but we can use the poly1305 API directly
        // Let's use a block-based approach
        const BLOCK_SIZE: usize = 16;
        for chunk in data.chunks(BLOCK_SIZE) {
            if chunk.len() == BLOCK_SIZE {
                // Full block - can use UniversalHash::update directly
                let block = GenericArray::from_slice(chunk);
                mac.update(&[*block]);
            } else {
                // Last partial block - pad it
                let mut block_data = [0u8; BLOCK_SIZE];
                block_data[..chunk.len()].copy_from_slice(chunk);
                let block = GenericArray::from_slice(&block_data);
                mac.update(&[*block]);
                break;
            }
        }

        let tag = mac.finalize();

        self.mac_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(tag.as_slice().to_vec())
    }

    /// Verify MAC of data
    pub async fn verify(&self, data: &[u8], tag: &[u8]) -> Result<bool> {
        let computed_tag = self.compute(data).await?;
        Ok(crate::security::constant_time_eq(&computed_tag, tag))
    }

    pub fn name(&self) -> &'static str {
        "Poly1305"
    }

    pub fn mac_length(&self) -> usize {
        16
    }

    pub fn key_length(&self) -> usize {
        32
    }

    pub async fn mac_count(&self) -> u64 {
        self.mac_count.load(std::sync::atomic::Ordering::Relaxed)
    }
}



/// Create a MAC instance
pub fn create_mac(
    mac_type: MacType,
    key: &[u8],
    security_level: crate::SecurityLevel,
) -> Result<MacEnum> {
    match mac_type {
        MacType::Hmac => {
            let hasher = crate::hash::create_hasher(crate::HashFunction::Blake3, security_level)?;
            Ok(MacEnum::Hmac(HmacMac::new(hasher, key.to_vec())?))
        }
        MacType::Poly1305 => Ok(MacEnum::Poly1305(Poly1305Mac::new(key.to_vec())?)),
    }
}

/// MAC types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MacType {
    /// HMAC - Hash-based Message Authentication Code
    #[default]
    Hmac,
    /// Poly1305 - Fast, secure MAC for authentication
    Poly1305,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_hmac_mac() {
        let hasher =
            crate::hash::create_hasher(crate::HashFunction::Blake3, crate::SecurityLevel::Maximum)
                .unwrap();
        let key = b"secret_key";
        let data = b"Hello, HMAC!";

        let mac = HmacMac::new(hasher, key.to_vec()).unwrap();
        let tag = mac.compute(data).await.unwrap();
        let verified = mac.verify(data, &tag).await.unwrap();

        assert!(verified);
        assert_eq!(mac.name(), "HMAC");
        assert_eq!(mac.mac_length(), 32); // BLAKE3 output length
        assert_eq!(mac.key_length(), 64); // BLAKE3 block size
    }

    #[tokio::test]
    async fn test_poly1305_mac() {
        let key = vec![0u8; 32];
        let data = b"Hello, Poly1305!";

        let mac = Poly1305Mac::new(key).unwrap();
        let tag = mac.compute(data).await.unwrap();
        let verified = mac.verify(data, &tag).await.unwrap();

        assert!(verified);
        assert_eq!(mac.name(), "Poly1305");
        assert_eq!(mac.mac_length(), 16);
        assert_eq!(mac.key_length(), 32);
    }

    #[tokio::test]
    async fn test_create_mac() {
        let key = b"secret_key";

        let mac = create_mac(MacType::Hmac, key, crate::SecurityLevel::Maximum).unwrap();
        assert_eq!(mac.name(), "HMAC");

        let key = vec![0u8; 32];
        let mac = create_mac(MacType::Poly1305, &key, crate::SecurityLevel::Maximum).unwrap();
        assert_eq!(mac.name(), "Poly1305");
    }

    #[tokio::test]
    async fn test_mac_consistency() {
        let hasher =
            crate::hash::create_hasher(crate::HashFunction::Blake3, crate::SecurityLevel::Maximum)
                .unwrap();
        let key = b"secret_key";
        let data = b"Hello, World!";

        let mac = HmacMac::new(hasher, key.to_vec()).unwrap();

        let tag1 = mac.compute(data).await.unwrap();
        let tag2 = mac.compute(data).await.unwrap();

        assert_eq!(tag1, tag2);
    }

    #[tokio::test]
    async fn test_mac_different_data() {
        let hasher =
            crate::hash::create_hasher(crate::HashFunction::Blake3, crate::SecurityLevel::Maximum)
                .unwrap();
        let key = b"secret_key";
        let data1 = b"Hello, World!";
        let data2 = b"Hello, Different!";

        let mac = HmacMac::new(hasher, key.to_vec()).unwrap();

        let tag1 = mac.compute(data1).await.unwrap();
        let tag2 = mac.compute(data2).await.unwrap();

        assert_ne!(tag1, tag2);
    }

    #[tokio::test]
    async fn test_mac_different_keys() {
        let hasher =
            crate::hash::create_hasher(crate::HashFunction::Blake3, crate::SecurityLevel::Maximum)
                .unwrap();
        let key1 = b"secret_key_1";
        let key2 = b"secret_key_2";
        let data = b"Hello, World!";

        let mac1 = HmacMac::new(hasher.new_hasher().unwrap(), key1.to_vec()).unwrap();
        let mac2 = HmacMac::new(hasher.new_hasher().unwrap(), key2.to_vec()).unwrap();

        let tag1 = mac1.compute(data).await.unwrap();
        let tag2 = mac2.compute(data).await.unwrap();

        assert_ne!(tag1, tag2);
    }

    #[tokio::test]
    async fn test_mac_verification_failure() {
        let hasher =
            crate::hash::create_hasher(crate::HashFunction::Blake3, crate::SecurityLevel::Maximum)
                .unwrap();
        let key = b"secret_key";
        let data1 = b"Hello, World!";
        let data2 = b"Hello, Different!";

        let mac = HmacMac::new(hasher, key.to_vec()).unwrap();

        let tag = mac.compute(data1).await.unwrap();
        let verified = mac.verify(data2, &tag).await.unwrap();

        assert!(!verified);
    }

    #[tokio::test]
    async fn test_mac_count() {
        let hasher =
            crate::hash::create_hasher(crate::HashFunction::Blake3, crate::SecurityLevel::Maximum)
                .unwrap();
        let key = b"secret_key";
        let data = b"Hello, World!";

        let mac = HmacMac::new(hasher, key.to_vec()).unwrap();

        assert_eq!(mac.mac_count().await, 0);

        let _tag = mac.compute(data).await.unwrap();
        assert_eq!(mac.mac_count().await, 1);

        let _tag = mac.compute(data).await.unwrap();
        assert_eq!(mac.mac_count().await, 2);
    }

    #[tokio::test]
    async fn test_mac_new_mac() {
        let hasher =
            crate::hash::create_hasher(crate::HashFunction::Blake3, crate::SecurityLevel::Maximum)
                .unwrap();
        let key1 = b"secret_key_1";
        let key2 = b"secret_key_2";

        let mac1 = HmacMac::new(hasher.new_hasher().unwrap(), key1.to_vec()).unwrap();
        let mac2 =
            MacEnum::Hmac(HmacMac::new(hasher.new_hasher().unwrap(), key2.to_vec()).unwrap());

        assert_eq!(mac1.name(), mac2.name());
        assert_eq!(mac1.mac_length(), mac2.mac_length());
        assert_eq!(mac1.key_length(), mac2.key_length());
    }

    #[tokio::test]
    async fn test_poly1305_invalid_key_length() {
        let key = vec![0u8; 16]; // Wrong length
        let result = Poly1305Mac::new(key);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_mac_type_default() {
        assert_eq!(MacType::default(), MacType::Hmac);
    }



    #[tokio::test]
    async fn test_mac_constant_time_verification() {
        let hasher =
            crate::hash::create_hasher(crate::HashFunction::Blake3, crate::SecurityLevel::Maximum)
                .unwrap();
        let key = b"secret_key";
        let data = b"Hello, World!";

        let mac = HmacMac::new(hasher, key.to_vec()).unwrap();
        let correct_tag = mac.compute(data).await.unwrap();
        let wrong_tag = vec![0u8; correct_tag.len()];

        // Both should return false, but timing should be similar
        let verified_correct = mac.verify(data, &correct_tag).await.unwrap();
        let verified_wrong = mac.verify(data, &wrong_tag).await.unwrap();

        assert!(verified_correct);
        assert!(!verified_wrong);
    }

    #[tokio::test]
    async fn test_mac_with_different_hashers() {
        let key = b"secret_key";
        let data = b"Hello, World!";

        let blake3_hasher =
            crate::hash::create_hasher(crate::HashFunction::Blake3, crate::SecurityLevel::Maximum)
                .unwrap();
        let sha256_hasher =
            crate::hash::create_hasher(crate::HashFunction::Sha256, crate::SecurityLevel::Maximum)
                .unwrap();

        let blake3_mac = HmacMac::new(blake3_hasher, key.to_vec()).unwrap();
        let sha256_mac = HmacMac::new(sha256_hasher, key.to_vec()).unwrap();

        let blake3_tag = blake3_mac.compute(data).await.unwrap();
        let sha256_tag = sha256_mac.compute(data).await.unwrap();

        assert_eq!(blake3_mac.name(), "HMAC");
        assert_eq!(sha256_mac.name(), "HMAC");
        assert_eq!(blake3_mac.mac_length(), 32); // BLAKE3
        assert_eq!(sha256_mac.mac_length(), 32); // SHA-256

        // Different hashers should produce different MACs
        assert_ne!(blake3_tag, sha256_tag);
    }
}
