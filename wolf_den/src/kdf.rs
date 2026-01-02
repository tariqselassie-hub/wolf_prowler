//! Key Derivation Functions for Wolf Den
//!
//! This module provides various key derivation functions including:
//! - PBKDF2
//! - Argon2
//! - HKDF
//! - Scrypt

use crate::error::{Error, Result};
use crate::hash::HasherEnum;

/// Key Derivation Function enum for type-safe KDF operations
#[derive(Debug)]
pub enum KdfEnum {
    /// Argon2 KDF - memory-hard, resistant to GPU/ASIC attacks
    Argon2(Argon2Kdf),
    /// PBKDF2 KDF - widely supported, proven security
    Pbkdf2(Pbkdf2Kdf),
    /// HKDF KDF - HMAC-based key derivation, suitable for key material
    Hkdf(HkdfKdf),
    /// Scrypt KDF - memory-hard, configurable parameters
    Scrypt(ScryptKdf),
}

impl KdfEnum {
    /// Derive a key from password and salt
    pub async fn derive_key(&self, password: &[u8], salt: &[u8], length: usize) -> Result<Vec<u8>> {
        match self {
            KdfEnum::Argon2(kdf) => kdf.derive_key(password, salt, length).await,
            KdfEnum::Pbkdf2(kdf) => kdf.derive_key(password, salt, length).await,
            KdfEnum::Hkdf(kdf) => kdf.derive_key(password, salt, length).await,
            KdfEnum::Scrypt(kdf) => kdf.derive_key(password, salt, length).await,
        }
    }

    /// Get the KDF name
    pub fn name(&self) -> &'static str {
        match self {
            KdfEnum::Argon2(kdf) => kdf.name(),
            KdfEnum::Pbkdf2(kdf) => kdf.name(),
            KdfEnum::Hkdf(kdf) => kdf.name(),
            KdfEnum::Scrypt(kdf) => kdf.name(),
        }
    }

    /// Check if the KDF is memory-hard
    pub fn is_memory_hard(&self) -> bool {
        match self {
            KdfEnum::Argon2(kdf) => kdf.is_memory_hard(),
            KdfEnum::Pbkdf2(kdf) => kdf.is_memory_hard(),
            KdfEnum::Hkdf(kdf) => kdf.is_memory_hard(),
            KdfEnum::Scrypt(kdf) => kdf.is_memory_hard(),
        }
    }

    /// Get the derivation count
    pub async fn derivation_count(&self) -> u64 {
        match self {
            KdfEnum::Argon2(kdf) => kdf.derivation_count().await,
            KdfEnum::Pbkdf2(kdf) => kdf.derivation_count().await,
            KdfEnum::Hkdf(kdf) => kdf.derivation_count().await,
            KdfEnum::Scrypt(kdf) => kdf.derivation_count().await,
        }
    }

    /// Create new KDF instance
    pub fn new_kdf(&self) -> Result<KdfEnum> {
        // The new_hasher method on HasherEnum now correctly creates a new instance of the same type.
        match self {
            KdfEnum::Argon2(kdf) => Ok(KdfEnum::Argon2(Argon2Kdf::new(kdf.security_level)?)),
            KdfEnum::Pbkdf2(kdf) => Ok(KdfEnum::Pbkdf2(Pbkdf2Kdf::new(
                kdf.security_level,
                kdf.hasher.new_hasher()?,
            )?)),
            KdfEnum::Hkdf(kdf) => Ok(KdfEnum::Hkdf(HkdfKdf::new(
                kdf.security_level,
                kdf.hasher.new_hasher()?,
            )?)),
            KdfEnum::Scrypt(kdf) => Ok(KdfEnum::Scrypt(ScryptKdf::new(kdf.security_level)?)),
        }
    }
}

/// Key derivation wrapper
pub struct KeyDerivation {
    kdf: KdfEnum,
    #[allow(dead_code)]
    security_level: crate::SecurityLevel,
}

impl KeyDerivation {
    pub fn new(security_level: crate::SecurityLevel) -> Result<Self> {
        let kdf = Argon2Kdf::new(security_level)?;
        Ok(Self {
            kdf: KdfEnum::Argon2(kdf),
            security_level,
        })
    }

    pub async fn derive_key(&self, password: &[u8], salt: &[u8], length: usize) -> Result<Vec<u8>> {
        self.kdf.derive_key(password, salt, length).await
    }

    pub fn name(&self) -> &'static str {
        self.kdf.name()
    }

    pub fn is_memory_hard(&self) -> bool {
        self.kdf.is_memory_hard()
    }

    pub async fn derivation_count(&self) -> u64 {
        self.kdf.derivation_count().await
    }
}

/// Argon2 KDF implementation
#[derive(Debug)]
pub struct Argon2Kdf {
    security_level: crate::SecurityLevel,
    derivation_count: std::sync::atomic::AtomicU64,
    params: argon2::Params,
}

impl Argon2Kdf {
    /// Creates a new Argon2Kdf instance with parameters based on the specified security level.
    ///
    /// # Arguments
    /// * `security_level` - The security level to configure the Argon2 parameters
    ///
    /// # Returns
    /// * `Result<Self>` - The configured Argon2Kdf instance or an error if parameters are invalid
    ///
    /// # Security Level Mapping
    /// * `Minimum` - 4096 memory, 3 passes, 1 parallelism, 32-bit output
    /// * `Standard` - 65536 memory, 3 passes, 2 parallelism, 32-bit output
    /// * `Maximum` - 262144 memory, 4 passes, 4 parallelism, 32-bit output
    pub fn new(security_level: crate::SecurityLevel) -> Result<Self> {
        let params = match security_level {
            crate::SecurityLevel::Minimum => argon2::Params::new(4096, 3, 1, Some(32))?,
            crate::SecurityLevel::Standard => argon2::Params::new(65536, 3, 2, Some(32))?,
            crate::SecurityLevel::Maximum => argon2::Params::new(262144, 4, 4, Some(32))?,
        };

        Ok(Self {
            security_level,
            derivation_count: std::sync::atomic::AtomicU64::new(0),
            params,
        })
    }

    /// Derive a key from password and salt
    pub async fn derive_key(&self, password: &[u8], salt: &[u8], length: usize) -> Result<Vec<u8>> {
        let mut key = vec![0u8; length];

        argon2::Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            self.params.clone(),
        )
        .hash_password_into(password, salt, &mut key)
        .map_err(|e| Error::key_derivation("Argon2", format!("error: {}", e)))?;

        self.derivation_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(key)
    }

    pub fn name(&self) -> &'static str {
        "Argon2id"
    }

    pub fn is_memory_hard(&self) -> bool {
        true
    }

    pub async fn derivation_count(&self) -> u64 {
        self.derivation_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// PBKDF2 KDF implementation
#[derive(Debug)]
pub struct Pbkdf2Kdf {
    security_level: crate::SecurityLevel,
    derivation_count: std::sync::atomic::AtomicU64,
    iterations: u32,
    hasher: HasherEnum,
}

impl Pbkdf2Kdf {
    /// Creates a new Pbkdf2Kdf instance with iterations based on the specified security level and hasher.
    ///
    /// # Arguments
    /// * `security_level` - The security level to determine iteration count
    /// * `hasher` - The hash function to use for key derivation
    ///
    /// # Returns
    /// * `Result<Self>` - The configured Pbkdf2Kdf instance
    ///
    /// # Security Level Mapping
    /// * `Minimum` - 100,000 iterations
    /// * `Standard` - 300,000 iterations
    /// * `Maximum` - 1,000,000 iterations
    pub fn new(security_level: crate::SecurityLevel, hasher: HasherEnum) -> Result<Self> {
        let iterations = match security_level {
            crate::SecurityLevel::Minimum => 210_000,
            crate::SecurityLevel::Standard => 600_000,
            crate::SecurityLevel::Maximum => 1_200_000,
        };

        Ok(Self {
            security_level,
            derivation_count: std::sync::atomic::AtomicU64::new(0),
            iterations,
            hasher,
        })
    }

    /// Derive a key from password and salt
    pub async fn derive_key(&self, password: &[u8], salt: &[u8], length: usize) -> Result<Vec<u8>> {
        use pbkdf2::pbkdf2_hmac;

        let mut key = vec![0u8; length];
        pbkdf2_hmac::<sha2::Sha256>(password, salt, self.iterations, &mut key);

        self.derivation_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(key)
    }

    pub fn name(&self) -> &'static str {
        "PBKDF2"
    }

    pub fn is_memory_hard(&self) -> bool {
        false
    }

    pub async fn derivation_count(&self) -> u64 {
        self.derivation_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// HKDF KDF implementation
#[derive(Debug)]
pub struct HkdfKdf {
    security_level: crate::SecurityLevel,
    derivation_count: std::sync::atomic::AtomicU64,
    hasher: HasherEnum,
}

impl HkdfKdf {
    /// Creates a new HkdfKdf instance with the specified security level and hasher.
    ///
    /// # Arguments
    /// * `security_level` - The security level for the KDF instance
    /// * `hasher` - The hash function to use for HMAC-based key derivation
    ///
    /// # Returns
    /// * `Result<Self>` - The configured HkdfKdf instance
    ///
    /// # Notes
    /// HKDF doesn't use iteration counts like PBKDF2, but the security level is stored
    /// for consistency and potential future parameter adjustments.
    pub fn new(security_level: crate::SecurityLevel, hasher: HasherEnum) -> Result<Self> {
        Ok(Self {
            security_level,
            derivation_count: std::sync::atomic::AtomicU64::new(0),
            hasher,
        })
    }

    /// Derive a key from password and salt
    pub async fn derive_key(&self, password: &[u8], salt: &[u8], length: usize) -> Result<Vec<u8>> {
        use hkdf::Hkdf;

        let hk = Hkdf::<sha2::Sha256>::new(Some(salt), password);
        let mut key = vec![0u8; length];

        hk.expand(&b"wolf_den_derivation"[..], &mut key)
            .map_err(|e| Error::key_derivation("HKDF", format!("error: {}", e)))?;

        self.derivation_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(key)
    }

    pub fn name(&self) -> &'static str {
        "HKDF"
    }

    pub fn is_memory_hard(&self) -> bool {
        false
    }

    pub async fn derivation_count(&self) -> u64 {
        self.derivation_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Scrypt KDF implementation
#[derive(Debug)]
pub struct ScryptKdf {
    security_level: crate::SecurityLevel,
    derivation_count: std::sync::atomic::AtomicU64,
    params: scrypt::Params,
}

impl ScryptKdf {
    pub fn new(security_level: crate::SecurityLevel) -> Result<Self> {
        let params = match security_level {
            crate::SecurityLevel::Minimum => scrypt::Params::new(7, 8, 1, 32)?, // N=128
            crate::SecurityLevel::Standard => scrypt::Params::new(14, 8, 2, 32)?, // N=16384
            crate::SecurityLevel::Maximum => scrypt::Params::new(15, 8, 4, 32)?, // N=32768
        };

        Ok(Self {
            security_level,
            derivation_count: std::sync::atomic::AtomicU64::new(0),
            params,
        })
    }

    /// Derive a key from password and salt
    pub async fn derive_key(&self, password: &[u8], salt: &[u8], length: usize) -> Result<Vec<u8>> {
        let mut key = vec![0u8; length];

        scrypt::scrypt(password, salt, &self.params, &mut key)
            .map_err(|e| Error::key_derivation("Scrypt", format!("error: {}", e)))?;

        self.derivation_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(key)
    }

    pub fn name(&self) -> &'static str {
        "Scrypt"
    }

    pub fn is_memory_hard(&self) -> bool {
        true
    }

    pub async fn derivation_count(&self) -> u64 {
        self.derivation_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Create a KDF instance based on security level
pub fn create_kdf(kdf_type: KdfType, security_level: crate::SecurityLevel) -> Result<KdfEnum> {
    match kdf_type {
        KdfType::Argon2 => Ok(KdfEnum::Argon2(Argon2Kdf::new(security_level)?)),
        KdfType::Pbkdf2 => {
            let hasher = crate::hash::create_hasher(crate::HashFunction::Sha256, security_level)?;
            Ok(KdfEnum::Pbkdf2(Pbkdf2Kdf::new(security_level, hasher)?))
        }
        KdfType::Hkdf => {
            let hasher = crate::hash::create_hasher(crate::HashFunction::Sha256, security_level)?;
            Ok(KdfEnum::Hkdf(HkdfKdf::new(security_level, hasher)?))
        }
        KdfType::Scrypt => Ok(KdfEnum::Scrypt(ScryptKdf::new(security_level)?)),
    }
}

/// KDF types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KdfType {
    /// Argon2 KDF - memory-hard, resistant to GPU/ASIC attacks
    #[default]
    Argon2,
    /// PBKDF2 KDF - widely supported, proven security
    Pbkdf2,
    /// HKDF KDF - HMAC-based key derivation, suitable for key material
    Hkdf,
    /// Scrypt KDF - memory-hard, configurable parameters
    Scrypt,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_argon2_kdf() {
        let kdf = Argon2Kdf::new(crate::SecurityLevel::Maximum).unwrap();
        let password = b"secure_password";
        let salt = b"random_salt";
        let length = 32;

        let key = kdf.derive_key(password, salt, length).await.unwrap();

        assert_eq!(key.len(), length);
        assert_eq!(kdf.name(), "Argon2id");
        assert!(kdf.is_memory_hard());
    }

    #[tokio::test]
    async fn test_pbkdf2_kdf() {
        let hasher =
            crate::hash::create_hasher(crate::HashFunction::Sha256, crate::SecurityLevel::Maximum)
                .unwrap();
        let kdf = Pbkdf2Kdf::new(crate::SecurityLevel::Maximum, hasher).unwrap();
        let password = b"secure_password";
        let salt = b"random_salt";
        let length = 32;

        let key = kdf.derive_key(password, salt, length).await.unwrap();

        assert_eq!(key.len(), length);
        assert_eq!(kdf.name(), "PBKDF2");
        assert!(!kdf.is_memory_hard());
    }

    #[tokio::test]
    async fn test_hkdf_kdf() {
        let hasher =
            crate::hash::create_hasher(crate::HashFunction::Sha256, crate::SecurityLevel::Maximum)
                .unwrap();
        let kdf = HkdfKdf::new(crate::SecurityLevel::Maximum, hasher).unwrap();
        let password = b"secure_password";
        let salt = b"random_salt";
        let length = 32;

        let key = kdf.derive_key(password, salt, length).await.unwrap();

        assert_eq!(key.len(), length);
        assert_eq!(kdf.name(), "HKDF");
        assert!(!kdf.is_memory_hard());
    }

    #[tokio::test]
    async fn test_scrypt_kdf() {
        let kdf = ScryptKdf::new(crate::SecurityLevel::Maximum).unwrap();
        let password = b"secure_password";
        let salt = b"random_salt";
        let length = 32;

        let key = kdf.derive_key(password, salt, length).await.unwrap();

        assert_eq!(key.len(), length);
        assert_eq!(kdf.name(), "Scrypt");
        assert!(kdf.is_memory_hard());
    }

    #[tokio::test]
    async fn test_key_derivation_wrapper() {
        let kdf = KeyDerivation::new(crate::SecurityLevel::Maximum).unwrap();
        let password = b"secure_password";
        let salt = b"random_salt";
        let length = 32;

        let key = kdf.derive_key(password, salt, length).await.unwrap();

        assert_eq!(key.len(), length);
        assert_eq!(kdf.name(), "Argon2id");
        assert!(kdf.is_memory_hard());
    }

    #[tokio::test]
    async fn test_create_kdf() {
        let kdf = create_kdf(KdfType::Argon2, crate::SecurityLevel::Maximum).unwrap();
        assert_eq!(kdf.name(), "Argon2id");

        let kdf = create_kdf(KdfType::Pbkdf2, crate::SecurityLevel::Maximum).unwrap();
        assert_eq!(kdf.name(), "PBKDF2");

        let kdf = create_kdf(KdfType::Hkdf, crate::SecurityLevel::Maximum).unwrap();
        assert_eq!(kdf.name(), "HKDF");

        let kdf = create_kdf(KdfType::Scrypt, crate::SecurityLevel::Maximum).unwrap();
        assert_eq!(kdf.name(), "Scrypt");
    }

    #[tokio::test]
    async fn test_kdf_consistency() {
        let kdf = Argon2Kdf::new(crate::SecurityLevel::Maximum).unwrap();
        let password = b"secure_password";
        let salt = b"random_salt";
        let length = 32;

        let key1 = kdf.derive_key(password, salt, length).await.unwrap();
        let key2 = kdf.derive_key(password, salt, length).await.unwrap();

        assert_eq!(key1, key2);
    }

    #[tokio::test]
    async fn test_kdf_different_salts() {
        let kdf = Argon2Kdf::new(crate::SecurityLevel::Maximum).unwrap();
        let password = b"secure_password";
        let salt1 = b"random_salt_1";
        let salt2 = b"random_salt_2";
        let length = 32;

        let key1 = kdf.derive_key(password, salt1, length).await.unwrap();
        let key2 = kdf.derive_key(password, salt2, length).await.unwrap();

        assert_ne!(key1, key2);
    }

    #[tokio::test]
    async fn test_kdf_different_passwords() {
        let kdf = Argon2Kdf::new(crate::SecurityLevel::Maximum).unwrap();
        let password1 = b"secure_password_1";
        let password2 = b"secure_password_2";
        let salt = b"random_salt";
        let length = 32;

        let key1 = kdf.derive_key(password1, salt, length).await.unwrap();
        let key2 = kdf.derive_key(password2, salt, length).await.unwrap();

        assert_ne!(key1, key2);
    }

    #[tokio::test]
    async fn test_kdf_derivation_count() {
        let kdf = Argon2Kdf::new(crate::SecurityLevel::Maximum).unwrap();
        let password = b"secure_password";
        let salt = b"random_salt";
        let length = 32;

        assert_eq!(kdf.derivation_count().await, 0);

        let _key = kdf.derive_key(password, salt, length).await.unwrap();
        assert_eq!(kdf.derivation_count().await, 1);

        let _key = kdf.derive_key(password, salt, length).await.unwrap();
        assert_eq!(kdf.derivation_count().await, 2);
    }

    #[tokio::test]
    async fn test_kdf_new_kdf() {
        let kdf = KdfEnum::Argon2(Argon2Kdf::new(crate::SecurityLevel::Maximum).unwrap());
        let new_kdf = kdf.new_kdf().unwrap();

        assert_eq!(kdf.name(), new_kdf.name());
        assert_eq!(kdf.is_memory_hard(), new_kdf.is_memory_hard());
    }

    #[tokio::test]
    async fn test_kdf_type_default() {
        assert_eq!(KdfType::default(), KdfType::Argon2);
    }

    #[tokio::test]
    async fn test_security_levels() {
        let minimum = Argon2Kdf::new(crate::SecurityLevel::Minimum).unwrap();
        let standard = Argon2Kdf::new(crate::SecurityLevel::Standard).unwrap();
        let maximum = Argon2Kdf::new(crate::SecurityLevel::Maximum).unwrap();

        assert_eq!(minimum.name(), "Argon2id");
        assert_eq!(standard.name(), "Argon2id");
        assert_eq!(maximum.name(), "Argon2id");

        // All should be memory-hard
        assert!(minimum.is_memory_hard());
        assert!(standard.is_memory_hard());
        assert!(maximum.is_memory_hard());
    }

    #[tokio::test]
    async fn test_different_kdf_types() {
        let password = b"secure_password";
        let salt = b"random_salt";
        let length = 32;

        let argon2 = create_kdf(KdfType::Argon2, crate::SecurityLevel::Maximum).unwrap();
        let pbkdf2 = create_kdf(KdfType::Pbkdf2, crate::SecurityLevel::Maximum).unwrap();
        let hkdf = create_kdf(KdfType::Hkdf, crate::SecurityLevel::Maximum).unwrap();
        let scrypt = create_kdf(KdfType::Scrypt, crate::SecurityLevel::Maximum).unwrap();

        let argon2_key = argon2.derive_key(password, salt, length).await.unwrap();
        let pbkdf2_key = pbkdf2.derive_key(password, salt, length).await.unwrap();
        let hkdf_key = hkdf.derive_key(password, salt, length).await.unwrap();
        let scrypt_key = scrypt.derive_key(password, salt, length).await.unwrap();

        // All should have the same length
        assert_eq!(argon2_key.len(), length);
        assert_eq!(pbkdf2_key.len(), length);
        assert_eq!(hkdf_key.len(), length);
        assert_eq!(scrypt_key.len(), length);

        // But should produce different outputs
        assert_ne!(argon2_key, pbkdf2_key);
        assert_ne!(argon2_key, hkdf_key);
        assert_ne!(argon2_key, scrypt_key);
        assert_ne!(pbkdf2_key, hkdf_key);
        assert_ne!(pbkdf2_key, scrypt_key);
        assert_ne!(hkdf_key, scrypt_key);
    }
}
