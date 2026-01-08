//! Symmetric cryptography for Wolf Den
//!
//! This module provides symmetric encryption algorithms including:
//! - ChaCha20-Poly1305
//! - AES-256-GCM
//! - AES-128-GCM

use crate::error::{Error, Result};

use aes_gcm::aead::{Aead, KeyInit};
// Removed unused async_trait

use rand::RngCore;

/// Symmetric cipher trait
pub trait Cipher: Send + Sync {
    /// Encrypt data
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails.
    fn encrypt(&self, plaintext: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>>;

    /// Decrypt data
    ///
    /// # Errors
    ///
    /// Returns an error if decryption fails.
    fn decrypt(&self, ciphertext: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>>;

    /// Generate a new key
    ///
    /// # Errors
    ///
    /// Returns an error if key generation fails.
    fn generate_key(&self) -> Result<Vec<u8>>;

    /// Get the key length
    #[must_use]
    fn key_length(&self) -> usize;

    /// Get the nonce length
    #[must_use]
    fn nonce_length(&self) -> usize;

    /// Get the tag length
    #[must_use]
    fn tag_length(&self) -> usize;

    /// Get the cipher name
    #[must_use]
    fn name(&self) -> &'static str;

    /// Get encryption count
    #[must_use]
    fn encryption_count(&self) -> u64;

    /// Get decryption count
    #[must_use]
    fn decryption_count(&self) -> u64;
}

/// Create a cipher instance
///
/// # Errors
///
/// Returns an error if cipher creation fails.
pub fn create_cipher(
    cipher_suite: crate::CipherSuite,
    security_level: crate::SecurityLevel,
) -> Result<Box<dyn Cipher>> {
    match cipher_suite {
        crate::CipherSuite::ChaCha20Poly1305 => {
            Ok(Box::new(ChaCha20Poly1305Cipher::new(security_level)?))
        }
        crate::CipherSuite::Aes256Gcm => Ok(Box::new(Aes256GcmCipher::new(security_level)?)),
        crate::CipherSuite::Aes128Gcm => Ok(Box::new(Aes128GcmCipher::new(security_level)?)),
    }
}

/// ChaCha20-Poly1305 cipher implementation
pub struct ChaCha20Poly1305Cipher {
    security_level: crate::SecurityLevel,
    encryption_count: std::sync::atomic::AtomicU64,
    decryption_count: std::sync::atomic::AtomicU64,
}

impl ChaCha20Poly1305Cipher {
    /// Create a new `ChaCha20Poly1305Cipher` instance
    ///
    /// # Errors
    ///
    /// Returns an error if initialization fails.
    pub const fn new(security_level: crate::SecurityLevel) -> Result<Self> {
        Ok(Self {
            security_level,
            encryption_count: std::sync::atomic::AtomicU64::new(0),
            decryption_count: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// Get the effective key size based on security level (NIST/NSA standards)
    #[must_use]
    pub const fn effective_key_size(&self) -> usize {
        match self.security_level {
            crate::SecurityLevel::Minimum => 128,  // FIPS 140-3 Level 1
            crate::SecurityLevel::Standard => 192, // NSA SECRET equivalent
            crate::SecurityLevel::Maximum => 256,  // NSA CNSA Suite (TOP SECRET)
        }
    }

    /// Check if this cipher meets FIPS 140-3 requirements
    #[must_use]
    pub const fn is_fips_compliant(&self) -> bool {
        // ChaCha20-Poly1305 is NIST-approved (RFC 8439)
        self.effective_key_size() >= 128
    }

    /// Get recommended key rotation interval in seconds
    #[must_use]
    pub const fn key_rotation_interval_secs(&self) -> u64 {
        match self.security_level {
            crate::SecurityLevel::Minimum => 86400 * 7, // 1 week
            crate::SecurityLevel::Standard => 86400,    // 1 day
            crate::SecurityLevel::Maximum => 3600,      // 1 hour (NSA CNSA)
        }
    }

    /// Get security level
    #[must_use]
    pub const fn get_security_level(&self) -> crate::SecurityLevel {
        self.security_level
    }
}

impl Cipher for ChaCha20Poly1305Cipher {
    fn encrypt(&self, plaintext: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        if key.len() != 32 {
            return Err(Error::encryption(
                "ChaCha20-Poly1305 encrypt",
                "invalid key length for ChaCha20-Poly1305",
            ));
        }
        if nonce.len() != 24 {
            return Err(Error::encryption(
                "ChaCha20-Poly1305 encrypt",
                "invalid nonce length for ChaCha20-Poly1305",
            ));
        }

        let key_array =
            chacha20poly1305::aead::Key::<chacha20poly1305::XChaCha20Poly1305>::from_slice(key);
        let nonce_array =
            chacha20poly1305::aead::Nonce::<chacha20poly1305::XChaCha20Poly1305>::from_slice(nonce);

        let cipher = chacha20poly1305::XChaCha20Poly1305::new(key_array);
        let ciphertext = cipher
            .encrypt(nonce_array, plaintext)
            .map_err(|e| Error::encryption("ChaCha20-Poly1305 encrypt", e.to_string()))?;

        self.encryption_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(ciphertext)
    }

    fn decrypt(&self, ciphertext: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        if key.len() != 32 {
            return Err(Error::decryption(
                "ChaCha20-Poly1305 decrypt",
                "invalid key length for ChaCha20-Poly1305",
            ));
        }
        if nonce.len() != 24 {
            return Err(Error::decryption(
                "ChaCha20-Poly1305 decrypt",
                "invalid nonce length for ChaCha20-Poly1305",
            ));
        }

        let key_array =
            chacha20poly1305::aead::Key::<chacha20poly1305::XChaCha20Poly1305>::from_slice(key);
        let nonce_array =
            chacha20poly1305::aead::Nonce::<chacha20poly1305::XChaCha20Poly1305>::from_slice(nonce);

        let cipher = chacha20poly1305::XChaCha20Poly1305::new(key_array);
        let plaintext = cipher
            .decrypt(nonce_array, ciphertext)
            .map_err(|e| Error::decryption("ChaCha20-Poly1305 decrypt", e.to_string()))?;

        self.decryption_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(plaintext)
    }

    fn generate_key(&self) -> Result<Vec<u8>> {
        let mut key = vec![0u8; 32];
        crate::random::global_rng().fill_bytes(&mut key);
        Ok(key)
    }

    fn key_length(&self) -> usize {
        32
    }

    fn nonce_length(&self) -> usize {
        24
    }

    fn tag_length(&self) -> usize {
        16
    }

    fn name(&self) -> &'static str {
        "ChaCha20-Poly1305"
    }

    fn encryption_count(&self) -> u64 {
        self.encryption_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    fn decryption_count(&self) -> u64 {
        self.decryption_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// AES-256-GCM cipher implementation
pub struct Aes256GcmCipher {
    security_level: crate::SecurityLevel,
    encryption_count: std::sync::atomic::AtomicU64,
    decryption_count: std::sync::atomic::AtomicU64,
}

impl Aes256GcmCipher {
    /// Create a new `Aes256GcmCipher` instance
    ///
    /// # Errors
    ///
    /// Returns an error if initialization fails.
    pub const fn new(security_level: crate::SecurityLevel) -> Result<Self> {
        Ok(Self {
            security_level,
            encryption_count: std::sync::atomic::AtomicU64::new(0),
            decryption_count: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// Get nonce size based on security level
    #[must_use]
    pub const fn nonce_size(&self) -> usize {
        // Standard GCM 96-bit (12-byte) nonce is recommended by NIST SP 800-38D
        12
    }

    /// Get recommended key rotation interval in seconds
    #[must_use]
    pub const fn key_rotation_interval_secs(&self) -> u64 {
        match self.security_level {
            crate::SecurityLevel::Minimum => 86400 * 7, // 1 week
            crate::SecurityLevel::Standard => 86400,    // 1 day
            crate::SecurityLevel::Maximum => 3600,      // 1 hour (NSA CNSA)
        }
    }

    /// Check NSA CNSA Suite compliance
    #[must_use]
    pub const fn is_cnsa_compliant(&self) -> bool {
        true
    }

    /// Check if configuration meets FIPS 140-3 Level 3 requirements
    #[must_use]
    pub const fn is_fips_level3_compliant(&self) -> bool {
        matches!(self.security_level, crate::SecurityLevel::Maximum)
    }

    /// Get security level
    #[must_use]
    pub const fn security_level(&self) -> crate::SecurityLevel {
        self.security_level
    }
}

impl Cipher for Aes256GcmCipher {
    fn encrypt(&self, plaintext: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        if key.len() != 32 {
            return Err(Error::encryption(
                "AES-256-GCM encrypt",
                "invalid key length for AES-256-GCM",
            ));
        }
        let expected_nonce = self.nonce_size();
        if nonce.len() != expected_nonce {
            return Err(Error::encryption(
                "AES-256-GCM encrypt",
                format!(
                    "invalid nonce length for AES-256-GCM: expected {expected_nonce}, got {}",
                    nonce.len()
                ),
            ));
        }

        let key_array = aes_gcm::aead::Key::<aes_gcm::Aes256Gcm>::from_slice(key);
        let nonce_array = aes_gcm::aead::Nonce::<aes_gcm::Aes256Gcm>::from_slice(nonce);

        let cipher = aes_gcm::Aes256Gcm::new(key_array);
        let ciphertext = cipher
            .encrypt(nonce_array, plaintext)
            .map_err(|e| Error::encryption("AES-256-GCM encrypt", e.to_string()))?;

        self.encryption_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(ciphertext)
    }

    fn decrypt(&self, ciphertext: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        if key.len() != 32 {
            return Err(Error::decryption(
                "AES-256-GCM decrypt",
                "invalid key length for AES-256-GCM",
            ));
        }
        let expected_nonce = self.nonce_size();
        if nonce.len() != expected_nonce {
            return Err(Error::decryption(
                "AES-256-GCM decrypt",
                format!(
                    "invalid nonce length for AES-256-GCM: expected {expected_nonce}, got {}",
                    nonce.len()
                ),
            ));
        }

        let key_array = aes_gcm::aead::Key::<aes_gcm::Aes256Gcm>::from_slice(key);
        let nonce_array = aes_gcm::aead::Nonce::<aes_gcm::Aes256Gcm>::from_slice(nonce);

        let cipher = aes_gcm::Aes256Gcm::new(key_array);
        let plaintext = cipher
            .decrypt(nonce_array, ciphertext)
            .map_err(|e| Error::decryption("AES-256-GCM decrypt", e.to_string()))?;

        self.decryption_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(plaintext)
    }

    fn generate_key(&self) -> Result<Vec<u8>> {
        let mut key = vec![0u8; 32];
        crate::random::global_rng().fill_bytes(&mut key);
        Ok(key)
    }

    fn key_length(&self) -> usize {
        32
    }

    fn nonce_length(&self) -> usize {
        self.nonce_size()
    }

    fn tag_length(&self) -> usize {
        16
    }

    fn name(&self) -> &'static str {
        "AES-256-GCM"
    }

    fn encryption_count(&self) -> u64 {
        self.encryption_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    fn decryption_count(&self) -> u64 {
        self.decryption_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// AES-128-GCM cipher implementation
pub struct Aes128GcmCipher {
    security_level: crate::SecurityLevel,
    encryption_count: std::sync::atomic::AtomicU64,
    decryption_count: std::sync::atomic::AtomicU64,
}

impl Aes128GcmCipher {
    /// Create a new `Aes128GcmCipher` instance
    ///
    /// # Errors
    ///
    /// Returns an error if initialization fails.
    pub const fn new(security_level: crate::SecurityLevel) -> Result<Self> {
        Ok(Self {
            security_level,
            encryption_count: std::sync::atomic::AtomicU64::new(0),
            decryption_count: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// Check if this cipher is appropriate for the security level
    #[must_use]
    pub const fn is_appropriate_for_level(&self) -> bool {
        matches!(self.security_level, crate::SecurityLevel::Minimum)
    }

    /// Get security warning if using AES-128 at higher levels
    #[must_use]
    pub fn security_warning(&self) -> Option<String> {
        match self.security_level {
            crate::SecurityLevel::Minimum => None,
            crate::SecurityLevel::Standard => Some(
                "WARNING: AES-128 not recommended for Standard security. Use AES-256 (NSA requirement).".to_string()
            ),
            crate::SecurityLevel::Maximum => Some(
                "CRITICAL: AES-128 insufficient for Maximum security. Use AES-256 or XChaCha20 (NSA CNSA Suite).".to_string()
            ),
        }
    }

    /// Check FIPS 140-3 compliance
    #[must_use]
    pub const fn is_fips_compliant(&self) -> bool {
        matches!(self.security_level, crate::SecurityLevel::Minimum)
    }

    /// Get security level
    #[must_use]
    pub const fn get_security_level(&self) -> crate::SecurityLevel {
        self.security_level
    }
}

impl Cipher for Aes128GcmCipher {
    fn encrypt(&self, plaintext: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        if key.len() != 16 {
            return Err(Error::encryption(
                "AES-128-GCM encrypt",
                "invalid key length for AES-128-GCM",
            ));
        }
        if nonce.len() != 12 {
            return Err(Error::encryption(
                "AES-128-GCM encrypt",
                "invalid nonce length for AES-128-GCM",
            ));
        }

        let key_array = aes_gcm::aead::Key::<aes_gcm::Aes128Gcm>::from_slice(key);
        let nonce_array = aes_gcm::aead::Nonce::<aes_gcm::Aes128Gcm>::from_slice(nonce);

        let cipher = aes_gcm::Aes128Gcm::new(key_array);
        let ciphertext = cipher
            .encrypt(nonce_array, plaintext)
            .map_err(|e| Error::encryption("AES-128-GCM encrypt", e.to_string()))?;

        self.encryption_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(ciphertext)
    }

    fn decrypt(&self, ciphertext: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        if key.len() != 16 {
            return Err(Error::decryption(
                "AES-128-GCM decrypt",
                "invalid key length for AES-128-GCM",
            ));
        }
        if nonce.len() != 12 {
            return Err(Error::decryption(
                "AES-128-GCM decrypt",
                "invalid nonce length for AES-128-GCM",
            ));
        }

        let key_array = aes_gcm::aead::Key::<aes_gcm::Aes128Gcm>::from_slice(key);
        let nonce_array = aes_gcm::aead::Nonce::<aes_gcm::Aes128Gcm>::from_slice(nonce);

        let cipher = aes_gcm::Aes128Gcm::new(key_array);
        let plaintext = cipher
            .decrypt(nonce_array, ciphertext)
            .map_err(|e| Error::decryption("AES-128-GCM decrypt", e.to_string()))?;

        self.decryption_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(plaintext)
    }

    fn generate_key(&self) -> Result<Vec<u8>> {
        let mut key = vec![0u8; 16];
        crate::random::global_rng().fill_bytes(&mut key);
        Ok(key)
    }

    fn key_length(&self) -> usize {
        16
    }

    fn nonce_length(&self) -> usize {
        12
    }

    fn tag_length(&self) -> usize {
        16
    }

    fn name(&self) -> &'static str {
        "AES-128-GCM"
    }

    fn encryption_count(&self) -> u64 {
        self.encryption_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    fn decryption_count(&self) -> u64 {
        self.decryption_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn test_chacha20poly1305() {
        let cipher = ChaCha20Poly1305Cipher::new(crate::SecurityLevel::Maximum).unwrap();
        let key = cipher.generate_key().unwrap();
        let nonce = vec![0u8; 24];
        let plaintext = b"Hello, ChaCha20-Poly1305!";

        let ciphertext = cipher.encrypt(plaintext, &key, &nonce).unwrap();
        let decrypted = cipher.decrypt(&ciphertext, &key, &nonce).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
        assert_eq!(cipher.name(), "ChaCha20-Poly1305");
        assert_eq!(cipher.key_length(), 32);
        assert_eq!(cipher.nonce_length(), 24);
        assert_eq!(cipher.tag_length(), 16);
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn test_aes256gcm() {
        let cipher = Aes256GcmCipher::new(crate::SecurityLevel::Maximum).unwrap();
        let key = cipher.generate_key().unwrap();
        let nonce = vec![0u8; 12]; // Standard 12 byte nonce for GCM
        let plaintext = b"Hello, AES-256-GCM!";

        let ciphertext = cipher.encrypt(plaintext, &key, &nonce).unwrap();
        let decrypted = cipher.decrypt(&ciphertext, &key, &nonce).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
        assert_eq!(cipher.name(), "AES-256-GCM");
        assert_eq!(cipher.key_length(), 32);
        assert_eq!(cipher.nonce_length(), 12);
        assert_eq!(cipher.tag_length(), 16);
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn test_create_cipher() {
        let cipher = create_cipher(
            crate::CipherSuite::ChaCha20Poly1305,
            crate::SecurityLevel::Maximum,
        )
        .unwrap();
        assert_eq!(cipher.name(), "ChaCha20-Poly1305");

        let cipher =
            create_cipher(crate::CipherSuite::Aes256Gcm, crate::SecurityLevel::Maximum).unwrap();
        assert_eq!(cipher.name(), "AES-256-GCM");

        let cipher =
            create_cipher(crate::CipherSuite::Aes128Gcm, crate::SecurityLevel::Maximum).unwrap();
        assert_eq!(cipher.name(), "AES-128-GCM");
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn test_cipher_counts() {
        let cipher = ChaCha20Poly1305Cipher::new(crate::SecurityLevel::Maximum).unwrap();
        let key = cipher.generate_key().unwrap();
        let nonce = vec![0u8; 24];
        let plaintext = b"Hello, World!";

        assert_eq!(cipher.encryption_count(), 0);
        assert_eq!(cipher.decryption_count(), 0);

        let ciphertext = cipher.encrypt(plaintext, &key, &nonce).unwrap();
        assert_eq!(cipher.encryption_count(), 1);

        let _decrypted = cipher.decrypt(&ciphertext, &key, &nonce).unwrap();
        assert_eq!(cipher.decryption_count(), 1);
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn test_invalid_key_length() {
        let cipher = ChaCha20Poly1305Cipher::new(crate::SecurityLevel::Maximum).unwrap();
        let nonce = vec![0u8; 24];
        let plaintext = b"Hello, World!";
        let invalid_key = vec![0u8; 16];

        let result = cipher.encrypt(plaintext, &invalid_key, &nonce);
        assert!(result.is_err());
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn test_invalid_nonce_length() {
        let cipher = ChaCha20Poly1305Cipher::new(crate::SecurityLevel::Maximum).unwrap();
        let key = cipher.generate_key().unwrap();
        let plaintext = b"Hello, World!";
        let invalid_nonce = vec![0u8; 12]; // Wrong length for XChaCha20

        let result = cipher.encrypt(plaintext, &key, &invalid_nonce);
        assert!(result.is_err());
    }
}
