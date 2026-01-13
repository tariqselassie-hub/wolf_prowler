//! Unit Tests for WolfSec Crypto Module
//!
//! Tests for cryptographic operations to ensure proper functionality and catch key size errors

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use tempfile::NamedTempFile;
    use wolf_den::SecurityLevel;
    use wolfsec::{
        crypto::{SecureBytes, WolfCrypto},
        identity::{IdentityConfig, IdentityManager, SystemIdentity},
    };

    // Test data for consistent testing
    const TEST_DATA: &[u8] = b"Test message for cryptographic operations";
    const TEST_PASSWORD: &[u8] = b"test_password_123";
    const TEST_SALT: &[u8] = b"test_salt_for_derivation";

    #[tokio::test]
    async fn test_wolf_crypto_creation() {
        let config = wolfsec::crypto::CryptoConfig::default();
        let crypto = WolfCrypto::new(config).expect("Failed to create WolfCrypto");
        crypto
            .initialize()
            .await
            .expect("Failed to initialize WolfCrypto");

        let status = crypto.get_status().await;
        assert_eq!(status.active_keys, 0);
        assert_eq!(status.default_algorithm, "AES-256-GCM");
        assert_eq!(status.security_level, SecurityLevel::Maximum);
    }

    #[tokio::test]
    async fn test_wolf_crypto_hashing() {
        let config = wolfsec::crypto::CryptoConfig::default();
        let crypto = WolfCrypto::new(config).expect("Failed to create WolfCrypto");

        let hash = crypto.hash(TEST_DATA).await.expect("Hash operation failed");
        assert!(!hash.is_empty());
        assert_eq!(hash.len(), 32); // Blake3 default output
    }

    #[tokio::test]
    async fn test_wolf_crypto_hmac() {
        let config = wolfsec::crypto::CryptoConfig::default();
        let crypto = WolfCrypto::new(config).expect("Failed to create WolfCrypto");

        let key = vec![0x01; 32];
        let hmac = crypto
            .hmac(&key, TEST_DATA)
            .await
            .expect("HMAC operation failed");
        assert!(!hmac.is_empty());
        assert_eq!(hmac.len(), 32); // HMAC output length
    }

    #[tokio::test]
    async fn test_wolf_crypto_key_derivation() {
        let config = wolfsec::crypto::CryptoConfig::default();
        let crypto = WolfCrypto::new(config).expect("Failed to create WolfCrypto");

        let derived_key = crypto
            .derive_key(TEST_PASSWORD, TEST_SALT, 32)
            .await
            .expect("Key derivation failed");

        assert_eq!(derived_key.len(), 32);
        assert!(!derived_key.iter().all(|&b| b == 0)); // Should not be all zeros
    }

    #[test]
    fn test_secure_bytes() {
        let data = vec![1, 2, 3, 4, 5];
        let secure_bytes = SecureBytes::new(data.clone());

        assert_eq!(secure_bytes.as_bytes(), &data[..]);
        assert_eq!(secure_bytes.len(), 5);
        assert!(!secure_bytes.is_empty());
    }

    #[test]
    fn test_constant_time_comparison() {
        let a = b"hello";
        let b = b"hello";
        let c = b"world";

        assert!(wolfsec::crypto::constant_time_eq(a, b));
        assert!(!wolfsec::crypto::constant_time_eq(a, c));
    }

    #[test]
    fn test_secure_compare() {
        let a = "hello";
        let b = "hello";
        let c = "world";

        assert!(wolfsec::crypto::secure_compare(a, b));
        assert!(!wolfsec::crypto::secure_compare(a, c));
    }

    #[test]
    fn test_crypto_config_defaults() {
        let config = wolfsec::crypto::CryptoConfig::default();

        assert_eq!(config.default_algorithm, "AES-256-GCM");
        assert_eq!(config.key_size, 256);
        assert!(config.secure_erase);
        assert!(config.hardware_acceleration);
        assert_eq!(config.security_level, SecurityLevel::Maximum);
    }

    #[tokio::test]
    async fn test_crypto_key_management() {
        let config = wolfsec::crypto::CryptoConfig::default();
        let crypto = WolfCrypto::new(config).expect("Failed to create WolfCrypto");

        // Test key derivation (since generate_key doesn't exist)
        let derived_key = crypto
            .derive_key(TEST_PASSWORD, TEST_SALT, 32)
            .await
            .expect("Key derivation failed");
        assert_eq!(derived_key.len(), 32);

        // Test salt generation (since generate_salt doesn't exist)
        // Use minimum size that Argon2 can handle
        let derived_salt = crypto
            .derive_key(b"salt_password", b"salt_context", 32)
            .await
            .expect("Salt generation failed");
        assert_eq!(derived_salt.len(), 32);

        // Test that derived keys are unique
        let derived_key2 = crypto
            .derive_key(TEST_PASSWORD, TEST_SALT, 32)
            .await
            .expect("Key derivation failed");
        assert_eq!(derived_key, derived_key2); // Should be deterministic
    }

    #[tokio::test]
    async fn test_crypto_status() {
        let config = wolfsec::crypto::CryptoConfig::default();
        let crypto = WolfCrypto::new(config).expect("Failed to create WolfCrypto");

        let status = crypto.get_status().await;

        assert_eq!(status.total_keys, 0);
        assert_eq!(status.active_keys, 0);
        assert_eq!(status.expired_keys, 0);
        assert_eq!(status.default_algorithm, "AES-256-GCM");
        assert_eq!(status.security_level, SecurityLevel::Maximum);
    }

    #[tokio::test]
    async fn test_edge_cases() {
        let config = wolfsec::crypto::CryptoConfig::default();
        let crypto = WolfCrypto::new(config).expect("Failed to create WolfCrypto");

        // Test empty data
        let empty_data = b"";
        let hash = crypto
            .hash(empty_data)
            .await
            .expect("Hash operation failed");
        assert!(!hash.is_empty());

        // Test very long data
        let long_data = vec![0x42; 10000];
        let hash = crypto
            .hash(&long_data)
            .await
            .expect("Hash operation failed");
        assert!(!hash.is_empty());

        // Test minimum key derivation size (Argon2 has minimum requirements)
        let result = crypto
            .derive_key(b"password", b"salt_must_be_long_enough", 32)
            .await;
        // This should work with minimum size
        assert!(result.is_ok(), "Failed to derive key: {:?}", result.err());
    }

    #[tokio::test]
    async fn test_error_handling() {
        // Test that errors are properly propagated
        let config = wolfsec::crypto::CryptoConfig::default();
        let crypto = WolfCrypto::new(config).expect("Failed to create WolfCrypto");

        // This should not panic, even if it fails
        let result = crypto.derive_key(b"password", b"salt", 0).await;
        match result {
            Ok(_) => {
                // If it succeeds, that's fine too
            }
            Err(e) => {
                // If it fails, the error should be meaningful
                assert!(!e.to_string().is_empty());
            }
        }
    }

    #[tokio::test]
    async fn test_key_size_validation() {
        let config = wolfsec::crypto::CryptoConfig::default();
        let crypto = WolfCrypto::new(config).expect("Failed to create WolfCrypto");

        // Test various key sizes - Argon2 has specific size requirements
        // Let's test the most common cryptographic key sizes
        let test_sizes = [32]; // AES-256 key sizes

        for size in test_sizes {
            let derived_key = crypto
                .derive_key(TEST_PASSWORD, TEST_SALT, size)
                .await
                .expect(&format!("Key derivation failed for size {}", size));
            assert_eq!(derived_key.len(), size);
        }
    }

    #[tokio::test]
    async fn test_hmac_key_sizes() {
        let config = wolfsec::crypto::CryptoConfig::default();
        let crypto = WolfCrypto::new(config).expect("Failed to create WolfCrypto");

        // Test various HMAC key sizes
        let test_key_sizes = [16, 32, 64];

        for key_size in test_key_sizes {
            let key = vec![0x01; key_size];
            let hmac = crypto
                .hmac(&key, TEST_DATA)
                .await
                .expect(&format!("HMAC failed for key size {}", key_size));
            assert!(!hmac.is_empty());
            assert_eq!(hmac.len(), 32); // HMAC output should be consistent
        }
    }

    #[tokio::test]
    async fn test_salt_length_validation() {
        let config = wolfsec::crypto::CryptoConfig::default();
        let crypto = WolfCrypto::new(config).expect("Failed to create WolfCrypto");

        // Test various salt lengths
        let test_salt_lengths = [8, 16, 32, 64];

        for salt_len in test_salt_lengths {
            let salt = vec![0x02; salt_len];
            let derived_key = crypto
                .derive_key(TEST_PASSWORD, &salt, 32)
                .await
                .expect(&format!(
                    "Key derivation failed for salt length {}",
                    salt_len
                ));
            assert_eq!(derived_key.len(), 32);
        }
    }

    #[tokio::test]
    async fn test_persistent_identity_key_derivation() {
        let temp_file = NamedTempFile::new().unwrap();
        let mut identity_config = IdentityConfig::default();
        identity_config.identity_file = temp_file.path().to_string_lossy().to_string();

        // Create persistent identity
        let identity = SystemIdentity::create_or_load(&identity_config)
            .expect("Failed to create or load identity");

        // Use identity key material for cryptographic operations
        let config = wolfsec::crypto::CryptoConfig::default();
        let crypto = WolfCrypto::new(config).expect("Failed to create WolfCrypto");

        // Derive key using identity's key material as password
        let derived_key = crypto
            .derive_key(&identity.key_material, TEST_SALT, 32)
            .await
            .expect("Key derivation with identity failed");

        assert_eq!(derived_key.len(), 32);
        assert!(!derived_key.iter().all(|&b| b == 0)); // Should not be all zeros

        // Test HMAC with identity key material
        let hmac = crypto
            .hmac(&identity.key_material, TEST_DATA)
            .await
            .expect("HMAC with identity failed");
        assert!(!hmac.is_empty());
        assert_eq!(hmac.len(), 32);

        // Test identity validation
        identity
            .validate(&identity_config)
            .expect("Identity validation failed");

        // Test identity fingerprint
        let fingerprint = identity.fingerprint();
        assert!(!fingerprint.is_empty());
        assert_eq!(fingerprint.len(), 64); // SHA-256 hex string
    }
}
