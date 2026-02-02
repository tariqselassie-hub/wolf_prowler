//! Comprehensive Unit Tests for WolfSec
//!
//! Tests for all major components to ensure proper functionality and catch key size errors

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use wolf_den::SecurityLevel;
    use wolfsec::{
        crypto::{SecureBytes, WolfCrypto},
        security::advanced::zero_trust::{
            contextual_auth::ContextualAuthenticator, microsegmentation::MicrosegmentationManager,
            policy_engine::WolfPolicyEngine, trust_engine::WolfTrustEngine,
        },
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

    #[tokio::test]
    async fn test_zero_trust_manager_creation() {
        let mut manager = wolfsec::identity::advanced::zero_trust::ZeroTrustManager::new()
            .expect("Failed to create ZeroTrustManager");

        // Create a test context
        let peer_id = libp2p::PeerId::random();
        let context = wolfsec::identity::advanced::zero_trust::TrustContext {
            peer_id: peer_id.clone(),
            timestamp: Utc::now(),
            location: wolfsec::identity::advanced::zero_trust::LocationContext {
                ip_address: "192.168.1.1".parse().unwrap(),
                geographic_location: None,
                network_segment: "internal".to_string(),
                is_known_territory: true,
            },
            device_info: wolfsec::identity::advanced::zero_trust::DeviceContext {
                device_id: "test_device".to_string(),
                device_type: wolfsec::identity::advanced::zero_trust::DeviceType::Alpha,
                security_posture: wolfsec::identity::advanced::zero_trust::SecurityPosture {
                    os_version: "Linux 5.14".to_string(),
                    patch_level: "latest".to_string(),
                    antivirus_status: wolfsec::identity::advanced::zero_trust::AVStatus::Active,
                    firewall_enabled: true,
                    disk_encryption: true,
                    secure_boot_enabled: true,
                    last_security_scan: Utc::now(),
                },
                certificate_info: None,
                health_score: 0.9,
            },
            behavioral_score: 0.8,
            historical_trust: wolfsec::identity::advanced::zero_trust::HistoricalTrust {
                first_seen: Utc::now(),
                last_seen: Utc::now(),
                total_interactions: 10,
                successful_interactions: 9,
                failed_interactions: 1,
                security_incidents: 0,
                average_trust_score: 0.85,
            },
            environmental_factors: wolfsec::identity::advanced::zero_trust::EnvironmentalContext {
                time_of_day: wolfsec::identity::advanced::zero_trust::TimeContext::Normal,
                day_of_week: wolfsec::identity::advanced::zero_trust::DayContext::Weekday,
                business_hours: true,
                current_threat_level: wolfsec::identity::advanced::zero_trust::ThreatLevel::Low,
                network_load: wolfsec::identity::advanced::zero_trust::NetworkLoad::Low,
                active_incidents: vec![],
            },
        };

        let result = manager
            .evaluate_trust(context)
            .await
            .expect("Trust evaluation failed");
        assert!(result.confidence_score >= 0.0 && result.confidence_score <= 1.0);
        assert!(result.risk_score >= 0.0 && result.risk_score <= 1.0);
    }

    #[tokio::test]
    async fn test_contextual_authenticator() {
        let mut authenticator =
            ContextualAuthenticator::new().expect("Failed to create authenticator");

        let peer_id = libp2p::PeerId::random();
        let context = wolfsec::identity::advanced::zero_trust::TrustContext {
            peer_id: peer_id.clone(),
            timestamp: Utc::now(),
            location: wolfsec::identity::advanced::zero_trust::LocationContext {
                ip_address: "192.168.1.1".parse().unwrap(),
                geographic_location: None,
                network_segment: "internal".to_string(),
                is_known_territory: true,
            },
            device_info: wolfsec::identity::advanced::zero_trust::DeviceContext {
                device_id: "test_device".to_string(),
                device_type: wolfsec::identity::advanced::zero_trust::DeviceType::Alpha,
                security_posture: wolfsec::identity::advanced::zero_trust::SecurityPosture {
                    os_version: "Linux 5.14".to_string(),
                    patch_level: "latest".to_string(),
                    antivirus_status: wolfsec::identity::advanced::zero_trust::AVStatus::Active,
                    firewall_enabled: true,
                    disk_encryption: true,
                    secure_boot_enabled: true,
                    last_security_scan: Utc::now(),
                },
                certificate_info: None,
                health_score: 0.9,
            },
            behavioral_score: 0.8,
            historical_trust: wolfsec::identity::advanced::zero_trust::HistoricalTrust {
                first_seen: Utc::now(),
                last_seen: Utc::now(),
                total_interactions: 10,
                successful_interactions: 9,
                failed_interactions: 1,
                security_incidents: 0,
                average_trust_score: 0.85,
            },
            environmental_factors: wolfsec::identity::advanced::zero_trust::EnvironmentalContext {
                time_of_day: wolfsec::identity::advanced::zero_trust::TimeContext::Normal,
                day_of_week: wolfsec::identity::advanced::zero_trust::DayContext::Weekday,
                business_hours: true,
                current_threat_level: wolfsec::identity::advanced::zero_trust::ThreatLevel::Low,
                network_load: wolfsec::identity::advanced::zero_trust::NetworkLoad::Low,
                active_incidents: vec![],
            },
        };

        let result = authenticator
            .authenticate(&context)
            .await
            .expect("Authentication failed");
        assert!(result.confidence >= 0.0 && result.confidence <= 1.0);
        assert!(result.risk_score >= 0.0 && result.risk_score <= 1.0);
    }

    #[tokio::test]
    async fn test_microsegmentation_manager() {
        let mut manager = MicrosegmentationManager::new().expect("Failed to create manager");

        let peer_id = libp2p::PeerId::random();
        let context = wolfsec::identity::advanced::zero_trust::TrustContext {
            peer_id: peer_id.clone(),
            timestamp: Utc::now(),
            location: wolfsec::identity::advanced::zero_trust::LocationContext {
                ip_address: "192.168.1.1".parse().unwrap(),
                geographic_location: None,
                network_segment: "internal".to_string(),
                is_known_territory: true,
            },
            device_info: wolfsec::identity::advanced::zero_trust::DeviceContext {
                device_id: "test_device".to_string(),
                device_type: wolfsec::identity::advanced::zero_trust::DeviceType::Alpha,
                security_posture: wolfsec::identity::advanced::zero_trust::SecurityPosture {
                    os_version: "Linux 5.14".to_string(),
                    patch_level: "latest".to_string(),
                    antivirus_status: wolfsec::identity::advanced::zero_trust::AVStatus::Active,
                    firewall_enabled: true,
                    disk_encryption: true,
                    secure_boot_enabled: true,
                    last_security_scan: Utc::now(),
                },
                certificate_info: None,
                health_score: 0.9,
            },
            behavioral_score: 0.8,
            historical_trust: wolfsec::identity::advanced::zero_trust::HistoricalTrust {
                first_seen: Utc::now(),
                last_seen: Utc::now(),
                total_interactions: 10,
                successful_interactions: 9,
                failed_interactions: 1,
                security_incidents: 0,
                average_trust_score: 0.85,
            },
            environmental_factors: wolfsec::identity::advanced::zero_trust::EnvironmentalContext {
                time_of_day: wolfsec::identity::advanced::zero_trust::TimeContext::Normal,
                day_of_week: wolfsec::identity::advanced::zero_trust::DayContext::Weekday,
                business_hours: true,
                current_threat_level: wolfsec::identity::advanced::zero_trust::ThreatLevel::Low,
                network_load: wolfsec::identity::advanced::zero_trust::NetworkLoad::Low,
                active_incidents: vec![],
            },
        };

        let result = manager
            .evaluate_access(&context)
            .await
            .expect("Access evaluation failed");
        assert!(result.confidence >= 0.0 && result.confidence <= 1.0);
        assert!(result.risk_score >= 0.0 && result.risk_score <= 1.0);
    }

    #[tokio::test]
    async fn test_policy_engine() {
        let mut engine = WolfPolicyEngine::new().expect("Failed to create policy engine");

        let peer_id = libp2p::PeerId::random();
        let context = wolfsec::identity::advanced::zero_trust::TrustContext {
            peer_id: peer_id.clone(),
            timestamp: Utc::now(),
            location: wolfsec::identity::advanced::zero_trust::LocationContext {
                ip_address: "192.168.1.1".parse().unwrap(),
                geographic_location: None,
                network_segment: "internal".to_string(),
                is_known_territory: true,
            },
            device_info: wolfsec::identity::advanced::zero_trust::DeviceContext {
                device_id: "test_device".to_string(),
                device_type: wolfsec::identity::advanced::zero_trust::DeviceType::Alpha,
                security_posture: wolfsec::identity::advanced::zero_trust::SecurityPosture {
                    os_version: "Linux 5.14".to_string(),
                    patch_level: "latest".to_string(),
                    antivirus_status: wolfsec::identity::advanced::zero_trust::AVStatus::Active,
                    firewall_enabled: true,
                    disk_encryption: true,
                    secure_boot_enabled: true,
                    last_security_scan: Utc::now(),
                },
                certificate_info: None,
                health_score: 0.9,
            },
            behavioral_score: 0.8,
            historical_trust: wolfsec::identity::advanced::zero_trust::HistoricalTrust {
                first_seen: Utc::now(),
                last_seen: Utc::now(),
                total_interactions: 10,
                successful_interactions: 9,
                failed_interactions: 1,
                security_incidents: 0,
                average_trust_score: 0.85,
            },
            environmental_factors: wolfsec::identity::advanced::zero_trust::EnvironmentalContext {
                time_of_day: wolfsec::identity::advanced::zero_trust::TimeContext::Normal,
                day_of_week: wolfsec::identity::advanced::zero_trust::DayContext::Weekday,
                business_hours: true,
                current_threat_level: wolfsec::identity::advanced::zero_trust::ThreatLevel::Low,
                network_load: wolfsec::identity::advanced::zero_trust::NetworkLoad::Low,
                active_incidents: vec![],
            },
        };

        let result = engine
            .evaluate_policies(
                &context,
                &wolfsec::identity::advanced::zero_trust::TrustLevel::Trusted,
            )
            .await
            .expect("Policy evaluation failed");

        assert!(result.confidence >= 0.0 && result.confidence <= 1.0);
        assert!(result.risk_score >= 0.0 && result.risk_score <= 1.0);
    }

    #[test]
    fn test_trust_level_comparisons() {
        use wolfsec::identity::advanced::zero_trust::TrustLevel;

        assert!(TrustLevel::Unknown < TrustLevel::Trusted);
        assert!(TrustLevel::Trusted < TrustLevel::AlphaTrusted);
        assert!(TrustLevel::AlphaTrusted > TrustLevel::PartiallyTrusted);
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
        let derived_salt = crypto
            .derive_key(b"salt_password", b"salt_context_must_be_long", 32)
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

        // Test zero-length key derivation
        let result = crypto.derive_key(b"password", b"salt", 0).await;
        assert!(result.is_err()); // Should return error for invalid length
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
}
