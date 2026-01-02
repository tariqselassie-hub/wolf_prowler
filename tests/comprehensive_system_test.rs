// Comprehensive Wolf Prowler System Integration Test
// Tests all active features under different security levels and conditions

use wolf_prowler::core::security_policy::{SecurityPolicy, SecurityStance};
use wolf_prowler::core::AppSettings as Config;
use wolf_den::{CryptoEngine, SecurityLevel};
use wolfsec::WolfSecurity;
use std::time::Duration;
use tokio::time::sleep;

/// Comprehensive system test covering all active features
#[tokio::test]
#[ignore] // Run with: cargo test --test comprehensive -- --ignored
async fn test_comprehensive_system_integration() {
    println!("\n🐺 === WOLF PROWLER COMPREHENSIVE SYSTEM TEST ===\n");
    
    // Test all three security levels
    for stance in [SecurityStance::Low, SecurityStance::Medium, SecurityStance::High] {
        println!("\n📊 Testing Security Level: {:?}", stance);
        test_security_level(stance).await;
    }
    
    println!("\n✅ === ALL COMPREHENSIVE TESTS PASSED ===\n");
}

async fn test_security_level(stance: SecurityStance) {
    let policy = SecurityPolicy::from_stance(stance);
    
    println!("  🔒 Security Policy: {}", policy.description());
    println!("  📏 Key Size: {} bits", policy.key_size_bits());
    println!("  ⏱️  Session Timeout: {} seconds", policy.session_timeout_secs());
    
    // 1. Test Cryptographic Operations
    test_crypto_operations(&policy).await;
    
    // 2. Test Security Monitoring
    test_security_monitoring(&policy).await;
    
    // 3. Test Network Operations
    test_network_operations(&policy).await;
    
    // 4. Test Compliance Validation
    test_compliance_validation(&policy).await;
    
    println!("  ✅ Security Level {:?} - All tests passed\n", stance);
}

/// Test 1: Cryptographic Operations
async fn test_crypto_operations(policy: &SecurityPolicy) {
    println!("    🔐 Testing Crypto Operations...");
    
    // Initialize crypto engine with policy-driven security level
    let crypto = CryptoEngine::new(policy.wolf_den_level).expect("Failed to create crypto engine");
    
    // Test hashing
    let plaintext = b"Wolf Prowler Test Message - Confidential Data";
    let hash = crypto.hash(plaintext).await.expect("Hashing failed");
    assert_eq!(hash.len(), crypto.hash_output_length(), "Invalid hash length");
    
    // Test key derivation
    let password = b"test_password_wolf_prowler";
    let salt = crypto.generate_salt(16).expect("Salt generation failed");
    let derived_key = crypto.derive_key(password, &salt, 32).await
        .expect("Key derivation failed");
    assert_eq!(derived_key.len(), 32, "Invalid derived key length");
    
    // Test MAC
    let mac = crypto.compute_mac(plaintext).await.expect("MAC failed");
    assert_eq!(mac.len(), crypto.mac_output_length());
    
    // Test key generation
    let key = crypto.generate_key(32).expect("Key generation failed");
    assert_eq!(key.len(), 32);
    
    // Verify security level compliance
    match policy.stance {
        SecurityStance::Low => {
            assert_eq!(policy.wolf_den_level, SecurityLevel::Minimum);
        }
        SecurityStance::Medium => {
            assert_eq!(policy.wolf_den_level, SecurityLevel::Standard);
        }
        SecurityStance::High => {
            assert_eq!(policy.wolf_den_level, SecurityLevel::Maximum);
        }
        _ => {} // Paranoid/Custom not tested in loop
    }
    
    println!("      ✅ Crypto operations validated");
}

/// Test 2: Security Monitoring
async fn test_security_monitoring(policy: &SecurityPolicy) {
    println!("    🛡️  Testing Security Monitoring...");
    
    // Initialize WolfSec
    let config = wolfsec::WolfSecurityConfig::default();
    let mut wolfsec = WolfSecurity::new(config).expect("Failed to create WolfSec");
    wolfsec.initialize().await.expect("WolfSec initialization failed");
    
    // Test threat detection sensitivity based on policy
    let expected_sensitivity = policy.threat_sensitivity;
    assert!(expected_sensitivity >= 0.0 && expected_sensitivity <= 1.0);
    
    match policy.stance {
        SecurityStance::Low => assert_eq!(expected_sensitivity, 0.3),
        SecurityStance::Medium => assert_eq!(expected_sensitivity, 0.6),
        SecurityStance::High => assert_eq!(expected_sensitivity, 0.9),
        _ => {} // Not tested
    }
    
    // Test audit logging level
    match policy.audit_level {
        wolf_prowler::core::security_policy::AuditLevel::ErrorsOnly => {
            assert_eq!(policy.stance, SecurityStance::Low);
        }
        wolf_prowler::core::security_policy::AuditLevel::Important => {
            assert_eq!(policy.stance, SecurityStance::Medium);
        }
        wolf_prowler::core::security_policy::AuditLevel::Verbose => {
            assert_eq!(policy.stance, SecurityStance::High);
        }
    }
    
    println!("      ✅ Security monitoring validated");
}

/// Test 3: Network Operations
async fn test_network_operations(policy: &SecurityPolicy) {
    println!("    🌐 Testing Network Operations...");
    
    // Create network config
    let mut config = Config::default();
    config.security.stance = format!("{:?}", policy.stance).to_lowercase();
    
    // Initialize P2P network
    let network = wolf_prowler::core::P2PNetwork::new(&config.network)
        .expect("Failed to create P2P network");
    
    let peer_id = network.local_peer_id();
    assert!(!peer_id.is_empty(), "Invalid peer ID");
    assert!(peer_id.starts_with("wolf_"), "Invalid peer ID format");
    
    // Verify session timeout matches policy
    let expected_timeout = policy.session_timeout_secs();
    match policy.stance {
        SecurityStance::Low => assert_eq!(expected_timeout, 7200),    // 2 hours
        SecurityStance::Medium => assert_eq!(expected_timeout, 3600), // 1 hour
        SecurityStance::High => assert_eq!(expected_timeout, 1800),   // 30 minutes
        _ => {}
    }
    
    println!("      ✅ Network operations validated");
}

/// Test 4: Compliance Validation
async fn test_compliance_validation(policy: &SecurityPolicy) {
    println!("    📋 Testing Compliance...");
    
    // Test FIPS 140-3 compliance
    match policy.stance {
        SecurityStance::Low => {
            // FIPS 140-3 Level 1
            assert_eq!(policy.key_size_bits(), 128);
            assert!(!policy.require_mfa);
        }
        SecurityStance::Medium => {
            // FIPS 140-3 Level 2 / NSA SECRET
            assert_eq!(policy.key_size_bits(), 192);
            assert!(!policy.require_mfa);
        }
        SecurityStance::High => {
            // FIPS 140-3 Level 3 / NSA TOP SECRET
            assert_eq!(policy.key_size_bits(), 256);
            assert!(policy.require_mfa);
        }
        _ => {}
    }
    
    // Test password requirements
    match policy.stance {
        SecurityStance::Low => assert_eq!(policy.min_password_length, 8),
        SecurityStance::Medium => assert_eq!(policy.min_password_length, 12),
        SecurityStance::High => assert_eq!(policy.min_password_length, 16),
        _ => {}
    }
    
    // Test rate limiting (requests per minute)
    let expected_rate_limit = match policy.stance {
        SecurityStance::Low => 1000,     // 1000 req/min - very permissive
        SecurityStance::Medium => 100,   // 100 req/min - balanced
        SecurityStance::High => 10,      // 10 req/min - strict
        _ => 10, // Default strict for others
    };
    assert_eq!(policy.rate_limit_strictness, expected_rate_limit, 
        "Rate limit mismatch for {:?}: expected {}, got {}", 
        policy.stance, expected_rate_limit, policy.rate_limit_strictness);
    
    println!("      ✅ Compliance validated");
}

/// Test 5: Cipher-Specific Compliance
#[tokio::test]
async fn test_cipher_compliance() {
    println!("\n🔐 Testing Cipher Compliance...\n");
    
    // Test ChaCha20Poly1305
    test_chacha20_compliance().await;
    
    // Test AES-256-GCM
    test_aes256_compliance().await;
    
    // Test AES-128-GCM
    test_aes128_compliance().await;
    
    println!("\n✅ All cipher compliance tests passed\n");
}

async fn test_chacha20_compliance() {
    use wolf_den::symmetric::ChaCha20Poly1305Cipher;
    
    println!("  Testing ChaCha20Poly1305...");
    
    for level in [SecurityLevel::Minimum, SecurityLevel::Standard, SecurityLevel::Maximum] {
        let cipher = ChaCha20Poly1305Cipher::new(level).expect("Failed to create cipher");
        
        // Test effective key size
        let key_size = cipher.effective_key_size();
        match level {
            SecurityLevel::Minimum => assert_eq!(key_size, 128),
            SecurityLevel::Standard => assert_eq!(key_size, 192),
            SecurityLevel::Maximum => assert_eq!(key_size, 256),
        }
        
        // Test FIPS compliance
        assert!(cipher.is_fips_compliant());
        
        // Test key rotation interval
        let rotation = cipher.key_rotation_interval_secs();
        match level {
            SecurityLevel::Minimum => assert_eq!(rotation, 86400 * 7), // 1 week
            SecurityLevel::Standard => assert_eq!(rotation, 86400),    // 1 day
            SecurityLevel::Maximum => assert_eq!(rotation, 3600),      // 1 hour
        }
    }
    
    println!("    ✅ ChaCha20Poly1305 compliance validated");
}

async fn test_aes256_compliance() {
    use wolf_den::symmetric::Aes256GcmCipher;
    
    println!("  Testing AES-256-GCM...");
    
    for level in [SecurityLevel::Minimum, SecurityLevel::Standard, SecurityLevel::Maximum] {
        let cipher = Aes256GcmCipher::new(level).expect("Failed to create cipher");
        
        // Test NSA CNSA Suite compliance
        assert!(cipher.is_cnsa_compliant());
        
        // Test FIPS Level 3 compliance (only for Maximum)
        match level {
            SecurityLevel::Maximum => assert!(cipher.is_fips_level3_compliant()),
            _ => assert!(!cipher.is_fips_level3_compliant()),
        }
        
        // Test nonce size
        let nonce_size = cipher.nonce_size();
        match level {
            SecurityLevel::Minimum | SecurityLevel::Standard => assert_eq!(nonce_size, 12),
            SecurityLevel::Maximum => assert_eq!(nonce_size, 12),
        }
    }
    
    println!("    ✅ AES-256-GCM compliance validated");
}

async fn test_aes128_compliance() {
    use wolf_den::symmetric::Aes128GcmCipher;
    
    println!("  Testing AES-128-GCM...");
    
    for level in [SecurityLevel::Minimum, SecurityLevel::Standard, SecurityLevel::Maximum] {
        let cipher = Aes128GcmCipher::new(level).expect("Failed to create cipher");
        
        // Test appropriateness for level
        match level {
            SecurityLevel::Minimum => {
                assert!(cipher.is_appropriate_for_level());
                assert!(cipher.is_fips_compliant());
                assert!(cipher.security_warning().is_none());
            }
            SecurityLevel::Standard => {
                assert!(!cipher.is_appropriate_for_level());
                assert!(!cipher.is_fips_compliant());
                assert!(cipher.security_warning().is_some());
            }
            SecurityLevel::Maximum => {
                assert!(!cipher.is_appropriate_for_level());
                assert!(!cipher.is_fips_compliant());
                let warning = cipher.security_warning().unwrap();
                assert!(warning.contains("CRITICAL"));
            }
        }
    }
    
    println!("    ✅ AES-128-GCM compliance validated");
}

/// Test 6: Performance Under Load
#[tokio::test]
#[ignore] // Run with: cargo test --test comprehensive test_performance -- --ignored
async fn test_performance_under_load() {
    println!("\n⚡ Testing Performance Under Load...\n");
    
    let policy = SecurityPolicy::from_stance(SecurityStance::High);
    let crypto = CryptoEngine::new(policy.wolf_den_level).expect("Failed to create crypto");
    
    let iterations = 1000;
    let start = std::time::Instant::now();
    
    for i in 0..iterations {
        let data = format!("Test message {}", i).into_bytes();
        
        // Test hashing performance
        let _hash = crypto.hash(&data).await.unwrap();
        
        // Test MAC performance
        let _mac = crypto.compute_mac(&data).await.unwrap();
    }
    
    let duration = start.elapsed();
    let ops_per_sec = (iterations as f64 * 2.0) / duration.as_secs_f64(); // 2 ops per iteration
    
    println!("  Completed {} hash+MAC cycles", iterations);
    println!("  Duration: {:?}", duration);
    println!("  Operations/sec: {:.2}", ops_per_sec);
    println!("  Avg time per operation: {:?}", duration / (iterations * 2));
    
    // Performance should be reasonable (>1000 ops/sec for hash+MAC)
    assert!(ops_per_sec > 1000.0, "Performance too slow: {} ops/sec", ops_per_sec);
    
    println!("\n✅ Performance test passed\n");
}

/// Test 7: Concurrent Operations
#[tokio::test]
#[ignore]
async fn test_concurrent_operations() {
    println!("\n🔄 Testing Concurrent Operations...\n");
    
    let policy = SecurityPolicy::from_stance(SecurityStance::Medium);
    let crypto = std::sync::Arc::new(
        CryptoEngine::new(policy.wolf_den_level).expect("Failed to create crypto")
    );
    
    let mut handles = vec![];
    
    for i in 0..10 {
        let crypto_clone = crypto.clone();
        let handle = tokio::spawn(async move {
            let data = format!("Concurrent test {}", i).into_bytes();
            
            // Test hashing
            let hash = crypto_clone.hash(&data).await.unwrap();
            assert_eq!(hash.len(), crypto_clone.hash_output_length());
            
            // Test MAC
            let mac = crypto_clone.compute_mac(&data).await.unwrap();
            assert_eq!(mac.len(), crypto_clone.mac_output_length());
            
            // Test key derivation
            let salt = crypto_clone.generate_salt(16).unwrap();
            let key = crypto_clone.derive_key(&data, &salt, 32).await.unwrap();
            assert_eq!(key.len(), 32);
        });
        handles.push(handle);
    }
    
    for handle in handles {
        handle.await.expect("Task failed");
    }
    
    println!("  ✅ All 10 concurrent operations completed successfully\n");
}
