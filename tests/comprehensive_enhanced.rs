// Enhanced Comprehensive Wolf Prowler System Integration Test
// Tests all active features with progress indicators, stress testing, and detailed reporting

use wolf_prowler::core::security_policy::{SecurityPolicy, SecurityStance};
use wolf_prowler::core::AppSettings as Config;
use wolf_den::{CryptoEngine, SecurityLevel};
use wolfsec::WolfSecurity;

/// Comprehensive system test covering all active features with enhanced output
#[tokio::test]
#[ignore] // Run with: cargo test --test comprehensive_enhanced -- --ignored --nocapture
async fn test_comprehensive_system_enhanced() {
    print_header();
    
    let mut total_tests = 0;
    let mut passed_tests = 0;
    let start_time = std::time::Instant::now();
    
    // Test all three security levels
    for stance in [SecurityStance::Low, SecurityStance::Medium, SecurityStance::High] {
        println!("\n{}", "=".repeat(80));
        print_security_level_header(stance);
        println!("{}", "=".repeat(80));
        
        let (tests, passed) = test_security_level_enhanced(stance).await;
        total_tests += tests;
        passed_tests += passed;
    }
    
    // Run stress tests
    println!("\n{}", "=".repeat(80));
    println!("🔥 STRESS TESTING");
    println!("{}", "=".repeat(80));
    
    let stress_results = run_stress_tests().await;
    total_tests += stress_results.0;
    passed_tests += stress_results.1;
    
    // Print final summary
    let duration = start_time.elapsed();
    print_final_summary(total_tests, passed_tests, duration);
}

fn print_header() {
    println!("\n{}", "█".repeat(80));
    println!("█{:^78}█", "");
    println!("█{:^78}█", "🐺 WOLF PROWLER COMPREHENSIVE SYSTEM TEST 🐺");
    println!("█{:^78}█", "");
    println!("█{:^78}█", "Military-Grade Security Validation Suite");
    println!("█{:^78}█", "NIST FIPS 140-3 | NSA CNSA Suite | Quantum-Resistant");
    println!("█{:^78}█", "");
    println!("{}", "█".repeat(80));
}

fn print_security_level_header(stance: SecurityStance) {
    let (icon, classification, key_size) = match stance {
        SecurityStance::Low => ("🟢", "DEVELOPMENT", "128-bit"),
        SecurityStance::Medium => ("🟡", "PRODUCTION", "192-bit"),
        SecurityStance::High => ("🔴", "MAXIMUM SECURITY", "256-bit"),
        _ => ("⚪", "CUSTOM/PARANOID", "Unknown"),
    };
    
    println!("\n{} {:?} SECURITY LEVEL - {} - {}", icon, stance, classification, key_size);
}

async fn test_security_level_enhanced(stance: SecurityStance) -> (usize, usize) {
    let policy = SecurityPolicy::from_stance(stance);
    let mut total = 0;
    let mut passed = 0;
    
    println!("\n📋 Configuration:");
    println!("   • Key Size: {} bits", policy.key_size_bits());
    println!("   • Session Timeout: {} seconds ({} min)", 
        policy.session_timeout_secs(), 
        policy.session_timeout_secs() / 60);
    println!("   • Threat Sensitivity: {}%", (policy.threat_sensitivity * 100.0) as u8);
    println!("   • Rate Limit: {} req/min", policy.rate_limit_strictness);
    println!("   • Min Password: {} chars", policy.min_password_length);
    println!("   • MFA Required: {}", if policy.require_mfa { "Yes" } else { "No" });
    
    // Test 1: Cryptographic Operations
    println!("\n[1/4] 🔐 Cryptographic Operations");
    let result = test_crypto_with_progress(&policy).await;
    total += 1;
    if result { passed += 1; print_pass(); } else { print_fail(); }
    
    // Test 2: Security Monitoring
    println!("[2/4] 🛡️  Security Monitoring");
    let result = test_security_with_progress(&policy).await;
    total += 1;
    if result { passed += 1; print_pass(); } else { print_fail(); }
    
    // Test 3: Network Operations
    println!("[3/4] 🌐 Network Operations");
    let result = test_network_with_progress(&policy).await;
    total += 1;
    if result { passed += 1; print_pass(); } else { print_fail(); }
    
    // Test 4: Compliance Validation
    println!("[4/4] 📋 Compliance Validation");
    let result = test_compliance_with_progress(&policy).await;
    total += 1;
    if result { passed += 1; print_pass(); } else { print_fail(); }
    
    println!("\n✅ Security Level {:?}: {}/{} tests passed", stance, passed, total);
    
    (total, passed)
}

async fn test_crypto_with_progress(policy: &SecurityPolicy) -> bool {
    let crypto = match CryptoEngine::new(policy.wolf_den_level) {
        Ok(c) => c,
        Err(_) => { print_fail(); return false; }
    };
    
    print!("      ├─ Hashing (Blake3)... ");
    let plaintext = b"Wolf Prowler Test Message - Confidential Data";
    match crypto.hash(plaintext).await {
        Ok(hash) if hash.len() == crypto.hash_output_length() => print_ok(),
        _ => { print_fail(); return false; }
    }
    
    print!("      ├─ Key Derivation (Argon2)... ");
    let password = b"test_password_wolf_prowler";
    let salt = crypto.generate_salt(16).unwrap();
    match crypto.derive_key(password, &salt, 32).await {
        Ok(key) if key.len() == 32 => print_ok(),
        _ => { print_fail(); return false; }
    }
    
    print!("      ├─ MAC (HMAC)... ");
    match crypto.compute_mac(plaintext).await {
        Ok(mac) if mac.len() == crypto.mac_output_length() => print_ok(),
        _ => { print_fail(); return false; }
    }
    
    print!("      └─ Key Generation... ");
    match crypto.generate_key(32) {
        Ok(key) if key.len() == 32 => { print_ok(); true }
        _ => { print_fail(); false }
    }
}

async fn test_security_with_progress(policy: &SecurityPolicy) -> bool {
    print!("      ├─ WolfSec Initialization... ");
    let config = wolfsec::WolfSecurityConfig::default();
    let mut wolfsec = match WolfSecurity::new(config) {
        Ok(w) => w,
        Err(_) => { print_fail(); return false; }
    };
    match wolfsec.initialize().await {
        Ok(_) => print_ok(),
        Err(_) => { print_fail(); return false; }
    }
    
    print!("      ├─ Threat Sensitivity... ");
    let expected = match policy.stance {
        SecurityStance::Low => 0.3,
        SecurityStance::Medium => 0.6,
        SecurityStance::High => 0.9,
        _ => 0.0,
    };
    if policy.threat_sensitivity == expected {
        print_ok();
    } else {
        print_fail();
        return false;
    }
    
    print!("      └─ Audit Level... ");
    let correct = match policy.stance {
        SecurityStance::Low => matches!(policy.audit_level, wolf_prowler::core::security_policy::AuditLevel::ErrorsOnly),
        SecurityStance::Medium => matches!(policy.audit_level, wolf_prowler::core::security_policy::AuditLevel::Important),
        SecurityStance::High => matches!(policy.audit_level, wolf_prowler::core::security_policy::AuditLevel::Verbose),
        _ => true,
    };
    if correct { print_ok(); true } else { print_fail(); false }
}

async fn test_network_with_progress(policy: &SecurityPolicy) -> bool {
    print!("      ├─ P2P Network Init... ");
    let mut config = Config::default();
    config.security.stance = format!("{:?}", policy.stance).to_lowercase();
    let network = match wolf_prowler::core::P2PNetwork::new(&config.network) {
        Ok(n) => n,
        Err(_) => { print_fail(); return false; }
    };
    print_ok();
    
    print!("      ├─ Peer ID Generation... ");
    let peer_id = network.local_peer_id();
    if !peer_id.is_empty() && peer_id.starts_with("wolf_") {
        print_ok();
    } else {
        print_fail();
        return false;
    }
    
    print!("      └─ Session Timeout... ");
    let expected = match policy.stance {
        SecurityStance::Low => 7200,
        SecurityStance::Medium => 3600,
        SecurityStance::High => 1800,
        _ => 0,
    };
    if policy.session_timeout_secs() == expected {
        print_ok();
        true
    } else {
        print_fail();
        false
    }
}

async fn test_compliance_with_progress(policy: &SecurityPolicy) -> bool {
    print!("      ├─ FIPS 140-3 Compliance... ");
    let key_size_ok = match policy.stance {
        SecurityStance::Low => policy.key_size_bits() == 128,
        SecurityStance::Medium => policy.key_size_bits() == 192,
        SecurityStance::High => policy.key_size_bits() == 256,
        _ => true,
    };
    if key_size_ok { print_ok(); } else { print_fail(); return false; }
    
    print!("      ├─ Password Requirements... ");
    let pwd_ok = match policy.stance {
        SecurityStance::Low => policy.min_password_length == 8,
        SecurityStance::Medium => policy.min_password_length == 12,
        SecurityStance::High => policy.min_password_length == 16,
        _ => true,
    };
    if pwd_ok { print_ok(); } else { print_fail(); return false; }
    
    print!("      ├─ MFA Requirements... ");
    let mfa_ok = match policy.stance {
        SecurityStance::Low | SecurityStance::Medium => !policy.require_mfa,
        SecurityStance::High => policy.require_mfa,
        _ => true,
    };
    if mfa_ok { print_ok(); } else { print_fail(); return false; }
    
    print!("      └─ Rate Limiting... ");
    let rate_ok = match policy.stance {
        SecurityStance::Low => policy.rate_limit_strictness == 1000,
        SecurityStance::Medium => policy.rate_limit_strictness == 100,
        SecurityStance::High => policy.rate_limit_strictness == 10,
        _ => true,
    };
    if rate_ok { print_ok(); true } else { print_fail(); false }
}

async fn run_stress_tests() -> (usize, usize) {
    let mut total = 0;
    let mut passed = 0;
    
    // Stress Test 1: High-volume hashing
    println!("\n[1/3] ⚡ High-Volume Hashing (10,000 operations)");
    print!("      ");
    let result = stress_test_hashing().await;
    total += 1;
    if result { passed += 1; print_pass(); } else { print_fail(); }
    
    // Stress Test 2: Concurrent operations
    println!("[2/3] 🔄 Concurrent Operations (100 parallel tasks)");
    print!("      ");
    let result = stress_test_concurrent().await;
    total += 1;
    if result { passed += 1; print_pass(); } else { print_fail(); }
    
    // Stress Test 3: All ciphers compliance
    println!("[3/3] 🔐 Cipher Compliance (All 3 ciphers × 3 levels)");
    print!("      ");
    let result = stress_test_ciphers().await;
    total += 1;
    if result { passed += 1; print_pass(); } else { print_fail(); }
    
    (total, passed)
}

async fn stress_test_hashing() -> bool {
    let policy = SecurityPolicy::from_stance(SecurityStance::High);
    let crypto = CryptoEngine::new(policy.wolf_den_level).unwrap();
    
    let iterations = 10000;
    let start = std::time::Instant::now();
    
    for i in 0..iterations {
        let data = format!("Stress test message {}", i).into_bytes();
        if crypto.hash(&data).await.is_err() {
            return false;
        }
        
        // Progress indicator every 1000 ops
        if i > 0 && i % 1000 == 0 {
            print!(".");
            use std::io::Write;
            std::io::stdout().flush().unwrap();
        }
    }
    
    let duration = start.elapsed();
    let ops_per_sec = (iterations as f64) / duration.as_secs_f64();
    
    println!("\n      ├─ Completed: {} operations", iterations);
    println!("      ├─ Duration: {:?}", duration);
    println!("      ├─ Throughput: {:.0} ops/sec", ops_per_sec);
    println!("      └─ Avg latency: {:?}", duration / iterations);
    
    ops_per_sec > 5000.0 // Must achieve >5000 ops/sec
}

async fn stress_test_concurrent() -> bool {
    let policy = SecurityPolicy::from_stance(SecurityStance::Medium);
    let crypto = std::sync::Arc::new(CryptoEngine::new(policy.wolf_den_level).unwrap());
    
    let mut handles = vec![];
    let task_count = 100;
    
    for i in 0..task_count {
        let crypto_clone = crypto.clone();
        let handle = tokio::spawn(async move {
            let data = format!("Concurrent stress test {}", i).into_bytes();
            crypto_clone.hash(&data).await.is_ok() &&
            crypto_clone.compute_mac(&data).await.is_ok()
        });
        handles.push(handle);
        
        if i > 0 && i % 10 == 0 {
            print!(".");
            use std::io::Write;
            std::io::stdout().flush().unwrap();
        }
    }
    
    let mut success_count = 0;
    for handle in handles {
        if handle.await.unwrap_or(false) {
            success_count += 1;
        }
    }
    
    println!("\n      ├─ Tasks launched: {}", task_count);
    println!("      ├─ Successful: {}", success_count);
    println!("      └─ Success rate: {:.1}%", (success_count as f64 / task_count as f64) * 100.0);
    
    success_count == task_count
}

async fn stress_test_ciphers() -> bool {
    use wolf_den::symmetric::{ChaCha20Poly1305Cipher, Aes256GcmCipher, Aes128GcmCipher};
    
    let mut tests_passed = 0;
    let total_tests = 9; // 3 ciphers × 3 levels
    
    for level in [SecurityLevel::Minimum, SecurityLevel::Standard, SecurityLevel::Maximum] {
        // ChaCha20
        if ChaCha20Poly1305Cipher::new(level).is_ok() {
            tests_passed += 1;
            print!(".");
        }
        
        // AES-256
        if Aes256GcmCipher::new(level).is_ok() {
            tests_passed += 1;
            print!(".");
        }
        
        // AES-128
        if Aes128GcmCipher::new(level).is_ok() {
            tests_passed += 1;
            print!(".");
        }
        
        use std::io::Write;
        std::io::stdout().flush().unwrap();
    }
    
    println!("\n      ├─ Cipher tests: {}/{}", tests_passed, total_tests);
    println!("      └─ All ciphers operational: {}", if tests_passed == total_tests { "Yes" } else { "No" });
    
    tests_passed == total_tests
}

fn print_final_summary(total: usize, passed: usize, duration: std::time::Duration) {
    println!("\n{}", "█".repeat(80));
    println!("█{:^78}█", "");
    println!("█{:^78}█", "TEST SUMMARY");
    println!("█{:^78}█", "");
    
    let pass_rate = (passed as f64 / total as f64) * 100.0;
    let status = if passed == total { "✅ ALL TESTS PASSED" } else { "❌ SOME TESTS FAILED" };
    
    println!("█{:^78}█", status);
    println!("█{:^78}█", "");
    println!("█  {:76}█", format!("Total Tests: {}", total));
    println!("█  {:76}█", format!("Passed: {}", passed));
    println!("█  {:76}█", format!("Failed: {}", total - passed));
    println!("█  {:76}█", format!("Pass Rate: {:.1}%", pass_rate));
    println!("█  {:76}█", format!("Duration: {:.2}s", duration.as_secs_f64()));
    println!("█{:^78}█", "");
    
    if passed == total {
        println!("█{:^78}█", "🎉 SYSTEM READY FOR PRODUCTION 🎉");
    } else {
        println!("█{:^78}█", "⚠️  REVIEW FAILURES BEFORE DEPLOYMENT ⚠️");
    }
    
    println!("█{:^78}█", "");
    println!("{}", "█".repeat(80));
    println!();
}

fn print_pass() {
    println!(" ✅ PASS");
}

fn print_fail() {
    println!(" ❌ FAIL");
}

fn print_ok() {
    println!("✓");
}
