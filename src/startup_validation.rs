//! Startup Validation Module for Wolf Prowler Dashboard
//!
//! This module provides comprehensive validation of all Wolf Prowler libraries
//! before the dashboard router starts. It ensures all dependencies are properly
//! initialized and functional before serving web traffic.

use anyhow::{Result, anyhow};
use std::time::{Duration, Instant};
use tokio::time::timeout;
use serde::{Serialize, Deserialize};
use tracing::{info, warn, error, debug};

/// Library validation results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResults {
    pub wolf_den: LibraryStatus,
    pub wolf_net: LibraryStatus,
    pub wolfsec: LibraryStatus,
    pub overall_success: bool,
    pub total_duration_ms: u64,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

/// Individual library status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LibraryStatus {
    pub name: String,
    pub initialized: bool,
    pub functional: bool,
    pub version: String,
    pub test_count: usize,
    pub passed_tests: usize,
    pub duration_ms: u64,
    pub issues: Vec<String>,
}

impl LibraryStatus {
    pub fn success_rate(&self) -> f64 {
        if self.test_count == 0 {
            0.0
        } else {
            self.passed_tests as f64 / self.test_count as f64 * 100.0
        }
    }
    
    pub fn is_healthy(&self) -> bool {
        self.initialized && self.functional && self.success_rate() >= 95.0
    }
}

/// Comprehensive startup validation
pub async fn validate_all_libraries() -> Result<ValidationResults> {
    let start_time = Instant::now();
    info!("🚀 Starting comprehensive library validation...");
    
    let mut results = ValidationResults {
        wolf_den: LibraryStatus {
            name: "wolf_den".to_string(),
            initialized: false,
            functional: false,
            version: "unknown".to_string(),
            test_count: 0,
            passed_tests: 0,
            duration_ms: 0,
            issues: Vec::new(),
        },
        wolf_net: LibraryStatus {
            name: "wolf_net".to_string(),
            initialized: false,
            functional: false,
            version: "unknown".to_string(),
            test_count: 0,
            passed_tests: 0,
            duration_ms: 0,
            issues: Vec::new(),
        },
        wolfsec: LibraryStatus {
            name: "wolfsec".to_string(),
            initialized: false,
            functional: false,
            version: "unknown".to_string(),
            test_count: 0,
            passed_tests: 0,
            duration_ms: 0,
            issues: Vec::new(),
        },
        overall_success: false,
        total_duration_ms: 0,
        warnings: Vec::new(),
        errors: Vec::new(),
    };
    
    // Validate wolf_den (Cryptography)
    let wolf_den_start = Instant::now();
    match validate_wolf_den().await {
        Ok(status) => {
            results.wolf_den = status;
            info!("✅ wolf_den validation completed");
        }
        Err(e) => {
            results.wolf_den.issues.push(format!("Validation failed: {}", e));
            results.errors.push(format!("wolf_den: {}", e));
            error!("❌ wolf_den validation failed: {}", e);
        }
    }
    results.wolf_den.duration_ms = wolf_den_start.elapsed().as_millis() as u64;
    
    // Validate wolf_net (Networking)
    let wolf_net_start = Instant::now();
    match validate_wolf_net().await {
        Ok(status) => {
            results.wolf_net = status;
            info!("✅ wolf_net validation completed");
        }
        Err(e) => {
            results.wolf_net.issues.push(format!("Validation failed: {}", e));
            results.errors.push(format!("wolf_net: {}", e));
            error!("❌ wolf_net validation failed: {}", e);
        }
    }
    results.wolf_net.duration_ms = wolf_net_start.elapsed().as_millis() as u64;
    
    // Validate wolfsec (Security)
    let wolfsec_start = Instant::now();
    match validate_wolfsec().await {
        Ok(status) => {
            results.wolfsec = status;
            info!("✅ wolfsec validation completed");
        }
        Err(e) => {
            results.wolfsec.issues.push(format!("Validation failed: {}", e));
            results.errors.push(format!("wolfsec: {}", e));
            error!("❌ wolfsec validation failed: {}", e);
        }
    }
    results.wolfsec.duration_ms = wolfsec_start.elapsed().as_millis() as u64;
    
    // Calculate overall success
    results.overall_success = results.wolf_den.is_healthy() && 
                              results.wolf_net.is_healthy() && 
                              results.wolfsec.is_healthy();
    results.total_duration_ms = start_time.elapsed().as_millis() as u64;
    
    // Print validation summary
    print_validation_summary(&results);
    
    // Determine if we should proceed with startup
    if results.overall_success {
        info!("🎉 All libraries validated successfully - Dashboard can start safely");
    } else {
        warn!("⚠️ Some library validations failed - Dashboard startup may be unstable");
    }
    
    Ok(results)
}

/// Validate wolf_den cryptographic library
async fn validate_wolf_den() -> Result<LibraryStatus> {
    let mut status = LibraryStatus {
        name: "wolf_den".to_string(),
        initialized: false,
        functional: false,
        version: "0.1.0".to_string(), // TODO: Get actual version
        test_count: 0,
        passed_tests: 0,
        duration_ms: 0,
        issues: Vec::new(),
    };
    
    debug!("🔐 Validating wolf_den cryptographic library...");
    
    let validation_result = timeout(Duration::from_secs(10), async {
        // Test 1: Initialize wolf_den
        wolf_den::init()
            .map_err(|e| anyhow!("Initialization failed: {}", e))?;
        status.initialized = true;
        debug!("  ✅ wolf_den initialized successfully");
        status.test_count += 1;
        status.passed_tests += 1;
        
        // Test 2: Basic crypto operations
        let keypair = wolf_den::crypto::generate_keypair()
            .map_err(|e| anyhow!("Keypair generation failed: {}", e))?;
        debug!("  ✅ Keypair generation successful");
        status.test_count += 1;
        status.passed_tests += 1;
        
        // Test 3: Encryption/decryption
        let plaintext = b"Test validation message";
        let encrypted = wolf_den::crypto::encrypt(&keypair.public_key, plaintext)
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;
        let decrypted = wolf_den::crypto::decrypt(&keypair.private_key, &encrypted)
            .map_err(|e| anyhow!("Decryption failed: {}", e))?;
        
        if decrypted != plaintext {
            return Err(anyhow!("Encryption/decryption mismatch"));
        }
        debug!("  ✅ Encryption/decryption successful");
        status.test_count += 1;
        status.passed_tests += 1;
        
        // Test 4: Hashing
        let hash = wolf_den::crypto::hash_data(plaintext)
            .map_err(|e| anyhow!("Hashing failed: {}", e))?;
        if hash.len() != 32 {
            return Err(anyhow!("Invalid hash length: {}", hash.len()));
        }
        debug!("  ✅ Hashing successful (32 bytes)");
        status.test_count += 1;
        status.passed_tests += 1;
        
        // Test 5: Digital signatures
        let signature = wolf_den::crypto::sign(&keypair.private_key, plaintext)
            .map_err(|e| anyhow!("Signing failed: {}", e))?;
        let verified = wolf_den::crypto::verify(&keypair.public_key, plaintext, &signature)
            .map_err(|e| anyhow!("Verification failed: {}", e))?;
        
        if !verified {
            return Err(anyhow!("Signature verification failed"));
        }
        debug!("  ✅ Digital signatures successful");
        status.test_count += 1;
        status.passed_tests += 1;
        
        status.functional = true;
        Ok(status)
    }).await;
    
    match validation_result {
        Ok(Ok(s)) => Ok(s),
        Ok(Err(e)) => {
            status.issues.push(e.to_string());
            Ok(status)
        }
        Err(_) => {
            status.issues.push("Validation timed out".to_string());
            Ok(status)
        }
    }
}

/// Validate wolf_net networking library
async fn validate_wolf_net() -> Result<LibraryStatus> {
    let mut status = LibraryStatus {
        name: "wolf_net".to_string(),
        initialized: false,
        functional: false,
        version: "0.1.0".to_string(), // TODO: Get actual version
        test_count: 0,
        passed_tests: 0,
        duration_ms: 0,
        issues: Vec::new(),
    };
    
    debug!("🌐 Validating wolf_net networking library...");
    
    let validation_result = timeout(Duration::from_secs(15), async {
        // Test 1: Initialize wolf_net
        wolf_net::init()
            .map_err(|e| anyhow!("Initialization failed: {}", e))?;
        status.initialized = true;
        debug!("  ✅ wolf_net initialized successfully");
        status.test_count += 1;
        status.passed_tests += 1;
        
        // Test 2: Peer ID operations
        let peer_id = wolf_net::PeerId::random();
        if !peer_id.is_valid() {
            return Err(anyhow!("Generated invalid peer ID"));
        }
        debug!("  ✅ Peer ID generation successful: {}", peer_id);
        status.test_count += 1;
        status.passed_tests += 1;
        
        // Test 3: Entity creation
        let entity = wolf_net::create_entity(
            wolf_net::ServiceType::Server,
            wolf_net::SystemType::Production,
            "1.0.0"
        );
        debug!("  ✅ Entity creation successful");
        status.test_count += 1;
        status.passed_tests += 1;
        
        // Test 4: Peer info management
        let mut peer_info = wolf_net::PeerInfo::new(peer_id.clone());
        peer_info.add_address("127.0.0.1:8080".parse()?);
        peer_info.add_capability("wolf_prowler".to_string());
        peer_info.update_trust_score(0.85);
        
        if peer_info.addresses.is_empty() || peer_info.capabilities.is_empty() {
            return Err(anyhow!("Peer info management failed"));
        }
        debug!("  ✅ Peer info management successful");
        status.test_count += 1;
        status.passed_tests += 1;
        
        // Test 5: Swarm creation (without starting)
        let swarm_config = wolf_net::SwarmConfig::default();
        let swarm = wolf_net::SwarmManager::new(swarm_config)
            .map_err(|e| anyhow!("Swarm creation failed: {}", e))?;
        debug!("  ✅ Swarm creation successful");
        status.test_count += 1;
        status.passed_tests += 1;
        
        // Test 6: Discovery service
        let discovery_config = wolf_net::DiscoveryConfig::default();
        let discovery = wolf_net::DiscoveryService::new(discovery_config)
            .map_err(|e| anyhow!("Discovery service creation failed: {}", e))?;
        debug!("  ✅ Discovery service creation successful");
        status.test_count += 1;
        status.passed_tests += 1;
        
        // Test 7: Message handling
        let message = wolf_net::Message::chat(peer_id, "Test message".to_string());
        debug!("  ✅ Message creation successful");
        status.test_count += 1;
        status.passed_tests += 1;
        
        // Test 8: Security manager
        let security_config = wolf_net::SecurityConfig::default();
        let security = wolf_net::SecurityManager::new(security_config)
            .map_err(|e| anyhow!("Security manager creation failed: {}", e))?;
        debug!("  ✅ Security manager creation successful");
        status.test_count += 1;
        status.passed_tests += 1;
        
        status.functional = true;
        Ok(status)
    }).await;
    
    match validation_result {
        Ok(Ok(s)) => Ok(s),
        Ok(Err(e)) => {
            status.issues.push(e.to_string());
            Ok(status)
        }
        Err(_) => {
            status.issues.push("Validation timed out".to_string());
            Ok(status)
        }
    }
}

/// Validate wolfsec security library
async fn validate_wolfsec() -> Result<LibraryStatus> {
    let mut status = LibraryStatus {
        name: "wolfsec".to_string(),
        initialized: false,
        functional: false,
        version: "0.1.0".to_string(), // TODO: Get actual version
        test_count: 0,
        passed_tests: 0,
        duration_ms: 0,
        issues: Vec::new(),
    };
    
    debug!("🛡️ Validating wolfsec security library...");
    
    let validation_result = timeout(Duration::from_secs(10), async {
        // Test 1: Initialize wolfsec
        wolfsec::init()
            .map_err(|e| anyhow!("Initialization failed: {}", e))?;
        status.initialized = true;
        debug!("  ✅ wolfsec initialized successfully");
        status.test_count += 1;
        status.passed_tests += 1;
        
        // Test 2: Security manager
        let security_manager = wolfsec::SecurityManager::new()
            .map_err(|e| anyhow!("Security manager creation failed: {}", e))?;
        debug!("  ✅ Security manager creation successful");
        status.test_count += 1;
        status.passed_tests += 1;
        
        // Test 3: Threat analyzer
        let threat_analyzer = wolfsec::ThreatAnalyzer::new()
            .map_err(|e| anyhow!("Threat analyzer creation failed: {}", e))?;
        debug!("  ✅ Threat analyzer creation successful");
        status.test_count += 1;
        status.passed_tests += 1;
        
        // Test 4: Vulnerability scanner
        let vuln_scanner = wolfsec::VulnerabilityScanner::new()
            .map_err(|e| anyhow!("Vulnerability scanner creation failed: {}", e))?;
        debug!("  ✅ Vulnerability scanner creation successful");
        status.test_count += 1;
        status.passed_tests += 1;
        
        // Test 5: Audit logger
        let audit_logger = wolfsec::AuditLogger::new()
            .map_err(|e| anyhow!("Audit logger creation failed: {}", e))?;
        debug!("  ✅ Audit logger creation successful");
        status.test_count += 1;
        status.passed_tests += 1;
        
        // Test 6: Compliance checker
        let compliance_checker = wolfsec::ComplianceChecker::new()
            .map_err(|e| anyhow!("Compliance checker creation failed: {}", e))?;
        debug!("  ✅ Compliance checker creation successful");
        status.test_count += 1;
        status.passed_tests += 1;
        
        // Test 7: Security policy engine
        let policy_engine = wolfsec::SecurityPolicyEngine::new()
            .map_err(|e| anyhow!("Security policy engine creation failed: {}", e))?;
        debug!("  ✅ Security policy engine creation successful");
        status.test_count += 1;
        status.passed_tests += 1;
        
        // Test 8: Incident response
        let incident_response = wolfsec::IncidentResponse::new()
            .map_err(|e| anyhow!("Incident response creation failed: {}", e))?;
        debug!("  ✅ Incident response system creation successful");
        status.test_count += 1;
        status.passed_tests += 1;
        
        status.functional = true;
        Ok(status)
    }).await;
    
    match validation_result {
        Ok(Ok(s)) => Ok(s),
        Ok(Err(e)) => {
            status.issues.push(e.to_string());
            Ok(status)
        }
        Err(_) => {
            status.issues.push("Validation timed out".to_string());
            Ok(status)
        }
    }
}

/// Print comprehensive validation summary
fn print_validation_summary(results: &ValidationResults) {
    info!("📊 LIBRARY VALIDATION SUMMARY");
    info!("══════════════════════════════════════════════");
    
    // Print individual library status
    print_library_status(&results.wolf_den);
    print_library_status(&results.wolf_net);
    print_library_status(&results.wolfsec);
    
    // Print overall statistics
    let total_tests = results.wolf_den.test_count + results.wolf_net.test_count + results.wolfsec.test_count;
    let total_passed = results.wolf_den.passed_tests + results.wolf_net.passed_tests + results.wolfsec.passed_tests;
    let overall_success_rate = if total_tests > 0 {
        total_passed as f64 / total_tests as f64 * 100.0
    } else {
        0.0
    };
    
    info!("\n📈 OVERALL STATISTICS:");
    info!("  Total Tests: {}", total_tests);
    info!("  Passed: {}", total_passed);
    info!("  Failed: {}", total_tests - total_passed);
    info!("  Success Rate: {:.1}%", overall_success_rate);
    info!("  Validation Duration: {}ms", results.total_duration_ms);
    
    // Print warnings and errors
    if !results.warnings.is_empty() {
        info!("\n⚠️ WARNINGS:");
        for (i, warning) in results.warnings.iter().enumerate() {
            info!("  {}. {}", i + 1, warning);
        }
    }
    
    if !results.errors.is_empty() {
        info!("\n❌ ERRORS:");
        for (i, error) in results.errors.iter().enumerate() {
            info!("  {}. {}", i + 1, error);
        }
    }
    
    // Final status
    info!("\n🎯 FINAL STATUS:");
    if results.overall_success {
        info!("  ✅ ALL LIBRARIES HEALTHY - Dashboard startup approved");
    } else {
        info!("  ⚠️ SOME LIBRARIES UNHEALTHY - Dashboard startup not recommended");
    }
    
    info!("══════════════════════════════════════════════\n");
}

/// Print individual library status
fn print_library_status(status: &LibraryStatus) {
    let health_indicator = if status.is_healthy() { "✅" } else { "❌" };
    info!("{} {} (v{}) - {:.1}% success rate ({}ms)", 
        health_indicator, 
        status.name, 
        status.version,
        status.success_rate(),
        status.duration_ms
    );
    
    if !status.issues.is_empty() {
        for issue in &status.issues {
            info!("    ⚠️ {}", issue);
        }
    }
}

/// Quick health check for ongoing monitoring
pub async fn quick_health_check() -> Result<bool> {
    debug!("🔍 Performing quick health check...");
    
    let checks = vec![
        async {
            // Quick wolf_den check
            wolf_den::crypto::hash_data(b"health_check")
                .map(|_| true)
                .unwrap_or(false)
        },
        async {
            // Quick wolf_net check
            let peer_id = wolf_net::PeerId::random();
            peer_id.is_valid()
        },
        async {
            // Quick wolfsec check
            wolfsec::SecurityManager::new().is_ok()
        },
    ];
    
    let results = futures::future::join_all(checks).await;
    let healthy_count = results.iter().filter(|&&result| result).count();
    
    let is_healthy = healthy_count == 3;
    if is_healthy {
        debug!("✅ Quick health check passed");
    } else {
        debug!("⚠️ Quick health check failed: {}/3 libraries healthy", healthy_count);
    }
    
    Ok(is_healthy)
}
