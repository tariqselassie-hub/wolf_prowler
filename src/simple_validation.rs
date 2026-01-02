//! Simple Startup Validation for Wolf Prowler Dashboard
//!
//! Minimal validation that checks basic library functionality without complex API calls

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use tracing::{info, warn};

/// Simple validation results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimpleValidationResults {
    pub wolf_den_loaded: bool,
    pub wolf_net_loaded: bool,
    pub wolfsec_loaded: bool,
    pub overall_success: bool,
    pub total_duration_ms: u64,
    pub errors: Vec<String>,
}

impl SimpleValidationResults {
    pub fn all_passed(&self) -> bool {
        self.wolf_den_loaded && self.wolf_net_loaded && self.wolfsec_loaded
    }
}

/// Simple library validation
pub async fn validate_libraries_simple() -> Result<SimpleValidationResults> {
    let start_time = Instant::now();
    info!("🔍 Running simple library validation...");

    let mut results = SimpleValidationResults {
        wolf_den_loaded: false,
        wolf_net_loaded: false,
        wolfsec_loaded: false,
        overall_success: false,
        total_duration_ms: 0,
        errors: Vec::new(),
    };

    // Test wolf_den - just check if it compiles and basic init works
    match wolf_den::CryptoEngine::new(wolf_den::SecurityLevel::Standard) {
        Ok(_) => {
            results.wolf_den_loaded = true;
            info!("✅ wolf_den loaded successfully");
        }
        Err(e) => {
            results.errors.push(format!("wolf_den: {}", e));
            warn!("❌ wolf_den failed to load: {}", e);
        }
    }

    // Test wolf_net - just check if it compiles and basic init works
    let temp_settings = wolf_prowler::core::AppSettings::default();
    match wolf_prowler::core::P2PNetwork::new(&temp_settings.network) {
        Ok(_) => {
            results.wolf_net_loaded = true;
            info!("✅ wolf_net loaded successfully");
        }
        Err(e) => {
            results.errors.push(format!("wolf_net: {}", e));
            warn!("❌ wolf_net failed to load: {}", e);
        }
    }

    // Test wolfsec - just check if basic types are available
    // Note: wolfsec doesn't have an init() function, so we'll test basic functionality
    if test_wolfsec_basic().await {
        results.wolfsec_loaded = true;
        info!("✅ wolfsec loaded successfully");
    } else {
        results
            .errors
            .push("wolfsec: Basic functionality test failed".to_string());
        warn!("❌ wolfsec failed basic functionality test");
    }

    results.overall_success = results.all_passed();
    results.total_duration_ms = start_time.elapsed().as_millis() as u64;

    print_simple_results(&results);

    Ok(results)
}

/// Test basic wolfsec functionality
async fn test_wolfsec_basic() -> bool {
    // Test basic wolfsec functionality by creating a config and the main struct
    let config = wolfsec::WolfSecurityConfig::default();
    match wolfsec::WolfSecurity::new(config) {
        Ok(_) => true,
        Err(e) => {
            warn!("wolfsec basic test failed during initialization: {}", e);
            false
        }
    }
}

/// Print simple validation results
fn print_simple_results(results: &SimpleValidationResults) {
    info!("📊 SIMPLE VALIDATION RESULTS");
    info!("════════════════════════════════════════");

    info!(
        "🔐 wolf_den (Cryptography):     {}",
        if results.wolf_den_loaded {
            "✅ LOADED"
        } else {
            "❌ FAILED"
        }
    );
    info!(
        "🌐 wolf_net (Networking):       {}",
        if results.wolf_net_loaded {
            "✅ LOADED"
        } else {
            "❌ FAILED"
        }
    );
    info!(
        "🛡️ wolfsec (Security):          {}",
        if results.wolfsec_loaded {
            "✅ LOADED"
        } else {
            "❌ FAILED"
        }
    );

    info!("\n📈 Overall Statistics:");
    info!("  Validation Duration: {}ms", results.total_duration_ms);

    if !results.errors.is_empty() {
        info!("\n❌ Errors:");
        for (i, error) in results.errors.iter().enumerate() {
            info!("  {}. {}", i + 1, error);
        }
    }

    info!(
        "\n🎯 Final Status: {}",
        if results.overall_success {
            "✅ ALL LIBRARIES LOADED - Dashboard can start safely"
        } else {
            "⚠️ SOME LIBRARIES FAILED - Dashboard startup may be unstable"
        }
    );

    info!("════════════════════════════════════════\n");
}
