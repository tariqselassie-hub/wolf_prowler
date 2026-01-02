//! Core functionality for Wolf Prowler
//!
//! This module contains the fundamental components:
//! - P2P networking engine
//! - Cryptographic operations using Wolf Den
//! - Security management
//! - Configuration handling

pub mod anomaly_detection;
pub mod behavioral_analysis;
pub mod crypto_wolf_den_simple;

pub mod defaults;
pub mod error;
pub mod p2p_simple;
pub mod reputation_response;
pub mod security_simple;
pub mod threat_detection;
pub mod types;
// Cloud features disabled - requires optional AWS dependencies
// #[cfg(feature = "cloud_security")]
// pub mod cloud;
pub mod security_policy;
pub mod settings;
pub mod reporting;

// Re-exports
pub use crypto_wolf_den_simple::CryptoEngine;
pub use p2p_simple::P2PNetwork;
pub use security_simple::SecurityManager;
pub use settings::{AppSettings, WolfRole};
pub use threat_detection::ThreatDetectionEngine;
pub use reporting::ReportingService;

/// Main Wolf Prowler core system
pub struct WolfProwlerCore {
    config: AppSettings,
    crypto: CryptoEngine,
    network: P2PNetwork,
    security: SecurityManager,
    threat_detection: ThreatDetectionEngine,
}

impl WolfProwlerCore {
    /// Create a new core instance with default configuration
    pub fn new_default() -> Result<Self, Box<dyn std::error::Error>> {
        let config = AppSettings::default();
        Self::new(config)
    }

    /// Create a new core instance with custom configuration
    pub fn new(config: AppSettings) -> Result<Self, Box<dyn std::error::Error>> {
        let crypto = CryptoEngine::new(&config.crypto)?;
        let network = P2PNetwork::new(&config.network)?;
        let security = SecurityManager::new(&config.security)?;
        let threat_detection = ThreatDetectionEngine::new(
            crate::core::threat_detection::ThreatDetectionConfig::default(),
        );

        Ok(Self {
            config,
            crypto,
            network,
            security,
            threat_detection,
        })
    }

    /// Get the current configuration
    pub fn config(&self) -> &AppSettings {
        &self.config
    }

    /// Get the crypto engine
    pub fn crypto(&self) -> &CryptoEngine {
        &self.crypto
    }

    /// Get the P2P network
    pub fn network(&self) -> &P2PNetwork {
        &self.network
    }

    /// Get the security manager
    pub fn security(&self) -> &SecurityManager {
        &self.security
    }

    /// Get the threat detection engine
    pub fn threat_detection(&self) -> &ThreatDetectionEngine {
        &self.threat_detection
    }

    /// Start the core system
    pub fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        log::info!("🐺 Starting Wolf Prowler Core...");

        self.network.start()?;

        log::info!("✅ Wolf Prowler Core started successfully");
        Ok(())
    }

    /// Stop the core system
    pub fn stop(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        log::info!("🛑 Stopping Wolf Prowler Core...");

        self.network.stop()?;

        log::info!("✅ Wolf Prowler Core stopped");
        Ok(())
    }
}
