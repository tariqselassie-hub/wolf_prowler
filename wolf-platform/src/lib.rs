//! Wolf Prowler Library
//!
//! A comprehensive P2P security network library with:
//! - Advanced cryptographic operations using Wolf Den
//! - Peer-to-peer networking and discovery
//! - Message routing and security
//! - Reputation and trust management
//! - SIEM security monitoring
//! - Metrics and monitoring

pub mod core;
// pub mod dashboard; // Moved to wolf_web
pub mod error; // Centralized error handling
pub mod health; // Health monitoring system
pub mod ingress_validation;
pub mod network;
pub mod network_extensions;
pub mod security;
pub mod utils;
pub mod validated_json;
pub mod validation; // Request validation // Validated JSON extractor

// Re-export wolfsec crate for easier access
pub use wolfsec;

pub mod compliance_service;
pub mod persistence;
pub mod threat_feeds;
pub mod wolf_brain;

// Re-export main components for easier use
pub use core::{AppSettings, CryptoEngine, P2PNetwork};
pub use network::P2PNetwork as NetworkService;
pub use security::SecurityManager;
pub use utils::MetricsCollector;

// Re-export validation utilities
pub use validated_json::ValidatedJson;
pub use validation::*;

/// Library version and metadata
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_is_set() {
        assert!(!VERSION.is_empty());
    }
}
