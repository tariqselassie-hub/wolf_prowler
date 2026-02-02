//! Wolfsec Prelude
//!
//! Common imports and re-exports for convenient use of the wolfsec crate.
//!
//! # Usage
//!
//! ```rust
//! use wolfsec::prelude::*;
//! ```

// Core types
pub use crate::WolfSecError;

// Identity & Authentication
pub use crate::identity::{
    auth::{AuthManager, Permission, Role, User},
    crypto::{CryptoConfig, SecureRandom, WolfCrypto},
    IdentityConfig, IdentityManager, SystemIdentity,
};

// Network Security
pub use crate::protection::network_security::{
    CryptoAlgorithm, SecurityConfig, SecurityLevel, SecurityManager as NetworkSecurityManager,
    SignatureAlgorithm, HIGH_SECURITY, LOW_SECURITY, MEDIUM_SECURITY,
};

// Threat Detection & Protection
pub use crate::protection::{
    reputation::ReputationCategory,
    threat_detection::{ThreatDetector, VulnerabilityScanner},
};

// Observability
pub use crate::observability::{
    alerts, audit, metrics,
    monitoring::{MetricsCollector, SecurityDashboard, SecurityMonitor, SIEM},
    reporting,
};

// Domain Events
pub use crate::domain::events::{AuditEventType, CertificateAuditEvent};

// Wolf Pack
pub use wolf_net::wolf_pack;
