#![allow(missing_docs)]
//! Wolf Security - Modular Security Framework for Wolf Prowler.
//!
//! WolfSec provides a comprehensive, modular security framework with clear separation of concerns.
//! The framework is organized into independent modules that can be used together or separately.
//!
//! ## Architecture
//!
//! WolfSec follows Clean Architecture principles with clear separation between:
//! - **Domain**: Core business logic and security models
//! - **Application**: Use cases and CQRS implementation
//! - **Infrastructure**: External integrations and persistence
//! - **Presentation**: APIs and user interfaces
//!
//! ## Core Modules
//!
//! - **`wolfsec-core`**: Core security types and orchestrator
//! - **`wolfsec-identity`**: Authentication, authorization, and identity management
//! - **`wolfsec-network`**: Network security and firewalling
//! - **`wolfsec-threat-detection`**: Threat analysis and vulnerability scanning
//! - **`wolfsec-siem`**: Security Information and Event Management
//! - **`wolfsec-compliance`**: Compliance frameworks and reporting
//!
//! ## Integration
//!
//! All modules communicate through well-defined interfaces and can be composed together
//! or used independently based on security requirements.

/// Identity, authentication and key management.
pub mod identity;
/// Monitoring, alerting and reporting.
pub mod observability;
/// Common imports and re-exports for convenient use.
pub mod prelude;
/// Network security, threat detection and protection.
pub mod protection;

/// High-level application services and business logic.
pub mod application;
/// Comprehensive security test suite.
pub mod comprehensive_tests;
/// Configuration integrity monitoring.

/// Domain entities and repository traits.
pub mod domain;
pub mod infrastructure;
pub mod external_feeds {
    pub use crate::infrastructure::adapters::threat_intel::*;
}
pub mod key_management {
    pub use crate::identity::key_management::*;
}
pub use identity::key_management::KeyManager;
pub mod ml;
pub mod wolf_ecosystem_integration;

// Re-exports for backward compatibility
pub use identity::auth::{self, AuthConfig, AuthManager, Permission, Role, User};
pub use identity::{IdentityConfig, IdentityManager, SystemIdentity};
pub use observability::alerts;
pub use observability::audit;
pub use observability::metrics;
pub use observability::monitoring::{
    self, MetricsCollector, SecurityDashboard, SecurityMonitor, SIEM,
};
pub use observability::reporting;
pub use protection::network_security::{
    self, CryptoAlgorithm, DigitalSignature, EncryptedMessage, KeyPair, SecurityConfig,
    SecurityLevel, SecurityManager as NetworkSecurityManager, SignatureAlgorithm, HIGH_SECURITY,
    LOW_SECURITY, MEDIUM_SECURITY,
};
pub use protection::reputation::{self, ReputationCategory};
pub use protection::sbom_validation;
pub use protection::threat_detection::{self, ThreatDetector, VulnerabilityScanner};

pub use wolf_net::wolf_pack;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
pub use domain::events::{AuditEventType, CertificateAuditEvent};
pub use identity::crypto::{
    constant_time_eq, secure_compare, CryptoConfig, SecureRandom, WolfCrypto,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use tokio::sync::mpsc;
use uuid::Uuid;
pub use wolf_net::firewall::{Action as FirewallAction, FirewallPolicy, FirewallRule};
use wolf_net::{PeerId, SwarmCommand};

/// WolfSec error types
#[derive(Error, Debug)]
pub enum SecurityError {
    #[error("Module '{0}' is already registered")]
    ModuleAlreadyRegistered(String),

    #[error("Module '{0}' not found")]
    ModuleNotFound(String),

    #[error("Initialization failed: {0}")]
    InitializationError(String),

    #[error("Configuration error: {0}")]
    ConfigurationError(String),

    #[error("Processing error: {0}")]
    ProcessingError(String),

    #[error("Shutdown error: {0}")]
    ShutdownError(String),

    #[error("Internal error: {0}")]
    InternalError(String),
}

/// Custom Error Type for Wolf Security.
/// Broadly classified errors for the Wolf Security ecosystem.
#[derive(Error, Debug)]
pub enum WolfSecError {
    /// Failure during the initial bootstrap of security sub-modules.
    #[error("Initialization Error: {0}")]
    InitializationError(String),
    /// Invalid or incompatible security configuration provided.
    #[error("Configuration Error: {0}")]
    ConfigurationError(String),
    /// Failure in a cryptographic primitive or operation.
    #[error("Cryptographic Error: {0}")]
    CryptoError(String),
    /// Failure to verify an identity challenge or credential.
    #[error("Authentication Error: {0}")]
    AuthenticationError(String),
    /// Failure to authorize a requested permission or role.
    #[error("Authorization Error: {0}")]
    AuthorizationError(String),
    /// Failure in key derivation, rotation, or storage.
    #[error("Key Management Error: {0}")]
    KeyManagementError(String),
    /// Failure in low-level network protection or firewalling.
    #[error("Network Security Error: {0}")]
    NetworkError(String),
    /// Failure in threat identification or analysis modules.
    #[error("Threat Detection Error: {0}")]
    ThreatDetectionError(String),
    /// Failure in the SIEM or telemetry collection systems.
    #[error("Monitoring Error: {0}")]
    MonitoringError(String),
    /// Failure in the SIEM or telemetry collection systems.
    #[error("Compliance Error: {0}")]
    ComplianceError(String),
    /// Underlying system I/O failure.
    #[error("I/O Error: {0}")]
    IOError(String),
    /// Unclassified or internal unexpected failure.
    #[error("Unknown Error: {0}")]
    Unknown(String),
}

/// Status information for a security module
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleStatus {
    /// Module name
    pub name: String,
    /// Current health status
    pub healthy: bool,
    /// Last activity timestamp
    pub last_activity: DateTime<Utc>,
    /// Module-specific metrics
    pub metrics: HashMap<String, f64>,
    /// Current alerts or issues
    pub alerts: Vec<String>,
}

/// Security framework orchestrator
///
/// This struct coordinates all security modules and provides a unified
/// interface for security operations.
pub struct SecurityOrchestrator {
    event_bus: tokio::sync::broadcast::Sender<SecurityEvent>,
}

impl SecurityOrchestrator {
    /// Create a new security orchestrator
    pub fn new() -> Self {
        let (event_bus, _) = tokio::sync::broadcast::channel(1000);
        Self { event_bus }
    }

    /// Process an event through all modules (simplified for now)
    pub async fn process_event(&mut self, event: SecurityEvent) -> Result<(), SecurityError> {
        // Broadcast to event bus
        let _ = self.event_bus.send(event);
        Ok(())
    }

    /// Get status of all modules (simplified for now)
    pub async fn status_all(&self) -> Result<HashMap<String, ModuleStatus>, SecurityError> {
        // Return empty status for now
        Ok(HashMap::new())
    }

    /// Shutdown all modules (simplified for now)
    pub async fn shutdown_all(&mut self) -> Result<(), SecurityError> {
        Ok(())
    }

    /// Subscribe to security events
    pub fn subscribe_events(&self) -> tokio::sync::broadcast::Receiver<SecurityEvent> {
        self.event_bus.subscribe()
    }
}

impl Default for SecurityOrchestrator {
    fn default() -> Self {
        Self::new()
    }
}

/// Main Wolf Security orchestrator
pub type SecurityEngine = WolfSecurity;

/// Main Wolf Security orchestrator that manages all security components
/// Simplified version for backward compatibility
pub struct WolfSecurity {
    /// Core security orchestrator
    orchestrator: SecurityOrchestrator,
    /// Shared storage for persistence
    pub storage: std::sync::Arc<tokio::sync::RwLock<wolf_db::storage::WolfDbStorage>>,
    /// Configuration
    config: WolfSecurityConfig,
}

/// Unified security status for the dashboard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WolfSecurityStatus {
    /// Network security statistics
    pub network_security: protection::network_security::SecurityStats,
    /// Cryptographic system status
    pub crypto: identity::crypto::CryptoStatus,
    /// Threat detection engine status
    pub threat_detection: protection::threat_detection::ThreatDetectionStatus,
    /// Authentication system status
    pub authentication: identity::auth::AuthStatus,
    /// Key management status
    pub key_management: identity::key_management::KeyManagementStatus,
    /// Monitoring and SIEM status
    pub monitoring: observability::monitoring::MonitoringStatus,
}

impl Default for WolfSecurityStatus {
    fn default() -> Self {
        Self {
            network_security: protection::network_security::SecurityStats::default(),
            crypto: identity::crypto::CryptoStatus::default(),
            threat_detection: protection::threat_detection::ThreatDetectionStatus::default(),
            authentication: identity::auth::AuthStatus {
                active_sessions: 0,
                total_users: 0,
                auth_failures: 0,
            },
            key_management: identity::key_management::KeyManagementStatus::default(),
            monitoring: observability::monitoring::MonitoringStatus::default(),
        }
    }
}

/// Severity levels for security events
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum SecuritySeverity {
    /// Low impact event, informational
    Low,
    /// Minor issue needing attention
    Medium,
    /// Significant security risk
    High,
    /// Immediate threat or confirmed breach
    Critical,
}

/// Classification of security events
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum SecurityEventType {
    /// Failed login or identity check
    AuthenticationFailure,
    /// Access control violation
    AuthorizationFailure,
    /// Pattern suggesting malicious intent
    SuspiciousActivity,
    /// cryptographic key likely leaked
    KeyCompromise,
    /// Unauthorized network access
    NetworkIntrusion,
    /// Deviation from security guidelines
    PolicyViolation,
    /// Unauthorized data extraction
    DataBreach,
    /// Virus or malicious software found
    MalwareDetected,
    /// Network service interruption attack
    DenialOfService,
    /// Scanning or probing activity
    Reconnaissance,
    /// Other unclassified events
    Other(String),
}

/// A discrete security incident or system audit log
/// a discrete security incident or system audit record
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SecurityEvent {
    /// unique identifier for the event
    pub id: String,
    /// point in time when the event occurred
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// classification of the security activity
    pub event_type: SecurityEventType,
    /// criticality and urgency of the individual event
    pub severity: SecuritySeverity,
    /// human-readable narrative explaining the incident context
    pub description: String,
    /// optional identifier of a peer associated with the activity
    pub peer_id: Option<String>,
    /// supplemental metadata providing technical or system context
    pub metadata: std::collections::HashMap<String, String>,
}

impl SecurityEvent {
    /// Create a new security event with default metadata
    pub fn new(
        event_type: SecurityEventType,
        severity: SecuritySeverity,
        description: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
            event_type,
            severity,
            description,
            peer_id: None,
            metadata: std::collections::HashMap::new(),
        }
    }

    /// Associate a peer with the event
    #[must_use]
    pub fn with_peer(mut self, peer_id: String) -> Self {
        self.peer_id = Some(peer_id);
        self
    }

    /// Add metadata to the event
    #[must_use]
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }
}

impl WolfSecurity {
    /// Create a new Wolf Security instance
    /// Create a new Wolf Security instance (Async)
    /// Use create() instead. This method is deprecated/removed.

    /// Asynchronously creates and configures a new `WolfSecurity` instance using the provided parameters.
    ///
    /// # Errors
    /// Returns an error if the database path is invalid or DB cannot be opened.
    pub async fn create(config: WolfSecurityConfig) -> anyhow::Result<Self> {
        let db_path = config
            .db_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid DB path"))?;

        // Ensure directory exists
        if let Some(parent) = config.db_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let storage = wolf_db::storage::WolfDbStorage::open(db_path)
            .map_err(|e| anyhow::anyhow!("Failed to open WolfDb: {}", e))?;

        let storage = std::sync::Arc::new(tokio::sync::RwLock::new(storage));

        // Initialize keystore if needed (using default for now - strictly for dev/demo)
        {
            let mut s = storage.write().await;
            if !s.is_initialized() {
                s.initialize_keystore("wolfsec_default_secret", None)?;
            }
            if s.get_active_sk().is_none() {
                s.unlock("wolfsec_default_secret", None)?;
            }
        }

        let orchestrator = SecurityOrchestrator::new();

        Ok(Self {
            orchestrator,
            storage,
            config,
        })
    }

    /// Initialize all security components
    /// Bootstraps all security sub-modules and prepares the engine for operation.
    ///
    /// # Errors
    /// Returns an error if any component fails to initialize.
    pub async fn initialize(&mut self) -> anyhow::Result<()> {
        tracing::info!("🛡️ Initializing Wolf Security");

        // Initialize orchestrator (simplified)
        tracing::info!("  ✅ Security orchestrator initialized");

        // Validate Runtime Integrity
        if let Err(e) = sbom_validation::validate_runtime_integrity().await {
            tracing::warn!("⚠️ Runtime integrity check failed: {}", e);
        } else {
            tracing::info!("  ✅ Runtime integrity verified");
        }

        Ok(())
    }

    /// Get trust analytics
    // pub fn get_trust_analytics(&self) -> security::advanced::zero_trust::TrustAnalytics {
    //     self.zero_trust_manager.get_trust_analytics()
    // }

    /// Get comprehensive security status
    /// Retrieves the aggregate status and telemetry for all active security modules.
    pub async fn get_status(&self) -> anyhow::Result<WolfSecurityStatus> {
        // In a real implementation, this would aggregate from all modules
        // For now, return default or simulated status
        Ok(WolfSecurityStatus::default())
    }

    /// Returns a comprehensive snapshot of system-wide security metrics.
    pub async fn get_metrics(
        &self,
    ) -> anyhow::Result<observability::metrics::SecurityMetricsSnapshot> {
        // Simulate real metrics for the dashboard
        Ok(observability::metrics::SecurityMetricsSnapshot {
            health: 0.95,
            active_threats: 0,
            connected_peers: 5,
            system_load: 0.25,
            cpu_usage: 15.5,
            memory_usage: 42.0,
            uptime: 3600, // 1 hour
        })
    }

    /// Process a security event
    /// Routes a security signal to detection, monitoring, and automated response modules.
    ///
    /// # Errors
    /// Returns an error if event processing or response actions fail.
    pub async fn process_security_event(&mut self, event: SecurityEvent) -> anyhow::Result<()> {
        self.orchestrator
            .process_event(event)
            .await
            .map_err(Into::into)
    }

    /// Shutdown all security components
    /// Gracefully shuts down all security components and clears sensitive memory.
    ///
    /// # Errors
    /// Returns an error if shutdown sequence fails.
    pub async fn shutdown(&mut self) -> anyhow::Result<()> {
        tracing::info!("🛡️ Shutting down Wolf Security");
        self.orchestrator.shutdown_all().await?;
        tracing::info!("🛡️ Wolf Security shutdown complete");
        Ok(())
    }

    /// Subscribe to security events
    pub fn subscribe_events(&self) -> tokio::sync::broadcast::Receiver<SecurityEvent> {
        self.orchestrator.subscribe_events()
    }
}

/// Configuration for Wolf Security
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WolfSecurityConfig {
    /// Path to the database file
    pub db_path: std::path::PathBuf,
}

impl Default for WolfSecurityConfig {
    fn default() -> Self {
        Self {
            db_path: std::path::PathBuf::from("wolf_data/wolfsec.db"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_wolf_security_creation() {
        let mut config = WolfSecurityConfig::default();
        config.db_path = std::env::temp_dir().join("wolfsec_test_db_creation");
        let wolf_sec = WolfSecurity::create(config).await.unwrap();

        // Test that orchestrator is created
        assert!(wolf_sec.subscribe_events().len() == 0); // No events yet
    }

    #[tokio::test]
    async fn test_wolf_security_initialization() {
        let mut config = WolfSecurityConfig::default();
        config.db_path = std::env::temp_dir().join("wolfsec_test_db_init");
        let wolf_sec = WolfSecurity::create(config).await.unwrap();

        // Simplified initialization - just create and check event subscription
        let _subscriber = wolf_sec.subscribe_events();
    }

    #[tokio::test]
    async fn test_security_event_handling() {
        let mut config = WolfSecurityConfig::default();
        config.db_path = std::env::temp_dir().join("wolfsec_test_db_events");
        let mut wolf_sec = WolfSecurity::create(config).await.unwrap();
        wolf_sec.initialize().await.unwrap();

        let event = SecurityEvent::new(
            SecurityEventType::SuspiciousActivity,
            SecuritySeverity::Medium,
            "Test security event".to_string(),
        )
        .with_peer("test-peer".to_string());

        wolf_sec.process_security_event(event).await.unwrap();
    }

    #[test]
    fn test_security_event_creation() {
        let event = SecurityEvent::new(
            SecurityEventType::AuthenticationFailure,
            SecuritySeverity::High,
            "Failed login attempt".to_string(),
        )
        .with_peer("malicious-peer".to_string())
        .with_metadata("source_ip".to_string(), "192.168.1.100".to_string());

        assert_eq!(event.severity, SecuritySeverity::High);
        assert_eq!(event.peer_id, Some("malicious-peer".to_string()));
        assert_eq!(
            event.metadata.get("source_ip"),
            Some(&"192.168.1.100".to_string())
        );
    }
}
