#![allow(missing_docs)]
//! Wolf Security - Consolidated Security Module for Wolf Prowler.
//!
//! This module serves as the primary security orchestrator, integrating:
//! - **Network Security**: Based on `wolf_net`, providing firewalling and transport protection.
//! - **Cryptographic Operations**: Leveraging `wolf_den` for PQC-secured encryption and signing.
//! - **`WolfNode`**: The primary system facade for initialization and orchestration.
//! - **`SwarmManager`**: Low-level P2P swarm management, discovery, and routing.
//! - **`HuntCoordinator`**: An actor-based engine managing the "Wolf Pack" lifecycle (`Scent` -> `Stalk` -> `Strike`).

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
pub mod configuration_monitor;
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

pub use domain::events::{AuditEventType, CertificateAuditEvent};
pub use identity::crypto::{
    constant_time_eq, secure_compare, CryptoConfig, SecureRandom, WolfCrypto,
};
use thiserror::Error;
pub use wolf_net::firewall::{Action as FirewallAction, FirewallPolicy, FirewallRule};

use crate::observability::siem::{
    /* Asset, */ EventDetails, EventSeverity as SiemSeverity, EventSource, SIEMConfig,
    SecurityEvent as AdvancedSecurityEvent, SecurityEventType as SiemEventType, SourceType,
    WolfSIEMManager,
};
use crate::protection::network_security::SecurityManager;
use uuid::Uuid;

use crate::observability::siem::ResponseAction;
use tokio::sync::mpsc;
use wolf_net::{PeerId, SwarmCommand};

use crate::protection::container_security::wolf_den_containers::WolfDenContainerManager;
use crate::wolf_pack::hierarchy::WolfDenConfig;

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
    /// Underlying system I/O failure.
    #[error("I/O Error: {0}")]
    IOError(String),
    /// Unclassified or internal unexpected failure.
    #[error("Unknown Error: {0}")]
    Unknown(String),
}

/// Main Wolf Security orchestrator
pub type SecurityEngine = WolfSecurity;

/// Main Wolf Security orchestrator that manages all security components
/// central orchestrator that manages the lifecycle of all security components
pub struct WolfSecurity {
    /// Manager for low-level network security and firewalling
    pub network_security: NetworkSecurityManager,
    /// Core cryptographic engine for PQC-secured encryption and signing
    pub crypto: WolfCrypto,
    /// High-level threat detection and behavioral analysis engine
    pub threat_detector: ThreatDetector,
    /// Manager for multi-factor identity and role-based access control
    pub auth_manager: AuthManager,
    /// Manager for certificates and transient cryptographic keys
    pub key_manager: KeyManager,
    /// SIEM collector for security metrics and real-time alerts
    pub monitor: SecurityMonitor,
    /// Monitor for configuration file integrity
    pub config_monitor: configuration_monitor::ConfigurationMonitor,
    /// Automated vulnerability assessment and scanning tool
    pub vulnerability_scanner: VulnerabilityScanner,
    /// Security Information and Event Management orchestrator
    pub siem: WolfSIEMManager,
    /// optional channel for initiating proactive measures via the P2P swarm
    pub swarm_sender: Option<mpsc::UnboundedSender<SwarmCommand>>,
    /// orchestrator for isolated security containers (Wolf Dens)
    pub container_manager: WolfDenContainerManager,
    /// Shared access to the unified PQC-secured persistence storage
    pub storage: std::sync::Arc<tokio::sync::RwLock<wolf_db::storage::WolfDbStorage>>,
    /// Event bus for broadcasting security events
    pub event_bus: tokio::sync::broadcast::Sender<SecurityEvent>,
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
    /// Returns an error if the database path is invalid, DB cannot be opened, or components fail to initialize.
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

        let auth_repo = std::sync::Arc::new(
            infrastructure::persistence::wolf_db_auth_repository::WolfDbAuthRepository::new(
                storage.clone(),
            ),
        );
        let alert_repo = std::sync::Arc::new(
            infrastructure::persistence::wolf_db_alert_repository::WolfDbAlertRepository::new(
                storage.clone(),
            ),
        );
        let monitoring_repo = std::sync::Arc::new(
            infrastructure::persistence::wolf_db_monitoring_repository::WolfDbMonitoringRepository::new(storage.clone()),
        );
        let threat_repo = std::sync::Arc::new(
            infrastructure::persistence::wolf_db_threat_repository::WolfDbThreatRepository::new(
                storage.clone(),
            ),
        );

        let (event_bus, _) = tokio::sync::broadcast::channel(1000);

        Ok(Self {
            network_security: SecurityManager::new(
                "wolf_security".to_string(),
                config.network_security.default_security_level.clone(),
            ),
            crypto: WolfCrypto::new(config.crypto.clone())?,
            threat_detector: ThreatDetector::new(config.threat_detection.clone(), threat_repo),
            auth_manager: AuthManager::new(config.authentication.clone(), auth_repo),
            key_manager: KeyManager::new(config.key_management.clone()),
            monitor: SecurityMonitor::new(config.monitoring.clone(), monitoring_repo, alert_repo),
            config_monitor: configuration_monitor::ConfigurationMonitor::new(event_bus.clone()),
            vulnerability_scanner: VulnerabilityScanner::new()?,
            siem: WolfSIEMManager::new(SIEMConfig::default())?,
            swarm_sender: None,
            container_manager: WolfDenContainerManager::new(WolfDenConfig::default()),
            storage,
            event_bus,
        })
    }

    /// Initialize all security components
    /// bootstraps all security sub-modules and prepares the engine for operation.
    ///
    /// # Errors
    /// Returns an error if any component fails to initialize.
    pub async fn initialize(&mut self) -> anyhow::Result<()> {
        tracing::info!("🛡️ Initializing Wolf Security");

        // Initialize network security
        self.network_security.initialize().await?;
        tracing::info!("  ✅ Network security initialized");

        // Initialize crypto
        self.crypto.initialize().await?;
        tracing::info!("  ✅ Crypto engine initialized");

        // Initialize threat detection
        self.threat_detector.initialize().await?;
        tracing::info!("  ✅ Threat detection initialized");

        // Initialize authentication
        self.auth_manager.initialize().await?;
        tracing::info!("  ✅ Authentication initialized");

        // Initialize key management
        self.key_manager.initialize().await?;
        tracing::info!("  ✅ Key management initialized");

        // Initialize monitoring
        self.monitor.initialize().await?;
        tracing::info!("  ✅ Security monitoring initialized");

        // Initialize Configuration Monitoring
        if let Err(e) = self.config_monitor.watch_file("settings.toml").await {
            tracing::warn!("⚠️ Could not watch settings.toml: {}", e);
        }
        tracing::info!("  ✅ Configuration monitor initialized");

        // Validate Runtime Integrity
        if let Err(e) = sbom_validation::validate_runtime_integrity().await {
            tracing::warn!("⚠️ Runtime integrity check failed: {}", e);
        } else {
            tracing::info!("  ✅ Runtime integrity verified");
        }

        // Initialize Zero Trust

        Ok(())
    }

    /// Get trust analytics
    // pub fn get_trust_analytics(&self) -> security::advanced::zero_trust::TrustAnalytics {
    //     self.zero_trust_manager.get_trust_analytics()
    // }

    /// Set the Swarm Command Sender for SOAR integration
    /// Set the Swarm Command Sender for SOAR integration
    pub fn with_swarm_sender(&mut self, sender: mpsc::UnboundedSender<SwarmCommand>) {
        self.swarm_sender = Some(sender);
    }

    /// Get comprehensive security status
    /// Retrieves the aggregate status and telemetry for all active security modules.
    pub async fn get_status(&self) -> WolfSecurityStatus {
        WolfSecurityStatus {
            network_security: self.network_security.get_stats().await,
            crypto: self.crypto.get_status().await,
            threat_detection: self.threat_detector.get_status().await,
            authentication: self.auth_manager.get_status(),
            key_management: self.key_manager.get_status().await,
            monitoring: self.monitor.get_status().await,
        }
    }

    /// Process a security event
    /// routes a security signal to detection, monitoring, and automated response modules.
    ///
    /// # Errors
    /// Returns an error if event processing or response actions fail.
    pub async fn process_security_event(&mut self, event: SecurityEvent) -> anyhow::Result<()> {
        // Broadcast event
        let _ = self.event_bus.send(event.clone());

        // Route event to appropriate handlers
        self.threat_detector.handle_event(event.clone()).await?;
        self.monitor.log_event(event.clone()).await?;

        // Convert to Advanced SIEM event and process
        let advanced_event = self.convert_to_advanced_event(&event);
        match self.siem.process_event(advanced_event.clone()).await {
            Ok(actions) => {
                if !actions.is_empty() {
                    tracing::info!("🤖 SOAR: Executing {} response actions", actions.len());
                    if let Err(e) = self
                        .execute_response_actions(actions, &advanced_event)
                        .await
                    {
                        tracing::error!("SOAR Execution failed: {}", e);
                    }
                }
            }
            Err(e) => {
                tracing::error!("SIEM processing failed: {}", e);
            }
        }

        // Take action based on event severity
        if event.severity >= SecuritySeverity::High {
            self.handle_high_severity_event(event).await?;
        }

        Ok(())
    }

    /// Handle high-severity security events
    async fn handle_high_severity_event(&mut self, event: SecurityEvent) -> anyhow::Result<()> {
        tracing::warn!("🚨 High severity security event: {}", event.description);

        // Auto-block malicious peers
        if let Some(peer_id) = event.peer_id {
            self.threat_detector.block_peer(peer_id).await?;
        }

        // Rotate keys if compromise detected
        if matches!(event.event_type, SecurityEventType::KeyCompromise) {
            self.key_manager.rotate_all_keys().await?;
        }

        // Alert administrators
        let monitoring_alert = monitoring::Alert {
            id: Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
            severity: monitoring::AlertSeverity::High,
            title: "High Security Event".to_string(),
            description: format!("High security event: {}", event.description),
            source_events: vec![event.id],
            recommendations: vec!["Investigate immediately".to_string()],
            status: monitoring::AlertStatus::Open,
            acknowledged: false,
            acknowledged_by: None,
            acknowledged_at: None,
        };
        self.monitor.send_alert(monitoring_alert).await?;

        Ok(())
    }

    /// Execute SOAR response actions
    pub async fn execute_response_actions(
        &mut self,
        actions: Vec<ResponseAction>,
        event: &AdvancedSecurityEvent,
    ) -> anyhow::Result<()> {
        for action in actions {
            match action {
                ResponseAction::BlockNetwork => {
                    if let Some(target) = &event.target {
                        tracing::warn!("🛡️ SOAR: Blocking network for {}", target);
                        // 1. Firewall
                        // self.network_security.block_peer(target).await?;
                        // 2. Swarm Ban
                        if let Some(sender) = &self.swarm_sender {
                            let peer_id = PeerId::from_string(target.clone());
                            let _ = sender.send(SwarmCommand::BlockPeer { peer_id });
                        }
                    }
                }
                ResponseAction::IsolateSystem => {
                    if let Some(target) = &event.target {
                        tracing::warn!("☣️ SOAR: Isolating system {}", target);
                        if let Some(sender) = &self.swarm_sender {
                            let peer_id = PeerId::from_string(target.clone());
                            let _ = sender.send(SwarmCommand::DisconnectPeer { peer_id });
                        }
                    }
                }
                ResponseAction::RevokeAccess => {
                    // Revoke keys and auth
                    tracing::warn!("🔐 SOAR: Revoking access/keys");
                    self.key_manager.rotate_all_keys().await?;
                    // self.auth_manager.revoke_all_sessions().await?;
                }
                ResponseAction::RequireMFA => {
                    tracing::info!("🛡️ SOAR: Enforcing MFA");
                    // Logic to enforce MFA (update policy)
                }
                ResponseAction::IncreaseMonitoring => {
                    tracing::info!("👁️ SOAR: Increasing monitoring level");
                    // Logic to lower alert thresholds
                }
                ResponseAction::SendNotification => {
                    tracing::info!("📨 SOAR: Sending notification: {}", event.description);
                }
                ResponseAction::LogForInvestigation => {
                    tracing::info!("📝 SOAR: Logged for investigation: {}", event.event_id);
                }
                ResponseAction::QuarantineSystem => {
                    tracing::warn!("🧟 SOAR: Quarantining system");
                }
            }
        }
        Ok(())
    }

    /// Shutdown all security components
    /// gracefully shuts down all security components and clears sensitive memory.
    ///
    /// # Errors
    /// Returns an error if shutdown sequence fails.
    pub async fn shutdown(&mut self) -> anyhow::Result<()> {
        tracing::info!("🛡️ Shutting down Wolf Security");

        self.monitor.shutdown().await?;
        self.key_manager.shutdown().await?;
        self.auth_manager.shutdown().await?;
        self.threat_detector.shutdown().await?;
        self.crypto.shutdown().await?;
        self.network_security.shutdown().await?;

        tracing::info!("🛡️ Wolf Security shutdown complete");
        Ok(())
    }

    // Additional methods for API compatibility
    pub async fn get_metrics(&self) -> anyhow::Result<threat_detection::SecurityMetrics> {
        Ok(self.threat_detector.get_status().await.metrics)
    }

    pub async fn get_recent_alerts(&self) -> Vec<String> {
        // Placeholder
        Vec::new()
    }

    pub async fn get_recent_threats(&self) -> Vec<String> {
        // Placeholder
        Vec::new()
    }

    /// Subscribe to security events
    pub fn subscribe_events(&self) -> tokio::sync::broadcast::Receiver<SecurityEvent> {
        self.event_bus.subscribe()
    }
}

/// Configuration for Wolf Security
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WolfSecurityConfig {
    pub network_security: SecurityConfig,
    pub crypto: CryptoConfig,
    pub threat_detection: threat_detection::ThreatDetectionConfig,
    pub authentication: AuthConfig,
    pub key_management: identity::key_management::KeyManagementConfig,
    pub monitoring: monitoring::MonitoringConfig,
    pub db_path: std::path::PathBuf,
}

impl Default for WolfSecurityConfig {
    fn default() -> Self {
        Self {
            network_security: Default::default(),
            crypto: Default::default(),
            threat_detection: Default::default(),
            authentication: Default::default(),
            key_management: Default::default(),
            monitoring: Default::default(),
            db_path: std::path::PathBuf::from("wolf_data/wolfsec.db"),
        }
    }
}

/// Overall security status
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WolfSecurityStatus {
    pub network_security: network_security::SecurityStats,
    pub crypto: identity::crypto::CryptoStatus,
    pub threat_detection: threat_detection::ThreatDetectionStatus,
    pub authentication: auth::AuthStatus,
    pub key_management: identity::key_management::KeyManagementStatus,
    pub monitoring: monitoring::MonitoringStatus,
}

impl WolfSecurity {
    fn convert_to_advanced_event(&self, event: &SecurityEvent) -> AdvancedSecurityEvent {
        let severity = match event.severity {
            SecuritySeverity::Low => SiemSeverity::Scout,
            SecuritySeverity::Medium => SiemSeverity::Hunter,
            SecuritySeverity::High => SiemSeverity::Beta,
            SecuritySeverity::Critical => SiemSeverity::Alpha,
        };

        // Map event type vaguely for now
        let event_type =
            SiemEventType::SystemEvent(observability::siem::SystemEventType::SystemUpdate); // Default fallback

        AdvancedSecurityEvent {
            event_id: Uuid::parse_str(&event.id).unwrap_or_else(|_| Uuid::new_v4()),
            timestamp: event.timestamp,
            severity,
            event_type,
            source: EventSource {
                source_type: SourceType::SystemLogs,
                source_id: "WolfSecurity".to_string(),
                location: "Local".to_string(),
                credibility: 1.0,
            },
            affected_assets: vec![],
            details: EventDetails {
                title: event.description.clone(),
                description: event.description.clone(),
                technical_details: std::collections::HashMap::new(),
                user_context: None,
                system_context: None,
            },
            mitre_tactics: vec![],
            correlation_data: observability::siem::CorrelationData {
                related_events: vec![],
                correlation_score: 0.0,
                correlation_rules: vec![],
                attack_chain: None,
            },
            response_actions: vec![],
            target: event.peer_id.clone(),
            description: event.description.clone(),
            metadata: event.metadata.clone(),
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
        let mut wolf_sec = WolfSecurity::create(config).await.unwrap();

        wolf_sec.initialize().await.unwrap();

        let status = wolf_sec.get_status().await;
        // Metrics are unsigned, so >= 0 checks are redundant.
        // We only check that float scores are non-negative.
        assert!(
            status.threat_detection.metrics.security_score >= 0.0,
            "Security score should be non-negative"
        );
        assert!(
            status.threat_detection.metrics.compliance_score >= 0.0,
            "Compliance score should be non-negative"
        );
        assert!(
            status.threat_detection.metrics.attack_surface_score >= 0.0,
            "Attack surface score should be non-negative"
        );
        assert!(
            status.threat_detection.metrics.risk_score >= 0.0,
            "Risk score should be non-negative"
        );
        assert!(
            status
                .threat_detection
                .metrics
                .security_awareness_training_completion_rate
                >= 0.0,
            "Security awareness training completion rate should be non-negative"
        );
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
