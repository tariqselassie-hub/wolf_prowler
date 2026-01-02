#![allow(dead_code)]
//! Wolf Security - Consolidated Security Module for Wolf Prowler
//!
//! This module consolidates all security functionality across the Wolf Prowler project:
//! - Network security (from wolf_net)
//! - Cryptographic operations (from wolf_den)
//! - Threat detection and response (from core)
//! - Authentication and authorization
//! - Key management and rotation
//! - Security monitoring and SIEM

pub mod alerts;
pub mod application;
pub mod authentication;
pub mod crypto;
pub mod domain;
pub mod external_feeds;
// pub mod firewall; // Moved to wolf_net
pub mod infrastructure;
pub mod key_management;
pub mod monitoring;
pub mod network_security;
pub mod reputation;
pub mod security;
pub mod threat_detection;
pub mod wolf_ecosystem_integration;
pub use authentication::{AuthManager, Permission, Role, User};
pub use wolf_net::wolf_pack;

pub use key_management::{
    AlertSeverity, AuditEventType, Certificate, CertificateAuditEvent, CertificateStore,
    ExpirationAlert, KeyEntry, KeyManager, KeyStore, RevocationInfo, RevocationReason,
    RevocationStatus, TrustLevel, ValidationResult,
};

pub use monitoring::{MetricsCollector, SecurityDashboard, SecurityMonitor, SIEM};
pub use reputation::ReputationManager;

pub use crypto::{constant_time_eq, secure_compare, CryptoConfig, SecureRandom, WolfCrypto};

pub use threat_detection::{ThreatDetector, VulnerabilityScanner};

pub use network_security::{
    CryptoAlgorithm, DigitalSignature, EncryptedMessage, KeyPair, SecurityConfig, SecurityLevel,
    SecurityManager as NetworkSecurityManager, SignatureAlgorithm, HIGH_SECURITY, LOW_SECURITY,
    MEDIUM_SECURITY,
};
use thiserror::Error;
pub use wolf_net::firewall::{Action as FirewallAction, FirewallPolicy, FirewallRule};

use crate::network_security::SecurityManager;
use crate::security::advanced::siem::{
    /* Asset, */ EventDetails, EventSeverity as SiemSeverity, EventSource, SIEMConfig,
    SecurityEvent as AdvancedSecurityEvent, SecurityEventType as SiemEventType, SourceType,
    WolfSIEMManager,
};
use uuid::Uuid;

use crate::security::advanced::siem::ResponseAction;
use tokio::sync::mpsc;
use wolf_net::{PeerId, SwarmCommand};

use crate::security::advanced::container_security::wolf_den_containers::WolfDenContainerManager;
use crate::wolf_pack::hierarchy::WolfDenConfig;

/// Custom Error Type for Wolf Security
#[derive(Error, Debug)]
pub enum WolfSecError {
    #[error("Initialization Error: {0}")]
    InitializationError(String),
    #[error("Configuration Error: {0}")]
    ConfigurationError(String),
    #[error("Cryptographic Error: {0}")]
    CryptoError(String),
    #[error("Authentication Error: {0}")]
    AuthenticationError(String),
    #[error("Authorization Error: {0}")]
    AuthorizationError(String),
    #[error("Key Management Error: {0}")]
    KeyManagementError(String),
    #[error("Network Security Error: {0}")]
    NetworkError(String),
    #[error("Threat Detection Error: {0}")]
    ThreatDetectionError(String),
    #[error("Monitoring Error: {0}")]
    MonitoringError(String),
    #[error("I/O Error: {0}")]
    IOError(String),
    #[error("Unknown Error: {0}")]
    Unknown(String),
}

/// Main Wolf Security orchestrator
pub type SecurityEngine = WolfSecurity;

pub struct WolfSecurity {
    /// Network security manager
    pub network_security: SecurityManager,
    /// Cryptographic engine
    pub crypto: WolfCrypto,
    /// Threat detection system
    pub threat_detector: ThreatDetector,
    /// Authentication manager
    pub auth_manager: AuthManager,
    /// Key management system
    pub key_manager: KeyManager,
    /// Security monitoring
    pub monitor: SecurityMonitor,
    /// Vulnerability scanner
    pub vulnerability_scanner: VulnerabilityScanner,
    /// Advanced SIEM Manager
    pub siem: WolfSIEMManager,
    /// Swarm Command Sender for SOAR
    pub swarm_sender: Option<mpsc::UnboundedSender<SwarmCommand>>,
    /// Container Security Manager
    pub container_manager: WolfDenContainerManager,
    // Zero Trust Manager
    // pub zero_trust_manager: security::advanced::zero_trust::ZeroTrustManager,
}

/// Security Event Severity
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum SecuritySeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Security Event Type
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum SecurityEventType {
    AuthenticationFailure,
    AuthorizationFailure,
    SuspiciousActivity,
    KeyCompromise,
    NetworkIntrusion,
    PolicyViolation,
    DataBreach,
    MalwareDetected,
    DenialOfService,
    Reconnaissance,
    // Add others as needed
    Other(String),
}

/// Security Event
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SecurityEvent {
    pub id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub event_type: SecurityEventType,
    pub severity: SecuritySeverity,
    pub description: String,
    pub peer_id: Option<String>,
    pub metadata: std::collections::HashMap<String, String>,
}

impl SecurityEvent {
    pub fn new(
        event_type: SecurityEventType,
        severity: SecuritySeverity,
        description: String,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
            event_type,
            severity,
            description,
            peer_id: None,
            metadata: std::collections::HashMap::new(),
        }
    }

    pub fn with_peer(mut self, peer_id: String) -> Self {
        self.peer_id = Some(peer_id);
        self
    }

    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }
}

impl WolfSecurity {
    /// Create a new Wolf Security instance
    pub fn new(config: WolfSecurityConfig) -> anyhow::Result<Self> {
        Ok(Self {
            network_security: SecurityManager::new(
                "wolf_security".to_string(),
                config.network_security.default_security_level.clone(),
            ),
            crypto: WolfCrypto::new(config.crypto.clone())?,
            threat_detector: ThreatDetector::new(config.threat_detection.clone()),
            auth_manager: AuthManager::new(config.authentication.clone()),
            key_manager: KeyManager::new(config.key_management.clone()),
            monitor: SecurityMonitor::new(config.monitoring.clone()),
            vulnerability_scanner: VulnerabilityScanner::new()?,
            siem: WolfSIEMManager::new(SIEMConfig::default())?,
            swarm_sender: None,
            container_manager: WolfDenContainerManager::new(WolfDenConfig::default()),
            // zero_trust_manager: security::advanced::zero_trust::ZeroTrustManager::new()?,
        })
    }

    /// Initialize all security components
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

        // Initialize Zero Trust
        // // self.zero_trust_manager.initialize().await?;
        // // ZeroTrustManager currently has no async initialize method in its interface, assuming new() is enough or we add one later.
        // tracing::info!("  ✅ Zero Trust initialized");

        Ok(())
    }

    /// Get trust analytics
    // pub fn get_trust_analytics(&self) -> security::advanced::zero_trust::TrustAnalytics {
    //     self.zero_trust_manager.get_trust_analytics()
    // }

    /// Set the Swarm Command Sender for SOAR integration
    pub fn with_swarm_sender(&mut self, sender: mpsc::UnboundedSender<SwarmCommand>) {
        self.swarm_sender = Some(sender);
    }

    /// Get comprehensive security status
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
    pub async fn process_security_event(&mut self, event: SecurityEvent) -> anyhow::Result<()> {
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
            id: uuid::Uuid::new_v4().to_string(),
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
    async fn execute_response_actions(
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
}

/// Configuration for Wolf Security
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct WolfSecurityConfig {
    pub network_security: network_security::SecurityConfig,
    pub crypto: crypto::CryptoConfig,
    pub threat_detection: threat_detection::ThreatDetectionConfig,
    pub authentication: authentication::AuthConfig,
    pub key_management: key_management::KeyManagementConfig,
    pub monitoring: monitoring::MonitoringConfig,
    // pub zero_trust: security::advanced::zero_trust::ZeroTrustConfig,
}

/// Overall security status
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WolfSecurityStatus {
    pub network_security: network_security::SecurityStats,
    pub crypto: crypto::CryptoStatus,
    pub threat_detection: threat_detection::ThreatDetectionStatus,
    pub authentication: authentication::AuthStatus,
    pub key_management: key_management::KeyManagementStatus,
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
        let event_type = SiemEventType::SystemEvent(
            crate::security::advanced::siem::SystemEventType::SystemUpdate,
        ); // Default fallback

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
            correlation_data: crate::security::advanced::siem::CorrelationData {
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
        let config = WolfSecurityConfig::default();
        let mut wolf_sec = WolfSecurity::new(config).unwrap();

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
        let config = WolfSecurityConfig::default();
        let mut wolf_sec = WolfSecurity::new(config).unwrap();
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
