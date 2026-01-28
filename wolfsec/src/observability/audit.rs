//! Security Auditing
//!
//! Comprehensive security operation tracking and audit trail with wolf-themed approach
// Audit system is now active - security critical component

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, instrument, warn};

use anyhow::Error;

// Import wolf-themed configurations
use crate::wolf_pack::hierarchy::WolfDenConfig;
use libp2p::PeerId;

/// Wolf-themed audit configuration
pub type AuditConfig = WolfDenConfig;

/// Wolf-themed audit manager
pub struct AuditManager {
    config: AuditConfig,
    audit_entries: Arc<RwLock<Vec<AuditEntry>>>,
    is_monitoring: Arc<RwLock<bool>>,
}

impl AuditManager {
    pub async fn new(config: AuditConfig) -> Result<Self, Error> {
        Ok(Self {
            config,
            audit_entries: Arc::new(RwLock::new(Vec::new())),
            is_monitoring: Arc::new(RwLock::new(true)),
        })
    }
}

/// Legacy audit configuration (for backward compatibility)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecurityAuditConfig {
    /// Enable audit logging
    pub enable_audit: bool,
    /// Maximum number of audit entries to keep
    pub max_audit_entries: usize,
    /// Audit retention period in days
    pub retention_days: u64,
    /// Enable detailed audit logging
    pub enable_detailed_audit: bool,
    /// Audit log level
    pub audit_log_level: AuditLogLevel,
    /// Enable audit compression
    pub enable_compression: bool,
    /// Audit file path
    pub audit_file_path: Option<String>,
}

impl Default for SecurityAuditConfig {
    fn default() -> Self {
        Self {
            enable_audit: true,
            max_audit_entries: 10000,
            retention_days: 30, // 30 days
            enable_detailed_audit: true,
            audit_log_level: AuditLogLevel::Info,
            enable_compression: true,
            audit_file_path: Some("logs/security_audit.log".to_string()),
        }
    }
}

/// Audit log level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum AuditLogLevel {
    #[default]
    Info,
    Debug,
    Warn,
    Error,
}

impl AuditLogLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuditLogLevel::Debug => "debug",
            AuditLogLevel::Info => "info",
            AuditLogLevel::Warn => "warn",
            AuditLogLevel::Error => "error",
        }
    }

    pub fn as_tracing_level(&self) -> tracing::Level {
        match self {
            AuditLogLevel::Debug => tracing::Level::DEBUG,
            AuditLogLevel::Info => tracing::Level::INFO,
            AuditLogLevel::Warn => tracing::Level::WARN,
            AuditLogLevel::Error => tracing::Level::ERROR,
        }
    }
}

/// Security operation type
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SecurityOperation {
    /// Cryptographic operations
    Encryption,
    Decryption,
    KeyGeneration,
    KeyDestruction,
    KeyRotation,
    Signature,
    Verification,

    /// Network operations
    ConnectionEstablished,
    ConnectionTerminated,
    MessageSent,
    MessageReceived,
    PeerDiscovered,
    PeerConnected,
    PeerDisconnected,

    /// Authentication operations
    AuthenticationAttempt,
    AuthenticationSuccess,
    AuthenticationFailure,
    AuthorizationCheck,

    /// System operations
    ConfigurationChange,
    SystemStartup,
    SystemShutdown,
    MaintenanceMode,

    /// Security events
    SecurityAlert,
    ThreatDetected,
    AnomalyDetected,
    PolicyViolation,

    /// Data operations
    DataAccess,
    DataModification,
    DataDeletion,
    DataBackup,
    DataRestore,
}

impl SecurityOperation {
    pub fn as_str(&self) -> &'static str {
        match self {
            SecurityOperation::Encryption => "encryption",
            SecurityOperation::Decryption => "decryption",
            SecurityOperation::KeyGeneration => "key_generation",
            SecurityOperation::KeyDestruction => "key_destruction",
            SecurityOperation::KeyRotation => "key_rotation",
            SecurityOperation::Signature => "signature",
            SecurityOperation::Verification => "verification",
            SecurityOperation::ConnectionEstablished => "connection_established",
            SecurityOperation::ConnectionTerminated => "connection_terminated",
            SecurityOperation::MessageSent => "message_sent",
            SecurityOperation::MessageReceived => "message_received",
            SecurityOperation::PeerDiscovered => "peer_discovered",
            SecurityOperation::PeerConnected => "peer_connected",
            SecurityOperation::PeerDisconnected => "peer_disconnected",
            SecurityOperation::AuthenticationAttempt => "authentication_attempt",
            SecurityOperation::AuthenticationSuccess => "authentication_success",
            SecurityOperation::AuthenticationFailure => "authentication_failure",
            SecurityOperation::AuthorizationCheck => "authorization_check",
            SecurityOperation::ConfigurationChange => "configuration_change",
            SecurityOperation::SystemStartup => "system_startup",
            SecurityOperation::SystemShutdown => "system_shutdown",
            SecurityOperation::MaintenanceMode => "maintenance_mode",
            SecurityOperation::SecurityAlert => "security_alert",
            SecurityOperation::ThreatDetected => "threat_detected",
            SecurityOperation::AnomalyDetected => "anomaly_detected",
            SecurityOperation::PolicyViolation => "policy_violation",
            SecurityOperation::DataAccess => "data_access",
            SecurityOperation::DataModification => "data_modification",
            SecurityOperation::DataDeletion => "data_deletion",
            SecurityOperation::DataBackup => "data_backup",
            SecurityOperation::DataRestore => "data_restore",
        }
    }

    pub fn category(&self) -> SecurityCategory {
        match self {
            SecurityOperation::Encryption
            | SecurityOperation::Decryption
            | SecurityOperation::KeyGeneration
            | SecurityOperation::KeyDestruction
            | SecurityOperation::KeyRotation
            | SecurityOperation::Signature
            | SecurityOperation::Verification => SecurityCategory::Cryptographic,

            SecurityOperation::ConnectionEstablished
            | SecurityOperation::ConnectionTerminated
            | SecurityOperation::MessageSent
            | SecurityOperation::MessageReceived
            | SecurityOperation::PeerDiscovered
            | SecurityOperation::PeerConnected
            | SecurityOperation::PeerDisconnected => SecurityCategory::Network,

            SecurityOperation::AuthenticationAttempt
            | SecurityOperation::AuthenticationSuccess
            | SecurityOperation::AuthenticationFailure
            | SecurityOperation::AuthorizationCheck => SecurityCategory::Authentication,

            SecurityOperation::ConfigurationChange
            | SecurityOperation::SystemStartup
            | SecurityOperation::SystemShutdown
            | SecurityOperation::MaintenanceMode => SecurityCategory::System,

            SecurityOperation::SecurityAlert
            | SecurityOperation::ThreatDetected
            | SecurityOperation::AnomalyDetected
            | SecurityOperation::PolicyViolation => SecurityCategory::Security,

            SecurityOperation::DataAccess
            | SecurityOperation::DataModification
            | SecurityOperation::DataDeletion
            | SecurityOperation::DataBackup
            | SecurityOperation::DataRestore => SecurityCategory::Data,
        }
    }
}

/// Security category
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityCategory {
    Cryptographic,
    Network,
    Authentication,
    System,
    Security,
    Data,
}

impl SecurityCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            SecurityCategory::Cryptographic => "cryptographic",
            SecurityCategory::Network => "network",
            SecurityCategory::Authentication => "authentication",
            SecurityCategory::System => "system",
            SecurityCategory::Security => "security",
            SecurityCategory::Data => "data",
        }
    }
}

/// Audit entry
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unique entry ID
    pub id: String,
    /// Timestamp of the operation
    pub timestamp: DateTime<Utc>,
    /// Security operation type
    pub operation: SecurityOperation,
    /// Operation result
    pub result: OperationResult,
    /// User or system that performed the operation
    pub actor: String,
    /// Target resource or object
    pub target: Option<String>,
    /// Operation description
    pub description: String,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
    /// Duration of the operation in milliseconds
    pub duration_ms: Option<u64>,
    /// IP address of the actor
    pub ip_address: Option<String>,
    /// User agent if applicable
    pub user_agent: Option<String>,
    /// Session ID if applicable
    pub session_id: Option<String>,
    /// Risk level of the operation
    pub risk_level: RiskLevel,
    /// Compliance tags
    pub compliance_tags: Vec<String>,
}

/// Operation result
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum OperationResult {
    #[default]
    Success,
    Failure,
    Partial,
    Timeout,
    Cancelled,
}

impl OperationResult {
    pub fn as_str(&self) -> &'static str {
        match self {
            OperationResult::Success => "success",
            OperationResult::Failure => "failure",
            OperationResult::Partial => "partial",
            OperationResult::Timeout => "timeout",
            OperationResult::Cancelled => "cancelled",
        }
    }

    pub fn is_successful(&self) -> bool {
        matches!(self, OperationResult::Success | OperationResult::Partial)
    }
}

/// Risk level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub enum RiskLevel {
    #[default]
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskLevel::None => "none",
            RiskLevel::Low => "low",
            RiskLevel::Medium => "medium",
            RiskLevel::High => "high",
            RiskLevel::Critical => "critical",
        }
    }

    pub fn numeric_value(&self) -> u8 {
        match self {
            RiskLevel::None => 0,
            RiskLevel::Low => 1,
            RiskLevel::Medium => 2,
            RiskLevel::High => 3,
            RiskLevel::Critical => 4,
        }
    }

    pub fn color_code(&self) -> &'static str {
        match self {
            RiskLevel::None => "#4CAF50",     // Green
            RiskLevel::Low => "#8BC34A",      // Light Green
            RiskLevel::Medium => "#FFC107",   // Yellow
            RiskLevel::High => "#FF9800",     // Orange
            RiskLevel::Critical => "#F44336", // Red
        }
    }
}

/// Audit summary
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct AuditSummary {
    pub total_entries: u64,
    pub successful_operations: u64,
    pub failed_operations: u64,
    pub operations_by_category: HashMap<String, u64>,
    pub operations_by_type: HashMap<String, u64>,
    pub operations_by_actor: HashMap<String, u64>,
    pub average_operation_duration_ms: f64,
    pub high_risk_operations: u64,
    pub critical_risk_operations: u64,
    pub compliance_summary: ComplianceSummary,
}

/// Compliance summary
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ComplianceSummary {
    pub total_compliant_operations: u64,
    pub total_non_compliant_operations: u64,
    pub compliance_rate: f64,
    pub compliance_by_standard: HashMap<String, ComplianceStatus>,
}

/// Compliance status
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ComplianceStatus {
    pub standard: String,
    pub compliant_operations: u64,
    pub non_compliant_operations: u64,
    pub compliance_rate: f64,
    pub last_assessment: DateTime<Utc>,
}

/// Security auditor
pub struct SecurityAuditor {
    config: SecurityAuditConfig,
    audit_entries: Arc<RwLock<Vec<AuditEntry>>>,
    is_auditing: Arc<RwLock<bool>>,
}

impl SecurityAuditor {
    /// Create a new security auditor
    pub async fn new(config: SecurityAuditConfig) -> Result<Self, Error> {
        info!("Initializing security auditor");

        let auditor = Self {
            config: config.clone(),
            audit_entries: Arc::new(RwLock::new(Vec::new())),
            is_auditing: Arc::new(RwLock::new(false)),
        };

        info!("Security auditor initialized successfully");
        Ok(auditor)
    }

    /// Record a security operation
    #[instrument(skip(self))]
    pub async fn record_operation(
        &self,
        operation: SecurityOperation,
        result: OperationResult,
        actor: String,
        description: String,
    ) -> Result<String, Error> {
        let entry_id = self.generate_entry_id();

        let entry = AuditEntry {
            id: entry_id.clone(),
            timestamp: Utc::now(),
            operation: operation.clone(),
            result,
            actor: actor.clone(),
            target: None,
            description,
            metadata: HashMap::new(),
            duration_ms: None,
            ip_address: None,
            user_agent: None,
            session_id: None,
            risk_level: self.calculate_risk_level(&operation, result),
            compliance_tags: self.get_compliance_tags(&operation),
        };

        // Add entry
        {
            let mut entries = self.audit_entries.write().await;
            entries.push(entry.clone());

            // Sort by timestamp (newest first)
            entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

            // Limit number of entries
            if entries.len() > self.config.max_audit_entries {
                entries.truncate(self.config.max_audit_entries);
            }
        }

        // Log the operation
        self.log_audit_entry(&entry).await?;

        debug!(
            "Audit entry recorded: {} - {}",
            entry_id,
            operation.as_str()
        );
        Ok(entry_id)
    }

    /// Record a detailed security operation
    #[instrument(skip(self))]
    pub async fn record_detailed_operation(
        &self,
        operation: SecurityOperation,
        result: OperationResult,
        actor: String,
        target: Option<String>,
        description: String,
        metadata: HashMap<String, String>,
        duration_ms: Option<u64>,
        ip_address: Option<String>,
        user_agent: Option<String>,
        session_id: Option<String>,
    ) -> Result<String, Error> {
        let entry_id = self.generate_entry_id();

        let entry = AuditEntry {
            id: entry_id.clone(),
            timestamp: Utc::now(),
            operation: operation.clone(),
            result,
            actor: actor.clone(),
            target,
            description,
            metadata,
            duration_ms,
            ip_address,
            user_agent,
            session_id,
            risk_level: self.calculate_risk_level(&operation, result),
            compliance_tags: self.get_compliance_tags(&operation),
        };

        // Add entry
        {
            let mut entries = self.audit_entries.write().await;
            entries.push(entry.clone());

            // Sort by timestamp (newest first)
            entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

            // Limit number of entries
            if entries.len() > self.config.max_audit_entries {
                entries.truncate(self.config.max_audit_entries);
            }
        }

        // Log the operation
        self.log_audit_entry(&entry).await?;

        debug!(
            "Detailed audit entry recorded: {} - {}",
            entry_id,
            operation.as_str()
        );
        Ok(entry_id)
    }

    /// Get audit entry by ID
    #[instrument(skip(self))]
    pub async fn get_audit_entry(&self, entry_id: &str) -> Option<AuditEntry> {
        let entries = self.audit_entries.read().await;
        entries.iter().find(|e| e.id == entry_id).cloned()
    }

    /// Get all audit entries
    #[instrument(skip(self))]
    pub async fn get_all_audit_entries(&self) -> Vec<AuditEntry> {
        self.audit_entries.read().await.clone()
    }

    /// Get audit entries by operation type
    #[instrument(skip(self))]
    pub async fn get_entries_by_operation(&self, operation: SecurityOperation) -> Vec<AuditEntry> {
        let entries = self.audit_entries.read().await;
        entries
            .iter()
            .filter(|e| e.operation == operation)
            .cloned()
            .collect()
    }

    /// Get audit entries by category
    #[instrument(skip(self))]
    pub async fn get_entries_by_category(&self, category: SecurityCategory) -> Vec<AuditEntry> {
        let entries = self.audit_entries.read().await;
        entries
            .iter()
            .filter(|e| e.operation.category() == category)
            .cloned()
            .collect()
    }

    /// Get audit entries by actor
    #[instrument(skip(self))]
    pub async fn get_entries_by_actor(&self, actor: &str) -> Vec<AuditEntry> {
        let entries = self.audit_entries.read().await;
        entries
            .iter()
            .filter(|e| e.actor == actor)
            .cloned()
            .collect()
    }

    /// Get audit entries in time range
    #[instrument(skip(self))]
    pub async fn get_entries_in_time_range(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Vec<AuditEntry> {
        let entries = self.audit_entries.read().await;
        entries
            .iter()
            .filter(|e| e.timestamp >= start && e.timestamp <= end)
            .cloned()
            .collect()
    }

    /// Get audit entries by risk level
    #[instrument(skip(self))]
    pub async fn get_entries_by_risk_level(&self, risk_level: RiskLevel) -> Vec<AuditEntry> {
        let entries = self.audit_entries.read().await;
        entries
            .iter()
            .filter(|e| e.risk_level == risk_level)
            .cloned()
            .collect()
    }

    /// Get recent audit entries
    #[instrument(skip(self))]
    pub async fn get_recent_entries(&self, limit: usize) -> Vec<AuditEntry> {
        let entries = self.audit_entries.read().await;
        entries.iter().take(limit).cloned().collect()
    }

    /// Get audit summary
    #[instrument(skip(self))]
    pub async fn get_audit_summary(&self) -> AuditSummary {
        let entries = self.audit_entries.read().await;

        let total_entries = entries.len() as u64;
        let successful_operations =
            entries.iter().filter(|e| e.result.is_successful()).count() as u64;
        let failed_operations = entries.iter().filter(|e| !e.result.is_successful()).count() as u64;

        let mut operations_by_category = HashMap::new();
        let mut operations_by_type = HashMap::new();
        let mut operations_by_actor = HashMap::new();
        let mut total_duration = 0.0;
        let mut duration_count = 0;

        for entry in entries.iter() {
            // Count by category
            let category = entry.operation.category().as_str().to_string();
            *operations_by_category.entry(category).or_insert(0) += 1;

            // Count by type
            let op_type = entry.operation.as_str().to_string();
            *operations_by_type.entry(op_type).or_insert(0) += 1;

            // Count by actor
            *operations_by_actor.entry(entry.actor.clone()).or_insert(0) += 1;

            // Calculate average duration
            if let Some(duration) = entry.duration_ms {
                total_duration += duration as f64;
                duration_count += 1;
            }
        }

        let average_operation_duration_ms = if duration_count > 0 {
            total_duration / duration_count as f64
        } else {
            0.0
        };

        let high_risk_operations = entries
            .iter()
            .filter(|e| e.risk_level == RiskLevel::High)
            .count() as u64;
        let critical_risk_operations = entries
            .iter()
            .filter(|e| e.risk_level == RiskLevel::Critical)
            .count() as u64;

        let compliance_summary = self.calculate_compliance_summary(&entries);

        AuditSummary {
            total_entries,
            successful_operations,
            failed_operations,
            operations_by_category,
            operations_by_type,
            operations_by_actor,
            average_operation_duration_ms,
            high_risk_operations,
            critical_risk_operations,
            compliance_summary,
        }
    }

    /// Clean up old audit entries
    #[instrument(skip(self))]
    pub async fn cleanup_old_entries(&self) -> Result<usize, Error> {
        let cutoff_time = Utc::now() - chrono::Duration::days(self.config.retention_days as i64);

        let mut entries = self.audit_entries.write().await;
        let initial_count = entries.len();

        entries.retain(|entry| entry.timestamp > cutoff_time);

        let removed_count = initial_count - entries.len();

        if removed_count > 0 {
            info!("Cleaned up {} old audit entries", removed_count);
        }

        Ok(removed_count)
    }

    /// Start audit monitoring
    #[instrument(skip(self))]
    pub async fn start_auditing(&self) -> Result<(), Error> {
        let mut is_auditing = self.is_auditing.write().await;

        if *is_auditing {
            warn!("Audit monitoring is already running");
            return Ok(());
        }

        *is_auditing = true;
        info!("Starting audit monitoring");

        let config = self.config.clone();
        let audit_entries = Arc::clone(&self.audit_entries);
        let is_auditing = Arc::clone(&self.is_auditing);

        tokio::spawn(async move {
            while *is_auditing.read().await {
                // Clean up old entries
                if let Err(e) = Self::perform_cleanup(&audit_entries, &config).await {
                    error!("Failed to cleanup old audit entries: {}", e);
                }

                // Wait for next cleanup
                tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;
                // Check every hour
            }
        });

        Ok(())
    }

    /// Stop audit monitoring
    #[instrument(skip(self))]
    pub async fn stop_auditing(&self) -> Result<(), Error> {
        let mut is_auditing = self.is_auditing.write().await;

        if !*is_auditing {
            warn!("Audit monitoring is not running");
            return Ok(());
        }

        *is_auditing = false;
        info!("Stopping audit monitoring");
        Ok(())
    }

    /// Generate unique entry ID
    fn generate_entry_id(&self) -> String {
        use uuid::Uuid;
        format!("audit-{}", Uuid::new_v4())
    }

    /// Calculate risk level for operation
    fn calculate_risk_level(
        &self,
        operation: &SecurityOperation,
        result: OperationResult,
    ) -> RiskLevel {
        let base_risk = match operation {
            SecurityOperation::KeyDestruction => RiskLevel::Critical,
            SecurityOperation::KeyGeneration => RiskLevel::High,
            SecurityOperation::KeyRotation => RiskLevel::Medium,
            SecurityOperation::AuthenticationFailure => RiskLevel::High,
            SecurityOperation::SecurityAlert => RiskLevel::High,
            SecurityOperation::ThreatDetected => RiskLevel::Critical,
            SecurityOperation::AnomalyDetected => RiskLevel::Medium,
            SecurityOperation::PolicyViolation => RiskLevel::High,
            SecurityOperation::DataDeletion => RiskLevel::High,
            SecurityOperation::ConfigurationChange => RiskLevel::Medium,
            SecurityOperation::SystemShutdown => RiskLevel::Medium,
            _ => RiskLevel::Low,
        };

        // Adjust based on result
        if !result.is_successful() {
            match base_risk {
                RiskLevel::None => RiskLevel::Low,
                RiskLevel::Low => RiskLevel::Medium,
                RiskLevel::Medium => RiskLevel::High,
                RiskLevel::High => RiskLevel::Critical,
                RiskLevel::Critical => RiskLevel::Critical,
            }
        } else {
            base_risk
        }
    }

    /// Get compliance tags for operation
    fn get_compliance_tags(&self, operation: &SecurityOperation) -> Vec<String> {
        let mut tags = Vec::new();

        match operation {
            SecurityOperation::Encryption | SecurityOperation::Decryption => {
                tags.push("data-protection".to_string());
                tags.push("encryption".to_string());
            }
            SecurityOperation::KeyGeneration
            | SecurityOperation::KeyRotation
            | SecurityOperation::KeyDestruction => {
                tags.push("key-management".to_string());
                tags.push("cryptographic-controls".to_string());
            }
            SecurityOperation::AuthenticationAttempt
            | SecurityOperation::AuthenticationSuccess
            | SecurityOperation::AuthenticationFailure => {
                tags.push("access-control".to_string());
                tags.push("authentication".to_string());
            }
            SecurityOperation::DataAccess
            | SecurityOperation::DataModification
            | SecurityOperation::DataDeletion => {
                tags.push("data-access".to_string());
                tags.push("privacy".to_string());
            }
            SecurityOperation::SecurityAlert
            | SecurityOperation::ThreatDetected
            | SecurityOperation::AnomalyDetected => {
                tags.push("security-monitoring".to_string());
                tags.push("incident-response".to_string());
            }
            _ => {}
        }

        tags
    }

    /// Log audit entry
    async fn log_audit_entry(&self, entry: &AuditEntry) -> Result<(), Error> {
        let level = match (self.config.audit_log_level, entry.risk_level) {
            (AuditLogLevel::Error, _) => tracing::Level::ERROR,
            (AuditLogLevel::Warn, RiskLevel::Critical | RiskLevel::High) => tracing::Level::ERROR,
            (AuditLogLevel::Warn, RiskLevel::Medium) => tracing::Level::WARN,
            (AuditLogLevel::Warn, _) => tracing::Level::INFO,
            (AuditLogLevel::Info, RiskLevel::Critical) => tracing::Level::ERROR,
            (AuditLogLevel::Info, RiskLevel::High) => tracing::Level::WARN,
            (AuditLogLevel::Info, _) => tracing::Level::INFO,
            (AuditLogLevel::Debug, _) => tracing::Level::DEBUG,
        };

        // Use match to call appropriate tracing macro with constant level
        match level {
            tracing::Level::ERROR => tracing::error!(
                target: "security_audit",
                audit_id = %entry.id,
                operation = %entry.operation.as_str(),
                result = %entry.result.as_str(),
                actor = %entry.actor,
                risk_level = %entry.risk_level.as_str(),
                description = %entry.description,
                timestamp = %entry.timestamp,
                "Security audit event"
            ),
            tracing::Level::WARN => tracing::warn!(
                target: "security_audit",
                audit_id = %entry.id,
                operation = %entry.operation.as_str(),
                result = %entry.result.as_str(),
                actor = %entry.actor,
                risk_level = %entry.risk_level.as_str(),
                description = %entry.description,
                timestamp = %entry.timestamp,
                "Security audit event"
            ),
            tracing::Level::INFO => tracing::info!(
                target: "security_audit",
                audit_id = %entry.id,
                operation = %entry.operation.as_str(),
                result = %entry.result.as_str(),
                actor = %entry.actor,
                risk_level = %entry.risk_level.as_str(),
                description = %entry.description,
                timestamp = %entry.timestamp,
                "Security audit event"
            ),
            tracing::Level::DEBUG => tracing::debug!(
                target: "security_audit",
                audit_id = %entry.id,
                operation = %entry.operation.as_str(),
                result = %entry.result.as_str(),
                actor = %entry.actor,
                risk_level = %entry.risk_level.as_str(),
                description = %entry.description,
                timestamp = %entry.timestamp,
                "Security audit event"
            ),
            _ => tracing::trace!(
                target: "security_audit",
                audit_id = %entry.id,
                operation = %entry.operation.as_str(),
                result = %entry.result.as_str(),
                actor = %entry.actor,
                risk_level = %entry.risk_level.as_str(),
                description = %entry.description,
                timestamp = %entry.timestamp,
                "Security audit event"
            ),
        }

        Ok(())
    }

    /// Calculate compliance summary
    fn calculate_compliance_summary(&self, entries: &[AuditEntry]) -> ComplianceSummary {
        let mut compliant_operations = 0;
        let mut non_compliant_operations = 0;
        let mut compliance_by_standard = HashMap::new();

        for entry in entries {
            // Simplified compliance check - in reality this would be more complex
            let is_compliant = entry.result.is_successful()
                && entry.risk_level != RiskLevel::Critical
                && !entry.compliance_tags.is_empty();

            if is_compliant {
                compliant_operations += 1;
            } else {
                non_compliant_operations += 1;
            }

            // Check compliance by standard (simplified)
            for tag in &entry.compliance_tags {
                let status =
                    compliance_by_standard
                        .entry(tag.clone())
                        .or_insert(ComplianceStatus {
                            standard: tag.clone(),
                            compliant_operations: 0,
                            non_compliant_operations: 0,
                            compliance_rate: 0.0,
                            last_assessment: Utc::now(),
                        });

                if is_compliant {
                    status.compliant_operations += 1;
                } else {
                    status.non_compliant_operations += 1;
                }

                let total = status.compliant_operations + status.non_compliant_operations;
                status.compliance_rate = if total > 0 {
                    status.compliant_operations as f64 / total as f64 * 100.0
                } else {
                    100.0
                };
            }
        }

        let total_operations = compliant_operations + non_compliant_operations;
        let compliance_rate = if total_operations > 0 {
            compliant_operations as f64 / total_operations as f64 * 100.0
        } else {
            100.0
        };

        ComplianceSummary {
            total_compliant_operations: compliant_operations,
            total_non_compliant_operations: non_compliant_operations,
            compliance_rate,
            compliance_by_standard,
        }
    }

    /// Perform cleanup
    async fn perform_cleanup(
        audit_entries: &Arc<RwLock<Vec<AuditEntry>>>,
        config: &SecurityAuditConfig,
    ) -> Result<(), Error> {
        let cutoff_time = Utc::now() - chrono::Duration::days(config.retention_days as i64);

        let mut entries = audit_entries.write().await;
        let initial_count = entries.len();

        entries.retain(|entry| entry.timestamp > cutoff_time);

        let removed_count = initial_count - entries.len();

        if removed_count > 0 {
            debug!("Cleaned up {} old audit entries", removed_count);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_config_default() {
        let config = SecurityAuditConfig::default();
        assert!(config.enable_audit);
        assert_eq!(config.max_audit_entries, 10000);
        assert_eq!(config.retention_days, 30);
    }

    #[test]
    fn test_security_operation() {
        let op = SecurityOperation::Encryption;
        assert_eq!(op.as_str(), "encryption");
        assert_eq!(op.category(), SecurityCategory::Cryptographic);
    }

    #[test]
    fn test_risk_level() {
        assert_eq!(RiskLevel::Low.as_str(), "low");
        assert_eq!(RiskLevel::Critical.numeric_value(), 4);
        assert_eq!(RiskLevel::High.color_code(), "#FF9800");
        assert!(RiskLevel::Critical > RiskLevel::High);
    }

    #[tokio::test]
    async fn test_security_auditor_creation() {
        let config = SecurityAuditConfig::default();
        let auditor = SecurityAuditor::new(config).await;
        assert!(auditor.is_ok());
    }

    #[tokio::test]
    async fn test_operation_recording() {
        let auditor = SecurityAuditor::new(SecurityAuditConfig::default())
            .await
            .unwrap();

        let entry_id = auditor
            .record_operation(
                SecurityOperation::Encryption,
                OperationResult::Success,
                "test_user".to_string(),
                "Test encryption operation".to_string(),
            )
            .await
            .unwrap();

        assert!(!entry_id.is_empty());

        let entry = auditor.get_audit_entry(&entry_id).await;
        assert!(entry.is_some());

        let entry = entry.unwrap();
        assert_eq!(entry.operation, SecurityOperation::Encryption);
        assert_eq!(entry.result, OperationResult::Success);
        assert_eq!(entry.actor, "test_user");
    }

    #[tokio::test]
    async fn test_detailed_operation_recording() {
        let auditor = SecurityAuditor::new(SecurityAuditConfig::default())
            .await
            .unwrap();

        let mut metadata = HashMap::new();
        metadata.insert("key_size".to_string(), "256".to_string());

        let entry_id = auditor
            .record_detailed_operation(
                SecurityOperation::KeyGeneration,
                OperationResult::Success,
                "system".to_string(),
                Some("encryption_key".to_string()),
                "Generated new encryption key".to_string(),
                metadata,
                Some(100),
                Some("127.0.0.1".to_string()),
                Some("WolfProwler/1.0".to_string()),
                Some("session_123".to_string()),
            )
            .await
            .unwrap();

        let entry = auditor.get_audit_entry(&entry_id).await.unwrap();
        assert_eq!(entry.operation, SecurityOperation::KeyGeneration);
        assert_eq!(entry.target.as_ref().unwrap(), "encryption_key");
        assert_eq!(entry.duration_ms.unwrap(), 100);
        assert_eq!(entry.ip_address.as_ref().unwrap(), "127.0.0.1");
    }

    #[tokio::test]
    async fn test_audit_summary() {
        let auditor = SecurityAuditor::new(SecurityAuditConfig::default())
            .await
            .unwrap();

        // Record some operations
        for i in 0..5 {
            auditor
                .record_operation(
                    if i < 2 {
                        SecurityOperation::Encryption
                    } else {
                        SecurityOperation::Decryption
                    },
                    OperationResult::Success,
                    "test_user".to_string(),
                    format!("Operation {}", i),
                )
                .await
                .unwrap();
        }

        let summary = auditor.get_audit_summary().await;
        assert_eq!(summary.total_entries, 5);
        assert_eq!(summary.successful_operations, 5);
        assert_eq!(summary.failed_operations, 0);
    }

    #[tokio::test]
    async fn test_audit_filtering() {
        let auditor = SecurityAuditor::new(SecurityAuditConfig::default())
            .await
            .unwrap();

        // Record operations of different types
        auditor
            .record_operation(
                SecurityOperation::Encryption,
                OperationResult::Success,
                "user1".to_string(),
                "Encryption".to_string(),
            )
            .await
            .unwrap();

        auditor
            .record_operation(
                SecurityOperation::AuthenticationSuccess,
                OperationResult::Success,
                "user2".to_string(),
                "Authentication".to_string(),
            )
            .await
            .unwrap();

        // Filter by operation type
        let encryption_entries = auditor
            .get_entries_by_operation(SecurityOperation::Encryption)
            .await;
        assert_eq!(encryption_entries.len(), 1);

        // Filter by category
        let crypto_entries = auditor
            .get_entries_by_category(SecurityCategory::Cryptographic)
            .await;
        assert_eq!(crypto_entries.len(), 1);

        // Filter by actor
        let user1_entries = auditor.get_entries_by_actor("user1").await;
        assert_eq!(user1_entries.len(), 1);
    }

    #[tokio::test]
    async fn test_audit_monitoring_lifecycle() {
        let auditor = SecurityAuditor::new(SecurityAuditConfig::default())
            .await
            .unwrap();

        // Start auditing
        let start_result = auditor.start_auditing().await;
        assert!(start_result.is_ok());

        // Give it a moment to start
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Stop auditing
        let stop_result = auditor.stop_auditing().await;
        assert!(stop_result.is_ok());
    }

    #[tokio::test]
    async fn test_audit_cleanup() {
        let mut config = SecurityAuditConfig::default();
        config.retention_days = 0; // Immediate cleanup

        let auditor = SecurityAuditor::new(config).await.unwrap();

        // Record an entry
        auditor
            .record_operation(
                SecurityOperation::Encryption,
                OperationResult::Success,
                "test_user".to_string(),
                "Test operation".to_string(),
            )
            .await
            .unwrap();

        // Wait a moment and cleanup
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        let removed_count = auditor.cleanup_old_entries().await.unwrap();

        assert!(removed_count > 0);
    }
}
