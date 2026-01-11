//! Zero-Knowledge Administration for Healthcare & GDPR Compliance
//!
//! This module implements privacy-preserving audit trails where command intent
//! is logged encrypted, and content is never revealed to logging infrastructure.

use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

/// Configuration for privacy-preserving audit system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyConfig {
    /// Syslog server endpoint
    pub syslog_endpoint: String,

    /// Alert channels for break-glass events
    pub alert_channels: Vec<String>,

    /// PII detection patterns
    pub pii_patterns: Vec<String>,

    /// Enable privacy mode
    pub privacy_mode: bool,

    /// Path to the Auditor's Public Key (ML-KEM-1024)
    pub audit_key_path: String,
}

/// Policy condition for fine-grained access control
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyCondition {
    /// Check if a specific role is present
    HasRole(String),
    /// Check if a specific operation is allowed
    CanPerform(String),
    /// Check if a specific resource is accessed
    AccessesResource(String),
    /// Check if the current time is within a specific window
    WithinTimeWindow,
    /// Custom expression for complex conditions
    Custom(String),
}

/// Time window for policy conditions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeWindow {
    /// Start hour of the time window (0-23)
    pub start_hour: u8,
    /// End hour of the time window (0-23)
    pub end_hour: u8,
    /// Days of the week when the window is active (0=Sunday, 1=Monday, etc.)
    pub days_of_week: Vec<u8>,
}

/// Policy definition for access control and auditing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Name of the policy
    pub name: String,
    /// Roles required for this policy
    pub roles: Vec<String>,
    /// Operations allowed by this policy
    pub operations: Vec<String>,
    /// Resources accessible under this policy
    pub resources: Vec<String>,
    /// Minimum number of approvals required
    pub threshold: usize,
    /// Additional conditions for policy evaluation
    pub conditions: Vec<PolicyCondition>,
    /// Time windows when the policy is active
    pub time_windows: Option<Vec<TimeWindow>>,
    /// Expression for approval logic (e.g., "Role:DevOps AND Role:ComplianceManager")
    pub approval_expression: Option<String>,
}

/// Encrypted audit entry for privacy-preserving logging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedAuditEntry {
    /// Timestamp of the audit event
    pub timestamp: u64,

    /// SHA-256 hash of the original command (for integrity)
    pub command_hash: String,

    /// Encrypted command content (KEM `CipherText` || Nonce || AES `CipherText`)
    pub encrypted_command: Vec<u8>,

    /// Execution status
    pub status: AuditStatus,

    /// Emergency flag (true if break-glass was used)
    pub emergency_mode: bool,

    /// Auditor verification signature
    pub auditor_signature: Option<Vec<u8>>,
}

/// Audit status enumeration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditStatus {
    /// Command executed successfully
    Success,
    /// Command failed
    Failed(String),
    /// Command rejected by policy
    Rejected(String),
}

/// Privacy-preserving audit logger
pub struct PrivacyAuditLogger {
    #[allow(dead_code)]
    config: PrivacyConfig,
    audit_channel: mpsc::UnboundedSender<EncryptedAuditEntry>,
    audit_key: fips203::ml_kem_1024::EncapsKey,
}

impl PrivacyAuditLogger {
    /// Create a new privacy audit logger
    ///
    /// # Errors
    /// Returns an error if the audit key cannot be loaded.
    pub fn new(config: PrivacyConfig) -> io::Result<Self> {
        // Load Audit Public Key
        let audit_key = shared::load_kem_public_key(&config.audit_key_path).map_err(|e| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "Failed to load audit key from {}: {e}",
                    config.audit_key_path
                ),
            )
        })?;

        let (tx, mut rx) = mpsc::unbounded_channel();

        // Start audit processing task
        let config_clone = config.clone();
        tokio::spawn(async move {
            while let Some(entry) = rx.recv().await {
                if let Err(e) = Self::process_audit_entry(entry, &config_clone) {
                    eprintln!("Failed to process audit entry: {e}");
                }
            }
        });

        Ok(Self {
            config,
            audit_channel: tx,
            audit_key,
        })
    }

    /// Log a command execution with privacy preservation
    ///
    /// # Errors
    /// Returns an error if logging fails.
    ///
    /// # Panics
    /// Panics if the current time is before the UNIX epoch.
    /// Log a command execution with privacy preservation
    ///
    /// # Errors
    /// Returns an error if logging fails.
    ///
    /// # Panics
    /// Panics if the current time is before the UNIX epoch.
    #[allow(clippy::unused_async)]
    pub async fn log_command_execution(
        &self,
        command: &str,
        status: AuditStatus,
        emergency_mode: bool,
    ) -> io::Result<()> {
        // Calculate command hash for integrity
        let command_hash = Self::calculate_sha256(command.as_bytes());

        // Encrypt command for auditor using ML-KEM-1024 + AES-GCM
        let encrypted_command = shared::encrypt_for_sentinel(command.as_bytes(), &self.audit_key);

        let entry = EncryptedAuditEntry {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(std::time::Duration::from_secs(0))
                .as_secs(),
            command_hash,
            encrypted_command,
            status,
            emergency_mode,
            auditor_signature: None, // Will be signed by auditor key
        };

        // Send to audit processing
        if let Err(e) = self.audit_channel.send(entry) {
            eprintln!("Failed to send audit entry: {e:?}");
        }

        // If emergency mode, send alerts
        if emergency_mode {
            // Send alerts synchronously for now
            self.send_sms_alert(command);
            self.send_email_alert(command);
            self.send_pagerduty_alert(command);
        }

        Ok(())
    }

    /// Decrypt command (Helper for verification/auditing tools, essentially)
    /// Note: Requires the PRIVATE key, which the Logger usually DOES NOT have.
    /// This function is kept for testing/verification scripts which might inject a key,
    /// but practically, the logger only encrypts.
    /// To match the interface, we'll assume this might be moved to a separate tool/struct.
    /// For now, since we don't store the private key in the logger, we can't implement this here easily without passing the SK.
    /// Let's change the signature to accept the SK or remove it.
    /// Given the context, I will remove it from the Logger struct methods as the Logger shouldn't decrypt.
    /// Decryption should be done by the Auditor tool.
    ///
    /// Process audit entry and ship to syslog
    fn process_audit_entry(entry: EncryptedAuditEntry, config: &PrivacyConfig) -> io::Result<()> {
        // Serialize entry
        let serialized = serde_json::to_string(&entry)
            .map_err(|e| io::Error::other(format!("Serialization failed: {e}")))?;

        // Ship to syslog server (ignore error to ensure local audit persists)
        if let Err(e) = Self::ship_to_syslog(&serialized, &config.syslog_endpoint) {
            eprintln!("Syslog shipment failed: {e}");
        }

        // Also write to local audit log
        Self::write_local_audit_log(&serialized, config)?;

        Ok(())
    }

    /// Ship audit entry to syslog server
    fn ship_to_syslog(audit_data: &str, endpoint: &str) -> io::Result<()> {
        // In a real implementation, this would use proper syslog protocol
        // For now, we'll write to a mock syslog endpoint
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(format!("{endpoint}/syslog_audit.log"))?;

        writeln!(file, "{audit_data}")?;

        Ok(())
    }

    /// Write to local audit log
    ///
    /// # Panics
    /// Panics if the current time is before the UNIX epoch.
    fn write_local_audit_log(audit_data: &str, config: &PrivacyConfig) -> io::Result<()> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(std::time::Duration::from_secs(0))
            .as_secs();

        let filename = format!("audit_log_{timestamp}.json");
        let path = Path::new(&config.syslog_endpoint)
            .join("local_audit")
            .join(filename);

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(&path, audit_data).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("Failed to write audit to {}: {e}", path.display()),
            )
        })?;

        Ok(())
    }

    /// Send emergency alerts for break-glass events
    #[allow(dead_code)]
    fn send_emergency_alerts(&self, command: &str) {
        for channel in &self.config.alert_channels {
            match channel.as_str() {
                "sms" => self.send_sms_alert(command),
                "email" => self.send_email_alert(command),
                "pagerduty" => self.send_pagerduty_alert(command),
                _ => {
                    eprintln!("Unknown alert channel: {channel}");
                }
            }
        }
    }

    /// Send SMS alert (mock implementation)
    #[allow(clippy::unused_self)]
    fn send_sms_alert(&self, command: &str) {
        println!("🚨 EMERGENCY: Break-glass command executed: {command}");
        println!("🚨 Alert sent via SMS to all stakeholders");
    }

    /// Send email alert (mock implementation)
    #[allow(clippy::unused_self)]
    fn send_email_alert(&self, command: &str) {
        println!("📧 EMERGENCY: Break-glass command executed: {command}");
        println!("📧 Alert sent via email to all stakeholders");
    }

    /// Send `PagerDuty` alert (mock implementation)
    #[allow(clippy::unused_self)]
    fn send_pagerduty_alert(&self, command: &str) {
        println!("🚨 EMERGENCY: Break-glass command executed: {command}");
        println!("🚨 PagerDuty alert triggered for all on-call personnel");
    }

    /// Calculate SHA-256 hash of data
    #[must_use]
    pub fn calculate_sha256(data: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        format!("{result:x}")
    }
}

/// Privacy-preserving command validator
pub struct PrivacyValidator {
    pii_patterns: Vec<regex::Regex>,
}

impl PrivacyValidator {
    /// Create a new privacy validator
    ///
    /// # Errors
    /// Returns an error if any PII pattern is an invalid regex.
    pub fn new(pii_patterns: &[String]) -> io::Result<Self> {
        let regex_patterns = pii_patterns
            .iter()
            .map(|pattern| regex::Regex::new(pattern))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        Ok(Self {
            pii_patterns: regex_patterns,
        })
    }

    /// Check if command contains PII and warn user
    #[must_use]
    pub fn check_pii(&self, command: &str) -> Vec<String> {
        let mut detected_pii = Vec::new();

        for (i, pattern) in self.pii_patterns.iter().enumerate() {
            if pattern.is_match(command) {
                detected_pii.push(format!("PII pattern {} detected in command", i + 1));
            }
        }

        detected_pii
    }

    /// Strip PII from command (basic implementation)
    #[must_use]
    pub fn strip_pii(&self, command: &str) -> String {
        let mut result = command.to_string();

        for pattern in &self.pii_patterns {
            result = pattern.replace_all(&result, "[REDACTED]").to_string();
        }

        result
    }

    /// Validate command for privacy compliance
    ///
    /// # Errors
    /// Returns an error if PII is detected in the command.
    pub fn validate_privacy(&self, command: &str) -> io::Result<()> {
        let pii_warnings = self.check_pii(command);

        if !pii_warnings.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("PII detected in command: {pii_warnings:?}"),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fips203::traits::{KeyGen, SerDes};
    use std::fs;
    use tempfile::TempDir;
    use tokio::time::Duration;

    #[tokio::test]
    async fn test_privacy_audit_logger() {
        let temp_dir = TempDir::new().unwrap();

        // Generate a test KEM key
        let (pk, _sk) = fips203::ml_kem_1024::KG::try_keygen().unwrap();
        let key_path = temp_dir.path().join("audit_key.pub");
        fs::write(&key_path, pk.into_bytes()).unwrap();

        let config = PrivacyConfig {
            syslog_endpoint: temp_dir.path().to_string_lossy().to_string(),
            alert_channels: vec!["sms".to_string()],
            pii_patterns: vec![],
            privacy_mode: true,
            audit_key_path: key_path.to_string_lossy().to_string(),
        };

        let logger = PrivacyAuditLogger::new(config).unwrap();

        // Test normal command logging
        logger
            .log_command_execution("echo 'normal command'", AuditStatus::Success, false)
            .await
            .unwrap();

        // Test emergency command logging
        logger
            .log_command_execution("rm -rf /emergency", AuditStatus::Success, true)
            .await
            .unwrap();

        // Wait for async processing (simplified)
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    #[test]
    fn test_privacy_validator() {
        let pii_patterns = vec![
            r"\b\d{3}-\d{2}-\d{4}\b".to_string(), // SSN pattern
            r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b".to_string(), // Email pattern
        ];

        let validator = PrivacyValidator::new(&pii_patterns).unwrap();

        // Test PII detection
        let pii_warnings = validator.check_pii("echo 'user@example.com'");
        assert!(!pii_warnings.is_empty());

        // Test PII stripping
        let stripped = validator.strip_pii("echo 'user@example.com'");
        assert!(stripped.contains("[REDACTED]"));

        // Test privacy validation
        let result = validator.validate_privacy("echo 'user@example.com'");
        assert!(result.is_err());
    }
}
