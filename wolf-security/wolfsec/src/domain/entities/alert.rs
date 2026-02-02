// /home/t4riq/Desktop/Rust/wolf_prowler/wolfsec/src/domain/entities/alert.rs
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Categorization of security event urgency.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AlertSeverity {
    /// Informational message, no immediate action required.
    Info,
    /// Minor issue, should be monitored.
    Low,
    /// Significant event, requires investigation.
    Medium,
    /// Critical issue, requires prompt response.
    High,
    /// Severe security breach or system failure, requires immediate intervention.
    Critical,
}

/// Life cycle state of a security alert.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AlertStatus {
    /// Newly created alert, not yet reviewed.
    New,
    /// Alert has been acknowledged by a security operator.
    Acknowledged,
    /// Active investigation or remediation is underway.
    InProgress,
    /// The issue has been addressed and the alert is closed.
    Resolved,
    /// The alert has been silenced or deemed a false positive.
    Suppressed,
}

/// The logical area or system that triggered the alert.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AlertCategory {
    /// Issues related to network traffic or connectivity.
    Network,
    /// Authentication failures or credential abuse.
    Authentication,
    /// Deviations from established behavioral baselines.
    Behavioral,
    /// General host or application system issues.
    System,
    /// Unauthorized data access or exfiltration attempts.
    Data,
    /// Violations of regulatory or organizational policies.
    Compliance,
    /// Matches against known threat signatures or indicators.
    ThreatIntelligence,
    /// User-defined custom category.
    Custom(String),
}

/// A discrete security notification representing an event of interest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    /// Unique identifier for the alert instance.
    pub id: Uuid,
    /// Precise point in time when the alert was generated.
    pub timestamp: DateTime<Utc>,
    /// How urgent or dangerous the event is.
    pub severity: AlertSeverity,
    /// The functional domain of the alert.
    pub category: AlertCategory,
    /// Short, human-readable summary of the event.
    pub title: String,
    /// Exhaustive technical explanation of the security event.
    pub description: String,
    /// The specific system, node, or module that emitted the alert.
    pub source: String,
    /// Current management state of the alert.
    pub status: AlertStatus,
    /// Arbitrary key-value pairs providing additional context.
    pub details: HashMap<String, String>,
    /// Identity of the operator who acknowledged the alert.
    pub acknowledged_by: Option<String>,
    /// Identity of the operator who marked the alert as resolved.
    pub resolved_by: Option<String>,
}

impl Alert {
    /// A constructor for a new alert. It is the responsibility of the application layer
    /// to create and save this domain entity.
    #[must_use]
    pub fn new(
        severity: AlertSeverity,
        category: AlertCategory,
        title: String,
        description: String,
        source: String,
        details: HashMap<String, String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            severity,
            category,
            title,
            description,
            source,
            status: AlertStatus::New,
            details,
            acknowledged_by: None,
            resolved_by: None,
        }
    }
}
