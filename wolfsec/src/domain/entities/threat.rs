use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Specific nature of a detected security threat.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ThreatType {
    /// A peer identity exhibiting proven harmful behavior.
    MaliciousPeer,
    /// Systematic probing or enumeration of network resources.
    NetworkScan,
    /// Evidence of unauthorized data moving outside the system.
    DataExfiltration,
    /// Early stage information gathering by an adversary.
    Reconnaissance,
    /// Presence of unauthorized, harmful software execution.
    Malware,
    /// Deceptive attempts to acquire sensitive credentials.
    Phishing,
    /// Abuse of legitimate credentials by an internal actor.
    InsiderThreat,
    /// Threat pattern that could not be categorically identified.
    Unknown,
}

/// Relative danger and priority associated with a security threat.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ThreatSeverity {
    /// Minor annoyance or low-impact deviation.
    Low,
    /// Potential risk that warrants attention.
    Medium,
    /// Significant threat that could result in partial compromise.
    High,
    /// Immediate, severe threat threatening core system integrity.
    Critical,
}

/// Formalized representation of a detected adversarial pattern or risk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Threat {
    /// Unique identifier for the threat instance.
    pub id: Uuid,
    /// Categorization of the threat behavior.
    pub threat_type: ThreatType,
    /// Danger level assigned to the threat.
    pub severity: ThreatSeverity,
    /// Human-readable explanation of why this was flagged.
    pub description: String,
    /// Unique identity of the peer responsible for the threat activity.
    pub source_peer: Option<String>,
    /// The specific system resource or asset being targeted.
    pub target_asset: Option<String>,
    /// Point in time when the threat was first identified.
    pub detected_at: DateTime<Utc>,
    /// Statistical score (0.0 - 1.0) indicating detection certainty.
    pub confidence: f64,
    /// Recommended or automated actions taken to neutralize the risk.
    pub mitigation_steps: Vec<String>,
    /// References to specific security events that informed this detection.
    pub related_events: Vec<Uuid>,
    /// Supplementary context for advanced forensics.
    pub metadata: HashMap<String, String>,
}

impl Threat {
    #[must_use]
    pub fn new(
        threat_type: ThreatType,
        severity: ThreatSeverity,
        description: String,
        confidence: f64,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            threat_type,
            severity,
            description,
            source_peer: None,
            target_asset: None,
            detected_at: Utc::now(),
            confidence,
            mitigation_steps: Vec::new(),
            related_events: Vec::new(),
            metadata: HashMap::new(),
        }
    }
}
