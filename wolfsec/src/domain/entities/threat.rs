use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ThreatType {
    MaliciousPeer,
    NetworkScan,
    DataExfiltration,
    Reconnaissance,
    Malware,
    Phishing,
    InsiderThreat,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ThreatSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Threat {
    pub id: Uuid,
    pub threat_type: ThreatType,
    pub severity: ThreatSeverity,
    pub description: String,
    pub source_peer: Option<String>,
    pub target_asset: Option<String>,
    pub detected_at: DateTime<Utc>,
    pub confidence: f64,
    pub mitigation_steps: Vec<String>,
    pub related_events: Vec<Uuid>,
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
