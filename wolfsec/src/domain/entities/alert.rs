// /home/t4riq/Desktop/Rust/wolf_prowler/wolfsec/src/domain/entities/alert.rs
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AlertSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AlertStatus {
    New,
    Acknowledged,
    InProgress,
    Resolved,
    Suppressed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AlertCategory {
    Network,
    Authentication,
    Behavioral,
    System,
    Data,
    Compliance,
    ThreatIntelligence,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub severity: AlertSeverity,
    pub category: AlertCategory,
    pub title: String,
    pub description: String,
    pub source: String,
    pub status: AlertStatus,
    pub details: HashMap<String, String>,
    pub acknowledged_by: Option<String>,
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
