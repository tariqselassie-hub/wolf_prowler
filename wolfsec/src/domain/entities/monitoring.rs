use crate::domain::entities::{AlertCategory, AlertSeverity};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Represents a security-relevant occurrence within the system.
/// This is a pure domain entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub category: AlertCategory,
    pub severity: AlertSeverity,
    pub title: String,
    pub description: String,
    pub source: String,
    pub details: HashMap<String, String>,
}

impl SecurityEvent {
    #[must_use]
    pub fn new(
        category: AlertCategory,
        severity: AlertSeverity,
        title: String,
        description: String,
        source: String,
        details: HashMap<String, String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            category,
            severity,
            title,
            description,
            source,
            details,
        }
    }
}

/// A domain entity representing a rule for correlating events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationRule {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    // In a real system, this would be a more complex structure representing the rule's logic.
    pub is_active: bool,
}
