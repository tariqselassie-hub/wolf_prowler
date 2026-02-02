use crate::domain::entities::{AlertCategory, AlertSeverity};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Represents a security-relevant occurrence within the system.
/// This is a pure domain entity.
/// Represents a security-relevant occurrence or observation within the system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    /// Unique identifier for the event.
    pub id: Uuid,
    /// Precise point in time when the event occurred.
    pub timestamp: DateTime<Utc>,
    /// The functional category this event belongs to.
    pub category: AlertCategory,
    /// The relative importance or risk associated with this event.
    pub severity: AlertSeverity,
    /// human-readable short title for the event.
    pub title: String,
    /// Detailed account of the event activity.
    pub description: String,
    /// The module, service, or node that emitted the event.
    pub source: String,
    /// Bag of supplementary key-value pairs for technical analysis.
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
/// Defines logic for identifying patterns across multiple disparate security events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationRule {
    /// Unique identifier for the rule.
    pub id: Uuid,
    /// Distinctive name identifying the rule's purpose.
    pub name: String,
    /// Detailed explanation of the logic this rule implements.
    pub description: String,
    /// Whether this rule is currently being evaluated by the monitoring system.
    pub is_active: bool,
}
