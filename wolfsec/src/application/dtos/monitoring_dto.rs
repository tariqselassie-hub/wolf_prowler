// /home/t4riq/Desktop/Rust/wolf_prowler/wolfsec/src/application/dtos/monitoring_dto.rs
use crate::domain::entities::{AlertCategory, AlertSeverity, SecurityEvent};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::HashMap;
use uuid::Uuid;

/// Data Transfer Object for a SecurityEvent.
#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityEventDto<'a> {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub category: AlertCategory,
    pub severity: AlertSeverity,
    #[serde(borrow)]
    pub title: Cow<'a, str>,
    #[serde(borrow)]
    pub description: Cow<'a, str>,
    #[serde(borrow)]
    pub source: Cow<'a, str>,
    pub details: HashMap<String, String>,
}

impl From<SecurityEvent> for SecurityEventDto<'static> {
    fn from(event: SecurityEvent) -> Self {
        Self {
            id: event.id,
            timestamp: event.timestamp,
            category: event.category,
            severity: event.severity,
            title: Cow::Owned(event.title),
            description: Cow::Owned(event.description),
            source: Cow::Owned(event.source),
            details: event.details,
        }
    }
}

impl<'a> From<&'a SecurityEvent> for SecurityEventDto<'a> {
    fn from(event: &'a SecurityEvent) -> Self {
        Self {
            id: event.id,
            timestamp: event.timestamp,
            category: event.category.clone(),
            severity: event.severity.clone(),
            title: Cow::Borrowed(&event.title),
            description: Cow::Borrowed(&event.description),
            source: Cow::Borrowed(&event.source),
            details: event.details.clone(),
        }
    }
}
