// /home/t4riq/Desktop/Rust/wolf_prowler/wolfsec/src/application/dtos/alert_dto.rs
use crate::domain::entities::{Alert, AlertCategory, AlertSeverity, AlertStatus};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use std::borrow::Cow;

/// Data Transfer Object for an Alert.
/// This is the public representation of an alert, used for API responses.
#[derive(Debug, Serialize, Deserialize)]
pub struct AlertDto<'a> {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub severity: AlertSeverity,
    pub category: AlertCategory,
    #[serde(borrow)]
    pub title: Cow<'a, str>,
    #[serde(borrow)]
    pub description: Cow<'a, str>,
    #[serde(borrow)]
    pub source: Cow<'a, str>,
    pub status: AlertStatus,
    pub details: HashMap<String, String>,
}

/// Converts a domain `Alert` into a public `AlertDto`.
impl From<Alert> for AlertDto<'static> {
    fn from(alert: Alert) -> Self {
        Self {
            id: alert.id,
            timestamp: alert.timestamp,
            severity: alert.severity,
            category: alert.category,
            title: Cow::Owned(alert.title),
            description: Cow::Owned(alert.description),
            source: Cow::Owned(alert.source),
            status: alert.status,
            details: alert.details,
        }
    }
}

impl<'a> From<&'a Alert> for AlertDto<'a> {
    fn from(alert: &'a Alert) -> Self {
        Self {
            id: alert.id,
            timestamp: alert.timestamp,
            severity: alert.severity.clone(),
            category: alert.category.clone(),
            title: Cow::Borrowed(&alert.title),
            description: Cow::Borrowed(&alert.description),
            source: Cow::Borrowed(&alert.source),
            status: alert.status.clone(),
            details: alert.details.clone(),
        }
    }
}
