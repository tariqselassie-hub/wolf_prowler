use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AuditEventType {
    CertificateGenerated,
    CertificateValidated,
    CertificateRevoked,
    CertificateExpired,
    KeyRotated,
    KeyGenerated,
    KeyRevoked,
    KeyExpired,
    AccessDenied,
    AccessGranted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateAuditEvent {
    pub event_type: AuditEventType,
    pub certificate_id: String,
    pub user_id: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub details: HashMap<String, String>,
    pub ip_address: Option<String>,
}
