//! Database models for Wolf Prowler persistence layer

use chrono::{DateTime, Utc};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ============================================================================
// PEER MODELS
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbPeer {
    pub org_id: Option<Uuid>,
    pub peer_id: String,
    pub service_type: String,
    pub system_type: String,
    pub version: Option<String>,
    pub status: String,
    pub trust_score: Option<f32>,
    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
    pub protocol_version: Option<String>,
    pub agent_version: Option<String>,
    pub capabilities: Option<serde_json::Value>,
    pub metadata: Option<serde_json::Value>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbPeerMetrics {
    pub org_id: Option<Uuid>,
    pub peer_id: String,
    pub latency_ms: Option<i64>,
    pub messages_sent: Option<i64>,
    pub messages_received: Option<i64>,
    pub bytes_sent: Option<i64>,
    pub bytes_received: Option<i64>,
    pub requests_sent: Option<i64>,
    pub requests_received: Option<i64>,
    pub requests_success: Option<i64>,
    pub requests_failed: Option<i64>,
    pub health_score: Option<f32>, // Changed to f32 to match database
    pub uptime_ms: Option<i64>,
}

// ============================================================================
// SECURITY MODELS
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbSecurityEvent {
    pub org_id: Option<Uuid>,
    pub id: Option<i64>,
    pub event_id: Option<Uuid>,
    pub timestamp: Option<DateTime<Utc>>,
    pub event_type: String,
    pub severity: String,
    pub source: Option<String>,
    pub peer_id: Option<String>,
    pub description: String,
    pub details: serde_json::Value,
    pub resolved: Option<bool>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub resolved_by: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbSecurityAlert {
    pub org_id: Option<Uuid>,
    pub id: Option<i64>,
    pub alert_id: Option<Uuid>,
    pub timestamp: Option<DateTime<Utc>>,
    pub severity: String,
    pub status: String,
    pub title: String,
    pub message: Option<String>,
    pub category: String,
    pub source: String,
    pub escalation_level: Option<i32>,
    pub acknowledged_by: Option<String>,
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub resolved_by: Option<String>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbThreatIntelligence {
    pub org_id: Option<Uuid>,
    pub id: Option<i64>,
    pub threat_id: Option<Uuid>,
    pub threat_type: String,
    pub severity: String,
    pub indicators: serde_json::Value,
    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
    pub source: Option<String>,
    pub confidence: Option<f64>,
    pub active: Option<bool>,
    pub metadata: serde_json::Value,
}

// ============================================================================
// SIEM CONVERSION HELPERS
// ============================================================================

impl DbSecurityEvent {
    /// Convert from SIEM SecurityEvent to database model
    pub fn from_siem_event(event: &wolfsec::security::advanced::siem::SecurityEvent) -> Self {
        // Extract peer_id from affected assets if available (first asset's ID)
        let peer_id = event
            .affected_assets
            .first()
            .map(|asset| asset.asset_id.clone());

        Self {
            org_id: None,
            id: None,
            event_id: Some(event.event_id),
            timestamp: Some(event.timestamp),
            event_type: format!("{:?}", event.event_type),
            severity: format!("{:?}", event.severity),
            source: Some(event.source.source_id.clone()),
            peer_id,
            description: event.description.clone(),
            details: serde_json::to_value(&event.details).unwrap_or_else(|_| serde_json::json!({})),
            resolved: Some(false),
            resolved_at: None,
            resolved_by: None,
        }
    }
}

// ============================================================================
// AUDIT MODELS
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbAuditLog {
    pub org_id: Option<Uuid>,
    pub id: Option<i64>,
    pub timestamp: Option<DateTime<Utc>>,
    pub action: String,
    pub actor: Option<String>,
    pub resource: Option<String>,
    pub resource_type: Option<String>,
    pub result: String,
    pub details: serde_json::Value,
    pub ip_address: Option<ipnetwork::IpNetwork>,
    pub user_agent: Option<String>,
}

// ============================================================================
// CONFIGURATION MODELS
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbConfig {
    pub key: String,
    pub value: serde_json::Value,
    pub description: Option<String>,
    pub updated_at: DateTime<Utc>,
    pub updated_by: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbOrganization {
    pub org_id: Uuid,
    pub name: String,
    pub org_key: String,
    pub admin_email: Option<String>,
    pub status: String,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

// ============================================================================
// WOLF PACK MODELS
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbPackMember {
    pub org_id: Option<Uuid>,
    pub peer_id: String,
    pub rank: String,
    pub pack_name: String,
    pub joined_at: Option<DateTime<Utc>>,
    pub last_active: Option<DateTime<Utc>>,
    pub contributions: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbPackHierarchy {
    pub org_id: Option<Uuid>,
    pub id: Option<i64>,
    pub pack_name: String,
    pub alpha_peer_id: Option<String>,
    pub established_at: Option<DateTime<Utc>>,
    pub member_count: Option<i32>,
    pub territory: serde_json::Value,
}

// ============================================================================
// SYSTEM MODELS
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbSystemLog {
    pub org_id: Option<Uuid>,
    pub id: Option<i64>,
    pub timestamp: Option<DateTime<Utc>>,
    pub level: String,
    pub message: String,
    pub source: Option<String>,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbNetworkMetrics {
    pub org_id: Option<Uuid>,
    pub id: Option<i64>,
    pub timestamp: Option<DateTime<Utc>>,
    pub active_connections: Option<i32>,
    pub total_messages_sent: Option<i64>,
    pub total_messages_received: Option<i64>,
    pub total_bytes_sent: Option<i64>,
    pub total_bytes_received: Option<i64>,
    pub connection_failures: Option<i64>,
    pub average_latency_ms: Option<f64>,
}

// ============================================================================
// CONVERSION HELPERS
// ============================================================================

impl From<&wolf_net::peer::EntityInfo> for DbPeer {
    fn from(info: &wolf_net::peer::EntityInfo) -> Self {
        DbPeer {
            org_id: None,
            peer_id: info.entity_id.peer_id.to_string(),
            service_type: info.entity_id.service_id.to_string(),
            system_type: info.entity_id.system_id.to_string(),
            version: None,
            status: format!("{:?}", info.status),
            trust_score: Some(0.5),
            first_seen: Some(Utc::now()),
            last_seen: Some(Utc::now()),
            protocol_version: None,
            agent_version: None,
            capabilities: Some(serde_json::json!({})),
            metadata: Some(serde_json::json!({})),
            created_at: Some(Utc::now()),
            updated_at: Some(Utc::now()),
        }
    }
}

impl DbPeerMetrics {
    pub fn from_entity_metrics(peer_id: &str, metrics: &wolf_net::peer::EntityMetrics) -> Self {
        Self {
            org_id: None,
            peer_id: peer_id.to_string(),
            latency_ms: Some(metrics.latency_ms as i64),
            messages_sent: Some(metrics.messages_sent as i64),
            messages_received: Some(metrics.messages_received as i64),
            bytes_sent: Some(metrics.bytes_sent as i64),
            bytes_received: Some(metrics.bytes_received as i64),
            requests_sent: Some(metrics.requests_sent as i64),
            requests_received: Some(metrics.requests_received as i64),
            requests_success: Some(metrics.requests_success as i64),
            requests_failed: Some(metrics.requests_failed as i64),
            health_score: Some(metrics.health_score as f32), // Cast f64 to f32
            uptime_ms: Some(metrics.uptime_ms as i64),
        }
    }
}

impl DbPackMember {
    pub fn new(peer_id: String, rank: String, pack_name: String) -> Self {
        Self {
            org_id: None,
            peer_id,
            rank,
            pack_name,
            joined_at: Some(Utc::now()),
            last_active: Some(Utc::now()),
            contributions: serde_json::json!({}),
        }
    }
}

impl DbSystemLog {
    pub fn new(level: String, message: String, source: Option<String>) -> Self {
        Self {
            org_id: None,
            id: None,
            timestamp: Some(Utc::now()),
            level,
            message,
            source,
            metadata: serde_json::json!({}),
        }
    }
}
