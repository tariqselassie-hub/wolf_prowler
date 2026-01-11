//! Database persistence layer for Wolf Prowler
//!
//! Provides WolfDb (PQC-Secured) persistence for all Wolf Prowler data including:
//! - Peer information and metrics
//! - Security events and alerts
//! - Audit logs
//! - Configuration
//! - Wolf Pack hierarchy

use anyhow::{Context, Result};
use chrono::Utc;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};
use uuid::Uuid;

use wolf_db::storage::model::Record;
use wolf_db::storage::WolfDbStorage;

pub mod models;
pub use models::*;

// Collection/Table Names
const TABLE_PEERS: &str = "peers";
const TABLE_PEER_METRICS: &str = "peer_metrics";
const TABLE_SECURITY_EVENTS: &str = "security_events";
const TABLE_SECURITY_ALERTS: &str = "security_alerts";
const TABLE_AUDIT_LOGS: &str = "audit_logs";
const TABLE_CONFIG: &str = "config";
const TABLE_ORGANIZATIONS: &str = "organizations";
const TABLE_PACK_MEMBERS: &str = "pack_members";
const TABLE_SYSTEM_LOGS: &str = "system_logs";

/// Database connection pool manager
#[derive(Clone)]
pub struct PersistenceManager {
    storage: Arc<RwLock<WolfDbStorage>>,
}

impl PersistenceManager {
    /// Create a new persistence manager with WolfDb path
    pub async fn new(db_path: &str) -> Result<Self> {
        info!("Initializing WolfDb at: {}", db_path);

        // Ensure directory exists
        if let Some(parent) = std::path::Path::new(db_path).parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut storage = WolfDbStorage::open(db_path).context("Failed to open WolfDb")?;

        // Initialize keystore if not exists users will need to set this up properly in production
        // For now we use a default dev password if not initialized to allow startup
        if !storage.is_initialized() {
            info!("Initializing new WolfDb keystore...");
            storage
                .initialize_keystore("wolf_prowler_default_secret", None)
                .context("Failed to initialize keystore")?;
        }

        // Auto-unlock for now (in prod this should be prompted or env var)
        if !storage.get_active_sk().is_some() {
            storage
                .unlock("wolf_prowler_default_secret", None)
                .context("Failed to unlock WolfDb")?;
        }

        info!("WolfDb initialized and unlocked");

        Ok(Self {
            storage: Arc::new(RwLock::new(storage)),
        })
    }

    /// Health check - verify database is open and unlocked
    pub async fn health_check(&self) -> Result<bool> {
        let storage = self.storage.read().await;
        Ok(storage.get_active_sk().is_some())
    }

    /// Get a reference to the underlying storage
    pub fn get_storage(&self) -> Arc<RwLock<WolfDbStorage>> {
        self.storage.clone()
    }

    // ========================================================================
    // HELPER METHODS
    // ========================================================================

    async fn get_record<T: serde::de::DeserializeOwned>(
        &self,
        table: &str,
        id: &str,
    ) -> Result<Option<T>> {
        let storage = self.storage.read().await;
        let sk = storage.get_active_sk().context("Database locked")?.to_vec();

        if let Some(record) = storage
            .get_record(table.to_string(), id.to_string(), sk)
            .await?
        {
            // WolfDb stores generic maps in record.data, but we likely stored the struct serialized in a specific way
            // Or we map the struct fields to the map.
            // However, WolfDb's `insert_record` takes a Record which has `data: HashMap<String, String>`.
            // Our models are structs. We need a way to serialize our structs into that HashMap or
            // modify WolfDb to support binary blobs or use a specific field for JSON.
            // Looking at WolfDb implementation from previous files, it seems to serialize the Whole Record struct.

            // Actually, `WolfDbStorage::insert_record` serializes the `Record` struct using bincode.
            // But we need to store OUR struct.
            // The `Record` struct has `data: HashMap<String, String>`.
            // We should serialize our struct to JSON and store it in `data["json"]`.

            if let Some(json_str) = record.data.get("json") {
                let obj = serde_json::from_str(json_str)?;
                return Ok(Some(obj));
            }
        }
        Ok(None)
    }

    async fn insert_struct<T: serde::Serialize>(
        &self,
        table: &str,
        id: &str,
        obj: &T,
        metadata: Option<std::collections::HashMap<String, String>>,
    ) -> Result<()> {
        let storage = self.storage.write().await;

        let pk = storage.get_active_pk().context("Database locked")?.to_vec(); // Clone key to release borrow if needed, but insert takes slice

        let json_str = serde_json::to_string(obj)?;
        let mut data = metadata.unwrap_or_default();
        data.insert("json".to_string(), json_str);

        let record = Record {
            id: id.to_string(),
            data,
            vector: None,
        };

        storage.insert_record(table.to_string(), record, pk).await?;
        Ok(())
    }

    // ========================================================================
    // ORGANIZATION OPERATIONS
    // ========================================================================

    pub async fn resolve_org_key(&self, org_key: &str) -> Result<Option<Uuid>> {
        // This effectively requires a secondary index lookup
        // In WolfDb we can search by metadata if we indexed it
        let storage = self.storage.read().await;
        let sk = storage.get_active_sk().context("Database locked")?;

        let records = storage
            .find_by_metadata(
                TABLE_ORGANIZATIONS.to_string(),
                "org_key".to_string(),
                org_key.to_string(),
                sk.to_vec(),
            )
            .await?;

        if let Some(record) = records.first() {
            if let Some(json) = record.data.get("json") {
                let org: DbOrganization = serde_json::from_str(json)?;
                return Ok(Some(org.org_id));
            }
        }
        Ok(None)
    }

    pub async fn create_organization(
        &self,
        name: &str,
        email: Option<&str>,
        org_key: &str,
    ) -> Result<Uuid> {
        let org_id = Uuid::new_v4();
        let org = DbOrganization {
            org_id,
            name: name.to_string(),
            org_key: org_key.to_string(),
            admin_email: email.map(|s| s.to_string()),
            status: "active".to_string(),
            created_at: Some(Utc::now()),
            updated_at: Some(Utc::now()),
        };

        let mut meta = std::collections::HashMap::new();
        meta.insert("org_key".to_string(), org_key.to_string());

        self.insert_struct(TABLE_ORGANIZATIONS, &org_id.to_string(), &org, Some(meta))
            .await?;
        Ok(org_id)
    }

    pub async fn get_organization(&self, org_id: Uuid) -> Result<Option<DbOrganization>> {
        self.get_record(TABLE_ORGANIZATIONS, &org_id.to_string())
            .await
    }

    pub async fn get_organization_by_key(&self, org_key: &str) -> Result<Option<DbOrganization>> {
        let storage = self.storage.read().await;
        let sk = storage.get_active_sk().context("Database locked")?;

        let records = storage
            .find_by_metadata(
                TABLE_ORGANIZATIONS.to_string(),
                "org_key".to_string(),
                org_key.to_string(),
                sk.to_vec(),
            )
            .await?;

        if let Some(record) = records.first() {
            if let Some(json) = record.data.get("json") {
                let org: DbOrganization = serde_json::from_str(json)?;
                return Ok(Some(org));
            }
        }
        Ok(None)
    }

    // ========================================================================
    // PEER OPERATIONS
    // ========================================================================

    pub async fn save_peer(&self, peer: &DbPeer) -> Result<()> {
        let mut meta = std::collections::HashMap::new();
        if let Some(org_id) = peer.org_id {
            meta.insert("org_id".to_string(), org_id.to_string());
        }
        meta.insert("status".to_string(), peer.status.clone());

        self.insert_struct(TABLE_PEERS, &peer.peer_id, peer, Some(meta))
            .await?;
        debug!("Saved peer: {}", peer.peer_id);
        Ok(())
    }

    pub async fn save_peers_batch(&self, peers: &[DbPeer]) -> Result<()> {
        // WolfDb has simple batching via loop for now or we could expose batch insert
        for peer in peers {
            self.save_peer(peer).await?;
        }
        Ok(())
    }

    pub async fn get_all_peers(&self, org_id: Uuid) -> Result<Vec<DbPeer>> {
        let storage = self.storage.read().await;
        let sk = storage.get_active_sk().context("Database locked")?;

        let records = storage
            .find_by_metadata(
                TABLE_PEERS.to_string(),
                "org_id".to_string(),
                org_id.to_string(),
                sk.to_vec(),
            )
            .await?;

        let mut peers = Vec::new();
        for record in records {
            if let Some(json) = record.data.get("json") {
                if let Ok(peer) = serde_json::from_str::<DbPeer>(json) {
                    peers.push(peer);
                }
            }
        }
        Ok(peers)
    }

    pub async fn get_peer(&self, _org_id: Uuid, peer_id: &str) -> Result<Option<DbPeer>> {
        // Ignoring org_id filter for direct ID lookup for now, or we could verify it matches
        self.get_record(TABLE_PEERS, peer_id).await
    }

    pub async fn get_active_peers(&self, org_id: Uuid) -> Result<Vec<DbPeer>> {
        // This requires filtering by org_id AND status. WolfDb basic find is one key.
        // We filter in memory after fetching by org_id
        let all = self.get_all_peers(org_id).await?;
        Ok(all.into_iter().filter(|p| p.status == "online").collect())
    }

    pub async fn save_peer_metrics(&self, metrics: &DbPeerMetrics) -> Result<()> {
        let id = format!("{}_{}", metrics.peer_id, Utc::now().timestamp_millis());
        self.insert_struct(TABLE_PEER_METRICS, &id, metrics, None)
            .await
    }

    pub async fn save_peer_metrics_batch(&self, metrics: &[DbPeerMetrics]) -> Result<()> {
        for m in metrics {
            self.save_peer_metrics(m).await?;
        }
        Ok(())
    }

    // ========================================================================
    // SECURITY OPERATIONS
    // ========================================================================

    pub async fn save_security_event(&self, event: &DbSecurityEvent) -> Result<()> {
        let id = event
            .event_id
            .map(|u| u.to_string())
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        let mut meta = std::collections::HashMap::new();
        meta.insert("severity".to_string(), event.severity.clone());
        if let Some(org_id) = event.org_id {
            meta.insert("org_id".to_string(), org_id.to_string());
        }

        self.insert_struct(TABLE_SECURITY_EVENTS, &id, event, Some(meta))
            .await
    }

    pub async fn save_security_alert(&self, alert: &DbSecurityAlert) -> Result<()> {
        let id = alert
            .alert_id
            .map(|u| u.to_string())
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        let mut meta = std::collections::HashMap::new();
        if let Some(org_id) = alert.org_id {
            meta.insert("org_id".to_string(), org_id.to_string());
        }
        meta.insert("severity".to_string(), alert.severity.clone());

        self.insert_struct(TABLE_SECURITY_ALERTS, &id, alert, Some(meta))
            .await
    }

    pub async fn store_siem_event(
        &self,
        event: &wolfsec::security::advanced::siem::SecurityEvent,
    ) -> Result<()> {
        let db_event = DbSecurityEvent::from_siem_event(event);
        self.save_security_event(&db_event).await
    }

    // ========================================================================
    // AUDIT OPERATIONS
    // ========================================================================

    pub async fn save_audit_log(&self, log: &DbAuditLog) -> Result<()> {
        let id = Uuid::new_v4().to_string();
        let mut meta = std::collections::HashMap::new();
        if let Some(actor) = &log.actor {
            meta.insert("actor".to_string(), actor.clone());
        }
        self.insert_struct(TABLE_AUDIT_LOGS, &id, log, Some(meta))
            .await
    }

    // ========================================================================
    // CONFIGURATION OPERATIONS
    // ========================================================================

    pub async fn get_config(&self, key: &str) -> Result<Option<serde_json::Value>> {
        if let Some(cfg) = self.get_record::<DbConfig>(TABLE_CONFIG, key).await? {
            Ok(Some(cfg.value))
        } else {
            Ok(None)
        }
    }

    pub async fn set_config(
        &self,
        key: &str,
        value: serde_json::Value,
        updated_by: Option<&str>,
    ) -> Result<()> {
        let config = DbConfig {
            key: key.to_string(),
            value,
            description: None,
            updated_at: Utc::now(),
            updated_by: updated_by.map(|s| s.to_string()),
        };
        self.insert_struct(TABLE_CONFIG, key, &config, None).await
    }

    // ========================================================================
    // WOLF PACK OPERATIONS
    // ========================================================================

    pub async fn save_pack_member(&self, member: &DbPackMember) -> Result<()> {
        let mut meta = std::collections::HashMap::new();
        meta.insert("pack_name".to_string(), member.pack_name.clone());
        self.insert_struct(TABLE_PACK_MEMBERS, &member.peer_id, member, Some(meta))
            .await
    }

    pub async fn save_system_log(&self, log: &DbSystemLog) -> Result<()> {
        let id = Uuid::new_v4().to_string();
        self.insert_struct(TABLE_SYSTEM_LOGS, &id, log, None).await
    }
}
