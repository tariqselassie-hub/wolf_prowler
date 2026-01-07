use anyhow::{Context, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;
use wolf_db::storage::{WolfDbStorage, model::Record};
use crate::persistence::models::*;

#[derive(Clone)]
pub struct PersistenceManager {
    storage: Arc<Mutex<WolfDbStorage>>,
}

impl PersistenceManager {
    pub async fn new(path: &str) -> Result<Self> {
        let mut storage = WolfDbStorage::open(path)?;
        
        // Auto-initialize if needed (for now, simpler than implementing full keystore management in WolfProwler)
        if !storage.is_initialized() {
            storage.initialize_keystore("wolf_default_pass", None)?;
        }
        storage.unlock("wolf_default_pass", None)?;

        Ok(Self {
            storage: Arc::new(Mutex::new(storage)),
        })
    }
    
    // Health check
    pub async fn health_check(&self) -> Result<bool> {
        // Simple check if we can lock the storage
        let _storage = self.storage.lock().await;
        Ok(true)
    }

    // ========================================================================
    // PEER OPERATIONS
    // ========================================================================

    pub async fn save_peer(&self, peer: &DbPeer) -> Result<()> {
        let mut storage = self.storage.lock().await;
        // Flatten critical fields for indexing
        let mut data = HashMap::new();
        data.insert("status".to_string(), peer.status.clone());
        if let Some(org_id) = peer.org_id {
            data.insert("org_id".to_string(), org_id.to_string());
        }
        
        // Serialize full object for retrieval
        let json = serde_json::to_string(peer)?;
        data.insert("json".to_string(), json);

        let record = Record {
            id: peer.peer_id.clone(),
            data,
            vector: None,
        };

        // Use 'peers' table
        let pk = storage.get_active_pk().context("DB locked")?.to_vec();
        storage.insert_record("peers", &record, &pk)?;
        Ok(())
    }

    pub async fn get_peer(&self, _org_id: Uuid, peer_id: &str) -> Result<Option<DbPeer>> {
        let storage = self.storage.lock().await;
        let sk = storage.get_active_sk().context("DB locked")?;
        
        if let Some(record) = storage.get_record("peers", peer_id, sk)? {
            if let Some(json) = record.data.get("json") {
                let peer: DbPeer = serde_json::from_str(json)?;
                return Ok(Some(peer));
            }
        }
        Ok(None)
    }

    pub async fn get_active_peers(&self, org_id: Uuid) -> Result<Vec<DbPeer>> {
        let storage = self.storage.lock().await;
        let sk = storage.get_active_sk().context("DB locked")?;
        
        // Query by status="online"
        let records = storage.find_by_metadata("peers", "status", "online", sk)?;
        
        let mut peers = Vec::new();
        for record in records {
            if let Some(json) = record.data.get("json") {
                let peer: DbPeer = serde_json::from_str(json)?;
                // Client-side filtering for org_id (since generic find_by_metadata only supports one field)
                // Optimization: Could index org_id too and intersect, but this is fine for now.
                if peer.org_id == Some(org_id) {
                    peers.push(peer);
                }
            }
        }
        Ok(peers)
    }

    // ========================================================================
    // SECURITY OPERATIONS
    // ========================================================================

    pub async fn save_security_event(&self, event: &DbSecurityEvent) -> Result<()> {
        let mut storage = self.storage.lock().await;
        let mut data = HashMap::new();
        data.insert("event_type".to_string(), event.event_type.clone());
        data.insert("severity".to_string(), event.severity.clone());
        if let Some(org_id) = event.org_id {
            data.insert("org_id".to_string(), org_id.to_string());
        }

        let json = serde_json::to_string(event)?;
        data.insert("json".to_string(), json);

        let id = event.event_id.unwrap_or_else(Uuid::new_v4).to_string();
        let record = Record {
            id,
            data,
            vector: None,
        };

        let pk = storage.get_active_pk().context("DB locked")?.to_vec();
        storage.insert_record("security_events", &record, &pk)?;
        Ok(())
    }

    // ========================================================================
    // CONFIG OPERATIONS
    // ========================================================================
    
    pub async fn get_config(&self, key: &str) -> Result<Option<serde_json::Value>> {
        let storage = self.storage.lock().await;
        let sk = storage.get_active_sk().context("DB locked")?;
        
        if let Some(record) = storage.get_record("config", key, sk)? {
            if let Some(val_str) = record.data.get("value") {
                let val: serde_json::Value = serde_json::from_str(val_str)?;
                return Ok(Some(val));
            }
        }
        Ok(None)
    }

    pub async fn set_config(&self, key: &str, value: serde_json::Value, _updated_by: Option<&str>) -> Result<()> {
        let mut storage = self.storage.lock().await;
        let mut data = HashMap::new();
        data.insert("value".to_string(), serde_json::to_string(&value)?);
        
        let record = Record {
            id: key.to_string(),
            data,
            vector: None,
        };

        let pk = storage.get_active_pk().context("DB locked")?.to_vec();
        storage.insert_record("config", &record, &pk)?;
        Ok(())
    }

    // ========================================================================
    // ORGANIZATION OPERATIONS
    // ========================================================================
    
    pub async fn get_organization_by_key(&self, org_key: &str) -> Result<Option<DbOrganization>> {
        let storage = self.storage.lock().await;
        let sk = storage.get_active_sk().context("DB locked")?;
        
        let records = storage.find_by_metadata("organizations", "org_key", org_key, sk)?;
        if let Some(record) = records.first() {
             if let Some(json) = record.data.get("json") {
                let org: DbOrganization = serde_json::from_str(json)?;
                return Ok(Some(org));
             }
        }
        Ok(None)
    }

    // ... Stub other methods to satisfy interface if needed, or implement incrementally ...
}
