use crate::domain::entities::monitoring::SecurityEvent;
use crate::domain::error::DomainError;
use crate::domain::repositories::MonitoringRepository;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use wolf_db::storage::WolfDbStorage;
use wolf_db::storage::model::Record;

const TABLE_SECURITY_EVENTS: &str = "security_events";

/// A repository for managing security monitoring events using WolfDb.
pub struct WolfDbMonitoringRepository {
    /// The thread-safe storage engine.
    pub storage: Arc<RwLock<WolfDbStorage>>,
}

impl WolfDbMonitoringRepository {
    /// Creates a new instance of `WolfDbMonitoringRepository`.
    ///
    /// # Arguments
    /// * `storage` - An `Arc<RwLock<WolfDbStorage>>` providing thread-safe access to the database.
    pub fn new(storage: Arc<RwLock<WolfDbStorage>>) -> Self {
        Self { storage }
    }
}

#[async_trait]
impl MonitoringRepository for WolfDbMonitoringRepository {
    async fn save_event(&self, event: &SecurityEvent) -> Result<(), DomainError> {
        let storage = self.storage.write().await;
        let pk = storage.get_active_pk().ok_or_else(|| DomainError::Unexpected("Database locked".to_string()))?.to_vec();
        
        let json_str = serde_json::to_string(event)
            .map_err(|e| DomainError::Unexpected(e.to_string()))?;
            
        let mut data = HashMap::new();
        data.insert("json".to_string(), json_str);
        data.insert("severity".to_string(), format!("{:?}", event.severity));
        
        let record = Record {
            id: event.id.to_string(),
            data,
            vector: None,
        };
        
        storage.insert_record(TABLE_SECURITY_EVENTS.to_string(), record, pk)
            .await
            .map_err(|e| DomainError::Unexpected(e.to_string()))?;
            
        Ok(())
    }

    async fn find_event_by_id(&self, id: &Uuid) -> Result<Option<SecurityEvent>, DomainError> {
         let storage = self.storage.read().await;
        let sk = storage.get_active_sk().ok_or_else(|| DomainError::Unexpected("Database locked".to_string()))?;
        
        if let Some(record) = storage.get_record(TABLE_SECURITY_EVENTS.to_string(), id.to_string(), sk.to_vec())
            .await
            .map_err(|e| DomainError::Unexpected(e.to_string()))? {
            
            if let Some(json) = record.data.get("json") {
                let event: SecurityEvent = serde_json::from_str(json)
                    .map_err(|e| DomainError::Unexpected(e.to_string()))?;
                return Ok(Some(event));
            }
        }
        Ok(None)
    }
}
