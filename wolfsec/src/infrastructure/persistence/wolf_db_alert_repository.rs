use crate::domain::entities::Alert;
use crate::domain::error::DomainError;
use crate::domain::repositories::AlertRepository;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use wolf_db::storage::WolfDbStorage;
use wolf_db::storage::model::Record;

const TABLE_ALERTS: &str = "alerts";

/// A repository for managing security alerts using WolfDb as the underlying storage.
pub struct WolfDbAlertRepository {
    /// The thread-safe storage engine.
    pub storage: Arc<RwLock<WolfDbStorage>>,
}

impl WolfDbAlertRepository {
    /// Creates a new instance of `WolfDbAlertRepository`.
    ///
    /// # Arguments
    /// * `storage` - An `Arc<RwLock<WolfDbStorage>>` providing thread-safe access to the database.
    pub fn new(storage: Arc<RwLock<WolfDbStorage>>) -> Self {
        Self { storage }
    }
}

#[async_trait]
impl AlertRepository for WolfDbAlertRepository {
    async fn save(&self, alert: &Alert) -> Result<(), DomainError> {
        let storage = self.storage.write().await;
        let pk = storage.get_active_pk().ok_or_else(|| DomainError::Unexpected("Database locked".to_string()))?.to_vec();
        
        let json_str = serde_json::to_string(alert)
            .map_err(|e| DomainError::Unexpected(e.to_string()))?;
            
        let mut data = HashMap::new();
        data.insert("json".to_string(), json_str);
        // Index useful fields
        data.insert("severity".to_string(), format!("{:?}", alert.severity));
        data.insert("status".to_string(), format!("{:?}", alert.status));
        data.insert("category".to_string(), format!("{:?}", alert.category));
        
        let record = Record {
            id: alert.id.to_string(),
            data,
            vector: None,
        };
        
        storage.insert_record(TABLE_ALERTS.to_string(), record, pk)
            .await
            .map_err(|e| DomainError::Unexpected(e.to_string()))?;
            
        Ok(())
    }

    async fn find_by_id(&self, id: &Uuid) -> Result<Option<Alert>, DomainError> {
        let storage = self.storage.read().await;
        let sk = storage.get_active_sk().ok_or_else(|| DomainError::Unexpected("Database locked".to_string()))?;
        
        if let Some(record) = storage.get_record(TABLE_ALERTS.to_string(), id.to_string(), sk.to_vec())
            .await
            .map_err(|e| DomainError::Unexpected(e.to_string()))? {
            
            if let Some(json) = record.data.get("json") {
                let alert: Alert = serde_json::from_str(json)
                    .map_err(|e| DomainError::Unexpected(e.to_string()))?;
                return Ok(Some(alert));
            }
        }
        Ok(None)
    }
}
