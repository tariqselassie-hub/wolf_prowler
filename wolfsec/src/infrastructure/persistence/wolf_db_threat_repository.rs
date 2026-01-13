use crate::domain::entities::Threat;
use crate::domain::error::DomainError;
use crate::domain::repositories::ThreatRepository;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use wolf_db::storage::model::Record;
use wolf_db::storage::WolfDbStorage;

const TABLE_THREATS: &str = "threats";

/// A repository for managing threat intelligence data using WolfDb.
pub struct WolfDbThreatRepository {
    /// The thread-safe storage engine.
    pub storage: Arc<RwLock<WolfDbStorage>>,
}

impl WolfDbThreatRepository {
    /// Creates a new instance of `WolfDbThreatRepository`.
    ///
    /// # Arguments
    /// * `storage` - An `Arc<RwLock<WolfDbStorage>>` providing thread-safe access to the database.
    pub fn new(storage: Arc<RwLock<WolfDbStorage>>) -> Self {
        Self { storage }
    }
}

#[async_trait]
impl ThreatRepository for WolfDbThreatRepository {
    async fn save(&self, threat: &Threat) -> Result<(), DomainError> {
        let storage = self.storage.write().await;
        let pk = storage
            .get_active_pk()
            .ok_or_else(|| DomainError::Unexpected("Database locked".to_string()))?
            .to_vec();

        let json_str =
            serde_json::to_string(threat).map_err(|e| DomainError::Unexpected(e.to_string()))?;

        let mut data = HashMap::new();
        data.insert("json".to_string(), json_str);
        data.insert("severity".to_string(), format!("{:?}", threat.severity));
        data.insert(
            "threat_type".to_string(),
            format!("{:?}", threat.threat_type),
        );

        let record = Record {
            id: threat.id.to_string(),
            data,
            vector: None,
        };

        storage
            .insert_record(TABLE_THREATS.to_string(), record, pk)
            .await
            .map_err(|e| DomainError::Unexpected(e.to_string()))?;

        Ok(())
    }

    async fn find_by_id(&self, id: &Uuid) -> Result<Option<Threat>, DomainError> {
        let storage = self.storage.read().await;
        let sk = storage
            .get_active_sk()
            .ok_or_else(|| DomainError::Unexpected("Database locked".to_string()))?;

        if let Some(record) = storage
            .get_record(TABLE_THREATS.to_string(), id.to_string(), sk.to_vec())
            .await
            .map_err(|e| DomainError::Unexpected(e.to_string()))?
        {
            if let Some(json) = record.data.get("json") {
                let threat: Threat = serde_json::from_str(json)
                    .map_err(|e| DomainError::Unexpected(e.to_string()))?;
                return Ok(Some(threat));
            }
        }
        Ok(None)
    }

    async fn get_recent_threats(&self, limit: usize) -> Result<Vec<Threat>, DomainError> {
        let storage = self.storage.read().await;
        let sk = storage
            .get_active_sk()
            .ok_or_else(|| DomainError::Unexpected("Database locked".to_string()))?;

        let keys = storage
            .list_keys(TABLE_THREATS.to_string().into())
            .await
            .map_err(|e| DomainError::Unexpected(e.to_string()))?;

        let mut threats = Vec::new();
        for key in keys {
            if let Some(record) = storage
                .get_record(TABLE_THREATS.to_string(), key, sk.to_vec())
                .await
                .map_err(|e| DomainError::Unexpected(e.to_string()))?
            {
                if let Some(json) = record.data.get("json") {
                    if let Ok(threat) = serde_json::from_str::<Threat>(json) {
                        threats.push(threat);
                    }
                }
            }
        }

        // Threat doesn't have a timestamp, but it might have internally.
        // For now, just take limit.
        Ok(threats.into_iter().take(limit).collect())
    }
}
