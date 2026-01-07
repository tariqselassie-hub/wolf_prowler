use crate::domain::entities::Threat;
use crate::domain::error::DomainError;
use crate::domain::repositories::ThreatRepository;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use wolf_db::storage::WolfDbStorage;
use wolf_db::storage::model::Record;

const TABLE_THREATS: &str = "threats";

pub struct WolfDbThreatRepository {
    storage: Arc<RwLock<WolfDbStorage>>,
}

impl WolfDbThreatRepository {
    pub fn new(storage: Arc<RwLock<WolfDbStorage>>) -> Self {
        Self { storage }
    }
}

#[async_trait]
impl ThreatRepository for WolfDbThreatRepository {
    async fn save(&self, threat: &Threat) -> Result<(), DomainError> {
        let mut storage = self.storage.write().await;
        let pk = storage.get_active_pk().ok_or_else(|| DomainError::Unexpected("Database locked".to_string()))?.to_vec();
        
        let json_str = serde_json::to_string(threat)
            .map_err(|e| DomainError::Unexpected(e.to_string()))?;
            
        let mut data = HashMap::new();
        data.insert("json".to_string(), json_str);
        data.insert("severity".to_string(), format!("{:?}", threat.severity));
         data.insert("threat_type".to_string(), format!("{:?}", threat.threat_type));
        
        let record = Record {
            id: threat.id.to_string(),
            data,
            vector: None,
        };
        
        storage.insert_record(TABLE_THREATS, &record, &pk)
            .map_err(|e| DomainError::Unexpected(e.to_string()))?;
            
        Ok(())
    }

    async fn find_by_id(&self, id: &Uuid) -> Result<Option<Threat>, DomainError> {
         let storage = self.storage.read().await;
        let sk = storage.get_active_sk().ok_or_else(|| DomainError::Unexpected("Database locked".to_string()))?;
        
        if let Some(record) = storage.get_record(TABLE_THREATS, &id.to_string(), sk)
            .map_err(|e| DomainError::Unexpected(e.to_string()))? {
            
            if let Some(json) = record.data.get("json") {
                let threat: Threat = serde_json::from_str(json)
                    .map_err(|e| DomainError::Unexpected(e.to_string()))?;
                return Ok(Some(threat));
            }
        }
        Ok(None)
    }
}
