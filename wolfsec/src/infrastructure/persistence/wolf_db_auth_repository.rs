use crate::domain::entities::auth::{Role, User};
use crate::domain::error::DomainError;
use crate::domain::repositories::AuthRepository;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use wolf_db::storage::WolfDbStorage;
use wolf_db::storage::model::Record;

const TABLE_USERS: &str = "users";
const TABLE_ROLES: &str = "roles";

pub struct WolfDbAuthRepository {
    storage: Arc<RwLock<WolfDbStorage>>,
}

impl WolfDbAuthRepository {
    pub fn new(storage: Arc<RwLock<WolfDbStorage>>) -> Self {
        Self { storage }
    }
}

#[async_trait]
impl AuthRepository for WolfDbAuthRepository {
    async fn save_user(&self, user: &User) -> Result<(), DomainError> {
        let mut storage = self.storage.write().await;
        let pk = storage.get_active_pk().ok_or_else(|| DomainError::Unexpected("Database locked".to_string()))?.to_vec();
        
        let json_str = serde_json::to_string(user)
            .map_err(|e| DomainError::Unexpected(e.to_string()))?;
            
        let mut data = HashMap::new();
        data.insert("json".to_string(), json_str);
        data.insert("username".to_string(), user.username.clone());
        
        let record = Record {
            id: user.id.to_string(),
            data,
            vector: None,
        };
        
        storage.insert_record(TABLE_USERS, &record, &pk)
            .map_err(|e| DomainError::Unexpected(e.to_string()))?;
            
        Ok(())
    }

    async fn find_user_by_id(&self, id: &Uuid) -> Result<Option<User>, DomainError> {
        let storage = self.storage.read().await;
        // Assuming public read is allowed or we use a read key if needed, but for now assuming local authenticated usage
        // WolfDb `get_record` requires secret key for decryption if encrypted.
        let sk = storage.get_active_sk().ok_or_else(|| DomainError::Unexpected("Database locked".to_string()))?;
        
        if let Some(record) = storage.get_record(TABLE_USERS, &id.to_string(), sk)
            .map_err(|e| DomainError::Unexpected(e.to_string()))? {
            
            if let Some(json) = record.data.get("json") {
                let user: User = serde_json::from_str(json)
                    .map_err(|e| DomainError::Unexpected(e.to_string()))?;
                return Ok(Some(user));
            }
        }
        Ok(None)
    }

    async fn find_user_by_username(&self, username: &str) -> Result<Option<User>, DomainError> {
        let storage = self.storage.read().await;
        let sk = storage.get_active_sk().ok_or_else(|| DomainError::Unexpected("Database locked".to_string()))?;
        
        // This requires a secondary index or scan. WolfDb `find_by_metadata` is suitable here.
        let records = storage.find_by_metadata(TABLE_USERS, "username", username, sk)
             .map_err(|e| DomainError::Unexpected(e.to_string()))?;
             
        if let Some(record) = records.first() {
             if let Some(json) = record.data.get("json") {
                let user: User = serde_json::from_str(json)
                    .map_err(|e| DomainError::Unexpected(e.to_string()))?;
                return Ok(Some(user));
            }
        }
        Ok(None)
    }

    async fn save_role(&self, role: &Role) -> Result<(), DomainError> {
        let mut storage = self.storage.write().await;
        let pk = storage.get_active_pk().ok_or_else(|| DomainError::Unexpected("Database locked".to_string()))?.to_vec();
        
        let json_str = serde_json::to_string(role)
            .map_err(|e| DomainError::Unexpected(e.to_string()))?;
            
        let mut data = HashMap::new();
        data.insert("json".to_string(), json_str);
        data.insert("name".to_string(), role.name.clone());
        
        let record = Record {
            id: role.id.to_string(),
            data,
            vector: None,
        };
        
        storage.insert_record(TABLE_ROLES, &record, &pk)
            .map_err(|e| DomainError::Unexpected(e.to_string()))?;
            
        Ok(())
    }

    async fn find_role_by_name(&self, name: &str) -> Result<Option<Role>, DomainError> {
        let storage = self.storage.read().await;
        let sk = storage.get_active_sk().ok_or_else(|| DomainError::Unexpected("Database locked".to_string()))?;
        
        let records = storage.find_by_metadata(TABLE_ROLES, "name", name, sk)
             .map_err(|e| DomainError::Unexpected(e.to_string()))?;
             
        if let Some(record) = records.first() {
             if let Some(json) = record.data.get("json") {
                let role: Role = serde_json::from_str(json)
                    .map_err(|e| DomainError::Unexpected(e.to_string()))?;
                return Ok(Some(role));
            }
        }
        Ok(None)
    }
}
