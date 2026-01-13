use crate::domain::entities::Threat;
use crate::domain::error::DomainError;
use async_trait::async_trait;
use uuid::Uuid;

/// A port for persisting and retrieving `Threat` entities.
#[async_trait]
pub trait ThreatRepository: Send + Sync {
    /// Saves a threat to the persistence layer.
    async fn save(&self, threat: &Threat) -> Result<(), DomainError>;

    /// Finds a threat by its unique ID.
    async fn find_by_id(&self, id: &Uuid) -> Result<Option<Threat>, DomainError>;

    /// Gets recent threats.
    async fn get_recent_threats(&self, limit: usize) -> Result<Vec<Threat>, DomainError>;
}
