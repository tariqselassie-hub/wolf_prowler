use crate::domain::entities::Alert;
use crate::domain::error::DomainError;
use async_trait::async_trait;
use uuid::Uuid;

/// A port for persisting and retrieving `Alert` entities.
#[async_trait]
pub trait AlertRepository: Send + Sync {
    /// Saves an alert to the persistence layer.
    async fn save(&self, alert: &Alert) -> Result<(), DomainError>;

    /// Finds an alert by its unique ID.
    async fn find_by_id(&self, id: &Uuid) -> Result<Option<Alert>, DomainError>;

    /// Gets recent alerts.
    async fn get_recent_alerts(&self, limit: usize) -> Result<Vec<Alert>, DomainError>;
}
