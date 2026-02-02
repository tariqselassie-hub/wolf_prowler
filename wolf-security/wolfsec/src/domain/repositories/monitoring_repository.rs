use crate::domain::entities::monitoring::SecurityEvent;
use crate::domain::error::DomainError;
use async_trait::async_trait;
use uuid::Uuid;

/// A port for storing and retrieving security events.
/// This trait is implemented by the persistence layer.
#[async_trait]
pub trait MonitoringRepository: Send + Sync {
    /// Saves a security event to the persistent store.
    async fn save_event(&self, event: &SecurityEvent) -> Result<(), DomainError>;

    /// Retrieves a security event by its unique ID.
    async fn find_event_by_id(&self, id: &Uuid) -> Result<Option<SecurityEvent>, DomainError>;

    /// Retrieves the most recent security events up to the specified limit.
    async fn get_recent_events(&self, limit: usize) -> Result<Vec<SecurityEvent>, DomainError>;
}
