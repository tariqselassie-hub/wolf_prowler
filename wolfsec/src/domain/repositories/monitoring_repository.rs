use crate::domain::entities::monitoring::SecurityEvent;
use crate::domain::error::DomainError;
use async_trait::async_trait;
use uuid::Uuid;

/// A port for storing and retrieving security events.
/// This trait is implemented by the persistence layer.
#[async_trait]
pub trait MonitoringRepository: Send + Sync {
    /// Saves a security event.
    async fn save_event(&self, event: &SecurityEvent) -> Result<(), DomainError>;

    /// Finds an event by its ID.
    async fn find_event_by_id(&self, id: &Uuid) -> Result<Option<SecurityEvent>, DomainError>;
}
