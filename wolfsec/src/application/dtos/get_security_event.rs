use crate::application::dtos::SecurityEventDto;
use crate::application::error::ApplicationError;
use crate::domain::repositories::MonitoringRepository;
use anyhow::Context;
use std::sync::Arc;
use uuid::Uuid;

/// Query to retrieve a specific security event by its ID.
pub struct GetSecurityEventQuery {
    pub event_id: Uuid,
}

/// Handler for the GetSecurityEventQuery.
pub struct GetSecurityEventHandler {
    monitoring_repo: Arc<dyn MonitoringRepository>,
}

impl GetSecurityEventHandler {
    pub fn new(monitoring_repo: Arc<dyn MonitoringRepository>) -> Self {
        Self { monitoring_repo }
    }

    /// Executes the query to find a security event and returns it as a DTO.
    pub async fn handle(
        &self,
        query: GetSecurityEventQuery,
    ) -> Result<Option<SecurityEventDto>, ApplicationError> {
        let event = self
            .monitoring_repo
            .find_event_by_id(&query.event_id)
            .await
            .context("Failed to query security event from repository")?;

        Ok(event.map(SecurityEventDto::from))
    }
}
