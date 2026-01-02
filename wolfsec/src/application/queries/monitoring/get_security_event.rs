// /home/t4riq/Desktop/Rust/wolf_prowler/wolfsec/src/application/queries/monitoring/get_security_event.rs
use crate::application::dtos::SecurityEventDto;
use crate::application::error::ApplicationError;
use crate::domain::repositories::MonitoringRepository;
use anyhow::Context;
use std::sync::Arc;
use tracing::instrument;
use uuid::Uuid;

/// Query to retrieve a specific security event by its ID.
#[derive(Debug)]
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
    #[instrument(skip(self), fields(event_id = %query.event_id))]
    pub async fn handle(
        &self,
        query: GetSecurityEventQuery,
    ) -> Result<Option<SecurityEventDto<'static>>, ApplicationError> {
        let event = self
            .monitoring_repo
            .find_event_by_id(&query.event_id)
            .await
            .context("Failed to query security event from repository")?;

        Ok(event.map(SecurityEventDto::from))
    }
}
