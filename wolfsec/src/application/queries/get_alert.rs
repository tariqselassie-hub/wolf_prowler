use crate::application::dtos::AlertDto;
use crate::application::error::ApplicationError;
use crate::domain::repositories::AlertRepository;
use anyhow::Context;
use std::sync::Arc;
use tracing::instrument;
use uuid::Uuid;

/// Query to retrieve a specific alert by its ID.
#[derive(Debug)]
pub struct GetAlertQuery {
    pub alert_id: Uuid,
}

/// Handler for the GetAlertQuery.
pub struct GetAlertHandler {
    alert_repo: Arc<dyn AlertRepository>,
}

impl GetAlertHandler {
    pub fn new(alert_repo: Arc<dyn AlertRepository>) -> Self {
        Self { alert_repo }
    }

    /// Executes the query to find an alert and returns it as a DTO.
    #[instrument(skip(self), fields(alert_id = %query.alert_id))]
    pub async fn handle(
        &self,
        query: GetAlertQuery,
    ) -> Result<Option<AlertDto<'static>>, ApplicationError> {
        let alert = self
            .alert_repo
            .find_by_id(&query.alert_id)
            .await
            .context("Failed to query alert from repository")?;

        Ok(alert.map(AlertDto::from))
    }
}
