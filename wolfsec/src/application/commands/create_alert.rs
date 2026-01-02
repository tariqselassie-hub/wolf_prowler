use crate::application::error::ApplicationError;
use crate::domain::{
    entities::{Alert, AlertCategory, AlertSeverity},
    repositories::AlertRepository,
};
use anyhow::Context;
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::instrument;
use uuid::Uuid;

/// Command to create a new security alert.
/// This represents a use case intent.
pub struct CreateAlertCommand<'a> {
    pub severity: AlertSeverity,
    pub category: AlertCategory,
    pub title: Cow<'a, str>,
    pub description: Cow<'a, str>,
    pub source: Cow<'a, str>,
    pub details: HashMap<String, String>,
}

/// Handler for the CreateAlertCommand.
/// It orchestrates the domain logic and infrastructure.
pub struct CreateAlertHandler {
    alert_repo: Arc<dyn AlertRepository>,
}

impl CreateAlertHandler {
    pub fn new(alert_repo: Arc<dyn AlertRepository>) -> Self {
        Self { alert_repo }
    }

    /// Executes the command to create and save an alert.
    #[instrument(skip(self, command), fields(title = %command.title, severity = ?command.severity))]
    pub async fn handle(&self, command: CreateAlertCommand<'_>) -> Result<Uuid, ApplicationError> {
        let alert = Alert::new(
            command.severity,
            command.category,
            command.title.into_owned(),
            command.description.into_owned(),
            command.source.into_owned(),
            command.details,
        );
        let alert_id = alert.id;

        self.alert_repo
            .save(&alert)
            .await
            .context("Failed to save alert in repository")?;

        Ok(alert_id)
    }
}
