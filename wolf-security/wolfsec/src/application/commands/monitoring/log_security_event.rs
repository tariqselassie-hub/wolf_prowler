use crate::application::error::ApplicationError;
use crate::domain::{
    entities::{monitoring::SecurityEvent, AlertCategory, AlertSeverity},
    repositories::MonitoringRepository,
};
use anyhow::Context;
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

/// Command to log a new security event.
pub struct LogSecurityEventCommand<'a> {
    pub category: AlertCategory,
    pub severity: AlertSeverity,
    pub title: Cow<'a, str>,
    pub description: Cow<'a, str>,
    pub source: Cow<'a, str>,
    pub details: HashMap<String, String>,
}

/// Handler for the LogSecurityEventCommand.
pub struct LogSecurityEventHandler {
    monitoring_repo: Arc<dyn MonitoringRepository>,
}

impl LogSecurityEventHandler {
    pub fn new(monitoring_repo: Arc<dyn MonitoringRepository>) -> Self {
        Self { monitoring_repo }
    }

    /// Executes the command to create and save a security event.
    pub async fn handle(
        &self,
        command: LogSecurityEventCommand<'_>,
    ) -> Result<Uuid, ApplicationError> {
        let event = SecurityEvent::new(
            command.category,
            command.severity,
            command.title.into_owned(),
            command.description.into_owned(),
            command.source.into_owned(),
            command.details,
        );
        let event_id = event.id;

        self.monitoring_repo
            .save_event(&event)
            .await
            .context("Failed to save security event in repository")?;

        Ok(event_id)
    }
}
