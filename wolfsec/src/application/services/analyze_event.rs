// /home/t4riq/Desktop/Rust/wolf_prowler/wolfsec/src/application/commands/threat/analyze_event.rs
use crate::application::error::ApplicationError;
use crate::domain::entities::monitoring::SecurityEvent;
use crate::domain::repositories::ThreatRepository;
use crate::application::services::ThreatDetectionService;
use anyhow::Context;
use std::sync::Arc;
use uuid::Uuid;

/// Command to analyze a security event for threats.
pub struct AnalyzeEventCommand {
    pub event: SecurityEvent,
}

/// Handler for AnalyzeEventCommand.
pub struct AnalyzeEventHandler {
    detection_service: Arc<dyn ThreatDetectionService>,
    threat_repo: Arc<dyn ThreatRepository>,
}

impl AnalyzeEventHandler {
    pub fn new(
        detection_service: Arc<dyn ThreatDetectionService>,
        threat_repo: Arc<dyn ThreatRepository>,
    ) -> Self {
        Self {
            detection_service,
            threat_repo,
        }
    }

    pub async fn handle(
        &self,
        command: AnalyzeEventCommand,
    ) -> Result<Option<Uuid>, ApplicationError> {
        if let Some(threat) = self
            .detection_service
            .detect_from_event(&command.event)
            .await?
        {
            let threat_id = threat.id;
            self.threat_repo
                .save(&threat)
                .await
                .context("Failed to save detected threat")?;
            Ok(Some(threat_id))
        } else {
            Ok(None)
        }
    }
}
