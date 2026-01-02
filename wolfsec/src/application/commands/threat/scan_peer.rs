// /home/t4riq/Desktop/Rust/wolf_prowler/wolfsec/src/application/commands/threat/scan_peer.rs
use crate::application::error::ApplicationError;
use crate::domain::repositories::ThreatRepository;
use crate::application::services::ThreatDetectionService;
use anyhow::Context;
use std::sync::Arc;
use uuid::Uuid;

/// Command to manually scan a peer for threats.
pub struct ScanPeerCommand {
    pub peer_id: String,
}

/// Handler for ScanPeerCommand.
pub struct ScanPeerHandler {
    detection_service: Arc<dyn ThreatDetectionService>,
    threat_repo: Arc<dyn ThreatRepository>,
}

impl ScanPeerHandler {
    pub fn new(
        detection_service: Arc<dyn ThreatDetectionService>,
        threat_repo: Arc<dyn ThreatRepository>,
    ) -> Self {
        Self {
            detection_service,
            threat_repo,
        }
    }

    pub async fn handle(&self, command: ScanPeerCommand) -> Result<Vec<Uuid>, ApplicationError> {
        let threats = self.detection_service.scan_peer(&command.peer_id).await?;
        for threat in &threats {
            self.threat_repo
                .save(threat)
                .await
                .context("Failed to save scanned threat")?;
        }
        Ok(threats.into_iter().map(|t| t.id).collect())
    }
}
