// /home/t4riq/Desktop/Rust/wolf_prowler/wolfsec/src/domain/services/threat_analyzer.rs
use crate::domain::entities::{Alert, AlertCategory, AlertSeverity, ThreatSeverity};
use crate::domain::error::DomainError;
use crate::domain::repositories::{AlertRepository, ThreatRepository};
use std::sync::Arc;

/// A domain service for analyzing threats and escalating them if necessary.
/// It contains pure business logic and depends only on domain-defined traits (ports).
pub struct ThreatAnalyzer {
    threat_repo: Arc<dyn ThreatRepository>,
    alert_repo: Arc<dyn AlertRepository>,
}

impl ThreatAnalyzer {
    #[must_use]
    pub fn new(
        threat_repo: Arc<dyn ThreatRepository>,
        alert_repo: Arc<dyn AlertRepository>,
    ) -> Self {
        Self {
            threat_repo,
            alert_repo,
        }
    }

    /// Analyzes a threat and creates a critical alert if the severity is high enough.
    ///
    /// # Errors
    ///
    /// Returns a `DomainError` if the threat cannot be found or if saving the alert fails.
    pub async fn analyze_and_escalate(
        &self,
        threat_id: &uuid::Uuid,
    ) -> Result<Option<Alert>, DomainError> {
        let threat = self
            .threat_repo
            .find_by_id(threat_id)
            .await?
            .ok_or_else(|| DomainError::NotFound {
                entity_type: "Threat",
                id: threat_id.to_string(),
            })?;

        if matches!(
            threat.severity,
            ThreatSeverity::High | ThreatSeverity::Critical
        ) && threat.confidence > 0.75
        {
            let alert = Alert::new(
                AlertSeverity::Critical,
                AlertCategory::ThreatIntelligence,
                format!("High-Confidence Threat Detected: {:?}", threat.threat_type),
                threat.description.clone(),
                "ThreatAnalyzer".to_string(),
                std::collections::HashMap::new(),
            );
            self.alert_repo.save(&alert).await?;
            return Ok(Some(alert));
        }

        Ok(None)
    }
}
