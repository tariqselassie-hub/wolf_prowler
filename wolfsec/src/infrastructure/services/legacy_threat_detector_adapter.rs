// /home/t4riq/Desktop/Rust/wolf_prowler/wolfsec/src/infrastructure/services/legacy_threat_detector.rs
use crate::application::services::ThreatDetectionService;
use crate::domain::entities::{monitoring::SecurityEvent, Threat, ThreatSeverity, ThreatType};
use crate::domain::error::DomainError;
use crate::threat_detection::ThreatDetector as LegacyThreatDetectorImpl;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::Mutex;

/// An adapter that wraps the legacy `ThreatDetector` to conform to the new `ThreatDetectionService` trait.
/// This acts as a bridge between the new architecture and the old implementation, forming an "anti-corruption layer".
pub struct LegacyThreatDetectorAdapter {
    legacy_detector: Arc<Mutex<LegacyThreatDetectorImpl>>,
}

impl LegacyThreatDetectorAdapter {
    pub fn new(legacy_detector: Arc<Mutex<LegacyThreatDetectorImpl>>) -> Self {
        Self { legacy_detector }
    }
}

#[async_trait]
impl ThreatDetectionService for LegacyThreatDetectorAdapter {
    async fn detect_from_event(
        &self,
        event: &SecurityEvent,
    ) -> Result<Option<Threat>, DomainError> {
        // Convert the new domain `SecurityEvent` to the old `crate::SecurityEvent`.
        let old_event = crate::SecurityEvent {
            id: event.id.to_string(),
            timestamp: event.timestamp,
            event_type: crate::SecurityEventType::Other(event.title.clone()),
            severity: match event.severity {
                crate::domain::entities::AlertSeverity::Info => crate::SecuritySeverity::Low,
                crate::domain::entities::AlertSeverity::Low => crate::SecuritySeverity::Low,
                crate::domain::entities::AlertSeverity::Medium => crate::SecuritySeverity::Medium,
                crate::domain::entities::AlertSeverity::High => crate::SecuritySeverity::High,
                crate::domain::entities::AlertSeverity::Critical => {
                    crate::SecuritySeverity::Critical
                }
            },
            description: event.description.clone(),
            peer_id: event.details.get("peer_id").cloned(),
            metadata: event.details.clone(),
        };

        let mut detector = self.legacy_detector.lock().await;

        // The legacy `analyze_threat_with_ai` is the closest function to what we need.
        let analysis_result = detector
            .analyze_threat_with_ai(&old_event)
            .await
            .map_err(|e| DomainError::ThreatDetectionError(e.to_string()))?;

        // If the anomaly score is high enough, create a new domain `Threat` entity.
        if analysis_result.anomaly_score > 0.75 {
            let threat = Threat::new(
                ThreatType::Unknown,
                ThreatSeverity::High,
                analysis_result.recommendations.join("; "),
                analysis_result.confidence,
            );
            Ok(Some(threat))
        } else {
            Ok(None)
        }
    }

    async fn scan_peer(&self, peer_id: &str) -> Result<Vec<Threat>, DomainError> {
        let detector = self.legacy_detector.lock().await;
        let (anomaly_score, recommendations) = detector
            .analyze_peer_behavior(peer_id)
            .await
            .ok_or_else(|| {
                DomainError::ThreatDetectionError("Peer behavior analysis failed".to_string())
            })?;

        // Convert the peer behavior analysis to a domain `Threat` if it's suspicious.
        let mut domain_threats = Vec::new();
        if anomaly_score > 0.5 {
            domain_threats.push(Threat::new(
                ThreatType::Unknown,
                ThreatSeverity::Medium,
                recommendations.join("; "),
                0.8, // Default confidence
            ));
        }

        Ok(domain_threats)
    }
}
