// /home/t4riq/Desktop/Rust/wolf_prowler/wolfsec/src/domain/services/threat_detection.rs
use crate::domain::entities::{monitoring::SecurityEvent, Threat};
use crate::domain::error::DomainError;
use async_trait::async_trait;

/// A domain service trait defining threat detection capabilities.
/// Implementations (Infrastructure) will handle the actual logic (AI, signatures, etc.).
#[async_trait]
pub trait ThreatDetectionService: Send + Sync {
    /// Analyzes a security event to determine if it represents a threat.
    async fn detect_from_event(&self, event: &SecurityEvent)
        -> Result<Option<Threat>, DomainError>;

    /// Performs a proactive scan on a peer to identify potential threats.
    async fn scan_peer(&self, peer_id: &str) -> Result<Vec<Threat>, DomainError>;
}
