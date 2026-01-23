//! WolfSec SIEM (Security Information and Event Management)
//!
//! Provides comprehensive security event collection, correlation, analysis,
//! and automated response capabilities.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use wolfsec_core::{SecurityEvent, SecurityModule, ModuleStatus, SecurityError};

/// SIEM configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SIEMConfig {
    /// Maximum events to keep in memory
    pub max_events_in_memory: usize,
    /// Event retention period in seconds
    pub event_retention_seconds: u64,
    /// Enable correlation analysis
    pub enable_correlation: bool,
    /// Alert threshold for event frequency
    pub alert_threshold: usize,
}

/// SIEM event with additional metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SIEMEvent {
    pub core_event: SecurityEvent,
    pub correlation_id: String,
    pub source_system: String,
    pub processing_timestamp: DateTime<Utc>,
    pub correlated_events: Vec<String>,
    pub risk_score: f64,
}

/// SIEM statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SIEMStats {
    pub total_events_processed: usize,
    pub events_last_hour: usize,
    pub alerts_generated: usize,
    pub correlations_found: usize,
    pub average_processing_time_ms: f64,
    pub storage_size_bytes: usize,
}

/// Response action for automated response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResponseAction {
    BlockNetwork,
    IsolateSystem,
    RevokeAccess,
    RequireMFA,
    IncreaseMonitoring,
    SendNotification,
    LogForInvestigation,
    QuarantineSystem,
}

/// Security Information and Event Management system
pub struct WolfSIEMManager {
    config: SIEMConfig,
    events: Vec<SIEMEvent>,
    stats: SIEMStats,
    initialized: bool,
}

impl WolfSIEMManager {
    /// Create a new SIEM manager
    pub fn new(config: SIEMConfig) -> Result<Self, SecurityError> {
        Ok(Self {
            config,
            events: Vec::with_capacity(config.max_events_in_memory),
            stats: SIEMStats {
                total_events_processed: 0,
                events_last_hour: 0,
                alerts_generated: 0,
                correlations_found: 0,
                average_processing_time_ms: 0.0,
                storage_size_bytes: 0,
            },
            initialized: false,
        })
    }

    /// Process and correlate a security event
    pub async fn process_event(&mut self, event: SecurityEvent) -> Result<Vec<ResponseAction>, SecurityError> {
        let start_time = std::time::Instant::now();

        // Convert to SIEM event
        let siem_event = SIEMEvent {
            core_event: event,
            correlation_id: uuid::Uuid::new_v4().to_string(),
            source_system: "WolfSec".to_string(),
            processing_timestamp: Utc::now(),
            correlated_events: Vec::new(),
            risk_score: self.calculate_risk_score(&event),
        };

        // Perform correlation analysis
        if self.config.enable_correlation {
            siem_event.correlated_events = self.find_correlations(&siem_event).await;
            self.stats.correlations_found += siem_event.correlated_events.len();
        }

        // Add to event store
        self.events.push(siem_event.clone());
        self.cleanup_old_events();

        // Update statistics
        self.stats.total_events_processed += 1;
        self.stats.events_last_hour += 1;
        self.stats.average_processing_time_ms = (self.stats.average_processing_time_ms + start_time.elapsed().as_millis() as f64) / 2.0;

        // Generate response actions based on event severity and correlations
        let actions = self.generate_response_actions(&siem_event);

        Ok(actions)
    }

    /// Calculate risk score for an event
    fn calculate_risk_score(&self, event: &SecurityEvent) -> f64 {
        let mut score = match event.severity {
            wolfsec_core::SecuritySeverity::Low => 1.0,
            wolfsec_core::SecuritySeverity::Medium => 3.0,
            wolfsec_core::SecuritySeverity::High => 7.0,
            wolfsec_core::SecuritySeverity::Critical => 10.0,
        };

        // Adjust based on event type
        match event.event_type {
            wolfsec_core::SecurityEventType::AuthenticationFailure => score *= 1.2,
            wolfsec_core::SecurityEventType::KeyCompromise => score *= 2.0,
            wolfsec_core::SecurityEventType::DataBreach => score *= 2.5,
            _ => {}
        }

        score.min(10.0)
    }

    /// Find correlated events
    async fn find_correlations(&self, event: &SIEMEvent) -> Vec<String> {
        let mut correlated = Vec::new();

        // Simple correlation: find events from same peer in last hour
        if let Some(peer_id) = &event.core_event.peer_id {
            for existing_event in &self.events {
                if let Some(existing_peer) = &existing_event.core_event.peer_id {
                    if existing_peer == peer_id &&
                       (event.processing_timestamp - existing_event.processing_timestamp).num_seconds() < 3600 {
                        correlated.push(existing_event.correlation_id.clone());
                    }
                }
            }
        }

        correlated
    }

    /// Generate automated response actions
    fn generate_response_actions(&mut self, event: &SIEMEvent) -> Vec<ResponseAction> {
        let mut actions = Vec::new();

        if event.risk_score >= 8.0 {
            actions.push(ResponseAction::BlockNetwork);
            actions.push(ResponseAction::SendNotification);
            self.stats.alerts_generated += 1;
        } else if event.risk_score >= 6.0 {
            actions.push(ResponseAction::IncreaseMonitoring);
            actions.push(ResponseAction::LogForInvestigation);
        }

        if !event.correlated_events.is_empty() && event.correlated_events.len() >= 3 {
            actions.push(ResponseAction::IsolateSystem);
        }

        actions
    }

    /// Clean up old events based on retention policy
    fn cleanup_old_events(&mut self) {
        let cutoff = Utc::now() - chrono::Duration::seconds(self.config.event_retention_seconds as i64);
        self.events.retain(|event| event.processing_timestamp > cutoff);

        // Limit memory usage
        if self.events.len() > self.config.max_events_in_memory {
            self.events = self.events.split_off(self.events.len() - self.config.max_events_in_memory);
        }
    }

    /// Get recent events
    pub fn get_recent_events(&self, limit: usize) -> Vec<&SIEMEvent> {
        self.events.iter().rev().take(limit).collect()
    }

    /// Get events by severity
    pub fn get_events_by_severity(&self, severity: wolfsec_core::SecuritySeverity) -> Vec<&SIEMEvent> {
        self.events.iter()
            .filter(|event| event.core_event.severity == severity)
            .collect()
    }
}

#[async_trait]
impl SecurityModule for WolfSIEMManager {
    fn name(&self) -> &'static str {
        "siem"
    }

    async fn initialize(&mut self) -> Result<(), SecurityError> {
        self.initialized = true;
        tracing::info!("SIEM module initialized with capacity for {} events", self.config.max_events_in_memory);
        Ok(())
    }

    async fn process_event(&mut self, event: &SecurityEvent) -> Result<(), SecurityError> {
        let _actions = self.process_event(event.clone()).await?;
        Ok(())
    }

    async fn status(&self) -> Result<ModuleStatus, SecurityError> {
        Ok(ModuleStatus {
            name: self.name().to_string(),
            healthy: self.initialized,
            last_activity: Utc::now(),
            metrics: HashMap::from([
                ("total_events_processed".to_string(), self.stats.total_events_processed as f64),
                ("events_last_hour".to_string(), self.stats.events_last_hour as f64),
                ("alerts_generated".to_string(), self.stats.alerts_generated as f64),
                ("correlations_found".to_string(), self.stats.correlations_found as f64),
                ("average_processing_time_ms".to_string(), self.stats.average_processing_time_ms),
            ]),
            alerts: Vec::new(),
        })
    }

    async fn shutdown(&mut self) -> Result<(), SecurityError> {
        self.initialized = false;
        tracing::info!("SIEM module shutdown");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_siem_initialization() {
        let config = SIEMConfig {
            max_events_in_memory: 1000,
            event_retention_seconds: 3600,
            enable_correlation: true,
            alert_threshold: 10,
        };

        let mut siem = WolfSIEMManager::new(config).unwrap();
        assert!(!siem.initialized);

        siem.initialize().await.unwrap();
        assert!(siem.initialized);
        assert_eq!(siem.name(), "siem");
    }

    #[tokio::test]
    async fn test_siem_event_processing() {
        let config = SIEMConfig {
            max_events_in_memory: 1000,
            event_retention_seconds: 3600,
            enable_correlation: false,
            alert_threshold: 10,
        };

        let mut siem = WolfSIEMManager::new(config).unwrap();
        siem.initialize().await.unwrap();

        let event = SecurityEvent::new(
            wolfsec_core::SecurityEventType::AuthenticationFailure,
            wolfsec_core::SecuritySeverity::High,
            "Failed login attempt".to_string(),
        );

        let actions = siem.process_event(event).await.unwrap();

        assert_eq!(siem.stats.total_events_processed, 1);
        assert!(!actions.is_empty()); // Should generate actions for high severity
    }

    #[tokio::test]
    async fn test_siem_correlation() {
        let config = SIEMConfig {
            max_events_in_memory: 1000,
            event_retention_seconds: 3600,
            enable_correlation: true,
            alert_threshold: 10,
        };

        let mut siem = WolfSIEMManager::new(config).unwrap();
        siem.initialize().await.unwrap();

        // Add first event
        let event1 = SecurityEvent::new(
            wolfsec_core::SecurityEventType::AuthenticationFailure,
            wolfsec_core::SecuritySeverity::Medium,
            "First failed login".to_string(),
        ).with_peer("test-peer".to_string());

        siem.process_event(event1).await.unwrap();

        // Add second correlated event
        let event2 = SecurityEvent::new(
            wolfsec_core::SecurityEventType::SuspiciousActivity,
            wolfsec_core::SecuritySeverity::Medium,
            "Second suspicious activity".to_string(),
        ).with_peer("test-peer".to_string());

        siem.process_event(event2).await.unwrap();

        // Check correlations
        let recent = siem.get_recent_events(1);
        assert!(!recent[0].correlated_events.is_empty());
    }

    #[test]
    fn test_risk_score_calculation() {
        let config = SIEMConfig {
            max_events_in_memory: 1000,
            event_retention_seconds: 3600,
            enable_correlation: false,
            alert_threshold: 10,
        };

        let siem = WolfSIEMManager::new(config).unwrap();

        let event = SecurityEvent::new(
            wolfsec_core::SecurityEventType::KeyCompromise,
            wolfsec_core::SecuritySeverity::Critical,
            "Key compromise detected".to_string(),
        );

        let score = siem.calculate_risk_score(&event);
        assert_eq!(score, 10.0); // Critical * 2.0 = 20.0, capped at 10.0
    }
}