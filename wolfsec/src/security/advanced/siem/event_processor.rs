use anyhow::Result;

use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use uuid::Uuid;

use super::{
    correlation_engine::WolfCorrelationEngine, event_storage::EventStorage, EventSeverity,
    SIEMConfig, SecurityEvent, SecurityEventType,
};
use crate::security::advanced::soar::{IncidentContext, IncidentOrchestrator};
use std::collections::HashMap;

/// Real-time SIEM event processor
/// Handles incoming security events, performs correlation, and triggers incidents
pub struct SIEMEventProcessor {
    /// Event storage for persistence
    event_storage: Arc<RwLock<EventStorage>>,
    /// Correlation engine for detecting related events
    correlation_engine: Arc<RwLock<WolfCorrelationEngine>>,
    /// Incident orchestrator for automated response
    incident_orchestrator: Arc<RwLock<IncidentOrchestrator>>,
    /// Configuration
    config: SIEMConfig,
}

impl SIEMEventProcessor {
    /// Create a new SIEM event processor
    pub fn new(
        event_storage: Arc<RwLock<EventStorage>>,
        correlation_engine: Arc<RwLock<WolfCorrelationEngine>>,
        incident_orchestrator: Arc<RwLock<IncidentOrchestrator>>,
        config: SIEMConfig,
    ) -> Self {
        Self {
            event_storage,
            correlation_engine,
            incident_orchestrator,
            config,
        }
    }

    /// Process a single security event
    /// This is the main entry point for real-time event processing
    pub async fn process_event(&self, event: SecurityEvent) -> Result<()> {
        debug!("📥 Processing security event: {}", event.event_id);

        // Step 1: Store the event
        self.event_storage
            .write()
            .await
            .store_event(event.clone())
            .await?;

        // Step 2: Perform correlation analysis
        let correlations = self
            .correlation_engine
            .write()
            .await
            .correlate_event(&event)
            .await?;

        if !correlations.correlated_events.is_empty() {
            info!(
                "🔗 Found {} correlations for event {}",
                correlations.correlated_events.len(),
                event.event_id
            );

            // Step 3: Check if correlations indicate an attack chain
            // Use the result from correlate_event directly
            if let Some(chain) = correlations.attack_chain {
                warn!("⚠️ Detected attack chain for event {}", event.event_id);

                // Step 4: Trigger incident for the attack chain
                // Convert stages into strings for the simplified trigger_incident signature
                let chain_desc: Vec<String> = chain
                    .stages
                    .iter()
                    .map(|s| format!("{:?}", s.tactic))
                    .collect();

                self.trigger_incident(event.clone(), chain_desc).await?;
            }
        }

        // Step 5: Check if event severity warrants immediate incident
        if self.should_trigger_immediate_incident(&event) {
            warn!(
                "🚨 Event {} triggers immediate incident (severity: {:?})",
                event.event_id, event.severity
            );
            self.trigger_immediate_incident(event).await?;
        }

        Ok(())
    }

    /// Trigger an incident based on an attack chain
    async fn trigger_incident(
        &self,
        event: SecurityEvent,
        attack_chain: Vec<String>,
    ) -> Result<()> {
        info!(
            "🎯 Triggering incident for attack chain: {:?}",
            attack_chain
        );

        // Create incident context
        let incident_context = IncidentContext {
            incident_id: Uuid::new_v4(),
            trigger_event: event.clone(),
            related_events: vec![], // TODO: Pass related events
            affected_assets: event
                .affected_assets
                .iter()
                .map(|a| a.asset_id.clone())
                .collect(),
            severity_score: match event.severity {
                EventSeverity::Alpha => 1.0,
                EventSeverity::Beta => 0.8,
                EventSeverity::Hunter => 0.6,
                EventSeverity::Scout => 0.4,
                EventSeverity::Pup => 0.1,
            }, // High severity for confirmed attack chains
            metadata: HashMap::from([
                ("attack_chain".to_string(), format!("{:?}", attack_chain)),
                ("source".to_string(), format!("{:?}", event.source)),
            ]),
        };

        // Trigger incident through orchestrator
        self.incident_orchestrator
            .write()
            .await
            .handle_incident(incident_context)
            .await?;

        Ok(())
    }

    /// Trigger an immediate incident for high-severity events
    async fn trigger_immediate_incident(&self, event: SecurityEvent) -> Result<()> {
        info!(
            "🚨 Triggering immediate incident for event: {}",
            event.event_id
        );

        let incident_context = IncidentContext {
            incident_id: Uuid::new_v4(),
            trigger_event: event.clone(),
            related_events: vec![],
            affected_assets: event
                .affected_assets
                .iter()
                .map(|a| a.asset_id.clone())
                .collect(),
            severity_score: 1.0, // Critical event
            metadata: HashMap::from([
                ("immediate_response".to_string(), "true".to_string()),
                ("description".to_string(), event.description.clone()),
            ]),
        };

        self.incident_orchestrator
            .write()
            .await
            .handle_incident(incident_context)
            .await?;

        Ok(())
    }

    /// Determine if an event should trigger an immediate incident
    fn should_trigger_immediate_incident(&self, event: &SecurityEvent) -> bool {
        match event.severity {
            EventSeverity::Alpha => true,
            EventSeverity::Beta => {
                // High severity events trigger incidents if they match certain patterns
                matches!(
                    event.event_type,
                    SecurityEventType::ThreatEvent(_) | SecurityEventType::AuthEvent(_)
                )
            }
            _ => false,
        }
    }

    /// Process multiple events in batch
    pub async fn process_events_batch(&self, events: Vec<SecurityEvent>) -> Result<()> {
        info!("📦 Processing batch of {} events", events.len());

        for event in events {
            if let Err(e) = self.process_event(event).await {
                warn!("Failed to process event: {}", e);
                // Continue processing other events even if one fails
            }
        }

        Ok(())
    }

    /// Get processing statistics
    pub async fn get_statistics(&self) -> ProcessorStatistics {
        let storage_stats = self.event_storage.read().await.get_statistics();
        let correlation_stats = self.correlation_engine.read().await.get_statistics();
        let orchestrator_stats = self.incident_orchestrator.read().await.get_statistics();

        ProcessorStatistics {
            total_events_processed: storage_stats.total_events,
            correlations_found: correlation_stats.total_correlations,
            incidents_triggered: orchestrator_stats.total_incidents,
            active_incidents: orchestrator_stats.in_progress_incidents,
        }
    }
}

/// Statistics for the event processor
#[derive(Debug, Clone)]
pub struct ProcessorStatistics {
    pub total_events_processed: usize,
    pub correlations_found: usize,
    pub incidents_triggered: usize,
    pub active_incidents: usize,
}
