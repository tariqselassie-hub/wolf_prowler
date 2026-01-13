use super::{ExecutionResult, ExecutionStatus, IncidentContext, PlaybookEngine};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, warn};
use uuid::Uuid;

/// Incident orchestrator coordinates automated responses
pub struct IncidentOrchestrator {
    playbook_engine: PlaybookEngine,
    active_incidents: HashMap<Uuid, IncidentState>,
}

/// State of an active incident
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentState {
    pub incident_id: Uuid,
    pub context: IncidentContext,
    pub selected_playbook: Option<String>,
    pub execution_result: Option<ExecutionResult>,
    pub status: IncidentStatus,
}

/// Incident status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IncidentStatus {
    New,
    Analyzing,
    ResponseInProgress,
    Resolved,
    Failed,
}

impl IncidentOrchestrator {
    pub fn new() -> Result<Self> {
        Ok(Self {
            playbook_engine: PlaybookEngine::new()?,
            active_incidents: HashMap::new(),
        })
    }

    /// Handle a new incident
    pub async fn handle_incident(&mut self, context: IncidentContext) -> Result<ExecutionResult> {
        let incident_id = context.incident_id;

        info!("🚨 Handling new incident: {}", incident_id);

        // Create incident state
        let mut state = IncidentState {
            incident_id,
            context: context.clone(),
            selected_playbook: None,
            execution_result: None,
            status: IncidentStatus::Analyzing,
        };

        // Select appropriate playbook
        let playbook_id = self.select_playbook_for_incident(&context)?;
        state.selected_playbook = Some(playbook_id.clone());
        state.status = IncidentStatus::ResponseInProgress;

        info!(
            "📋 Selected playbook: {} for incident {}",
            playbook_id, incident_id
        );

        // Execute playbook
        let result = self
            .playbook_engine
            .execute_playbook(&playbook_id, &context)
            .await?;

        // Update incident state
        state.status = match result.status {
            ExecutionStatus::Completed => IncidentStatus::Resolved,
            ExecutionStatus::Failed => IncidentStatus::Failed,
            _ => IncidentStatus::ResponseInProgress,
        };
        state.execution_result = Some(result.clone());

        // Store incident state
        self.active_incidents.insert(incident_id, state);

        info!(
            "✅ Incident {} handled: {} steps executed",
            incident_id,
            result.steps_executed.len()
        );

        Ok(result)
    }

    /// Select appropriate playbook for an incident
    fn select_playbook_for_incident(&self, context: &IncidentContext) -> Result<String> {
        // Use playbook library's selection logic
        let library = &self.playbook_engine.library;

        if let Some(playbook) = library.select_playbook(context) {
            Ok(playbook.id.clone())
        } else {
            // Default to brute force response if no specific match
            warn!(
                "⚠️ No specific playbook matched for incident {}, using default",
                context.incident_id
            );
            Ok("brute_force_response".to_string())
        }
    }

    /// Get incident status
    pub fn get_incident_status(&self, incident_id: &Uuid) -> Option<&IncidentState> {
        self.active_incidents.get(incident_id)
    }

    /// List all active incidents
    pub fn list_active_incidents(&self) -> Vec<&IncidentState> {
        self.active_incidents
            .values()
            .filter(|state| {
                state.status == IncidentStatus::ResponseInProgress
                    || state.status == IncidentStatus::Analyzing
            })
            .collect()
    }

    /// Get orchestrator statistics
    pub fn get_statistics(&self) -> OrchestratorStatistics {
        let total_incidents = self.active_incidents.len();
        let resolved = self
            .active_incidents
            .values()
            .filter(|s| s.status == IncidentStatus::Resolved)
            .count();
        let failed = self
            .active_incidents
            .values()
            .filter(|s| s.status == IncidentStatus::Failed)
            .count();
        let in_progress = self
            .active_incidents
            .values()
            .filter(|s| s.status == IncidentStatus::ResponseInProgress)
            .count();

        OrchestratorStatistics {
            total_incidents,
            resolved_incidents: resolved,
            failed_incidents: failed,
            in_progress_incidents: in_progress,
        }
    }
}

/// Orchestrator statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrchestratorStatistics {
    pub total_incidents: usize,
    pub resolved_incidents: usize,
    pub failed_incidents: usize,
    pub in_progress_incidents: usize,
}
