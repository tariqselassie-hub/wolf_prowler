//! SOAR Management API Endpoints
//!
//! This module provides API endpoints for managing security orchestration,
//! automation, and response (SOAR) actions.

use axum::extract::State;
use axum::{
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::dashboard::state::AppState;
use wolfsec::observability::siem::ResponseAction;

/// Response action request
#[derive(Debug, Serialize, Deserialize)]
pub struct TriggerActionRequest {
    /// The action to trigger
    pub action: String,
    /// Optional target (e.g., peer ID, IP address)
    pub target: Option<String>,
    /// Optional description/reason for the action
    pub reason: Option<String>,
}

/// Response action status
#[derive(Debug, Serialize, Deserialize)]
pub struct ActionStatusResponse {
    /// Action ID
    pub action_id: String,
    /// Action name
    pub action: String,
    /// Target
    pub target: Option<String>,
    /// Timestamp
    pub timestamp: String,
    /// Status (Pending, Completed, Failed)
    pub status: String,
    /// Message
    pub message: Option<String>,
}

/// List of available actions response
#[derive(Debug, Serialize, Deserialize)]
pub struct AvailableActionsResponse {
    /// List of available orchestration actions
    pub actions: Vec<AvailableAction>,
}

/// A specific orchestration action that can be triggered
#[derive(Debug, Serialize, Deserialize)]
pub struct AvailableAction {
    /// Unique identifier for the action
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Detailed description of what the action does
    pub description: String,
    /// Whether the action requires a target identifier
    pub requires_target: bool,
}

/// Create SOAR management router
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/actions", get(list_available_actions))
        .route("/trigger", post(trigger_action))
        .route("/history", get(get_action_history))
        .with_state(state)
}

/// List all available SOAR actions
async fn list_available_actions() -> Json<AvailableActionsResponse> {
    let actions = vec![
        AvailableAction {
            id: "BlockNetwork".to_string(),
            name: "Block Network Access".to_string(),
            description: "Block all network communication for a specific peer or IP.".to_string(),
            requires_target: true,
        },
        AvailableAction {
            id: "IsolateSystem".to_string(),
            name: "Isolate System".to_string(),
            description: "Disconnect a peer from the swarm and prevent reconnection.".to_string(),
            requires_target: true,
        },
        AvailableAction {
            id: "RequireMFA".to_string(),
            name: "Require MFA".to_string(),
            description: "Enforce multi-factor authentication for the next session.".to_string(),
            requires_target: false,
        },
        AvailableAction {
            id: "RevokeAccess".to_string(),
            name: "Revoke Access".to_string(),
            description: "Revoke all active sessions and rotate security keys.".to_string(),
            requires_target: false,
        },
        AvailableAction {
            id: "QuarantineSystem".to_string(),
            name: "Quarantine System".to_string(),
            description: "Put the system into a restricted operational mode.".to_string(),
            requires_target: false,
        },
        AvailableAction {
            id: "IncreaseMonitoring".to_string(),
            name: "Increase Monitoring".to_string(),
            description: "Lower alert thresholds and increase logging verbosity.".to_string(),
            requires_target: false,
        },
    ];

    Json(AvailableActionsResponse { actions })
}

/// Trigger a manual security action
async fn trigger_action(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<TriggerActionRequest>,
) -> Json<ActionStatusResponse> {
    state.increment_request_count().await;

    let action_id = Uuid::new_v4().to_string();
    let timestamp = chrono::Utc::now().to_rfc3339();

    // Map string to ResponseAction
    let action_enum = match payload.action.as_str() {
        "BlockNetwork" => Some(ResponseAction::BlockNetwork),
        "IsolateSystem" => Some(ResponseAction::IsolateSystem),
        "RequireMFA" => Some(ResponseAction::RequireMFA),
        "IncreaseMonitoring" => Some(ResponseAction::IncreaseMonitoring),
        "QuarantineSystem" => Some(ResponseAction::QuarantineSystem),
        "RevokeAccess" => Some(ResponseAction::RevokeAccess),
        _ => None,
    };

    let mut status = "Failed".to_string();
    let mut message = Some("Unknown action".to_string());

    if let Some(action) = action_enum {
        if let Some(wolf_security_arc) = state.get_wolf_security() {
            let wolf_security = wolf_security_arc.read().await;

            // Construct a mock event for the SOAR engine to process
            let event = wolfsec::observability::siem::SecurityEvent {
                event_id: Uuid::new_v4(),
                timestamp: chrono::Utc::now(),
                severity: wolfsec::observability::siem::EventSeverity::Beta, // High priority manual action
                event_type: wolfsec::observability::siem::SecurityEventType::SystemEvent(
                    wolfsec::observability::siem::SystemEventType::ConfigurationChange,
                ),
                source: wolfsec::observability::siem::EventSource {
                    source_type: wolfsec::observability::siem::SourceType::UserReport,
                    source_id: "DashboardAdmin".to_string(),
                    location: "WebUI".to_string(),
                    credibility: 1.0,
                },
                affected_assets: vec![],
                details: wolfsec::observability::siem::EventDetails {
                    title: format!("Manual SOAR Action: {}", payload.action),
                    description: payload
                        .reason
                        .clone()
                        .unwrap_or_else(|| "Manual trigger from dashboard".to_string()),
                    technical_details: std::collections::HashMap::new(),
                    user_context: None,
                    system_context: None,
                },
                mitre_tactics: vec![],
                correlation_data: wolfsec::observability::siem::CorrelationData {
                    related_events: vec![],
                    correlation_score: 1.0,
                    correlation_rules: vec![],
                    attack_chain: None,
                },
                response_actions: vec![action.clone()],
                target: payload.target.clone(),
                description: format!("Manual trigger of {action:?}"),
                metadata: std::collections::HashMap::new(),
            };

            // Directly execute response actions via WolfSecurity
            match wolf_security
                .execute_response_actions(vec![action], &event)
                .await
            {
                Ok(()) => {
                    status = "Completed".to_string();
                    message = Some(format!("Successfully triggered {}", payload.action));
                }
                Err(e) => {
                    status = "Failed".to_string();
                    message = Some(format!("Execution failed: {e}"));
                }
            }
        } else {
            message = Some("WolfSecurity engine not available".to_string());
        }
    }

    Json(ActionStatusResponse {
        action_id,
        action: payload.action,
        target: payload.target,
        timestamp,
        status,
        message,
    })
}

/// Get history of triggered actions
async fn get_action_history() -> Json<Vec<ActionStatusResponse>> {
    // This would typically come from a database (WolfDb via WolfSecurity)
    // For now, we return an empty list or mock history
    let history = vec![ActionStatusResponse {
        action_id: Uuid::new_v4().to_string(),
        action: "BlockNetwork".to_string(),
        target: Some("peer-abc-123".to_string()),
        timestamp: chrono::Utc::now().to_rfc3339(),
        status: "Completed".to_string(),
        message: Some("Automatically triggered by Scent detection".to_string()),
    }];

    Json(history)
}
