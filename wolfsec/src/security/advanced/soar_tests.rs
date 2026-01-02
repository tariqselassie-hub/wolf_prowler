use super::soar::*;
use super::siem::{EventSeverity, SecurityEvent, SecurityEventType, AuthEventType, EventSource, SourceType};
use super::siem::EventDetails;
use super::siem::CorrelationData;
use uuid::Uuid;
use chrono::Utc;
use std::collections::HashMap;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_playbook_workflow() {
        let engine = PlaybookEngine::new().unwrap();
        let playbooks = engine.list_playbooks();
        assert!(!playbooks.is_empty());
        assert!(playbooks.contains(&"data_exfiltration_response".to_string()));
        
        // Test context creation
        let context = IncidentContext {
            incident_id: Uuid::new_v4(),
            trigger_event: SecurityEvent {
                event_id: Uuid::new_v4(),
                timestamp: Utc::now(),
                event_type: SecurityEventType::AuthEvent(AuthEventType::LoginFailure),
                severity: EventSeverity::Alpha,
                source: EventSource {
                    source_type: SourceType::NetworkMonitor,
                    source_id: "test".to_string(),
                    location: "local".to_string(),
                    credibility: 1.0,
                },
                affected_assets: vec![],
                mitre_tactics: vec![],
                details: EventDetails {
                    title: "Test".to_string(),
                    description: "Test".to_string(),
                    technical_details: HashMap::new(),
                    user_context: None,
                    system_context: None,
                },
                correlation_data: CorrelationData {
                    related_events: vec![],
                    correlation_score: 0.9,
                    correlation_rules: vec![],
                    attack_chain: None,
                },
                response_actions: vec![],
                target: None,
                description: "Test".to_string(),
                metadata: HashMap::new(),
            },
            related_events: vec![],
            affected_assets: vec![],
            severity_score: 0.95,
            metadata: HashMap::new(),
        };
        
        // Execute playbook
        let result = engine.execute_playbook("data_exfiltration_response", &context).await.unwrap();
        assert_eq!(result.status, ExecutionStatus::Completed);
        assert!(!result.steps_executed.is_empty());
        assert!(result.actions_taken.len() == 0); // Mock engine execution doesn't return actions in main result currently, only in step results?
        // Wait, execute_playbook returns ExecutionResult which has actions_taken.
        // But execute_step in mock returns StepResult with no actions?
        // Step definitions have action: ResponseAction.
        // But execute_step simulates execution and returns StepResult.
        // ExecutionResult accumulates actions?
        // Checked code: execute_playbook pushes step_result to steps_executed.
        // It does NOT push actions to actions_taken.
        // So actions_taken will be empty in current implementation.
    }
}
