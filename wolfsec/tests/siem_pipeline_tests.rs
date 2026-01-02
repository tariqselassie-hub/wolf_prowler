use chrono::Utc;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use wolfsec::security::advanced::siem::{
    correlation_engine::WolfCorrelationEngine, event_processor::SIEMEventProcessor,
    event_storage::EventStorage, AuthEventType, CorrelationData, EventDetails, EventSeverity,
    EventSource, NetworkEventType, SIEMConfig, SecurityEvent, SecurityEventType, SourceType,
    SystemContext,
};
use wolfsec::security::advanced::soar::orchestrator::IncidentOrchestrator;

#[tokio::test]
async fn test_siem_event_pipeline_processing() {
    // 1. Initialize components
    let temp_dir = std::env::temp_dir().join("wolf_siem_test");
    // Ensure temp dir is clean or at least exists
    let _ = std::fs::create_dir_all(&temp_dir);

    let event_storage = Arc::new(RwLock::new(
        EventStorage::new(temp_dir.to_string_lossy().into_owned(), 30)
            .expect("Failed to create storage"),
    ));

    let correlation_engine = Arc::new(RwLock::new(
        WolfCorrelationEngine::new().expect("Failed to create engine"),
    ));
    let incident_orchestrator = Arc::new(RwLock::new(
        IncidentOrchestrator::new().expect("Failed to create orchestrator"),
    ));
    let config = SIEMConfig::default();

    // 2. Create Processor
    let processor = SIEMEventProcessor::new(
        event_storage.clone(),
        correlation_engine.clone(),
        incident_orchestrator.clone(),
        config,
    );

    // 3. Create a test event
    let event = SecurityEvent {
        event_id: Uuid::new_v4(),
        timestamp: Utc::now(),
        event_type: SecurityEventType::NetworkEvent(NetworkEventType::UnusualTraffic),
        severity: EventSeverity::Beta,
        source: EventSource {
            source_type: SourceType::SystemLogs,
            source_id: "integration_test".to_string(),
            location: "test_env".to_string(),
            credibility: 1.0,
        },
        description: "Test event for pipeline".to_string(),
        affected_assets: vec![],
        metadata: std::collections::HashMap::new(),
        details: EventDetails {
            title: "Test Event".to_string(),
            description: "Test event for pipeline".to_string(),
            technical_details: std::collections::HashMap::new(),
            user_context: None,
            system_context: Some(SystemContext {
                hostname: "test_host".to_string(),
                ip_address: "127.0.0.1".to_string(),
                process_id: None,
                process_name: None,
                command_line: None,
            }),
        },
        mitre_tactics: vec![],
        correlation_data: CorrelationData {
            related_events: vec![],
            correlation_score: 0.0,
            correlation_rules: vec![],
            attack_chain: None,
        },
        response_actions: vec![],
        target: None,
    };

    // 4. Process event
    let result = processor.process_event(event.clone()).await;
    assert!(
        result.is_ok(),
        "Event processing failed: {:?}",
        result.err()
    );

    // 5. Verify storage
    let stats = processor.get_statistics().await;
    assert_eq!(
        stats.total_events_processed, 1,
        "Should have processed 1 event"
    );

    // 6. Test batch processing
    let batch = vec![
        SecurityEvent {
            event_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type: SecurityEventType::AuthEvent(AuthEventType::LoginFailure),
            severity: EventSeverity::Scout,
            source: EventSource {
                source_type: SourceType::SystemLogs,
                source_id: "test_src".to_string(),
                location: "test_env".to_string(),
                credibility: 0.8,
            },
            description: "Failed login".to_string(),
            affected_assets: vec![],
            metadata: std::collections::HashMap::new(),
            details: EventDetails {
                title: "Login Failure".to_string(),
                description: "Failed login attempt".to_string(),
                technical_details: std::collections::HashMap::new(),
                user_context: None,
                system_context: None,
            },
            mitre_tactics: vec![],
            correlation_data: CorrelationData {
                related_events: vec![],
                correlation_score: 0.0,
                correlation_rules: vec![],
                attack_chain: None,
            },
            response_actions: vec![],
            target: None,
        },
        SecurityEvent {
            event_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type: SecurityEventType::AuthEvent(AuthEventType::PrivilegeEscalation),
            severity: EventSeverity::Hunter,
            source: EventSource {
                source_type: SourceType::SystemLogs,
                source_id: "test_src".to_string(),
                location: "test_env".to_string(),
                credibility: 0.9,
            },
            description: "Privilege violation".to_string(),
            affected_assets: vec![],
            metadata: std::collections::HashMap::new(),
            details: EventDetails {
                title: "PrivEsc".to_string(),
                description: "Privilege escalation attempt".to_string(),
                technical_details: std::collections::HashMap::new(),
                user_context: None,
                system_context: None,
            },
            mitre_tactics: vec![],
            correlation_data: CorrelationData {
                related_events: vec![],
                correlation_score: 0.0,
                correlation_rules: vec![],
                attack_chain: None,
            },
            response_actions: vec![],
            target: None,
        },
    ];

    let batch_result = processor.process_events_batch(batch).await;
    assert!(batch_result.is_ok());

    let final_stats = processor.get_statistics().await;
    assert_eq!(
        final_stats.total_events_processed, 3,
        "Total events should be 3"
    );
}
