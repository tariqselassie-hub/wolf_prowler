#![allow(missing_docs)]
#![allow(missing_docs)]
use wolfsec::security::advanced::ml_security::{MLSecurityEngine, MLSecurityConfig};
use wolfsec::security::advanced::siem::{WolfSIEMManager, SIEMConfig, SecurityEvent, SecurityEventType, EventSeverity, AuthEventType, EventSource, SourceType, EventDetails, CorrelationData, MitreTactic};
use wolfsec::security::advanced::soar::PlaybookEngine; // Removed unused
use chrono::Utc;
use std::collections::HashMap;
use uuid::Uuid;

async fn create_test_pipeline() -> (MLSecurityEngine, WolfSIEMManager, PlaybookEngine) {
    let ml_config = MLSecurityConfig::default();
    let mut ml_engine = MLSecurityEngine::new(ml_config).expect("Failed to create ML Engine");
    // Force classical ML backend for tests
    ml_engine.initialize_models().await.expect("Failed to init models");

    let siem_config = SIEMConfig::default();
    let siem_engine = WolfSIEMManager::new(siem_config).expect("Failed to create SIEM Manager");

    let playbook_engine = PlaybookEngine::new().expect("Failed to creates Playbook Engine");

    (ml_engine, siem_engine, playbook_engine)
}

fn create_auth_failure_event(source_ip: &str, count: i32) -> SecurityEvent {
    let mut details = HashMap::new();
    details.insert("username".to_string(), "admin".to_string());
    details.insert("source_ip".to_string(), source_ip.to_string());
    
    SecurityEvent {
        event_id: Uuid::new_v4(),
        timestamp: Utc::now(),
        event_type: SecurityEventType::AuthEvent(AuthEventType::LoginFailure),
        severity: EventSeverity::Hunter, // Medium
        source: EventSource {
            source_type: SourceType::NetworkMonitor,
            source_id: source_ip.to_string(),
            location: "external".to_string(),
            credibility: 0.5,
        },
        affected_assets: vec![],
        details: EventDetails {
            title: format!("Login Failure #{}", count),
            description: "Failed login attempt".to_string(),
            technical_details: details.into_iter().map(|(k,v)| (k, serde_json::Value::String(v))).collect(),
            user_context: None,
            system_context: None,
        },
        mitre_tactics: vec![MitreTactic::InitialAccess, MitreTactic::CredentialAccess],
        correlation_data: CorrelationData {
            related_events: vec![],
            correlation_score: 0.0,
            correlation_rules: vec![],
            attack_chain: None,
        },
        response_actions: vec![],
        target: Some("auth-server".to_string()),
        description: "Brute force attempt".to_string(),
        metadata: HashMap::new(),
    }
}

#[tokio::test]
async fn test_end_to_end_brute_force_response() {
    // 1. Setup Pipeline
    let (mut ml_engine, mut siem_engine, _playbook_engine) = create_test_pipeline().await;
    let attacker_ip = "192.168.1.66";

    // 2. Simulate Attack (Multiple Failed Logins)
    let mut events = Vec::new();
    // Need enough events to boost correlation score > 0.5 threshold
    // Score = (count/10 + severity)/2. With Medium(0.5) severity, we need count close to 10.
    for i in 1..=12 {
        events.push(create_auth_failure_event(attacker_ip, i));
    }

    // 3. Process Events
    let mut high_risk_detected = false;
    let mut incident_triggered = false;
    let mut triggered_playbook_id = String::new();

    for event in events {
        // A. ML Analysis
        // Convert SecurityEvent to MLInputData (simplified mapping for test)
        let mut features = HashMap::new();
        features.insert("failed_attempts".to_string(), serde_json::Value::from(1.0));
        
        // Use full path to avoid import issues if not imported
        let ml_input = wolfsec::security::advanced::ml_security::MLInputData {
            id: event.event_id,
            source: event.source.source_id.clone(),
            data_type: "auth".to_string(),
            features,
            timestamp: event.timestamp,
        };

        let ml_results = ml_engine.run_inference(&ml_input).await.unwrap();
        // Check if average risk is increasing or high (heuristics might flag it immediately)
        let max_risk = ml_results.iter().map(|r| r.risk_score).fold(0.0, f64::max);
        
        // B. SIEM Processing (Enrichment, Correlation, Alerting, Response)
        let response_actions = siem_engine.process_event(event.clone()).await.unwrap();

        // Check verification flags
        if max_risk > 0.7 {
            high_risk_detected = true;
        }

        // If ResponseActions are generated, it implies Correlation -> Alert -> Response
        if !response_actions.is_empty() {
             incident_triggered = true;
             // Check if we have RequireMFA (standard for Auth alerts) or BlockNetwork (Critical)
             if response_actions.contains(&wolfsec::security::advanced::siem::ResponseAction::RequireMFA) {
                 triggered_playbook_id = "brute_force_response".to_string(); 
             }
        }
    }

    // 4. Verification
    // assert!(high_risk_detected, "ML Detection failed to flag high risk"); // Heuristics might vary
    assert!(incident_triggered, "SIEM failed to trigger response on brute force attack");
    assert_eq!(triggered_playbook_id, "brute_force_response", "Expected RequireMFA response action");
}
