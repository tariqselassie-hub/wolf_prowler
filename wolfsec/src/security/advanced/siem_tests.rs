use super::siem::*;
use super::siem::WolfCorrelationEngine;
use super::siem::event_storage::EventStorage;
use uuid::Uuid;
use chrono::Utc;
use std::collections::HashMap;

#[cfg(test)]
mod tests {
    use super::*;

    // Helper to create a dummy event
    fn create_dummy_event(severity: EventSeverity) -> SecurityEvent {
        SecurityEvent {
            event_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type: SecurityEventType::AuthEvent(AuthEventType::LoginFailure),
            severity,
            source: EventSource {
                source_type: SourceType::NetworkMonitor,
                source_id: "test_monitor".to_string(),
                location: "internal".to_string(),
                credibility: 1.0,
            },
            affected_assets: vec![
                Asset {
                    asset_id: "server-1".to_string(),
                    asset_type: AssetType::Beta,
                    owner: Some("admin".to_string()),
                    location: "dc-1".to_string(),
                    criticality: AssetCriticality::High,
                    current_status: AssetStatus::Operational,
                }
            ],
            details: EventDetails {
                title: "Login Failure".to_string(),
                description: "Failed login attempt".to_string(),
                technical_details: HashMap::new(),
                user_context: None,
                system_context: None,
            },
            mitre_tactics: vec![MitreTactic::InitialAccess],
            correlation_data: CorrelationData {
                related_events: vec![],
                correlation_score: 0.0,
                correlation_rules: vec![],
                attack_chain: None,
            },
            response_actions: vec![],
            target: Some("192.168.1.100".to_string()),
            description: "Failed login".to_string(),
            metadata: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn test_event_storage_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_str().unwrap().to_string();
        
        let mut storage = EventStorage::new(path.clone(), 1).unwrap();
        
        // Ensure directory is created
        assert!(std::path::Path::new(&path).exists());
        
        let event = create_dummy_event(EventSeverity::Beta);
        storage.store_event(event.clone()).await.unwrap();
        
        // Create new storage instance to verify reload
        let mut storage2 = EventStorage::new(path.clone(), 1).unwrap();
        
        // load_events_for_date loads today's file
        let loaded = storage2.load_events_for_date(Utc::now()).await.unwrap();
        
        assert!(!loaded.is_empty());
        assert_eq!(loaded.iter().find(|e| e.event_id == event.event_id).is_some(), true);
    }

    #[tokio::test]
    async fn test_correlation_engine_relationship() {
        let mut engine = WolfCorrelationEngine::new().unwrap();
        
        let mut event1 = create_dummy_event(EventSeverity::Scout);
        event1.timestamp = Utc::now();
        event1.source.source_id = "192.168.1.10".to_string();
        
        // Correlate first event (stores it in buffer)
        engine.correlate_event(&event1).await.unwrap();
        
        let mut event2 = create_dummy_event(EventSeverity::Hunter);
        event2.event_type = SecurityEventType::NetworkEvent(NetworkEventType::PortScan);
        event2.timestamp = Utc::now();
        event2.source.source_id = "192.168.1.10".to_string(); // Same source
        
        let result = engine.correlate_event(&event2).await.unwrap();
        
        // Should find correlation due to same source ID in short window
        assert!(!result.correlated_events.is_empty());
        assert!(result.correlation_score > 0.0);
    }
}
