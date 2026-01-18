#![allow(missing_docs)]
use chrono::Utc;
use std::collections::HashMap;
use std::time::Instant;
use uuid::Uuid;
use wolfsec::observability::siem::{
    Asset, AssetCriticality, AssetStatus, AssetType, AuthEventType, CorrelationData, EventDetails,
    EventSeverity, EventSource, MitreTactic, NetworkEventType, SIEMConfig, SecurityEvent,
    SecurityEventType, SourceType, SystemContext, WolfSIEMManager,
};
use wolfsec::protection::ml_security::{MLInputData, MLSecurityConfig, MLSecurityEngine}; // EventSeverity

async fn create_test_engines() -> (MLSecurityEngine, WolfSIEMManager) {
    let ml_config = MLSecurityConfig::default();
    let mut ml_engine = MLSecurityEngine::new(ml_config).expect("Failed to create ML Engine");
    ml_engine
        .initialize_models()
        .await
        .expect("Failed to init models");

    let siem_config = SIEMConfig::default();
    let siem_engine = WolfSIEMManager::new(siem_config).expect("Failed to create SIEM Manager"); // Removed await

    (ml_engine, siem_engine)
}

fn generate_dummy_events(count: usize) -> Vec<SecurityEvent> {
    let mut events = Vec::with_capacity(count);
    for i in 0..count {
        let event = SecurityEvent {
            event_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type: if i % 2 == 0 {
                SecurityEventType::AuthEvent(AuthEventType::LoginFailure)
            } else {
                SecurityEventType::NetworkEvent(NetworkEventType::PortScan)
            },
            severity: EventSeverity::Scout, // Low (Scout)
            source: EventSource {
                source_type: SourceType::NetworkMonitor,
                source_id: format!("192.168.1.{}", i % 255),
                location: "internal".to_string(),
                credibility: 1.0,
            },
            affected_assets: vec![],
            mitre_tactics: vec![MitreTactic::Discovery],
            details: EventDetails {
                title: "Stress Test Event".to_string(),
                description: "Automated benchmark event".to_string(),
                technical_details: HashMap::new(),
                user_context: None,
                system_context: None,
            },
            correlation_data: CorrelationData {
                related_events: vec![],
                correlation_score: 0.0,
                correlation_rules: vec![],
                attack_chain: None,
            },
            response_actions: vec![],
            target: None,
            description: "Benchmark".to_string(),
            metadata: HashMap::new(),
        };
        events.push(event);
    }
    events
}

#[tokio::test]
async fn test_ml_siem_performance_benchmark() {
    let (mut ml_engine, mut siem_engine) = create_test_engines().await;

    let event_count = 1000; // Start with 1000 for standard test suite to avoid slow runs
    println!("Generating {} events...", event_count);
    let events = generate_dummy_events(event_count);

    // --- ML Inference Benchmark ---
    println!("Starting ML Inference Benchmark...");
    let start_ml = Instant::now();
    for event in &events {
        let mut features = HashMap::new();
        features.insert("metric_val".to_string(), serde_json::Value::from(10.0));
        let input = MLInputData {
            id: event.event_id,
            source: event.source.source_id.clone(),
            data_type: "benchmark".to_string(),
            features,
            timestamp: event.timestamp,
        };
        // We unwrap here because errors in benchmark = failure
        let _ = ml_engine.run_inference(&input).await.unwrap();
    }
    let duration_ml = start_ml.elapsed();
    let ml_throughput = event_count as f64 / duration_ml.as_secs_f64();
    println!(
        "ML Engine Processed {} events in {:.2?}. Throughput: {:.2} events/sec",
        event_count, duration_ml, ml_throughput
    );

    // --- SIEM Correlation Benchmark ---
    println!("Starting SIEM Correlation Benchmark...");
    let start_siem = Instant::now();
    for event in &events {
        let _ = siem_engine.process_event(event.clone()).await.unwrap();
    }
    let duration_siem = start_siem.elapsed();
    let siem_throughput = event_count as f64 / duration_siem.as_secs_f64();
    println!(
        "SIEM Manager Processed {} events in {:.2?}. Throughput: {:.2} events/sec",
        event_count, duration_siem, siem_throughput
    );

    // Assert minimum performance standards
    // Note: Adjust thresholds based on actual environment capabilities (CI vs local)
    // Checking > 100 events/sec is a safe baseline for dev environments
    assert!(
        ml_throughput > 100.0,
        "ML Engine throughput too low: {:.2} < 100.0",
        ml_throughput
    );
    assert!(
        siem_throughput > 100.0,
        "SIEM Engine throughput too low: {:.2} < 100.0",
        siem_throughput
    );
}
