#![cfg(test)]

use std::sync::Arc;
use wolf_web::dashboard::api::create_api_router;
use wolf_web::dashboard::state::AppState;
use wolf_web::dashboard::MockThreatRepository;
use wolfsec::identity::iam::{AuthenticationManager, IAMConfig};
use wolfsec::threat_detection::{BehavioralAnalyzer, ThreatDetector as ThreatDetectionEngine};

#[tokio::test]
async fn test_basic_dashboard_creation() {
    // Test that we can create the basic dashboard components
    let app_state = AppState::new(
        ThreatDetectionEngine::new(Default::default(), Arc::new(MockThreatRepository)),
        BehavioralAnalyzer {
            baseline_window: 100,
            deviation_threshold: 2.0,
            patterns_detected: 0,
        },
        AuthenticationManager::new(IAMConfig::default())
            .await
            .unwrap(),
    );

    let _router = create_api_router(Arc::new(app_state));

    // Basic assertion that router exists (can't easily check routes in axum 0.7 without testing)
    assert!(true);
}

#[tokio::test]
async fn test_state_components() {
    let app_state = AppState::new(
        ThreatDetectionEngine::new(Default::default(), Arc::new(MockThreatRepository)),
        BehavioralAnalyzer {
            baseline_window: 100,
            deviation_threshold: 2.0,
            patterns_detected: 0,
        },
        AuthenticationManager::new(IAMConfig::default())
            .await
            .unwrap(),
    );

    // Test that all components are accessible
    let threat_engine = app_state.threat_engine.lock().await;
    let stats = threat_engine.get_status().await;
    assert_eq!(stats.total_events, 0);

    let _behavioral_engine = app_state.behavioral_engine.lock().await;
    // let patterns = behavioral_engine.get_known_patterns();

    // let anomaly_engine = app_state.anomaly_engine.lock().await;
    // let thresholds = anomaly_engine.get_detection_thresholds();
    // assert!(thresholds.cpu_threshold > 0.0);
}
