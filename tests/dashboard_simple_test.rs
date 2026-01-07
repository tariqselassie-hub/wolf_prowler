#![cfg(test)]

use std::sync::Arc;
use wolf_prowler::core::threat_detection::{
    AnomalyDetector, BehavioralAnalyzer, ThreatDetectionEngine,
};
use wolf_prowler::dashboard::api::create_api_router;
use wolf_prowler::dashboard::state::AppState;
use wolf_prowler::security::advanced::iam::{AuthenticationManager, IAMConfig};

#[tokio::test]
async fn test_basic_dashboard_creation() {
    // Test that we can create the basic dashboard components
    let app_state = AppState::new(
        ThreatDetectionEngine::new(Default::default()),
        BehavioralAnalyzer::new(),
        AnomalyDetector::new(),
        AuthenticationManager::new(IAMConfig::default())
            .await
            .unwrap(),
    );

    let router = create_api_router(Arc::new(app_state));

    // Basic assertion that router was created
    assert!(
        router.routes().len() > 0,
        "Dashboard router should have routes"
    );
}

#[tokio::test]
async fn test_state_components() {
    let app_state = AppState::new(
        ThreatDetectionEngine::new(Default::default()),
        BehavioralAnalyzer::new(),
        AnomalyDetector::new(),
        AuthenticationManager::new(IAMConfig::default())
            .await
            .unwrap(),
    );

    // Test that all components are accessible
    let threat_engine = app_state.threat_engine.lock().await;
    let stats = threat_engine.get_detection_stats();
    assert_eq!(stats.total_detections, 0);

    let behavioral_engine = app_state.behavioral_engine.lock().await;
    let patterns = behavioral_engine.get_known_patterns();

    let anomaly_engine = app_state.anomaly_engine.lock().await;
    let thresholds = anomaly_engine.get_detection_thresholds();
    assert!(thresholds.cpu_threshold > 0.0);
}
