use crate::security::advanced::ml_security::*;
use crate::security::advanced::ml_security::baselines::*;
use crate::security::advanced::ml_security::data_pipeline::*;
use chrono::Utc;
use std::collections::HashMap;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_baseline_metric_update() {
        // Test Welford's online variance algorithm
        let mut metric = BaselineMetric::new(10.0);
        assert_eq!(metric.count, 1);
        assert_eq!(metric.mean, 10.0);
        assert_eq!(metric.m2, 0.0);

        metric.update(20.0);
        // mean = (10 + 20) / 2 = 15
        // delta = 20 - 10 = 10
        // mean += 10 / 2 = 15
        // delta2 = 20 - 15 = 5
        // m2 += 10 * 5 = 50
        assert_eq!(metric.count, 2);
        assert_eq!(metric.mean, 15.0);
        assert_eq!(metric.m2, 50.0);
        
        // Variance = 50 / (2-1) = 50
        assert_eq!(metric.variance(), 50.0);
        // Std dev = sqrt(50) ≈ 7.07
        assert!((metric.std_dev() - 7.0710678).abs() < 0.0001);

        metric.update(30.0);
        // mean = (15*2 + 30) / 3 = 20
        // delta = 30 - 15 = 15
        // mean += 15 / 3 = 20
        // delta2 = 30 - 20 = 10
        // m2 += 50 + (15 * 10) = 200
        assert_eq!(metric.count, 3);
        assert_eq!(metric.mean, 20.0);
        assert_eq!(metric.m2, 200.0);
        
        // Variance = 200 / (3-1) = 100
        assert_eq!(metric.variance(), 100.0);
        assert_eq!(metric.std_dev(), 10.0);
    }

    #[test]
    fn test_peer_profile_z_score() {
        let mut profile = PeerProfile::new("test_peer".to_string());
        
        // Add some "normal" behavior
        for i in 1..=5 {
            let mut features = HashMap::new();
            features.insert("request_count".to_string(), 100.0 + (i as f64 * 10.0));
            
            let data = BehavioralDataPoint {
                peer_id: "test_peer".to_string(),
                timestamp: Utc::now(),
                features,
                context: HashMap::new(),
            };
            profile.update(&data);
        }

        // Mean should be around 130 (110, 120, 130, 140, 150)
        // Values: 110, 120, 130, 140, 150
        // Sum: 650, Count: 5, Mean: 130
        // (110-130)^2 = 400
        // (120-130)^2 = 100
        // (130-130)^2 = 0
        // (140-130)^2 = 100
        // (150-130)^2 = 400
        // Sum squares: 1000
        // Variance: 1000 / 4 = 250
        // Std Dev: sqrt(250) ≈ 15.81

        let z_score = profile.get_z_score("request_count", 200.0).unwrap();
        // (200 - 130) / 15.81 ≈ 4.42
        assert!(z_score > 4.0);
        
        let normal_z = profile.get_z_score("request_count", 135.0).unwrap();
        // (135 - 130) / 15.81 ≈ 0.31
        assert!(normal_z < 1.0);
    }

    #[test]
    fn test_data_pipeline_extraction() {
        let config = FeatureConfig::default();
        let extractor = FeatureExtractor::new(config);
        
        let event = SecurityEventData {
            timestamp: Utc::now(),
            event_type: "login_failure".to_string(),
            success: false,
            data_size: None,
            session_duration: Some(10.0),
            resource_id: Some("server_alpha".to_string()),
            data: serde_json::json!({
                "command": "sudo rm -rf /"
            }),
        };

        let fv = extractor.extract(&event);
        assert_eq!(fv.failed_attempts, 1.0);
        assert_eq!(fv.connection_duration_avg, 10.0);
        // Command line entropy (simplified in code: len / 100)
        assert!(fv.command_line_entropy > 0.1);
    }

    #[test]
    fn test_feature_vector_to_array() {
         let fv = SecurityFeatureVector {
            login_frequency: 1.0,
            failed_attempts: 2.0,
            resource_consumption: 3.0,
            network_packets_in: 4.0,
            network_packets_out: 5.0,
            port_scan_ratio: 6.0,
            connection_duration_avg: 7.0,
            unique_peers: 8.0,
            protocol_anomaly_score: 9.0,
            unusual_timing_score: 10.0,
            sensitive_file_access: 11.0,
            process_ancestry_depth: 12.0,
            privilege_escalation_score: 13.0,
            data_exfiltration_score: 14.0,
            lateral_movement_score: 15.0,
            external_threat_intel_score: 16.0,
            geolocation_anomaly: 17.0,
            user_agent_strangeness: 18.0,
            command_line_entropy: 19.0,
            dns_query_volume: 20.0,
        };

        let arr = fv.to_array();
        assert_eq!(arr.len(), 20);
        assert_eq!(arr[0], 1.0);
        assert_eq!(arr[19], 20.0);
    }

    #[test]
    fn test_normalization() {
        let raw = [0.5, 1.5, -1.0, 0.8, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0];
        let normalized = DataPipeline::normalize(&raw);
        
        assert_eq!(normalized[0], 0.5);
        assert_eq!(normalized[1], 1.0); // Capped at 1.0
        assert_eq!(normalized[2], 0.0); // Floored at 0.0
        assert_eq!(normalized[3], 0.8);
    }

    #[tokio::test]
    async fn test_ml_security_engine_initialization() {
        let config = MLSecurityConfig::default();
        let engine = MLSecurityEngine::new(config);
        assert!(engine.is_ok());
        
        let mut engine = engine.unwrap();
        let init_result = engine.initialize_models().await;
        assert!(init_result.is_ok());
    }

    #[tokio::test]
    #[cfg(feature = "ml-classical")]
    async fn test_ml_security_engine_inference() {
        let config = MLSecurityConfig::default();
        let mut engine = MLSecurityEngine::new(config).unwrap();
        engine.initialize_models().await.unwrap();
        
        let mut features = HashMap::new();
        features.insert("failed_attempts".to_string(), serde_json::Value::from(10.0));
        
        let data = MLInputData {
            id: uuid::Uuid::new_v4(),
            source: "test_peer".to_string(),
            data_type: "auth_event".to_string(),
            features,
            timestamp: Utc::now(),
        };
        
        let results = engine.run_inference(&data).await.unwrap();
        // Since models are initialized with mock backends, we should get some results
        assert!(!results.is_empty());
        // At least one model (ThreatClassifier) should detect high risk
        assert!(results.iter().any(|r| r.risk_score > 0.0));
    }
}
