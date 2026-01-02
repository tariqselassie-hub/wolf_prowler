// use ndarray::Array1; // Removed ndarray dependency
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Represents the raw features extracted from system and network events.
/// This corresponds to the 20-dimensional feature vector mentioned in the plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFeatureVector {
    pub login_frequency: f32,
    pub failed_attempts: f32,
    pub resource_consumption: f32,
    pub network_packets_in: f32,
    pub network_packets_out: f32,
    pub port_scan_ratio: f32,
    pub connection_duration_avg: f32,
    pub unique_peers: f32,
    pub protocol_anomaly_score: f32,
    pub unusual_timing_score: f32,
    pub sensitive_file_access: f32,
    pub process_ancestry_depth: f32,
    pub privilege_escalation_score: f32,
    pub data_exfiltration_score: f32,
    pub lateral_movement_score: f32,
    pub external_threat_intel_score: f32,
    pub geolocation_anomaly: f32,
    pub user_agent_strangeness: f32,
    pub command_line_entropy: f32,
    pub dns_query_volume: f32,
}

impl SecurityFeatureVector {
    /// Convert features to a fixed-size array for processing (Zero-allocation)
    pub fn to_array(&self) -> [f32; 20] {
        [
            self.login_frequency,
            self.failed_attempts,
            self.resource_consumption,
            self.network_packets_in,
            self.network_packets_out,
            self.port_scan_ratio,
            self.connection_duration_avg,
            self.unique_peers,
            self.protocol_anomaly_score,
            self.unusual_timing_score,
            self.sensitive_file_access,
            self.process_ancestry_depth,
            self.privilege_escalation_score,
            self.data_exfiltration_score,
            self.lateral_movement_score,
            self.external_threat_intel_score,
            self.geolocation_anomaly,
            self.user_agent_strangeness,
            self.command_line_entropy,
            self.dns_query_volume,
        ]
    }
}

/// Configuration for feature extraction
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FeatureConfig {
    /// Normalization method
    pub normalization: String,
    /// Feature scaling
    pub scaling: bool,
}

/// Feature extractor for processing security events
pub struct FeatureExtractor {
    config: FeatureConfig,
}

impl FeatureExtractor {
    pub fn new(config: FeatureConfig) -> Self {
        FeatureExtractor { config }
    }

    pub fn extract(&self, event: &SecurityEventData) -> SecurityFeatureVector {
        // Real-world extraction logic would parse the JSON 'data' field
        let mut fv = SecurityFeatureVector {
            login_frequency: 0.0,
            failed_attempts: 0.0,
            resource_consumption: 0.0,
            network_packets_in: 0.0,
            network_packets_out: 0.0,
            port_scan_ratio: 0.0,
            connection_duration_avg: 0.0,
            unique_peers: 0.0,
            protocol_anomaly_score: 0.0,
            unusual_timing_score: 0.0,
            sensitive_file_access: 0.0,
            process_ancestry_depth: 0.0,
            privilege_escalation_score: 0.0,
            data_exfiltration_score: 0.0,
            lateral_movement_score: 0.0,
            external_threat_intel_score: 0.0,
            geolocation_anomaly: 0.0,
            user_agent_strangeness: 0.0,
            command_line_entropy: 0.0,
            dns_query_volume: 0.0,
        };

        // Extract basic features from event metadata
        if event.event_type.contains("login") && !event.success {
            fv.failed_attempts = 1.0;
        }

        if let Some(duration) = event.session_duration {
            fv.connection_duration_avg = duration as f32;
        }

        // Example: check command line entropy if present in data
        if let Some(cmd) = event.data.get("command").and_then(|v| v.as_str()) {
            fv.command_line_entropy = (cmd.len() as f32 / 100.0).min(1.0);
        }

        fv
    }

    pub fn extract_behavioral_features(
        &self,
        events: &[SecurityEventData],
    ) -> SecurityFeatureVector {
        // Aggregate features from multiple events
        let mut fv = SecurityFeatureVector {
            // Initialize all fields to 0.0
            login_frequency: 0.0,
            failed_attempts: 0.0,
            resource_consumption: 0.0,
            network_packets_in: 0.0,
            network_packets_out: 0.0,
            port_scan_ratio: 0.0,
            connection_duration_avg: 0.0,
            unique_peers: 0.0,
            protocol_anomaly_score: 0.0,
            unusual_timing_score: 0.0,
            sensitive_file_access: 0.0,
            process_ancestry_depth: 0.0,
            privilege_escalation_score: 0.0,
            data_exfiltration_score: 0.0,
            lateral_movement_score: 0.0,
            external_threat_intel_score: 0.0,
            geolocation_anomaly: 0.0,
            user_agent_strangeness: 0.0,
            command_line_entropy: 0.0,
            dns_query_volume: 0.0,
        };

        for event in events {
            if event.event_type.contains("login") {
                fv.login_frequency += 1.0;
                if !event.success {
                    fv.failed_attempts += 1.0;
                }
            }
        }

        // Normalize frequency based on time window (placeholder)
        fv.login_frequency /= 24.0; // events per hour roughly

        // Calculate UNIQUE peers correctly using a HashSet to avoid counting duplicates
        let unique_resources: HashSet<&str> = events
            .iter()
            .filter_map(|e| e.resource_id.as_deref())
            .collect();
        fv.unique_peers = unique_resources.len() as f32;

        fv
    }

    /// Extract features from a HashMap (used by InferenceEngine)
    pub fn extract_from_map(
        &self,
        map: &HashMap<String, serde_json::Value>,
    ) -> SecurityFeatureVector {
        let get_val =
            |key: &str| -> f32 { map.get(key).and_then(|v| v.as_f64()).unwrap_or(0.0) as f32 };

        SecurityFeatureVector {
            login_frequency: get_val("login_frequency"),
            failed_attempts: get_val("failed_attempts"),
            resource_consumption: get_val("resource_consumption"),
            network_packets_in: get_val("network_packets_in"),
            network_packets_out: get_val("network_packets_out"),
            port_scan_ratio: get_val("port_scan_ratio"),
            connection_duration_avg: get_val("connection_duration_avg"),
            unique_peers: get_val("unique_peers"),
            protocol_anomaly_score: get_val("protocol_anomaly_score"),
            unusual_timing_score: get_val("unusual_timing_score"),
            sensitive_file_access: get_val("sensitive_file_access"),
            process_ancestry_depth: get_val("process_ancestry_depth"),
            privilege_escalation_score: get_val("privilege_escalation_score"),
            data_exfiltration_score: get_val("data_exfiltration_score"),
            lateral_movement_score: get_val("lateral_movement_score"),
            external_threat_intel_score: get_val("external_threat_intel_score"),
            geolocation_anomaly: get_val("geolocation_anomaly"),
            user_agent_strangeness: get_val("user_agent_strangeness"),
            command_line_entropy: get_val("command_line_entropy"),
            dns_query_volume: get_val("dns_query_volume"),
        }
    }
}

/// Data structure for security events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEventData {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub event_type: String,
    pub success: bool,
    pub data_size: Option<u64>,
    pub session_duration: Option<f64>,
    pub resource_id: Option<String>,
    pub data: serde_json::Value,
}

pub struct DataPipeline;

impl DataPipeline {
    /// Normalize features (e.g., Min-Max scaling) before inference
    pub fn normalize(features: &[f32; 20]) -> [f32; 20] {
        let mut normalized = *features;
        for x in normalized.iter_mut() {
            *x = x.max(0.0).min(1.0);
        }
        normalized
    }
}
