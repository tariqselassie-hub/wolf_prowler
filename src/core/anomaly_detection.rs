//! Anomaly Detection Algorithms for Advanced Threat Detection
//!
//! This module implements statistical anomaly detection algorithms including
//! Z-score analysis, isolation forests, clustering-based anomaly detection,
//! and time series analysis for sophisticated threat detection.

use crate::core::security_simple::{Severity, Threat, ThreatStatus, ThreatType};
use crate::core::threat_detection::{
    AnomalyAlgorithm, DetectionResult, DetectionType, GlobalBaseline, StatisticalModel,
};
use std::time::{Duration, Instant};

/// Z-score based anomaly detector
pub struct ZScoreAnomalyDetector {
    /// Z-score threshold for anomaly detection
    z_threshold: f64,
    /// Minimum sample size for reliable statistics
    min_sample_size: usize,
}

impl ZScoreAnomalyDetector {
    pub fn new() -> Self {
        Self {
            z_threshold: 3.0, // Standard 3-sigma rule
            min_sample_size: 30,
        }
    }

    /// Calculate Z-score for a value
    fn calculate_z_score(&self, value: f64, mean: f64, std_dev: f64) -> f64 {
        if std_dev == 0.0 {
            0.0
        } else {
            (value - mean) / std_dev
        }
    }

    /// Detect anomalies in message statistics
    fn detect_message_anomalies(
        &self,
        model: &StatisticalModel,
        baseline: &GlobalBaseline,
    ) -> Vec<DetectionResult> {
        let mut results = Vec::new();

        // Check message size anomaly
        let size_z = self.calculate_z_score(
            model.message_stats.mean_size,
            baseline.average_message_size,
            (model.message_stats.size_variance.sqrt()).max(0.1),
        );

        if size_z.abs() > self.z_threshold {
            results.push(DetectionResult {
                detection_type: DetectionType::StatisticalAnomaly,
                confidence: (size_z.abs() / self.z_threshold).min(1.0),
                indicators: vec![
                    format!("Message size Z-score: {:.2}", size_z),
                    format!(
                        "Peer size: {:.2}, Network avg: {:.2}",
                        model.message_stats.mean_size, baseline.average_message_size
                    ),
                ],
                recommended_actions: vec![
                    "content_analysis".to_string(),
                    "size_monitoring".to_string(),
                ],
            });
        }

        // Check message frequency anomaly
        let freq_z = self.calculate_z_score(
            model.message_stats.frequency_mean,
            baseline.average_connection_rate,
            (model.message_stats.frequency_variance.sqrt()).max(0.1),
        );

        if freq_z.abs() > self.z_threshold {
            results.push(DetectionResult {
                detection_type: DetectionType::StatisticalAnomaly,
                confidence: (freq_z.abs() / self.z_threshold).min(1.0),
                indicators: vec![
                    format!("Message frequency Z-score: {:.2}", freq_z),
                    format!(
                        "Peer frequency: {:.2}, Network avg: {:.2}",
                        model.message_stats.frequency_mean, baseline.average_connection_rate
                    ),
                ],
                recommended_actions: vec![
                    "rate_limit".to_string(),
                    "frequency_monitoring".to_string(),
                ],
            });
        }

        // Check entropy anomaly
        let entropy_z = self.calculate_z_score(
            model.message_stats.entropy_mean,
            baseline.network_entropy,
            1.0, // Assume unit variance for entropy
        );

        if entropy_z.abs() > self.z_threshold {
            results.push(DetectionResult {
                detection_type: DetectionType::CryptoAnomaly,
                confidence: (entropy_z.abs() / self.z_threshold).min(1.0),
                indicators: vec![
                    format!("Message entropy Z-score: {:.2}", entropy_z),
                    format!(
                        "Peer entropy: {:.2}, Network avg: {:.2}",
                        model.message_stats.entropy_mean, baseline.network_entropy
                    ),
                ],
                recommended_actions: vec![
                    "crypto_analysis".to_string(),
                    "content_inspection".to_string(),
                ],
            });
        }

        results
    }
}

impl AnomalyAlgorithm for ZScoreAnomalyDetector {
    fn detect(
        &self,
        peer_model: &StatisticalModel,
        baseline: &GlobalBaseline,
    ) -> Vec<DetectionResult> {
        let mut results = Vec::new();

        // Skip if insufficient data
        if peer_model.message_stats.frequency_mean == 0.0 {
            return results;
        }

        results.extend(self.detect_message_anomalies(peer_model, baseline));

        results
    }

    fn algorithm_name(&self) -> &'static str {
        "zscore_anomaly"
    }
}

/// Isolation Forest based anomaly detector
pub struct IsolationForestAnomalyDetector {
    /// Number of trees in the forest
    n_trees: usize,
    /// Sample size for each tree
    sample_size: usize,
    /// Anomaly score threshold
    anomaly_threshold: f64,
}

impl IsolationForestAnomalyDetector {
    pub fn new() -> Self {
        Self {
            n_trees: 100,
            sample_size: 256,
            anomaly_threshold: 0.6,
        }
    }

    /// Calculate isolation score (simplified version)
    fn calculate_isolation_score(&self, features: &[f64]) -> f64 {
        // Simplified isolation score calculation
        // In a real implementation, this would build actual isolation trees
        let variance = self.calculate_variance(features);
        let mean = features.iter().sum::<f64>() / features.len() as f64;

        // Higher variance and deviation from mean indicate more isolation
        let isolation_factor = (variance + mean.abs()) / 2.0;
        (isolation_factor / 10.0).min(1.0) // Normalize to 0-1
    }

    /// Calculate variance of features
    fn calculate_variance(&self, features: &[f64]) -> f64 {
        if features.is_empty() {
            return 0.0;
        }

        let mean = features.iter().sum::<f64>() / features.len() as f64;
        let variance =
            features.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / features.len() as f64;

        variance
    }

    /// Extract features from statistical model
    fn extract_features(&self, model: &StatisticalModel, baseline: &GlobalBaseline) -> Vec<f64> {
        vec![
            model.message_stats.mean_size / baseline.average_message_size.max(1.0),
            model.message_stats.frequency_mean / baseline.average_connection_rate.max(1.0),
            model.message_stats.entropy_mean / baseline.network_entropy.max(1.0),
            model.connection_stats.connection_rate / baseline.average_connection_rate.max(1.0),
            model.connection_stats.failure_rate,
            model.timing_stats.burst_frequency,
        ]
    }
}

impl AnomalyAlgorithm for IsolationForestAnomalyDetector {
    fn detect(
        &self,
        peer_model: &StatisticalModel,
        baseline: &GlobalBaseline,
    ) -> Vec<DetectionResult> {
        let mut results = Vec::new();

        let features = self.extract_features(peer_model, baseline);
        let isolation_score = self.calculate_isolation_score(&features);

        if isolation_score > self.anomaly_threshold {
            results.push(DetectionResult {
                detection_type: DetectionType::StatisticalAnomaly,
                confidence: isolation_score,
                indicators: vec![
                    format!("Isolation score: {:.3}", isolation_score),
                    format!("Feature vector: {:?}", features),
                ],
                recommended_actions: vec![
                    "deep_analysis".to_string(),
                    "behavioral_monitoring".to_string(),
                    "peer_isolation".to_string(),
                ],
            });
        }

        results
    }

    fn algorithm_name(&self) -> &'static str {
        "isolation_forest"
    }
}

/// Time series anomaly detector
pub struct TimeSeriesAnomalyDetector {
    /// Time window for analysis
    time_window: Duration,
    /// Seasonality period
    seasonality_period: Duration,
    /// Trend threshold
    trend_threshold: f64,
}

impl TimeSeriesAnomalyDetector {
    pub fn new() -> Self {
        Self {
            time_window: Duration::from_secs(3600),         // 1 hour
            seasonality_period: Duration::from_secs(86400), // 24 hours
            trend_threshold: 2.0,
        }
    }

    /// Detect trend anomalies
    fn detect_trend_anomaly(
        &self,
        current_rate: f64,
        historical_rates: &[f64],
    ) -> Option<DetectionResult> {
        if historical_rates.len() < 10 {
            return None;
        }

        // Calculate trend using linear regression (simplified)
        let n = historical_rates.len() as f64;
        let sum_x: f64 = (0..historical_rates.len()).map(|i| i as f64).sum();
        let sum_y: f64 = historical_rates.iter().sum();
        let sum_xy: f64 = historical_rates
            .iter()
            .enumerate()
            .map(|(i, &y)| i as f64 * y)
            .sum();
        let sum_x2: f64 = (0..historical_rates.len())
            .map(|i| (i as f64).powi(2))
            .sum();

        let slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x.powi(2));

        // Calculate expected value
        let expected = slope * (historical_rates.len() as f64) + (sum_y - slope * sum_x) / n;

        let deviation = (current_rate - expected).abs() / expected.max(1.0);

        if deviation > self.trend_threshold {
            Some(DetectionResult {
                detection_type: DetectionType::StatisticalAnomaly,
                confidence: (deviation / self.trend_threshold).min(1.0),
                indicators: vec![
                    format!("Trend deviation: {:.2}x", deviation),
                    format!(
                        "Current rate: {:.2}, Expected: {:.2}",
                        current_rate, expected
                    ),
                ],
                recommended_actions: vec![
                    "trend_analysis".to_string(),
                    "rate_monitoring".to_string(),
                ],
            })
        } else {
            None
        }
    }

    /// Detect seasonal anomalies
    fn detect_seasonal_anomaly(
        &self,
        current_rate: f64,
        seasonal_avg: f64,
    ) -> Option<DetectionResult> {
        let deviation = (current_rate - seasonal_avg).abs() / seasonal_avg.max(1.0);

        if deviation > self.trend_threshold {
            Some(DetectionResult {
                detection_type: DetectionType::StatisticalAnomaly,
                confidence: (deviation / self.trend_threshold).min(1.0),
                indicators: vec![
                    format!("Seasonal deviation: {:.2}x", deviation),
                    format!(
                        "Current rate: {:.2}, Seasonal avg: {:.2}",
                        current_rate, seasonal_avg
                    ),
                ],
                recommended_actions: vec![
                    "seasonal_analysis".to_string(),
                    "time_pattern_monitoring".to_string(),
                ],
            })
        } else {
            None
        }
    }
}

impl AnomalyAlgorithm for TimeSeriesAnomalyDetector {
    fn detect(
        &self,
        peer_model: &StatisticalModel,
        baseline: &GlobalBaseline,
    ) -> Vec<DetectionResult> {
        let mut results = Vec::new();

        // This would require time series data for the peer
        // For now, implement basic checks using current statistics

        let current_rate = peer_model.message_stats.frequency_mean;

        // Simulate historical data (in real implementation, this would be stored)
        let historical_rates = vec![
            baseline.average_connection_rate * 0.8,
            baseline.average_connection_rate * 0.9,
            baseline.average_connection_rate * 1.0,
            baseline.average_connection_rate * 1.1,
            baseline.average_connection_rate * 0.95,
        ];

        if let Some(trend_result) = self.detect_trend_anomaly(current_rate, &historical_rates) {
            results.push(trend_result);
        }

        // Simulate seasonal average
        let seasonal_avg = baseline.average_connection_rate;
        if let Some(seasonal_result) = self.detect_seasonal_anomaly(current_rate, seasonal_avg) {
            results.push(seasonal_result);
        }

        results
    }

    fn algorithm_name(&self) -> &'static str {
        "timeseries_anomaly"
    }
}

/// Clustering-based anomaly detector
pub struct ClusteringAnomalyDetector {
    /// Number of clusters
    n_clusters: usize,
    /// Distance threshold for anomaly
    distance_threshold: f64,
}

impl ClusteringAnomalyDetector {
    pub fn new() -> Self {
        Self {
            n_clusters: 5,
            distance_threshold: 2.0,
        }
    }

    /// Calculate Euclidean distance between two feature vectors
    fn calculate_distance(&self, features1: &[f64], features2: &[f64]) -> f64 {
        if features1.len() != features2.len() {
            return f64::INFINITY;
        }

        features1
            .iter()
            .zip(features2.iter())
            .map(|(a, b)| (a - b).powi(2))
            .sum::<f64>()
            .sqrt()
    }

    /// Find nearest cluster center
    fn find_nearest_cluster(&self, features: &[f64], cluster_centers: &[Vec<f64>]) -> (usize, f64) {
        cluster_centers
            .iter()
            .enumerate()
            .map(|(i, center)| (i, self.calculate_distance(features, center)))
            .min_by(|(_, d1), (_, d2)| d1.partial_cmp(d2).unwrap_or(std::cmp::Ordering::Equal))
            .unwrap_or((0, f64::INFINITY))
    }

    /// Extract features for clustering
    fn extract_features(&self, model: &StatisticalModel) -> Vec<f64> {
        vec![
            model.message_stats.mean_size,
            model.message_stats.frequency_mean,
            model.message_stats.entropy_mean,
            model.connection_stats.connection_rate,
            model.connection_stats.failure_rate,
            model.timing_stats.inter_arrival_mean.as_secs_f64(),
        ]
    }
}

impl AnomalyAlgorithm for ClusteringAnomalyDetector {
    fn detect(
        &self,
        peer_model: &StatisticalModel,
        baseline: &GlobalBaseline,
    ) -> Vec<DetectionResult> {
        let mut results = Vec::new();

        let features = self.extract_features(peer_model);

        // Update cluster centers based on baseline data
        let cluster_centers = vec![
            vec![
                baseline.average_message_size,
                baseline.average_connection_rate,
                baseline.network_entropy,
                0.5,  // connection rate
                0.1,  // failure rate
                60.0, // timing in seconds
            ], // Normal behavior
            vec![
                baseline.average_message_size * 2.0,
                baseline.average_connection_rate * 3.0,
                baseline.network_entropy * 1.5,
                0.8,  // high connection rate
                0.3,  // higher failure rate
                10.0, // rapid timing
            ], // High activity/suspicious
            vec![
                baseline.average_message_size * 0.5,
                baseline.average_connection_rate * 0.5,
                baseline.network_entropy * 0.8,
                0.3,   // low connection rate
                0.05,  // low failure rate
                120.0, // slow timing
            ], // Low activity
        ];

        let (nearest_cluster, distance) = self.find_nearest_cluster(&features, &cluster_centers);

        // Adjust distance threshold based on network conditions
        let adjusted_threshold = if baseline.threat_rate > 0.1 {
            self.distance_threshold * 0.8 // Lower threshold during high threat periods
        } else {
            self.distance_threshold
        };

        if distance > adjusted_threshold {
            results.push(DetectionResult {
                detection_type: DetectionType::StatisticalAnomaly,
                confidence: (distance / adjusted_threshold).min(1.0),
                indicators: vec![
                    format!("Cluster distance: {:.2}", distance),
                    format!("Nearest cluster: {}", nearest_cluster),
                    format!("Network threat rate: {:.2}", baseline.threat_rate),
                    format!("Feature vector: {:?}", features),
                ],
                recommended_actions: vec![
                    "cluster_analysis".to_string(),
                    "peer_classification".to_string(),
                    "anomaly_investigation".to_string(),
                ],
            });
        }

        results
    }

    fn algorithm_name(&self) -> &'static str {
        "clustering_anomaly"
    }
}

/// Convert anomaly detection results to threats
pub fn anomaly_results_to_threats(
    peer_id: &str,
    detection_results: Vec<DetectionResult>,
) -> Vec<Threat> {
    detection_results
        .into_iter()
        .map(|result| {
            let threat_type = match result.detection_type {
                DetectionType::StatisticalAnomaly => ThreatType::Reconnaissance,
                DetectionType::CryptoAnomaly => ThreatType::DataTampering,
                DetectionType::NetworkAnomaly => ThreatType::SybilAttack,
                _ => ThreatType::MaliciousPeer,
            };

            let severity = if result.confidence > 0.9 {
                Severity::Critical
            } else if result.confidence > 0.7 {
                Severity::High
            } else if result.confidence > 0.5 {
                Severity::Medium
            } else {
                Severity::Low
            };

            Threat {
                id: uuid::Uuid::new_v4().to_string(),
                threat_type,
                source_peer: peer_id.to_string(),
                severity,
                detected_at: Instant::now(),
                status: ThreatStatus::Active,
                description: format!(
                    "Statistical anomaly detected with {:.1}% confidence: {}",
                    result.confidence * 100.0,
                    result.indicators.join("; ")
                ),
                mitigation_actions: result.recommended_actions,
            }
        })
        .collect()
}
