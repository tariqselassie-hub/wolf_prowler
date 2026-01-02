//! Anomaly Detection Engine
//!
//! Advanced anomaly detection with wolf pack behavioral patterns.
//! Wolves detect anomalies in pack behavior to identify potential threats.

pub mod adaptive;
pub mod behavioral;
pub mod network;
pub mod statistical;

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info};
use uuid::Uuid;

/// Main anomaly detection engine
pub struct AnomalyDetectionEngine {
    /// Statistical analyzer
    statistical_analyzer: statistical::StatisticalAnalyzer,
    /// Behavioral analyzer
    behavioral_analyzer: behavioral::BehavioralAnalyzer,
    /// Network analyzer
    network_analyzer: network::NetworkAnalyzer,
    /// Adaptive analyzer
    adaptive_analyzer: adaptive::AdaptiveAnalyzer,
    /// Configuration
    config: AnomalyDetectionConfig,
    /// Statistics
    statistics: AnomalyDetectionStats,
}

/// Anomaly detection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyDetectionConfig {
    /// Detection sensitivity (0.0-1.0)
    pub sensitivity: f64,
    /// False positive tolerance
    pub false_positive_tolerance: f64,
    /// Analysis window size
    pub analysis_window: usize,
    /// Minimum confidence threshold
    pub min_confidence: f64,
    /// Alert thresholds
    pub alert_thresholds: AlertThresholds,
}

/// Alert thresholds
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertThresholds {
    /// Low anomaly threshold
    pub low_threshold: f64,
    /// Medium anomaly threshold
    pub medium_threshold: f64,
    /// High anomaly threshold
    pub high_threshold: f64,
    /// Critical anomaly threshold
    pub critical_threshold: f64,
}

/// Anomaly detection statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyDetectionStats {
    /// Total anomalies detected
    pub total_anomalies: u64,
    /// Anomalies by type
    pub anomalies_by_type: HashMap<AnomalyType, u64>,
    /// Anomalies by severity
    pub anomalies_by_severity: HashMap<AnomalySeverity, u64>,
    /// False positives
    pub false_positives: u64,
    /// True positives
    pub true_positives: u64,
    /// Detection rate
    pub detection_rate: f64,
    /// Average detection time
    pub avg_detection_time_ms: f64,
    /// Last update timestamp
    pub last_update: DateTime<Utc>,
}

/// Anomaly detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyDetectionResult {
    /// Anomaly ID
    pub id: Uuid,
    /// Anomaly type
    pub anomaly_type: AnomalyType,
    /// Anomaly severity
    pub severity: AnomalySeverity,
    /// Anomaly score (0.0-1.0)
    pub anomaly_score: f64,
    /// Confidence score (0.0-1.0)
    pub confidence: f64,
    /// Description
    pub description: String,
    /// Affected entities
    pub affected_entities: Vec<String>,
    /// Detection method
    pub detection_method: DetectionMethod,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Context
    pub context: AnomalyContext,
    /// Recommended actions
    pub recommended_actions: Vec<String>,
}

/// Anomaly types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AnomalyType {
    /// Statistical anomaly
    Statistical,
    /// Behavioral anomaly
    Behavioral,
    /// Network anomaly
    Network,
    /// Temporal anomaly
    Temporal,
    /// Resource anomaly
    Resource,
    /// Access anomaly
    Access,
    /// Communication anomaly
    Communication,
    /// Performance anomaly
    Performance,
}

/// Anomaly severity with wolf-themed classification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AnomalySeverity {
    /// Pup level - Low anomaly
    Pup = 0,
    /// Scout level - Informational
    Scout = 1,
    /// Hunter level - Medium anomaly
    Hunter = 2,
    /// Beta level - High anomaly
    Beta = 3,
    /// Alpha level - Critical anomaly
    Alpha = 4,
}

/// Detection methods
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DetectionMethod {
    Statistical,
    Behavioral,
    Network,
    Adaptive,
    Hybrid,
}

/// Anomaly context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyContext {
    /// Source entity
    pub source_entity: String,
    /// Time window
    pub time_window: TimeWindow,
    /// Baseline metrics
    pub baseline_metrics: HashMap<String, f64>,
    /// Current metrics
    pub current_metrics: HashMap<String, f64>,
    /// Environmental factors
    pub environmental_factors: HashMap<String, serde_json::Value>,
}

/// Time window
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeWindow {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    pub duration_minutes: u64,
}

/// Wolf pack anomaly pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WolfPackAnomalyPattern {
    /// Pattern ID
    pub id: String,
    /// Pattern name
    pub name: String,
    /// Pattern description
    pub description: String,
    /// Anomaly indicators
    pub indicators: Vec<AnomalyIndicator>,
    /// Pattern frequency
    pub frequency: f64,
    /// Last observed
    pub last_observed: DateTime<Utc>,
    /// Associated threats
    pub associated_threats: Vec<String>,
}

/// Anomaly indicator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyIndicator {
    /// Indicator type
    pub indicator_type: String,
    /// Indicator value
    pub value: serde_json::Value,
    /// Deviation from baseline
    pub deviation: f64,
    /// Significance
    pub significance: f64,
}

impl AnomalyDetectionEngine {
    /// Create new anomaly detection engine
    pub fn new(config: AnomalyDetectionConfig) -> Result<Self> {
        info!("🔍 Initializing Anomaly Detection Engine");

        let engine = Self {
            statistical_analyzer: statistical::StatisticalAnalyzer::new(config.clone())?,
            behavioral_analyzer: behavioral::BehavioralAnalyzer::new(config.clone())?,
            network_analyzer: network::NetworkAnalyzer::new(config.clone())?,
            adaptive_analyzer: adaptive::AdaptiveAnalyzer::new(config.clone())?,
            config,
            statistics: AnomalyDetectionStats::default(),
        };

        info!("✅ Anomaly Detection Engine initialized successfully");
        Ok(engine)
    }

    /// Detect anomalies in data
    pub async fn detect_anomalies(
        &mut self,
        data: &AnomalyInputData,
    ) -> Result<Vec<AnomalyDetectionResult>> {
        debug!("🔍 Detecting anomalies in data");

        let mut all_anomalies = Vec::new();
        let start_time = std::time::Instant::now();

        // Run statistical analysis
        let statistical_anomalies = self.statistical_analyzer.detect_anomalies(data).await?;
        all_anomalies.extend(statistical_anomalies);

        // Run behavioral analysis
        let behavioral_anomalies = self.behavioral_analyzer.detect_anomalies(data).await?;
        all_anomalies.extend(behavioral_anomalies);

        // Run network analysis
        let network_anomalies = self.network_analyzer.detect_anomalies(data).await?;
        all_anomalies.extend(network_anomalies);

        // Run adaptive analysis
        let adaptive_anomalies = self.adaptive_analyzer.detect_anomalies(data).await?;
        all_anomalies.extend(adaptive_anomalies);

        // Filter and rank anomalies
        let filtered_anomalies = self.filter_and_rank_anomalies(all_anomalies);

        // Update statistics
        let detection_time = start_time.elapsed().as_millis() as f64;
        self.update_statistics(&filtered_anomalies, detection_time);

        debug!("✅ Detected {} anomalies", filtered_anomalies.len());
        Ok(filtered_anomalies)
    }

    /// Analyze anomaly patterns
    pub async fn analyze_patterns(
        &mut self,
        anomalies: &[AnomalyDetectionResult],
    ) -> Result<Vec<WolfPackAnomalyPattern>> {
        debug!("🐺 Analyzing wolf pack anomaly patterns");

        let mut patterns = Vec::new();

        // Group anomalies by type and context
        let mut grouped_anomalies: HashMap<String, Vec<&AnomalyDetectionResult>> = HashMap::new();

        for anomaly in anomalies {
            let key = format!(
                "{:?}-{}",
                anomaly.anomaly_type, anomaly.context.source_entity
            );
            grouped_anomalies
                .entry(key)
                .or_insert_with(Vec::new)
                .push(anomaly);
        }

        // Analyze each group for patterns
        for (group_key, group_anomalies) in grouped_anomalies {
            if group_anomalies.len() >= 3 {
                // Minimum pattern size
                let pattern = self
                    .create_pattern_from_group(group_key, group_anomalies)
                    .await?;
                patterns.push(pattern);
            }
        }

        info!("✅ Analyzed {} anomaly patterns", patterns.len());
        Ok(patterns)
    }

    /// Update baseline with new data
    pub async fn update_baseline(&mut self, data: &AnomalyInputData) -> Result<()> {
        debug!("📊 Updating anomaly detection baseline");

        // Update all analyzers
        self.statistical_analyzer.update_baseline(data).await?;
        self.behavioral_analyzer.update_baseline(data).await?;
        self.network_analyzer.update_baseline(data).await?;
        self.adaptive_analyzer.update_baseline(data).await?;

        info!("✅ Baseline updated successfully");
        Ok(())
    }

    /// Get anomaly statistics
    pub fn get_statistics(&self) -> &AnomalyDetectionStats {
        &self.statistics
    }

    /// Filter and rank anomalies
    fn filter_and_rank_anomalies(
        &self,
        anomalies: Vec<AnomalyDetectionResult>,
    ) -> Vec<AnomalyDetectionResult> {
        let mut filtered = anomalies;

        // Filter by confidence threshold
        filtered.retain(|a| a.confidence >= self.config.min_confidence);

        // Filter by false positive tolerance
        filtered.retain(|a| a.anomaly_score >= (1.0 - self.config.false_positive_tolerance));

        // Sort by anomaly score and severity
        filtered.sort_by(|a, b| {
            b.anomaly_score
                .partial_cmp(&a.anomaly_score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| {
                    b.severity
                        .partial_cmp(&a.severity)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
        });

        // Limit to top anomalies
        filtered.truncate(100); // Keep top 100 anomalies

        filtered
    }

    /// Create pattern from anomaly group
    async fn create_pattern_from_group(
        &self,
        group_key: String,
        anomalies: Vec<&AnomalyDetectionResult>,
    ) -> Result<WolfPackAnomalyPattern> {
        let frequency = anomalies.len() as f64 / 30.0; // Frequency per day (simplified)
        let last_observed = anomalies
            .iter()
            .map(|a| a.timestamp)
            .max()
            .unwrap_or(Utc::now());

        let indicators = anomalies
            .iter()
            .take(5) // Take top 5 as indicators
            .map(|a| AnomalyIndicator {
                indicator_type: format!("{:?}", a.anomaly_type),
                value: serde_json::json!(a.anomaly_score),
                deviation: a.anomaly_score,
                significance: a.confidence,
            })
            .collect();

        Ok(WolfPackAnomalyPattern {
            id: Uuid::new_v4().to_string(),
            name: format!("Pattern-{}", group_key),
            description: format!("Anomaly pattern detected in {}", group_key),
            indicators,
            frequency,
            last_observed,
            associated_threats: Vec::new(), // Would be populated from threat intelligence
        })
    }

    /// Update statistics
    fn update_statistics(&mut self, anomalies: &[AnomalyDetectionResult], detection_time: f64) {
        self.statistics.total_anomalies += anomalies.len() as u64;

        for anomaly in anomalies {
            *self
                .statistics
                .anomalies_by_type
                .entry(anomaly.anomaly_type.clone())
                .or_insert(0) += 1;

            *self
                .statistics
                .anomalies_by_severity
                .entry(anomaly.severity.clone())
                .or_insert(0) += 1;
        }

        // Update average detection time
        self.statistics.avg_detection_time_ms = (self.statistics.avg_detection_time_ms
            * (self.statistics.total_anomalies - 1) as f64
            + detection_time)
            / self.statistics.total_anomalies as f64;

        self.statistics.last_update = Utc::now();
    }

    /// Calculate detection rate
    pub fn calculate_detection_rate(&mut self, true_positives: u64, total_events: u64) {
        if total_events > 0 {
            self.statistics.detection_rate = true_positives as f64 / total_events as f64;
        }
    }
}

/// Anomaly input data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyInputData {
    /// Data ID
    pub id: Uuid,
    /// Entity ID
    pub entity_id: String,
    /// Data type
    pub data_type: String,
    /// Metrics
    pub metrics: HashMap<String, f64>,
    /// Features
    pub features: HashMap<String, serde_json::Value>,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Context
    pub context: HashMap<String, serde_json::Value>,
}

impl Default for AnomalyDetectionConfig {
    fn default() -> Self {
        Self {
            sensitivity: 0.7,
            false_positive_tolerance: 0.1,
            analysis_window: 100,
            min_confidence: 0.6,
            alert_thresholds: AlertThresholds::default(),
        }
    }
}

impl Default for AlertThresholds {
    fn default() -> Self {
        Self {
            low_threshold: 0.2,
            medium_threshold: 0.4,
            high_threshold: 0.7,
            critical_threshold: 0.9,
        }
    }
}

impl Default for AnomalyDetectionStats {
    fn default() -> Self {
        Self {
            total_anomalies: 0,
            anomalies_by_type: HashMap::new(),
            anomalies_by_severity: HashMap::new(),
            false_positives: 0,
            true_positives: 0,
            detection_rate: 0.0,
            avg_detection_time_ms: 0.0,
            last_update: Utc::now(),
        }
    }
}
