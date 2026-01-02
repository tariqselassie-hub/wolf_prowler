//! ML Security Engine
//!
//! Machine learning for advanced threat detection with wolf pack behavioral patterns.
//! Wolves learn from pack behavior to detect anomalies and threats.

pub mod backends;
pub mod baselines;
pub mod data_pipeline;
pub mod inference;
pub mod models;
pub mod patterns;
pub mod training;

use crate::external_feeds::ThreatFeedItem;
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Main ML security engine
pub struct MLSecurityEngine {
    /// ML models
    models: HashMap<String, MLModel>,
    /// Training pipeline
    training_pipeline: training::TrainingPipeline,
    /// Inference engine
    inference_engine: inference::InferenceEngine,
    /// Pattern analyzer
    pattern_analyzer: patterns::PatternAnalyzer,
    /// Configuration
    config: MLSecurityConfig,
    /// ML backends
    backends: HashMap<String, Box<dyn backends::MLBackend>>,
    /// Training data buffer
    training_buffer: Vec<MLTrainingData>,
    /// Statistics
    statistics: MLSecurityStats,
    /// Recent predictions (cache for dashboard)
    recent_predictions: Vec<MLPredictionResult>,
}

/// ML security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MLSecurityConfig {
    /// Model update interval in seconds
    pub model_update_interval: u64,
    /// Training data retention days
    pub training_retention_days: u32,
    /// Inference thresholds
    pub thresholds: InferenceThresholds,
    /// Model configuration
    pub model_config: ModelConfig,
    /// External feeds configuration
    pub external_feeds: crate::external_feeds::ExternalFeedsConfig,
    /// LLM API URL for generative AI features (e.g. Llama3)
    pub llm_api_url: Option<String>,
    /// ML Backend configuration
    pub backend_config: backends::BackendConfig,
    /// Path to store trained models
    pub model_storage_path: String,
}

/// Inference thresholds
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceThresholds {
    /// Anomaly detection threshold
    pub anomaly_threshold: f64,
    /// Threat detection threshold
    pub threat_threshold: f64,
    /// Confidence threshold for predictions
    pub confidence_threshold: f64,
    /// False positive tolerance
    pub false_positive_tolerance: f64,
}

/// Model configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ModelConfig {
    /// Behavioral model settings
    pub behavioral_model: BehavioralModelConfig,
    /// Network model settings
    pub network_model: NetworkModelConfig,
    /// Threat model settings
    pub threat_model: ThreatModelConfig,
}

/// Behavioral model configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralModelConfig {
    /// Window size for behavioral analysis
    pub window_size: usize,
    /// Behavioral features to track
    pub features: Vec<BehavioralFeature>,
    /// Pattern recognition sensitivity
    pub sensitivity: f64,
}

/// Network model configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkModelConfig {
    /// Network flow analysis window
    pub flow_window: usize,
    /// Protocol analysis enabled
    pub protocol_analysis: bool,
    /// Traffic pattern recognition
    pub traffic_patterns: bool,
}

/// Threat model configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatModelConfig {
    /// Threat intelligence integration
    pub threat_intel_integration: bool,
    /// Historical threat patterns
    pub historical_patterns: bool,
    /// Predictive threat modeling
    pub predictive_modeling: bool,
}

/// Behavioral features
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BehavioralFeature {
    LoginFrequency,
    AccessPatterns,
    TimePatterns,
    ResourceUsage,
    CommunicationPatterns,
    DeviceUsage,
    LocationPatterns,
    CommandSequences,
}

/// ML model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MLModel {
    /// Model ID
    pub id: String,
    /// Model name
    pub name: String,
    /// Model type
    pub model_type: ModelType,
    /// Model version
    pub version: String,
    /// Training data count
    pub training_samples: u64,
    /// Model performance metrics
    pub performance: ModelPerformance,
    /// Last trained timestamp
    pub last_trained: DateTime<Utc>,
    /// Active status
    pub active: bool,
}

/// Model types
#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub enum ModelType {
    Behavioral,
    Network,
    Threat,
    Anomaly,
    Predictive,
}

/// Model performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelPerformance {
    /// Accuracy score
    pub accuracy: f64,
    /// Precision score
    pub precision: f64,
    /// Recall score
    pub recall: f64,
    /// F1 score
    pub f1_score: f64,
    /// False positive rate
    pub false_positive_rate: f64,
    /// False negative rate
    pub false_negative_rate: f64,
}

/// ML security statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MLSecurityStats {
    /// Total predictions made
    pub total_predictions: u64,
    /// Predictions by model type
    pub predictions_by_model: HashMap<ModelType, u64>,
    /// Anomalies detected
    pub anomalies_detected: u64,
    /// Threats detected
    pub threats_detected: u64,
    /// False positives
    pub false_positives: u64,
    /// False negatives
    pub false_negatives: u64,
    /// Model training runs
    pub training_runs: u64,
    /// Average inference time
    pub avg_inference_time_ms: f64,
    /// Last update timestamp
    pub last_update: DateTime<Utc>,
}

/// ML prediction result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MLPredictionResult {
    /// Prediction ID
    pub id: Uuid,
    /// Model used
    pub model_id: String,
    /// Prediction type
    pub prediction_type: PredictionType,
    /// Input data hash
    pub input_hash: String,
    /// Predicted class
    pub predicted_class: String,
    /// Confidence score
    pub confidence: f64,
    /// Risk score
    pub risk_score: f64,
    /// Feature importance
    pub feature_importance: HashMap<String, f64>,
    /// Explanation
    pub explanation: String,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

/// Prediction types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PredictionType {
    AnomalyDetection,
    ThreatDetection,
    BehaviorClassification,
    RiskAssessment,
    ThreatPrediction,
}

/// Wolf behavioral pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WolfBehavioralPattern {
    /// Pattern ID
    pub id: String,
    /// Pattern name
    pub name: String,
    /// Pattern description
    pub description: String,
    /// Behavioral indicators
    pub indicators: Vec<BehavioralIndicator>,
    /// Risk level
    pub risk_level: RiskLevel,
    /// Frequency
    pub frequency: f64,
    /// Last observed
    pub last_observed: DateTime<Utc>,
}

/// Behavioral indicator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralIndicator {
    /// Indicator type
    pub indicator_type: String,
    /// Indicator value
    pub value: serde_json::Value,
    /// Weight
    pub weight: f64,
    /// Threshold
    pub threshold: f64,
}

/// Risk levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

impl MLSecurityEngine {
    /// Create new ML security engine
    pub fn new(config: MLSecurityConfig) -> Result<Self> {
        info!("🤖 Initializing ML Security Engine");

        let engine = Self {
            models: HashMap::new(),
            training_pipeline: training::TrainingPipeline::new(config.clone())?,
            inference_engine: inference::InferenceEngine::new(config.clone())?,
            pattern_analyzer: patterns::PatternAnalyzer::new(config.clone())?,
            config,
            backends: HashMap::new(),
            training_buffer: Vec::new(),
            statistics: MLSecurityStats::default(),
            recent_predictions: Vec::new(),
        };

        info!("✅ ML Security Engine initialized successfully");
        Ok(engine)
    }

    /// Initialize default models
    pub async fn initialize_models(&mut self) -> Result<()> {
        info!("🔧 Initializing default ML models");

        // Behavioral analysis model
        let behavioral_model = MLModel {
            id: "behavioral_analysis".to_string(),
            name: "Wolf Pack Behavioral Analysis".to_string(),
            model_type: ModelType::Behavioral,
            version: "1.0.0".to_string(),
            training_samples: 0,
            performance: ModelPerformance::default(),
            last_trained: Utc::now(),
            active: true,
        };

        // Network analysis model
        let network_model = MLModel {
            id: "network_analysis".to_string(),
            name: "Wolf Territory Network Analysis".to_string(),
            model_type: ModelType::Network,
            version: "1.0.0".to_string(),
            training_samples: 0,
            performance: ModelPerformance::default(),
            last_trained: Utc::now(),
            active: true,
        };

        // Threat detection model
        let threat_model = MLModel {
            id: "threat_detection".to_string(),
            name: "Wolf Pack Threat Detection".to_string(),
            model_type: ModelType::Threat,
            version: "1.0.0".to_string(),
            training_samples: 0,
            performance: ModelPerformance::default(),
            last_trained: Utc::now(),
            active: true,
        };

        // Anomaly detection model
        let anomaly_model = MLModel {
            id: "anomaly_detection".to_string(),
            name: "Wolf Pack Anomaly Detection".to_string(),
            model_type: ModelType::Anomaly,
            version: "1.0.0".to_string(),
            training_samples: 0,
            performance: ModelPerformance::default(),
            last_trained: Utc::now(),
            active: true,
        };

        // Add models
        self.models
            .insert(behavioral_model.id.clone(), behavioral_model);
        self.models.insert(network_model.id.clone(), network_model);
        self.models.insert(threat_model.id.clone(), threat_model);
        self.models.insert(anomaly_model.id.clone(), anomaly_model);

        // Initialize corresponding backends
        for (id, model) in &self.models {
            let mut backend_config = self.config.backend_config.clone();

            // Map model types to default backends if not specifically configured
            match model.model_type {
                ModelType::Anomaly => backend_config.backend_type = "isolation_forest".to_string(),
                ModelType::Threat => backend_config.backend_type = "threat_classifier".to_string(),
                _ => {} // Default is onnx or as configured
            }

            if let Ok(mut backend) = backends::create_backend(&backend_config) {
                // Try to load persisted model
                let model_file = format!("{}/{}.json", self.config.model_storage_path, id);
                if std::path::Path::new(&model_file).exists() {
                    if let Err(e) = backend.load(&model_file) {
                        warn!("⚠️ Failed to load persisted model for {}: {}", id, e);
                    } else {
                        info!("💾 Loaded persisted model for {}", id);
                    }
                }
                self.backends.insert(id.clone(), backend);
            }
        }

        info!(
            "✅ Initialized {} ML models and {} backends",
            self.models.len(),
            self.backends.len()
        );
        Ok(())
    }

    /// Run inference on data
    pub async fn run_inference(&mut self, data: &MLInputData) -> Result<Vec<MLPredictionResult>> {
        debug!("🔍 Running ML inference on data");

        let mut results = Vec::new();
        let start_time = std::time::Instant::now();

        // Run inference on active models
        for model in self.models.values().filter(|m| m.active) {
            if let Some(backend) = self.backends.get(&model.id) {
                // Convert HashMap features to fixed-size array
                let fv = self
                    .inference_engine
                    .extractor()
                    .extract_from_map(&data.features);
                let features = fv.to_array();

                match backend.predict(&features) {
                    Ok(predictions) => {
                        let risk_score = predictions.first().copied().unwrap_or(0.0);
                        let confidence = predictions.get(1).copied().unwrap_or(0.8);
                        let class_idx = predictions.get(2).copied().unwrap_or(0.0);

                        let predicted_class = if risk_score > 0.7 {
                            "Threat".to_string()
                        } else if risk_score > 0.3 {
                            "Suspicious".to_string()
                        } else {
                            "Normal".to_string()
                        };

                        let result = MLPredictionResult {
                            id: Uuid::new_v4(),
                            model_id: model.id.clone(),
                            prediction_type: PredictionType::RiskAssessment,
                            input_hash: format!(
                                "{:x}",
                                md5::compute(format!("{:?}", data.features))
                            ),
                            predicted_class,
                            confidence,
                            risk_score,
                            feature_importance: HashMap::new(),
                            explanation: format!(
                                "ML Analysis (Backend: {}): Confidence {:.2}. Class Index: {}",
                                backend.get_model_info().name,
                                confidence,
                                class_idx
                            ),
                            timestamp: Utc::now(),
                        };

                        results.push(result.clone());

                        // Cache recent prediction
                        self.recent_predictions.push(result.clone());
                        if self.recent_predictions.len() > 20 {
                            self.recent_predictions.remove(0);
                        }

                        self.statistics.total_predictions += 1;

                        *self
                            .statistics
                            .predictions_by_model
                            .entry(model.model_type.clone())
                            .or_insert(0) += 1;
                    }
                    Err(e) => {
                        warn!("⚠️ Inference failed for model {}: {}", model.id, e);
                    }
                }
            }
        }

        // Update statistics
    if self.statistics.total_predictions > 0 {
        let inference_time = start_time.elapsed().as_millis() as f64;
        self.statistics.avg_inference_time_ms = (self.statistics.avg_inference_time_ms
            * (self.statistics.total_predictions - 1) as f64
            + inference_time)
            / self.statistics.total_predictions as f64;
    }

    self.statistics.last_update = Utc::now();

        debug!("✅ ML inference completed: {} predictions", results.len());
        Ok(results)
    }

    /// Test connection to AI backend
    pub async fn test_ai_connection(&self, override_url: Option<String>) -> Result<bool> {
        info!("🔌 Testing connection to AI backend");
        self.inference_engine.test_connection(override_url).await
    }

    /// Process natural language command
    pub async fn process_command(
        &self,
        command: &str,
        override_url: Option<String>,
    ) -> Result<String> {
        debug!("🗣️ Processing natural language command: {}", command);
        self.inference_engine
            .process_command(command, override_url)
            .await
    }

    /// Predict threat using ML backend
    pub async fn predict_with_ml_backend(&self, features: &[f32]) -> Result<MLPredictionResult> {
        debug!("🤖 Running ML backend prediction");

        // Try to find a suitable backend (e.g. threat detection)
        let backend = self
            .backends
            .get("threat_detection")
            .or_else(|| self.backends.values().next())
            .ok_or_else(|| anyhow::anyhow!("No ML backends available"))?;

        // Run inference
        let predictions = backend.predict(features)?;

        // Extract primary prediction
        let risk_score = predictions.first().copied().unwrap_or(0.0);
        let confidence = predictions.get(1).copied().unwrap_or(0.8);

        // Classify threat level
        let (predicted_class, explanation) = if risk_score < 0.3 {
            ("Low Risk", "Behavioral patterns within normal parameters")
        } else if risk_score < 0.7 {
            (
                "Medium Risk",
                "Some anomalous behavior detected, monitoring recommended",
            )
        } else {
            (
                "High Risk",
                "Significant threat indicators detected, immediate action required",
            )
        };

        // Create prediction result
        Ok(MLPredictionResult {
            id: Uuid::new_v4(),
            model_id: backend.get_model_info().name,
            prediction_type: PredictionType::ThreatDetection,
            input_hash: format!("{:x}", md5::compute(format!("{:?}", features))),
            predicted_class: predicted_class.to_string(),
            confidence: confidence as f64,
            risk_score: risk_score as f64,
            feature_importance: HashMap::new(), // TODO: Implement SHAP values
            explanation: explanation.to_string(),
            timestamp: Utc::now(),
        })
    }

    /// Analyze security events using ML
    pub async fn analyze_events(
        &self,
        events: &[crate::SecurityEvent],
    ) -> Result<MLPredictionResult> {
        debug!("📊 Analyzing {} security events with ML", events.len());

        // Convert events to feature extraction format
        let event_data: Vec<data_pipeline::SecurityEventData> = events
            .iter()
            .map(|e| data_pipeline::SecurityEventData {
                event_type: format!("{:?}", e.event_type),
                timestamp: e.timestamp,
                success: true, // TODO: Extract from event metadata
                data_size: None,
                session_duration: None,
                resource_id: None,
                data: serde_json::Value::Null,
            })
            .collect();

        // Extract features
        let extractor =
            data_pipeline::FeatureExtractor::new(data_pipeline::FeatureConfig::default());
        let features = extractor.extract_behavioral_features(&event_data);

        // Run ML prediction
        self.predict_with_ml_backend(&features.to_array()).await
    }

    /// Train models with new data
    pub async fn train_models(&mut self, training_data: &[MLTrainingData]) -> Result<()> {
        info!("🎓 Training ML models with {} samples", training_data.len());

        let mut trained_models = 0;

        for (id, model) in self.models.iter_mut() {
            if let Some(backend) = self.backends.get_mut(id) {
                match self
                    .training_pipeline
                    .train_model(model, backend.as_mut(), training_data)
                    .await
                {
                    Ok(performance) => {
                        model.performance = performance;
                        model.last_trained = Utc::now();
                        trained_models += 1;
                        debug!("✅ Trained model: {}", id);

                        // Persist model after training
                        let model_file = format!("{}/{}.json", self.config.model_storage_path, id);
                        if let Err(e) = backend.save(&model_file) {
                            warn!("⚠️ Failed to persist model {}: {}", id, e);
                        } else {
                            info!("💾 Persisted trained model {}", id);
                        }
                    }
                    Err(e) => {
                        warn!("⚠️ Training failed for model {}: {}", id, e);
                    }
                }
            }
        }

        self.statistics.training_runs += 1;

        info!(
            "✅ Training completed: {}/{} models trained",
            trained_models,
            self.models.len()
        );
        Ok(())
    }

    /// Add data to training buffer and trigger retraining if threshold met
    pub async fn collect_training_data(&mut self, data: MLTrainingData) -> Result<()> {
        self.training_buffer.push(data);

        // Retrain if we have enough data (e.g. 100 samples)
        if self.training_buffer.len() >= 100 {
            info!("🔄 Training buffer threshold met, triggering retraining");
            let data_to_train = self.training_buffer.clone();
            self.train_models(&data_to_train).await?;
            self.training_buffer.clear();
        }

        Ok(())
    }

    /// Analyze behavioral patterns
    pub async fn analyze_patterns(
        &mut self,
        behavior_data: &[BehavioralDataPoint],
    ) -> Result<Vec<WolfBehavioralPattern>> {
        debug!("🐺 Analyzing wolf behavioral patterns");

        let patterns = self
            .pattern_analyzer
            .analyze_patterns(behavior_data)
            .await?;

        info!("✅ Analyzed {} behavioral patterns", patterns.len());
        Ok(patterns)
    }

    /// Detect anomalies
    pub async fn detect_anomalies(
        &mut self,
        data: &MLInputData,
    ) -> Result<Vec<AnomalyDetectionResult>> {
        debug!("🚨 Detecting anomalies in data");

        let mut anomalies = Vec::new();

        // Use anomaly detection model
        if let Some(model) = self.models.get("anomaly_detection") {
            if model.active {
                match self.inference_engine.detect_anomalies(model, data).await {
                    Ok(detected_anomalies) => {
                        anomalies = detected_anomalies;
                        self.statistics.anomalies_detected += anomalies.len() as u64;
                    }
                    Err(e) => {
                        warn!("⚠️ Anomaly detection failed: {}", e);
                    }
                }
            }
        }

        info!("🚨 Detected {} anomalies", anomalies.len());
        Ok(anomalies)
    }

    /// Predict threats
    pub async fn predict_threats(&mut self, data: &MLInputData) -> Result<Vec<ThreatPrediction>> {
        debug!("🔮 Predicting threats from data");

        let mut predictions = Vec::new();

        // Use threat detection model
        if let Some(model) = self.models.get("threat_detection") {
            if model.active {
                match self.inference_engine.predict_threats(model, data).await {
                    Ok(threat_predictions) => {
                        predictions = threat_predictions;
                        self.statistics.threats_detected += predictions.len() as u64;
                    }
                    Err(e) => {
                        warn!("⚠️ Threat prediction failed: {}", e);
                    }
                }
            }
        }

        info!("🔮 Predicted {} threats", predictions.len());
        Ok(predictions)
    }

    /// Get model performance
    pub fn get_model_performance(&self, model_id: &str) -> Option<&ModelPerformance> {
        self.models.get(model_id).map(|m| &m.performance)
    }

    /// Get statistics
    pub fn get_statistics(&self) -> &MLSecurityStats {
        &self.statistics
    }

    /// Get recent predictions
    pub fn get_recent_predictions(&self) -> &[MLPredictionResult] {
        &self.recent_predictions
    }

    /// Update model performance
    pub fn update_model_performance(&mut self, model_id: &str, performance: ModelPerformance) {
        if let Some(model) = self.models.get_mut(model_id) {
            model.performance = performance;
        }
    }
}

/// ML input data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MLInputData {
    /// Data ID
    pub id: Uuid,
    /// Data type
    pub data_type: String,
    /// Features
    pub features: HashMap<String, serde_json::Value>,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Source
    pub source: String,
}

/// ML training data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MLTrainingData {
    /// Data ID
    pub id: Uuid,
    /// Input features
    pub input_features: HashMap<String, serde_json::Value>,
    /// Expected output (label)
    pub expected_output: String,
    /// Numeric label if applicable
    pub label_index: Option<usize>,
    /// Data quality score
    pub quality_score: f64,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

/// Behavioral data point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralDataPoint {
    /// Peer ID
    pub peer_id: String,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Behavioral features
    pub features: HashMap<String, f64>,
    /// Context
    pub context: HashMap<String, serde_json::Value>,
}

/// Anomaly detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyDetectionResult {
    /// Anomaly ID
    pub id: Uuid,
    /// Anomaly type
    pub anomaly_type: String,
    /// Anomaly score
    pub anomaly_score: f64,
    /// Confidence
    pub confidence: f64,
    /// Description
    pub description: String,
    /// Affected entities
    pub affected_entities: Vec<String>,
    /// Recommended actions
    pub recommended_actions: Vec<String>,
}

/// Threat prediction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatPrediction {
    /// Prediction ID
    pub id: Uuid,
    /// Threat type
    pub threat_type: String,
    /// Probability
    pub probability: f64,
    /// Time horizon
    pub time_horizon: String,
    /// Confidence
    pub confidence: f64,
    /// Risk factors
    pub risk_factors: Vec<String>,
    /// Mitigation recommendations
    pub mitigation: Vec<String>,
    /// External threat intelligence
    pub external_info: Option<ThreatFeedItem>,
}

impl Default for MLSecurityConfig {
    fn default() -> Self {
        Self {
            model_update_interval: 3600, // 1 hour
            training_retention_days: 30,
            thresholds: InferenceThresholds::default(),
            model_config: ModelConfig::default(),
            external_feeds: crate::external_feeds::ExternalFeedsConfig::default(),
            llm_api_url: None,
            backend_config: backends::BackendConfig::default(),
            model_storage_path: "./models".to_string(),
        }
    }
}

impl Default for InferenceThresholds {
    fn default() -> Self {
        Self {
            anomaly_threshold: 0.7,
            threat_threshold: 0.8,
            confidence_threshold: 0.6,
            false_positive_tolerance: 0.1,
        }
    }
}

impl Default for BehavioralModelConfig {
    fn default() -> Self {
        Self {
            window_size: 100,
            features: vec![
                BehavioralFeature::LoginFrequency,
                BehavioralFeature::AccessPatterns,
                BehavioralFeature::TimePatterns,
                BehavioralFeature::ResourceUsage,
            ],
            sensitivity: 0.7,
        }
    }
}

impl Default for NetworkModelConfig {
    fn default() -> Self {
        Self {
            flow_window: 1000,
            protocol_analysis: true,
            traffic_patterns: true,
        }
    }
}

impl Default for ThreatModelConfig {
    fn default() -> Self {
        Self {
            threat_intel_integration: true,
            historical_patterns: true,
            predictive_modeling: true,
        }
    }
}

impl Default for ModelPerformance {
    fn default() -> Self {
        Self {
            accuracy: 0.0,
            precision: 0.0,
            recall: 0.0,
            f1_score: 0.0,
            false_positive_rate: 0.0,
            false_negative_rate: 0.0,
        }
    }
}

impl Default for MLSecurityStats {
    fn default() -> Self {
        Self {
            total_predictions: 0,
            predictions_by_model: HashMap::new(),
            anomalies_detected: 0,
            threats_detected: 0,
            false_positives: 0,
            false_negatives: 0,
            training_runs: 0,
            avg_inference_time_ms: 0.0,
            last_update: Utc::now(),
        }
    }
}
