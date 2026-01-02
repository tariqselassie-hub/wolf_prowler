use crate::external_feeds::{enrich_threat, ThreatFeedItem};
use crate::security::advanced::ml_security::backends;
use crate::security::advanced::ml_security::data_pipeline::{FeatureConfig, FeatureExtractor};
use crate::security::advanced::ml_security::{
    AnomalyDetectionResult, MLInputData, MLModel, MLPredictionResult, MLSecurityConfig,
    PredictionType, ThreatPrediction,
};
use anyhow::Result;
use chrono::Utc;
use serde_json::json;
use std::collections::HashMap;
use uuid::Uuid;

pub struct InferenceEngine {
    config: MLSecurityConfig,
    client: reqwest::Client,
    extractor: FeatureExtractor,
}

impl InferenceEngine {
    pub fn new(config: MLSecurityConfig) -> Result<Self> {
        Ok(Self {
            config,
            client: reqwest::Client::new(),
            extractor: FeatureExtractor::new(FeatureConfig::default()),
        })
    }

    pub fn extractor(&self) -> &FeatureExtractor {
        &self.extractor
    }

    pub async fn predict(&self, model: &MLModel, data: &MLInputData) -> Result<MLPredictionResult> {
        // 1. Try real ML backend if available
        if let Ok(backend) = backends::create_backend(&self.config.backend_config) {
            // Convert HashMap features to fixed-size array
            let fv = self.extractor.extract_from_map(&data.features);
            let features = fv.to_array();

            if let Ok(predictions) = backend.predict(&features) {
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

                return Ok(MLPredictionResult {
                    id: Uuid::new_v4(),
                    model_id: model.id.clone(),
                    prediction_type: PredictionType::RiskAssessment,
                    input_hash: md5::compute(format!("{:?}", data.features)),
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
                });
            }
        }

        // 2. Fallback: Heuristic-based risk scoring (enhanced with LLM if enabled)
        let mut risk_score: f64 = 0.0;
        let mut explanation = "Behavior appears normal.".to_string();
        let mut feature_importance = HashMap::new();

        // Check if LLM is enabled
        if let Some(llm_url) = &self.config.llm_api_url {
            let prompt = format!(
                "Analyze the following security event features and determine if it represents a threat. Return a JSON object with 'risk_score' (0.0-1.0), 'explanation', and 'predicted_class' (Normal, Suspicious, Threat).\n\nFeatures: {:?}\n\nResponse:",
                data.features
            );

            if let Ok(llm_response) = self.call_llm(llm_url, "llama3", &prompt).await {
                explanation = format!("AI Analysis: {}", llm_response);
            }
        }

        // Basic heuristics as a robust fallback
        if let Some(val) = data
            .features
            .get("login_frequency")
            .and_then(|v| v.as_f64())
        {
            if val > 10.0 {
                risk_score += 0.3;
                feature_importance.insert("login_frequency".to_string(), 0.8);
                explanation = "High login frequency detected.".to_string();
            }
        }

        if let Some(failed) = data
            .features
            .get("failed_attempts")
            .and_then(|v| v.as_f64())
        {
            if failed > 5.0 {
                risk_score += 0.5;
                feature_importance.insert("failed_attempts".to_string(), 0.9);
                explanation = "Multiple failed login attempts detected.".to_string();
            }
        }

        let predicted_class = if risk_score > 0.7 {
            "Threat".to_string()
        } else if risk_score > 0.3 {
            "Suspicious".to_string()
        } else {
            "Normal".to_string()
        };

        Ok(MLPredictionResult {
            id: Uuid::new_v4(),
            model_id: model.id.clone(),
            prediction_type: PredictionType::RiskAssessment,
            input_hash: md5::compute(format!("{:?}", data.features)),
            predicted_class,
            confidence: 0.85,
            risk_score: risk_score.min(1.0f64),
            feature_importance,
            explanation,
            timestamp: Utc::now(),
        })
    }

    pub async fn detect_anomalies(
        &self,
        _model: &MLModel,
        data: &MLInputData,
    ) -> Result<Vec<AnomalyDetectionResult>> {
        let mut anomalies = Vec::new();

        // Check for anomalies using IsolationForest backend
        let mut backend_config = self.config.backend_config.clone();
        backend_config.backend_type = "isolation_forest".to_string();

        if let Ok(backend) = backends::create_backend(&backend_config) {
            let fv = self.extractor.extract_from_map(&data.features);
            let features = fv.to_array();

            if let Ok(predictions) = backend.predict(&features) {
                let anomaly_score = predictions.first().copied().unwrap_or(0.0);
                let is_anomaly = predictions.get(2).copied().unwrap_or(0.0) > 0.5;

                if is_anomaly {
                    anomalies.push(AnomalyDetectionResult {
                        id: Uuid::new_v4(),
                        anomaly_type: "BehavioralAnomaly".to_string(),
                        anomaly_score,
                        confidence: 0.88,
                        description: format!(
                            "ML-detected behavioral anomaly. Score: {:.2}",
                            anomaly_score
                        ),
                        affected_entities: vec![data.source.clone()],
                        recommended_actions: vec![
                            "Examine peer communication logs".to_string(),
                            "Verify identity with challenge-response".to_string(),
                        ],
                    });
                }
            }
        }

        // Heuristic fallback
        if let Some(usage) = data.features.get("cpu_usage").and_then(|v| v.as_f64()) {
            if usage > 90.0 {
                anomalies.push(AnomalyDetectionResult {
                    id: Uuid::new_v4(),
                    anomaly_type: "ResourceSpike".to_string(),
                    anomaly_score: 0.85,
                    confidence: 0.9,
                    description: format!("Abnormal CPU usage detected: {:.1}%", usage),
                    affected_entities: vec![data.source.clone()],
                    recommended_actions: vec![
                        "Investigate process list".to_string(),
                        "Check for malware".to_string(),
                    ],
                });
            }
        }

        Ok(anomalies)
    }

    pub async fn predict_threats(
        &self,
        _model: &MLModel,
        data: &MLInputData,
    ) -> Result<Vec<ThreatPrediction>> {
        let mut threats = Vec::new();

        // Check for threats using ThreatClassifier backend
        let mut backend_config = self.config.backend_config.clone();
        backend_config.backend_type = "threat_classifier".to_string();

        if let Ok(backend) = backends::create_backend(&backend_config) {
            let fv = self.extractor.extract_from_map(&data.features);
            let features = fv.to_array();

            if let Ok(predictions) = backend.predict(&features) {
                let risk_score = predictions.first().copied().unwrap_or(0.0);
                let class_idx = predictions.get(2).copied().unwrap_or(0.0) as usize;

                // BruteForce (1), DDoS (2), Malware (3), Recon (4), Exfiltration (5)
                if risk_score > 0.5 {
                    let threat_type = match class_idx {
                        1 => "BruteForce",
                        2 => "DDoS",
                        3 => "Malware",
                        4 => "Recon",
                        5 => "Exfiltration",
                        _ => "GenericThreat",
                    };

                    threats.push(ThreatPrediction {
                        id: Uuid::new_v4(),
                        threat_type: threat_type.to_string(),
                        probability: risk_score,
                        time_horizon: "Immediate".to_string(),
                        confidence: 0.85,
                        risk_factors: vec![format!("ML Classification Score: {:.2}", risk_score)],
                        mitigation: vec![
                            "Restrict network access".to_string(),
                            "Rotate credentials".to_string(),
                        ],
                        external_info: None,
                    });
                }
            }
        }

        // Heuristic fallback for brute force
        if let Some(failed) = data
            .features
            .get("failed_attempts")
            .and_then(|v| v.as_f64())
        {
            if failed > 10.0 {
                threats.push(ThreatPrediction {
                    id: Uuid::new_v4(),
                    threat_type: "BruteForce".to_string(),
                    probability: 0.92,
                    time_horizon: "Immediate".to_string(),
                    confidence: 0.88,
                    risk_factors: vec![
                        "Source IP rotation".to_string(),
                        "Common username attempts".to_string(),
                    ],
                    mitigation: vec!["Block IP".to_string(), "Enable MFA".to_string()],
                    external_info: None,
                });
            }
        }

        // Check for external threat intelligence (CVEs, File Hashes)
        let mut potential_id = None;
        if let Some(cve) = data.features.get("cve_id").and_then(|v| v.as_str()) {
            potential_id = Some(cve.to_string());
        } else if let Some(hash) = data.features.get("file_hash").and_then(|v| v.as_str()) {
            potential_id = Some(hash.to_string());
        }

        if let Some(id) = potential_id {
            let mut feed_item = ThreatFeedItem {
                id: id.clone(),
                title: String::new(),
                description: None,
                severity: None,
                source: "Unknown".to_string(),
                raw: serde_json::Value::Null,
            };

            if (enrich_threat(&mut feed_item, &self.config.external_feeds).await).is_ok() {
                if !feed_item.title.is_empty() {
                    threats.push(ThreatPrediction {
                        id: Uuid::new_v4(),
                        threat_type: "External Intelligence".to_string(),
                        probability: 0.99,
                        time_horizon: "Immediate".to_string(),
                        confidence: 0.95,
                        risk_factors: vec!["Known Vulnerability/Malware".to_string()],
                        mitigation: vec!["Isolate and Remediate".to_string()],
                        external_info: Some(feed_item),
                    });
                }
            }
        }

        Ok(threats)
    }

    async fn call_llm(&self, url: &str, model: &str, prompt: &str) -> Result<String> {
        let payload = json!({
            "model": model,
            "prompt": prompt,
            "stream": false
        });

        let res = self
            .client
            .post(url)
            .json(&payload)
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        if let Some(text) = res.get("response").and_then(|v| v.as_str()) {
            Ok(text.to_string())
        } else {
            Ok(res.to_string())
        }
    }

    pub async fn process_command(
        &self,
        command: &str,
        override_url: Option<String>,
    ) -> Result<String> {
        let url = override_url.or_else(|| self.config.llm_api_url.clone());

        if url.is_none() {
            return Ok(
                "AI module is not configured. Please set the LLM API URL in settings.".to_string(),
            );
        }

        let system_prompt =
            if let Ok(mut content) = tokio::fs::read_to_string("llama_directive.md").await {
                content.push_str("\n\n");
                content
            } else {
                "You are Wolf, an advanced AI security assistant for the Wolf Prowler system.\n"
                    .to_string()
            };

        let full_prompt = format!("{}User: {}\nWolf:", system_prompt, command);

        let response = self
            .call_llm(url.as_deref().unwrap(), "llama3", &full_prompt)
            .await?;
        Ok(response)
    }

    pub async fn test_connection(&self, override_url: Option<String>) -> Result<bool> {
        let url = override_url.or_else(|| self.config.llm_api_url.clone());

        if let Some(api_url) = url {
            let base_url = api_url.replace("/api/generate", "");
            let tags_url = format!("{}/api/tags", base_url);

            let res = self.client.get(&tags_url).send().await;

            match res {
                Ok(response) => Ok(response.status().is_success()),
                Err(_) => Ok(false),
            }
        } else {
            Ok(false)
        }
    }
}

mod md5 {
    use sha2::{Digest, Sha256};
    pub fn compute(data: impl AsRef<[u8]>) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }
}
