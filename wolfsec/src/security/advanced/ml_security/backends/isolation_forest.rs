// Isolation Forest backend for anomaly detection in security contexts

use super::{MLBackend, ModelInfo};
use anyhow::Result;

pub struct IsolationForest {
    threshold: f64,
}

impl IsolationForest {
    pub fn new() -> Self {
        IsolationForest { threshold: 0.7 }
    }

    pub fn detect_anomaly(&self, data: &[f64]) -> (bool, f64) {
        // Simple logic for stub: check if features are outside expected ranges
        // In a real implementation, this would use linfa-clustering or a pre-trained model
        let mut anomaly_score = 0.0;

        // Example: high failed attempts and high entropy together are very suspicious
        if data.get(1).map_or(false, |&f| f > 0.5) && data.get(18).map_or(false, |&e| e > 0.6) {
            anomaly_score += 0.5;
        }

        // Unusual protocol behavior
        if data.get(8).map_or(false, |&p| p > 0.7) {
            anomaly_score += 0.3;
        }

        (anomaly_score > self.threshold, anomaly_score)
    }
}

impl MLBackend for IsolationForest {
    fn predict(&self, input: &[f32]) -> Result<Vec<f64>> {
        let (anomaly, score) =
            self.detect_anomaly(&input.iter().map(|&x| x as f64).collect::<Vec<f64>>());
        Ok(vec![score, 0.85, if anomaly { 1.0 } else { 0.0 }]) // score, confidence, is_anomaly
    }

    fn get_model_info(&self) -> ModelInfo {
        ModelInfo {
            name: "IsolationForest".to_string(),
            version: "1.1-heuristic-trainable".to_string(),
        }
    }

    fn train(
        &mut self,
        training_data: &[&[f32]],
        _labels: Option<&[usize]>,
    ) -> Result<(), anyhow::Error> {
        if training_data.is_empty() {
            return Ok(());
        }

        // Simple unsupervised adjustment: calibrate threshold based on training data "normality"
        let mut total_score = 0.0;
        for data in training_data {
            let (_, score) =
                self.detect_anomaly(&data.iter().map(|&x| x as f64).collect::<Vec<f64>>());
            total_score += score;
        }

        let avg_score = total_score / training_data.len() as f64;
        self.threshold = (self.threshold + avg_score * 1.5) / 2.0; // Smooth adjustment

        Ok(())
    }

    fn save(&self, path: &str) -> Result<(), anyhow::Error> {
        let json = serde_json::json!({ "threshold": self.threshold });
        std::fs::write(path, json.to_string())?;
        Ok(())
    }

    fn load(&mut self, path: &str) -> Result<(), anyhow::Error> {
        let content = std::fs::read_to_string(path)?;
        let json: serde_json::Value = serde_json::from_str(&content)?;
        if let Some(t) = json.get("threshold").and_then(|v| v.as_f64()) {
            self.threshold = t;
        }
        Ok(())
    }
}
