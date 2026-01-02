// Threat Classifier backend for classifying security threats using ML

use super::{MLBackend, ModelInfo};
use anyhow::Result;

pub struct ThreatClassifier {
    // Labels for the classifier output
    pub labels: Vec<String>,
}

impl ThreatClassifier {
    pub fn new() -> Self {
        ThreatClassifier {
            labels: vec![
                "Normal".to_string(),
                "BruteForce".to_string(),
                "DDoS".to_string(),
                "Malware".to_string(),
                "Recon".to_string(),
                "Exfiltration".to_string(),
            ],
        }
    }

    pub fn classify_threat(&self, data: &[f64]) -> (String, f64) {
        // Logic for stub: map features to threat classes
        // In a real implementation, this would use a Random Forest or Neural Network

        let failed_attempts = data.get(1).copied().unwrap_or(0.0);
        let network_out = data.get(4).copied().unwrap_or(0.0);
        let port_scan = data.get(5).copied().unwrap_or(0.0);
        let exfil_score = data.get(13).copied().unwrap_or(0.0);

        if failed_attempts > 0.8 {
            ("BruteForce".to_string(), 0.92)
        } else if port_scan > 0.7 {
            ("Recon".to_string(), 0.88)
        } else if exfil_score > 0.6 || network_out > 0.9 {
            ("Exfiltration".to_string(), 0.85)
        } else if network_out > 0.7 {
            ("DDoS".to_string(), 0.80)
        } else {
            ("Normal".to_string(), 0.95)
        }
    }
}

impl MLBackend for ThreatClassifier {
    fn predict(&self, input: &[f32]) -> Result<Vec<f64>> {
        let (class_name, confidence) =
            self.classify_threat(&input.iter().map(|&x| x as f64).collect::<Vec<f64>>());

        // Find index of class
        let class_idx = self
            .labels
            .iter()
            .position(|l| l == &class_name)
            .unwrap_or(0) as f64;

        let risk_score = if class_name == "Normal" { 0.0 } else { 0.8 };

        Ok(vec![risk_score, confidence, class_idx])
    }

    fn get_model_info(&self) -> ModelInfo {
        ModelInfo {
            name: "ThreatClassifier".to_string(),
            version: "1.1-heuristic-supervised".to_string(),
        }
    }

    fn train(
        &mut self,
        _training_data: &[&[f32]],
        _labels: Option<&[usize]>,
    ) -> Result<(), anyhow::Error> {
        // Supervised training stub: in a real implementation, this would train a model on labeled data
        // For now, we assume the heuristic remains static or labels are updated
        Ok(())
    }

    fn save(&self, path: &str) -> Result<(), anyhow::Error> {
        let json = serde_json::json!({ "labels": self.labels });
        std::fs::write(path, json.to_string())?;
        Ok(())
    }

    fn load(&mut self, path: &str) -> Result<(), anyhow::Error> {
        let content = std::fs::read_to_string(path)?;
        let json: serde_json::Value = serde_json::from_str(&content)?;
        if let Some(l) = json.get("labels").and_then(|v| v.as_array()) {
            self.labels = l
                .iter()
                .filter_map(|v| v.as_str())
                .map(|s| s.to_string())
                .collect();
        }
        Ok(())
    }
}
