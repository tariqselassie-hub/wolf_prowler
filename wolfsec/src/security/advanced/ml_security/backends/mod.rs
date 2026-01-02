#[cfg(feature = "ml-classical")]
pub mod isolation_forest;
#[cfg(feature = "ml-onnx")]
pub mod onnx_backend;
#[cfg(feature = "ml-classical")]
pub mod threat_classifier;

use serde::{Deserialize, Serialize};

/// Configuration for ML backends
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BackendConfig {
    /// Backend type
    pub backend_type: String,
    /// Model path
    pub model_path: Option<String>,
}

/// Model information
#[derive(Debug, Clone)]
pub struct ModelInfo {
    pub name: String,
    pub version: String,
}

/// Trait for ML backends
pub trait MLBackend: Send + Sync {
    /// Run inference on input data
    fn predict(&self, input: &[f32]) -> Result<Vec<f64>, anyhow::Error>;
    /// Get model information
    fn get_model_info(&self) -> ModelInfo;
    /// Train the model on data
    fn train(
        &mut self,
        training_data: &[&[f32]],
        labels: Option<&[usize]>,
    ) -> Result<(), anyhow::Error>;
    /// Save model to disk
    fn save(&self, path: &str) -> Result<(), anyhow::Error>;
    /// Load model from disk
    fn load(&mut self, path: &str) -> Result<(), anyhow::Error>;
}

/// Create a backend based on configuration
pub fn create_backend(config: &BackendConfig) -> Result<Box<dyn MLBackend>, anyhow::Error> {
    match config.backend_type.as_str() {
        #[cfg(feature = "ml-classical")]
        "isolation_forest" => Ok(Box::new(isolation_forest::IsolationForest::new())),
        #[cfg(feature = "ml-classical")]
        "threat_classifier" => Ok(Box::new(threat_classifier::ThreatClassifier::new())),
        #[cfg(feature = "ml-onnx")]
        "onnx" => {
            let path = config
                .model_path
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Model path required for onnx backend"))?;
            Ok(Box::new(onnx_backend::OnnxBackend::new(
                path,
                "WolfOnnxModel".to_string(),
            )?))
        }
        _ => Err(anyhow::anyhow!(
            "Unknown backend type: {}",
            config.backend_type
        )),
    }
}
