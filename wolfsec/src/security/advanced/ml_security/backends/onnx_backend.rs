use super::{MLBackend, ModelInfo};
use anyhow::{Context, Result};
use ort::session::builder::GraphOptimizationLevel;
use ort::session::{Session, SessionInputs};
// use ort::value::Value;
use std::path::Path;

/// Wrapper around the ONNX Runtime session
pub struct OnnxBackend {
    session: Session,
    model_name: String,
}

impl OnnxBackend {
    /// Initialize a new ONNX session from a model file
    pub fn new(model_path: impl AsRef<Path>, model_name: String) -> Result<Self> {
        let session = Session::builder()?
            .with_optimization_level(GraphOptimizationLevel::Level3)?
            .with_intra_threads(4)?
            .commit_from_file(model_path)
            .context("Failed to load ONNX model")?;

        Ok(Self {
            session,
            model_name,
        })
    }

    /// Access the underlying session for inference
    pub fn session(&self) -> &Session {
        &self.session
    }
}

impl MLBackend for OnnxBackend {
    fn predict(&self, _input: &[f32]) -> Result<Vec<f64>> {
        // Placeholder for actual ONNX inference logic
        // This would involve creating an ort::Value from input, running the session,
        // and extracting the output floats.
        Ok(vec![0.0, 0.8]) // Default values
    }

    fn get_model_info(&self) -> ModelInfo {
        ModelInfo {
            name: self.model_name.clone(),
            version: "1.0-onnx".to_string(),
        }
    }

    fn train(
        &mut self,
        _training_data: &[&[f32]],
        _labels: Option<&[usize]>,
    ) -> Result<(), anyhow::Error> {
        Err(anyhow::anyhow!(
            "Training not supported for ONNX backend in this phase"
        ))
    }

    fn save(&self, _path: &str) -> Result<(), anyhow::Error> {
        Err(anyhow::anyhow!(
            "Saving not supported for ONNX backend in this phase (already persistent)"
        ))
    }

    fn load(&mut self, path: &str) -> Result<(), anyhow::Error> {
        let session = Session::builder()?
            .with_optimization_level(GraphOptimizationLevel::Level3)?
            .with_intra_threads(4)?
            .commit_from_file(path)
            .context("Failed to reload ONNX model")?;

        self.session = session;
        Ok(())
    }
}
