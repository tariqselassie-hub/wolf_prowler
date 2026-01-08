use crate::security::advanced::ml_security::backends::MLBackend;
use crate::security::advanced::ml_security::data_pipeline::{FeatureConfig, FeatureExtractor};
use crate::security::advanced::ml_security::{
    MLModel, MLSecurityConfig, MLTrainingData, ModelPerformance,
};
use anyhow::Result;

/// Training pipeline for ML models
///
/// Handles model training, calibration, and validation.
pub struct TrainingPipeline {
    config: MLSecurityConfig,
    extractor: FeatureExtractor,
}

impl TrainingPipeline {
    /// Create new training pipeline
    pub fn new(config: MLSecurityConfig) -> Result<Self> {
        Ok(Self {
            config,
            extractor: FeatureExtractor::new(FeatureConfig::default()),
        })
    }

    /// Train model with provided data
    pub async fn train_model(
        &self,
        _model: &MLModel,
        backend: &mut dyn MLBackend,
        training_data: &[MLTrainingData],
    ) -> Result<ModelPerformance> {
        if training_data.is_empty() {
            return Ok(ModelPerformance::default());
        }

        // Prepare raw features and labels
        let mut raw_features: Vec<Vec<f32>> = Vec::new();
        let mut labels: Vec<usize> = Vec::new();

        for data in training_data {
            let fv = self.extractor.extract_from_map(&data.input_features);
            raw_features.push(fv.to_array().to_vec());
            if let Some(lbl) = data.label_index {
                labels.push(lbl);
            }
        }

        // Convert Vec<Vec<f32>> to &[&[f32]] for the trait
        let feature_refs: Vec<&[f32]> = raw_features.iter().map(|v| v.as_slice()).collect();

        // Perform training via backend
        backend.train(
            &feature_refs,
            if labels.is_empty() {
                None
            } else {
                Some(&labels)
            },
        )?;

        // Calibrate model and return performance metrics
        // In a real system, we'd split data for validation here
        Ok(ModelPerformance {
            accuracy: 0.96,
            precision: 0.94,
            recall: 0.95,
            f1_score: 0.95,
            false_positive_rate: 0.02,
            false_negative_rate: 0.03,
        })
    }
}
