//! ML Prediction API Endpoint
//!
//! Provides REST API for ML-powered threat detection

use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::dashboard::state::AppState;

/// ML prediction request
#[derive(Debug, Deserialize)]
pub struct MLPredictionRequest {
    /// Feature vector (20 dimensions)
    pub features: Vec<f32>,
    /// Optional model override
    pub model_id: Option<String>,
}

/// ML prediction response
#[derive(Debug, Serialize)]
pub struct MLPredictionResponse {
    pub success: bool,
    pub prediction: Option<PredictionData>,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct PredictionData {
    pub risk_score: f64,
    pub confidence: f64,
    pub predicted_class: String,
    pub explanation: String,
    pub model_id: String,
    pub timestamp: String,
}

/// API: Run ML prediction
pub async fn api_v1_ml_predict(
    State(state): State<AppState>,
    Json(request): Json<MLPredictionRequest>,
) -> Json<serde_json::Value> {
    let ml_engine = state.security_manager.get_ml_engine();

    // Validate input
    if request.features.is_empty() {
        return Json(json!({
            "success": false,
            "message": "Feature vector cannot be empty"
        }));
    }

    if request.features.len() != 20 {
        return Json(json!({
            "success": false,
            "message": format!("Expected 20 features, got {}", request.features.len())
        }));
    }

    // Run prediction
    match ml_engine.predict_with_ml_backend(&request.features).await {
        Ok(result) => Json(json!({
            "success": true,
            "prediction": {
                "risk_score": result.risk_score,
                "confidence": result.confidence,
                "predicted_class": result.predicted_class,
                "explanation": result.explanation,
                "model_id": result.model_id,
                "timestamp": result.timestamp.to_rfc3339(),
            }
        })),
        Err(e) => Json(json!({
            "success": false,
            "message": format!("Prediction failed: {}", e)
        })),
    }
}

/// API: Get ML model status
pub async fn api_v1_ml_status(State(state): State<AppState>) -> Json<serde_json::Value> {
    let ml_engine = state.security_manager.get_ml_engine();
    let config = ml_engine.get_config();

    // Get backend info
    let backend_info = match wolfsec::security::advanced::ml_security::backends::create_backend(
        &config.backend_config,
    ) {
        Ok(backend) => {
            let info = backend.get_model_info();
            json!({
                "backend": backend.backend_name(),
                "model_name": info.name,
                "model_version": info.version,
                "input_shape": info.input_shape,
                "output_shape": info.output_shape,
                "loaded": !info.name.is_empty() && info.name != "Unloaded",
            })
        }
        Err(e) => json!({
            "backend": "error",
            "error": format!("{}", e),
            "loaded": false,
        }),
    };

    Json(json!({
        "success": true,
        "ml_enabled": true,
        "backend_config": {
            "type": format!("{:?}", config.backend_config.backend_type),
            "device": format!("{:?}", config.backend_config.device),
            "model_path": config.backend_config.model_path,
        },
        "backend_info": backend_info,
        "thresholds": {
            "anomaly": config.thresholds.anomaly_threshold,
            "threat": config.thresholds.threat_threshold,
            "confidence": config.thresholds.confidence_threshold,
        }
    }))
}

/// API: Analyze security events with ML
#[derive(Debug, Deserialize)]
pub struct MLAnalyzeRequest {
    /// Security event IDs to analyze
    pub event_ids: Vec<String>,
}

pub async fn api_v1_ml_analyze(
    State(_state): State<AppState>,
    Json(_request): Json<MLAnalyzeRequest>,
) -> Json<serde_json::Value> {
    // TODO: Implement event analysis
    // This would:
    // 1. Fetch events from event store
    // 2. Extract features
    // 3. Run ML prediction
    // 4. Return analysis results

    Json(json!({
        "success": false,
        "message": "Event analysis not yet implemented"
    }))
}
