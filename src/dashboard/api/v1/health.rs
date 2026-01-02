use axum::Json;
use serde_json::json;

pub async fn health_ok() -> Json<serde_json::Value> {
    Json(json!({"status":"ok"}))
}
