// Additional API handler implementations for wolf_server persistence

use crate::AppState;
use axum::{
    extract::{Path, Query, State},
    http::header,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct HistoryQuery {
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(default)]
    offset: i64,
}

fn default_limit() -> i64 {
    100
}

// Historical peer data endpoint
pub async fn get_peers_history(
    State(_state): State<AppState>,
    Query(_query): Query<HistoryQuery>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "error": "Feature temporarily unavailable: Migrating to WolfDb"
    }))
}

// Peer metrics endpoint
pub async fn get_peer_metrics(
    State(_state): State<AppState>,
    Path(_peer_id): Path<String>,
    Query(_query): Query<HistoryQuery>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "error": "Feature temporarily unavailable: Migrating to WolfDb"
    }))
}

// Security alerts history endpoint
pub async fn get_alerts_history(
    State(_state): State<AppState>,
    Query(_query): Query<HistoryQuery>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "error": "Feature temporarily unavailable: Migrating to WolfDb"
    }))
}

// Audit logs endpoint
pub async fn get_audit_logs(
    State(_state): State<AppState>,
    Query(_query): Query<HistoryQuery>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "error": "Feature temporarily unavailable: Migrating to WolfDb"
    }))
}

// Metrics timeline endpoint
pub async fn get_metrics_timeline(
    State(_state): State<AppState>,
    Query(_query): Query<HistoryQuery>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "error": "Feature temporarily unavailable: Migrating to WolfDb"
    }))
}

// CSV export for peers
pub async fn export_peers_csv(State(_state): State<AppState>) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/plain")],
        [(header::CONTENT_DISPOSITION, "")],
        "Feature temporarily unavailable: Migrating to WolfDb".to_string(),
    )
}

// JSON export for peers
pub async fn export_peers_json(State(_state): State<AppState>) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "application/json")],
        [(header::CONTENT_DISPOSITION, "")],
        serde_json::json!({
             "error": "Feature temporarily unavailable: Migrating to WolfDb"
        })
        .to_string(),
    )
}

// CSV export for alerts
pub async fn export_alerts_csv(State(_state): State<AppState>) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/plain")],
        [(header::CONTENT_DISPOSITION, "")],
        "Feature temporarily unavailable: Migrating to WolfDb".to_string(),
    )
}

// CSV export for metrics
pub async fn export_metrics_csv(State(_state): State<AppState>) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/plain")],
        [(header::CONTENT_DISPOSITION, "")],
        "Feature temporarily unavailable: Migrating to WolfDb".to_string(),
    )
}
