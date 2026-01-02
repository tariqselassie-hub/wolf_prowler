use axum::{extract::State, Json};
use std::sync::Arc;

use crate::dashboard::AppState;

pub async fn get_peers(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let stats = state.swarm_manager.get_stats().await.unwrap_or_default();
    Json(serde_json::json!({"peers": stats.connected_peers_list}))
}
