//! Container Security API Endpoints
//!
//! This module provides API endpoints for monitoring and managing
//! Docker/Wolf Den containers.

use axum::extract::State;
use axum::{
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::dashboard::api::ApiError;
use crate::dashboard::state::AppState;

/// Container information response
#[derive(Debug, Serialize, Deserialize)]
pub struct ContainerInfo {
    /// Unique identifier for the container
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Operational status (e.g., Up, Down)
    pub status: String,
    /// Detailed state (e.g., running, exited)
    pub state: String,
    /// Security rank/level assigned to the container
    pub security_rank: String,
    /// When the container was created
    pub created_at: String,
}

/// Create containers router
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(list_containers))
        .route("/:id/scan", post(scan_container))
        .route("/:id/isolate", post(isolate_container))
        .with_state(state)
}

/// List all containers
async fn list_containers(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<ContainerInfo>>, ApiError> {
    state.increment_request_count().await;

    let mut result = Vec::new();

    if let Some(wolf_security_arc) = state.get_wolf_security() {
        let security = wolf_security_arc.read().await;
        if let Ok(containers) = security.container_manager.list_running_containers().await {
            for c in containers {
                result.push(ContainerInfo {
                    id: c.id,
                    name: c.name,
                    status: c.status,
                    state: c.state,
                    security_rank: format!("{:?}", c.security_level),
                    created_at: c.created_at.to_rfc3339(),
                });
            }
        }
    }

    Ok(Json(result))
}

/// Scan a container
async fn scan_container(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state.increment_request_count().await;

    if let Some(wolf_security_arc) = state.get_wolf_security() {
        let security = wolf_security_arc.read().await;
        match security.container_manager.scan_container(&id).await {
            Ok(access) => {
                return Ok(Json(serde_json::json!({
                    "success": true,
                    "access_granted": access.access_granted,
                    "reason": access.reason,
                    "risk_rank": format!("{:?}", access.pack_rank)
                })));
            }
            Err(e) => return Err(ApiError::InternalError(format!("Scan failed: {}", e))),
        }
    }

    Err(ApiError::InternalError(
        "Security engine not available".to_string(),
    ))
}

/// Isolate a container
async fn isolate_container(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state.increment_request_count().await;

    if let Some(wolf_security_arc) = state.get_wolf_security() {
        let security = wolf_security_arc.read().await;
        match security.container_manager.isolate_container(&id).await {
            Ok(_) => {
                return Ok(Json(serde_json::json!({
                    "success": true,
                    "message": format!("Container {} isolated successfully", id)
                })));
            }
            Err(e) => return Err(ApiError::InternalError(format!("Isolation failed: {}", e))),
        }
    }

    Err(ApiError::InternalError(
        "Security engine not available".to_string(),
    ))
}
