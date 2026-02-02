use axum::{
    extract::{FromRef, Query, State},
    http::{header, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::api_middleware::create_cors_layer;
use wolf_db::storage::WolfDbStorage;
use wolf_net::api::{ApiResponse, BroadcastRequest, ConnectPeerRequest, WolfNodeControl};
use wolf_net::peer::{EntityInfo, PeerId};
use wolf_net::wolf_pack::coordinator::CoordinatorMsg;
use wolf_net::wolf_pack::state::WolfState;
pub use wolfsec;
use wolfsec::domain::repositories::AlertRepository;
use wolfsec::infrastructure::persistence::wolf_db_alert_repository::WolfDbAlertRepository;
use wolfsec::WolfSecurity;

/// Shared application state for the Axum server
#[derive(Clone)]
pub struct AppState {
    /// Thread-safe access to the global wolf pack state
    pub wolf_state: Arc<RwLock<WolfState>>,
    /// Thread-safe access to peer metrics
    pub metrics: Arc<RwLock<HashMap<PeerId, EntityInfo>>>,
    /// Handle to send commands back to the WolfNode
    pub control: WolfNodeControl,
    /// Shared storage for the JWT authentication token
    pub auth_token: Arc<RwLock<Option<String>>>,
    /// Handle to the persistence layer
    pub persistence: Option<Arc<RwLock<WolfDbStorage>>>,
    /// The WolfSecurity engine
    pub security: Arc<RwLock<WolfSecurity>>,
}

impl FromRef<AppState> for Arc<RwLock<Option<String>>> {
    fn from_ref(state: &AppState) -> Self {
        state.auth_token.clone()
    }
}

impl FromRef<AppState> for WolfNodeControl {
    fn from_ref(state: &AppState) -> Self {
        state.control.clone()
    }
}

/// DTO for triggering a manual hunt via the dashboard
#[derive(Deserialize)]
pub struct ManualHuntRequest {
    pub target_ip: String,
    pub reason: String,
}

/// Query parameters for fetching alerts history
#[derive(Deserialize)]
pub struct AlertsQuery {
    pub limit: Option<usize>,
}

/// Returns the full WolfState (Role, Prestige, Territories, etc.)
pub async fn get_wolf_state(State(state): State<AppState>) -> impl IntoResponse {
    let wolf_state = state.wolf_state.read().await;
    Json(ApiResponse::success(wolf_state.clone()))
}

/// Returns only the list of active hunts
pub async fn get_active_hunts(State(state): State<AppState>) -> impl IntoResponse {
    let wolf_state = state.wolf_state.read().await;
    Json(ApiResponse::success(wolf_state.active_hunts.clone()))
}

/// Returns metrics for all known peers
pub async fn get_peer_metrics(State(state): State<AppState>) -> impl IntoResponse {
    let metrics = state.metrics.read().await;
    // Convert HashMap to a Vec or simpler Map for JSON serialization if needed,
    // but EntityInfo is already serializable.
    Json(ApiResponse::success(metrics.clone()))
}

/// Triggers a manual hunt (Kill Order) from the dashboard
pub async fn trigger_manual_hunt(
    State(state): State<AppState>,
    Json(payload): Json<ManualHuntRequest>,
) -> impl IntoResponse {
    let hunt_id = format!("manual-{}", uuid::Uuid::new_v4());

    let msg = CoordinatorMsg::KillOrder {
        target_ip: payload.target_ip,
        authorizer: PeerId::random(), // Conceptual placeholder
        reason: payload.reason,
        hunt_id,
    };

    match state.control.send_coordinator_msg(msg).await {
        Ok(_) => (StatusCode::ACCEPTED, Json(ApiResponse::<()>::success(()))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::<()>::error(e.to_string())),
        ),
    }
}

/// Returns historical security alerts from the persistence layer
pub async fn get_alerts_history(
    State(state): State<AppState>,
    Query(query): Query<AlertsQuery>,
) -> Response {
    let storage = match &state.persistence {
        Some(s) => s.clone(),
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiResponse::<()>::error("Persistence not enabled")),
            )
                .into_response()
        }
    };

    let repository = WolfDbAlertRepository::new(storage);
    let limit = query.limit.unwrap_or(100);

    match repository.get_recent_alerts(limit).await {
        Ok(alerts) => Json(ApiResponse::success(alerts)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::<Vec<wolfsec::domain::entities::Alert>>::error(
                e.to_string(),
            )),
        )
            .into_response(),
    }
}

/// Middleware to validate the JWT token against the one stored in WolfNode
async fn auth_middleware(
    State(auth_token): State<Arc<RwLock<Option<String>>>>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, impl IntoResponse> {
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or((
            StatusCode::UNAUTHORIZED,
            Json(ApiResponse::<()>::error("Missing Authorization header")),
        ))?;

    let token = auth_header.strip_prefix("Bearer ").ok_or((
        StatusCode::UNAUTHORIZED,
        Json(ApiResponse::<()>::error("Invalid token format")),
    ))?;

    let stored_token_lock = auth_token.read().await;
    let stored_token = stored_token_lock.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        Json(ApiResponse::<()>::error(
            "Authentication token not yet initialized",
        )),
    ))?;

    if token == stored_token {
        Ok(next.run(req).await)
    } else {
        Err((
            StatusCode::UNAUTHORIZED,
            Json(ApiResponse::<()>::error("Invalid token")),
        ))
    }
}

/// --- Legacy Handlers from main.rs ---

pub async fn status_handler() -> Json<ApiResponse<&'static str>> {
    Json(ApiResponse::success("WolfNode is running"))
}

pub async fn connect_peer_handler(
    State(control): State<WolfNodeControl>,
    Json(req): Json<ConnectPeerRequest>,
) -> Json<ApiResponse<String>> {
    match control.connect_peer(req.multiaddr).await {
        Ok(_) => Json(ApiResponse::success("Connection initiated".to_string())),
        Err(e) => Json(ApiResponse::error(e.to_string())),
    }
}

pub async fn broadcast_handler(
    State(control): State<WolfNodeControl>,
    Json(req): Json<BroadcastRequest>,
) -> Json<ApiResponse<String>> {
    match control.broadcast(req.message.into_bytes()).await {
        Ok(_) => Json(ApiResponse::success("Broadcast initiated".to_string())),
        Err(e) => Json(ApiResponse::error(e.to_string())),
    }
}

pub async fn shutdown_handler(State(control): State<WolfNodeControl>) -> Json<ApiResponse<String>> {
    match control.shutdown().await {
        Ok(_) => Json(ApiResponse::success("Shutdown initiated".to_string())),
        Err(e) => Json(ApiResponse::error(e.to_string())),
    }
}

/// Configures the API routes
pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/api/wolf/state", get(get_wolf_state))
        .route("/api/wolf/hunts", get(get_active_hunts))
        .route("/api/peers/metrics", get(get_peer_metrics))
        .route("/api/wolf/hunts/trigger", post(trigger_manual_hunt))
        .route("/api/v1/alerts/history", get(get_alerts_history))
        .route("/api/v1/status", get(status_handler))
        .route("/api/v1/peers/connect", post(connect_peer_handler))
        .route("/api/v1/messages/broadcast", post(broadcast_handler))
        .route("/api/v1/system/shutdown", post(shutdown_handler))
        .layer(create_cors_layer())
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .with_state(state)
}
