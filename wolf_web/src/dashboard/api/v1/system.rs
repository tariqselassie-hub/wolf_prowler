//! System Administration API Endpoints
//!
//! This module provides API endpoints for system administration including
//! Wolf Pack hierarchy management, prestige system, and Omega controls.

use axum::extract::State;
use axum::{routing::get, Json, Router};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::dashboard::state::AppState;

/// System status response
#[derive(Debug, Serialize, Deserialize)]
pub struct SystemStatusResponse {
    /// Pack members count
    pub pack_members: usize,
    /// Active pack members
    pub active_pack: usize,
    /// Prestige pool
    pub prestige_pool: u64,
    /// Decay rate per minute
    pub decay_rate: f64,
    /// Omega status
    pub omega_status: String,
    /// Omega controls count
    pub omega_controls: usize,
}

/// Pack member information
#[derive(Debug, Serialize, Deserialize)]
pub struct PackMember {
    /// Peer ID
    pub peer_id: String,
    /// Current role
    pub role: String,
    /// Prestige score
    pub prestige: u64,
    /// Role rank
    pub rank: u8,
    /// Last activity
    pub last_activity: String,
}

/// Hierarchy distribution
#[derive(Debug, Serialize, Deserialize)]
pub struct HierarchyDistribution {
    /// Stray count
    pub stray: usize,
    /// Scout count
    pub scout: usize,
    /// Hunter count
    pub hunter: usize,
    /// Beta count
    pub beta: usize,
    /// Alpha count
    pub alpha: usize,
    /// Omega count
    pub omega: usize,
}

/// Prestige metrics
#[derive(Debug, Serialize, Deserialize)]
pub struct PrestigeMetrics {
    /// Total prestige in system
    pub total_prestige: u64,
    /// Average prestige per member
    pub average_prestige: f64,
    /// Prestige gained today
    pub gained_today: u64,
    /// Prestige decayed today
    pub decayed_today: u64,
}

/// Administrative action
#[derive(Debug, Serialize, Deserialize)]
pub struct AdminAction {
    /// Action ID
    pub action_id: String,
    /// Action type
    pub action_type: String,
    /// Target peer
    pub target_peer: String,
    /// Action description
    pub description: String,
    /// Timestamp
    pub timestamp: String,
    /// Status
    pub status: String,
}

/// Create system router
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/status", get(get_system_status))
        .route("/pack", get(get_pack_members))
        .route("/hierarchy", get(get_hierarchy))
        .route("/prestige", get(get_prestige_metrics))
        .route("/actions", get(get_admin_actions))
        .with_state(state)
}

/// Get system status
async fn get_system_status(State(state): State<Arc<AppState>>) -> Json<SystemStatusResponse> {
    state.increment_request_count().await;

    // Get real system data from threat engine
    let threat_engine = state.threat_engine.lock().await;
    let status = threat_engine.get_status().await;

    // Get pack hierarchy data from reputation system
    let reputation_system = threat_engine.reputation_system();
    let pack_members = reputation_system.peer_count().await;
    let active_pack = reputation_system.active_peer_count().await;

    Json(SystemStatusResponse {
        pack_members,
        active_pack,
        prestige_pool: 0,                   // Not available in metrics
        decay_rate: 0.0,                    // Not available in metrics
        omega_status: "Active".to_string(), // Would get from actual Omega status
        omega_controls: 0,                  // Not available in metrics
    })
}

/// Get pack members
async fn get_pack_members(State(state): State<Arc<AppState>>) -> Json<Vec<PackMember>> {
    state.increment_request_count().await;

    // Get real pack member data from reputation system
    let threat_engine = state.threat_engine.lock().await;
    let reputation_system = threat_engine.reputation_system();
    let members = reputation_system.get_pack_members().await;

    let member_info: Vec<PackMember> = members
        .into_iter()
        .map(|member_id| PackMember {
            peer_id: member_id,
            role: "Unknown".to_string(),
            prestige: 0,
            rank: 0,
            last_activity: chrono::Utc::now().to_rfc3339(),
        })
        .collect();

    Json(member_info)
}

/// Get hierarchy distribution
async fn get_hierarchy(State(state): State<Arc<AppState>>) -> Json<HierarchyDistribution> {
    state.increment_request_count().await;

    // Get real hierarchy data from reputation system
    let threat_engine = state.threat_engine.lock().await;
    let reputation_system = threat_engine.reputation_system();

    Json(HierarchyDistribution {
        stray: reputation_system.get_role_count("Stray").await,
        scout: reputation_system.get_role_count("Scout").await,
        hunter: reputation_system.get_role_count("Hunter").await,
        beta: reputation_system.get_role_count("Beta").await,
        alpha: reputation_system.get_role_count("Alpha").await,
        omega: reputation_system.get_role_count("Omega").await,
    })
}

/// Get prestige metrics
async fn get_prestige_metrics(State(state): State<Arc<AppState>>) -> Json<PrestigeMetrics> {
    state.increment_request_count().await;

    // Get real prestige metrics from reputation system
    let threat_engine = state.threat_engine.lock().await;
    let reputation_system = threat_engine.reputation_system();

    Json(PrestigeMetrics {
        total_prestige: reputation_system.get_total_prestige().await as u64,
        average_prestige: reputation_system.get_average_prestige().await,
        gained_today: reputation_system.get_prestige_gained_today().await as u64,
        decayed_today: reputation_system.get_prestige_decayed_today().await as u64,
    })
}

/// Get administrative actions
async fn get_admin_actions(State(state): State<Arc<AppState>>) -> Json<Vec<AdminAction>> {
    state.increment_request_count().await;

    // Get real admin actions from reputation system
    let threat_engine = state.threat_engine.lock().await;
    let reputation_system = threat_engine.reputation_system();
    let actions = reputation_system.get_admin_actions().await;

    let action_info: Vec<AdminAction> = actions
        .into_iter()
        .map(|action_desc| AdminAction {
            action_id: uuid::Uuid::new_v4().to_string(),
            action_type: "System".to_string(),
            target_peer: "Unknown".to_string(),
            description: action_desc,
            timestamp: chrono::Utc::now().to_rfc3339(),
            status: "Logged".to_string(),
        })
        .collect();

    Json(action_info)
}
