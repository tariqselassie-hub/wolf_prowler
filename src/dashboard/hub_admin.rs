//! SaaS Hub Admin API Handlers
//! Handles organization management for the central SaaS Hub.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use crate::dashboard::api::OmegaUser;
use crate::dashboard::state::AppState;
use crate::persistence::DbOrganization;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use tracing::{info, error};

#[derive(Deserialize)]
pub struct CreateOrganizationRequest {
    pub name: String,
    pub admin_email: Option<String>,
    pub org_key: String,
}

#[derive(Serialize)]
pub struct CreateOrganizationResponse {
    pub org_id: Uuid,
    pub name: String,
}

/// Handler for creating a new organization
pub async fn admin_create_organization(
    _admin: OmegaUser,
    State(state): State<AppState>,
    Json(payload): Json<CreateOrganizationRequest>,
) -> Result<Json<CreateOrganizationResponse>, StatusCode> {
    info!("🏢 Admin creating new organization: {}", payload.name);
    
    if let Some(persistence) = &state.persistence {
        match persistence.create_organization(&payload.name, payload.admin_email.as_deref(), &payload.org_key).await {
            Ok(org_id) => {
                Ok(Json(CreateOrganizationResponse {
                    org_id,
                    name: payload.name,
                }))
            },
            Err(e) => {
                error!("Failed to create organization: {}", e);
                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    } else {
        Err(StatusCode::SERVICE_UNAVAILABLE)
    }
}

/// Handler for listing all organizations
pub async fn admin_list_organizations(
    _admin: OmegaUser,
    State(state): State<AppState>,
) -> Result<Json<Vec<DbOrganization>>, StatusCode> {
    info!("📋 Admin listing all organizations");
    
    if let Some(persistence) = &state.persistence {
        match persistence.list_organizations().await {
            Ok(orgs) => Ok(Json(orgs)),
            Err(e) => {
                error!("Failed to list organizations: {}", e);
                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    } else {
        Err(StatusCode::SERVICE_UNAVAILABLE)
    }
}

#[derive(Serialize)]
pub struct OrganizationStatsResponse {
    pub org_id: Uuid,
    pub agent_count: usize,
    pub active_alerts: usize,
    pub status: String,
}

/// Handler for getting organization-wide stats
pub async fn admin_get_organization_stats(
    _admin: OmegaUser,
    State(state): State<AppState>,
    Path(org_id): Path<Uuid>,
) -> Result<Json<OrganizationStatsResponse>, StatusCode> {
    info!("📊 Admin fetching stats for organization: {}", org_id);
    
    if let Some(persistence) = &state.persistence {
        // Fetch organization details
        let org = persistence.get_organization(org_id).await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .ok_or(StatusCode::NOT_FOUND)?;

        // Fetch agent count (scoped by org_id)
        let peers = persistence.get_all_peers(org_id).await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        // Fetch recent alerts (scoped by org_id)
        let alerts = persistence.get_recent_alerts(org_id, 100).await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        Ok(Json(OrganizationStatsResponse {
            org_id,
            agent_count: peers.len(),
            active_alerts: alerts.len(),
            status: org.status,
        }))
    } else {
        Err(StatusCode::SERVICE_UNAVAILABLE)
    }
}
