//! SaaS Hub API Handlers
//! Handles telemetry and alerts from distributed headless agents.

use axum::{
    async_trait,
    extract::{FromRef, FromRequestParts, State},
    http::{header, request::Parts, StatusCode},
    Json,
};
use crate::dashboard::state::AppState;
use crate::persistence::DbPeer;
use chrono::Utc;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{info, warn, error};
use uuid::Uuid;

/// Context for an authenticated organization
pub struct OrgContext {
    pub org_id: Uuid,
    pub org_key: String,
}

#[async_trait]
impl<S> FromRequestParts<S> for OrgContext
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let state = AppState::from_ref(state);
        
        // 1. Check for JWT in Authorization header
        if let Some(auth_header) = parts.headers.get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer ")) 
        {
            let secret = state.config.read().await.dashboard.secret_key.clone();
            let token_data = decode::<Claims>(
                auth_header,
                &DecodingKey::from_secret(secret.as_bytes()),
                &Validation::default(),
            );

            if let Ok(data) = token_data {
                if let Ok(org_id) = Uuid::parse_str(&data.claims.sub) {
                    return Ok(OrgContext {
                        org_id,
                        org_key: "JWT".to_string(), // Org key not needed when using JWT
                    });
                }
            }
        }

        // 2. Fallback to X-Org-Key (for bootstrap/initial login)
        let org_key = parts.headers.get("X-Org-Key")
            .and_then(|h| h.to_str().ok())
            .ok_or(StatusCode::UNAUTHORIZED)?;

        if let Some(persistence) = &state.persistence {
            if let Ok(Some(org_id)) = persistence.resolve_org_key(org_key).await {
                return Ok(OrgContext {
                    org_id,
                    org_key: org_key.to_string(),
                });
            }
        }

        Err(StatusCode::UNAUTHORIZED)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // org_id
    pub exp: usize,
}

#[derive(Deserialize)]
pub struct AgentLoginRequest {
    pub org_key: String,
}

#[derive(Serialize)]
pub struct AgentLoginResponse {
    pub token: String,
}

/// Handler for agent login - exchanges org_key for a JWT
pub async fn hub_agent_login(
    State(state): State<AppState>,
    Json(payload): Json<AgentLoginRequest>,
) -> Result<Json<AgentLoginResponse>, StatusCode> {
    if let Some(persistence) = &state.persistence {
        if let Ok(Some(org_id)) = persistence.resolve_org_key(&payload.org_key).await {
            let secret = state.config.read().await.dashboard.secret_key.clone();
            let exp = (chrono::Utc::now() + chrono::Duration::hours(24)).timestamp() as usize;
            let claims = Claims {
                sub: org_id.to_string(),
                exp,
            };

            let token = encode(
                &Header::default(),
                &claims,
                &EncodingKey::from_secret(secret.as_bytes()),
            ).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

            info!("🔑 Agent logged in: {} -> JWT issued", org_id);
            return Ok(Json(AgentLoginResponse { token }));
        }
    }

    Err(StatusCode::UNAUTHORIZED)
}

#[derive(Deserialize)]
pub struct AgentRegisterRequest {
    pub hostname: String,
    pub os_type: String,
    pub architecture: String,
    pub agent_version: String,
    pub service_type: String,
}

#[derive(Serialize)]
pub struct AgentRegisterResponse {
    pub peer_id: String,
    pub org_id: Uuid,
    pub update_interval_secs: u64,
}

/// Handler for agent registration
pub async fn hub_agent_register(
    State(state): State<AppState>,
    org: OrgContext,
    Json(payload): Json<AgentRegisterRequest>,
) -> Result<Json<AgentRegisterResponse>, StatusCode> {
    info!("📋 Hub registering new agent for Org: {} (Host: {})", org.org_id, payload.hostname);
    
    // Generate a unique peer ID for this agent
    let peer_id = format!("{}-{}", payload.hostname, Uuid::new_v4().to_string().chars().take(8).collect::<String>());
    
    if let Some(persistence) = &state.persistence {
        // We can pre-register the peer in the database with 'pending' or 'new' status
        let peer = DbPeer {
            org_id: Some(org.org_id),
            peer_id: peer_id.clone(),
            service_type: payload.service_type,
            system_type: payload.os_type,
            version: Some(payload.agent_version),
            status: "new".to_string(),
            trust_score: Some(50.0), // Default trust
            first_seen: Some(Utc::now()),
            last_seen: Some(Utc::now()),
            protocol_version: Some("1.0".to_string()),
            agent_version: Some("0.1.0".to_string()),
            capabilities: Some(serde_json::json!({})),
            metadata: Some(serde_json::json!({ "hostname": payload.hostname, "arch": payload.architecture })),
            created_at: Some(Utc::now()),
            updated_at: Some(Utc::now()),
        };

        if let Err(e) = persistence.save_peer(&peer).await {
            error!("Failed to pre-register peer: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }

    Ok(Json(AgentRegisterResponse {
        peer_id,
        org_id: org.org_id,
        update_interval_secs: 60,
    }))
}

/// Handler for fetching organization security policy
pub async fn hub_agent_policy(
    State(_state): State<AppState>,
    org: OrgContext,
) -> Result<Json<serde_json::Value>, StatusCode> {
    info!("📜 Hub fetching security policy for Org: {}", org.org_id);
    
    // For now, return a default policy. Later this will be fetched from persistence managed by org_id
    let policy = serde_json::json!({
        "org_id": org.org_id,
        "stance": "Balanced",
        "rules": [
            { "id": "p-1", "action": "Block", "pattern": "brute_force" },
            { "id": "p-2", "action": "Alert", "pattern": "unusual_telemetry" }
        ],
        "version": "1.0.0"
    });

    Ok(Json(policy))
}

#[derive(Deserialize)]
pub struct AgentReportRequest {
    pub node_metrics: serde_json::Value,
    pub agent_status: String,
}

#[derive(Deserialize)]
pub struct AgentAlertRequest {
    pub event: serde_json::Value,
}

/// Handler for receiving telemetry from agents
pub async fn hub_agent_report(
    State(_state): State<AppState>,
    org: OrgContext,
    Json(_payload): Json<AgentReportRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    info!("📈 Hub received report from Org: {}", org.org_id);
    
    // In a real implementation, we would extract peer_id from the request
    // and save metrics to the database.
    
    Ok(Json(serde_json::json!({ "success": true })))
}

/// Handler for receiving security alerts from agents
pub async fn hub_agent_alert(
    State(state): State<AppState>,
    org: OrgContext,
    Json(_payload): Json<AgentAlertRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    warn!("🔥 Hub received CRITICAL ALERT from Org: {}", org.org_id);
    
    if let Some(_persistence) = &state.persistence {
        // Log the alert to the database scoped by org_id
        // (Simplified for now)
    }

    Ok(Json(serde_json::json!({ "success": true })))
}
